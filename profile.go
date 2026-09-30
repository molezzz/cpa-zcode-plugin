package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// zcodePlanUpstreamBase is the Z.AI Coding Plan upstream origin. It is a
// variable so integration tests can point the plugin at a local httptest
// server; public configuration deliberately exposes no base-URL override.
var zcodePlanUpstreamBase = "https://zcode.z.ai"

// zcodeMessagesPath is the Coding Plan Anthropic Messages endpoint served for
// Coding Plan JWT credentials.
const zcodeMessagesPath = "/api/v1/zcode-plan/anthropic/v1/messages"

// messagesEndpointURL builds the absolute upstream Messages URL.
func messagesEndpointURL() string {
	return strings.TrimRight(zcodePlanUpstreamBase, "/") + zcodeMessagesPath
}

// Observed upstream product headers. The Coding Plan endpoint routes plan
// traffic by these identifiers; they are plugin-constructed and never copied
// from caller input.
const (
	anthropicVersionValue = "2023-06-01"
	zcodeUserAgent        = "ZCode/3.0.1"
	zcodeAppVersionHeader = "3.0.1"
	zcodeAgentHeader      = "glm"
	zcodeReferer          = "https://zcode.z.ai/"
)

// CredentialKind names which credential form an upstream profile authenticates
// with. JWT is the primary credential; the managed API key is the fallback
// introduced by a later milestone.
type CredentialKind string

const (
	// CredentialJWT is the primary credential kind used in this slice; the
	// managed API key fallback kind arrives with the fallback milestone.
	CredentialJWT CredentialKind = "jwt"
)

// JWT credential states persisted in the zcode namespace. Only jwtStatusActive
// (or an unset status on legacy documents) allows execution attempts.
const (
	jwtStatusActive              = "active"
	jwtStatusInvalid             = "invalid"
	jwtStatusExhausted           = "exhausted"
	jwtStatusVerificationBlocked = "verification_blocked"
	jwtStatusCooldown            = "cooldown"
)

// credentialErrors distinguish why a profile could not be built. Both are
// sanitized before they reach an error envelope; they never quote the
// document or its secrets.
var (
	errNoCredential = errors.New("zcode credential is missing or incomplete; complete the ZCode login again")
	// errCredentialUnavailable covers credentials recorded as not currently
	// usable (invalid, exhausted, verification-blocked, or cooling down).
	errCredentialUnavailable = errors.New("zcode primary credential is currently unavailable; refresh the credential or log in again")
)

// credentialSnapshot is the read-only view of the plugin-owned zcode
// namespace of one host auth record.
type credentialSnapshot struct {
	IdentityID string
	JWTToken   string
	JWTStatus  string
}

// readCredentialSnapshot decodes the plugin-owned namespace of an auth
// document. Unknown host-owned fields around it are ignored. jwtStatus is
// empty on legacy documents that predate explicit status tracking.
func readCredentialSnapshot(doc []byte) (credentialSnapshot, error) {
	var root struct {
		Zcode struct {
			IdentityID string `json:"identity_id"`
			JWT        struct {
				Token  string `json:"token"`
				Status string `json:"status"`
			} `json:"jwt"`
		} `json:"zcode"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(doc), &root); err != nil {
		return credentialSnapshot{}, fmt.Errorf("auth document is not valid JSON")
	}
	snap := credentialSnapshot{
		IdentityID: strings.TrimSpace(root.Zcode.IdentityID),
		JWTToken:   strings.TrimSpace(root.Zcode.JWT.Token),
		JWTStatus:  strings.ToLower(strings.TrimSpace(root.Zcode.JWT.Status)),
	}
	if snap.JWTToken == "" {
		return credentialSnapshot{}, errNoCredential
	}
	return snap, nil
}

// jwtUsable reports whether a recorded JWT state may attempt upstream
// execution. Unknown status strings are treated as usable: the upstream API
// verifies the token on every request, so a stale or unrecognized status must
// not strand a possibly-valid credential.
func jwtUsable(status string) bool {
	switch status {
	case "", jwtStatusActive:
		return true
	case jwtStatusInvalid, jwtStatusExhausted, jwtStatusVerificationBlocked, jwtStatusCooldown:
		return false
	default:
		return true
	}
}

// ResolvedProfile is the immutable per-request upstream configuration. Every
// execution request builds a fresh profile from the selected auth record; the
// profile owns endpoint, credential kind, authentication and product headers,
// model normalization, and HTTP limits. Callers must not mutate it.
type ResolvedProfile struct {
	IdentityID     string
	CredentialKind CredentialKind
	MessagesURL    string
	ModelID        string
	// Headers is the complete upstream request header set: plugin-built
	// authentication plus product headers plus allowlisted caller headers.
	Headers http.Header
	// MaxResponseBytes bounds every upstream read (single SSE frame and
	// non-streaming aggregation share this limit).
	MaxResponseBytes int64
	ConnectTimeout   time.Duration
	// HeaderTimeout bounds waiting for upstream response headers.
	HeaderTimeout time.Duration
	// IdleReadTimeout bounds waiting for the next upstream read on an
	// established stream; long-lived streams are fine as long as data flows.
	IdleReadTimeout time.Duration
}

// buildProfile resolves one execution attempt's upstream profile from a host
// auth document, the config snapshot, and the caller request headers (filtered
// through the allowlist). The model id is normalized against the plugin
// catalog. Errors are credential-classified and sanitized.
func buildProfile(doc []byte, cfg Config, model string, callerHeaders http.Header) (ResolvedProfile, error) {
	snap, err := readCredentialSnapshot(doc)
	if err != nil {
		return ResolvedProfile{}, err
	}
	if !jwtUsable(snap.JWTStatus) {
		return ResolvedProfile{}, credentialStatusError{Status: snap.JWTStatus}
	}
	cfg = normalizeConfig(cfg)
	return ResolvedProfile{
		IdentityID:       snap.IdentityID,
		CredentialKind:   CredentialJWT,
		MessagesURL:      messagesEndpointURL(),
		ModelID:          normalizeRequestModel(model, cfg.Models),
		Headers:          buildUpstreamHeaders(snap.JWTToken, callerHeaders),
		MaxResponseBytes: cfg.Upstream.MaxResponseBytes,
		ConnectTimeout:   time.Duration(cfg.Upstream.ConnectTimeoutSeconds) * time.Second,
		HeaderTimeout:    time.Duration(cfg.Upstream.RequestTimeoutSeconds) * time.Second,
		IdleReadTimeout:  time.Duration(cfg.Upstream.RequestTimeoutSeconds) * time.Second,
	}, nil
}

// buildUpstreamHeaders constructs the complete upstream header set: the
// plugin's own authentication and product headers plus exactly the allowlisted
// caller headers. Everything else — caller credentials, cookies, proxy
// credentials, host-control headers, and any X-ZCode-* header — is dropped.
// The result is a fresh header map; mutating it cannot leak into other
// profiles.
func buildUpstreamHeaders(jwtToken string, callerHeaders http.Header) http.Header {
	headers := http.Header{}
	for name, values := range callerHeaders {
		if !callerHeaderAllowed(name) {
			continue
		}
		for _, value := range values {
			headers.Add(name, value)
		}
	}
	headers.Set("Content-Type", "application/json")
	// The upstream transport is always SSE; a caller-provided Accept can
	// never change that.
	headers.Set("Accept", "text/event-stream")
	headers.Set("anthropic-version", anthropicVersionValue)
	headers.Set("User-Agent", zcodeUserAgent)
	headers.Set("X-ZCode-App-Version", zcodeAppVersionHeader)
	headers.Set("X-ZCode-Agent", zcodeAgentHeader)
	headers.Set("HTTP-Referer", zcodeReferer)
	// Authentication is constructed here from the host-managed credential;
	// caller Authorization/x-api-key values were dropped above.
	headers.Set("Authorization", "Bearer "+jwtToken)
	return headers
}

// callerHeaderAllowed is the explicit allowlist of caller request headers that
// may reach the upstream. It contains only non-sensitive protocol headers.
// The allowlist is the security boundary: deny-by-default means caller
// Authorization, x-api-key, Cookie, Proxy-Authorization, Host, Connection,
// and any X-ZCode-* header can never be forwarded, including headers added to
// the protocol by future host versions.
func callerHeaderAllowed(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "anthropic-beta":
		return true
	default:
		return false
	}
}

// knownModelAliases maps lower-case caller spellings to the canonical
// catalog ids. The upstream model names are case-sensitive, so aliases must
// be folded before the request leaves the plugin.
var knownModelAliases = map[string]string{
	"glm-turbo": "GLM-5-Turbo",
}

// normalizeRequestModel maps a caller model id onto the canonical upstream
// name. A leading provider scope ("zcode/GLM-5.2") is dropped, catalog ids
// are matched case-insensitively so their canonical casing is restored, and
// unknown models pass through unchanged for the upstream to judge.
func normalizeRequestModel(model string, catalog []string) string {
	trimmed := strings.TrimSpace(model)
	if idx := strings.LastIndex(trimmed, "/"); idx >= 0 {
		trimmed = strings.TrimSpace(trimmed[idx+1:])
	}
	if trimmed == "" {
		return trimmed
	}
	lower := strings.ToLower(trimmed)
	for _, id := range catalog {
		if strings.ToLower(id) == lower {
			return id
		}
	}
	if canonical, ok := knownModelAliases[lower]; ok {
		return canonical
	}
	return trimmed
}
