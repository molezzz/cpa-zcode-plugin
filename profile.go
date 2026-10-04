package main

import (
	"bytes"
	"encoding/json"
	"errors"
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

// zaiMessagesPath is the Z.AI business Anthropic Messages endpoint served for
// the managed fallback API key. It shares the base with the key exchange.
const zaiMessagesPath = "/api/anthropic/v1/messages"

// messagesEndpointURL builds the absolute Coding Plan Messages URL.
func messagesEndpointURL() string {
	return strings.TrimRight(zcodePlanUpstreamBase, "/") + zcodeMessagesPath
}

// zaiMessagesEndpointURL builds the absolute Z.AI Messages URL used by the
// managed fallback key.
func zaiMessagesEndpointURL() string {
	return strings.TrimRight(zaiAPIBase, "/") + zaiMessagesPath
}

// Observed upstream product headers. The Coding Plan endpoint routes plan
// traffic by these identifiers; they are plugin-constructed and never copied
// from caller input. The version-dependent headers carry the configured
// product.app_version rather than a constant, because the upstream judges
// client capability by it.
const (
	anthropicVersionValue = "2023-06-01"
	zcodeAgentHeader      = "glm"
	zcodeReferer          = "https://zcode.z.ai/"
)

// zcodeUserAgent renders the product User-Agent for one declared client
// version.
func zcodeUserAgent(appVersion string) string {
	return "ZCode/" + strings.TrimSpace(appVersion)
}

// CredentialKind names which credential form an upstream profile authenticates
// with. The Coding Plan JWT is the primary credential and the plugin-managed
// API key is the fallback for the same upstream identity.
type CredentialKind string

const (
	// CredentialJWT is the primary credential: it is attempted first and its
	// conclusions drive the recovery of its own state.
	CredentialJWT CredentialKind = "jwt"
	// CredentialAPIKey is the fallback credential: it is attempted only after
	// the primary became unusable, and its conclusions are recorded
	// separately from the primary's.
	CredentialAPIKey CredentialKind = "api_key"
)

// credentialStatusCooldown is the temporary, windowed conclusion both
// credential schemas spell identically. It is a separate constant so that a
// switch over either vocabulary never has to list the same value twice.
const credentialStatusCooldown = "cooldown"

// JWT credential states persisted in the zcode namespace. Only jwtStatusActive
// (or an unset status on legacy documents) allows execution attempts.
const (
	jwtStatusActive    = "active"
	jwtStatusInvalid   = "invalid"
	jwtStatusExhausted = "exhausted"
	// jwtStatusPlanExpired is a subscription whose term ended. It is kept apart
	// from exhausted: the remaining units may be untouched, and the account
	// recovers by renewing the plan, not by a quota refresh reading balance.
	jwtStatusPlanExpired         = "plan_expired"
	jwtStatusVerificationBlocked = "verification_blocked"
	jwtStatusCooldown            = credentialStatusCooldown
)

// Managed API key availability conclusions. The exchange statuses describe how
// the key material was obtained (active, failed, needs_selection, unavailable);
// apiKeyStatusCooldown and apiKeyStatusInvalid describe what the upstream
// concluded when the key was actually used, so a rejected key is never retried
// on every request.
const (
	apiKeyStatusCooldown  = credentialStatusCooldown
	apiKeyStatusInvalid   = "invalid"
	apiKeyStatusExhausted = "exhausted"
)

// credentialErrors distinguish why a profile could not be built. All are
// sanitized before they reach an error envelope; they never quote the document
// or its secrets.
var (
	errNoCredential = errors.New("zcode credential is missing or incomplete; complete the ZCode login again")
	// errCredentialUnavailable covers any credential recorded as not currently
	// usable (invalid, exhausted, verification-blocked, or cooling down).
	errCredentialUnavailable = errors.New("zcode credential is currently unavailable; refresh the credential or log in again")
	// errAuthDocument marks a stored record the plugin cannot read as a
	// credential document. It carries no document content.
	errAuthDocument = errors.New("auth document is not valid JSON")
)

// credentialSnapshot is the read-only view of the plugin-owned zcode
// namespace of one host auth record: both credential forms of the same
// upstream identity, each with its own recorded state.
type credentialSnapshot struct {
	IdentityID string
	JWTToken   string
	JWTStatus  string
	// Site is the site this credential was authorized against. A document written
	// before the dual-site split reads as the international site, which is the
	// only site that could have produced it. It is carried here rather than
	// re-read at each use so that every consumer of one snapshot agrees on the
	// site — the snapshot is the single read of the document a request is planned
	// from.
	Site string
	// JWTRetryAfter is the recorded retry window of a windowed JWT state; an
	// elapsed window means the JWT is usable again.
	JWTRetryAfter string
	// APIKeyToken is the callable material of the plugin-managed fallback
	// key. APIKeyStatus is its own availability conclusion, independent of
	// the JWT's, and APIKeyRetryAfter is the window of a windowed key state.
	APIKeyToken      string
	APIKeyStatus     string
	APIKeyRetryAfter string
	// ModelQuota is the per-model conclusion the JWT section carries: which
	// models have been found to have every one of their buckets empty, and
	// until when. It is what lets an empty GLM-5.3 allowance leave
	// GLM-5.3-Flash schedulable on the very same credential.
	ModelQuota map[string]string
}

// readCredentialSnapshot decodes the plugin-owned namespace of an auth
// document. Unknown host-owned fields around it are ignored. An absent status
// is empty on legacy documents that predate explicit status tracking.
func readCredentialSnapshot(doc []byte) (credentialSnapshot, error) {
	var root struct {
		Zcode struct {
			IdentityID string `json:"identity_id"`
			Site       string `json:"site"`
			JWT        struct {
				Token      string            `json:"token"`
				Status     string            `json:"status"`
				RetryAfter string            `json:"retry_after"`
				ModelQuota map[string]string `json:"model_quota"`
			} `json:"jwt"`
			APIKey struct {
				Material   string `json:"key_material"`
				Status     string `json:"status"`
				RetryAfter string `json:"retry_after"`
			} `json:"api_key"`
		} `json:"zcode"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(doc), &root); err != nil {
		return credentialSnapshot{}, errAuthDocument
	}
	snap := credentialSnapshot{
		IdentityID:       strings.TrimSpace(root.Zcode.IdentityID),
		JWTToken:         strings.TrimSpace(root.Zcode.JWT.Token),
		JWTStatus:        normalizeStatus(root.Zcode.JWT.Status),
		JWTRetryAfter:    strings.TrimSpace(root.Zcode.JWT.RetryAfter),
		APIKeyToken:      strings.TrimSpace(root.Zcode.APIKey.Material),
		APIKeyStatus:     normalizeStatus(root.Zcode.APIKey.Status),
		APIKeyRetryAfter: strings.TrimSpace(root.Zcode.APIKey.RetryAfter),
		ModelQuota:       readModelQuota(root.Zcode.JWT.ModelQuota),
		Site:             recordedSite(root.Zcode.Site),
	}
	if snap.JWTToken == "" && snap.APIKeyToken == "" {
		return credentialSnapshot{}, errNoCredential
	}
	return snap, nil
}

// normalizeStatus folds a recorded status onto the lower-case form the state
// machine compares on.
func normalizeStatus(status string) string {
	return strings.ToLower(strings.TrimSpace(status))
}

// readModelQuota recovers the per-model conclusions of a JWT section, dropping
// any entry the model key or the value did not fill in: a conclusion with no
// model names nothing and one with no deadline states no period, and treating
// either as a fact would skip a model on an empty record.
func readModelQuota(raw map[string]string) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	out := make(map[string]string, len(raw))
	for model, until := range raw {
		if strings.TrimSpace(model) == "" || strings.TrimSpace(until) == "" {
			continue
		}
		out[model] = strings.TrimSpace(until)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// modelQuotaBlocked reports whether the JWT is recorded as unable to serve one
// model because every bucket that pays for it was empty when it was last read.
//
// The recorded deadline is the earliest window close among those buckets, and it
// is checked rather than trusted: the upstream decides when a bucket refills, so
// an elapsed deadline means the plugin must let the model back in and let the
// next request settle it. Skipping on an elapsed deadline would hold a credential
// out of service for a model whose buckets came back hours ago, which is the same
// failure this whole change exists to remove.
func (s credentialSnapshot) modelQuotaBlocked(model string, now time.Time) bool {
	until, ok := s.modelQuotaWindow(model)
	if !ok {
		return false
	}
	return modelQuotaPending(until, now)
}

// modelQuotaWindow reads the raw deadline recorded against one model's block.
// The second result is false when the model has no entry at all, which is a
// different fact from an entry that records the deadline-less sentinel: the
// first says this model was never blocked, the second says it was and that the
// upstream gave no window. The caller that only asks "is it blocked" treats both
// as pending-or-absent through modelQuotaPending, while a re-assertion has to
// carry the stored value through so it does not overwrite a real deadline with
// the sentinel.
func (s credentialSnapshot) modelQuotaWindow(model string) (string, bool) {
	target := normalizeRequestModel(model, nil)
	if until, ok := s.ModelQuota[target]; ok {
		return strings.TrimSpace(until), true
	}
	// A caller may spell the model differently from the spelling recorded by the
	// conclusion that blocked it, so the lookup falls back to a case-insensitive
	// match rather than to no conclusion at all.
	for recorded, until := range s.ModelQuota {
		if strings.EqualFold(recorded, target) {
			return strings.TrimSpace(until), true
		}
	}
	return "", false
}

// modelQuotaPending reports whether a recorded per-model deadline still holds the
// model out of service. A deadline-less entry holds until a reading observes an
// allowance, which is the same recovery rule the credential-wide exhausted state
// uses and the reason no window is invented for one.
func modelQuotaPending(until string, now time.Time) bool {
	until = strings.TrimSpace(until)
	if until == modelQuotaNoDeadline {
		return true
	}
	return retryWindowPending(until, now)
}

// jwtUsableForModel reports whether the Coding Plan JWT may attempt one model
// now, which is both the credential-level gate and the per-model one.
//
// The credential-level gate is unchanged: a JWT the upstream rejected, whose
// plan ended, or which is cooling down serves no model. On top of it, a model
// whose every bucket was empty is out of service until the recorded refill
// deadline passes, while every other model on the same JWT stays schedulable —
// that separation is what keeps an exhausted GLM-5.3 from disabling GLM-5.3-Flash.
func jwtUsableForModel(snap credentialSnapshot, model string, now time.Time) bool {
	if !jwtUsable(snap.JWTStatus, snap.JWTRetryAfter, now) {
		return false
	}
	return !snap.modelQuotaBlocked(model, now)
}

// jwtUsable reports whether a recorded JWT state may attempt upstream
// execution now. Unknown status strings are treated as usable: the upstream API
// verifies the token on every request, so a stale or unrecognized status must
// not strand a possibly-valid credential. A windowed state is usable again
// once its retry window has passed, which is how a verification block
// automatically retries after five minutes.
func jwtUsable(status string, retryAfter string, now time.Time) bool {
	switch status {
	case "", jwtStatusActive:
		return true
	case jwtStatusInvalid, jwtStatusExhausted, jwtStatusPlanExpired:
		return false
	case jwtStatusVerificationBlocked, jwtStatusCooldown:
		return !retryWindowPending(retryAfter, now)
	default:
		return true
	}
}

// apiKeyUsable reports whether the managed fallback key may be attempted. The
// exchange states describe how the key material was obtained rather than what
// the upstream concluded about it, so a key whose selection is still pending or
// whose last exchange failed stays usable; only a key the upstream itself
// rejected, exhausted, or rate-limited is skipped. apiKeyStatusUnavailable is
// written only when the exchange never obtained a key identity at all, so no
// material can exist for it.
func apiKeyUsable(status, retryAfter string, now time.Time) bool {
	switch status {
	case "", apiKeyStatusActive, apiKeyStatusFailed, apiKeyStatusNeedsSelection:
		return true
	case apiKeyStatusInvalid, apiKeyStatusExhausted, apiKeyStatusUnavailable:
		return false
	case apiKeyStatusCooldown:
		return !retryWindowPending(retryAfter, now)
	default:
		return true
	}
}

// ResolvedProfile is the immutable per-request upstream configuration. Every
// execution request builds a fresh profile from the selected auth record; the
// profile owns route, credential kind, authentication and product headers,
// model normalization, and HTTP limits. Callers must not mutate it.
type ResolvedProfile struct {
	IdentityID     string
	CredentialKind CredentialKind
	// Record identifies the host auth record this attempt's conclusions belong to.
	// It is empty for the record the host selected, so every single-record caller
	// and every profile built by newProfile is unchanged; a pooled attempt carries
	// the record it came from, so an exhaustion recorded on one credential lands
	// on that credential and not on whichever record happened to be selected.
	Record string
	// Route is the resolved upstream route this profile sends to: identity,
	// URL, authentication shape, billing/entitlement domain, and gateway
	// status. It is the only route description the executor and classifier
	// reason about.
	Route resolvedRoute
	// MessagesURL is the route's absolute Messages URL, kept as a direct field
	// because every attempt reads it.
	MessagesURL string
	ModelID     string
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

// newProfile builds one credential's immutable profile. Route and
// authentication depend on the credential kind alone: the route resolver
// declares the authentication shape, and the profile builds it from the
// credential itself. The primary reaches the Coding Plan endpoint with a
// bearer JWT, the fallback reaches the Z.AI endpoint with the managed key in
// x-api-key. The JWT's final wire shape — whether the route also wants the JWT
// in x-api-key — stays an open question until an authorized capture proves it,
// so the profile declares only the bearer form.
//
// identity is the request's caller-facing identity (device and session); its
// device id is the credential's persisted device identity, sent as the client
// fingerprint's X-Device-Mid and, in the same value, as the request body's
// metadata.user_id, so a Messages request and a balance request for the same
// account describe one installation.
func newProfile(snap credentialSnapshot, kind CredentialKind, cfg Config, model string, callerHeaders http.Header, identity requestIdentity) ResolvedProfile {
	route := resolveRoute(kind)
	profile := ResolvedProfile{
		IdentityID:       snap.IdentityID,
		CredentialKind:   kind,
		Route:            route,
		MessagesURL:      route.URL,
		ModelID:          normalizeRequestModel(model, cfg.Models),
		Headers:          buildUpstreamHeaders(callerHeaders, cfg, identity),
		MaxResponseBytes: cfg.Upstream.MaxResponseBytes,
		ConnectTimeout:   time.Duration(cfg.Upstream.ConnectTimeoutSeconds) * time.Second,
		HeaderTimeout:    time.Duration(cfg.Upstream.RequestTimeoutSeconds) * time.Second,
		IdleReadTimeout:  time.Duration(cfg.Upstream.RequestTimeoutSeconds) * time.Second,
	}
	switch route.AuthMode {
	case authAPIKey:
		profile.Headers.Set("x-api-key", snap.APIKeyToken)
	case authBearerJWT:
		profile.Headers.Set("Authorization", "Bearer "+snap.JWTToken)
	}
	if route.GatewayRewritten {
		// A gateway-routed request drops only the explicit Host header;
		// authentication and every other header go through unchanged.
		profile.Headers = gatewayRequestHeaders(profile.Headers)
	}
	return profile
}

// buildUpstreamHeaders constructs the product and protocol header set plus
// exactly the allowlisted caller headers. Everything else — caller credentials,
// cookies, proxy credentials, host-control headers, and any X-ZCode-* header —
// is dropped. Authentication is added by newProfile from the host-managed
// credential, so a caller Authorization/x-api-key value can never reach the
// upstream, and the two credential forms cannot inherit each other's header. The
// result is a fresh header map; mutating it cannot leak into other profiles.
func buildUpstreamHeaders(callerHeaders http.Header, cfg Config, identity requestIdentity) http.Header {
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
	appVersion := cfg.Product.AppVersion
	headers.Set("User-Agent", zcodeUserAgent(appVersion))
	headers.Set("X-ZCode-App-Version", appVersion)
	headers.Set("X-ZCode-Agent", zcodeAgentHeader)
	headers.Set("HTTP-Referer", zcodeReferer)
	applyClientFingerprint(headers, cfg, identity)
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

// officialGLMModelIDs is the upstream's canonical GLM model id table
// (official shared/official-glm-model-id.ts). The Coding Plan balance
// endpoint declares model capabilities in lower case, so this table is how
// capability ids and caller spellings are folded onto the official casing
// the upstream model router expects. New official models enter the table
// together with the official source's own list.
var officialGLMModelIDs = []string{
	"GLM-5.3",
	"GLM-5.3-Flash",
	"GLM-5V-Turbo",
	"GLM-5.2",
	"GLM-5.1",
	"GLM-5.1-Highspeed",
	"GLM-5",
	"GLM-5-Turbo",
	"GLM-4.7",
	"GLM-4.7-FlashX",
	"GLM-4.7-Flash",
	"GLM-4.6",
	"GLM-4.5-Air",
	"GLM-4.5",
	"GLM-4.6V",
	"GLM-4.6V-Flash",
	"GLM-4.6V-FlashX",
	"GLM-4.1V-Thinking-FlashX",
	"GLM-4.1V-Thinking-Flash",
	"GLM-4-FlashX-250414",
	"GLM-4-Flash-250414",
	"GLM-4V-Flash",
}

var officialGLMModelIDsByLower = func() map[string]string {
	byLower := make(map[string]string, len(officialGLMModelIDs))
	for _, id := range officialGLMModelIDs {
		byLower[strings.ToLower(id)] = id
	}
	return byLower
}()

// canonicalizeGLMModelID folds one model id onto the official casing. An id
// outside the official table is returned unchanged: dynamic discovery may
// name models the table does not know yet.
func canonicalizeGLMModelID(id string) string {
	trimmed := strings.TrimSpace(id)
	if canonical, ok := officialGLMModelIDsByLower[strings.ToLower(trimmed)]; ok {
		return canonical
	}
	return trimmed
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
	// A caller or capability spelling of an official GLM id ("glm-5.3-flash")
	// must reach the upstream in the official casing; the model router is
	// case-sensitive.
	if canonical, ok := officialGLMModelIDsByLower[lower]; ok {
		return canonical
	}
	return trimmed
}
