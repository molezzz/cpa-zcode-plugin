package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// oauthUpstreamBase is the Z.AI CLI OAuth API root. It is a variable so
// integration tests can point the plugin at a local httptest server.
var oauthUpstreamBase = "https://zcode.z.ai/api/v1"

// oauthRequestTimeout bounds each upstream OAuth HTTP call. The host polls
// login status every few seconds, so a call must fail fast enough to stay
// inside the host's poll cadence.
const oauthRequestTimeout = 30 * time.Second

// oauthLoginProvider is the upstream provider selector for the CLI OAuth
// flow; it configures what the authorize URL will authenticate against.
const oauthLoginProvider = "zai"

// maxOAuthBodyBytes bounds upstream OAuth response bodies regardless of the
// general upstream limit, because login payloads are small JSON documents.
const maxOAuthBodyBytes int64 = 1 << 20

// authStoreProvider resolves the host auth store used to read the previous
// credential document on re-login. It is a seam so tests can inject a fake
// instead of the CGO bridge.
var authStoreProvider = func() AuthStore { return pluginHost().AuthStore() }

// initEndpointURL and pollEndpointURL build the two upstream OAuth endpoints.
func initEndpointURL(base string) string { return strings.TrimRight(base, "/") + "/oauth/cli/init" }

func pollEndpointURL(base, flowID string) string {
	return strings.TrimRight(base, "/") + "/oauth/cli/poll/" + url.PathEscape(flowID)
}

// oauthInitResponse mirrors the observed upstream init payload: the flow
// data sits under "data", with the top level accepted defensively.
type oauthInitResponse struct {
	Data struct {
		FlowID       string `json:"flow_id"`
		AuthorizeURL string `json:"authorize_url"`
	} `json:"data"`
	FlowID       string `json:"flow_id"`
	AuthorizeURL string `json:"authorize_url"`
}

// oauthPollResponse mirrors the observed upstream poll payload. status is
// oauthPollStatusReady once the user finished authorization and
// oauthPollStatusFailed when the flow was rejected; anything else means the
// user has not finished yet.
type oauthPollResponse struct {
	Data struct {
		Status string `json:"status"`
		Token  string `json:"token"`
		Zai    struct {
			AccessToken string `json:"access_token"`
		} `json:"zai"`
	} `json:"data"`
	Status string `json:"status"`
	Token  string `json:"token"`
}

// Observed upstream poll status values.
const (
	oauthPollStatusReady  = "ready"
	oauthPollStatusFailed = "failed"
)

// zcodeAuthLabel is the user-facing label for every ZCode auth record.
const zcodeAuthLabel = "ZCode (Z.AI)"

// oauthInit starts one upstream OAuth flow authenticated by the session's
// fresh polling secret. Errors are redacted: they carry no secret, URL
// query, or response body.
func oauthInit(ctx context.Context, client *http.Client, baseURL, pollSecret string) (string, string, error) {
	ctx, cancel := context.WithTimeout(ctx, oauthRequestTimeout)
	defer cancel()
	payload, err := json.Marshal(map[string]string{"provider": oauthLoginProvider})
	if err != nil {
		return "", "", fmt.Errorf("encode authorization init request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, initEndpointURL(baseURL), bytes.NewReader(payload))
	if err != nil {
		return "", "", fmt.Errorf("build authorization init request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+pollSecret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", errors.New("authorization upstream unreachable")
	}
	defer drainAndClose(resp.Body)
	body, err := readLimited(resp.Body, maxOAuthBodyBytes)
	if err != nil {
		return "", "", fmt.Errorf("read authorization init response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", "", fmt.Errorf("authorization upstream rejected the login (http %d)", resp.StatusCode)
	}
	var parsed oauthInitResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", "", fmt.Errorf("authorization upstream response is not valid JSON")
	}
	flowID := strings.TrimSpace(parsed.Data.FlowID)
	authorizeURL := strings.TrimSpace(parsed.Data.AuthorizeURL)
	if flowID == "" {
		flowID = strings.TrimSpace(parsed.FlowID)
	}
	if authorizeURL == "" {
		authorizeURL = strings.TrimSpace(parsed.AuthorizeURL)
	}
	if flowID == "" || authorizeURL == "" {
		return "", "", fmt.Errorf("authorization upstream response is incomplete")
	}
	if _, err := url.Parse(authorizeURL); err != nil {
		return "", "", fmt.Errorf("authorization upstream returned an invalid authorize URL")
	}
	return flowID, authorizeURL, nil
}

// drainAndClose releases an upstream response body without unbounded reads.
func drainAndClose(body io.Reader) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 64<<10))
	if closer, ok := body.(io.Closer); ok {
		_ = closer.Close()
	}
}

// handleAuthIdentifier answers the host's auth provider discovery call.
func handleAuthIdentifier() ([]byte, error) {
	return okEnvelope(struct {
		Identifier string `json:"identifier"`
	}{Identifier: pluginID})
}

// authLoginStartRPC mirrors the host request for auth.login.start. Field
// names follow the host's JSON encoding of pluginapi.AuthLoginStartRequest.
type authLoginStartRPC struct {
	Provider string
	Metadata map[string]any
}

// handleAuthLoginStart creates one authorization session and returns the
// browser authorization link plus the opaque polling handle. The polling
// secret stays inside the session.
func handleAuthLoginStart(request []byte) ([]byte, error) {
	var req authLoginStartRPC
	if len(request) > 0 {
		if err := json.Unmarshal(request, &req); err != nil {
			return errorEnvelope("invalid_request", "decode auth.login.start request: "+err.Error(), http.StatusBadRequest), nil
		}
	}
	if strings.TrimSpace(req.Provider) != "" && req.Provider != pluginID {
		return errorEnvelope("unknown_provider", "auth.login.start does not handle provider "+req.Provider, http.StatusBadRequest), nil
	}

	session, err := startAuthorizationSession(currentConfig())
	if err != nil {
		if errors.Is(err, errOAuthUpstream) {
			return errorEnvelope("oauth_upstream_failed", err.Error(), http.StatusBadGateway), nil
		}
		return errorEnvelope("plugin_error", "could not create authorization session", http.StatusInternalServerError), nil
	}
	return okEnvelope(pluginapi.AuthLoginStartResponse{
		Provider:  pluginID,
		URL:       session.authorizeURL,
		State:     session.id,
		ExpiresAt: session.expiresAt,
	})
}

// errOAuthUpstream marks a session-start failure that originated at the
// authorization upstream, so callers can map it to an upstream-failure
// envelope instead of a local plugin error.
var errOAuthUpstream = errors.New("authorization upstream failed")

// startAuthorizationSession creates one pending authorization session with its
// own polling secret, HTTP client, and cookie jar. Both the host's native
// login entry and the management plane's re-authorization action create
// sessions through it, so the two entries cannot drift in how sessions are
// constructed.
func startAuthorizationSession(cfg Config) (*authSession, error) {
	client := newSessionHTTPClient(cfg)
	pollSecret, err := randomHexToken(pollSecretBytes)
	if err != nil {
		client.CloseIdleConnections()
		return nil, errors.New("could not create authorization session")
	}
	flowID, authorizeURL, err := oauthInit(context.Background(), client, oauthUpstreamBase, pollSecret)
	if err != nil {
		client.CloseIdleConnections()
		if !errors.Is(err, errOAuthUpstream) {
			err = fmt.Errorf("%w: %v", errOAuthUpstream, err)
		}
		return nil, err
	}
	session, err := activeSessions.create(flowID, authorizeURL, pollSecret, client, time.Duration(cfg.OAuth.SessionTTLSeconds)*time.Second)
	if err != nil {
		client.CloseIdleConnections()
		return nil, errors.New("could not create authorization session")
	}
	return session, nil
}

// authLoginPollRPC mirrors the host request for auth.login.poll.
type authLoginPollRPC struct {
	Provider string
	State    string
}

// handleAuthLoginPoll reports session progress. Pending, completed, failed,
// and expired sessions all return a poll response so the host renders the
// matching login state; only malformed requests produce error envelopes.
func handleAuthLoginPoll(request []byte) ([]byte, error) {
	var req authLoginPollRPC
	if len(request) > 0 {
		if err := json.Unmarshal(request, &req); err != nil {
			return errorEnvelope("invalid_request", "decode auth.login.poll request: "+err.Error(), http.StatusBadRequest), nil
		}
	}
	state := strings.TrimSpace(req.State)
	if state == "" {
		return errorEnvelope("invalid_request", "auth.login.poll requires the login state", http.StatusBadRequest), nil
	}
	session := activeSessions.lookup(state)
	if session == nil {
		return pollResponse(pluginapi.AuthLoginStatusError, "authorization session expired or unknown", nil), nil
	}

	if reply, done := terminalPollResponse(session); done {
		return reply, nil
	}
	cfg := currentConfig()
	ctx, cancel, ok := session.sessionRequestContext(context.Background(), oauthRequestTimeout)
	if !ok {
		// The session became terminal between the snapshot and here; report
		// the stable terminal status instead of a spurious failure.
		if reply, done := terminalPollResponse(session); done {
			return reply, nil
		}
		session.expireIfDue(time.Now())
		return pollResponse(pluginapi.AuthLoginStatusError, "authorization session expired", nil), nil
	}
	defer cancel()
	body, statusCode, err := session.pollUpstream(ctx, oauthUpstreamBase, min(maxOAuthBodyBytes, cfg.Upstream.MaxResponseBytes))
	if err != nil {
		// Transient upstream or network trouble: stay pending so the host's
		// poll cadence can retry until the session expires.
		return pollResponse(pluginapi.AuthLoginStatusPending, "waiting for authorization", nil), nil
	}
	if statusCode < 200 || statusCode > 299 {
		// Unknown upstream error contract: do not fail the login on a
		// transient rejection; the session TTL bounds the waiting time.
		return pollResponse(pluginapi.AuthLoginStatusPending, "waiting for authorization", nil), nil
	}
	return interpretPollBody(ctx, session, body)
}

// terminalPollResponse renders replies for completed, failed, and expired
// sessions without touching upstream. done is false while still pending.
func terminalPollResponse(session *authSession) (reply []byte, done bool) {
	snap := session.snapshot()
	switch snap.State {
	case authSessionCompleted:
		if snap.Result == nil {
			return pollResponse(pluginapi.AuthLoginStatusError, "authorization result is unavailable", nil), true
		}
		response := pluginapi.AuthLoginPollResponse{
			Status: pluginapi.AuthLoginStatusSuccess,
			Auth:   authDataFromStorage(snap.Result.IdentityID, snap.Result.Storage),
		}
		raw, err := okEnvelope(response)
		if err != nil {
			return errorEnvelope("plugin_error", "could not encode login result", http.StatusInternalServerError), true
		}
		return raw, true
	case authSessionFailed:
		return pollResponse(pluginapi.AuthLoginStatusError, snap.Message, nil), true
	case authSessionExpired:
		return pollResponse(pluginapi.AuthLoginStatusError, snap.Message, nil), true
	default:
		return nil, false
	}
}

// pollOutcomeKind classifies the result of applying one upstream poll body to
// a session.
type pollOutcomeKind string

const (
	pollPending   pollOutcomeKind = "pending"
	pollCompleted pollOutcomeKind = "completed"
	pollFailed    pollOutcomeKind = "failed"
)

// pollOutcome is the shared verdict of one poll. The native host poll path
// maps it onto RPC replies; the management plane's re-authorization loop
// reacts to it and stops on terminal outcomes.
type pollOutcome struct {
	Kind    pollOutcomeKind
	Message string
	Result  *completedLogin
}

// interpretPollBody applies the upstream poll verdict to the session and
// renders the poll reply. The credentials persist through the host: a
// successful poll carries the completed auth record back to the host, which
// stores it.
func interpretPollBody(_ context.Context, session *authSession, body []byte) ([]byte, error) {
	return pollOutcomeReply(session, applyPollVerdict(session, body, nil)), nil
}

// applyPollVerdict applies one upstream poll body to the session. The persist
// callback, when set, stores the completed credential document before the
// session is marked complete — the management plane's re-authorization path
// uses it because no host poll is waiting to persist the result. A persist
// failure fails the session: an unpersisted OAuth result must not look like a
// completed login. A nil persist keeps the native behavior, where the host
// persists from the poll reply.
func applyPollVerdict(session *authSession, body []byte, persist func(identityID string, storage []byte) error) pollOutcome {
	var parsed oauthPollResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return pollOutcome{Kind: pollPending, Message: "waiting for authorization"}
	}
	status := strings.TrimSpace(parsed.Data.Status)
	if status == "" {
		status = strings.TrimSpace(parsed.Status)
	}
	token := strings.TrimSpace(parsed.Data.Token)
	if token == "" {
		token = strings.TrimSpace(parsed.Token)
	}
	accessToken := strings.TrimSpace(parsed.Data.Zai.AccessToken)

	switch {
	case status == oauthPollStatusFailed:
		session.fail("authorization was rejected or failed upstream")
		return pollOutcome{Kind: pollFailed, Message: "authorization was rejected or failed upstream"}
	case status == oauthPollStatusReady:
		if token == "" {
			session.fail("authorization completed without a coding plan credential")
			return pollOutcome{Kind: pollFailed, Message: "authorization completed without a coding plan credential"}
		}
		if !session.beginFinalization() {
			// Another poll of this session is completing the credentials,
			// including the managed key exchange; report pending so the host
			// retries and observes the single consistent completion.
			return pollOutcome{Kind: pollPending, Message: "finalizing authorization"}
		}
		if snap := session.snapshot(); snap.State != authSessionPending {
			// A concurrent poll expired or failed the session between the
			// upstream read and here; report the stable terminal outcome and
			// skip the credential completion (and its upstream side effects).
			return terminalPollOutcome(session)
		}
		storage, identityID, err := completeLoginStorage(token, accessToken)
		if err != nil {
			session.fail(err.Error())
			return pollOutcome{Kind: pollFailed, Message: err.Error()}
		}
		if persist != nil {
			if err := persist(identityID, storage); err != nil {
				session.fail("credentials could not be persisted; retry the authorization")
				return pollOutcome{Kind: pollFailed, Message: "credentials could not be persisted; retry the authorization"}
			}
		}
		result, completed := session.complete(completedLogin{IdentityID: identityID, Storage: storage})
		if !completed {
			// The session reached a terminal state concurrently (for example
			// expired between the upstream read and here); report that stable
			// outcome instead of a bogus success with an empty record.
			return terminalPollOutcome(session)
		}
		return pollOutcome{Kind: pollCompleted, Result: &result}
	default:
		return pollOutcome{Kind: pollPending, Message: "waiting for authorization"}
	}
}

// terminalPollOutcome renders the poll outcome of an already-terminal
// session. An unreachable terminal state falls back to pending, which the
// caller treats as "keep waiting" exactly like an ordinary poll.
func terminalPollOutcome(session *authSession) pollOutcome {
	snap := session.snapshot()
	switch snap.State {
	case authSessionCompleted:
		if snap.Result == nil {
			return pollOutcome{Kind: pollFailed, Message: "authorization result is unavailable"}
		}
		return pollOutcome{Kind: pollCompleted, Result: snap.Result}
	case authSessionFailed, authSessionExpired:
		message := snap.Message
		if message == "" {
			message = "authorization session expired"
		}
		return pollOutcome{Kind: pollFailed, Message: message}
	default:
		return pollOutcome{Kind: pollPending, Message: "waiting for authorization"}
	}
}

// pollOutcomeReply renders the host poll reply for one outcome, preserving
// the exact reply contract of the native poll path.
func pollOutcomeReply(session *authSession, outcome pollOutcome) []byte {
	switch outcome.Kind {
	case pollCompleted:
		if outcome.Result == nil {
			return pollResponse(pluginapi.AuthLoginStatusError, "authorization result is unavailable", nil)
		}
		raw, err := okEnvelope(pluginapi.AuthLoginPollResponse{
			Status: pluginapi.AuthLoginStatusSuccess,
			Auth:   authDataFromStorage(outcome.Result.IdentityID, outcome.Result.Storage),
		})
		if err != nil {
			return pollResponse(pluginapi.AuthLoginStatusError, "could not encode login result", nil)
		}
		return raw
	case pollFailed:
		return pollResponse(pluginapi.AuthLoginStatusError, outcome.Message, nil)
	default:
		return pollResponse(pluginapi.AuthLoginStatusPending, outcome.Message, nil)
	}
}

// completeLoginStorage builds the plugin-owned namespace for a fresh JWT by
// patching the previous auth document of the same identity, so a re-login
// never destroys host fields or the managed API key of an existing account.
// The fresh OAuth access token, when present, is spent on the managed key
// exchange in the same pass; its outcome is recorded as diagnosable api_key
// state and never fails or rolls back the JWT login. The host store read uses
// its own deadline: it must not be cut short by the session TTL, which only
// bounds upstream OAuth traffic.
func completeLoginStorage(token, accessToken string) ([]byte, string, error) {
	subject, ok := zcodeSubjectFromJWT(token)
	if !ok {
		return nil, "", fmt.Errorf("upstream credential does not expose a stable identity claim; refusing to create an untrackable account")
	}
	identityID := identityIDFor(subject)
	ctx, cancel := context.WithTimeout(context.Background(), oauthStoreReadTimeout)
	defer cancel()
	previous, err := readPreviousAuthDoc(ctx, identityID)
	if err != nil {
		return nil, "", fmt.Errorf("existing credentials could not be read; login aborted to protect them")
	}
	doc, err := buildZcodeStorage(previous, identityID, token, accessToken, time.Now())
	if err != nil {
		return nil, "", fmt.Errorf("authorization result could not be stored")
	}
	// The managed key exchange runs first because it already performs the
	// business-token login and primes the cache, so recording the business
	// token afterwards costs no second upstream call. Doing it in this order is
	// also the only order that leaves the exchange result cached when the key
	// exchange fails: a failed key exchange still obtained a business token.
	doc = attachManagedAPIKey(doc, identityID, accessToken, time.Now())
	return attachBusinessToken(doc, identityID, accessToken, time.Now()), identityID, nil
}

// attachBusinessToken records the Z.AI business token for the identity, so the
// account is usable against the business API from the moment it is created
// rather than failing the first subscription or quota call that needs it.
//
// It is a recording step, not a second exchange: the managed key exchange
// already called the same login endpoint and cached the result. When that
// cache is cold the exchange happens here, and a refusal is not a login
// failure — the Coding Plan JWT does not depend on it, and the exchange is
// retried on demand once the OAuth material is usable again.
func attachBusinessToken(doc []byte, identityID, accessToken string, now time.Time) []byte {
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return doc
	}
	cached, ok := activeBusinessTokens.get(identityID, accessToken, now)
	if ok {
		return writeBusinessToken(doc, businessToken{Token: cached}, now)
	}
	ctx, cancel := context.WithTimeout(context.Background(), managedKeyExchangeTimeout)
	defer cancel()
	client := newSessionHTTPClient(currentConfig())
	defer client.CloseIdleConnections()
	exchanged, err := exchangeBusinessTokenWithExpiry(ctx, client, accessToken)
	if err != nil {
		// The Coding Plan credential is unaffected, so the login still
		// succeeds. The failure is recorded instead of discarded: it is the
		// only thing that tells the user their business-side access lapsed.
		return recordBusinessTokenFailure(doc, now)
	}
	activeBusinessTokens.put(identityID, accessToken, exchanged)
	return writeBusinessToken(doc, exchanged, now)
}

// oauthStoreReadTimeout bounds the host auth store round trip during login
// completion.
const oauthStoreReadTimeout = 10 * time.Second

// readPreviousAuthDoc finds the stored auth document of one identity. It
// fails only when the host auth store is broken for zcode records, which
// must abort the login instead of risking a credential-clobbering rewrite.
func readPreviousAuthDoc(ctx context.Context, identityID string) ([]byte, error) {
	entries, err := authStoreProvider().List(ctx)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.Provider != pluginID && entry.Type != pluginID {
			continue
		}
		if strings.TrimSpace(entry.AuthIndex) == "" {
			continue
		}
		doc, err := authStoreProvider().Get(ctx, entry.AuthIndex)
		if err != nil {
			return nil, err
		}
		if storedID, ok := readStoredIdentity(doc); ok && storedID == identityID {
			return doc, nil
		}
	}
	return nil, nil
}

// pollResponse builds a poll envelope with a human-readable status message.
func pollResponse(status pluginapi.AuthLoginStatus, message string, auth *pluginapi.AuthData) []byte {
	response := pluginapi.AuthLoginPollResponse{Status: status, Message: message}
	if auth != nil {
		response.Auth = *auth
	}
	raw, err := okEnvelope(response)
	if err != nil {
		return errorEnvelope("plugin_error", "could not encode login status", http.StatusInternalServerError)
	}
	return raw
}

// decodeJWTPayload extracts the unverified JWT claim set. Only non-sensitive
// routing claims are read; the signature is never validated here because the
// token is verified by the upstream API on every request.
func decodeJWTPayload(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return map[string]any{}
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return map[string]any{}
	}
	claims := map[string]any{}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return map[string]any{}
	}
	return claims
}

// identityClaimOrder lists the JWT claims considered as the stable upstream
// subject, most authoritative first.
var identityClaimOrder = []string{"sub", "uid", "user_id", "id"}

// maxIdentitySubjectLength caps how much of a raw subject may become part of
// the identity id before falling back to a digest.
const maxIdentitySubjectLength = 100

// identityDomainSeparator domain-separates the identity digest so a JWT can
// never collide with another hashed input by accident.
const identityDomainSeparator = "cpa-zcode-plugin/identity/v1"

// zcodeSubjectFromJWT resolves the stable, non-sensitive upstream subject
// used as the account identity. It fails when the JWT carries no subject
// claim: hashing the token would not be stable across re-logins and would
// silently mint a new host account per login, so such logins are refused.
func zcodeSubjectFromJWT(token string) (string, bool) {
	claims := decodeJWTPayload(token)
	for _, key := range identityClaimOrder {
		if value, ok := claims[key].(string); ok {
			if subject := strings.TrimSpace(value); subject != "" {
				if len(subject) > maxIdentitySubjectLength {
					return identityDigest(subject), true
				}
				return subject, true
			}
		}
	}
	return "", false
}

// identityDigest derives a digest for stable inputs that are too long or
// unsafe to use verbatim as a subject.
func identityDigest(value string) string {
	sum := sha256.Sum256([]byte(identityDomainSeparator + "\x00" + value))
	return hex.EncodeToString(sum[:16])
}

// identityIDFor renders the plugin's identity id from a subject.
func identityIDFor(subject string) string { return "zcode-" + subject }

// authFileNameFor derives a stable, filesystem-safe auth file name from an
// identity id so re-login reuses the same host account record.
func authFileNameFor(identityID string) string {
	sum := sha256.Sum256([]byte(identityID))
	return "zcode-" + hex.EncodeToString(sum[:8]) + ".json"
}

// buildZcodeStorage writes the plugin-owned zcode namespace of the host auth
// document for a fresh JWT login on top of the previous document. Unknown
// fields anywhere in the previous document survive the patch.
func buildZcodeStorage(previousDoc []byte, identityID, token, accessToken string, now time.Time) ([]byte, error) {
	namespace := map[string]any{
		"schema_version": 1,
		"identity_id":    identityID,
		"jwt": map[string]any{
			"token":           token,
			"status":          "active",
			"last_checked_at": now.UTC().Format(time.RFC3339),
		},
	}
	if accessToken != "" {
		// Kept for the managed API key exchange; without it the OAuth
		// session cleanup would lose the exchange material permanently.
		namespace["oauth"] = map[string]any{
			"access_token": accessToken,
			"received_at":  now.UTC().Format(time.RFC3339),
		}
	}
	return patchZcodeNamespace(previousDoc, func(zcode map[string]any) error {
		for key, value := range namespace {
			zcode[key] = value
		}
		return nil
	})
}

// authDataFromStorage renders the pluginapi.AuthData the host persists on
// successful login. StorageJSON carries the plugin-owned namespace document.
func authDataFromStorage(identityID string, storage []byte) pluginapi.AuthData {
	return pluginapi.AuthData{
		Provider:    pluginID,
		ID:          identityID,
		FileName:    authFileNameFor(identityID),
		Label:       zcodeAuthLabel,
		StorageJSON: storage,
	}
}

// authParseRPC mirrors the host request for auth.parse.
type authParseRPC struct {
	Provider string
	Path     string
	FileName string
	RawJSON  []byte
}

// handleAuthParse claims host auth documents that belong to this plugin and
// reconstructs the schedulable auth record from the zcode namespace. Foreign
// documents are left unhandled so other providers can claim them.
func handleAuthParse(request []byte) ([]byte, error) {
	var req authParseRPC
	if len(request) > 0 {
		if err := json.Unmarshal(request, &req); err != nil {
			return errorEnvelope("invalid_request", "decode auth.parse request: "+err.Error(), http.StatusBadRequest), nil
		}
	}
	if trimmed := strings.TrimSpace(req.Provider); trimmed != "" && trimmed != pluginID {
		return okEnvelope(pluginapi.AuthParseResponse{Handled: false})
	}
	identityID, ok := readStoredIdentity(req.RawJSON)
	if !ok {
		return okEnvelope(pluginapi.AuthParseResponse{Handled: false})
	}
	fileName := strings.TrimSpace(req.FileName)
	if fileName == "" {
		fileName = authFileNameFor(identityID)
	}
	return okEnvelope(pluginapi.AuthParseResponse{
		Handled: true,
		Auth: pluginapi.AuthData{
			Provider:    pluginID,
			ID:          identityID,
			FileName:    fileName,
			Label:       zcodeAuthLabel,
			StorageJSON: req.RawJSON,
		},
	})
}

// readStoredIdentity extracts the identity id from a stored auth document's
// zcode namespace, tolerating any host-owned fields around it.
func readStoredIdentity(doc []byte) (string, bool) {
	if len(bytes.TrimSpace(doc)) == 0 {
		return "", false
	}
	var root struct {
		Zcode struct {
			IdentityID string `json:"identity_id"`
			JWT        struct {
				Token string `json:"token"`
			} `json:"jwt"`
		} `json:"zcode"`
	}
	if err := json.Unmarshal(doc, &root); err != nil {
		return "", false
	}
	if strings.TrimSpace(root.Zcode.IdentityID) == "" || strings.TrimSpace(root.Zcode.JWT.Token) == "" {
		return "", false
	}
	return strings.TrimSpace(root.Zcode.IdentityID), true
}

// authRefreshRPC mirrors the host request for auth.refresh.
type authRefreshRPC struct {
	AuthID       string
	AuthProvider string
	StorageJSON  []byte
	Metadata     map[string]any
	Attributes   map[string]string
}

// handleAuthRefresh echoes the stored credential back unchanged. The Coding
// Plan JWT has no observed refresh flow, so refresh keeps the record valid
// instead of failing the host's refresh cycle.
func handleAuthRefresh(request []byte) ([]byte, error) {
	var req authRefreshRPC
	if len(request) > 0 {
		if err := json.Unmarshal(request, &req); err != nil {
			return errorEnvelope("invalid_request", "decode auth.refresh request: "+err.Error(), http.StatusBadRequest), nil
		}
	}
	provider := strings.TrimSpace(req.AuthProvider)
	if provider == "" {
		provider = pluginID
	}
	identityID := strings.TrimSpace(req.AuthID)
	fileName := ""
	if identityID != "" {
		fileName = authFileNameFor(identityID)
	}
	data := pluginapi.AuthData{
		Provider:    provider,
		ID:          identityID,
		StorageJSON: req.StorageJSON,
		Metadata:    req.Metadata,
		Attributes:  req.Attributes,
	}
	if identityID != "" {
		data.FileName = fileName
		data.Label = zcodeAuthLabel
	}
	return okEnvelope(pluginapi.AuthRefreshResponse{Auth: data})
}
