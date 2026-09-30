package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// zcodePlanBillingBase is the Coding Plan billing origin the quota endpoints
// live under. It is a variable so tests can point the plugin at a local
// httptest server; public configuration deliberately exposes no base-URL
// override.
var zcodePlanBillingBase = "https://zcode.z.ai/api/v1/zcode-plan"

// Billing endpoint paths observed on the Coding Plan upstream. Both are plain
// authenticated GETs; the balance endpoint is the state evidence, the current
// endpoint only names the subscription.
const (
	billingCurrentPath = "/billing/current"
	billingBalancePath = "/billing/balance"
)

// quotaRequestTimeout bounds one quota refresh. It is a management-plane
// convenience, not request work: a slow billing upstream must delay neither
// executions nor the host's quota UI for long.
const quotaRequestTimeout = 20 * time.Second

// maxQuotaBodyBytes bounds each billing response body.
const maxQuotaBodyBytes int64 = 1 << 20

// maxQuotaBalanceRows caps how many balance rows are parsed, so a drifted
// upstream cannot make one refresh unbounded.
const maxQuotaBalanceRows = 32

// quotaHTTPClient performs the bounded billing calls. Its timeout covers the
// whole call; the response bodies are additionally size-limited at read time.
var quotaHTTPClient = &http.Client{Timeout: quotaRequestTimeout}

// quotaBalance is one parsed balance row. Only explicit numeric evidence is
// kept: a field the upstream omitted, or one whose type drifted from number,
// stays unknown instead of being coerced into a false zero.
type quotaBalance struct {
	Name      string
	Total     *float64
	Used      *float64
	Remaining *float64
	ExpiresAt string
	// Malformed marks a row that carried a wrong JSON type in a numeric
	// field. It contributes schema-incompatibility evidence but never balance
	// evidence.
	Malformed bool
}

// quotaVerdict is what the balance evidence says about the credential's
// remaining quota. verdictUnknown means the response carried no explicit,
// well-typed remaining value at all.
type quotaVerdict string

const (
	verdictUnknown   quotaVerdict = "unknown"
	verdictAvailable quotaVerdict = "available"
	verdictExhausted quotaVerdict = "exhausted"
)

// quotaEvidence is the sanitized outcome of one quota refresh: what the
// upstream concluded about the credential, what the balances said, and the
// normalized view both produce. It never carries an upstream body, a URL, or
// credential material.
type quotaEvidence struct {
	// AuthFailure is the classified credential conclusion when a billing
	// endpoint rejected the credential, or nil when authentication succeeded
	// or was not observable.
	AuthFailure *upstreamFailure
	Verdict     quotaVerdict
	// Reason explains an unknown verdict with a sanitized, bounded class.
	Reason string
	// SchemaCompatible reports whether the responses still match the observed
	// upstream shape.
	SchemaCompatible bool
	Plan             string
	Balances         []quotaBalance

	Subscription *pluginapi.QuotaSubscription
	Summary      []pluginapi.QuotaMetric
	Groups       []pluginapi.QuotaGroup
}

// quotaEndpointURL builds one billing endpoint URL.
func quotaEndpointURL(path string) string {
	return strings.TrimRight(zcodePlanBillingBase, "/") + path
}

// quotaGet performs one bounded authenticated GET. The status is returned for
// every HTTP answer; transport errors return zero status and the error.
func quotaGet(ctx context.Context, url string, jwt string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/json")
	resp, err := quotaHTTPClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer drainAndClose(resp.Body)
	body, err := readLimited(resp.Body, maxQuotaBodyBytes)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

// quotaAuthFailure maps one billing HTTP outcome onto the credential
// conclusion it implies. Only credential-rejecting statuses conclude
// something; the classification mirrors the Messages endpoint's rules — a
// captcha-bearing 403 is a verification block, any other 401/403 rejects the
// credential, and the 402 status itself is the payment verdict. Everything
// else is a transport or schema concern, not a credential state.
func quotaAuthFailure(status int, body []byte) *upstreamFailure {
	switch {
	case status == http.StatusForbidden && containsMarker(string(body), captchaMarkers):
		return &upstreamFailure{
			Class:          failureVerificationBlocked,
			UpstreamStatus: status,
			Code:           "quota_verification_required",
			Message:        "upstream verification is required before the Coding Plan credential can be used; no verification is automated",
		}
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return &upstreamFailure{
			Class:          failureInvalid,
			UpstreamStatus: status,
			Code:           "quota_credential_invalid",
			Message:        "upstream rejected the credential during the quota check; refresh it or complete the ZCode login again",
		}
	case status == http.StatusPaymentRequired:
		return &upstreamFailure{
			Class:          failureExhausted,
			UpstreamStatus: status,
			Code:           "quota_exhausted",
			Message:        "upstream quota is exhausted for this credential; refresh the quota to restore it",
		}
	default:
		return nil
	}
}

// fetchQuotaEvidence performs one quota refresh against the Coding Plan
// billing endpoints with the JWT credential. Authentication is checked before
// any field is read; only explicit, well-typed balance evidence produces a
// verdict. A verdict of unknown always carries a sanitized reason.
func fetchQuotaEvidence(ctx context.Context, jwt string) quotaEvidence {
	evidence := quotaEvidence{Verdict: verdictUnknown, SchemaCompatible: true}

	currentBody, currentStatus, currentErr := quotaGet(ctx, quotaEndpointURL(billingCurrentPath), jwt)
	balanceBody, balanceStatus, balanceErr := quotaGet(ctx, quotaEndpointURL(billingBalancePath), jwt)

	// Authentication is concluded before any body field is read: a rejection
	// of either billing call is a statement about the credential itself.
	if evidence.AuthFailure = quotaAuthFailure(currentStatus, currentBody); evidence.AuthFailure == nil {
		evidence.AuthFailure = quotaAuthFailure(balanceStatus, balanceBody)
	}
	if evidence.AuthFailure != nil {
		evidence.SchemaCompatible = false
		evidence.Reason = evidence.AuthFailure.Code
		return evidence
	}

	if currentErr == nil && currentStatus >= 200 && currentStatus < 300 {
		evidence.Plan = parseQuotaPlan(currentBody)
	}

	if balanceErr != nil || balanceStatus < 200 || balanceStatus >= 300 {
		evidence.SchemaCompatible = false
		evidence.Reason = quotaTransportReason(balanceErr, balanceStatus)
		return evidence
	}

	balances, compatible := parseQuotaBalances(balanceBody)
	evidence.Balances = balances
	if !compatible {
		evidence.SchemaCompatible = false
		evidence.Reason = "upstream_schema_incompatible"
		return evidence
	}

	evidence.Verdict, evidence.Reason = balanceVerdict(balances)
	evidence.finish()
	return evidence
}

// quotaTransportReason renders the sanitized reason for a refresh that never
// produced readable balance evidence.
func quotaTransportReason(err error, status int) string {
	if err != nil {
		return "upstream_unreachable"
	}
	return sanitizedDiscoveryStatus(status)
}

// parseQuotaPlan extracts the subscription name from the billing/current
// body. The plan is display-only evidence: any shape drift leaves it empty
// instead of failing the refresh.
func parseQuotaPlan(body []byte) string {
	var parsed struct {
		Data struct {
			Plans []json.RawMessage `json:"plans"`
		} `json:"data"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(body), &parsed); err != nil {
		return ""
	}
	if len(parsed.Data.Plans) == 0 {
		return ""
	}
	var name string
	if err := json.Unmarshal(parsed.Data.Plans[0], &name); err == nil {
		return strings.TrimSpace(name)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(parsed.Data.Plans[0], &fields); err != nil {
		return ""
	}
	for _, key := range []string{"name", "plan_name", "plan", "tier"} {
		if value, ok := optionalString(fields[key]); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// parseQuotaBalances reads the balance rows. The second result reports
// whether the envelope still matches the observed upstream shape: data.balances
// must be a JSON array of objects. Row-level type drift marks the row
// malformed instead of invalidating the envelope, so one drifted field cannot
// hide the evidence of the rows that still parse.
func parseQuotaBalances(body []byte) ([]quotaBalance, bool) {
	var parsed struct {
		Data struct {
			Balances json.RawMessage `json:"balances"`
		} `json:"data"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(body), &parsed); err != nil {
		return nil, false
	}
	trimmed := bytes.TrimSpace(parsed.Data.Balances)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, false
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(trimmed, &rows); err != nil {
		return nil, false
	}
	if len(rows) > maxQuotaBalanceRows {
		rows = rows[:maxQuotaBalanceRows]
	}
	balances := make([]quotaBalance, 0, len(rows))
	for _, row := range rows {
		balance, ok := parseQuotaBalanceRow(row)
		if !ok {
			return nil, false
		}
		balances = append(balances, balance)
	}
	return balances, true
}

// parseQuotaBalanceRow decodes one balance row. ok is false only when the row
// is not an object at all — a schema change, not a field-level drift.
func parseQuotaBalanceRow(row json.RawMessage) (quotaBalance, bool) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(bytes.TrimSpace(row), &fields); err != nil {
		return quotaBalance{}, false
	}
	balance := quotaBalance{Name: "model"}
	if name, ok := optionalString(fields["show_name"]); ok && name != "" {
		balance.Name = name
	} else if name, ok := optionalString(fields["model"]); ok && name != "" {
		balance.Name = name
	}
	if value, present := optionalString(fields["expires_at"]); present {
		balance.ExpiresAt = value
	}
	// A numeric field that is present but not a number leaves the pointer
	// nil while marking the row malformed: the drift is visible as schema
	// evidence, never as a silent zero.
	balance.Total, _, _ = optionalNumber(fields["total_units"])
	if balance.Total == nil && fields["total_units"] != nil {
		balance.Malformed = true
	}
	balance.Used, _, _ = optionalNumber(fields["used_units"])
	if balance.Used == nil && fields["used_units"] != nil {
		balance.Malformed = true
	}
	balance.Remaining, _, _ = optionalNumber(fields["remaining_units"])
	if balance.Remaining == nil && fields["remaining_units"] != nil {
		balance.Malformed = true
	}
	return balance, true
}

// optionalString reads an optional JSON string.
func optionalString(raw json.RawMessage) (string, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "", false
	}
	var value string
	if err := json.Unmarshal(trimmed, &value); err != nil {
		return "", false
	}
	return value, true
}

// optionalNumber reads an optional JSON number. present distinguishes an
// absent field from one that carried a wrong type, so type drift is visible
// as evidence of schema change instead of silently reading as zero. A quoted
// number is a type change, not a number: the decoder would happily accept
// "60" into json.Number, so quoted values are rejected before decoding.
func optionalNumber(raw json.RawMessage) (*float64, bool, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, false, true
	}
	if trimmed[0] == '"' {
		return nil, true, false
	}
	var number json.Number
	if err := json.Unmarshal(trimmed, &number); err != nil {
		return nil, true, false
	}
	value, err := number.Float64()
	if err != nil {
		return nil, true, false
	}
	return &value, true, true
}

// balanceVerdict decides what explicit balance evidence says about the
// credential. Only rows with a well-typed remaining_units are evidence: an
// empty list, or rows without any explicit remaining value, stay unknown —
// the plugin must never spell "exhausted" from missing data.
func balanceVerdict(balances []quotaBalance) (quotaVerdict, string) {
	sawMalformed := false
	any := false
	allZero := true
	for _, balance := range balances {
		if balance.Malformed {
			sawMalformed = true
		}
		if balance.Remaining == nil {
			continue
		}
		any = true
		if *balance.Remaining > 0 {
			allZero = false
		}
	}
	switch {
	case !any:
		if sawMalformed {
			return verdictUnknown, "upstream_schema_incompatible"
		}
		return verdictUnknown, "no_explicit_balance_evidence"
	case allZero:
		return verdictExhausted, ""
	default:
		return verdictAvailable, ""
	}
}

// finish renders the normalized management view of the evidence: the
// subscription summary and the per-balance metrics and buckets. Only explicit
// numbers are rendered; nothing defaults to zero.
func (e *quotaEvidence) finish() {
	if e.Plan != "" {
		e.Subscription = &pluginapi.QuotaSubscription{Plan: e.Plan}
	}
	for _, balance := range e.Balances {
		if balance.Malformed {
			continue
		}
		if value := balance.Remaining; value != nil {
			e.Summary = append(e.Summary, pluginapi.QuotaMetric{
				Key:    "remaining:" + balance.Name,
				Label:  balance.Name + " remaining",
				Value:  *value,
				Format: "number",
			})
		}
		if value := balance.Used; value != nil {
			e.Summary = append(e.Summary, pluginapi.QuotaMetric{
				Key:    "used:" + balance.Name,
				Label:  balance.Name + " used",
				Value:  *value,
				Format: "number",
			})
		}
		// A bucket needs both ends of the window; a remaining value without a
		// total would render as a misleading fraction, so it stays in the
		// flat metrics only.
		if balance.Remaining != nil && balance.Total != nil && *balance.Total > 0 {
			e.Groups = append(e.Groups, pluginapi.QuotaGroup{
				DisplayName: balance.Name,
				Buckets: []pluginapi.QuotaBucket{{
					Window:            balance.Name,
					RemainingFraction: *balance.Remaining / *balance.Total,
					ResetTime:         balance.ExpiresAt,
				}},
			})
		}
	}
}

// response renders the host quota.fetch result.
func (e *quotaEvidence) response() pluginapi.QuotaFetchResponse {
	return pluginapi.QuotaFetchResponse{
		Subscription: e.Subscription,
		Summary:      e.Summary,
		Groups:       e.Groups,
	}
}

// quotaStateUpdates turns quota evidence into the credential conclusions it
// implies. The JWT is the credential that authenticates the billing
// endpoints, so only its state is ever touched: the managed API key has no
// verified billing endpoint, and a conclusion about one credential must never
// move the other. Evidence that is not explicit — an unknown verdict, a
// schema drift, a transport failure — concludes nothing.
func quotaStateUpdates(evidence quotaEvidence, now time.Time) []recordedState {
	if failure := evidence.AuthFailure; failure != nil {
		return []recordedState{conclusionFor(CredentialJWT, failure, now)}
	}
	switch evidence.Verdict {
	case verdictExhausted:
		return []recordedState{{
			Kind:   CredentialJWT,
			Status: jwtStatusExhausted,
			Code:   "quota_exhausted",
		}}
	case verdictAvailable:
		// Explicit positive balance restores an exhausted credential — the
		// recovery path the exhausted state exists for. The recovery is
		// guarded on the persisted status so it cannot overwrite a state that
		// changed while the upstream call ran: an invalid or verification-
		// blocked credential recovers through a credential refresh or a
		// re-login, which re-test it against the Messages endpoint.
		return []recordedState{{
			Kind:         CredentialJWT,
			Status:       jwtStatusActive,
			Code:         "quota_recovered",
			OnlyIfStatus: jwtStatusExhausted,
		}}
	default:
		return nil
	}
}

// quotaObservation is the management-plane record of the last quota refresh
// for one identity. It is kept in memory only: it is a live operational
// reading, and persisting it would grow the credential document for
// information the page can refresh on demand.
type quotaObservation struct {
	State     string // "ok" | "exhausted" | "unknown" | "unavailable"
	Reason    string
	CheckedAt time.Time
	Plan      string
	Balances  []quotaBalance
}

// observationFor derives the management view of one refresh's outcome.
func observationFor(evidence quotaEvidence, checkedAt time.Time) quotaObservation {
	observation := quotaObservation{
		CheckedAt: checkedAt,
		Plan:      evidence.Plan,
		Balances:  evidence.Balances,
	}
	switch {
	case evidence.AuthFailure != nil:
		observation.State = "unavailable"
		observation.Reason = evidence.AuthFailure.Code
	case evidence.Verdict == verdictAvailable:
		observation.State = "ok"
	case evidence.Verdict == verdictExhausted:
		observation.State = "exhausted"
	default:
		observation.State = "unknown"
		observation.Reason = evidence.Reason
	}
	return observation
}

// quotaCache remembers the last quota observation per identity for the
// management plane. It mirrors the model catalog's role: runtime state the
// page displays and refreshes, never a source of truth about credentials.
type quotaCache struct {
	mu      sync.Mutex
	entries map[string]quotaObservation
}

func newQuotaCache() *quotaCache {
	return &quotaCache{entries: map[string]quotaObservation{}}
}

func (c *quotaCache) put(identity string, observation quotaObservation) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[identity] = observation
}

func (c *quotaCache) get(identity string) (quotaObservation, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	observation, ok := c.entries[identity]
	return observation, ok
}

// activeQuotaCache is the plugin-wide quota observation cache.
var activeQuotaCache = newQuotaCache()

// errNoJWTForQuota reports that a quota refresh found no Coding Plan JWT to
// authenticate with. The managed API key has no verified billing endpoint, so
// the refresh is refused rather than guessed.
var errNoJWTForQuota = errors.New("no Coding Plan JWT credential to check quota with")

// quotaRefreshScope carries what one quota refresh needs: the auth record the
// conclusions belong to, the identity the observation is cached under, and
// the JWT that authenticates the billing endpoints.
type quotaRefreshScope struct {
	AuthIndex  string
	IdentityID string
	JWT        string
	Document   []byte
}

// resolveQuotaScope reads the JWT credential a quota refresh authenticates
// with. hasJWT is false when the record is one of this plugin's but carries
// no JWT: the managed API key has no verified billing endpoint, so there is
// nothing to refresh and nothing to guess. A document without a plugin-owned
// identity is refused outright.
func resolveQuotaScope(authIndex string, storageJSON []byte, store AuthStore) (scope quotaRefreshScope, hasJWT bool, err error) {
	scope.AuthIndex = strings.TrimSpace(authIndex)
	doc := bytes.TrimSpace(storageJSON)
	if len(doc) == 0 && scope.AuthIndex != "" {
		if doc, err = store.Get(context.Background(), scope.AuthIndex); err != nil {
			return scope, false, err
		}
		doc = bytes.TrimSpace(doc)
	}
	if len(doc) == 0 {
		return scope, false, errNoCredential
	}
	var root struct {
		Zcode struct {
			IdentityID string `json:"identity_id"`
			JWT        struct {
				Token string `json:"token"`
			} `json:"jwt"`
		} `json:"zcode"`
	}
	if err := json.Unmarshal(doc, &root); err != nil || strings.TrimSpace(root.Zcode.IdentityID) == "" {
		// A document this plugin does not own is never read for credentials
		// and never written to.
		return scope, false, errAuthDocument
	}
	scope.IdentityID = strings.TrimSpace(root.Zcode.IdentityID)
	scope.JWT = strings.TrimSpace(root.Zcode.JWT.Token)
	scope.Document = doc
	return scope, scope.JWT != "", nil
}

// runQuotaRefresh fetches, decides, records, and caches one account's quota.
// The returned evidence is sanitized and safe to embed in management
// responses. State conclusions land through the shared credential recorder,
// which re-reads and re-serializes the document inside the identity lock; a
// write loss is reported but never hides the fetched evidence.
func runQuotaRefresh(ctx context.Context, store AuthStore, scope quotaRefreshScope, now time.Time) (quotaEvidence, error) {
	if scope.JWT == "" {
		return quotaEvidence{Verdict: verdictUnknown, Reason: "no_jwt_credential"}, errNoJWTForQuota
	}
	evidence := fetchQuotaEvidence(ctx, scope.JWT)
	recordErr := credentialStates.forStore(store).record(ctx, credentialRef{
		AuthIndex:  scope.AuthIndex,
		IdentityID: scope.IdentityID,
		Document:   scope.Document,
	}, quotaStateUpdates(evidence, now)...)
	if scope.IdentityID != "" {
		activeQuotaCache.put(scope.IdentityID, observationFor(evidence, now))
	}
	return evidence, recordErr
}

// handleQuotaIdentifier answers the host's quota provider discovery call.
func handleQuotaIdentifier() ([]byte, error) {
	return okEnvelope(struct {
		Identifier string `json:"identifier"`
	}{Identifier: pluginID})
}

// handleQuotaDescribe declares the provider keys this quota provider answers
// for. ZCode credentials have no upstream reset endpoint, so reset is
// declared unsupported.
func handleQuotaDescribe() ([]byte, error) {
	return okEnvelope(pluginapi.QuotaDescribeResponse{
		SupportedProviders: []string{pluginID},
		DisplayName:        "ZCode",
		SupportsReset:      false,
	})
}

// handleQuotaFetch serves the host's normalized quota query for one
// credential. The refresh records credential state only on explicit evidence;
// an unknown or schema-drifted upstream answer leaves the credential alone
// and reports unknown.
func handleQuotaFetch(request []byte) ([]byte, error) {
	var req pluginapi.QuotaFetchRequest
	if len(request) > 0 {
		if err := json.Unmarshal(request, &req); err != nil {
			return errorEnvelope("invalid_request", "decode quota.fetch request: "+err.Error(), http.StatusBadRequest), nil
		}
	}
	if provider := strings.TrimSpace(req.Provider); provider != "" && provider != pluginID {
		return errorEnvelope("unknown_provider", "quota.fetch does not handle provider "+provider, http.StatusBadRequest), nil
	}
	store := authStoreProvider()
	scope, hasJWT, err := resolveQuotaScope(req.AuthIndex, req.StorageJSON, store)
	if err != nil || !hasJWT {
		// A credential the plugin cannot read or cannot check is reported as
		// an empty quota answer, not as an upstream failure: the host UI
		// renders nothing rather than an error for a record that was never
		// ours or has no verifiable billing surface.
		return okEnvelope(pluginapi.QuotaFetchResponse{})
	}
	ctx, cancel := context.WithTimeout(context.Background(), quotaRequestTimeout)
	defer cancel()
	evidence, _ := runQuotaRefresh(ctx, store, scope, time.Now())
	return okEnvelope(evidence.response())
}

// handleQuotaReset declines the reset operation. The upstream exposes no
// reset endpoint for Coding Plan credentials, so declaring one would be a
// lie in the management UI.
func handleQuotaReset(request []byte) ([]byte, error) {
	var req pluginapi.QuotaResetRequest
	if len(request) > 0 {
		if err := json.Unmarshal(request, &req); err != nil {
			return errorEnvelope("invalid_request", "decode quota.reset request: "+err.Error(), http.StatusBadRequest), nil
		}
	}
	if provider := strings.TrimSpace(req.Provider); provider != "" && provider != pluginID {
		return errorEnvelope("unknown_provider", "quota.reset does not handle provider "+provider, http.StatusBadRequest), nil
	}
	return okEnvelope(pluginapi.QuotaResetResponse{
		Success: false,
		Message: "quota reset is not supported for ZCode credentials",
	})
}
