package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
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

// billingBalancePath is the only billing endpoint the plugin queries. The
// upstream deprecated billing/current, and its plans field is no longer
// authoritative for Start Plan availability, so the balance endpoint is the
// single source of both entitlement and quota. Its Authorization header is the
// bare Coding Plan JWT: the upstream explicitly rejects a Bearer-prefixed
// credential on this path.
const billingBalancePath = "/billing/balance"

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
	// Capabilities are the upstream's own declarations of what this balance
	// covers. Entries shaped "model:<id>" are the authoritative dynamic model
	// source for the identity, so they are read here rather than by a second
	// request the upstream has no endpoint for.
	Capabilities []string
	// Malformed marks a row that carried a wrong JSON type in a numeric
	// field. It contributes schema-incompatibility evidence but never balance
	// evidence.
	Malformed bool
}

// quotaVerdict is what the balance evidence says about the credential's
// entitlement. unknown means the response carried no explicit, well-typed
// evidence at all; noPlan and expired are positive readings of an account the
// upstream did describe, and are kept distinct from unknown so the management
// page can tell "this account has no plan" from "the plugin could not tell".
type quotaVerdict string

const (
	verdictUnknown   quotaVerdict = "unknown"
	verdictAvailable quotaVerdict = "available"
	verdictExhausted quotaVerdict = "exhausted"
	verdictNoPlan    quotaVerdict = "no_plan"
	verdictExpired   quotaVerdict = "expired"
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
	// Plans is the entitlement evidence itself. Its presence is what separates
	// an account without a Coding Plan from one whose quota could not be read.
	Plans    []quotaPlan
	Balances []quotaBalance

	Subscription *pluginapi.QuotaSubscription
	Summary      []pluginapi.QuotaMetric
	Groups       []pluginapi.QuotaGroup
}

// balanceURL builds the balance endpoint URL for one declared client version.
// The upstream decides Start Plan capability by the declared app_version, so
// the configured product version — not a constant — is what the query carries.
func balanceURL(appVersion string) string {
	query := url.Values{"app_version": []string{strings.TrimSpace(appVersion)}}
	return strings.TrimRight(zcodePlanBillingBase, "/") + billingBalancePath + "?" + query.Encode()
}

// quotaGet performs one bounded authenticated GET. The status is returned for
// every HTTP answer; transport errors return zero status and the error. The
// Authorization header is the bare Coding Plan JWT: this endpoint does not
// accept a Bearer prefix, and sending one is answered as though no credential
// were presented.
//
// deviceID must be a well-formed UUID. The endpoint gates on it and answers a
// request without one with 3001 "parameter error" — a rejection that reads as
// a malformed query rather than a missing header.
func quotaGet(ctx context.Context, url string, jwt string, deviceID string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", jwt)
	req.Header.Set("Accept", "application/json")
	req.Header.Set(deviceMidHeader, deviceID)
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
// something, and the class rules are the shared credentialRejectionClass —
// the same ruleset the Messages executor applies, so a billing rejection and
// a Messages rejection of the same credential always classify alike. The
// quota-specific codes and messages name the billing surface; everything else
// is a transport or schema concern, not a credential state.
func quotaAuthFailure(status int, body []byte) *upstreamFailure {
	// The verification requirement is settled first, for the same reason the
	// Messages path does it: it is a body-level conclusion about this credential
	// that must not be re-read as whatever status or business code accompanies
	// it, or a five-minute retry would become a permanent conclusion.
	if status == http.StatusForbidden && containsMarker(string(body), captchaMarkers) {
		return &upstreamFailure{
			Class:          failureVerificationBlocked,
			UpstreamStatus: status,
			Code:           "quota_verification_required",
			Message:        "upstream verification is required before the Coding Plan credential can be used; no verification is automated",
		}
	}
	// A business verdict is consulted next, for the same reason as on the
	// Messages path: this upstream carries business outcomes on statuses that
	// mean something else, so a 403 holding a request-level business code must
	// not be read as a credential rejection.
	if semantics, code, ok := zaiBusinessSemanticsFor(body); ok {
		class, movesCredential := failureClassForSemantics(semantics)
		if !movesCredential {
			// A request-level verdict on the billing call is a conclusion about
			// this refresh, not about the credential: it concludes nothing and
			// leaves the recorded state alone.
			return &upstreamFailure{
				Class:          failureRejected,
				UpstreamStatus: status,
				Code:           "quota_" + string(semantics),
				Message:        businessRejectionMessage(semantics, code, body),
			}
		}
		return &upstreamFailure{
			Class:          class,
			UpstreamStatus: status,
			Code:           "quota_" + string(semantics),
			Message:        businessRejectionMessage(semantics, code, body),
		}
	}
	class, rejected := credentialRejectionClass(status, string(body))
	if !rejected {
		return nil
	}
	switch class {
	case failureInvalid:
		return &upstreamFailure{
			Class:          failureInvalid,
			UpstreamStatus: status,
			Code:           "quota_credential_invalid",
			Message:        "upstream rejected the credential during the quota check; refresh it or complete the ZCode login again",
		}
	case failureExhausted:
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
// balance endpoint with the JWT credential. Authentication and the business
// verdict are settled before any field is read; only explicit, well-typed
// balance evidence produces a verdict. A verdict of unknown always carries a
// sanitized reason.
func fetchQuotaEvidence(ctx context.Context, jwt string, appVersion string, deviceID string, now time.Time) quotaEvidence {
	evidence := quotaEvidence{Verdict: verdictUnknown, SchemaCompatible: true}

	body, status, err := quotaGet(ctx, balanceURL(appVersion), jwt, deviceID)

	// The credential verdict is concluded before any body field is read: a
	// rejection of the billing call is a statement about the credential itself,
	// whatever the endpoint happens to report it in.
	if failure := quotaAuthFailure(status, body); failure != nil {
		evidence.AuthFailure = failure
		evidence.SchemaCompatible = false
		evidence.Reason = failure.Code
		return evidence
	}
	if err != nil || status < 200 || status >= 300 {
		evidence.SchemaCompatible = false
		evidence.Reason = quotaTransportReason(err, status)
		return evidence
	}
	// The upstream carries business failures inside HTTP 200 as readily as in
	// 4xx, so a 2xx is only usable evidence once the envelope agrees. Without
	// this check a "parameter error" delivered as 200 would read as an account
	// with no plans.
	if !zaiBusinessSuccess(body) {
		evidence.SchemaCompatible = false
		evidence.Reason = "upstream_reported_failure"
		return evidence
	}

	plans, plansCompatible := parseQuotaPlans(body, now)
	evidence.Plans = plans
	evidence.Plan = planNameFor(plans)
	if !plansCompatible {
		evidence.SchemaCompatible = false
		evidence.Reason = "upstream_schema_incompatible"
		return evidence
	}

	balances, compatible := parseQuotaBalances(body)
	evidence.Balances = balances
	if !compatible {
		evidence.SchemaCompatible = false
		evidence.Reason = "upstream_schema_incompatible"
		return evidence
	}

	evidence.Verdict, evidence.Reason = balanceVerdict(balances, plans)
	evidence.renderView()
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

// quotaPlan is one Coding Plan subscription row of the balance response. The
// upstream uses the plan's presence and status, not any balance row, to decide
// whether the account has a plan at all, so the list is kept as its own
// evidence rather than being collapsed into a display string.
type quotaPlan struct {
	Name string
	// Status is the plan's effective status after the term-end check, so it is
	// one of planStatusActive, planStatusExpired, or planStatusUnknown for every
	// plan the upstream described.
	Status string
	// EndsAt is the term end in epoch seconds, when the upstream states one.
	EndsAt *float64
}

// Plan statuses. Only an explicit "active" is a live plan: the upstream states
// the status on every plan row, so a plan read without one is evidence the
// plugin could not read, not a plan in good standing.
const (
	planStatusActive  = "active"
	planStatusExpired = "expired"
	planStatusUnknown = ""
)

// parseQuotaPlans reads data.plans from the balance body. The second result
// reports whether the envelope still matches the observed shape: data.plans
// must be a JSON array. An absent field is compatible and reads as no plans —
// the upstream omits it for accounts that have none, and that is an answer, not
// a schema change.
func parseQuotaPlans(body []byte, now time.Time) ([]quotaPlan, bool) {
	var parsed struct {
		Data struct {
			ServerTime json.Number     `json:"server_time"`
			Plans      json.RawMessage `json:"plans"`
		} `json:"data"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(body), &parsed); err != nil {
		return nil, false
	}
	trimmed := bytes.TrimSpace(parsed.Data.Plans)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil, true
	}
	if trimmed[0] != '[' {
		return nil, false
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(trimmed, &rows); err != nil {
		return nil, false
	}
	if len(rows) > maxQuotaBalanceRows {
		rows = rows[:maxQuotaBalanceRows]
	}
	plans := make([]quotaPlan, 0, len(rows))
	for _, row := range rows {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(bytes.TrimSpace(row), &fields); err != nil {
			return nil, false
		}
		plan := quotaPlan{}
		plan.Name, _ = optionalString(fields["name"])
		plan.Status, _ = optionalString(fields["status"])
		plan.EndsAt, _, _ = optionalNumber(fields["ends_at"])
		plan.Status = planStatusFor(plan, parsed.Data.ServerTime, now)
		plans = append(plans, plan)
	}
	return plans, true
}

// planStatusFor resolves a plan's effective status, and is the only place that
// decides whether a plan is in force.
//
// The upstream states "active" while the term has run out, so the term's own
// end is checked against the server's clock and an elapsed term reads as
// expired. The server's stated time is preferred over the local one so a clock
// skew between the plugin and the upstream cannot expire a live plan early or
// keep a dead one alive.
//
// A plan that states no status at all is not treated as live: the upstream
// always states one, so its absence means this refresh could not read the plan,
// and reading it as active would report an entitlement it has no evidence for.
func planStatusFor(plan quotaPlan, serverTime json.Number, now time.Time) string {
	status := normalizeStatus(plan.Status)
	reference := now
	if seconds, err := serverTime.Int64(); err == nil && seconds > 0 {
		reference = time.Unix(seconds, 0).UTC()
	}
	if status == planStatusActive && plan.EndsAt != nil && *plan.EndsAt > 0 {
		if end := time.Unix(int64(*plan.EndsAt), 0).UTC(); !end.After(reference) {
			return planStatusExpired
		}
	}
	if status == "" {
		return planStatusUnknown
	}
	return status
}

// planIsLive reports whether a plan is currently in force. Only an explicit
// "active" status is a live plan: the absence of a status is unreadable
// evidence, and reading it as live would report an entitlement the upstream
// never granted.
func planIsLive(plan quotaPlan) bool {
	return plan.Status == planStatusActive
}

// planNameFor renders the display name of the first plan that names itself.
// A plan with no name still proves a plan exists; it just cannot be labelled,
// so the entitlement reading never depends on the name being present.
func planNameFor(plans []quotaPlan) string {
	for _, plan := range plans {
		if plan.Name != "" {
			return plan.Name
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
	balance.ExpiresAt = quotaExpiryText(fields["expires_at"])
	if capabilities, ok := parseQuotaCapabilities(fields["capabilities"]); ok {
		balance.Capabilities = capabilities
	} else if fields["capabilities"] != nil {
		balance.Malformed = true
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

// quotaExpiryText renders a bucket's reset instant as the host's ResetTime
// string. The upstream states it as epoch seconds, which is a JSON number, so
// a plain string read drops it and the management page loses the reset time for
// every bucket. A quoted value is accepted too: it costs nothing to read both
// shapes rather than betting the field on one of them.
func quotaExpiryText(raw json.RawMessage) string {
	if text, ok := optionalString(raw); ok {
		return text
	}
	seconds, present, wellTyped := optionalNumber(raw)
	if !present || !wellTyped || seconds == nil {
		return ""
	}
	return time.Unix(int64(*seconds), 0).UTC().Format(time.RFC3339)
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

// maxQuotaCapabilitiesRows caps the capabilities of one balance row, so a
// drifted upstream cannot make a single refresh unbounded.
const maxQuotaCapabilitiesRows = 64

// parseQuotaCapabilities reads a row's capability list. ok is false only when
// the field is present and is not an array of strings — a schema change, which
// the row records as drift rather than as an empty capability set.
func parseQuotaCapabilities(raw json.RawMessage) ([]string, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil, true
	}
	if trimmed[0] != '[' {
		return nil, false
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(trimmed, &rows); err != nil {
		return nil, false
	}
	if len(rows) > maxQuotaCapabilitiesRows {
		rows = rows[:maxQuotaCapabilitiesRows]
	}
	capabilities := make([]string, 0, len(rows))
	for _, row := range rows {
		value, ok := optionalString(row)
		if !ok {
			// One non-string entry does not invalidate the others; the model
			// ids it does carry are still evidence.
			continue
		}
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			capabilities = append(capabilities, trimmed)
		}
	}
	return capabilities, true
}

// modelCapabilityPrefix is the capability spelling the upstream uses to declare
// that a balance covers a model. The remainder is the model id.
const modelCapabilityPrefix = "model:"

// balanceModelIDs renders the model ids one balance row declares. A row that
// declares none falls back to its display name, matching the upstream's own
// reading: a balance whose meter is a model is how the plan advertises that
// model even without an explicit capability entry. Ids are folded onto the
// official casing, matching the official client's own reading of the same
// capability list.
func balanceModelIDs(balance quotaBalance) []string {
	if balance.Malformed {
		// A row whose fields drifted is not evidence about what it covers.
		return nil
	}
	ids := make([]string, 0, len(balance.Capabilities))
	for _, capability := range balance.Capabilities {
		if !strings.HasPrefix(strings.ToLower(capability), modelCapabilityPrefix) {
			continue
		}
		if id := strings.TrimSpace(capability[len(modelCapabilityPrefix):]); id != "" {
			ids = append(ids, canonicalizeGLMModelID(id))
		}
	}
	if len(ids) == 0 {
		// A balance whose meter is a model is how the plan advertises that
		// model even without an explicit capability entry.
		if name := strings.TrimSpace(balance.Name); name != "" {
			ids = append(ids, canonicalizeGLMModelID(name))
		}
	}
	return ids
}

// balanceVerdict decides what the balance evidence says about the credential.
//
// The plan list is read first because it answers the question the balance rows
// cannot: an account with no plan has no quota to exhaust, and reporting that
// as "exhausted" would record a conclusion the upstream never made. A live plan
// with explicit zero remaining units is exhausted; the same plan with units
// left is available; rows that state no remaining value are unknown, because
// the plugin must never spell a verdict from missing data.
func balanceVerdict(balances []quotaBalance, plans []quotaPlan) (quotaVerdict, string) {
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
	live := false
	for _, plan := range plans {
		if planIsLive(plan) {
			live = true
			break
		}
	}
	switch {
	case sawMalformed && !any:
		return verdictUnknown, "upstream_schema_incompatible"
	case live && any && allZero:
		return verdictExhausted, ""
	case live && any:
		return verdictAvailable, ""
	case live:
		// A live plan whose rows state no remaining value: the subscription
		// exists, but this refresh cannot say what is left in it.
		return verdictUnknown, "no_explicit_balance_evidence"
	case len(plans) > 0:
		// Plans exist and none of them is in force.
		return verdictExpired, "plan_expired"
	case any:
		// Balance rows without a plan row: the numbers are the only evidence
		// there is, so they are read as such.
		if allZero {
			return verdictExhausted, ""
		}
		return verdictAvailable, ""
	default:
		// Neither a plan nor a balance row: the account has no Start Plan.
		// That is a real answer, distinct from not knowing.
		return verdictNoPlan, "no_plan"
	}
}

// renderView renders the normalized host/management view of the evidence into
// its Subscription, Summary, and Groups fields. Only explicit numbers are
// rendered; nothing defaults to zero.
func (e *quotaEvidence) renderView() {
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
		// The balance reading is explicit zero evidence, but it was gathered
		// before this write: a credential the Messages endpoint has since
		// rejected (invalid) must not be silently cleared by the older
		// reading, because invalid recovers through a credential refresh or a
		// re-login only. Cooldown, verification-blocked, and active states may
		// be overwritten — a billing endpoint that authenticated and reported
		// the balance is the stronger, fresher statement about those.
		return []recordedState{{
			Kind:        CredentialJWT,
			Status:      jwtStatusExhausted,
			Code:        "quota_exhausted",
			NotIfStatus: jwtStatusInvalid,
		}}
	case verdictExpired:
		// An elapsed term is a definitive conclusion about the subscription, and
		// unlike exhaustion it is not restored by reading the balance: the plan
		// itself has to be renewed. It is written unguarded because a refresh
		// that positively read an elapsed term is the strongest statement
		// available, and a credential already recorded as invalid must not be
		// revived by an older quota reading.
		return []recordedState{{
			Kind:        CredentialJWT,
			Status:      jwtStatusPlanExpired,
			Code:        "plan_expired",
			NotIfStatus: jwtStatusInvalid,
		}}
	case verdictAvailable:
		// Explicit positive balance restores an exhausted credential — the
		// recovery path the exhausted state exists for. The recovery is
		// guarded on the persisted status so it cannot overwrite a state that
		// changed while the upstream call ran: an invalid or verification-
		// blocked credential recovers through a credential refresh or a
		// re-login, which re-test it against the Messages endpoint. An elapsed
		// term is restored the same way, because only renewing the plan
		// changes that conclusion.
		return []recordedState{{
			Kind:         CredentialJWT,
			Status:       jwtStatusActive,
			Code:         "quota_recovered",
			OnlyIfStatus: jwtStatusExhausted,
		}, {
			Kind:         CredentialJWT,
			Status:       jwtStatusActive,
			Code:         "plan_renewed",
			OnlyIfStatus: jwtStatusPlanExpired,
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
	// State is the entitlement reading the page renders: "ok" (a plan with
	// quota), "exhausted", "no_plan", "plan_expired", "unknown" (the upstream
	// schema or answer was not readable), or "unavailable" (the credential was
	// rejected). "no_plan" and "plan_expired" are positive readings of an
	// account the upstream did describe, so they stay distinct from "unknown",
	// which means the plugin could not tell.
	State     string
	Reason    string
	CheckedAt time.Time
	Plan      string
	// PlanCount is how many plan rows the upstream reported, so the page can
	// tell an account with no plan from a plan it could not name.
	PlanCount int
	Balances  []quotaBalance
}

// observationFor derives the management view of one refresh's outcome.
func observationFor(evidence quotaEvidence, checkedAt time.Time) quotaObservation {
	observation := quotaObservation{
		CheckedAt: checkedAt,
		Plan:      evidence.Plan,
		PlanCount: len(evidence.Plans),
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
	case evidence.Verdict == verdictNoPlan:
		observation.State = "no_plan"
		observation.Reason = evidence.Reason
	case evidence.Verdict == verdictExpired:
		observation.State = "plan_expired"
		observation.Reason = evidence.Reason
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
	// AppVersion is the client version declared to the billing endpoint. It
	// travels with the scope rather than being read from the plugin-wide
	// config so one refresh is decided by the configuration snapshot the
	// caller was started with.
	AppVersion string
	// DeviceID is the identity token the billing endpoint gates on. It is
	// resolved once per refresh so a credential reports the same device across
	// restarts instead of appearing as a new install each time.
	DeviceID string
	Document []byte
}

// resolveQuotaScope reads the JWT credential a quota refresh authenticates
// with. hasJWT is false when the record is one of this plugin's but carries
// no JWT: the managed API key has no verified billing endpoint, so there is
// nothing to refresh and nothing to guess. A document without a plugin-owned
// identity is refused outright.
func resolveQuotaScope(authIndex string, storageJSON []byte, store AuthStore, cfg Config) (scope quotaRefreshScope, hasJWT bool, err error) {
	scope.AppVersion = normalizeConfig(cfg).Product.AppVersion
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
	if scope.DeviceID == "" {
		scope.DeviceID = deviceIdentity(scope.AuthIndex, scope.Document)
	}
	evidence := fetchQuotaEvidence(ctx, scope.JWT, scope.AppVersion, scope.DeviceID, now)
	diagf("quota auth=%s url=%s verdict=%s reason=%q plan=%q plans=[%s] balances=[%s]",
		scope.AuthIndex, balanceURL(scope.AppVersion), evidence.Verdict, evidence.Reason,
		evidence.Plan, diagPlanSummary(evidence.Plans), diagBalanceSummary(evidence.Balances))
	if failure := evidence.AuthFailure; failure != nil {
		diagf("quota auth=%s auth_failure upstream_status=%d class=%s code=%s msg=%q",
			scope.AuthIndex, failure.UpstreamStatus, failure.Class, failure.Code, failure.Message)
	}
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
	scope, hasJWT, err := resolveQuotaScope(req.AuthIndex, req.StorageJSON, store, currentConfig())
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
