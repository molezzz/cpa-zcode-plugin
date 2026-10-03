package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
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
	// Meter and UnitType are the upstream's own reading of what this bucket
	// counts. They are the only thing that makes a bare unit count legible:
	// 59534117 means model tokens, tool calls, or nothing at all depending on
	// the meter, and a row the upstream named nothing about stays blank rather
	// than being called "model".
	Meter    string
	UnitType string
	// EntitlementID names the grant this bucket spends, which is how a bucket
	// inherits the period and granted amount its own row does not repeat.
	EntitlementID string
	// PlanID and UserPlanID say which plan this bucket draws from. The bucket's
	// billing axis is this pair, not the bucket: one product sold twice yields
	// two plans sharing a PlanID, so UserPlanID is what tells their buckets
	// apart. Both are kept because they are the only keys a bucket's owning
	// plan row can be matched on, and a bucket the plugin cannot place is
	// reported on its own rather than folded into a plan that may be a
	// different billing axis.
	PlanID     string
	UserPlanID string
	// Period is the bucket's recurrence, as the upstream spells it. The
	// balance rows of the observed response state no period of their own, so
	// this is folded in from the entitlement that granted the bucket; the
	// one_time and recurring shapes are read differently on the management
	// page, so an unread period stays unknown.
	Period string
	// GrantUnits is the amount the entitlement granted, when it stated one. It
	// is not the bucket total: a bucket's own total_units is what it may spend
	// now, and the two differ whenever the grant is larger than one window.
	GrantUnits *float64
	// PeriodStart and PeriodEnd are the window the current numbers belong to.
	// A recurring bucket restarts at PeriodEnd; a one-time grant does not.
	PeriodStart *float64
	PeriodEnd   *float64
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

	balances, compatible := parseQuotaBalancesWithPlans(body, plans)
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
	// PlanID and UserPlanID are the two keys a balance row names its owner by.
	// PlanID is the product, UserPlanID the individual subscription instance:
	// one product sold twice shares a PlanID and differs by UserPlanID, so the
	// user plan id is what makes two live instances distinguishable and the
	// product id is only the fallback for a row that states no instance.
	PlanID     string
	UserPlanID string
	// Status is the plan's effective status after the term-end check, so it is
	// one of planStatusActive, planStatusExpired, or planStatusUnknown for every
	// plan the upstream described.
	Status string
	// EndsAt is the term end in epoch seconds, when the upstream states one.
	EndsAt *float64
	// Entitlements are the grants the plan issued. They are kept because they
	// are where the upstream states a bucket's period and granted amount —
	// the balance rows the grants turned into carry the numbers but not the
	// semantics.
	Entitlements []quotaEntitlement
}

// quotaEntitlement is one grant inside a plan. The balance rows that spend it
// name it by entitlement_id, which is what lets a bucket inherit the semantics
// its own row does not repeat.
type quotaEntitlement struct {
	EntitlementID string
	// ShowName and Meter are alternative readings of the same thing; the
	// bucket resolves its own label, so only the meter and unit matter here.
	Meter    string
	UnitType string
	Period   string
	// GrantUnits is what the entitlement granted. It stays unknown when the
	// upstream states no amount, which is not the same as granting zero.
	GrantUnits *float64
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
		plan.PlanID, _ = optionalString(fields["plan_id"])
		plan.UserPlanID, _ = optionalString(fields["user_plan_id"])
		plan.Status, _ = optionalString(fields["status"])
		plan.EndsAt, _, _ = optionalNumber(fields["ends_at"])
		plan.Entitlements = parseQuotaEntitlements(fields["entitlements"])
		plan.Status = planStatusFor(plan, parsed.Data.ServerTime, now)
		plans = append(plans, plan)
	}
	return plans, true
}

// maxQuotaEntitlementRows caps the grants read from one plan, so a drifted
// upstream cannot make one plan unbounded.
const maxQuotaEntitlementRows = 32

// parseQuotaEntitlements reads a plan's grants. A missing or null list is an
// empty one — a plan can be in force without spelling its grants — and a field
// that drifted away from an array of objects is dropped rather than
// invalidating the plan row, because the plan's own status is what decides
// whether the account has an entitlement at all.
func parseQuotaEntitlements(raw json.RawMessage) []quotaEntitlement {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" || trimmed[0] != '[' {
		return nil
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(trimmed, &rows); err != nil {
		return nil
	}
	if len(rows) > maxQuotaEntitlementRows {
		rows = rows[:maxQuotaEntitlementRows]
	}
	entitlements := make([]quotaEntitlement, 0, len(rows))
	for _, row := range rows {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(bytes.TrimSpace(row), &fields); err != nil {
			continue
		}
		entitlement := quotaEntitlement{}
		entitlement.EntitlementID, _ = optionalString(fields["entitlement_id"])
		entitlement.Meter, _ = optionalString(fields["meter"])
		entitlement.UnitType, _ = optionalString(fields["unit_type"])
		entitlement.Period, _ = optionalString(fields["period"])
		entitlement.GrantUnits, _, _ = optionalNumber(fields["grant_units"])
		entitlements = append(entitlements, entitlement)
	}
	return entitlements
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
	return parseQuotaBalancesWithPlans(body, nil)
}

// parseQuotaBalancesWithPlans reads the balance rows and folds in the
// semantics each row's granting entitlement stated. The observed response
// repeats the meter and unit on the row but states the period and the granted
// amount only on the entitlement, so a row read on its own cannot answer "how
// often does this come back".
func parseQuotaBalancesWithPlans(body []byte, plans []quotaPlan) ([]quotaBalance, bool) {
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
	grants := entitlementIndex(plans)
	balances := make([]quotaBalance, 0, len(rows))
	for _, row := range rows {
		balance, ok := parseQuotaBalanceRow(row)
		if !ok {
			return nil, false
		}
		balance.inheritEntitlement(grants)
		balances = append(balances, balance)
	}
	return balances, true
}

// entitlementIndex collects every plan's grants under the id the balance rows
// name them by. An id stated by two plans keeps the first: the upstream orders
// its rows by priority, and a duplicated id is not a second bucket.
func entitlementIndex(plans []quotaPlan) map[string]quotaEntitlement {
	index := map[string]quotaEntitlement{}
	for _, plan := range plans {
		for _, entitlement := range plan.Entitlements {
			id := strings.TrimSpace(entitlement.EntitlementID)
			if id == "" {
				continue
			}
			if _, exists := index[id]; !exists {
				index[id] = entitlement
			}
		}
	}
	return index
}

// inheritEntitlement fills the fields a balance row left unread from the grant
// that produced it. A row's own reading always wins: the grant states what was
// given, the bucket states what is left of it.
func (b *quotaBalance) inheritEntitlement(grants map[string]quotaEntitlement) {
	if len(grants) == 0 {
		return
	}
	grant, ok := grants[strings.TrimSpace(b.EntitlementID)]
	if !ok {
		return
	}
	if b.Meter == "" {
		b.Meter = grant.Meter
	}
	if b.UnitType == "" {
		b.UnitType = grant.UnitType
	}
	if b.Period == "" {
		b.Period = grant.Period
	}
	if b.GrantUnits == nil {
		b.GrantUnits = grant.GrantUnits
	}
}

// parseQuotaBalanceRow decodes one balance row. ok is false only when the row
// is not an object at all — a schema change, not a field-level drift.
func parseQuotaBalanceRow(row json.RawMessage) (quotaBalance, bool) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(bytes.TrimSpace(row), &fields); err != nil {
		return quotaBalance{}, false
	}
	balance := quotaBalance{}
	if name, ok := optionalString(fields["show_name"]); ok && name != "" {
		balance.Name = name
	} else if name, ok := optionalString(fields["model"]); ok && name != "" {
		balance.Name = name
	}
	balance.EntitlementID, _ = optionalString(fields["entitlement_id"])
	balance.PlanID, _ = optionalString(fields["plan_id"])
	balance.UserPlanID, _ = optionalString(fields["user_plan_id"])
	// A textual field that drifted is dropped rather than guessed at, and the
	// row still stands: it describes a real bucket, and only its label or unit
	// is unreadable. That is why these do not mark the row the way a drifted
	// number does — the numbers are what a drifted row would leave the page
	// nothing to show.
	balance.Meter, _ = optionalString(fields["meter"])
	balance.UnitType, _ = optionalString(fields["unit_type"])
	balance.Period, _ = optionalString(fields["period"])
	balance.ExpiresAt = quotaExpiryText(fields["expires_at"])
	if capabilities, ok := parseQuotaCapabilities(fields["capabilities"]); ok {
		balance.Capabilities = capabilities
	} else if fields["capabilities"] != nil {
		balance.Malformed = true
	}
	// A numeric field that is present but not a number leaves the pointer
	// nil while marking the row malformed: the drift is visible as schema
	// evidence, never as a silent zero.
	for _, field := range []struct {
		key  string
		slot **float64
	}{
		{"total_units", &balance.Total},
		{"used_units", &balance.Used},
		{"remaining_units", &balance.Remaining},
		{"grant_units", &balance.GrantUnits},
		{"period_start", &balance.PeriodStart},
		{"period_end", &balance.PeriodEnd},
	} {
		value, _, _ := optionalNumber(fields[field.key])
		*field.slot = value
		if value == nil && fields[field.key] != nil {
			balance.Malformed = true
		}
	}
	return balance, true
}

// balanceDisplayName renders one bucket's label from the upstream's own
// semantics. A bucket that names itself is shown by that name; one that does
// not is shown by what it meters and in what unit, which is strictly more
// information than the literal "model" this used to invent — that literal was
// neither a model nor a unit and reached the page as the label of every
// capability-less bucket. A bucket the upstream described nothing about has no
// label to render, and stays blank rather than being given a placeholder that
// reads like one.
func balanceDisplayName(balance quotaBalance) string {
	if name := strings.TrimSpace(balance.Name); name != "" {
		return name
	}
	meter := strings.TrimSpace(balance.Meter)
	unit := strings.TrimSpace(balance.UnitType)
	switch {
	case meter != "" && unit != "":
		return meter + "(" + unit + ")"
	case meter != "":
		return meter
	case unit != "":
		return unit
	default:
		return ""
	}
}

// balanceRemainingFraction is the one reading of "how much is left": the
// bucket's remaining share of its own total, clamped into [0,1]. Both the host
// group and the management page render this value, so the page cannot disagree
// with the host about how much is left.
//
// The fraction is unknown, not zero, whenever either end is missing or the row
// drifted: a share of nothing says nothing about how much remains, and a
// drifted row is not evidence about its numbers at all.
func balanceRemainingFraction(balance quotaBalance) (float64, bool) {
	if balance.Malformed || balance.Remaining == nil || balance.Total == nil {
		return 0, false
	}
	if *balance.Total <= 0 {
		return 0, false
	}
	return math.Max(0, math.Min(1, *balance.Remaining / *balance.Total)), true
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

// optionalString reads an optional JSON string. The value is trimmed of the
// whitespace a JSON document may carry inside its strings, so callers compare
// identity fields directly without each trimming again.
func optionalString(raw json.RawMessage) (string, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "", false
	}
	var value string
	if err := json.Unmarshal(trimmed, &value); err != nil {
		return "", false
	}
	return strings.TrimSpace(value), true
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
		// model even without an explicit capability entry — but only when the
		// upstream named it. A bucket labelled by its meter and unit instead
		// ("model_usage(token)") carries no model: it is the plan's billing
		// shape, not a model id, and admitting it would put a non-model into
		// the dynamic catalog.
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

// Start Plan identity markers. The upstream spells the plan in its id
// ("zcode-v3-start-plan-1003") and in its display name ("ZCode V3 Start
// Plan"), so either surface can carry the identity and both spellings of the
// separator occur. This mirrors the official client's own reading
// (docs/ZCode packages/services/src/model-provider/
// codingPlanProviderAvailability.ts isZaiStartPlanIdentity): Start Plan and the
// general Coding Plan are separate billing axes, and recognizing only the exact
// id would read a live Start Plan as a Coding Plan and merge the two.
const (
	startPlanIdentityMarker = "start-plan"
	startPlanNameMarker     = "start plan"
)

// isStartPlanPlan reports whether a plan is a Start Plan rather than the
// general Coding Plan. A plan stating neither an id nor a name is not claimed
// either way: the caller decides what an unreadable identity means, and only
// the id and the name are evidence here.
func isStartPlanPlan(plan quotaPlan) bool {
	for _, value := range []string{plan.PlanID, plan.Name} {
		if lowered := strings.ToLower(value); lowered != "" &&
			(strings.Contains(lowered, startPlanIdentityMarker) || strings.Contains(lowered, startPlanNameMarker)) {
			return true
		}
	}
	return false
}

// Plan group kinds. They name the billing axis a bucket's numbers belong to, so
// an operator can tell a Start Plan allowance from a general Coding Plan
// allowance without reading either plan's details.
const (
	planGroupStartPlan  = "start_plan"
	planGroupCodingPlan = "coding_plan"
	planGroupUnassigned = "unassigned"
)

// quotaGroup is one billing axis's buckets: the plan they belong to, and every
// bucket that plan's own reading said was available. Grouping exists because a
// flat bucket list cannot tell two plans' allowances apart, and an operator
// cannot act on "18%" without knowing which of them is about to run out.
//
// A group is identified by its position, never by its label: two plans can
// share a display name — an unnamed plan falls back to the key that identifies
// it, and nothing stops two rows from sharing one — so a label-keyed join would
// merge two separate allowances into a single heading.
type quotaGroup struct {
	// Label is the group's display name: the plan's own name where it has one,
	// otherwise the key the group's buckets were matched on. It names the axis
	// for a reader; it does not identify it.
	Label string
	// Kind is the billing axis the group belongs to.
	Kind string
	// Balances are the group's buckets in the order the upstream listed them.
	Balances []quotaBalance
}

// placeBucketsByPlan groups the buckets by the plan that granted them, and
// reports each bucket's group index alongside. Callers that only need the
// groups discard the axis; it is a second return value because the management
// page joins each bucket to its group by position, not by label.
//
// Ownership follows the upstream's own rule, evaluated per bucket-and-plan
// pair rather than through an index: when both rows state a user plan id they
// are compared on it, and otherwise they are compared on the product id. That
// asymmetry is what keeps two live instances of one product apart — both
// instances share a product id, so a comparison on it alone would put their
// buckets under whichever plan was read first, merging two separate
// allowances into one number.
//
// A bucket no plan claims is never folded into the plans that are present: its
// owning plan may simply have been omitted from the response, and attaching its
// numbers to a different plan would report the wrong billing axis. It forms
// its own group, named by the key the upstream did give it.
//
// The per-bucket result is a group index rather than a label because labels are
// not unique: two plans may share a display name, and a caller that rejoined
// buckets to groups by label would merge them. The index is positional and
// unambiguous.
func placeBucketsByPlan(plans []quotaPlan, balances []quotaBalance) ([]quotaGroup, []int) {
	groups := []quotaGroup{}
	// matched is keyed by plan position, so two plans sharing a display name
	// stay separate groups. Orphans are keyed under their own plan key and
	// never collide with one.
	matched := make([]int, len(plans))
	for i := range matched {
		matched[i] = -1
	}
	orphans := map[string]int{}
	axis := make([]int, len(balances))
	for i, balance := range balances {
		at := -1
		for j, plan := range plans {
			if !planGrantsBucket(plan, balance) {
				continue
			}
			if matched[j] >= 0 {
				at = matched[j]
				break
			}
			groups = append(groups, quotaGroup{
				Label: planGroupLabel(plan),
				Kind:  planGroupKind(plan),
			})
			matched[j], at = len(groups)-1, len(groups)-1
			break
		}
		if at < 0 {
			key := unassignedGroupKey(balance)
			existing, seen := orphans[key]
			if !seen {
				groups = append(groups, quotaGroup{Label: key, Kind: planGroupUnassigned})
				existing = len(groups) - 1
				orphans[key] = existing
			}
			at = existing
		}
		axis[i] = at
		groups[at].Balances = append(groups[at].Balances, balance)
	}
	return groups, axis
}

// planGrantsBucket reports whether a plan is the one a bucket's numbers come
// from, by the upstream's own comparison: the instance id when both rows state
// one, the product id otherwise.
//
// The product-id branch requires the plan to state one. The upstream's own
// rule compares the bare ids, under which two rows that both state none would
// match and their buckets would fold into one plan; requiring the plan's id is
// a deliberate divergence, because a plan with no readable identity has no
// evidence it granted anything, and an idless bucket already has its own
// unassigned group.
func planGrantsBucket(plan quotaPlan, balance quotaBalance) bool {
	if plan.UserPlanID != "" && balance.UserPlanID != "" {
		return plan.UserPlanID == balance.UserPlanID
	}
	return plan.PlanID != "" && plan.PlanID == balance.PlanID
}

// planGroupKind names the billing axis a plan's group belongs to.
//
// A plan whose identity the plugin could read is classified by that identity.
// A plan that states neither an id nor a name has no identity to classify, so
// it is left unassigned rather than assumed to be the general Coding Plan:
// reading an unreadable plan as the coding axis is precisely the mislabeling
// this grouping exists to prevent, and the official client treats the same
// unreadable case as unproven rather than as one axis or the other.
//
// The readable case knows of exactly two axes: any readable plan that is not a
// Start Plan is the general Coding Plan. A third plan kind the upstream later
// introduces would land on the coding axis until this switch learns it.
func planGroupKind(plan quotaPlan) string {
	switch {
	case isStartPlanPlan(plan):
		return planGroupStartPlan
	case plan.PlanID != "" || plan.Name != "":
		return planGroupCodingPlan
	default:
		return planGroupUnassigned
	}
}

// planGroupLabel renders the display name of a plan's group: the plan's own
// name where it states one, and the key that identifies it otherwise. An
// unnamed plan is still a real axis, so it is named by its id rather than
// dropped or given a placeholder.
func planGroupLabel(plan quotaPlan) string {
	if plan.Name != "" {
		return plan.Name
	}
	if plan.UserPlanID != "" {
		return plan.UserPlanID
	}
	return plan.PlanID
}

// unassignedGroupKey names the group of a bucket no plan claimed, by the key
// the bucket itself stated. Buckets that stated no key at all share one group,
// which is honest: the plugin cannot tell them apart, and inventing a split
// would suggest a distinction the evidence does not carry.
func unassignedGroupKey(balance quotaBalance) string {
	if balance.PlanID != "" {
		return balance.PlanID
	}
	return balance.UserPlanID
}

// renderView renders the normalized host/management view of the evidence into
// its Subscription, Summary, and Groups fields. Only explicit numbers are
// rendered; nothing defaults to zero.
//
// Groups are per billing axis rather than per bucket: the summary stays flat
// because a host metric list is unordered, but a group's display name is what
// tells an operator which plan the numbers under it belong to. A bucket whose
// remaining share is unreadable stays in the summary alone rather than opening
// a group around a measurement the upstream never made.
func (e *quotaEvidence) renderView() {
	if e.Plan != "" {
		e.Subscription = &pluginapi.QuotaSubscription{Plan: e.Plan}
	}
	for _, balance := range e.Balances {
		if balance.Malformed {
			continue
		}
		name := balanceDisplayName(balance)
		if value := balance.Remaining; value != nil {
			e.Summary = append(e.Summary, pluginapi.QuotaMetric{
				Key:    "remaining:" + name,
				Label:  name + " remaining",
				Value:  *value,
				Format: "number",
			})
		}
		if value := balance.Used; value != nil {
			e.Summary = append(e.Summary, pluginapi.QuotaMetric{
				Key:    "used:" + name,
				Label:  name + " used",
				Value:  *value,
				Format: "number",
			})
		}
	}
	groups, _ := placeBucketsByPlan(e.Plans, e.Balances)
	for _, group := range groups {
		rendered := pluginapi.QuotaGroup{DisplayName: group.Label}
		for _, balance := range group.Balances {
			// A bucket needs both ends of the window; a remaining value without
			// a total would render as a misleading fraction, so it stays in the
			// flat metrics only. The fraction itself comes from the one reading
			// the management page also renders, so the two surfaces cannot
			// disagree about the same bucket.
			fraction, ok := balanceRemainingFraction(balance)
			if !ok {
				continue
			}
			name := balanceDisplayName(balance)
			rendered.Buckets = append(rendered.Buckets, pluginapi.QuotaBucket{
				Window:            name,
				RemainingFraction: fraction,
				ResetTime:         balance.ExpiresAt,
			})
		}
		if len(rendered.Buckets) > 0 {
			e.Groups = append(e.Groups, rendered)
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
	// Plans are the rows themselves, kept because a bucket's billing axis is
	// only knowable by matching it against the plan that granted it — a flat
	// bucket list cannot tell a Start Plan allowance from a Coding Plan one,
	// and the page never receives the response to re-derive the match.
	Plans    []quotaPlan
	Balances []quotaBalance
}

// observationFor derives the management view of one refresh's outcome.
func observationFor(evidence quotaEvidence, checkedAt time.Time) quotaObservation {
	observation := quotaObservation{
		CheckedAt: checkedAt,
		Plan:      evidence.Plan,
		PlanCount: len(evidence.Plans),
		Plans:     evidence.Plans,
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
