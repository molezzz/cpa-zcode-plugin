package main

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"
)

// A Start Plan JWT is one credential that carries a whole set of server-side
// plans and buckets, and which bucket a request spends is the upstream's own
// decision: the official Messages request carries the JWT and the model and
// nothing that selects a plan (docs/ZCode
// packages/services/src/model-provider/accountProviderRequestAuthService.ts
// hands Start Plan requests the zcodeJwtToken alone). So the plugin cannot ask
// "which plan should pay for this?" and must never pretend to: it decides only
// whether the credential has any allowance left for the model at hand, and lets
// the upstream pick among the buckets it holds.
//
// Everything in this file is therefore about eligibility and ordering. None of
// it routes a request to a bucket, and nothing here is persisted as credential
// material.

// startPlanBucket is one balance row reduced to the facts that decide whether a
// model may be attempted: the models it covers, the units left, when the window
// closes, and the short digest identifying the owning plan instance.
//
// The owner is carried as a digest rather than the upstream's user_plan_id.
// That id is a durable account-scoped identifier, and the diagnostic and
// management surfaces of this plugin show plan identity to an operator; putting
// the raw value into a log line or a credential document would leak the account
// through a field no operator needs. Two digests of the same id still compare
// equal, which is all any consumer needs.
type startPlanBucket struct {
	// Models are the canonical upstream model ids this bucket pays for, from
	// its declared capabilities or — when it declares none — from its own
	// display name.
	Models []string
	// Remaining and Total are the upstream's own numbers, nil when it stated
	// neither. An unread number is never a zero: it means the plugin cannot
	// tell, and treating it as zero would skip a bucket that may be full.
	Remaining *float64
	Total     *float64
	// ExpiresAt is when the current window closes. For a recurring bucket that
	// is when it refills, so it is also the earliest a currently-empty bucket
	// can become usable again; for a one-time grant it never refills.
	ExpiresAt string
	// Period is the bucket's recurrence as the upstream spells it, which is what
	// distinguishes those two readings of ExpiresAt.
	Period string
	// PlanID is the product. PlanInstance is the short digest of the individual
	// subscription instance, and is empty when the upstream named none.
	PlanID        string
	PlanInstance  string
	EntitlementID string
	// Malformed marks a row whose numbers could not be read. It is not
	// evidence about the allowance in either direction.
	Malformed bool
}

// StartPlanSnapshot is the plugin's read of one credential's entitlement and
// per-model allowance. It is a diagnostic and scheduling input, never a source
// of truth: every field is re-derived from a live billing/balance read, and a
// snapshot that has gone stale costs a wrong ordering decision at worst, not a
// wrong credential.
type StartPlanSnapshot struct {
	// CheckedAt is when this snapshot's numbers were read.
	CheckedAt time.Time
	// Readable is false when the billing endpoint answered with something this
	// build cannot interpret. A Readable=false snapshot asserts nothing, and
	// every eligibility question answered from it answers "unknown", which is
	// never a reason to skip a credential.
	Readable bool
	// Plans are the plan rows the upstream described, in its own order. It is
	// empty on a snapshot rebuilt from a persisted section, which carries only
	// product ids — so the scheduling policy reads PlanIDs and LastTried rather
	// than depending on plan rows being present.
	Plans []quotaPlan
	// PlanIDs are the live Start Plan products this credential holds, as the
	// upstream named them. It is the only plan fact a persisted section carries.
	PlanIDs []string
	// LastTried is the scheduling decision already made for this credential's plan,
	// so a snapshot rebuilt from a persisted section keeps it without re-deriving
	// it from plan rows it does not have.
	LastTried bool
	// Buckets are the Start Plan balance rows, in the upstream's order, which
	// is its priority order.
	Buckets []startPlanBucket
}

// planInstanceDigestLength is how much of the digest identifies a plan
// instance. It is short on purpose: the value only has to tell two instances
// apart inside one account's own document, so a truncated digest is enough and
// a longer one would add no discriminating power.
const planInstanceDigestLength = 12

// planSnapshotDigest domain-separates the plan-instance digest from every other
// digest the plugin derives, so a user_plan_id can never collide with some
// other hashed input by accident.
const planSnapshotDigest = "cpa-zcode-plugin/plan-instance/v1"

// planInstanceRef renders the safe reference to one plan instance: its product
// id, plus a short digest of the instance id when the upstream stated one. The
// product id is already an opaque product identifier and is what an operator
// reads to recognise a plan; the instance id is what has to be reduced.
func planInstanceRef(planID, userPlanID string) string {
	planID = strings.TrimSpace(planID)
	userPlanID = strings.TrimSpace(userPlanID)
	if userPlanID == "" {
		return planID
	}
	digest := identityDigestOf(planSnapshotDigest, userPlanID)
	if planID == "" {
		return digest
	}
	return planID + "#" + digest
}

// identityDigestOf derives a truncated, domain-separated digest of a value.
func identityDigestOf(domain, value string) string {
	sum := sha256Sum(domain + "\x00" + value)
	return hexEncode(sum)[:planInstanceDigestLength]
}

// snapshotFor derives the Start Plan view of one billing refresh. A refresh that
// never produced readable evidence yields a snapshot that asserts nothing, so
// its consumers fall back to "attempt this credential" rather than to "skip it".
func snapshotFor(evidence quotaEvidence, checkedAt time.Time) StartPlanSnapshot {
	snapshot := StartPlanSnapshot{CheckedAt: checkedAt, Readable: evidence.SchemaCompatible}
	if evidence.AuthFailure != nil {
		// The credential was rejected, so the snapshot is about the rejection
		// rather than about an allowance. Nothing about it is usable evidence.
		snapshot.Readable = false
		return snapshot
	}
	snapshot.Plans = evidence.Plans
	for _, balance := range evidence.Balances {
		if !startPlanBucketEligible(balance, evidence.Plans) {
			continue
		}
		snapshot.Buckets = append(snapshot.Buckets, startPlanBucket{
			Models:        balanceModelIDs(balance),
			Remaining:     balance.Remaining,
			Total:         balance.Total,
			ExpiresAt:     balance.ExpiresAt,
			Period:        balance.Period,
			PlanID:        strings.TrimSpace(balance.PlanID),
			PlanInstance:  planInstanceRef(balance.PlanID, balance.UserPlanID),
			EntitlementID: strings.TrimSpace(balance.EntitlementID),
			Malformed:     balance.Malformed,
		})
	}
	return snapshot
}

// startPlanBucketEligible reports whether one balance row is part of a Start
// Plan that is currently in force.
//
// The plan must match the row and must be live. A row whose owning plan the
// response did not describe is kept only when the row's own plan id is itself a
// Start Plan, so a plan the upstream omitted still schedules its own buckets
// rather than being discarded for want of a plan row.
func startPlanBucketEligible(balance quotaBalance, plans []quotaPlan) bool {
	for _, plan := range plans {
		if planGrantsBucket(plan, balance) {
			return planIsLive(plan) && isStartPlanPlan(plan)
		}
	}
	return isStartPlanIdentity(balance.PlanID)
}

// isStartPlanIdentity reports whether one plan product id names a Start Plan.
func isStartPlanIdentity(planID string) bool {
	lowered := strings.ToLower(strings.TrimSpace(planID))
	return lowered != "" && strings.Contains(lowered, startPlanIdentityMarker)
}

// modelAllowance is what one snapshot says about one model. The three-valued
// answer is the whole point: a model with a funded bucket, a model whose every
// bucket is empty, and a model this snapshot knows nothing about are three
// different situations, and only the middle one is a reason to skip a
// credential.
type modelAllowance int

const (
	// allowanceUnknown means the snapshot carries no usable evidence for the
	// model: it could not be read, the row is unreadable, or the account has no
	// bucket for it. It never skips a credential.
	allowanceUnknown modelAllowance = iota
	// allowanceFunded means at least one live, matching bucket still has units.
	allowanceFunded
	// allowanceEmpty means every live, matching bucket the snapshot saw has zero
	// units left, so there is nothing for this credential to spend on the model.
	allowanceEmpty
)

// modelAllowance reads one model's standing in the snapshot.
//
// A bucket with no readable remaining value is treated as unknown rather than
// as zero, for the same reason the verdict logic treats unreadable rows that
// way: the plugin has no evidence it is empty, and skipping a credential on a
// number it could not read would be an invented conclusion.
func (s StartPlanSnapshot) modelAllowance(model string) modelAllowance {
	target := normalizeRequestModel(model, nil)
	funded, empty := false, false
	for _, bucket := range s.Buckets {
		if !bucket.coversModel(target) {
			continue
		}
		if bucket.Malformed || bucket.Remaining == nil {
			continue
		}
		if *bucket.Remaining > 0 {
			funded = true
			break
		}
		empty = true
	}
	switch {
	case funded:
		return allowanceFunded
	case empty:
		return allowanceEmpty
	default:
		return allowanceUnknown
	}
}

// coversModel reports whether this bucket pays for one model, compared the way
// the upstream's own capability list spells model ids: case-insensitively,
// after the plugin has folded both sides onto the official casing.
func (b startPlanBucket) coversModel(model string) bool {
	for _, candidate := range b.Models {
		if strings.EqualFold(candidate, model) {
			return true
		}
	}
	return false
}

// earliestRefill reports when the model's currently-empty buckets come back, as
// the caller-facing text for an exhausted-model error. It is the earliest window
// close among them, because that is the first moment a retry can succeed. A
// bucket the upstream gave no window for contributes no deadline, and a bucket
// that does not recur contributes none either — a one-time grant never returns,
// so promising a reset time for it would be false.
func (s StartPlanSnapshot) earliestRefill(model string) (string, bool) {
	target := normalizeRequestModel(model, nil)
	var earliest time.Time
	for _, bucket := range s.Buckets {
		if !bucket.coversModel(target) || bucket.Malformed || bucket.Remaining == nil || *bucket.Remaining > 0 {
			continue
		}
		if !bucket.recurring() {
			continue
		}
		reset, err := time.Parse(time.RFC3339, strings.TrimSpace(bucket.ExpiresAt))
		if err != nil || reset.IsZero() {
			continue
		}
		if earliest.IsZero() || reset.Before(earliest) {
			earliest = reset
		}
	}
	if earliest.IsZero() {
		return "", false
	}
	return earliest.UTC().Format(time.RFC3339), true
}

// recurring reports whether the bucket's window comes back on its own. The
// upstream spells the non-recurring case "one_time"; anything the plugin does
// not recognise as non-recurring is treated as recurring, because that reading
// only ever adds a possible deadline to a message while the opposite would
// suppress a real one.
func (b startPlanBucket) recurring() bool {
	period := normalizeStatus(b.Period)
	return period != quotaPeriodOneTime
}

// quotaPeriodOneTime is the upstream's spelling of a non-recurring grant.
const quotaPeriodOneTime = "one_time"

// hasStartPlan reports whether the snapshot describes any Start Plan at all,
// which the login preflight needs and the scheduling path does not: an account
// holding only a general Coding Plan is a different entitlement, not a Start
// Plan with an empty bucket.
func (s StartPlanSnapshot) hasStartPlan() bool {
	if !s.Readable {
		return false
	}
	for _, plan := range s.Plans {
		if isStartPlanPlan(plan) && planIsLive(plan) {
			return true
		}
	}
	return false
}

// startPlanIDs lists the product ids of the live Start Plans the snapshot
// describes, de-duplicated and in the upstream's order. It is the evidence the
// allowed-plan filter and the diagnostics report from.
func (s StartPlanSnapshot) startPlanIDs() []string {
	var ids []string
	seen := map[string]struct{}{}
	add := func(id string) {
		if id = strings.TrimSpace(id); id == "" {
			return
		}
		if _, duplicate := seen[id]; duplicate {
			return
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	for _, plan := range s.Plans {
		if isStartPlanPlan(plan) && planIsLive(plan) {
			add(plan.PlanID)
		}
	}
	// A snapshot rebuilt from a persisted section carries no plan rows, only the
	// product ids, so those are consulted too: a scheduling decision has to
	// survive a restart, or the same account would be scheduled differently on
	// either side of one.
	for _, id := range s.PlanIDs {
		add(id)
	}
	return ids
}

// startsWithLastPriority reports whether this snapshot's Start Plan is one the
// configuration reserves for last resort.
//
// The decision is made on the product id alone. It is tempting to also read the
// display name or the credential's file name, and both would be wrong: a plan's
// name is localized and a file name is derived from a hash, so either would
// decide a scheduling policy from a value that can change without the upstream
// changing anything.
func (s StartPlanSnapshot) isLastPriority(cfg Config) bool {
	last := normalizePlanIDs(cfg.StartPlanCredentialPool.LastPriorityPlanIDs)
	if len(last) == 0 {
		return false
	}
	ids := s.startPlanIDs()
	if len(ids) == 0 {
		// A rebuilt snapshot with no plan ids keeps the decision it was stored
		// with rather than guessing one.
		return s.LastTried
	}
	for _, id := range ids {
		if !containsPlanID(last, id) {
			// The credential also holds a plan that is not reserved. Demoting the
			// whole record would put that plan's allowance behind every other
			// record's, which is the opposite of what the reservation is for: it
			// reserves the product, not every credential that happens to hold it
			// alongside something else.
			return false
		}
	}
	return true
}

// containsPlanID reports whether one product id is in a list of plan ids.
func containsPlanID(ids []string, id string) bool {
	for _, candidate := range ids {
		if candidate == id {
			return true
		}
	}
	return false
}

// planSnapshotSection is the persisted shape of the safe snapshot written into
// a credential document. It carries no token, no raw user id, and no raw
// user_plan_id or bucket_id: the instance is identified by the digest
// planInstanceRef derives, which is all an operator needs to tell two plans of
// one account apart.
type planSnapshotSection struct {
	CheckedAt  string               `json:"checked_at"`
	Readable   bool                 `json:"readable"`
	PlanIDs    []string             `json:"plan_ids,omitempty"`
	Instances  []string             `json:"plan_instances,omitempty"`
	Models     map[string]modelLine `json:"models,omitempty"`
	LastTried  bool                 `json:"last_priority,omitempty"`
	ReasonCode string               `json:"reason,omitempty"`
}

// modelLine is one model's standing in a persisted snapshot.
type modelLine struct {
	Allowance   string `json:"allowance"`
	ResetAt     string `json:"reset_at,omitempty"`
	BucketCount int    `json:"buckets"`
	FundedCount int    `json:"funded_buckets,omitempty"`
}

// renderPlanSnapshot reduces a live snapshot to its persistable, redacted form.
//
// The rendered form is deliberately aggregate: per model it records whether an
// allowance exists, is empty, or is unknown, and when the empty ones come back.
// It does not record individual bucket counts per plan instance, because the
// numbers that matter for scheduling and for the caller's error message are the
// per-model ones, and every extra number is another thing to leak or keep in
// sync.
func renderPlanSnapshot(snapshot StartPlanSnapshot, cfg Config) planSnapshotSection {
	section := planSnapshotSection{
		CheckedAt: snapshot.CheckedAt.UTC().Format(time.RFC3339),
		Readable:  snapshot.Readable,
		LastTried: snapshot.isLastPriority(cfg),
	}
	if !snapshot.Readable {
		return section
	}
	section.PlanIDs = snapshot.startPlanIDs()
	instances := map[string]struct{}{}
	for _, bucket := range snapshot.Buckets {
		if ref := bucket.PlanInstance; ref != "" {
			instances[ref] = struct{}{}
		}
	}
	section.Instances = sortedKeys(instances)

	models := map[string]modelLine{}
	for _, bucket := range snapshot.Buckets {
		for _, model := range bucket.Models {
			line, seen := models[model]
			if !seen {
				line = modelLine{Allowance: allowanceUnknown.String()}
			}
			line.BucketCount++
			switch {
			case !bucket.Malformed && bucket.Remaining != nil && *bucket.Remaining > 0:
				line.FundedCount++
				line.Allowance = allowanceFunded.String()
			case !bucket.Malformed && bucket.Remaining != nil && line.FundedCount == 0:
				if line.Allowance == allowanceUnknown.String() {
					line.Allowance = allowanceEmpty.String()
				}
			}
			models[model] = line
		}
	}
	for model, line := range models {
		if line.Allowance == allowanceEmpty.String() {
			if reset, ok := snapshot.earliestRefill(model); ok {
				line.ResetAt = reset
			}
		}
		models[model] = line
	}
	section.Models = models
	return section
}

// String names the allowance for storage and for the management view.
func (a modelAllowance) String() string {
	switch a {
	case allowanceFunded:
		return "funded"
	case allowanceEmpty:
		return "empty"
	default:
		return "unknown"
	}
}

// sortedKeys returns a map's keys in ascending order, so a rendered document
// and a debug line are byte-stable for the same input.
func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return nil
	}
	return keys
}

// planRefreshGate bounds how often one credential's per-model block may be
// re-read from the billing endpoint on the request path.
//
// A block whose recorded deadline has elapsed is the one condition that makes
// every subsequent request want a fresh reading, so without a gate a client
// looping on one model would turn into one upstream billing call per request. The
// gate is per credential and per model rather than global, because one record's
// blocked model says nothing about another's, and a model that is not blocked is
// never gated at all — it costs no request-path call.
//
// The window is deliberately short: it only has to collapse a burst, not to
// decide anything. A credential that recovered inside the window stays blocked for
// at most that long, which is the same order as the cooldown a temporary upstream
// failure already imposes.
type planRefreshGate struct {
	mu   sync.Mutex
	last map[string]time.Time
}

const planRefreshGateWindow = 10 * time.Second

func newPlanRefreshGate() *planRefreshGate {
	return &planRefreshGate{last: map[string]time.Time{}}
}

// allows reports whether one credential-and-model pair may be re-read now, and
// records that it was.
func (g *planRefreshGate) allows(key string, now time.Time) bool {
	if g == nil {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if previous, seen := g.last[key]; seen && now.Sub(previous) < planRefreshGateWindow {
		return false
	}
	g.last[key] = now
	return true
}

// activePlanRefreshGate is the plugin-wide gate over request-path balance
// re-reads.
var activePlanRefreshGate = newPlanRefreshGate()

// planRefreshKey names one credential-and-model pair for the gate.
func planRefreshKey(authIndex, model string) string {
	return strings.TrimSpace(authIndex) + "\x00" + normalizeRequestModel(model, nil)
}

// readPlanSnapshotSection recovers the persisted snapshot of a credential
// document. A missing or unreadable section yields the zero snapshot, whose
// every allowance reads unknown — so a record without a snapshot schedules
// exactly like one from before this feature existed.
func readPlanSnapshotSection(doc []byte) planSnapshotSection {
	var root struct {
		Zcode struct {
			Plan planSnapshotSection `json:"plan"`
		} `json:"zcode"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(doc), &root); err != nil {
		return planSnapshotSection{}
	}
	return root.Zcode.Plan
}

// writePlanSnapshotSection records a snapshot on a credential document. It
// patches rather than replaces, so a document's host-owned fields and every
// other plugin field survive untouched.
func writePlanSnapshotSection(doc []byte, section planSnapshotSection) ([]byte, error) {
	return patchZcodeNamespace(doc, func(zcode map[string]any) error {
		rendered, err := json.Marshal(section)
		if err != nil {
			return err
		}
		var value any
		if err := json.Unmarshal(rendered, &value); err != nil {
			return err
		}
		zcode["plan"] = value
		return nil
	})
}
