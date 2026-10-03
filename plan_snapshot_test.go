package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// liveStartPlan is one active Start Plan row, the plan shape the fixture bodies
// below spell.
func liveStartPlan(planID, userPlanID string) quotaPlan {
	return quotaPlan{
		Name:       "ZCode V3 Start Plan",
		PlanID:     planID,
		UserPlanID: userPlanID,
		Status:     planStatusActive,
	}
}

// startPlanSnapshotFrom parses a billing body the way the quota path does, so a
// test exercises the real parse-to-snapshot path rather than a hand-built
// snapshot that could drift from it.
func startPlanSnapshotFrom(t *testing.T, plansJSON string, rowsJSON string, now time.Time) StartPlanSnapshot {
	t.Helper()
	body := []byte(planBalanceBody(plansJSON, rowsJSON))
	parsed, ok := parseQuotaPlans(body, now)
	if !ok {
		t.Fatal("plans did not parse")
	}
	balances, ok := parseQuotaBalancesWithPlans(body, parsed)
	if !ok {
		t.Fatal("balances did not parse")
	}
	return snapshotFor(quotaEvidence{
		Verdict:          verdictAvailable,
		SchemaCompatible: true,
		Plans:            parsed,
		Balances:         balances,
	}, now)
}

// The central case from the issue: one Start Plan whose GLM-5.3 bucket is empty
// while another plan's bucket for the same model still has units. A single
// global exhausted verdict would take the whole JWT out of service here.
func TestModelAllowanceIsPerModelNotGlobal(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	snapshot := startPlanSnapshotFrom(t,
		`[{"name":"ZCode V3 Start Plan","plan_id":"zcode-v3-start-plan-trust-1003","user_plan_id":"plan-a","status":"active"},
		  {"name":"ZCode V3 Start Plan","plan_id":"zcode-v3-start-plan-0817","user_plan_id":"plan-b","status":"active"}]`,
		`{"show_name":"GLM-5.3","plan_id":"zcode-v3-start-plan-trust-1003","user_plan_id":"plan-a","capabilities":["model:glm-5.3"],"total_units":100,"remaining_units":0,"expires_at":"2026-10-04T00:00:00Z"},
		 {"show_name":"GLM-5.3","plan_id":"zcode-v3-start-plan-0817","user_plan_id":"plan-b","capabilities":["model:glm-5.3"],"total_units":100,"remaining_units":30,"expires_at":"2026-10-04T00:00:00Z"}`,
		now)
	if got := snapshot.modelAllowance("GLM-5.3"); got != allowanceFunded {
		t.Fatalf("GLM-5.3 allowance = %s, want funded: one plan's empty bucket must not speak for the other", got)
	}
}

// Acceptance criterion 3: GLM-5.3 exhausted while Flash still has units must
// leave Flash schedulable on the same credential.
func TestModelAllowanceSeparatesModelsOnOneCredential(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	snapshot := startPlanSnapshotFrom(t,
		`[{"name":"ZCode V3 Start Plan","plan_id":"zcode-v3-start-plan-trust-1003","user_plan_id":"plan-a","status":"active"}]`,
		`{"show_name":"GLM-5.3","plan_id":"zcode-v3-start-plan-trust-1003","user_plan_id":"plan-a","capabilities":["model:glm-5.3"],"total_units":100,"remaining_units":0,"expires_at":"2026-10-04T00:00:00Z"},
		 {"show_name":"GLM-5.3-Flash","plan_id":"zcode-v3-start-plan-trust-1003","user_plan_id":"plan-a","capabilities":["model:glm-5.3-flash"],"total_units":100,"remaining_units":42,"expires_at":"2026-10-04T00:00:00Z"}`,
		now)
	if got := snapshot.modelAllowance("GLM-5.3"); got != allowanceEmpty {
		t.Fatalf("GLM-5.3 allowance = %s, want empty", got)
	}
	if got := snapshot.modelAllowance("GLM-5.3-Flash"); got != allowanceFunded {
		t.Fatalf("GLM-5.3-Flash allowance = %s, want funded", got)
	}
	// Case folding is the upstream's own spelling: capability ids arrive lower
	// case and callers may send the official casing.
	if got := snapshot.modelAllowance("glm-5.3-flash"); got != allowanceFunded {
		t.Fatalf("lower-case caller spelling allowance = %s, want funded", got)
	}
}

// A model with no bucket at all is unknown, not empty. Skipping a credential for
// a model the account simply does not offer would disable it on invented
// evidence.
func TestModelAllowanceWithoutAnyBucketIsUnknown(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	snapshot := startPlanSnapshotFrom(t,
		`[{"name":"ZCode V3 Start Plan","plan_id":"zcode-v3-start-plan-0817","user_plan_id":"plan-b","status":"active"}]`,
		`{"show_name":"GLM-5.3-Flash","plan_id":"zcode-v3-start-plan-0817","user_plan_id":"plan-b","capabilities":["model:glm-5.3-flash"],"total_units":100,"remaining_units":0}`,
		now)
	if got := snapshot.modelAllowance("GLM-5.3"); got != allowanceUnknown {
		t.Fatalf("GLM-5.3 allowance = %s, want unknown", got)
	}
	if snapshot.hasStartPlan() != true {
		t.Fatal("hasStartPlan = false, want true: a Start Plan whose bucket is empty is still a Start Plan")
	}
}

// An unreadable remaining value is unknown rather than zero, for the same
// reason the verdict logic treats unreadable rows that way.
func TestModelAllowanceTreatsUnreadableNumbersAsUnknown(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	snapshot := startPlanSnapshotFrom(t,
		`[{"name":"ZCode V3 Start Plan","plan_id":"zcode-v3-start-plan-0817","user_plan_id":"plan-b","status":"active"}]`,
		`{"show_name":"GLM-5.3-Flash","plan_id":"zcode-v3-start-plan-0817","user_plan_id":"plan-b","capabilities":["model:glm-5.3-flash"],"total_units":"lots","remaining_units":"some"}`,
		now)
	if got := snapshot.modelAllowance("GLM-5.3-Flash"); got != allowanceUnknown {
		t.Fatalf("allowance = %s, want unknown for drifted numbers", got)
	}
}

// The refill deadline is the bucket's own window close, never one this code
// anchors — an anchored window would slide forward on every refresh.
func TestEarliestRefillUsesTheUpstreamWindow(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	snapshot := startPlanSnapshotFrom(t,
		`[{"name":"ZCode V3 Start Plan","plan_id":"zcode-v3-start-plan-0817","user_plan_id":"plan-b","status":"active","entitlements":[{"entitlement_id":"e1","period":"daily"}]}]`,
		`{"show_name":"GLM-5.3","entitlement_id":"e1","plan_id":"zcode-v3-start-plan-0817","user_plan_id":"plan-b","capabilities":["model:glm-5.3"],"remaining_units":0,"expires_at":"2026-10-04T09:00:00Z"}`,
		now)
	reset, ok := snapshot.earliestRefill("GLM-5.3")
	if !ok || reset != "2026-10-04T09:00:00Z" {
		t.Fatalf("reset = %q ok %v, want the upstream window 2026-10-04T09:00:00Z", reset, ok)
	}
}

// A one-time grant never refills, so promising a reset time for it would be
// false. The caller is told nothing rather than something untrue.
func TestEarliestRefillOmitsNonRecurringBuckets(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	snapshot := startPlanSnapshotFrom(t,
		`[{"name":"ZCode V3 Start Plan","plan_id":"zcode-v3-start-plan-0817","user_plan_id":"plan-b","status":"active","entitlements":[{"entitlement_id":"e1","period":"one_time"}]}]`,
		`{"show_name":"GLM-5.3","entitlement_id":"e1","plan_id":"zcode-v3-start-plan-0817","user_plan_id":"plan-b","capabilities":["model:glm-5.3"],"remaining_units":0,"expires_at":"2026-10-04T09:00:00Z"}`,
		now)
	if reset, ok := snapshot.earliestRefill("GLM-5.3"); ok {
		t.Fatalf("reset = %q, want none for a one_time grant", reset)
	}
}

// Last-priority is decided on the product id alone. A localized display name or
// a derived file name would make the scheduling policy depend on a value the
// upstream can change for unrelated reasons.
func TestLastPriorityIsDecidedOnPlanIDAlone(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	cfg := normalizeConfig(Config{})
	reserved := startPlanSnapshotFrom(t,
		`[{"name":"ZCode V3 Start Plan","plan_id":"zcode-v3-start-plan-0817","user_plan_id":"plan-b","status":"active"}]`, "", now)
	if !reserved.isLastPriority(cfg) {
		t.Fatal("0817 snapshot was not classified last priority")
	}
	// Same product, renamed display: still last priority.
	renamed := startPlanSnapshotFrom(t,
		`[{"name":"Completely Different Label","plan_id":"zcode-v3-start-plan-0817","user_plan_id":"plan-b","status":"active"}]`, "", now)
	if !renamed.isLastPriority(cfg) {
		t.Fatal("0817 stopped being last priority because its display name changed")
	}
	// A different product that happens to be named "0817": not last priority.
	other := startPlanSnapshotFrom(t,
		`[{"name":"0817 special offer","plan_id":"zcode-v3-start-plan-trust-1003","user_plan_id":"plan-a","status":"active"}]`, "", now)
	if other.isLastPriority(cfg) {
		t.Fatal("a different product was demoted on its display name")
	}
	// A plan this build has never heard of is not last priority, so a newly
	// introduced product is scheduled ahead of the configured one.
	future := startPlanSnapshotFrom(t,
		`[{"name":"ZCode V3 Start Plan","plan_id":"zcode-v4-start-plan-2000","user_plan_id":"plan-c","status":"active"}]`, "", now)
	if future.isLastPriority(cfg) {
		t.Fatal("an unknown active Start Plan was demoted into the last-priority group")
	}
}

// A plan instance is referenced by a digest, never by the raw upstream id: that
// id is a durable account-scoped identifier and the plugin's surfaces are read by
// operators and written to logs.
func TestPlanInstanceRefRedactsTheUpstreamID(t *testing.T) {
	ref := planInstanceRef("zcode-v3-start-plan-0817", "34dd6d87-1234-4321-abcd-0123456789ab")
	if strings.Contains(ref, "34dd6d87") {
		t.Fatalf("plan instance reference leaks the upstream id: %q", ref)
	}
	if !strings.HasPrefix(ref, "zcode-v3-start-plan-0817#") {
		t.Fatalf("plan instance reference = %q, want the product id then a digest", ref)
	}
	if got := planInstanceRef("plan", "same-id"); got != ref2("same-id") {
		t.Fatalf("digest is not stable: %q vs %q", got, ref2("same-id"))
	}
	// Two instances of one product must not collapse into one reference, or the
	// two separate allowances become indistinguishable.
	if planInstanceRef("p", "a") == planInstanceRef("p", "b") {
		t.Fatal("two plan instances produced the same reference")
	}
}

func ref2(value string) string { return "plan#" + identityDigestOf(planSnapshotDigest, value) }

// A Start Plan's allowance is measured over the Start Plan's own buckets. A
// general Coding Plan bucket for the same model pays for a different billing
// axis, so it must not be counted as Start Plan availability — otherwise a Start
// Plan whose buckets are empty would read as funded because the account also
// holds a paid plan, which is exactly the conflation the axis split prevents.
func TestSnapshotKeepsStartPlanBucketsOffTheCodingPlanAxis(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	snapshot := startPlanSnapshotFrom(t,
		`[{"name":"ZCode V3 Start Plan","plan_id":"zcode-v3-start-plan-0817","user_plan_id":"plan-b","status":"active"},
		  {"name":"GLM Coding Plan","plan_id":"coding-plan","user_plan_id":"coding-1","status":"active"}]`,
		`{"show_name":"GLM-5.3","plan_id":"zcode-v3-start-plan-0817","user_plan_id":"plan-b","remaining_units":0},
		 {"show_name":"GLM-5.3","plan_id":"coding-plan","user_plan_id":"coding-1","remaining_units":10}`,
		now)
	if got := snapshot.modelAllowance("GLM-5.3"); got != allowanceEmpty {
		t.Fatalf("allowance = %s, want empty: a Coding Plan bucket is not Start Plan availability", got)
	}
	if snapshot.hasStartPlan() != true {
		t.Fatal("hasStartPlan = false, want true")
	}
	for _, bucket := range snapshot.Buckets {
		if bucket.PlanID == "coding-plan" {
			t.Fatal("a Coding Plan bucket was kept in the Start Plan snapshot")
		}
	}
}

// A row whose owning plan the response omitted still schedules, when the row's
// own product id names a Start Plan. Discarding it would strand a live plan over
// a missing plan row.
func TestSnapshotKeepsOrphanedStartPlanBuckets(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	snapshot := startPlanSnapshotFrom(t,
		`[]`,
		`{"show_name":"GLM-5.3-Flash","plan_id":"zcode-v3-start-plan-0817","user_plan_id":"plan-b","capabilities":["model:glm-5.3-flash"],"remaining_units":7}`,
		now)
	if got := snapshot.modelAllowance("GLM-5.3-Flash"); got != allowanceFunded {
		t.Fatalf("allowance = %s, want funded for a Start Plan row with no plan row", got)
	}
	// An orphan on the general Coding Plan axis is not a Start Plan bucket.
	coding := startPlanSnapshotFrom(t,
		`[]`,
		`{"show_name":"GLM-5.3","plan_id":"coding-plan","user_plan_id":"coding-1","remaining_units":7}`,
		now)
	if got := coding.modelAllowance("GLM-5.3"); got != allowanceUnknown {
		t.Fatalf("allowance = %s, want unknown for an orphaned Coding Plan row", got)
	}
}

// The rendered snapshot is what the management view and the diagnostics read, so
// it must name the plans and per-model standings and must carry no credential
// material or raw upstream identifiers.
func TestRenderPlanSnapshotCarriesOnlyRedactedFacts(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	snapshot := startPlanSnapshotFrom(t,
		`[{"name":"ZCode V3 Start Plan","plan_id":"zcode-v3-start-plan-0817","user_plan_id":"34dd6d87-1234-4321-abcd-0123456789ab","status":"active","entitlements":[{"entitlement_id":"34dd6d87-entitlement","period":"daily"}]}]`,
		`{"show_name":"GLM-5.3","entitlement_id":"34dd6d87-entitlement","plan_id":"zcode-v3-start-plan-0817","user_plan_id":"34dd6d87-1234-4321-abcd-0123456789ab","remaining_units":0,"expires_at":"2026-10-04T09:00:00Z"}`,
		now)
	section := renderPlanSnapshot(snapshot, normalizeConfig(Config{}))
	if len(section.PlanIDs) != 1 || section.PlanIDs[0] != "zcode-v3-start-plan-0817" {
		t.Fatalf("plan ids = %v, want the configured last-priority product", section.PlanIDs)
	}
	if !section.LastTried {
		t.Fatal("last_priority = false, want true for the configured plan")
	}
	line, ok := section.Models["GLM-5.3"]
	if !ok || line.Allowance != "empty" || line.ResetAt != "2026-10-04T09:00:00Z" {
		t.Fatalf("model line = %+v, want empty with the upstream reset", line)
	}
	rendered, err := json.Marshal(section)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"34dd6d87-1234", "34dd6d87-entitlement"} {
		if strings.Contains(string(rendered), forbidden) {
			t.Fatalf("rendered snapshot leaks %q: %s", forbidden, rendered)
		}
	}
}

// An unreadable reading renders nothing, so a failed refresh cannot overwrite a
// good snapshot with an empty section.
func TestRenderPlanSnapshotOfAnUnreadableReadingIsEmpty(t *testing.T) {
	section := renderPlanSnapshot(StartPlanSnapshot{CheckedAt: time.Now(), Readable: false}, normalizeConfig(Config{}))
	if section.Readable || len(section.PlanIDs) != 0 || len(section.Models) != 0 {
		t.Fatalf("unreadable snapshot rendered as data: %+v", section)
	}
}

// Round-tripping the persisted section is what lets a restart schedule on the
// same information the last refresh read.
func TestPlanSnapshotSectionRoundTrips(t *testing.T) {
	section := renderPlanSnapshot(StartPlanSnapshot{
		CheckedAt: time.Now(),
		Readable:  true,
		Plans:     []quotaPlan{liveStartPlan("zcode-v3-start-plan-trust-1003", "plan-a")},
		Buckets: []startPlanBucket{{
			Models:       []string{"GLM-5.3-Flash"},
			Remaining:    float64Ptr(12),
			PlanInstance: "zcode-v3-start-plan-trust-1003#abcdef012345",
		}},
	}, normalizeConfig(Config{}))
	doc, err := writePlanSnapshotSection(nil, section)
	if err != nil {
		t.Fatal(err)
	}
	if got := readPlanSnapshotSection(doc); got.Readable != section.Readable || len(got.Models) != len(section.Models) || got.LastTried != section.LastTried {
		t.Fatalf("round trip = %+v, want %+v", got, section)
	}
	// A document without the section reads as the zero value, whose allowances
	// are all unknown — so a pre-existing record schedules exactly as before.
	if got := readPlanSnapshotSection([]byte(`{"zcode":{"identity_id":"z"}}`)); got.Readable {
		t.Fatalf("absent section read as readable: %+v", got)
	}
}

// startPlanBalanceBody is the balance answer a successful login preflight sees:
// one active Start Plan with a funded Flash bucket. It is the fixture default
// rather than a per-test constant because most login tests are about something
// other than the preflight, and a login that is refused by default would fail
// them all for a reason they never set up.
const startPlanBalanceBody = `{"code":0,"success":true,"data":{"plans":[{"name":"ZCode V3 Start Plan","plan_id":"zcode-v3-start-plan-trust-1003","user_plan_id":"plan-a","status":"active","entitlements":[{"entitlement_id":"e1","period":"daily"}]}],"balances":[{"show_name":"GLM-5.3-Flash","entitlement_id":"e1","plan_id":"zcode-v3-start-plan-trust-1003","user_plan_id":"plan-a","capabilities":["model:glm-5.3-flash"],"total_units":100,"remaining_units":64,"expires_at":"2026-10-04T00:00:00Z"}]}}`
