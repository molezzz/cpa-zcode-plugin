package main

import (
	"context"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// poolRecordDoc builds one account record carrying a Start Plan snapshot, so a
// pool test describes accounts by their plan and allowance rather than by the
// plumbing that reads them.
func poolRecordDoc(t *testing.T, identity, planID, model string, remaining float64) []byte {
	t.Helper()
	doc := newTestAccountDoc(t, identity, makeJWT(t, map[string]any{"sub": identity}), jwtStatusActive, "")
	plan := liveStartPlan(planID, "instance-"+identity)
	section := renderPlanSnapshot(StartPlanSnapshot{
		CheckedAt: time.Now(),
		Readable:  true,
		Plans:     []quotaPlan{plan},
		Buckets: []startPlanBucket{{
			Models:       []string{model},
			Remaining:    &remaining,
			PlanID:       planID,
			PlanInstance: planInstanceRef(planID, "instance-"+identity),
			ExpiresAt:    "2026-10-04T00:00:00Z",
		}},
	}, normalizeConfig(Config{}))
	patched, err := writePlanSnapshotSection(doc, section)
	if err != nil {
		t.Fatalf("write snapshot for %s: %v", identity, err)
	}
	return patched
}

func poolOrder(candidates []poolCandidate) []string {
	out := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		out = append(out, candidate.AuthIndex)
	}
	return out
}

// Acceptance criterion 6: with a non-0817 record and an 0817 record both eligible,
// the non-0817 record is always scheduled first.
func TestPoolSchedulesReservedPlanLast(t *testing.T) {
	fixture := newQuotaFixture(t)
	trust := poolRecordDoc(t, "trust-user", "zcode-v3-start-plan-trust-1003", "GLM-5.3-Flash", 50)
	reserved := poolRecordDoc(t, "legacy-user", "zcode-v3-start-plan-0817", "GLM-5.3-Flash", 900)
	addFakeAccount(t, fixture.store, "auth-trust", "trust-user", string(trust))
	addFakeAccount(t, fixture.store, "auth-legacy", "legacy-user", string(reserved))

	candidates, err := buildCredentialPool(context.Background(), fixture.store, "auth-legacy", "GLM-5.3-Flash", normalizeConfig(Config{}), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	got := poolOrder(candidates)
	if len(got) != 2 || got[0] != "auth-trust" || got[1] != "auth-legacy" {
		t.Fatalf("order = %v, want the non-reserved record first even with 900 units on the reserved one", got)
	}
}

// Acceptance criterion 7: the order is reproducible and does not depend on the
// store's enumeration order.
func TestPoolOrderIsStableAcrossEnumerationOrder(t *testing.T) {
	cfg := normalizeConfig(Config{})
	first := []poolCandidate{
		{AuthIndex: "auth-a", IdentityID: "user-a"},
		{AuthIndex: "auth-b", IdentityID: "user-b"},
		{AuthIndex: "auth-c", IdentityID: "user-c"},
	}
	second := []poolCandidate{first[2], first[0], first[1]}
	sortPool(first, "GLM-5.3-Flash", "", cfg)
	sortPool(second, "GLM-5.3-Flash", "", cfg)
	if poolOrder(first)[0] != poolOrder(second)[0] {
		t.Fatalf("first differs by enumeration order: %v vs %v", poolOrder(first), poolOrder(second))
	}
	for i := range first {
		if poolOrder(first)[i] != poolOrder(second)[i] {
			t.Fatalf("order %v differs from %v", poolOrder(first), poolOrder(second))
		}
	}
}

// Within one policy group the record with more of the model's allowance is
// preferred, and the host's own pick wins every tie.
func TestPoolOrderWithinAGroup(t *testing.T) {
	cfg := normalizeConfig(Config{})
	candidates := []poolCandidate{
		{AuthIndex: "auth-little", IdentityID: "u1", Snapshot: snapshotWithUnits("GLM-5.3-Flash", 5)},
		{AuthIndex: "auth-lots", IdentityID: "u2", Snapshot: snapshotWithUnits("GLM-5.3-Flash", 80)},
		{AuthIndex: "auth-host", IdentityID: "u3", Snapshot: snapshotWithUnits("GLM-5.3-Flash", 80)},
	}
	sortPool(candidates, "GLM-5.3-Flash", "auth-host", cfg)
	got := poolOrder(candidates)
	if got[0] != "auth-host" {
		t.Fatalf("order = %v, want the host's own pick first on a tie", got)
	}
	if got[1] != "auth-lots" {
		t.Fatalf("order = %v, want the larger remaining allowance second", got)
	}
}

// A record with no recorded knowledge of a model stays schedulable: the upstream
// verifies every request, so "the plugin could not tell" must not remove a working
// credential from service.
func TestPoolKeepsRecordsTheSnapshotSaysNothingAbout(t *testing.T) {
	fixture := newQuotaFixture(t)
	unknown := newTestAccountDoc(t, "quiet-user", makeJWT(t, map[string]any{"sub": "quiet"}), jwtStatusActive, "")
	addFakeAccount(t, fixture.store, "auth-quiet", "quiet-user", string(unknown))
	candidates, err := buildCredentialPool(context.Background(), fixture.store, "auth-quiet", "GLM-5.3-Flash", normalizeConfig(Config{}), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 {
		t.Fatalf("candidates = %d, want the record kept", len(candidates))
	}
	if !candidateEligible(candidates[0], "GLM-5.3-Flash") {
		t.Fatal("a record with no snapshot reading was excluded")
	}
}

// A record whose allowance for this model is spent is not eligible, so it is not
// offered and the request goes straight to a record that can serve.
func TestPoolExcludesRecordsWithNoAllowanceForTheModel(t *testing.T) {
	fixture := newQuotaFixture(t)
	spent := poolRecordDoc(t, "spent-user", "zcode-v3-start-plan-trust-1003", "GLM-5.3-Flash", 0)
	funded := poolRecordDoc(t, "funded-user", "zcode-v3-start-plan-trust-1003", "GLM-5.3-Flash", 20)
	addFakeAccount(t, fixture.store, "auth-spent", "spent-user", string(spent))
	addFakeAccount(t, fixture.store, "auth-funded", "funded-user", string(funded))
	candidates, err := buildCredentialPool(context.Background(), fixture.store, "auth-funded", "GLM-5.3-Flash", normalizeConfig(Config{}), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range candidates {
		switch candidate.AuthIndex {
		case "auth-spent":
			if candidateEligible(candidate, "GLM-5.3-Flash") {
				t.Fatal("a record whose allowance for this model is spent is still eligible")
			}
		case "auth-funded":
			if !candidateEligible(candidate, "GLM-5.3-Flash") {
				t.Fatal("a funded record was excluded from the pool")
			}
		}
	}
}

// Acceptance criterion 9: with the pool disabled, only the host-selected record is
// scheduled and the request resolves exactly as it did before the pool existed.
func TestPoolDisabledSchedulesOnlyTheHostRecord(t *testing.T) {
	cfg := normalizeConfig(Config{})
	cfg.StartPlanCredentialPool.Enabled = boolPtr(false)
	if cfg.StartPlanCredentialPool.IsEnabled() {
		t.Fatal("pool reports enabled when explicitly disabled")
	}
	if got := pooledCandidatesForRequest("auth-host", "GLM-5.3-Flash", cfg, "tag", time.Now()); got != nil {
		t.Fatalf("pooled candidates = %+v, want none when disabled", got)
	}
}

// A foreign record, and one without a Start Plan JWT, are never scheduled: the
// first is not the plugin's, the second has no entitlement to schedule.
func TestPoolIgnoresForeignAndCredentiallessRecords(t *testing.T) {
	fixture := newQuotaFixture(t)
	fixture.store.docs["foreign"] = []byte(`{"other":"record"}`)
	fixture.store.entries = append(fixture.store.entries, pluginapi.HostAuthFileEntry{AuthIndex: "foreign", Name: "foreign.json"})
	keyless := newTestAccountDoc(t, "keyless", "", jwtStatusActive, "key-material")
	addFakeAccount(t, fixture.store, "auth-keyless", "keyless", string(keyless))

	candidates, err := buildCredentialPool(context.Background(), fixture.store, "", "GLM-5.3-Flash", normalizeConfig(Config{}), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 0 {
		t.Fatalf("candidates = %v, want none", poolOrder(candidates))
	}
}

// Acceptance criterion 8: a cross-record replay is allowed only for a definite
// pre-output allowance verdict — exhausted or plan-expired — because those are
// the only conclusions another record's entitlement can cure. Every other
// failure class, credential-level ones included, must not cross accounts.
func TestCrossRecordReplayIsRefusedForRequestLevelRejections(t *testing.T) {
	plan := ResolvedProfile{Record: "auth-a", Route: resolvedRoute{BillingDomain: billingPlanEntitlement}}
	other := ResolvedProfile{Record: "auth-b", Route: resolvedRoute{BillingDomain: billingPlanEntitlement}}
	cases := []struct {
		name    string
		class   failureClass
		allowed bool
	}{
		{name: "exhausted is an allowance verdict", class: failureExhausted, allowed: true},
		{name: "an expired plan is an allowance verdict", class: failurePlanExpired, allowed: true},
		{name: "an invalid credential is not an allowance verdict", class: failureInvalid},
		{name: "a verification block is not an allowance verdict", class: failureVerificationBlocked},
		{name: "a cooldown is not an allowance verdict", class: failureCooldown},
		{name: "3012 is a request verdict", class: failureRejected},
		{name: "a network failure is neither", class: failureUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			failure := &upstreamFailure{Class: tc.class, RetryableBeforeOutput: true}
			if got := fallbackAllowed(plan, failure, other); got != tc.allowed {
				t.Fatalf("fallbackAllowed across records = %v, want %v", got, tc.allowed)
			}
		})
	}
}

// The same-record JWT-to-key fallback is unaffected: both records share the
// account, so the billing-domain rule alone still governs it.
func TestSameRecordCrossDomainFallbackStillWorks(t *testing.T) {
	jwt := ResolvedProfile{Record: "", Route: resolvedRoute{BillingDomain: billingPlanEntitlement}}
	key := ResolvedProfile{Record: "", Route: resolvedRoute{BillingDomain: billingAPIBalance}}
	failure := &upstreamFailure{Class: failureExhausted, RetryableBeforeOutput: true}
	if !fallbackAllowed(jwt, failure, key) {
		t.Fatal("the same record's managed key fallback was refused")
	}
}

func snapshotWithUnits(model string, remaining float64) StartPlanSnapshot {
	return StartPlanSnapshot{
		Readable: true,
		Plans:    []quotaPlan{liveStartPlan("zcode-v3-start-plan-trust-1003", "instance")},
		Buckets: []startPlanBucket{{
			Models:    []string{model},
			Remaining: &remaining,
			PlanID:    "zcode-v3-start-plan-trust-1003",
		}},
	}
}
