package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

// preflightFor runs one preflight against a scripted balance body and returns the
// snapshot and the refusal.
func preflightFor(t *testing.T, body string, cfg Config) (loginPreflight, error) {
	t.Helper()
	originalBase := zcodePlanBillingBase
	originalBilling := quotaHTTPClient
	t.Cleanup(func() {
		zcodePlanBillingBase = originalBase
		quotaHTTPClient = originalBilling
	})
	fixture := newQuotaFixture(t)
	fixture.balanceBody = body
	// The quota fixture owns zcodePlanBillingBase and restores it; re-apply the
	// config this test needs after it is installed.
	_ = originalBilling
	return preflightCandidate(context.Background(), "candidate-jwt", "70861758810173130", normalizeConfig(cfg))
}

// Acceptance criterion 1: one candidate JWT covering two active plans is stored as
// one credential, and both plans appear with all their buckets.
func TestPreflightAcceptsAMultiPlanCandidate(t *testing.T) {
	body := `{"code":0,"success":true,"data":{"plans":[
		{"name":"ZCode V3 Start Plan","plan_id":"zcode-v3-start-plan-trust-1003","user_plan_id":"plan-a","status":"active"},
		{"name":"ZCode V3 Start Plan","plan_id":"zcode-v3-start-plan-0817","user_plan_id":"plan-b","status":"active"}],
		"balances":[
		{"show_name":"GLM-5.3-Flash","plan_id":"zcode-v3-start-plan-trust-1003","user_plan_id":"plan-a","capabilities":["model:glm-5.3-flash"],"remaining_units":16},
		{"show_name":"GLM-5.3-Flash","plan_id":"zcode-v3-start-plan-0817","user_plan_id":"plan-b","capabilities":["model:glm-5.3-flash"],"remaining_units":0}]}}`
	preflight, err := preflightFor(t, body, Config{})
	if err != nil {
		t.Fatalf("preflight refused a valid two-plan candidate: %v", err)
	}
	if ids := preflight.Snapshot.startPlanIDs(); len(ids) != 2 {
		t.Fatalf("plan ids = %v, want both plans of the one credential", ids)
	}
	if len(preflight.Snapshot.Buckets) != 2 {
		t.Fatalf("buckets = %d, want both plans' buckets", len(preflight.Snapshot.Buckets))
	}
	// One plan is empty and the other is not, so the model is funded overall —
	// the exact case a global verdict would have got wrong.
	if got := preflight.Snapshot.modelAllowance("GLM-5.3-Flash"); got != allowanceFunded {
		t.Fatalf("allowance = %s, want funded", got)
	}
}

// A Start Plan whose current bucket is empty is a valid credential that will
// refill. Refusing it would make the plugin unable to store the accounts it most
// needs to be able to explain.
func TestPreflightAcceptsAStartPlanWithAnEmptyBucket(t *testing.T) {
	body := `{"code":0,"success":true,"data":{"plans":[
		{"name":"ZCode V3 Start Plan","plan_id":"zcode-v3-start-plan-0817","user_plan_id":"plan-b","status":"active"}],
		"balances":[{"show_name":"GLM-5.3-Flash","plan_id":"zcode-v3-start-plan-0817","user_plan_id":"plan-b","capabilities":["model:glm-5.3-flash"],"remaining_units":0,"expires_at":"2026-10-04T00:00:00Z"}]}}`
	preflight, err := preflightFor(t, body, Config{})
	if err != nil {
		t.Fatalf("preflight refused an empty-but-valid Start Plan: %v", err)
	}
	if got := preflight.Snapshot.modelAllowance("GLM-5.3-Flash"); got != allowanceEmpty {
		t.Fatalf("allowance = %s, want empty", got)
	}
}

// An account with no Start Plan is refused. Storing it silently is what produced
// an account that could never serve a request and looked fine until it failed.
func TestPreflightRefusesAnAccountWithoutAStartPlan(t *testing.T) {
	_, err := preflightFor(t, balanceBody(balanceRow("GLM Coding", 100.0, 30.0, 70.0)), Config{})
	var refusal *preflightError
	if !asPreflightError(err, &refusal) {
		t.Fatalf("err = %v, want a preflight refusal", err)
	}
	if refusal.code != "start_plan_preflight_no_plan" {
		t.Fatalf("code = %q", refusal.code)
	}
	if !strings.Contains(refusal.message, "no active Start Plan") {
		t.Fatalf("message = %q, want it to name the missing plan", refusal.message)
	}
}

// An unreadable billing answer is neither a confirmation nor a refusal of the
// plan, but it cannot support storing an unverified credential either.
func TestPreflightRefusesWhenTheBillingAnswerIsUnreadable(t *testing.T) {
	_, err := preflightFor(t, `{"data":{"balances":"not-an-array"}}`, Config{})
	var refusal *preflightError
	if !asPreflightError(err, &refusal) {
		t.Fatalf("err = %v, want a preflight refusal", err)
	}
	if refusal.code != "start_plan_preflight_unreadable" {
		t.Fatalf("code = %q", refusal.code)
	}
	if !strings.Contains(refusal.message, "nothing was saved") {
		t.Fatalf("message = %q, want it to say nothing was stored", refusal.message)
	}
}

// An allow-list is honoured when configured and ignored when it is not. The
// fixture's candidate holds trust-1003, so that is the plan a list must name for
// the login to be accepted.
func TestPreflightAllowList(t *testing.T) {
	cases := []struct {
		name    string
		allowed []string
		wantErr bool
	}{
		{name: "unset accepts any active Start Plan"},
		{name: "the candidate's own plan is accepted", allowed: []string{"zcode-v3-start-plan-trust-1003"}},
		{name: "a configured plan the login does not hold is refused", allowed: []string{"zcode-v3-start-plan-0817"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := preflightFor(t, startPlanBalanceBody, Config{AllowedStartPlanIDs: tc.allowed})
			if tc.wantErr && err == nil {
				t.Fatal("preflight stored a credential outside the allow list")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("preflight refused: %v", err)
			}
		})
	}
}

// The refusal message names what the login actually got, so a user who
// authorized the wrong account can tell which one they got rather than only that
// it was rejected.
func TestPreflightRefusalNamesThePlanItGot(t *testing.T) {
	_, err := preflightFor(t, startPlanBalanceBody, Config{AllowedStartPlanIDs: []string{"zcode-v3-start-plan-0817"}})
	var refusal *preflightError
	if !asPreflightError(err, &refusal) {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(refusal.message, "zcode-v3-start-plan-trust-1003") {
		t.Fatalf("message = %q, want it to name the plan the login got", refusal.message)
	}
}

// The refusal message is composed only of plan ids, so it can never carry the
// credential, the account id, or an upstream body.
func TestPreflightRefusalCarriesNoCredentialOrAccountIdentity(t *testing.T) {
	_, err := preflightFor(t, startPlanBalanceBody, Config{AllowedStartPlanIDs: []string{"zcode-v3-start-plan-0817"}})
	if err == nil {
		t.Fatal("expected a refusal")
	}
	for _, forbidden := range []string{"candidate-jwt", "70861758810173130"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("refusal leaks %q: %s", forbidden, err)
		}
	}
}

// The diagnostic line for a preflight identifies the account by digest.
func TestPreflightDiagnosticIdentityIsADigest(t *testing.T) {
	if got := preflightIdentityDiag("70861758810173130"); strings.Contains(got, "70861758810173130") || len(got) < 8 {
		t.Fatalf("preflightIdentityDiag = %q, want a digest", got)
	}
	if preflightIdentityDiag("") != "(none)" {
		t.Fatal("an absent account id should render as (none)")
	}
	// The login digest is domain-separated from the plan-instance digest, so the
	// same value hashed for the two purposes never collides.
	same := "70861758810173130"
	if preflightIdentityDiag(same) == identityDigestOf(planSnapshotDigest, same) {
		t.Fatal("the login and plan-instance digests are not domain-separated")
	}
}

// The persisted record names the plan and per-model standing, and carries no
// token, no raw user id, and no raw plan instance id.
func TestAttachPreflightRecordsOnlyRedactedFacts(t *testing.T) {
	now := time.Now()
	preflight := loginPreflight{
		UserID: "70861758810173130",
		Snapshot: StartPlanSnapshot{
			CheckedAt: now,
			Readable:  true,
			Plans:     []quotaPlan{liveStartPlan("zcode-v3-start-plan-0817", "34dd6d87-1234-4321-abcd-0123456789ab")},
			Buckets: []startPlanBucket{{
				Models:       []string{"GLM-5.3-Flash"},
				Remaining:    float64Ptr(0),
				PlanID:       "zcode-v3-start-plan-0817",
				PlanInstance: planInstanceRef("zcode-v3-start-plan-0817", "34dd6d87-1234-4321-abcd-0123456789ab"),
				ExpiresAt:    "2026-10-04T00:00:00Z",
				Period:       "daily",
			}},
		},
	}
	doc := attachPreflight([]byte(`{"zcode":{"identity_id":"zcode-x","jwt":{"token":"secret-jwt"}}}`), preflight, "zcode-x", normalizeConfig(Config{}), now)
	// The preflight's own fields must add nothing sensitive. The JWT is already
	// in the seed document and is checked to have survived untouched rather than
	// to be absent: the plugin preserves the credential it was handed.
	text := string(doc)
	if !strings.Contains(text, "secret-jwt") {
		t.Fatal("the preflight dropped the credential it was supposed to preserve")
	}
	for _, forbidden := range []string{"70861758810173130", "34dd6d87-1234"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("preflight record leaks %q: %s", forbidden, text)
		}
	}
	for _, required := range []string{"zcode-v3-start-plan-0817", "GLM-5.3-Flash", "user_id_hash"} {
		if !strings.Contains(text, required) {
			t.Fatalf("preflight record is missing %q: %s", required, text)
		}
	}
}

// An unreadable preflight writes no snapshot, so a failed login cannot leave a
// half-written entitlement record on the credential.
func TestAttachPreflightWritesNothingForAnUnreadableReading(t *testing.T) {
	doc := attachPreflight([]byte(`{"zcode":{"identity_id":"zcode-x"}}`), loginPreflight{
		Snapshot: StartPlanSnapshot{CheckedAt: time.Now(), Readable: false},
	}, "zcode-x", normalizeConfig(Config{}), time.Now())
	if strings.Contains(string(doc), `"plan"`) {
		t.Fatalf("an unreadable preflight wrote a snapshot: %s", doc)
	}
}

func asPreflightError(err error, target **preflightError) bool {
	refusal, ok := err.(*preflightError)
	if ok {
		*target = refusal
	}
	return ok
}
