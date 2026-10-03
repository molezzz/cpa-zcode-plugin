package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
)

// planFixture wires an executor request to a scripted Messages upstream, a
// separate billing endpoint, and a fake auth store. The billing endpoint gets its
// own server deliberately: the recheck calls it on the request path, and sharing
// the Messages server would make a billing call indistinguishable from an attempt.
type planFixture struct {
	t        *testing.T
	upstream *scriptedUpstream
	store    *fakeAuthStore
	billing  *httptest.Server

	mu           sync.Mutex
	balance      string
	billingCalls int
}

// billingRequests counts the billing reads, so a test can assert that a
// request-path refresh did not become one upstream call per request.
func (f *planFixture) billingRequests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.billingCalls
}

func newPlanFixture(t *testing.T, scripts ...upstreamScript) *planFixture {
	t.Helper()
	fixture := &planFixture{
		t:        t,
		upstream: newScriptedUpstream(t, scripts...),
		store:    &fakeAuthStore{docs: map[string]json.RawMessage{}},
		balance:  startPlanBalanceBody,
	}
	mux := http.NewServeMux()
	mux.HandleFunc(billingBalancePath, func(w http.ResponseWriter, _ *http.Request) {
		fixture.mu.Lock()
		body := fixture.balance
		fixture.billingCalls++
		fixture.mu.Unlock()
		writeBilling(w, 0, body)
	})
	fixture.billing = httptest.NewServer(mux)
	t.Cleanup(fixture.billing.Close)

	// The host override installs its own auth store, so the fixture's store is
	// installed after it: the test store is the one both the pool and the state
	// recorder must see.
	overrideHost(t)
	originalStore := authStoreProvider
	authStoreProvider = func() AuthStore { return fixture.store }
	originalBilling := zcodePlanBillingBase
	zcodePlanBillingBase = fixture.billing.URL
	// The request-path refresh is gated per credential and model, so a test that
	// exercises it starts with a fresh gate rather than inheriting another test's.
	originalGate := activePlanRefreshGate
	activePlanRefreshGate = newPlanRefreshGate()
	t.Cleanup(func() {
		authStoreProvider = originalStore
		zcodePlanBillingBase = originalBilling
		activePlanRefreshGate = originalGate
	})
	return fixture
}

// setBalance sets the billing answer the recheck will read.
func (f *planFixture) setBalance(body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.balance = body
}

// messagesCalls returns only the Messages attempts, so a billing call is never
// counted as an attempt at the model.
func (f *planFixture) messagesCalls() []observedCall {
	var out []observedCall
	for _, call := range f.upstream.calls() {
		if call.endpoint != billingBalancePath {
			out = append(out, call)
		}
	}
	return out
}

// planDoc builds one account record whose JWT is recorded as serving the model.
func planDoc(t *testing.T, identity string, models map[string]int) []byte {
	t.Helper()
	doc := newTestAccountDoc(t, identity, makeJWT(t, map[string]any{"sub": strings.TrimPrefix(identity, "zcode-")}), jwtStatusActive, "")
	if len(models) == 0 {
		return doc
	}
	section := renderPlanSnapshot(StartPlanSnapshot{
		CheckedAt: time.Now(),
		Readable:  true,
		Plans:     []quotaPlan{liveStartPlan("zcode-v3-start-plan-trust-1003", "instance-"+identity)},
		Buckets:   planBuckets(models),
	}, normalizeConfig(Config{}))
	patched, err := writePlanSnapshotSection(doc, section)
	if err != nil {
		t.Fatal(err)
	}
	return patched
}

func planBuckets(models map[string]int) []startPlanBucket {
	buckets := make([]startPlanBucket, 0, len(models))
	for model, remaining := range models {
		value := float64(remaining)
		buckets = append(buckets, startPlanBucket{
			Models:    []string{model},
			Remaining: &value,
			PlanID:    "zcode-v3-start-plan-trust-1003",
		})
	}
	return buckets
}

// With a model recorded as spent, the JWT must not be attempted at all: the
// request goes to the fallback rather than paying for an attempt the credential
// cannot satisfy.
func TestPerModelBlockSkipsOnlyThatModel(t *testing.T) {
	fixture := newPlanFixture(t, upstreamScript{frames: completeAnthropicSSE()})
	doc := planDoc(t, "zcode-split", map[string]int{"GLM-5.2": 0, "GLM-5.3-Flash": 40})
	doc = withManagedKey(doc)
	doc = withModelQuota(t, doc, "GLM-5.2", time.Now().Add(time.Hour))
	addFakeAccount(t, fixture.store, "auth-1", "zcode-split", string(doc))

	// The request asks for Flash, which has allowance: the JWT serves it.
	env := callMethod(t, "executor.execute", executorRequestJSON(t, doc, flashPayload(), "", nil))
	if !env.OK {
		t.Fatalf("flash request failed: %+v", env.Error)
	}
	if calls := fixture.messagesCalls(); len(calls) != 1 || calls[0].auth != "Bearer "+extractJWT(t, doc) {
		t.Fatalf("calls = %+v, want the JWT to serve flash", calls)
	}

	// The same record asked for the spent model: the JWT is skipped, and the
	// managed key of that same record serves instead. The caller is told which
	// credential is serving, not handed a bare failure.
	fixture.resetUpstream()
	env = callMethod(t, "executor.execute", executorRequestJSON(t, doc, glm52Payload(), "", nil))
	if !env.OK {
		t.Fatalf("the fallback did not serve the spent model: %+v", env.Error)
	}
	calls := fixture.messagesCalls()
	if len(calls) != 1 || calls[0].apiKey != testAPIKeyMaterial {
		t.Fatalf("calls = %+v, want the managed key of the same record to serve", calls)
	}
}

// An exhaustion the plugin learns from the Messages endpoint is recorded against
// that model only. Acceptance criterion 3: GLM-5.3 failing must not take Flash
// out of service on the same credential.
func TestUpstreamExhaustionBlocksOnlyTheFailingModel(t *testing.T) {
	fixture := newPlanFixture(t, upstreamScript{status: http.StatusPaymentRequired, body: `{"code":1005,"msg":"quota exhausted"}`})
	doc := planDoc(t, "zcode-narrow", map[string]int{"GLM-5.2": 50, "GLM-5.3-Flash": 40})
	addFakeAccount(t, fixture.store, "auth-1", "zcode-narrow", string(doc))

	env := callMethod(t, "executor.execute", executorRequestJSON(t, doc, glm52Payload(), "", nil))
	_ = env
	snap := readStoredModelQuota(t, fixture.store.docs["auth-1"])
	if snap.JWTStatus == jwtStatusExhausted {
		t.Fatalf("the whole credential was marked exhausted: %+v", snap)
	}
	blocked := snap.ModelQuota
	if len(blocked) == 0 {
		t.Fatalf("no per-model conclusion was recorded: %+v", snap)
	}
	if _, flashBlocked := blocked["GLM-5.3-Flash"]; flashBlocked {
		t.Fatalf("an unrelated model was blocked by GLM-5.2's failure: %+v", blocked)
	}
}

// When the balance confirms the model is spent, the caller is told the plan has
// nothing left for that model and when it returns — not that some other
// credential's balance needs topping up.
func TestExhaustedModelReportsThePlanAndTheRefill(t *testing.T) {
	fixture := newPlanFixture(t, upstreamScript{status: http.StatusPaymentRequired, body: `{"code":1005,"msg":"quota exhausted"}`})
	doc := planDoc(t, "zcode-refill", map[string]int{"GLM-5.2": 0})
	addFakeAccount(t, fixture.store, "auth-1", "zcode-refill", string(doc))
	// The recheck reads the bucket's own window, and that window is what the
	// caller's message must quote.
	fixture.setBalance(`{"code":0,"success":true,"data":{"plans":[{"name":"ZCode V3 Start Plan","plan_id":"zcode-v3-start-plan-trust-1003","user_plan_id":"p","status":"active","entitlements":[{"entitlement_id":"e1","period":"daily"}]}],"balances":[{"show_name":"GLM-5.2","entitlement_id":"e1","plan_id":"zcode-v3-start-plan-trust-1003","user_plan_id":"p","capabilities":["model:glm-5.2"],"remaining_units":0,"expires_at":"2026-10-04T09:00:00Z"}]}}`)
	fixture.setBalance(`{"code":0,"success":true,"data":{"plans":[{"name":"ZCode V3 Start Plan","plan_id":"zcode-v3-start-plan-trust-1003","user_plan_id":"p","status":"active"}],"balances":[{"show_name":"GLM-5.2","plan_id":"zcode-v3-start-plan-trust-1003","user_plan_id":"p","capabilities":["model:glm-5.2"],"remaining_units":0,"expires_at":"2026-10-04T09:00:00Z"}]}}`)

	env := callMethod(t, "executor.execute", executorRequestJSON(t, doc, glm52Payload(), "", nil))
	failure := envelopeFailure(t, env)
	if failure.Code != modelAllowanceExhaustedCode {
		t.Fatalf("failure code = %q, want %q", failure.Code, modelAllowanceExhaustedCode)
	}
	if !strings.Contains(failure.Message, "GLM-5.2") || !strings.Contains(failure.Message, "2026-10-04T09:00:00Z") {
		t.Fatalf("message = %q, want it to name the model and its refill", failure.Message)
	}
	// It must not be reported as the managed key's own insufficient balance: that
	// is a different problem with a different fix.
	if strings.Contains(failure.Message, "1113") || failure.Code == "upstream_quota_exhausted" && failure.Message == "" {
		t.Fatalf("failure misreported the cause: %+v", failure)
	}
}

// A balance reading that contradicts the Messages endpoint's exhaustion clears the
// per-model block instead of recording one: the billing endpoint is the
// authority on what the credential holds.
func TestRecheckClearsAContradictedModelBlock(t *testing.T) {
	fixture := newPlanFixture(t, upstreamScript{status: http.StatusPaymentRequired, body: `{"code":1005,"msg":"quota exhausted"}`})
	doc := planDoc(t, "zcode-contradicted", map[string]int{"GLM-5.2": 40})
	addFakeAccount(t, fixture.store, "auth-1", "zcode-contradicted", string(doc))
	// The account was already recorded as blocked for this model.
	doc = withModelQuota(t, doc, "GLM-5.2", time.Now().Add(time.Hour))
	fixture.store.docs["auth-1"] = json.RawMessage(doc)
	// The request asks for the blocked model, and the billing endpoint — the
	// authority on what the credential holds — still shows allowance for it.
	fixture.setBalance(`{"code":0,"success":true,"data":{"plans":[{"name":"ZCode V3 Start Plan","plan_id":"zcode-v3-start-plan-trust-1003","user_plan_id":"p","status":"active"}],"balances":[{"show_name":"GLM-5.2","plan_id":"zcode-v3-start-plan-trust-1003","user_plan_id":"p","capabilities":["model:glm-5.2"],"remaining_units":40,"expires_at":"2026-10-04T09:00:00Z"}]}}`)

	env := callMethod(t, "executor.execute", executorRequestJSON(t, doc, glm52Payload(), "", nil))
	_ = env
	snap := readStoredModelQuota(t, fixture.store.docs["auth-1"])
	if snap.JWTStatus == jwtStatusExhausted {
		t.Fatalf("a funded balance reading marked the credential exhausted: %+v", snap)
	}
	if _, blocked := snap.ModelQuota["GLM-5.2"]; blocked {
		t.Fatalf("a model with funded allowance is still blocked: %+v", snap.ModelQuota)
	}
}

// A 3012 is a request-level verdict. It must never be replayed on another
// record's credential, however the pool is ordered.
func TestPoolDoesNotReplayARequestRejection(t *testing.T) {
	upstream := newScriptedUpstream(t,
		upstreamScript{status: http.StatusBadRequest, body: `{"code":3012,"msg":"unusual activity"}`},
		upstreamScript{frames: completeAnthropicSSE()},
	)
	overrideHost(t)
	store := &fakeAuthStore{docs: map[string]json.RawMessage{}}
	originalStore := authStoreProvider
	authStoreProvider = func() AuthStore { return store }
	t.Cleanup(func() { authStoreProvider = originalStore })

	primary := planDoc(t, "zcode-first", map[string]int{"GLM-5.2": 10})
	other := planDoc(t, "zcode-second", map[string]int{"GLM-5.2": 10})
	addFakeAccount(t, store, "auth-1", "zcode-first", string(primary))
	addFakeAccount(t, store, "auth-2", "zcode-second", string(other))

	env := callMethod(t, "executor.execute", executorRequestJSON(t, primary, glm52Payload(), "", nil))
	if env.OK {
		t.Fatal("a 3012 replayed onto another account's credential and succeeded")
	}
	if got := len(upstream.calls()); got != 1 {
		t.Fatalf("upstream attempts = %d, want 1: a request rejection must not cross accounts", got)
	}
}

// With the pool disabled, a second eligible record is never attempted.
func TestPoolDisabledNeverAttemptsAnotherRecord(t *testing.T) {
	upstream := newScriptedUpstream(t,
		upstreamScript{status: http.StatusPaymentRequired, body: `{"code":1005,"msg":"quota exhausted"}`},
		upstreamScript{frames: completeAnthropicSSE()},
	)
	overrideHost(t)
	overrideConfig(t, func(cfg *Config) { cfg.StartPlanCredentialPool.Enabled = boolPtr(false) })
	store := &fakeAuthStore{docs: map[string]json.RawMessage{}}
	originalStore := authStoreProvider
	authStoreProvider = func() AuthStore { return store }
	t.Cleanup(func() { authStoreProvider = originalStore })
	originalBilling := zcodePlanBillingBase
	zcodePlanBillingBase = upstream.server.URL
	t.Cleanup(func() { zcodePlanBillingBase = originalBilling })

	primary := planDoc(t, "zcode-only-first", map[string]int{"GLM-5.2": 0})
	other := planDoc(t, "zcode-only-second", map[string]int{"GLM-5.2": 10})
	addFakeAccount(t, store, "auth-1", "zcode-only-first", string(primary))
	addFakeAccount(t, store, "auth-2", "zcode-only-second", string(other))

	callMethod(t, "executor.execute", executorRequestJSON(t, primary, glm52Payload(), "", nil))
	// The billing recheck shares the scripted server here, so only Messages
	// attempts count: the question is whether another record's credential was tried.
	messages := 0
	for _, call := range upstream.calls() {
		if call.endpoint != billingBalancePath {
			messages++
		}
	}
	if messages > 1 {
		t.Fatalf("messages attempts = %d, want the pool disabled to schedule only the host's record", messages)
	}
}

// Acceptance criterion 2 and 5 end to end: one plan's Flash bucket empty while
// another's is funded keeps the request on the Coding Plan route, and produces
// exactly one credential rather than one per plan.
func TestMultiPlanCredentialServesFlashFromItsFundedPlan(t *testing.T) {
	upstream := newScriptedUpstream(t, upstreamScript{frames: completeAnthropicSSE()})
	overrideHost(t)
	store := &fakeAuthStore{docs: map[string]json.RawMessage{}}
	originalStore := authStoreProvider
	authStoreProvider = func() AuthStore { return store }
	t.Cleanup(func() { authStoreProvider = originalStore })
	originalBilling := zcodePlanBillingBase
	zcodePlanBillingBase = upstream.server.URL
	t.Cleanup(func() { zcodePlanBillingBase = originalBilling })

	doc := newTestAccountDoc(t, "zcode-multi", makeJWT(t, map[string]any{"sub": "multi"}), jwtStatusActive, "")
	section := renderPlanSnapshot(StartPlanSnapshot{
		CheckedAt: time.Now(),
		Readable:  true,
		Plans: []quotaPlan{
			liveStartPlan("zcode-v3-start-plan-trust-1003", "plan-a"),
			liveStartPlan("zcode-v3-start-plan-0817", "plan-b"),
		},
		Buckets: []startPlanBucket{
			{Models: []string{"GLM-5.3-Flash"}, Remaining: float64Ptr(0), PlanID: "zcode-v3-start-plan-0817", ExpiresAt: "2026-10-04T00:00:00Z"},
			{Models: []string{"GLM-5.3-Flash"}, Remaining: float64Ptr(16), PlanID: "zcode-v3-start-plan-trust-1003", ExpiresAt: "2026-10-04T00:00:00Z"},
		},
	}, normalizeConfig(Config{}))
	doc, err := writePlanSnapshotSection(doc, section)
	if err != nil {
		t.Fatal(err)
	}
	addFakeAccount(t, store, "auth-1", "zcode-multi", string(doc))

	env := callMethod(t, "executor.execute", executorRequestJSON(t, doc, flashPayload(), "", nil))
	if !env.OK {
		t.Fatalf("flash request failed although one plan's bucket was funded: %+v", env.Error)
	}
	calls := upstream.calls()
	if len(calls) != 1 || calls[0].endpoint != zcodeMessagesPath {
		t.Fatalf("calls = %+v, want the Start Plan route", calls)
	}
	// One credential, not one per plan: the request presents exactly one JWT.
	if got := len(store.entries); got != 1 {
		t.Fatalf("auth records = %d, want the two plans to remain one credential", got)
	}
}

// resetUpstream forgets the calls recorded so far, so one test can assert on a
// second request's attempts independently of the first.
func (f *planFixture) resetUpstream() {
	f.upstream.mu.Lock()
	defer f.upstream.mu.Unlock()
	f.upstream.observed = nil
}

// withManagedKey gives the record its own managed fallback key, which is what a
// real record with an exhausted model ends up using.
func withManagedKey(doc []byte) []byte {
	raw, err := patchZcodeNamespace(doc, func(zcode map[string]any) error {
		zcode["api_key"] = map[string]any{
			"status": apiKeyStatusActive, "managed": true,
			"key_id": "key-1", "key_material": testAPIKeyMaterial,
		}
		return nil
	})
	if err != nil {
		panic(err)
	}
	return raw
}

func withModelQuota(t *testing.T, doc []byte, model string, until time.Time) []byte {
	t.Helper()
	patched, err := patchZcodeNamespace(doc, func(zcode map[string]any) error {
		jwt, _ := zcode["jwt"].(map[string]any)
		jwt["model_quota"] = map[string]any{model: until.UTC().Format(time.RFC3339)}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return patched
}

// withModelQuotaDeadline records a raw per-model deadline, which is what a
// conclusion with no refill time stores.
func withModelQuotaDeadline(t *testing.T, doc []byte, model, deadline string) []byte {
	t.Helper()
	patched, err := patchZcodeNamespace(doc, func(zcode map[string]any) error {
		jwt, _ := zcode["jwt"].(map[string]any)
		jwt["model_quota"] = map[string]any{model: deadline}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return patched
}

func withPlanReset(t *testing.T, doc []byte, model, reset string) []byte {
	t.Helper()
	patched, err := patchZcodeNamespace(doc, func(zcode map[string]any) error {
		plan, _ := zcode["plan"].(map[string]any)
		models, _ := plan["models"].(map[string]any)
		line, _ := models[model].(map[string]any)
		if line != nil {
			line["reset_at"] = reset
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return patched
}

func readStoredModelQuota(t *testing.T, doc json.RawMessage) credentialSnapshot {
	t.Helper()
	snap, err := readCredentialSnapshot(doc)
	if err != nil {
		t.Fatalf("read stored snapshot: %v", err)
	}
	return snap
}

func extractJWT(t *testing.T, doc []byte) string {
	t.Helper()
	snap, err := readCredentialSnapshot(doc)
	if err != nil {
		t.Fatal(err)
	}
	return snap.JWTToken
}

func flashPayload() []byte {
	return []byte(`{"model":"GLM-5.3-Flash","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`)
}

func glm52Payload() []byte {
	return []byte(`{"model":"GLM-5.2","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`)
}

// envelopeFailure reads the code and message of a failure envelope, so a test can
// assert on the cause the caller is actually told.
func envelopeFailure(t *testing.T, env pluginabi.Envelope) upstreamFailure {
	t.Helper()
	if env.OK {
		t.Fatalf("expected a failure envelope, got a successful one: %s", env.Result)
	}
	return upstreamFailure{Code: env.Error.Code, Message: env.Error.Message}
}

// envelopeCode reads a failure envelope's code, or "" when the call succeeded.
func envelopeCode(t *testing.T, env pluginabi.Envelope) string {
	t.Helper()
	if env.OK {
		return ""
	}
	return env.Error.Code
}

// A model still recorded as blocked whose bucket is still empty keeps the block,
// but on the deadline the fresh reading gives it. A block that outlived its own
// evidence would keep the model out of service on a date nothing describes.
func TestBlockedModelKeepsItsBlockAndTakesTheFreshDeadline(t *testing.T) {
	fixture := newPlanFixture(t, upstreamScript{frames: completeAnthropicSSE()})
	doc := planDoc(t, "zcode-still-empty", map[string]int{"GLM-5.2": 0})
	addFakeAccount(t, fixture.store, "auth-1", "zcode-still-empty", string(doc))
	doc = withManagedKey(doc)
	// The recorded deadline is in the future, so the model really is out of
	// service when this request arrives and the refresh is what keeps it there.
	doc = withModelQuota(t, doc, "GLM-5.2", time.Now().Add(time.Hour))
	fixture.store.docs["auth-1"] = json.RawMessage(doc)
	fixture.setBalance(`{"code":0,"success":true,"data":{"plans":[{"name":"ZCode V3 Start Plan","plan_id":"zcode-v3-start-plan-trust-1003","user_plan_id":"p","status":"active","entitlements":[{"entitlement_id":"e1","period":"daily"}]}],"balances":[{"show_name":"GLM-5.2","entitlement_id":"e1","plan_id":"zcode-v3-start-plan-trust-1003","user_plan_id":"p","capabilities":["model:glm-5.2"],"remaining_units":0,"expires_at":"2099-01-01T00:00:00Z"}]}}`)

	env := callMethod(t, "executor.execute", executorRequestJSON(t, doc, glm52Payload(), "", nil))
	if !env.OK {
		t.Fatalf("the managed key should have served the still-empty model: %+v", env.Error)
	}
	calls := fixture.messagesCalls()
	if len(calls) != 1 || calls[0].apiKey != testAPIKeyMaterial {
		t.Fatalf("calls = %d, want the still-empty model kept blocked and the key to serve", len(calls))
	}
}

// A blocked model whose bucket the fresh reading cannot see is still blocked. An
// unreadable balance is not evidence the allowance came back.
func TestBlockedModelIsKeptWhenTheReadingIsUnreadable(t *testing.T) {
	fixture := newPlanFixture(t, upstreamScript{frames: completeAnthropicSSE()})
	doc := planDoc(t, "zcode-unreadable", map[string]int{"GLM-5.2": 40})
	addFakeAccount(t, fixture.store, "auth-1", "zcode-unreadable", string(doc))
	doc = withManagedKey(doc)
	doc = withModelQuota(t, doc, "GLM-5.2", time.Now().Add(time.Hour))
	fixture.store.docs["auth-1"] = json.RawMessage(doc)
	fixture.setBalance(`{"data":{"balances":"not-an-array"}}`)

	env := callMethod(t, "executor.execute", executorRequestJSON(t, doc, glm52Payload(), "", nil))
	if !env.OK {
		t.Fatalf("the managed key should still serve: %+v", env.Error)
	}
	calls := fixture.messagesCalls()
	if len(calls) != 1 || calls[0].apiKey != testAPIKeyMaterial {
		t.Fatalf("calls = %+v, want the unreadable reading to keep the block", calls)
	}
}

// A record whose model block keeps the JWT out of a request must not have the
// whole credential taken out of service: the other models on it keep working.
// This is the path where the skip is re-asserted from the plan, so it is the one
// most able to undo the per-model separation.
func TestSkippedModelDoesNotDisableTheWholeCredential(t *testing.T) {
	fixture := newPlanFixture(t, upstreamScript{frames: completeAnthropicSSE()})
	doc := planDoc(t, "zcode-still-serving", map[string]int{"GLM-5.2": 0, "GLM-5.3-Flash": 40})
	doc = withManagedKey(doc)
	doc = withModelQuota(t, doc, "GLM-5.2", time.Now().Add(time.Hour))
	addFakeAccount(t, fixture.store, "auth-1", "zcode-still-serving", string(doc))

	// The spent model is served by the managed key, which re-asserts the skip.
	if env := callMethod(t, "executor.execute", executorRequestJSON(t, doc, glm52Payload(), "", nil)); !env.OK {
		t.Fatalf("the managed key did not serve: %+v", env.Error)
	}
	snap := readStoredModelQuota(t, fixture.store.docs["auth-1"])
	if snap.JWTStatus == jwtStatusExhausted {
		t.Fatalf("a per-model skip disabled the whole credential: %+v", snap)
	}

	// The model that still has allowance must therefore still be schedulable.
	if !jwtUsableForModel(snap, "GLM-5.3-Flash", time.Now()) {
		t.Fatalf("a model with allowance became unusable: %+v", snap)
	}
	env := callMethod(t, "executor.execute", executorRequestJSON(t, doc, flashPayload(), "", nil))
	if !env.OK {
		t.Fatalf("the funded model stopped being served: %+v", env.Error)
	}
	if calls := fixture.messagesCalls(); len(calls) == 0 || calls[len(calls)-1].auth == "" {
		t.Fatalf("calls = %+v, want the funded model served by the JWT", calls)
	}
}

// A model's block must land even when the credential already tracks another
// blocked model: the change-detection must not read "this model has no entry" and
// "this model has an entry with no deadline" as the same thing.
func TestFirstModelBlockIsRecordedAlongsideAnother(t *testing.T) {
	fixture := newPlanFixture(t, upstreamScript{status: http.StatusPaymentRequired, body: `{"code":1005,"msg":"quota exhausted"}`})
	doc := planDoc(t, "zcode-two-blocked", map[string]int{"GLM-5.2": 10, "GLM-5.3-Flash": 10})
	addFakeAccount(t, fixture.store, "auth-1", "zcode-two-blocked", string(doc))
	// The billing recheck is unreachable here, so the conclusion carries no
	// deadline — the case that used to be indistinguishable from "no entry".
	fixture.setBalance(`{"data":{"balances":"not-an-array"}}`)

	doc = withModelQuotaDeadline(t, doc, "GLM-5.2", modelQuotaNoDeadline)
	fixture.store.docs["auth-1"] = json.RawMessage(doc)

	callMethod(t, "executor.execute", executorRequestJSON(t, doc, flashPayload(), "", nil))
	snap := readStoredModelQuota(t, fixture.store.docs["auth-1"])
	if _, blocked := snap.ModelQuota["GLM-5.3-Flash"]; !blocked {
		t.Fatalf("a new model block was dropped beside an existing one: %+v", snap.ModelQuota)
	}
}

// A credential holding both a reserved plan and an ordinary one is not demoted:
// the reservation is about the product, not about every record that also happens
// to hold something else.
func TestMixedPlanCredentialIsNotDemoted(t *testing.T) {
	snapshot := StartPlanSnapshot{
		Readable: true,
		Plans: []quotaPlan{
			liveStartPlan("zcode-v3-start-plan-trust-1003", "plan-a"),
			liveStartPlan("zcode-v3-start-plan-0817", "plan-b"),
		},
	}
	if snapshot.isLastPriority(normalizeConfig(Config{})) {
		t.Fatal("a credential holding a non-reserved plan was demoted to last priority")
	}
	reservedOnly := StartPlanSnapshot{Readable: true, Plans: []quotaPlan{liveStartPlan("zcode-v3-start-plan-0817", "plan-b")}}
	if !reservedOnly.isLastPriority(normalizeConfig(Config{})) {
		t.Fatal("a credential holding only the reserved plan was not demoted")
	}
}

// Each pooled record presents its own installation. Reusing the host-selected
// record's device id would describe two accounts as one device.
func TestPooledAttemptPresentsItsOwnDevice(t *testing.T) {
	overrideHost(t)
	store := &fakeAuthStore{docs: map[string]json.RawMessage{}}
	originalStore := authStoreProvider
	authStoreProvider = func() AuthStore { return store }
	t.Cleanup(func() { authStoreProvider = originalStore })

	primary := planDoc(t, "zcode-device-a", map[string]int{"GLM-5.2": 10})
	other := planDoc(t, "zcode-device-b", map[string]int{"GLM-5.2": 10})
	addFakeAccount(t, store, "auth-1", "zcode-device-a", string(withDeviceID(primary, "11111111-1111-4111-8111-111111111111")))
	addFakeAccount(t, store, "auth-2", "zcode-device-b", string(withDeviceID(other, "22222222-2222-4222-8222-222222222222")))

	profiles := pooledProfiles([]poolCandidate{
		{AuthIndex: "auth-2", IdentityID: "zcode-device-b", Document: store.docs["auth-2"]},
	}, normalizeConfig(defaultConfig()), "GLM-5.2", nil, time.Now())
	if len(profiles) != 1 {
		t.Fatalf("profiles = %d, want one", len(profiles))
	}
	if got := profiles[0].Headers.Get(deviceMidHeader); got != "22222222-2222-4222-8222-222222222222" {
		t.Fatalf("pooled device id = %q, want the pooled record's own", got)
	}
}

// A confirmed model exhaustion is a credential verdict about this model, so it
// must still permit the same record's managed key to serve.
func TestConfirmedExhaustionStillPermitsTheFallback(t *testing.T) {
	fixture := newPlanFixture(t,
		upstreamScript{status: http.StatusPaymentRequired, body: `{"code":1005,"msg":"quota exhausted"}`},
		upstreamScript{frames: completeAnthropicSSE()},
	)
	// The model is not yet blocked: this is the upstream reporting the exhaustion,
	// which is what the recheck then confirms against the billing endpoint. The
	// managed key spends the API balance rather than the plan's bucket, so it is
	// what serves the request once the plan's allowance is confirmed spent.
	doc := planDoc(t, "zcode-confirmed", map[string]int{"GLM-5.2": 0})
	doc = withManagedKey(doc)
	addFakeAccount(t, fixture.store, "auth-1", "zcode-confirmed", string(doc))
	fixture.setBalance(`{"code":0,"success":true,"data":{"plans":[{"name":"ZCode V3 Start Plan","plan_id":"zcode-v3-start-plan-trust-1003","user_plan_id":"p","status":"active"}],"balances":[{"show_name":"GLM-5.2","plan_id":"zcode-v3-start-plan-trust-1003","user_plan_id":"p","capabilities":["model:glm-5.2"],"remaining_units":0,"expires_at":"2026-10-04T09:00:00Z"}]}}`)

	env := callMethod(t, "executor.execute", executorRequestJSON(t, doc, glm52Payload(), "", nil))
	if !env.OK {
		t.Fatalf("the managed key did not serve a confirmed-empty model: %+v", env.Error)
	}
	calls := fixture.messagesCalls()
	if len(calls) != 2 {
		t.Fatalf("attempts = %d, want the JWT then the managed key", len(calls))
	}
	if calls[0].auth == "" || calls[1].apiKey != testAPIKeyMaterial {
		t.Fatalf("attempts = %+v, want the JWT then the managed key", calls)
	}
}

// A burst of requests for one blocked model collapses into a single billing read.
func TestBlockedModelRefreshIsGated(t *testing.T) {
	fixture := newPlanFixture(t, upstreamScript{frames: completeAnthropicSSE()})
	doc := planDoc(t, "zcode-gated", map[string]int{"GLM-5.2": 0})
	doc = withManagedKey(doc)
	addFakeAccount(t, fixture.store, "auth-1", "zcode-gated", string(doc))
	doc = withModelQuota(t, doc, "GLM-5.2", time.Now().Add(time.Hour))
	fixture.store.docs["auth-1"] = json.RawMessage(doc)
	fixture.setBalance(`{"code":0,"success":true,"data":{"plans":[{"name":"ZCode V3 Start Plan","plan_id":"zcode-v3-start-plan-trust-1003","user_plan_id":"p","status":"active"}],"balances":[{"show_name":"GLM-5.2","plan_id":"zcode-v3-start-plan-trust-1003","user_plan_id":"p","capabilities":["model:glm-5.2"],"remaining_units":40}]}}`)

	for i := 0; i < 4; i++ {
		callMethod(t, "executor.execute", executorRequestJSON(t, doc, glm52Payload(), "", nil))
	}
	// The billing endpoint is on its own server, so its request count is exact.
	if got := fixture.billingRequests(); got != 1 {
		t.Fatalf("billing reads = %d for four requests on one blocked model, want 1", got)
	}
}

func withDeviceID(doc []byte, id string) []byte {
	raw, err := patchZcodeNamespace(doc, func(zcode map[string]any) error {
		zcode[deviceIDField] = id
		return nil
	})
	if err != nil {
		panic(err)
	}
	return raw
}

// A pooled record's own exhaustion is recorded on that record, read from that
// record's balance. Reading the host-selected record's balance instead would both
// strand a record that still has units and falsely exhaust one that does not.
func TestPooledExhaustionIsRecordedOnItsOwnRecord(t *testing.T) {
	overrideHost(t)
	store := &fakeAuthStore{docs: map[string]json.RawMessage{}}
	originalStore := authStoreProvider
	authStoreProvider = func() AuthStore { return store }
	t.Cleanup(func() { authStoreProvider = originalStore })

	// The host-selected record cannot serve the model, so the request reaches the
	// pooled one; the pooled one then reports the exhaustion upstream.
	primary := planDoc(t, "zcode-pool-primary", map[string]int{"GLM-5.2": 0})
	primary = withModelQuota(t, primary, "GLM-5.2", time.Now().Add(time.Hour))
	pooled := planDoc(t, "zcode-pool-other", map[string]int{"GLM-5.2": 10})
	addFakeAccount(t, store, "auth-1", "zcode-pool-primary", string(primary))
	addFakeAccount(t, store, "auth-2", "zcode-pool-other", string(pooled))
	// The recheck must read the pooled record's own balance, so the billing
	// endpoint answers on its own server with that record's entitlement.
	billing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeBilling(w, 0, `{"code":0,"success":true,"data":{"plans":[{"name":"ZCode V3 Start Plan","plan_id":"zcode-v3-start-plan-trust-1003","user_plan_id":"q","status":"active"}],"balances":[{"show_name":"GLM-5.2","plan_id":"zcode-v3-start-plan-trust-1003","user_plan_id":"q","capabilities":["model:glm-5.2"],"remaining_units":0,"expires_at":"2026-10-04T09:00:00Z"}]}}`)
	}))
	t.Cleanup(billing.Close)
	originalBilling := zcodePlanBillingBase
	zcodePlanBillingBase = billing.URL
	t.Cleanup(func() { zcodePlanBillingBase = originalBilling })

	candidates, err := buildCredentialPool(t.Context(), store, "auth-1", "GLM-5.2", normalizeConfig(Config{}), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 2 {
		t.Fatalf("candidates = %+v, want both records", poolOrder(candidates))
	}
	var others []poolCandidate
	for _, candidate := range candidates {
		if candidate.AuthIndex != "auth-1" {
			others = append(others, candidate)
		}
	}
	profiles := pooledProfiles(others, normalizeConfig(defaultConfig()), "GLM-5.2", nil, time.Now())
	if len(profiles) != 1 || profiles[0].Record != "auth-2" {
		t.Fatalf("pooled profiles = %+v, want one profile on auth-2", len(profiles))
	}

	scope := executionScope{
		AuthIndex:  "auth-1",
		IdentityID: "zcode-pool-primary",
		Document:   primary,
		Recorder:   credentialStates.forStore(store),
		Now:        time.Now,
	}
	scope.batch = newStateBatch(scope.Recorder, scope.credentialRef())
	failure := &upstreamFailure{Class: failureExhausted, Code: "upstream_quota_exhausted", RetryableBeforeOutput: true, Message: "quota exhausted"}
	result := scope.recheckModelAllowance(t.Context(), profiles[0], failure)
	if result.Code != modelAllowanceExhaustedCode {
		t.Fatalf("recheck code = %q, want the confirmed model exhaustion", result.Code)
	}
	scope.batch.flush(t.Context())

	hostSnap := readStoredModelQuota(t, store.docs["auth-1"])
	if len(hostSnap.ModelQuota) != 1 {
		t.Fatalf("the host-selected record's conclusions changed: %+v", hostSnap.ModelQuota)
	}
	pooledSnap := readStoredModelQuota(t, store.docs["auth-2"])
	if len(pooledSnap.ModelQuota) != 1 || pooledSnap.ModelQuota["GLM-5.2"] == "" {
		t.Fatalf("the pooled record's own exhaustion was not recorded: %+v", pooledSnap)
	}
	if pooledSnap.IdentityID != "zcode-pool-other" {
		t.Fatalf("the pooled record's identity changed: %q", pooledSnap.IdentityID)
	}
}
