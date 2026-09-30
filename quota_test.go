package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// quotaFixture points the billing base at an httptest server and the auth
// store at a fake, recording every billing request.
type quotaFixture struct {
	t     *testing.T
	srv   *httptest.Server
	store *fakeAuthStore

	mu            sync.Mutex
	currentAuth   []string
	balanceAuth   []string
	currentStatus int
	balanceStatus int
	currentBody   string
	balanceBody   string
}

func newQuotaFixture(t *testing.T) *quotaFixture {
	t.Helper()
	fixture := &quotaFixture{t: t, store: &fakeAuthStore{docs: map[string]json.RawMessage{}}}
	mux := http.NewServeMux()
	mux.HandleFunc(billingCurrentPath, fixture.serveCurrent)
	mux.HandleFunc(billingBalancePath, fixture.serveBalance)
	fixture.srv = httptest.NewServer(mux)
	t.Cleanup(fixture.srv.Close)

	originalBase := zcodePlanBillingBase
	originalStore := authStoreProvider
	originalCache := activeQuotaCache
	zcodePlanBillingBase = fixture.srv.URL
	authStoreProvider = func() AuthStore { return fixture.store }
	activeQuotaCache = newQuotaCache()
	t.Cleanup(func() {
		zcodePlanBillingBase = originalBase
		authStoreProvider = originalStore
		activeQuotaCache = originalCache
	})
	return fixture
}

func (f *quotaFixture) recordAuth(isCurrent bool, auth string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if isCurrent {
		f.currentAuth = append(f.currentAuth, auth)
		return
	}
	f.balanceAuth = append(f.balanceAuth, auth)
}

func (f *quotaFixture) serveCurrent(w http.ResponseWriter, r *http.Request) {
	f.recordAuth(true, r.Header.Get("Authorization"))
	f.mu.Lock()
	status, body := f.currentStatus, f.currentBody
	f.mu.Unlock()
	writeBilling(w, status, body)
}

func (f *quotaFixture) serveBalance(w http.ResponseWriter, r *http.Request) {
	f.recordAuth(false, r.Header.Get("Authorization"))
	f.mu.Lock()
	status, body := f.balanceStatus, f.balanceBody
	f.mu.Unlock()
	writeBilling(w, status, body)
}

func writeBilling(w http.ResponseWriter, status int, body string) {
	if status == 0 {
		status = http.StatusOK
	}
	if body == "" {
		body = `{"data":{}}`
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func balanceBody(rows ...string) string {
	return `{"data":{"balances":[` + strings.Join(rows, ",") + `]}}`
}

func balanceRow(name string, total, used, remaining any) string {
	row := map[string]any{
		"show_name":       name,
		"total_units":     total,
		"used_units":      used,
		"remaining_units": remaining,
	}
	raw, err := json.Marshal(row)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

// addFakeAccount registers one plugin account with the fake store so the
// credential recorder can resolve and save it by name.
func addFakeAccount(t *testing.T, store *fakeAuthStore, authIndex, identityID, doc string) {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	store.entries = append(store.entries, pluginapi.HostAuthFileEntry{
		AuthIndex: authIndex,
		Name:      authIndex,
		Provider:  pluginID,
		ID:        identityID,
	})
	store.docs[authIndex] = json.RawMessage(doc)
}

// newTestAccountDoc builds an auth document with a zcode namespace holding a
// JWT, an optional managed key, and the given jwt status.
func newTestAccountDoc(t *testing.T, identityID, jwtToken, jwtStatus, keyMaterial string) []byte {
	t.Helper()
	doc, err := patchZcodeNamespace(nil, func(zcode map[string]any) error {
		zcode["schema_version"] = json.Number("1")
		zcode["identity_id"] = identityID
		zcode["jwt"] = map[string]any{
			"token":           jwtToken,
			"status":          jwtStatus,
			"last_checked_at": "2026-01-01T00:00:00Z",
		}
		if keyMaterial != "" {
			zcode["api_key"] = map[string]any{
				"key_material": keyMaterial,
				"status":       "active",
				"managed":      true,
				"name":         "cpa-zcode-abcd1234",
				"key_id":       "key-77",
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("build test account doc: %v", err)
	}
	return doc
}

func TestBalanceVerdictRequiresExplicitEvidence(t *testing.T) {
	ten, zero := 10.0, 0.0
	cases := []struct {
		name     string
		balances []quotaBalance
		verdict  quotaVerdict
		reason   string
	}{
		{
			name:     "positive remaining is available",
			balances: []quotaBalance{{Name: "glm", Remaining: &ten, Total: &ten}},
			verdict:  verdictAvailable,
		},
		{
			name:     "all zero remainings are exhausted",
			balances: []quotaBalance{{Name: "glm", Remaining: &zero, Total: &ten}},
			verdict:  verdictExhausted,
		},
		{
			name:     "mixed zero and positive is available",
			balances: []quotaBalance{{Name: "a", Remaining: &zero}, {Name: "b", Remaining: &ten}},
			verdict:  verdictAvailable,
		},
		{
			name:     "no rows is unknown",
			balances: []quotaBalance{},
			verdict:  verdictUnknown,
			reason:   "no_explicit_balance_evidence",
		},
		{
			name:     "rows without remaining are unknown",
			balances: []quotaBalance{{Name: "glm", Total: &ten}},
			verdict:  verdictUnknown,
			reason:   "no_explicit_balance_evidence",
		},
		{
			name:     "malformed rows without remaining are schema evidence",
			balances: []quotaBalance{{Name: "glm", Malformed: true}},
			verdict:  verdictUnknown,
			reason:   "upstream_schema_incompatible",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verdict, reason := balanceVerdict(tc.balances)
			if verdict != tc.verdict {
				t.Fatalf("verdict = %q, want %q", verdict, tc.verdict)
			}
			if reason != tc.reason {
				t.Fatalf("reason = %q, want %q", reason, tc.reason)
			}
		})
	}
}

func TestParseQuotaBalancesShapeTolerance(t *testing.T) {
	cases := []struct {
		name         string
		body         string
		compatible   bool
		rowCount     int
		malformed    bool
		hasRemaining bool
	}{
		{
			name:         "well-formed rows parse",
			body:         balanceBody(balanceRow("GLM", 100.0, 40.0, 60.0)),
			compatible:   true,
			rowCount:     1,
			hasRemaining: true,
		},
		{
			name:       "missing balances key is incompatible",
			body:       `{"data":{}}`,
			compatible: false,
		},
		{
			name:       "non-array balances is incompatible",
			body:       `{"data":{"balances":{"gone":"wrong"}}}`,
			compatible: false,
		},
		{
			name:       "null balances is incompatible",
			body:       `{"data":{"balances":null}}`,
			compatible: false,
		},
		{
			name:       "non-object row is incompatible",
			body:       balanceBody(`"a-string-row"`),
			compatible: false,
		},
		{
			name:       "string remaining is malformed but compatible",
			body:       balanceBody(`{"show_name":"GLM","total_units":"100","remaining_units":"60"}`),
			compatible: true,
			rowCount:   1,
			malformed:  true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			balances, compatible := parseQuotaBalances([]byte(tc.body))
			if compatible != tc.compatible {
				t.Fatalf("compatible = %v, want %v", compatible, tc.compatible)
			}
			if len(balances) != tc.rowCount {
				t.Fatalf("rows = %d, want %d", len(balances), tc.rowCount)
			}
			if tc.rowCount > 0 {
				if balances[0].Malformed != tc.malformed {
					t.Fatalf("malformed = %v, want %v", balances[0].Malformed, tc.malformed)
				}
				if has := balances[0].Remaining != nil; has != tc.hasRemaining {
					t.Fatalf("remaining present = %v, want %v", has, tc.hasRemaining)
				}
			}
		})
	}
}

func TestParseQuotaPlanToleratesShapeDrift(t *testing.T) {
	cases := []struct {
		name string
		body string
		plan string
	}{
		{name: "string plan", body: `{"data":{"plans":["GLM Coding Plan"]}}`, plan: "GLM Coding Plan"},
		{name: "object plan with name", body: `{"data":{"plans":[{"name":"Pro"}]}}`, plan: "Pro"},
		{name: "object plan with unknown fields", body: `{"data":{"plans":[{"price":9}]}}`, plan: ""},
		{name: "empty plans", body: `{"data":{"plans":[]}}`, plan: ""},
		{name: "drifted envelope", body: `{"plans":"gone"}`, plan: ""},
		{name: "unparsable body", body: `not json`, plan: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if plan := parseQuotaPlan([]byte(tc.body)); plan != tc.plan {
				t.Fatalf("plan = %q, want %q", plan, tc.plan)
			}
		})
	}
}

func TestFetchQuotaEvidenceClassifiesOutcomes(t *testing.T) {
	jwt := makeJWT(t, map[string]any{"sub": "quota-user"})
	cases := []struct {
		name          string
		currentStatus int
		balanceStatus int
		balanceBody   string
		verdict       quotaVerdict
		reason        string
		authCode      string
	}{
		{
			name:        "positive balance is available",
			balanceBody: balanceBody(balanceRow("GLM", 100, 40, 60)),
			verdict:     verdictAvailable,
		},
		{
			name:        "all zero is exhausted",
			balanceBody: balanceBody(balanceRow("GLM", 100, 100, 0)),
			verdict:     verdictExhausted,
		},
		{
			name:        "schema drift is unknown",
			balanceBody: `{"data":{"balances":"gone"}}`,
			verdict:     verdictUnknown,
			reason:      "upstream_schema_incompatible",
		},
		{
			name:          "balance 404 is unknown with status reason",
			balanceStatus: http.StatusNotFound,
			verdict:       verdictUnknown,
			reason:        "upstream_status_404",
		},
		{
			name:          "401 rejects the credential",
			balanceStatus: http.StatusUnauthorized,
			verdict:       verdictUnknown,
			reason:        "quota_credential_invalid",
			authCode:      "quota_credential_invalid",
		},
		{
			name:          "captcha 403 is verification blocked",
			balanceStatus: http.StatusForbidden,
			balanceBody:   `{"error":{"message":"captcha required"}}`,
			verdict:       verdictUnknown,
			reason:        "quota_verification_required",
			authCode:      "quota_verification_required",
		},
		{
			name:          "402 is the payment verdict",
			balanceStatus: http.StatusPaymentRequired,
			verdict:       verdictUnknown,
			reason:        "quota_exhausted",
			authCode:      "quota_exhausted",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newQuotaFixture(t)
			fixture.currentStatus = tc.currentStatus
			fixture.balanceStatus = tc.balanceStatus
			fixture.balanceBody = tc.balanceBody

			evidence := fetchQuotaEvidence(context.Background(), jwt)
			if evidence.Verdict != tc.verdict {
				t.Fatalf("verdict = %q, want %q (%s)", evidence.Verdict, tc.verdict, evidence.Reason)
			}
			if evidence.Reason != tc.reason {
				t.Fatalf("reason = %q, want %q", evidence.Reason, tc.reason)
			}
			if tc.authCode == "" {
				if evidence.AuthFailure != nil {
					t.Fatalf("unexpected auth failure: %+v", evidence.AuthFailure)
				}
			} else if evidence.AuthFailure == nil || evidence.AuthFailure.Code != tc.authCode {
				t.Fatalf("auth failure = %+v, want code %q", evidence.AuthFailure, tc.authCode)
			}
		})
	}
}

func TestFetchQuotaEvidenceSendsBearerAuth(t *testing.T) {
	fixture := newQuotaFixture(t)
	fixture.balanceBody = balanceBody(balanceRow("GLM", 10, 1, 9))
	evidence := fetchQuotaEvidence(context.Background(), "jwt-token-value")
	if evidence.Verdict != verdictAvailable {
		t.Fatalf("verdict = %q, want available", evidence.Verdict)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	for i, auth := range fixture.currentAuth {
		if auth != "Bearer jwt-token-value" {
			t.Fatalf("billing auth %d = %q, want bearer jwt", i, auth)
		}
	}
	for i, auth := range fixture.balanceAuth {
		if auth != "Bearer jwt-token-value" {
			t.Fatalf("balance auth %d = %q, want bearer jwt", i, auth)
		}
	}
}

func TestQuotaStateUpdatesOnlyOnExplicitEvidence(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name     string
		evidence quotaEvidence
		want     []recordedState
	}{
		{
			name:     "unknown verdict concludes nothing",
			evidence: quotaEvidence{Verdict: verdictUnknown, Reason: "upstream_unreachable"},
			want:     nil,
		},
		{
			name:     "exhausted verdict marks exhausted",
			evidence: quotaEvidence{Verdict: verdictExhausted},
			want:     []recordedState{{Kind: CredentialJWT, Status: jwtStatusExhausted, Code: "quota_exhausted"}},
		},
		{
			name:     "available verdict recovers only exhausted",
			evidence: quotaEvidence{Verdict: verdictAvailable},
			want: []recordedState{{
				Kind:         CredentialJWT,
				Status:       jwtStatusActive,
				Code:         "quota_recovered",
				OnlyIfStatus: jwtStatusExhausted,
			}},
		},
		{
			name: "auth failure maps through the state machine",
			evidence: quotaEvidence{
				Verdict:     verdictUnknown,
				AuthFailure: &upstreamFailure{Class: failureVerificationBlocked, Code: "quota_verification_required"},
			},
			want: []recordedState{{
				Kind:       CredentialJWT,
				Status:     jwtStatusVerificationBlocked,
				RetryAfter: now.Add(verificationRetryWindow),
				Code:       "quota_verification_required",
			}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			updates := quotaStateUpdates(tc.evidence, now)
			if len(updates) != len(tc.want) {
				t.Fatalf("updates = %+v, want %+v", updates, tc.want)
			}
			for i, want := range tc.want {
				got := updates[i]
				if got.Kind != want.Kind || got.Status != want.Status || got.Code != want.Code || got.OnlyIfStatus != want.OnlyIfStatus {
					t.Fatalf("update %d = %+v, want %+v", i, got, want)
				}
				if !want.RetryAfter.IsZero() && !got.RetryAfter.After(now) {
					t.Fatalf("update %d retry_after = %v, want after %v", i, got.RetryAfter, now)
				}
			}
		})
	}
}

func TestQuotaFetchRPCEndToEnd(t *testing.T) {
	fixture := newQuotaFixture(t)
	jwt := makeJWT(t, map[string]any{"sub": "quota-e2e"})
	doc := newTestAccountDoc(t, "zcode-quota-e2e", jwt, "exhausted", "key-material-1")
	addFakeAccount(t, fixture.store, "auth-q1", "zcode-quota-e2e", string(doc))
	fixture.balanceBody = balanceBody(balanceRow("GLM", 100, 30, 70))
	fixture.currentBody = `{"data":{"plans":["GLM Coding Plan"]}}`

	request, err := json.Marshal(pluginapi.QuotaFetchRequest{
		AuthIndex: "auth-q1",
		Provider:  pluginID,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := handleQuotaFetch(request)
	if err != nil {
		t.Fatalf("quota.fetch failed: %v", err)
	}
	var env pluginabi.Envelope
	if err := json.Unmarshal(raw, &env); err != nil || !env.OK {
		t.Fatalf("quota.fetch envelope = %+v err %v", env, err)
	}
	var response pluginapi.QuotaFetchResponse
	if err := json.Unmarshal(env.Result, &response); err != nil {
		t.Fatalf("decode quota response: %v", err)
	}
	if response.Subscription == nil || response.Subscription.Plan != "GLM Coding Plan" {
		t.Fatalf("subscription = %+v, want GLM Coding Plan", response.Subscription)
	}
	if len(response.Summary) == 0 {
		t.Fatal("quota response carried no summary metrics")
	}

	// The explicit positive balance recovers the exhausted JWT.
	fixture.store.mu.Lock()
	saved := len(fixture.store.saves)
	fixture.store.mu.Unlock()
	if saved == 0 {
		t.Fatal("quota.fetch recorded no state write")
	}
	var root struct {
		Zcode struct {
			JWT struct {
				Status string `json:"status"`
			} `json:"jwt"`
		} `json:"zcode"`
	}
	if err := json.Unmarshal(fixture.store.saves[saved-1].request, &root); err != nil {
		t.Fatalf("decode saved doc: %v", err)
	}
	if root.Zcode.JWT.Status != jwtStatusActive {
		t.Fatalf("saved jwt status = %q, want active", root.Zcode.JWT.Status)
	}

	// The observation is cached for the management plane under the identity.
	if observation, ok := activeQuotaCache.get("zcode-quota-e2e"); !ok || observation.State != "ok" {
		t.Fatalf("quota cache = %+v ok %v, want ok observation", observation, ok)
	}
}

func TestQuotaFetchUnknownEvidenceLeavesStateUntouched(t *testing.T) {
	fixture := newQuotaFixture(t)
	jwt := makeJWT(t, map[string]any{"sub": "quota-unknown"})
	doc := newTestAccountDoc(t, "zcode-quota-unknown", jwt, "exhausted", "")
	addFakeAccount(t, fixture.store, "auth-q2", "zcode-quota-unknown", string(doc))
	// A schema-drifted balance body is unknown: the exhausted credential must
	// stay exactly as it was.
	fixture.balanceBody = `{"data":{"balances":[{"show_name":"GLM"}]}}`

	request, err := json.Marshal(pluginapi.QuotaFetchRequest{AuthIndex: "auth-q2", Provider: pluginID})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := handleQuotaFetch(request)
	if err != nil {
		t.Fatalf("quota.fetch failed: %v", err)
	}
	var env pluginabi.Envelope
	if err := json.Unmarshal(raw, &env); err != nil || !env.OK {
		t.Fatalf("quota.fetch envelope = %+v err %v", env, err)
	}
	var response pluginapi.QuotaFetchResponse
	if err := json.Unmarshal(env.Result, &response); err != nil {
		t.Fatalf("decode quota response: %v", err)
	}
	if response.Subscription != nil || len(response.Summary) > 0 || len(response.Groups) > 0 {
		t.Fatalf("unknown evidence rendered as data: %+v", response)
	}
	fixture.store.mu.Lock()
	defer fixture.store.mu.Unlock()
	if len(fixture.store.saves) != 0 {
		t.Fatalf("unknown evidence wrote state %d times", len(fixture.store.saves))
	}
}

func TestQuotaFetchGuardsForeignAndCredentiallessRecords(t *testing.T) {
	fixture := newQuotaFixture(t)
	// A foreign record without a zcode namespace.
	fixture.store.docs["foreign"] = json.RawMessage(`{"other":"record"}`)
	fixture.store.entries = append(fixture.store.entries, pluginapi.HostAuthFileEntry{AuthIndex: "foreign", Name: "foreign"})
	// A plugin record without a JWT.
	doc := newTestAccountDoc(t, "zcode-keyless", "", "active", "key-material-only")
	addFakeAccount(t, fixture.store, "auth-keyless", "zcode-keyless", string(doc))

	for _, authIndex := range []string{"foreign", "auth-keyless", "missing"} {
		request, err := json.Marshal(pluginapi.QuotaFetchRequest{AuthIndex: authIndex, Provider: pluginID})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := handleQuotaFetch(request)
		if err != nil {
			t.Fatalf("quota.fetch(%s) failed: %v", authIndex, err)
		}
		var env pluginabi.Envelope
		if err := json.Unmarshal(raw, &env); err != nil || !env.OK {
			t.Fatalf("quota.fetch(%s) = %+v err %v, want empty ok response", authIndex, env, err)
		}
		var response pluginapi.QuotaFetchResponse
		if err := json.Unmarshal(env.Result, &response); err != nil {
			t.Fatalf("decode quota response: %v", err)
		}
		if response.Subscription != nil || len(response.Summary) > 0 {
			t.Fatalf("quota.fetch(%s) rendered data for an uncheckable record", authIndex)
		}
	}
}

func TestQuotaRPCMetadata(t *testing.T) {
	env := callMethod(t, pluginabi.MethodQuotaIdentifier, nil)
	if !env.OK {
		t.Fatalf("quota.identifier failed: %+v", env.Error)
	}
	var identifier struct {
		Identifier string `json:"identifier"`
	}
	if err := json.Unmarshal(env.Result, &identifier); err != nil {
		t.Fatalf("decode identifier: %v", err)
	}
	if identifier.Identifier != pluginID {
		t.Fatalf("identifier = %q, want %q", identifier.Identifier, pluginID)
	}

	env = callMethod(t, pluginabi.MethodQuotaDescribe, []byte(`{}`))
	if !env.OK {
		t.Fatalf("quota.describe failed: %+v", env.Error)
	}
	var describe pluginapi.QuotaDescribeResponse
	if err := json.Unmarshal(env.Result, &describe); err != nil {
		t.Fatalf("decode describe: %v", err)
	}
	if len(describe.SupportedProviders) != 1 || describe.SupportedProviders[0] != pluginID {
		t.Fatalf("supported providers = %v, want [%s]", describe.SupportedProviders, pluginID)
	}
	if describe.SupportsReset {
		t.Fatal("reset must be declared unsupported: the upstream has no reset endpoint")
	}

	env = callMethod(t, pluginabi.MethodQuotaReset, []byte(`{"provider":"zcode"}`))
	if !env.OK {
		t.Fatalf("quota.reset failed: %+v", env.Error)
	}
	var reset pluginapi.QuotaResetResponse
	if err := json.Unmarshal(env.Result, &reset); err != nil {
		t.Fatalf("decode reset: %v", err)
	}
	if reset.Success {
		t.Fatal("reset must not claim success")
	}

	env = callMethod(t, pluginabi.MethodQuotaFetch, []byte(`{"provider":"other"}`))
	if env.OK || env.Error == nil || env.Error.Code != "unknown_provider" {
		t.Fatalf("quota.fetch foreign provider = %+v, want unknown_provider", env.Error)
	}
}

func TestQuotaRecoveryGuardOnlyFlipsExhausted(t *testing.T) {
	// The quota recovery is guarded on the persisted status: it must flip an
	// exhausted credential to active, but leave an invalid one invalid — an
	// invalid credential recovers through a credential refresh or a re-login,
	// not through a balance reading.
	jwt := makeJWT(t, map[string]any{"sub": "quota-guard"})
	doc := newTestAccountDoc(t, "zcode-quota-guard", jwt, "invalid", "")
	store := &fakeAuthStore{docs: map[string]json.RawMessage{}}
	addFakeAccount(t, store, "auth-guard", "zcode-quota-guard", string(doc))

	recorder := newCredentialStateRecorderOver(store)
	recovery := recordedState{
		Kind:         CredentialJWT,
		Status:       jwtStatusActive,
		Code:         "quota_recovered",
		OnlyIfStatus: jwtStatusExhausted,
	}
	if err := recorder.record(context.Background(), credentialRef{
		AuthIndex:  "auth-guard",
		IdentityID: "zcode-quota-guard",
	}, recovery); err != nil {
		t.Fatalf("record recovery: %v", err)
	}
	saved, err := store.Get(context.Background(), "auth-guard")
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		Zcode struct {
			JWT struct {
				Status string `json:"status"`
			} `json:"jwt"`
		} `json:"zcode"`
	}
	if err := json.Unmarshal(saved, &root); err != nil {
		t.Fatal(err)
	}
	if root.Zcode.JWT.Status != jwtStatusInvalid {
		t.Fatalf("jwt status = %q, want invalid to survive the guarded recovery", root.Zcode.JWT.Status)
	}

	// The same recovery does land on a record that still reads exhausted.
	exhausted := newTestAccountDoc(t, "zcode-quota-guard", jwt, "exhausted", "")
	addFakeAccount(t, store, "auth-guard", "zcode-quota-guard", string(exhausted))
	if err := recorder.record(context.Background(), credentialRef{
		AuthIndex:  "auth-guard",
		IdentityID: "zcode-quota-guard",
	}, recovery); err != nil {
		t.Fatalf("record recovery on exhausted: %v", err)
	}
	saved, err = store.Get(context.Background(), "auth-guard")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(saved, &root); err != nil {
		t.Fatal(err)
	}
	if root.Zcode.JWT.Status != jwtStatusActive {
		t.Fatalf("jwt status = %q, want active after recovery", root.Zcode.JWT.Status)
	}
}
