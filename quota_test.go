package main

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// testDeviceID is the device identity balance calls are made with when the
// test is about something else. The upstream gates the balance endpoint on a
// well-formed id, so a refresh made without one is rejected as a parameter
// error before any credential conclusion is drawn.
const testDeviceID = "11111111-2222-4333-8444-555555555555"

// quotaFixture points the billing base at an httptest server and the auth
type quotaFixture struct {
	t     *testing.T
	srv   *httptest.Server
	store *fakeAuthStore

	mu            sync.Mutex
	balanceAuth   []string
	balanceDevice []string
	balanceQuery  []string
	balanceStatus int
	balanceBody   string
}

func newQuotaFixture(t *testing.T) *quotaFixture {
	t.Helper()
	fixture := &quotaFixture{t: t, store: &fakeAuthStore{docs: map[string]json.RawMessage{}}}
	mux := http.NewServeMux()
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

// lastAppVersion returns the app_version query the most recent balance call
// carried, which is the only authoritative record of what the plugin declared.
func (f *quotaFixture) lastAppVersion() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.balanceQuery) == 0 {
		return ""
	}
	return f.balanceQuery[len(f.balanceQuery)-1]
}

// lastDeviceID returns the X-Device-Mid the most recent balance call carried.
func (f *quotaFixture) lastDeviceID() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.balanceDevice) == 0 {
		return ""
	}
	return f.balanceDevice[len(f.balanceDevice)-1]
}

func (f *quotaFixture) serveBalance(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.balanceAuth = append(f.balanceAuth, r.Header.Get("Authorization"))
	f.balanceDevice = append(f.balanceDevice, r.Header.Get(deviceMidHeader))
	f.balanceQuery = append(f.balanceQuery, r.URL.Query().Get("app_version"))
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

// balanceBody renders the balance endpoint's envelope. The plans list is part
// of it because the same response is the authority for entitlement: a body
// without plans means an account with no Coding Plan.
func balanceBody(rows ...string) string {
	// The upstream states a status on every plan row; a live plan reads
	// "active", which is the only status that means the plan is in force.
	return planBalanceBody(`[{"name":"GLM Coding Plan","status":"active"}]`, rows...)
}

func planBalanceBody(plans string, rows ...string) string {
	return `{"code":0,"success":true,"data":{"plans":` + plans +
		`,"balances":[` + strings.Join(rows, ",") + `]}}`
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

// float64Ptr is the explicit-number shorthand the quota tests compare against.
// A bucket field the upstream omitted must stay nil, so assertions need to say
// "unknown" rather than let a zero stand for it.
func float64Ptr(value float64) *float64 {
	return &value
}

// floatPtrEqual compares two optional numbers by value, treating two unknowns
// as equal — the distinction these tests assert on is read-vs-unread. It is
// shared across the package because asserting "the plugin read exactly this
// number" otherwise gets hand-rolled per test, and a hand-rolled comparison is
// where a silent tolerance typo hides.
func floatPtrEqual(got, want *float64) bool {
	if got == nil || want == nil {
		return got == want
	}
	return math.Abs(*got-*want) < 1e-9
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

// addLabelledAccount registers one plugin account carrying a human label, so a
// test can prove a value that appears in the authenticated state is absent from
// the unauthenticated shell.
func addLabelledAccount(t *testing.T, store *fakeAuthStore, authIndex, label, doc string) string {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	store.entries = append(store.entries, pluginapi.HostAuthFileEntry{
		AuthIndex: authIndex,
		Name:      authIndex + ".json",
		Label:     label,
		Provider:  pluginID,
		ID:        "identity-" + authIndex,
	})
	store.docs[authIndex] = json.RawMessage(doc)
	return authIndex
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
	live := []quotaPlan{{Name: "Pro", Status: planStatusActive}}
	cases := []struct {
		name     string
		balances []quotaBalance
		plans    []quotaPlan
		verdict  quotaVerdict
		reason   string
	}{
		{
			name:     "positive remaining is available",
			balances: []quotaBalance{{Name: "glm", Remaining: &ten, Total: &ten}},
			plans:    live,
			verdict:  verdictAvailable,
		},
		{
			name:     "all zero remainings are exhausted",
			balances: []quotaBalance{{Name: "glm", Remaining: &zero, Total: &ten}},
			plans:    live,
			verdict:  verdictExhausted,
		},
		{
			name:     "mixed zero and positive is available",
			balances: []quotaBalance{{Name: "a", Remaining: &zero}, {Name: "b", Remaining: &ten}},
			plans:    live,
			verdict:  verdictAvailable,
		},
		{
			name:     "no rows is unknown",
			balances: []quotaBalance{},
			plans:    live,
			verdict:  verdictUnknown,
			reason:   "no_explicit_balance_evidence",
		},
		{
			name:     "rows without remaining are unknown",
			balances: []quotaBalance{{Name: "glm", Total: &ten}},
			plans:    live,
			verdict:  verdictUnknown,
			reason:   "no_explicit_balance_evidence",
		},
		{
			name:     "malformed rows without remaining are schema evidence",
			balances: []quotaBalance{{Name: "glm", Malformed: true}},
			plans:    live,
			verdict:  verdictUnknown,
			reason:   "upstream_schema_incompatible",
		},
		{
			// The three-state reading the issue asks for: an account with no
			// plan is a positive answer, distinct from not knowing.
			name:     "no plan and no rows is no_plan",
			balances: []quotaBalance{},
			verdict:  verdictNoPlan,
			reason:   "no_plan",
		},
		{
			name:     "a terminated plan is expired",
			balances: []quotaBalance{{Name: "glm", Remaining: &ten}},
			plans:    []quotaPlan{{Name: "Pro", Status: planStatusExpired}},
			verdict:  verdictExpired,
			reason:   "plan_expired",
		},
		{
			name:     "balance rows without a plan row still read",
			balances: []quotaBalance{{Name: "glm", Remaining: &ten}},
			verdict:  verdictAvailable,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verdict, reason := balanceVerdict(tc.balances, tc.plans)
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

func TestParseQuotaPlansToleratesShapeDrift(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		plan       string
		planCount  int
		compatible bool
	}{
		{name: "object plan with name", body: `{"data":{"plans":[{"name":"Pro"}]}}`,
			plan: "Pro", planCount: 1, compatible: true},
		{name: "plan with a terminal status", body: `{"data":{"plans":[{"name":"Pro","status":"expired"}]}}`,
			plan: "Pro", planCount: 1, compatible: true},
		{name: "active plan", body: `{"data":{"plans":[{"name":"Pro","status":"active"}]}}`,
			plan: "Pro", planCount: 1, compatible: true},
		{name: "object plan with unknown fields", body: `{"data":{"plans":[{"price":9}]}}`,
			planCount: 1, compatible: true},
		{name: "empty plans", body: `{"data":{"plans":[]}}`, compatible: true},
		{name: "absent plans is a compatible no-plan answer", body: `{"data":{}}`, compatible: true},
		// The plan list is entitlement evidence, so a shape change must be
		// reported rather than silently read as "no plan": reading it as
		// no-plan would tell the operator their working plan does not exist.
		{name: "string plan is drift", body: `{"data":{"plans":["GLM Coding Plan"]}}`, compatible: false},
		{name: "drifted plans type", body: `{"data":{"plans":"gone"}}`, compatible: false},
		// Plans outside data are not this endpoint's field: the envelope is
		// readable, it simply carries no plan evidence.
		{name: "plans outside data read as no plan", body: `{"plans":"gone"}`, compatible: true},
		{name: "unparsable body", body: `not json`, compatible: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plans, compatible := parseQuotaPlans([]byte(tc.body), time.Now())
			if compatible != tc.compatible {
				t.Fatalf("compatible = %v, want %v", compatible, tc.compatible)
			}
			if !compatible {
				return
			}
			if len(plans) != tc.planCount {
				t.Fatalf("plans = %d, want %d", len(plans), tc.planCount)
			}
			if plan := planNameFor(plans); plan != tc.plan {
				t.Fatalf("plan = %q, want %q", plan, tc.plan)
			}
		})
	}
}

func TestFetchQuotaEvidenceClassifiesOutcomes(t *testing.T) {
	jwt := makeJWT(t, map[string]any{"sub": "quota-user"})
	cases := []struct {
		name          string
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
			fixture.balanceStatus = tc.balanceStatus
			fixture.balanceBody = tc.balanceBody

			evidence := fetchQuotaEvidence(context.Background(), jwt, defaultConfig().Product.AppVersion, testDeviceID, time.Now())
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

// TestFetchQuotaEvidenceSendsBareJWT pins the one authentication detail the
// balance endpoint does not share with the Messages endpoint: it takes the
// Coding Plan JWT without a Bearer prefix, and a prefixed credential is answered
// as though none were presented.
func TestFetchQuotaEvidenceSendsBareJWT(t *testing.T) {
	fixture := newQuotaFixture(t)
	fixture.balanceBody = balanceBody(balanceRow("GLM", 10, 1, 9))
	evidence := fetchQuotaEvidence(context.Background(), "jwt-token-value", defaultConfig().Product.AppVersion, testDeviceID, time.Now())
	if evidence.Verdict != verdictAvailable {
		t.Fatalf("verdict = %q, want available", evidence.Verdict)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if len(fixture.balanceAuth) != 1 {
		t.Fatalf("balance calls = %d, want exactly one", len(fixture.balanceAuth))
	}
	if got := fixture.balanceAuth[0]; got != "jwt-token-value" {
		t.Fatalf("balance auth = %q, want the bare jwt", got)
	}
}

// TestFetchQuotaEvidenceDeclaresTheConfiguredAppVersion pins that the balance
// query carries the configured product version: the upstream decides Start Plan
// capability by it, so a plugin-configured value must actually reach the wire.
func TestFetchQuotaEvidenceDeclaresTheConfiguredAppVersion(t *testing.T) {
	fixture := newQuotaFixture(t)
	fixture.balanceBody = balanceBody(balanceRow("GLM", 10, 1, 9))
	fetchQuotaEvidence(context.Background(), "jwt-token-value", "9.9.9", testDeviceID, time.Now())
	if got := fixture.lastAppVersion(); got != "9.9.9" {
		t.Fatalf("app_version = %q, want the configured 9.9.9", got)
	}
}

// TestFetchQuotaEvidenceDeclaresTheDeviceIdentity pins that the balance call
// carries a device identity. The upstream rejects a request without one as
// 3001 "parameter error" — indistinguishable from a malformed query — which is
// why this was the whole reason the refresh never produced any evidence.
func TestFetchQuotaEvidenceDeclaresTheDeviceIdentity(t *testing.T) {
	fixture := newQuotaFixture(t)
	fixture.balanceBody = balanceBody(balanceRow("GLM", 10, 1, 9))
	fetchQuotaEvidence(context.Background(), "jwt-token-value", "3.14.4", testDeviceID, time.Now())
	if got := fixture.lastDeviceID(); got != testDeviceID {
		t.Fatalf("%s = %q, want %q", deviceMidHeader, got, testDeviceID)
	}
}

// TestDeviceIdentityIsGeneratedOnceAndReused covers the continuity the header
// exists for: a credential that reported a new id on every refresh would look
// like a fresh install on each poll instead of one continuing installation.
func TestDeviceIdentityIsGeneratedOnceAndReused(t *testing.T) {
	resetDeviceIDCache(t)

	first := deviceIdentity("auth-1", nil)
	if !isUUID(first) {
		t.Fatalf("generated id = %q, want a well-formed UUID", first)
	}
	if second := deviceIdentity("auth-1", nil); second != first {
		t.Fatalf("second call = %q, want the same id %q", second, first)
	}
	if other := deviceIdentity("auth-2", nil); other == first {
		t.Fatal("a different credential shared the first credential's device id")
	}
}

// TestDeviceIdentityPrefersTheRecordedValue keeps a restart from changing the
// reported device: an id already in the auth document is authoritative.
func TestDeviceIdentityPrefersTheRecordedValue(t *testing.T) {
	resetDeviceIDCache(t)
	recorded := `{"zcode":{"device_mid":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"}}`
	if got := deviceIdentity("auth-1", []byte(recorded)); got != "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" {
		t.Fatalf("device id = %q, want the recorded value", got)
	}
}

// TestRecordDeviceIDPersistsForReuse checks a recorded id reaches the
// credential document, which is what makes it survive a restart.
func TestRecordDeviceIDPersistsForReuse(t *testing.T) {
	resetDeviceIDCache(t)
	store := &fakeAuthStore{docs: map[string]json.RawMessage{
		"auth-1": json.RawMessage(`{"type":"zcode","zcode":{"identity_id":"id-1"}}`),
	}}
	generated := deviceIdentity("auth-1", nil)
	if err := recordDeviceID("auth-1", generated, store); err != nil {
		t.Fatalf("record: %v", err)
	}

	saved, err := store.Get(context.Background(), "auth-1")
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got := recordedDeviceID(saved); got != generated {
		t.Fatalf("persisted device id = %q, want %q", got, generated)
	}
	// A fresh process reading the stored document must reach the same id.
	resetDeviceIDCache(t)
	if got := deviceIdentity("auth-1", saved); got != generated {
		t.Fatalf("after restart device id = %q, want %q", got, generated)
	}
}

// TestDeviceIdentityDoesNotWriteOnTheReadPath keeps a refresh read-only. A
// quota observation must leave the credential byte-for-byte as it found it, so
// resolving an identity may not save the document: a second write would be
// indistinguishable from a credential-state change to everything that watches
// the store, including the guarantee that unknown evidence writes nothing.
func TestDeviceIdentityDoesNotWriteOnTheReadPath(t *testing.T) {
	resetDeviceIDCache(t)
	store := &fakeAuthStore{docs: map[string]json.RawMessage{
		"auth-1": json.RawMessage(`{"type":"zcode","zcode":{"identity_id":"id-1"}}`),
	}}
	deviceIdentity("auth-1", nil)

	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.saves) != 0 {
		t.Fatalf("read path wrote the credential %d times", len(store.saves))
	}
}

// TestDeviceIdentityIsStampedOnFirstLogin covers where the id is meant to be
// persisted: a login builds the credential document, so the identity is
// established there rather than on the first quota read.
func TestDeviceIdentityIsStampedOnFirstLogin(t *testing.T) {
	resetDeviceIDCache(t)
	token := makeJWT(t, map[string]any{"sub": "device-login"})
	now := time.Unix(0, 0).UTC()

	doc, err := buildZcodeStorage(nil, "zcode-device-user", token, "", now)
	if err != nil {
		t.Fatalf("build storage: %v", err)
	}
	first := recordedDeviceID(doc)
	if !isUUID(first) {
		t.Fatalf("login stored device id = %q, want a well-formed UUID", first)
	}

	// Re-login is the same installation and must not look like a new device.
	doc, err = buildZcodeStorage(doc, "zcode-device-user", token, "", now)
	if err != nil {
		t.Fatalf("re-login: %v", err)
	}
	if got := recordedDeviceID(doc); got != first {
		t.Fatalf("re-login device id = %q, want the original %q", got, first)
	}
}

func resetDeviceIDCache(t *testing.T) {
	t.Helper()
	deviceIDMu.Lock()
	previous := deviceIDCache
	deviceIDCache = map[string]string{}
	deviceIDMu.Unlock()
	t.Cleanup(func() {
		deviceIDMu.Lock()
		deviceIDCache = previous
		deviceIDMu.Unlock()
	})
}

// isUUID reports whether the value has the shape the upstream accepts. The
// endpoint rejects anything else with the same 3001 a missing id produces.
func isUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, r := range value {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !strings.ContainsRune("0123456789abcdef", r) {
				return false
			}
		}
	}
	return true
}

// TestFetchQuotaEvidenceReadsTheRealBalancePayload parses a response captured
// verbatim from the upstream for a Start Plan account: one active plan whose
// two entitlements each carry a daily token bucket. It is the shape the
// management page renders, so a field the code failed to read would show up as
// an empty or unknown quota rather than as a parse error.
func TestFetchQuotaEvidenceReadsTheRealBalancePayload(t *testing.T) {
	fixture := newQuotaFixture(t)
	fixture.balanceBody = realBalancePayload
	evidence := fetchQuotaEvidence(context.Background(), "jwt-token-value", "3.14.4", testDeviceID, time.Now())

	if !evidence.SchemaCompatible {
		t.Fatalf("schema incompatible, reason %q", evidence.Reason)
	}
	if evidence.Verdict != verdictAvailable {
		t.Fatalf("verdict = %q, want available (%s)", evidence.Verdict, evidence.Reason)
	}
	if len(evidence.Plans) != 1 {
		t.Fatalf("plans = %d, want 1", len(evidence.Plans))
	}
	if got := evidence.Plans[0].Name; got != "ZCode Start Plan" {
		t.Fatalf("plan name = %q", got)
	}
	if got := evidence.Plans[0].Status; got != planStatusActive {
		t.Fatalf("plan status = %q, want active", got)
	}
	if len(evidence.Balances) != 2 {
		t.Fatalf("balances = %d, want 2 buckets", len(evidence.Balances))
	}

	byName := map[string]quotaBalance{}
	for _, balance := range evidence.Balances {
		if balance.Malformed {
			t.Fatalf("bucket %q read as malformed", balance.Name)
		}
		byName[balance.Name] = balance
	}
	glm, ok := byName["GLM-5.3"]
	if !ok {
		t.Fatalf("buckets = %v, want a GLM-5.3 bucket", byName)
	}
	if glm.Total == nil || *glm.Total != 3000000 {
		t.Fatalf("GLM-5.3 total = %v, want 3000000", glm.Total)
	}
	if glm.Remaining == nil || *glm.Remaining != 3000000 {
		t.Fatalf("GLM-5.3 remaining = %v, want 3000000", glm.Remaining)
	}
	// The capabilities array is the only place the upstream declares which
	// models the plan covers, and it is read as the authoritative model source.
	if len(glm.Capabilities) != 1 || glm.Capabilities[0] != "model:glm-5.3" {
		t.Fatalf("GLM-5.3 capabilities = %v, want [model:glm-5.3]", glm.Capabilities)
	}
	// The reset instant arrives as epoch seconds, a JSON number. Read as a
	// string it would drop out, leaving every bucket with no reset time.
	if glm.ExpiresAt == "" {
		t.Fatal("GLM-5.3 reset time is empty; the upstream states it as epoch seconds")
	}
	reset, err := time.Parse(time.RFC3339, glm.ExpiresAt)
	if err != nil {
		t.Fatalf("reset time %q is not RFC3339: %v", glm.ExpiresAt, err)
	}
	if want := time.Unix(1790870399, 0).UTC(); !reset.Equal(want) {
		t.Fatalf("reset time = %v, want %v", reset, want)
	}
	if _, ok := byName["GLM-5.3-Flash"]; !ok {
		t.Fatal("missing the GLM-5.3-Flash bucket")
	}
}

// TestQuotaExpiryTextAcceptsBothShapes keeps the reset time readable whether the
// upstream states it as a number or a quoted string.
func TestQuotaExpiryTextAcceptsBothShapes(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"epoch number", `1790870399`, "2026-10-01T15:59:59Z"},
		{"quoted number", `"1790870399"`, "1790870399"},
		{"already text", `"2026-10-02T15:59:59Z"`, "2026-10-02T15:59:59Z"},
		{"absent", ``, ""},
		{"wrong type", `true`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := quotaExpiryText(json.RawMessage(tc.raw)); got != tc.want {
				t.Fatalf("quotaExpiryText(%s) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

// realBalancePayload is a billing/balance success response captured verbatim
// from the upstream for a Start Plan account, with logid and identity fields
// left in place so the parser reads exactly what it will read in production.
const realBalancePayload = `{"code":0,"msg":"","data":{"server_time":1790833679,"plans":[{"user_plan_id":"upl_2105534823644946432","plan_id":"zcode-v3-start-plan-0817","name":"ZCode Start Plan","description":"免费 GLM 旗舰模型体验","priority":90,"status":"active","starts_at":1790833595,"ends_at":1791215999,"entitlements":[{"entitlement_id":"ent_2_0817_glm_5p3","show_name":"GLM-5.3","meter":"model_usage","unit_type":"token","capabilities":["model:glm-5.3"],"grant_units":3000000,"period":"daily","priority":110,"effective_at":0},{"entitlement_id":"ent_2_0817_glm_5p3f","show_name":"GLM-5.3-Flash","meter":"model_usage","unit_type":"token","capabilities":["model:glm-5.3-flash"],"grant_units":5000000,"period":"daily","priority":80,"effective_at":0}]}],"balances":[{"bucket_id":"bucket_2105534823678500864","user_plan_id":"upl_2105534823644946432","plan_id":"zcode-v3-start-plan-0817","entitlement_id":"ent_2_0817_glm_5p3","show_name":"GLM-5.3","meter":"model_usage","unit_type":"token","capabilities":["model:glm-5.3"],"priority":110,"plan_priority":90,"entitlement_priority":110,"total_units":3000000,"used_units":0,"remaining_units":3000000,"available_units":3000000,"period_start":1790784000,"period_end":1790870399,"expires_at":1790870399},{"bucket_id":"bucket_2105534823682695168","user_plan_id":"upl_2105534823644946432","plan_id":"zcode-v3-start-plan-0817","entitlement_id":"ent_2_0817_glm_5p3f","show_name":"GLM-5.3-Flash","meter":"model_usage","unit_type":"token","capabilities":["model:glm-5.3-flash"],"priority":80,"plan_priority":90,"entitlement_priority":80,"total_units":5000000,"used_units":0,"remaining_units":5000000,"available_units":5000000,"period_start":1790784000,"period_end":1790870399,"expires_at":1790870399}]},"logid":"2026100105475959a32e0d7aaa4280f5ed"}`

// TestFetchQuotaEvidenceRejectsTheRealParameterErrorCarrier pins how the
// upstream actually delivers 3001: on HTTP 400, not inside a 200. A refresh that
// only recognized the 200 carrier would read this as a transport failure and
// lose the reason, which is the whole difficulty of this failure — it looks
// like a parameter complaint, and the parameter it names is not the missing one.
func TestFetchQuotaEvidenceRejectsTheRealParameterErrorCarrier(t *testing.T) {
	fixture := newQuotaFixture(t)
	fixture.balanceStatus = http.StatusBadRequest
	fixture.balanceBody = `{"code":3001,"msg":"parameter error","logid":"2026100105443300cff798cd2094aba1dd"}`
	evidence := fetchQuotaEvidence(context.Background(), "jwt-token-value", "3.14.4", testDeviceID, time.Now())
	if evidence.Verdict != verdictUnknown {
		t.Fatalf("verdict = %q, want unknown", evidence.Verdict)
	}
	if evidence.Reason != "quota_invalid_request" {
		t.Fatalf("reason = %q, want quota_invalid_request", evidence.Reason)
	}
	// The rejection is reported as a reason, but it is a request-level verdict:
	// it must not be classified as anything that moves the credential, or a
	// missing device header would read as a dead credential. failureRejected has
	// no status in the JWT vocabulary, so the update it produces concludes
	// nothing and the recorded state is left alone.
	if evidence.AuthFailure == nil {
		t.Fatal("3001 produced no reported reason")
	}
	if evidence.AuthFailure.Class != failureRejected {
		t.Fatalf("3001 classified as %q, want a request-level rejection", evidence.AuthFailure.Class)
	}
	for _, update := range quotaStateUpdates(evidence, time.Now()) {
		if update.Status != "" {
			t.Fatalf("3001 concluded credential status %q, want it left untouched", update.Status)
		}
	}
}

// TestFetchQuotaEvidenceRejectsBusinessFailureOnHTTP200 covers the upstream's
// habit of carrying failures inside a 200. Reading the status alone would turn
// a "parameter error" into an account with no plan.
func TestFetchQuotaEvidenceRejectsBusinessFailureOnHTTP200(t *testing.T) {
	fixture := newQuotaFixture(t)
	fixture.balanceBody = `{"code":3001,"msg":"parameter error"}`
	evidence := fetchQuotaEvidence(context.Background(), "jwt-token-value", "3.14.3", testDeviceID, time.Now())
	if evidence.Verdict != verdictUnknown {
		t.Fatalf("verdict = %q, want unknown", evidence.Verdict)
	}
	if evidence.Reason != "quota_invalid_request" {
		t.Fatalf("reason = %q", evidence.Reason)
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
			name:     "available verdict recovers exhausted and renewed",
			evidence: quotaEvidence{Verdict: verdictAvailable},
			// Each recovery is guarded on its own persisted state, so a
			// positive balance clears exhaustion and a renewed plan clears an
			// elapsed term without either overwriting an unrelated conclusion.
			want: []recordedState{{
				Kind:         CredentialJWT,
				Status:       jwtStatusActive,
				Code:         "quota_recovered",
				OnlyIfStatus: jwtStatusExhausted,
			}, {
				Kind:         CredentialJWT,
				Status:       jwtStatusActive,
				Code:         "plan_renewed",
				OnlyIfStatus: jwtStatusPlanExpired,
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
	// The one balance response carries both the plan and its quota, which is
	// the whole point of reading entitlement from this endpoint.
	fixture.balanceBody = balanceBody(balanceRow("GLM", 100, 30, 70))

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
	// A balance body the upstream answers with a plan-less account: the exhausted
	// credential's own state must stay exactly as it was.
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
	// The invariant is about the credential's conclusion, not about how many
	// writes the refresh made: a plan-less reading concludes nothing about any
	// allowance, so the recorded exhaustion must survive it untouched.
	snap, err := readCredentialSnapshot(fixture.store.docs["auth-q2"])
	if err != nil {
		t.Fatalf("read account after refresh: %v", err)
	}
	if snap.JWTStatus != "exhausted" || len(snap.ModelQuota) != 0 {
		t.Fatalf("concluding reading moved credential state: status=%q models=%v", snap.JWTStatus, snap.ModelQuota)
	}
}

func TestQuotaFetchUnreadableSnapshotKeepsTheLastGoodOne(t *testing.T) {
	fixture := newQuotaFixture(t)
	jwt := makeJWT(t, map[string]any{"sub": "quota-unreadable"})
	doc := newTestAccountDoc(t, "zcode-quota-unreadable", jwt, "active", "")
	good := renderPlanSnapshot(StartPlanSnapshot{
		CheckedAt: time.Now(),
		Readable:  true,
		Plans:     []quotaPlan{{PlanID: "zcode-v3-start-plan-trust-1003", Status: planStatusActive}},
		Buckets:   []startPlanBucket{{Models: []string{"GLM-5.3-Flash"}, Remaining: float64Ptr(4)}},
	}, normalizeConfig(Config{}))
	doc, err := writePlanSnapshotSection(doc, good)
	if err != nil {
		t.Fatalf("seed snapshot: %v", err)
	}
	addFakeAccount(t, fixture.store, "auth-q3", "zcode-quota-unreadable", string(doc))

	// A schema-drifted body is unreadable evidence. It must neither conclude
	// anything nor replace the last good snapshot with an empty one: that section
	// is what an operator reads to tell a wrong account from an exhausted one.
	fixture.balanceBody = `{"data":{"balances":"not-an-array"}}`
	if _, err := runQuotaRefresh(t.Context(), fixture.store, quotaRefreshScope{
		AuthIndex:  "auth-q3",
		IdentityID: "zcode-quota-unreadable",
		JWT:        jwt,
		AppVersion: defaultAppVersion,
		DeviceID:   testDeviceID,
		Document:   doc,
	}, time.Now()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	after := readPlanSnapshotSection(fixture.store.docs["auth-q3"])
	if !reflect.DeepEqual(after, good) {
		t.Fatalf("unreadable reading replaced the snapshot:\n got %+v\nwant %+v", after, good)
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

// TestParseQuotaBalancesReadsCapabilities covers the dynamic model source the
// official client takes from the same response: each balance row declares the
// models it covers as "model:<id>" capabilities.
func TestParseQuotaBalancesReadsCapabilities(t *testing.T) {
	body := planBalanceBody(`[{"name":"Pro"}]`,
		`{"show_name":"Pro","remaining_units":10,"total_units":100,`+
			`"capabilities":["model:GLM-5.2","model:GLM-5-Turbo","realtime"]}`)
	balances, compatible := parseQuotaBalances([]byte(body))
	if !compatible {
		t.Fatal("a well-formed body must stay compatible")
	}
	if len(balances) != 1 {
		t.Fatalf("rows = %d", len(balances))
	}
	ids := balanceModelIDs(balances[0])
	if strings.Join(ids, ",") != "GLM-5.2,GLM-5-Turbo" {
		t.Fatalf("model ids = %v, want only the model capabilities in order", ids)
	}
}

// oneTimeBalanceRow is the bucket shape captured from a Start Plan account on
// 2026-10-02: a one_time entitlement whose bucket resets at the day's end. The
// numbers and semantics are verbatim, because the two periodic readings —
// this reset at the day's end, and one that also states how often it recurs —
// must not collapse into the same line.
const oneTimeBalanceRow = `{"bucket_id":"bucket_2105787069353938944","plan_id":"zcode-v3-start-plan-trust-1002",` +
	`"entitlement_id":"zcode-v3-start-plan-trust-1002","show_name":"GLM-5.3-Flash","meter":"model_usage",` +
	`"unit_type":"token","capabilities":["model:glm-5.3-flash"],"priority":110,"total_units":100000000,` +
	`"used_units":40465883,"remaining_units":59534117,"available_units":59534117,` +
	`"period_start":1790893735,"period_end":1790956800,"expires_at":1790956800}`

// TestParseQuotaBalancesReadsBucketSemantics covers the entitlement fields the
// balance rows carry: what a bucket meters, in what unit, how often it recurs,
// and what it was granted. Without them a page can print how many units are
// left but cannot say what the unit is or when the bucket comes back.
func TestParseQuotaBalancesReadsBucketSemantics(t *testing.T) {
	body := planBalanceBody(`[{"name":"ZCode Trust Build","status":"active"}]`, oneTimeBalanceRow)
	balances, compatible := parseQuotaBalances([]byte(body))
	if !compatible || len(balances) != 1 {
		t.Fatalf("balances = %d compatible = %v, want one parsed bucket", len(balances), compatible)
	}
	row := balances[0]
	if row.Meter != "model_usage" || row.UnitType != "token" {
		t.Fatalf("bucket = meter %q unit %q, want model_usage/token", row.Meter, row.UnitType)
	}
	if row.Period != "" {
		t.Fatalf("period = %q; the balance row states no period of its own", row.Period)
	}
	if row.GrantUnits != nil || *row.Total != 100000000 {
		t.Fatalf("grant = %v; a row without entitlements carries no granted amount", row.GrantUnits)
	}
	if row.PeriodStart == nil || *row.PeriodStart != 1790893735 {
		t.Fatalf("period start = %v, want 1790893735", row.PeriodStart)
	}
	if row.PeriodEnd == nil || *row.PeriodEnd != 1790956800 {
		t.Fatalf("period end = %v, want 1790956800", row.PeriodEnd)
	}
}

// TestParseQuotaBalancesFoldsEntitlementSemantics covers the same fields read
// from where the upstream actually states a period: the plan's entitlements.
// The bucket inherits them through its entitlement_id, so "how often does this
// come back" is an answer even on a row that omits it.
func TestParseQuotaBalancesFoldsEntitlementSemantics(t *testing.T) {
	plans := `[{"user_plan_id":"upl_1","plan_id":"zcode-v3-start-plan-trust-1002","name":"ZCode Trust Build","status":"active",` +
		`"entitlements":[{"entitlement_id":"zcode-v3-start-plan-trust-1002","show_name":"GLM-5.3-Flash","meter":"model_usage",` +
		`"unit_type":"token","capabilities":["model:glm-5.3-flash"],"grant_units":100000000,"period":"one_time"}]}]`
	body := planBalanceBody(plans, oneTimeBalanceRow)
	parsed, compatible := parseQuotaPlans([]byte(body), time.Now())
	if !compatible || len(parsed) != 1 || len(parsed[0].Entitlements) != 1 {
		t.Fatalf("plans = %+v compatible = %v, want one plan with one grant", parsed, compatible)
	}
	balances, compatible := parseQuotaBalancesWithPlans([]byte(body), parsed)
	if !compatible || len(balances) != 1 {
		t.Fatalf("balances = %d compatible = %v, want one parsed bucket", len(balances), compatible)
	}
	if balances[0].Period != "one_time" {
		t.Fatalf("period = %q, want the entitlement's one_time", balances[0].Period)
	}
	if balances[0].GrantUnits == nil || *balances[0].GrantUnits != 100000000 {
		t.Fatalf("grant = %v, want the entitlement's 100000000", balances[0].GrantUnits)
	}
	// The row's own meter and unit outrank the grant's: the grant states what
	// was given, the bucket states what it may spend now.
	if balances[0].Meter != "model_usage" || balances[0].UnitType != "token" {
		t.Fatalf("bucket = meter %q unit %q", balances[0].Meter, balances[0].UnitType)
	}
}

// TestParseQuotaBalancesKeepsUnknownSemanticsUnknown covers the three readings
// every new field must have: stated, absent, and drifted. Only a drifted
// numeric marks the row malformed, and a drifted textual field is dropped
// rather than guessed at.
func TestParseQuotaBalancesKeepsUnknownSemanticsUnknown(t *testing.T) {
	cases := []struct {
		name        string
		row         string
		meter       string
		period      string
		grant       *float64
		periodStart *float64
		malformed   bool
	}{
		{
			name:        "every field stated",
			row:         `{"show_name":"GLM","meter":"model_usage","unit_type":"token","period":"daily","grant_units":100,"period_start":5}`,
			meter:       "model_usage",
			period:      "daily",
			grant:       float64Ptr(100),
			periodStart: float64Ptr(5),
		},
		{
			name: "every field absent stays unknown",
			row:  `{"show_name":"GLM","remaining_units":1}`,
		},
		{
			name:      "drifted grant is malformed and unread",
			row:       `{"show_name":"GLM","grant_units":"100","meter":"model_usage","period":"daily"}`,
			meter:     "model_usage",
			period:    "daily",
			malformed: true,
		},
		{
			name:      "drifted period start is malformed and unread",
			row:       `{"show_name":"GLM","period_start":"5","meter":"model_usage"}`,
			meter:     "model_usage",
			malformed: true,
		},
		{
			name:        "drifted meter is dropped, not guessed",
			row:         `{"show_name":"GLM","meter":5,"period_start":5}`,
			periodStart: float64Ptr(5),
			malformed:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			row, ok := parseQuotaBalanceRow(json.RawMessage(tc.row))
			if !ok {
				t.Fatal("an object row is always readable")
			}
			if row.Meter != tc.meter || row.Period != tc.period {
				t.Fatalf("row = meter %q period %q, want %q / %q", row.Meter, row.Period, tc.meter, tc.period)
			}
			if !floatPtrEqual(row.GrantUnits, tc.grant) {
				t.Fatalf("grant = %v, want %v", row.GrantUnits, tc.grant)
			}
			if !floatPtrEqual(row.PeriodStart, tc.periodStart) {
				t.Fatalf("period start = %v, want %v", row.PeriodStart, tc.periodStart)
			}
			if row.Malformed != tc.malformed {
				t.Fatalf("malformed = %v, want %v", row.Malformed, tc.malformed)
			}
		})
	}
}

// TestBalanceRemainingFractionIsOneReading covers the single fraction both the
// host group and the management view render. It is the remaining share of the
// bucket, clamped into [0,1]: a bucket that reports more remaining than its
// total is a statement the page must not turn into a 100+%-wide bar.
func TestBalanceRemainingFractionIsOneReading(t *testing.T) {
	cases := []struct {
		name    string
		balance quotaBalance
		want    float64
		has     bool
	}{
		{
			name:    "the captured bucket",
			balance: quotaBalance{Remaining: float64Ptr(59534117), Total: float64Ptr(100000000)},
			want:    0.59534117,
			has:     true,
		},
		{
			name:    "an empty bucket reads as zero, not as unknown",
			balance: quotaBalance{Remaining: float64Ptr(0), Total: float64Ptr(100)},
			want:    0,
			has:     true,
		},
		{
			name:    "over-reported remaining clamps to a full bucket",
			balance: quotaBalance{Remaining: float64Ptr(150), Total: float64Ptr(100)},
			want:    1,
			has:     true,
		},
		{
			name:    "no total leaves the fraction unknown",
			balance: quotaBalance{Remaining: float64Ptr(60)},
		},
		{
			name:    "a zero total cannot divide",
			balance: quotaBalance{Remaining: float64Ptr(0), Total: float64Ptr(0)},
		},
		{
			name:    "an unknown remaining is not a zero fraction",
			balance: quotaBalance{Total: float64Ptr(100)},
		},
		{
			name: "a drifted row is not a fraction",
			balance: quotaBalance{Remaining: float64Ptr(60), Total: float64Ptr(100),
				Malformed: true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, has := balanceRemainingFraction(tc.balance)
			if has != tc.has {
				t.Fatalf("has = %v, want %v", has, tc.has)
			}
			if has && math.Abs(got-tc.want) > 1e-9 {
				t.Fatalf("fraction = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestBalanceDisplayNameUsesTheUpstreamsOwnSemantics covers the label of a
// bucket the upstream did not name. The literal "model" it used to fall back to
// carried no information at all and appeared in the page as "model:59534117";
// the meter's own reading is what the upstream would call it.
func TestBalanceDisplayNameUsesTheUpstreamsOwnSemantics(t *testing.T) {
	cases := []struct {
		name    string
		balance quotaBalance
		want    string
	}{
		{
			name:    "the upstream's own display name wins",
			balance: quotaBalance{Name: "GLM-5.3-Flash", Meter: "model_usage", UnitType: "token"},
			want:    "GLM-5.3-Flash",
		},
		{
			name:    "an unnamed model bucket reads as its meter and unit",
			balance: quotaBalance{Meter: "model_usage", UnitType: "token"},
			want:    "model_usage(token)",
		},
		{
			name:    "an unnamed bucket with one meter reads as the meter",
			balance: quotaBalance{Meter: "model_usage"},
			want:    "model_usage",
		},
		{
			name:    "an unnamed non-model bucket keeps its unit",
			balance: quotaBalance{Meter: "tool_calls", UnitType: "count"},
			want:    "tool_calls(count)",
		},
		{
			name:    "a bucket the upstream described nothing about stays blank",
			balance: quotaBalance{},
			want:    "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := balanceDisplayName(tc.balance); got != tc.want {
				t.Fatalf("name = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestBalanceModelIDsFallsBackToRowName covers the row that declares no
// capability but names a model: the upstream reads it the same way.
func TestBalanceModelIDsFallsBackToRowName(t *testing.T) {
	if got := balanceModelIDs(quotaBalance{Name: "GLM-5.2"}); strings.Join(got, ",") != "GLM-5.2" {
		t.Fatalf("ids = %v, want the row name", got)
	}
	// A drifted row is not evidence about which models exist.
	if got := balanceModelIDs(quotaBalance{Name: "GLM-5.2", Malformed: true}); got != nil {
		t.Fatalf("ids = %v, want none from a drifted row", got)
	}
	// Capabilities that are not model declarations must not become model ids.
	if got := balanceModelIDs(quotaBalance{Name: "Pro", Capabilities: []string{"realtime"}}); strings.Join(got, ",") != "Pro" {
		t.Fatalf("ids = %v, want the row name when no model capability exists", got)
	}
	// A row the upstream named nothing about stays empty: the literal "model"
	// the parser used to invent here was neither a model nor a label, and it
	// reached the page as the model id of every capability-less bucket.
	if got := balanceModelIDs(quotaBalance{Meter: "model_usage", UnitType: "token"}); len(got) != 0 {
		t.Fatalf("ids = %v, want none from a bucket that declared no model", got)
	}
}

// TestParseQuotaCapabilitiesRejectsTypeDrift keeps a changed capability shape
// visible as schema evidence instead of silently reading as "no models here".
func TestParseQuotaCapabilitiesRejectsTypeDrift(t *testing.T) {
	if _, ok := parseQuotaCapabilities([]byte(`"not-an-array"`)); ok {
		t.Fatal("a non-array capabilities field is drift")
	}
	if caps, ok := parseQuotaCapabilities([]byte(`["a", 5, "b"]`)); !ok || strings.Join(caps, ",") != "a,b" {
		t.Fatalf("caps = %v ok = %v, want the string entries kept", caps, ok)
	}
	if caps, ok := parseQuotaCapabilities([]byte(`null`)); !ok || caps != nil {
		t.Fatalf("null capabilities = %v ok = %v, want an empty compatible read", caps, ok)
	}
}

// TestPlanModelIDsReadsTheCachedBalance covers the catalog's use of the plan's
// own declaration, including the guard that an unreadable refresh is not
// evidence about which models exist.
func TestPlanModelIDsReadsTheCachedBalance(t *testing.T) {
	original := activeQuotaCache
	activeQuotaCache = newQuotaCache()
	t.Cleanup(func() { activeQuotaCache = original })

	snap := credentialSnapshot{IdentityID: "zcode-user-1", JWTToken: "jwt"}
	if got := planModelIDs(snap, time.Now()); got != nil {
		t.Fatalf("ids = %v, want none before any refresh", got)
	}

	activeQuotaCache.put("zcode-user-1", quotaObservation{
		State: "ok",
		Balances: []quotaBalance{
			{Name: "Pro", Capabilities: []string{"model:GLM-5.2"}, Remaining: float64Ptr(10)},
			{Name: "Pro", Capabilities: []string{"model:glm-5.2"}, Remaining: float64Ptr(5)},
		},
	})
	got := planModelIDs(snap, time.Now())
	if strings.Join(got, ",") != "GLM-5.2" {
		t.Fatalf("ids = %v, want the capability model de-duplicated", got)
	}

	// An unknown or absent plan is not evidence about models.
	for _, state := range []string{"unknown", "no_plan", "plan_expired", "unavailable"} {
		activeQuotaCache = newQuotaCache()
		activeQuotaCache.put("zcode-user-1", quotaObservation{
			State:    state,
			Balances: []quotaBalance{{Name: "Pro", Capabilities: []string{"model:GLM-5.2"}}},
		})
		if got := planModelIDs(snap, time.Now()); got != nil {
			t.Errorf("state %q ids = %v, want none", state, got)
		}
	}
}

// TestObservationRendersTheEntitlementTriState pins the P7 requirement that the
// page can tell "has quota" from "no plan" from "the plugin could not tell".
func TestObservationRendersTheEntitlementTriState(t *testing.T) {
	now := time.Now()
	cases := []struct {
		verdict quotaVerdict
		reason  string
		state   string
	}{
		{verdictAvailable, "", "ok"},
		{verdictExhausted, "", "exhausted"},
		{verdictNoPlan, "no_plan", "no_plan"},
		{verdictExpired, "plan_expired", "plan_expired"},
		{verdictUnknown, "upstream_schema_incompatible", "unknown"},
		{verdictUnknown, "upstream_reported_failure", "unknown"},
	}
	for _, tc := range cases {
		observation := observationFor(quotaEvidence{Verdict: tc.verdict, Reason: tc.reason}, now)
		if observation.State != tc.state {
			t.Errorf("verdict %q state = %q, want %q", tc.verdict, observation.State, tc.state)
		}
	}
	// A rejected credential is its own state, not a quota reading.
	failed := observationFor(quotaEvidence{
		AuthFailure: &upstreamFailure{Code: "quota_credential_invalid"},
		Verdict:     verdictUnknown,
	}, now)
	if failed.State != "unavailable" || failed.Reason != "quota_credential_invalid" {
		t.Errorf("state = %q reason = %q", failed.State, failed.Reason)
	}
	// The plan count reaches the page so an unnamed plan is still visible.
	named := observationFor(quotaEvidence{Verdict: verdictAvailable, Plans: []quotaPlan{{}}}, now)
	if named.PlanCount != 1 {
		t.Errorf("plan count = %d, want 1", named.PlanCount)
	}
}

// TestParseQuotaPlansResolvesTheTermEnd covers the difference between "the
// upstream says active" and "the plan is in force": the upstream keeps stating
// active past the end of the term, so only the term end against the server's
// own clock distinguishes a live plan from a dead one.
func TestParseQuotaPlansResolvesTheTermEnd(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cases := []struct {
		name       string
		body       string
		wantStatus string
		wantLive   bool
	}{
		{
			name:       "active and unended is live",
			body:       `{"data":{"server_time":1700000000,"plans":[{"name":"Pro","status":"active","ends_at":1800000000}]}}`,
			wantStatus: planStatusActive,
			wantLive:   true,
		},
		{
			// The upstream still says active; the term has run out anyway.
			name:       "active but past ends_at is expired",
			body:       `{"data":{"server_time":1700000000,"plans":[{"name":"Pro","status":"active","ends_at":1699000000}]}}`,
			wantStatus: planStatusExpired,
			wantLive:   false,
		},
		{
			// A zero or absent end is not a term end, so an active plan stays.
			name:       "active with no ends_at is live",
			body:       `{"data":{"server_time":1700000000,"plans":[{"name":"Pro","status":"active"}]}}`,
			wantStatus: planStatusActive,
			wantLive:   true,
		},
		{
			name:       "a stated expired status is not revived by a future end",
			body:       `{"data":{"server_time":1700000000,"plans":[{"name":"Pro","status":"expired","ends_at":1800000000}]}}`,
			wantStatus: planStatusExpired,
			wantLive:   false,
		},
		{
			// An unreadable status is not an entitlement: reading it as live
			// would report a plan the upstream never put in force.
			name:       "a plan with no status is not live",
			body:       `{"data":{"server_time":1700000000,"plans":[{"name":"Pro"}]}}`,
			wantStatus: planStatusUnknown,
			wantLive:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plans, compatible := parseQuotaPlans([]byte(tc.body), now)
			if !compatible {
				t.Fatal("body must stay schema-compatible")
			}
			if len(plans) != 1 {
				t.Fatalf("plans = %d", len(plans))
			}
			if plans[0].Status != tc.wantStatus {
				t.Errorf("status = %q, want %q", plans[0].Status, tc.wantStatus)
			}
			if planIsLive(plans[0]) != tc.wantLive {
				t.Errorf("live = %v, want %v", planIsLive(plans[0]), tc.wantLive)
			}
		})
	}
}

// TestPlanStatusForPrefersTheServerClock keeps a clock skew between the plugin
// and the upstream from expiring a live plan early or keeping a dead one alive.
func TestPlanStatusForPrefersTheServerClock(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	plan := quotaPlan{Status: "active", EndsAt: float64Ptr(1_700_000_100)}
	// The local clock says the term has ended; the server's says it has not.
	server := json.Number("1700000000")
	if got := planStatusFor(plan, server, now); got != planStatusActive {
		t.Errorf("status = %q, want active per the server clock", got)
	}
	// With no server time the local clock is the only reference available.
	if got := planStatusFor(plan, json.Number(""), now.Add(time.Hour)); got != planStatusExpired {
		t.Errorf("status = %q, want expired per the local clock", got)
	}
}

// TestBalanceModelIDsCanonicalizesCapabilityCasing pins the official casing
// fold: the balance endpoint declares capabilities in lower case, and the
// catalog must carry the upstream's canonical spellings.
func TestBalanceModelIDsCanonicalizesCapabilityCasing(t *testing.T) {
	balance := quotaBalance{
		Name:         "GLM-5.3-Flash",
		Capabilities: []string{"model:glm-5.3-flash", "model:GLM-5.2", "realtime"},
	}
	if got := strings.Join(balanceModelIDs(balance), ","); got != "GLM-5.3-Flash,GLM-5.2" {
		t.Fatalf("ids = %v, want the canonical GLM-5.3-Flash and GLM-5.2", got)
	}
	// The name fallback folds the same way.
	if got := balanceModelIDs(quotaBalance{Name: "glm-5.3-flash"}); strings.Join(got, ",") != "GLM-5.3-Flash" {
		t.Fatalf("ids = %v, want the canonical row name", got)
	}
}

// TestQuotaBalancePathIsIndependentOfMessagesRouteDecisions pins the boundary
// the issue asks for: route and billing-domain decisions exist for Messages
// traffic only. The quota path keeps its own JWT-only contract — the balance
// URL is not a Messages route, stays direct even with the official gateway
// candidates registered, and the plan-JWT route's billing domain is the plan
// entitlement the balance endpoint reads.
func TestQuotaBalancePathIsIndependentOfMessagesRouteDecisions(t *testing.T) {
	if route := resolveRoute(CredentialJWT); route.BillingDomain != billingPlanEntitlement {
		t.Fatalf("plan route billing domain = %q, want %q", route.BillingDomain, billingPlanEntitlement)
	}
	balance := balanceURL("3.14.4")
	if strings.Contains(balance, zcodeMessagesPath) {
		t.Fatalf("balance url %q must not be a Messages route", balance)
	}
	official := []gatewayRouteCandidate{
		{ProviderEndpoint: "https://api.z.ai/api/anthropic/v1/messages", GatewayPath: "/api/v1/ultra-zai/anthropic/v1/messages"},
		{ProviderEndpoint: "https://open.bigmodel.cn/api/anthropic/v1/messages", GatewayPath: "/api/v1/ultra/anthropic/v1/messages"},
	}
	if rewritten, ok := applyGatewayRoutes(balance, zcodeGatewayOrigin(), official); ok {
		t.Fatalf("balance url was rewritten to %q; billing paths must stay direct", rewritten)
	}
}

// TestParseQuotaReadsPlanOwnershipKeys covers the two keys the upstream uses
// to say which plan a bucket spends. Both are read here because grouping is the
// only reason they exist: a bucket with neither can only be reported as
// unassigned, and a bucket whose keys were dropped could never be told apart
// from one at all.
func TestParseQuotaReadsPlanOwnershipKeys(t *testing.T) {
	plans, compatible := parseQuotaPlans([]byte(realBalancePayload), time.Now())
	if !compatible || len(plans) != 1 {
		t.Fatalf("plans = %+v compatible = %v, want one plan", plans, compatible)
	}
	if plans[0].PlanID != "zcode-v3-start-plan-0817" {
		t.Fatalf("plan id = %q, want zcode-v3-start-plan-0817", plans[0].PlanID)
	}
	if plans[0].UserPlanID != "upl_2105534823644946432" {
		t.Fatalf("plan user id = %q, want upl_2105534823644946432", plans[0].UserPlanID)
	}

	balances, compatible := parseQuotaBalances([]byte(realBalancePayload))
	if !compatible || len(balances) != 2 {
		t.Fatalf("balances = %d compatible = %v, want two buckets", len(balances), compatible)
	}
	for _, bucket := range balances {
		if bucket.PlanID != "zcode-v3-start-plan-0817" || bucket.UserPlanID != "upl_2105534823644946432" {
			t.Fatalf("bucket %q ownership = %q/%q", bucket.Name, bucket.UserPlanID, bucket.PlanID)
		}
	}
}

// TestIsStartPlanPlan covers how a plan is recognized as a Start Plan rather
// than a general Coding Plan. The upstream's own reading is a substring match
// on the id or the name, in either the hyphenated or the spaced spelling —
// matching on the exact id alone would read a live Start Plan as a Coding Plan
// and merge its quota into the wrong axis.
func TestIsStartPlanPlan(t *testing.T) {
	cases := []struct {
		name string
		plan quotaPlan
		want bool
	}{
		{name: "hyphenated plan id", plan: quotaPlan{PlanID: "zcode-v3-start-plan-trust-1003"}, want: true},
		{name: "spaced display name", plan: quotaPlan{Name: "ZCode V3 Start Plan"}, want: true},
		{name: "hyphenated display name", plan: quotaPlan{Name: "Start-Plan"}, want: true},
		{name: "coding plan id", plan: quotaPlan{PlanID: "zcode-v3-coding-plan", Name: "GLM Coding Plan"}, want: false},
		{name: "plan stating neither", plan: quotaPlan{}, want: false},
		{name: "plan naming only its user id", plan: quotaPlan{UserPlanID: "upl_1"}, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isStartPlanPlan(tc.plan); got != tc.want {
				t.Fatalf("isStartPlanPlan(%+v) = %v, want %v", tc.plan, got, tc.want)
			}
		})
	}
}

// TestGroupBalancesByPlanPrefersTheUserPlanID covers the ownership rule the
// upstream itself applies: a bucket and a plan that both state a user plan id
// are matched on that id, not on the shared product id. One product sold twice
// produces two plans sharing a plan_id, so matching on plan_id alone would put
// both instances' buckets into whichever plan was read first.
func TestGroupBalancesByPlanPrefersTheUserPlanID(t *testing.T) {
	plans := []quotaPlan{
		{Name: "Start Plan A", PlanID: "zcode-v3-start-plan", UserPlanID: "upl_a", Status: planStatusActive},
		{Name: "Start Plan B", PlanID: "zcode-v3-start-plan", UserPlanID: "upl_b", Status: planStatusActive},
	}
	balances := []quotaBalance{
		{Name: "GLM-5.3-Flash", PlanID: "zcode-v3-start-plan", UserPlanID: "upl_a"},
		{Name: "GLM-5.3", PlanID: "zcode-v3-start-plan", UserPlanID: "upl_b"},
	}
	groups, _ := placeBucketsByPlan(plans, balances)
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2; one product sold twice is two quota axes", len(groups))
	}
	for _, group := range groups {
		if len(group.Balances) != 1 {
			t.Fatalf("group %q holds %d buckets, want 1", group.Label, len(group.Balances))
		}
	}
	if groups[0].Label != "Start Plan A" || groups[0].Kind != planGroupStartPlan {
		t.Fatalf("first group = %+v, want Start Plan A as a start_plan group", groups[0])
	}
	if groups[1].Balances[0].Name != "GLM-5.3" {
		t.Fatalf("second group holds %q, want the upl_b bucket", groups[1].Balances[0].Name)
	}
}

// TestGroupBalancesByPlanFallsBackToTheProductID covers the fallback half of
// the ownership rule: a bucket that states no user plan id is matched on the
// product id, which is the only key the two rows share.
func TestGroupBalancesByPlanFallsBackToTheProductID(t *testing.T) {
	plans := []quotaPlan{{Name: "GLM Coding Plan", PlanID: "zcode-v3-coding-plan", Status: planStatusActive}}
	balances := []quotaBalance{{Name: "GLM", PlanID: "zcode-v3-coding-plan"}}
	groups, _ := placeBucketsByPlan(plans, balances)
	if len(groups) != 1 {
		t.Fatalf("groups = %d, want 1", len(groups))
	}
	if groups[0].Label != "GLM Coding Plan" || groups[0].Kind != planGroupCodingPlan {
		t.Fatalf("group = %+v, want the Coding Plan group", groups[0])
	}
}

// TestGroupBalancesByPlanKeepsOrphansUnassigned covers the bucket whose plan
// the upstream did not describe. It gets a group of its own rather than being
// folded into the plan that happens to be present: putting a Start Plan bucket
// inside a Coding Plan group would report the wrong billing axis, which is the
// mistake this grouping exists to prevent.
func TestGroupBalancesByPlanKeepsOrphansUnassigned(t *testing.T) {
	plans := []quotaPlan{{Name: "GLM Coding Plan", PlanID: "zcode-v3-coding-plan", Status: planStatusActive}}
	balances := []quotaBalance{
		{Name: "GLM", PlanID: "zcode-v3-coding-plan"},
		{Name: "GLM-5.3-Flash", PlanID: "zcode-v3-start-plan-trust-1003"},
	}
	groups, _ := placeBucketsByPlan(plans, balances)
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want the coding group plus one orphan group", len(groups))
	}
	if groups[1].Kind != planGroupUnassigned {
		t.Fatalf("orphan group kind = %q, want %q", groups[1].Kind, planGroupUnassigned)
	}
	if groups[1].Label != "zcode-v3-start-plan-trust-1003" {
		t.Fatalf("orphan group label = %q, want the bucket's own plan id", groups[1].Label)
	}
	if len(groups[0].Balances) != 1 || groups[0].Balances[0].Name != "GLM" {
		t.Fatalf("coding group = %+v, want only its own bucket", groups[0].Balances)
	}
}

// TestGroupBalancesByPlanOrdersByUpstreamBalanceOrder covers the reading order:
// a page renders groups in the order the upstream listed their buckets, so a
// reader sees the same sequence the response states.
func TestGroupBalancesByPlanOrdersByUpstreamBalanceOrder(t *testing.T) {
	plans := []quotaPlan{
		{Name: "ZCode V3 Start Plan", PlanID: "zcode-v3-start-plan-1003", UserPlanID: "upl_1", Status: planStatusActive},
		{Name: "GLM Coding Plan", PlanID: "zcode-v3-coding-plan", Status: planStatusActive},
	}
	balances := []quotaBalance{
		{Name: "coding", PlanID: "zcode-v3-coding-plan"},
		{Name: "flash", PlanID: "zcode-v3-start-plan-1003", UserPlanID: "upl_1"},
	}
	groups, _ := placeBucketsByPlan(plans, balances)
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2", len(groups))
	}
	if groups[0].Label != "GLM Coding Plan" {
		t.Fatalf("first group = %q; the first bucket upstream belongs to the coding plan", groups[0].Label)
	}
	if groups[1].Kind != planGroupStartPlan {
		t.Fatalf("second group kind = %q, want %q", groups[1].Kind, planGroupStartPlan)
	}
}

// TestPlanGroupKindNeverGuessesAnUnreadableIdentity covers the classification
// of a plan the plugin cannot read. Every plan the upstream names is a Start
// Plan or a general Coding Plan, so a plan stating neither an id nor a name
// cannot be placed on either axis: reading it as the general one would render
// an unreadable Start Plan under "通用额度", which is the exact mislabeling the
// grouping exists to prevent.
func TestPlanGroupKindNeverGuessesAnUnreadableIdentity(t *testing.T) {
	cases := []struct {
		name string
		plan quotaPlan
		want string
	}{
		{name: "named start plan", plan: quotaPlan{PlanID: "zcode-v3-start-plan-trust-1003"}, want: planGroupStartPlan},
		{name: "named coding plan", plan: quotaPlan{PlanID: "zcode-v3-coding-plan"}, want: planGroupCodingPlan},
		{name: "coding plan named only by its display name", plan: quotaPlan{Name: "GLM Coding Plan"}, want: planGroupCodingPlan},
		{name: "identity unreadable stays unproven", plan: quotaPlan{UserPlanID: "upl_1"}, want: planGroupUnassigned},
		{name: "no identity at all stays unproven", plan: quotaPlan{}, want: planGroupUnassigned},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := planGroupKind(tc.plan); got != tc.want {
				t.Fatalf("planGroupKind(%+v) = %q, want %q", tc.plan, got, tc.want)
			}
		})
	}
}

// TestGroupBalancesByPlanKeepsPlansSharingALabelApart covers the case a
// label-keyed join would silently merge: two live plans that display
// identically — both carrying the same display name — while drawing different
// allowances. Groups are identified positionally precisely so that this stays
// two headings.
func TestGroupBalancesByPlanKeepsPlansSharingALabelApart(t *testing.T) {
	plans := []quotaPlan{
		{Name: "Start Plan", PlanID: "zcode-v3-start-plan", UserPlanID: "upl_a", Status: planStatusActive},
		{Name: "Start Plan", PlanID: "zcode-v3-start-plan", UserPlanID: "upl_b", Status: planStatusActive},
	}
	balances := []quotaBalance{
		{Name: "GLM-5.3-Flash", PlanID: "zcode-v3-start-plan", UserPlanID: "upl_a"},
		{Name: "GLM-5.3", PlanID: "zcode-v3-start-plan", UserPlanID: "upl_b"},
	}
	groups, axis := placeBucketsByPlan(plans, balances)
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2; two instances of one product are two axes", len(groups))
	}
	// Both groups carry the same label, which is exactly why the join the page
	// performs must be positional rather than by name.
	if groups[0].Label != groups[1].Label {
		t.Fatalf("labels = %q/%q; the fixture is only meaningful when they collide", groups[0].Label, groups[1].Label)
	}
	if axis[0] != 0 || axis[1] != 1 {
		t.Fatalf("axis = %v, want [0 1] so the page can join positionally", axis)
	}
	for i, group := range groups {
		if len(group.Balances) != 1 || group.Balances[0].Name != balances[i].Name {
			t.Fatalf("group %d holds %+v, want only bucket %d", i, group.Balances, i)
		}
	}
}

// TestPlaceBucketsByPlanReportsAPositionalAxis pins the join the management
// page depends on: the axis is a group index, not a label, so a caller that
// rejoins buckets to groups cannot merge two plans that share a name.
func TestPlaceBucketsByPlanReportsAPositionalAxis(t *testing.T) {
	plans := []quotaPlan{
		{Name: "GLM Coding Plan", PlanID: "zcode-v3-coding-plan", Status: planStatusActive},
		{Name: "ZCode V3 Start Plan", PlanID: "zcode-v3-start-plan-1003", UserPlanID: "upl_1", Status: planStatusActive},
	}
	balances := []quotaBalance{
		{Name: "flash", PlanID: "zcode-v3-start-plan-1003", UserPlanID: "upl_1"},
		{Name: "orphan", PlanID: "zcode-v3-start-plan-trust-1003"},
		{Name: "coding", PlanID: "zcode-v3-coding-plan"},
	}
	groups, axis := placeBucketsByPlan(plans, balances)
	if len(groups) != 3 {
		t.Fatalf("groups = %d, want 3", len(groups))
	}
	for i, want := range []int{0, 1, 2} {
		if axis[i] != want {
			t.Fatalf("bucket %q axis = %d, want %d", balances[i].Name, axis[i], want)
		}
	}
	if groups[1].Kind != planGroupUnassigned {
		t.Fatalf("orphan group kind = %q, want %q", groups[1].Kind, planGroupUnassigned)
	}
}

// TestRenderViewGroupsQuotaByPlan covers the host-facing view: the response
// carries one group per plan, each named for the plan it belongs to, and the
// remaining share each bucket reports is the same number before and after
// grouping — the grouping is a presentation change and must not move a
// measurement.
func TestRenderViewGroupsQuotaByPlan(t *testing.T) {
	fixture := newQuotaFixture(t)
	fixture.balanceBody = realBalancePayload
	evidence := fetchQuotaEvidence(context.Background(), "jwt-token-value", "3.14.4", testDeviceID, time.Now())

	if len(evidence.Groups) != 1 {
		t.Fatalf("groups = %d, want 1 group for a single-plan response", len(evidence.Groups))
	}
	group := evidence.Groups[0]
	if group.DisplayName != "ZCode Start Plan" {
		t.Fatalf("group name = %q, want the plan's own name", group.DisplayName)
	}
	if len(group.Buckets) != 2 {
		t.Fatalf("buckets = %d, want both buckets under the plan", len(group.Buckets))
	}
	for i, name := range []string{"GLM-5.3", "GLM-5.3-Flash"} {
		if group.Buckets[i].Window != name {
			t.Fatalf("bucket %d = %q, want %q", i, group.Buckets[i].Window, name)
		}
		if full := 1.0; group.Buckets[i].RemainingFraction != full {
			t.Fatalf("bucket %q fraction = %v, want %v", name, group.Buckets[i].RemainingFraction, full)
		}
	}
	// A group with no readable share is not rendered at all: a fraction of
	// nothing would be a measurement the upstream never made.
	floored := quotaEvidence{Balances: []quotaBalance{{Name: "drifted", Malformed: true, Total: float64Ptr(10), Remaining: float64Ptr(5)}}}
	floored.renderView()
	if len(floored.Groups) != 0 {
		t.Fatalf("malformed bucket produced %d groups, want none", len(floored.Groups))
	}
}

// TestRenderViewKeepsOrphanBucketsOffOtherPlansInTheHostView covers the host
// surface's half of the axis separation. The management page groups its buckets
// explicitly, but the host only receives a flat group list, so a bucket that
// belongs to no described plan must still reach it under a group of its own —
// the numbers are real and the flat summary already carries them, but rendering
// them under someone else's heading would name the wrong billing axis.
func TestRenderViewKeepsOrphanBucketsOffOtherPlansInTheHostView(t *testing.T) {
	evidence := quotaEvidence{
		Plans: []quotaPlan{
			{Name: "GLM Coding Plan", PlanID: "zcode-v3-coding-plan", Status: planStatusActive},
			{Name: "ZCode V3 Start Plan", PlanID: "zcode-v3-start-plan-1003", UserPlanID: "upl_1", Status: planStatusActive},
		},
		Balances: []quotaBalance{
			{Name: "GLM Coding", PlanID: "zcode-v3-coding-plan", Total: float64Ptr(100), Remaining: float64Ptr(20)},
			{Name: "GLM-5.3-Flash", PlanID: "zcode-v3-start-plan-1003", UserPlanID: "upl_1", Total: float64Ptr(200), Remaining: float64Ptr(150)},
			{Name: "unclaimed", PlanID: "zcode-v3-start-plan-trust-1003", Total: float64Ptr(50), Remaining: float64Ptr(50)},
		},
	}
	evidence.renderView()

	if len(evidence.Groups) != 3 {
		t.Fatalf("groups = %d, want one per billing axis; an unclaimed bucket must not be folded into a plan", len(evidence.Groups))
	}
	names := []string{"GLM Coding Plan", "ZCode V3 Start Plan", "zcode-v3-start-plan-trust-1003"}
	for i, want := range names {
		if evidence.Groups[i].DisplayName != want {
			t.Fatalf("group %d = %q, want %q", i, evidence.Groups[i].DisplayName, want)
		}
		if len(evidence.Groups[i].Buckets) != 1 {
			t.Fatalf("group %q holds %d buckets, want exactly its own", want, len(evidence.Groups[i].Buckets))
		}
	}
	// Every bucket is also in the flat summary, so a group dropped for an
	// unread fraction never costs the host the numbers themselves.
	if len(evidence.Summary) != 3 {
		t.Fatalf("summary = %d metrics, want one remaining reading per bucket", len(evidence.Summary))
	}
}
