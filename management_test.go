package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// managementFixture wires the management plane against a fake auth store and
// local test doubles for the two upstream models endpoints and the billing
// endpoints. It optionally builds on an oauthFixture's store so the OAuth
// retry tests share one store across both planes.
type managementFixture struct {
	t         *testing.T
	store     *fakeAuthStore
	oauth     *upstreamFixture
	modelsSrv *httptest.Server

	mu         sync.Mutex
	planStatus int
	planBody   string
	zaiStatus  int
	zaiBody    string
	billStatus int
	billBody   string
}

func newManagementFixture(t *testing.T) *managementFixture {
	t.Helper()
	fixture := &managementFixture{t: t, store: &fakeAuthStore{docs: map[string]json.RawMessage{}}}
	fixture.setup(t)
	return fixture
}

// newManagementFixtureOver shares the oauth fixture's store and upstream
// doubles, so an OAuth retry exercise completes through one store.
func newManagementFixtureOver(t *testing.T, oauth *upstreamFixture) *managementFixture {
	t.Helper()
	fixture := &managementFixture{t: t, store: oauth.store, oauth: oauth}
	fixture.setup(t)
	return fixture
}

func (f *managementFixture) setup(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/zcode-plan/anthropic/v1/models", f.servePlanModels)
	mux.HandleFunc("/api/anthropic/v1/models", f.serveZaiModels)
	mux.HandleFunc(billingCurrentPath, f.serveBillingCurrent)
	mux.HandleFunc(billingBalancePath, f.serveBillingBalance)
	f.modelsSrv = httptest.NewServer(mux)
	t.Cleanup(f.modelsSrv.Close)

	originalPlan := zcodePlanUpstreamBase
	originalZai := zaiAPIBase
	originalBilling := zcodePlanBillingBase
	originalStore := authStoreProvider
	originalCatalog := activeModelCatalog
	originalQuota := activeQuotaCache
	originalInterval := managementPollInterval
	zcodePlanUpstreamBase = f.modelsSrv.URL
	zaiAPIBase = f.modelsSrv.URL
	zcodePlanBillingBase = f.modelsSrv.URL
	authStoreProvider = func() AuthStore { return f.store }
	activeModelCatalog = newModelCatalog()
	activeQuotaCache = newQuotaCache()
	managementPollInterval = 10 * time.Millisecond
	t.Cleanup(func() {
		zcodePlanUpstreamBase = originalPlan
		zaiAPIBase = originalZai
		zcodePlanBillingBase = originalBilling
		authStoreProvider = originalStore
		activeModelCatalog = originalCatalog
		activeQuotaCache = originalQuota
		managementPollInterval = originalInterval
		managementOAuth.stopAll()
	})
}

func (f *managementFixture) servePlanModels(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	status, body := f.planStatus, f.planBody
	f.mu.Unlock()
	f.respondJSON(w, status, body)
}

func (f *managementFixture) serveZaiModels(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	status, body := f.zaiStatus, f.zaiBody
	f.mu.Unlock()
	f.respondJSON(w, status, body)
}

func (f *managementFixture) serveBillingCurrent(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	status, body := f.billStatus, f.billBody
	f.mu.Unlock()
	f.respondJSON(w, status, body)
}

func (f *managementFixture) serveBillingBalance(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	status, body := f.billStatus, f.billBody
	f.mu.Unlock()
	f.respondJSON(w, status, body)
}

func (f *managementFixture) respondJSON(w http.ResponseWriter, status int, body string) {
	if status == 0 {
		status = http.StatusOK
	}
	if body == "" {
		body = `{"data":[]}`
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// accountDoc builds and registers one account on the fixture's store.
func (f *managementFixture) accountDoc(t *testing.T, authIndex, identityID, jwtStatus, keyMaterial string) []byte {
	t.Helper()
	jwt := makeJWT(t, map[string]any{"sub": strings.TrimPrefix(identityID, "zcode-")})
	doc := newTestAccountDoc(t, identityID, jwt, jwtStatus, keyMaterial)
	addFakeAccount(t, f.store, authIndex, identityID, string(doc))
	return doc
}

// addAccountOnly registers a raw document without building one.
func (f *managementFixture) addAccountOnly(t *testing.T, authIndex, identityID, doc string) {
	t.Helper()
	addFakeAccount(t, f.store, authIndex, identityID, doc)
}

// callAction serves one action POST directly and decodes the JSON body.
func (f *managementFixture) callAction(t *testing.T, action, authIndex string) (int, map[string]any) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"action": action, "auth_index": authIndex})
	if err != nil {
		t.Fatal(err)
	}
	response := serveManagementHTTP(http.MethodPost, "/v0/management/zcode/action", body)
	return decodeManagementResponse(t, response)
}

// callState serves the state route and decodes the JSON body.
func (f *managementFixture) callState(t *testing.T) map[string]any {
	t.Helper()
	response := serveManagementHTTP(http.MethodGet, "/v0/management/zcode/state", nil)
	_, data := decodeManagementResponse(t, response)
	return data
}

func decodeManagementResponse(t *testing.T, response pluginapi.ManagementResponse) (int, map[string]any) {
	t.Helper()
	var data map[string]any
	if len(response.Body) > 0 {
		if err := json.Unmarshal(response.Body, &data); err != nil {
			t.Fatalf("decode management response body: %v", err)
		}
	}
	return response.StatusCode, data
}

// savedDoc returns the auth document currently stored under one name.
func (f *managementFixture) savedDoc(t *testing.T, authIndex string) map[string]any {
	t.Helper()
	raw, err := f.store.Get(t.Context(), authIndex)
	if err != nil {
		t.Fatalf("read saved doc %s: %v", authIndex, err)
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatalf("decode saved doc %s: %v", authIndex, err)
	}
	return data
}

func jwtStatusOf(t *testing.T, doc map[string]any) string {
	t.Helper()
	zcode, ok := doc["zcode"].(map[string]any)
	if !ok {
		t.Fatal("saved doc carries no zcode namespace")
	}
	jwt, ok := zcode["jwt"].(map[string]any)
	if !ok {
		t.Fatal("saved doc carries no jwt section")
	}
	status, _ := jwt["status"].(string)
	return status
}

func TestManagementRegisterDeclaresRoutes(t *testing.T) {
	env := callMethod(t, pluginabi.MethodManagementRegister, []byte(`{"BasePath":"/v0/management"}`))
	if !env.OK {
		t.Fatalf("management.register failed: %+v", env.Error)
	}
	var response struct {
		Routes []pluginapi.ManagementRoute `json:"routes"`
	}
	if err := json.Unmarshal(env.Result, &response); err != nil {
		t.Fatalf("decode registration: %v", err)
	}
	paths := map[string]bool{}
	for _, route := range response.Routes {
		// No route may declare a legacy Menu label: Menu-bearing GET routes
		// become unauthenticated resource routes, and the management page
		// must stay management-authenticated.
		if route.Menu != "" {
			t.Errorf("route %s %s declares a Menu label", route.Method, route.Path)
		}
		paths[route.Method+" "+route.Path] = true
	}
	for _, want := range []string{"GET /zcode/page", "GET /zcode/state", "POST /zcode/action"} {
		if !paths[want] {
			t.Errorf("route %q missing, got %v", want, paths)
		}
	}
}

func TestManagementHandleServesPageAndUnknownRoutes(t *testing.T) {
	request, err := json.Marshal(managementHandleRPC{Method: http.MethodGet, Path: "/v0/management/zcode/page"})
	if err != nil {
		t.Fatal(err)
	}
	env := callMethod(t, pluginabi.MethodManagementHandle, request)
	if !env.OK {
		t.Fatalf("management.handle failed: %+v", env.Error)
	}
	var response pluginapi.ManagementResponse
	if err := json.Unmarshal(env.Result, &response); err != nil {
		t.Fatalf("decode management response: %v", err)
	}
	if got := response.Headers.Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("page content type = %q, want text/html; charset=utf-8", got)
	}
	page := string(response.Body)
	if !strings.Contains(page, "<!DOCTYPE html>") {
		t.Fatal("the page is not an HTML document")
	}
	// The page's dynamic content contract: DOM textContent writes, a
	// generation guard against stale replies, and no HTML interpolation of
	// dynamic values.
	if !strings.Contains(page, "textContent") {
		t.Error("the page must write dynamic content through textContent")
	}
	if !strings.Contains(page, "innerHTML") {
		// reversed check below; innerHTML must not be used at all
	}
	if strings.Contains(page, "innerHTML") {
		t.Error("the page must not use innerHTML")
	}
	if !strings.Contains(page, "localGeneration !== generation") {
		t.Error("the page must guard asynchronous renders with a generation check")
	}

	request, err = json.Marshal(managementHandleRPC{Method: http.MethodGet, Path: "/v0/management/zcode/unknown"})
	if err != nil {
		t.Fatal(err)
	}
	env = callMethod(t, pluginabi.MethodManagementHandle, request)
	if !env.OK {
		t.Fatalf("management.handle unknown route failed: %+v", env.Error)
	}
	if err := json.Unmarshal(env.Result, &response); err != nil {
		t.Fatalf("decode management response: %v", err)
	}
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown route status = %d, want 404", response.StatusCode)
	}
}

func TestManagementStateRedactsSecrets(t *testing.T) {
	fixture := newManagementFixture(t)
	const (
		jwtSecret   = "jwt-secret-token-value"
		keySecret   = "key-secret-material-value"
		oauthSecret = "oauth-access-secret-value"
	)
	doc, err := patchZcodeNamespace(nil, func(zcode map[string]any) error {
		zcode["schema_version"] = json.Number("1")
		zcode["identity_id"] = "zcode-redacted-user"
		zcode["jwt"] = map[string]any{
			"token":           jwtSecret,
			"status":          "exhausted",
			"last_checked_at": "2026-01-02T03:04:05Z",
			"last_error_code": "upstream_quota_exhausted",
		}
		zcode["api_key"] = map[string]any{
			"key_material": keySecret,
			"status":       "failed",
			"managed":      true,
			"name":         "cpa-zcode-deadbeef",
			"key_id":       "key-9",
			"last_error":   map[string]any{"stage": "create", "message": "upstream rejected the key creation", "at": "2026-01-02T00:00:00Z"},
		}
		zcode["oauth"] = map[string]any{"access_token": oauthSecret, "received_at": "2026-01-01T00:00:00Z"}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.addAccountOnly(t, "auth-redacted", "zcode-redacted-user", string(doc))
	// A foreign record the management plane must not render.
	fixture.store.docs["auth-foreign"] = json.RawMessage(`{"provider":"other","identity":"x"}`)
	fixture.store.entries = append(fixture.store.entries, pluginapi.HostAuthFileEntry{AuthIndex: "auth-foreign", Name: "auth-foreign", Provider: "other"})

	state := fixture.callState(t)
	rendered, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	page := string(rendered)
	for _, secret := range []string{jwtSecret, keySecret, oauthSecret} {
		if strings.Contains(page, secret) {
			t.Errorf("management state leaks a secret: %q", secret)
		}
	}
	accounts, ok := state["accounts"].([]any)
	if !ok || len(accounts) != 1 {
		t.Fatalf("accounts = %v, want exactly the one plugin account", state["accounts"])
	}
	account := accounts[0].(map[string]any)
	if account["auth_index"] != "auth-redacted" || account["identity_id"] != "zcode-redacted-user" {
		t.Fatalf("account identity fields = %+v", account)
	}
	jwtView := account["jwt"].(map[string]any)
	if jwtView["status"] != "exhausted" || jwtView["last_error_code"] != "upstream_quota_exhausted" {
		t.Fatalf("jwt view = %+v", jwtView)
	}
	if jwtView["present"] != true {
		t.Fatalf("jwt presence = %+v", jwtView)
	}
	keyView := account["api_key"].(map[string]any)
	if keyView["status"] != "failed" || keyView["name"] != "cpa-zcode-deadbeef" {
		t.Fatalf("api key view = %+v", keyView)
	}
	if keyView["last_error"] == nil {
		t.Fatal("api key view lost the sanitized error summary")
	}
	oauthView := account["oauth"].(map[string]any)
	if oauthView["has_access_token"] != true {
		t.Fatalf("oauth view = %+v", oauthView)
	}
}

func TestManagementActionValidation(t *testing.T) {
	fixture := newManagementFixture(t)
	cases := []struct {
		name   string
		body   string
		status int
		code   string
	}{
		{name: "unknown action", body: `{"action":"deploy_missiles"}`, status: http.StatusBadRequest, code: "unknown_action"},
		{name: "missing auth index", body: `{"action":"refresh_quota"}`, status: http.StatusBadRequest, code: "invalid_request"},
		{name: "batch with auth index", body: `{"action":"batch_refresh","auth_index":"auth-x"}`, status: http.StatusBadRequest, code: "invalid_request"},
		{name: "unknown auth index", body: `{"action":"refresh_quota","auth_index":"auth-missing"}`, status: http.StatusNotFound, code: "unknown_auth_index"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response := serveManagementHTTP(http.MethodPost, "/v0/management/zcode/action", []byte(tc.body))
			status, data := decodeManagementResponse(t, response)
			if status != tc.status {
				t.Fatalf("status = %d body %v, want %d", status, data, tc.status)
			}
			errObj, ok := data["error"].(map[string]any)
			if !ok || errObj["code"] != tc.code {
				t.Fatalf("error = %v, want code %q", data["error"], tc.code)
			}
		})
	}

	// A body that is not JSON at all is a request error, not a panic.
	response := serveManagementHTTP(http.MethodPost, "/v0/management/zcode/action", []byte("{not json"))
	if status, _ := decodeManagementResponse(t, response); status != http.StatusBadRequest {
		t.Fatalf("malformed body status = %d, want 400", status)
	}
	// None of the refused actions reached the auth store.
	fixture.store.mu.Lock()
	defer fixture.store.mu.Unlock()
	if len(fixture.store.saves) != 0 {
		t.Fatalf("refused actions wrote state %d times", len(fixture.store.saves))
	}
}

func TestManagementActionConflictIsRefused(t *testing.T) {
	fixture := newManagementFixture(t)
	fixture.accountDoc(t, "auth-c1", "zcode-conflict-user", "exhausted", "key-material-c")

	// Someone else already holds the management lock for the account.
	unlock, ok := managementLocks.tryLock(identityLockKey("zcode-conflict-user", "auth-c1"))
	if !ok {
		t.Fatal("could not acquire the lock the test needs to hold")
	}
	t.Cleanup(unlock)

	status, data := fixture.callAction(t, actionRefreshQuota, "auth-c1")
	if status != http.StatusConflict {
		t.Fatalf("status = %d, want 409", status)
	}
	errObj := data["error"].(map[string]any)
	if errObj["code"] != "operation_conflict" {
		t.Fatalf("error = %v, want operation_conflict", errObj)
	}
}

func TestRefreshCredentialRecordsUpstreamConclusions(t *testing.T) {
	cases := []struct {
		name       string
		planStatus int
		planBody   string
		jwtBefore  string
		jwtAfter   string
		outcome    string
	}{
		{
			name:      "a successful probe restores active",
			jwtBefore: "invalid",
			jwtAfter:  "active",
			outcome:   "active",
		},
		{
			name:       "captcha rejection is verification blocked",
			planStatus: http.StatusForbidden,
			planBody:   `{"error":{"message":"captcha required"}}`,
			jwtBefore:  "active",
			jwtAfter:   "verification_blocked",
			outcome:    "verification_blocked",
		},
		{
			name:       "plain 401 marks invalid",
			planStatus: http.StatusUnauthorized,
			jwtBefore:  "active",
			jwtAfter:   "invalid",
			outcome:    "invalid",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newManagementFixture(t)
			fixture.accountDoc(t, "auth-cred", "zcode-cred-user", tc.jwtBefore, "key-material-cred")
			fixture.planStatus = tc.planStatus
			fixture.planBody = tc.planBody

			status, data := fixture.callAction(t, actionRefreshCredential, "auth-cred")
			if status != http.StatusOK {
				t.Fatalf("status = %d body %v, want 200", status, data)
			}
			credentials := data["credentials"].([]any)
			var jwtOutcome map[string]any
			for _, item := range credentials {
				view := item.(map[string]any)
				if view["credential"] == "jwt" {
					jwtOutcome = view
				}
			}
			if jwtOutcome == nil || jwtOutcome["status"] != tc.outcome {
				t.Fatalf("jwt outcome = %v, want %q", jwtOutcome, tc.outcome)
			}
			if got := jwtStatusOf(t, fixture.savedDoc(t, "auth-cred")); got != tc.jwtAfter {
				t.Fatalf("persisted jwt status = %q, want %q", got, tc.jwtAfter)
			}
		})
	}
}

func TestRefreshCredentialLeavesPlainRejectionsUnrecorded(t *testing.T) {
	fixture := newManagementFixture(t)
	fixture.accountDoc(t, "auth-reject", "zcode-reject-user", "active", "")
	fixture.planStatus = http.StatusBadRequest

	status, data := fixture.callAction(t, actionRefreshCredential, "auth-reject")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	credentials := data["credentials"].([]any)
	var jwtOutcome map[string]any
	for _, item := range credentials {
		view := item.(map[string]any)
		if view["credential"] == "jwt" {
			jwtOutcome = view
		}
	}
	if jwtOutcome["status"] != nil || jwtOutcome["reason"] == "" {
		t.Fatalf("jwt outcome = %v, want no status with a reason", jwtOutcome)
	}
	// A request rejection says nothing about the credential.
	fixture.store.mu.Lock()
	defer fixture.store.mu.Unlock()
	if len(fixture.store.saves) != 0 {
		t.Fatalf("a request rejection wrote state %d times", len(fixture.store.saves))
	}
}

func TestRefreshQuotaRestoresExhaustedCredential(t *testing.T) {
	fixture := newManagementFixture(t)
	fixture.accountDoc(t, "auth-quota", "zcode-quota-user", "exhausted", "key-material-q")
	fixture.billBody = balanceBody(balanceRow("GLM Coding", 100.0, 30.0, 70.0))

	status, data := fixture.callAction(t, actionRefreshQuota, "auth-quota")
	if status != http.StatusOK {
		t.Fatalf("status = %d body %v, want 200", status, data)
	}
	recorded, ok := data["recorded"].([]any)
	if !ok || len(recorded) != 1 || recorded[0] != jwtStatusActive {
		t.Fatalf("recorded = %v, want [active]", data["recorded"])
	}
	if got := jwtStatusOf(t, fixture.savedDoc(t, "auth-quota")); got != jwtStatusActive {
		t.Fatalf("persisted jwt status = %q, want active", got)
	}
	quota := data["quota"].(map[string]any)
	if quota["state"] != "ok" {
		t.Fatalf("quota view = %v, want ok", quota)
	}

	// The observation is on the state page for the account.
	state := fixture.callState(t)
	for _, item := range state["accounts"].([]any) {
		account := item.(map[string]any)
		if account["auth_index"] == "auth-quota" {
			quotaView, ok := account["quota"].(map[string]any)
			if !ok || quotaView["state"] != "ok" {
				t.Fatalf("state quota view = %v, want ok", account["quota"])
			}
			return
		}
	}
	t.Fatal("the account vanished from the state page")
}

func TestRefreshQuotaWithoutJWTIsRefused(t *testing.T) {
	fixture := newManagementFixture(t)
	// A fallback-only account: a managed API key without a Coding Plan JWT.
	doc, err := patchZcodeNamespace(nil, func(zcode map[string]any) error {
		zcode["schema_version"] = json.Number("1")
		zcode["identity_id"] = "zcode-keyonly-user"
		zcode["api_key"] = map[string]any{"key_material": "key-material-only", "status": "active", "managed": true}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.addAccountOnly(t, "auth-keyonly", "zcode-keyonly-user", string(doc))

	status, data := fixture.callAction(t, actionRefreshQuota, "auth-keyonly")
	if status != http.StatusConflict {
		t.Fatalf("status = %d body %v, want 409", status, data)
	}
	if data["error"].(map[string]any)["code"] != "no_jwt_credential" {
		t.Fatalf("error = %v, want no_jwt_credential", data["error"])
	}
}

func TestRefreshModelsForcesDiscovery(t *testing.T) {
	fixture := newManagementFixture(t)
	fixture.accountDoc(t, "auth-models", "zcode-models-user", "active", "key-material-m")
	fixture.planBody = `{"data":[{"id":"GLM-5.2-Extra"}]}`
	fixture.zaiBody = `{"data":[]}` // the zai environment discovers nothing

	status, data := fixture.callAction(t, actionRefreshModels, "auth-models")
	if status != http.StatusOK {
		t.Fatalf("status = %d body %v, want 200", status, data)
	}
	environments := data["environments"].([]any)
	planOK := false
	for _, item := range environments {
		view := item.(map[string]any)
		switch view["environment"] {
		case environmentCodingPlan:
			if view["ok"] != true || view["model_count"].(float64) != 1 {
				t.Fatalf("plan environment outcome = %v", view)
			}
			planOK = true
		case environmentZai:
			if view["ok"] == true {
				t.Fatal("an empty discovery must not report success")
			}
		}
	}
	if !planOK {
		t.Fatalf("plan environment missing from %v", environments)
	}

	state := fixture.callState(t)
	found := false
	for _, item := range state["model_cache"].([]any) {
		entry := item.(map[string]any)
		if entry["identity"] == "zcode-models-user" && entry["environment"] == environmentCodingPlan {
			if entry["state"] != "cached" || entry["model_count"].(float64) != 1 {
				t.Fatalf("cache view entry = %v", entry)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("the refreshed plan scope is not on the state page")
	}
}

func TestBatchRefreshSnapshotsAndSummarizes(t *testing.T) {
	fixture := newManagementFixture(t)
	fixture.accountDoc(t, "auth-b1", "zcode-batch-one", "active", "key-1")
	fixture.accountDoc(t, "auth-b2", "zcode-batch-two", "exhausted", "key-2")
	// The third account's record is unreadable: the batch must name it as a
	// failure, not skip it silently.
	fixture.addAccountOnly(t, "auth-b3", "zcode-batch-three", `{}`)
	// The second account's quota state write fails: one partial failure.
	fixture.billBody = balanceBody(balanceRow("GLM", 10, 1, 9))
	fixture.store.mu.Lock()
	originalSaveErr := fixture.store.saveErr
	fixture.store.saveErr = fmt.Errorf("disk on fire")
	fixture.store.mu.Unlock()
	t.Cleanup(func() {
		fixture.store.mu.Lock()
		fixture.store.saveErr = originalSaveErr
		fixture.store.mu.Unlock()
	})

	status, data := fixture.callAction(t, actionBatchRefresh, "")
	if status != http.StatusOK {
		t.Fatalf("status = %d body %v, want 200", status, data)
	}
	if data["total"].(float64) != 3 {
		t.Fatalf("total = %v, want 3", data["total"])
	}
	if data["succeeded"].(float64) != 1 || data["failed"].(float64) != 2 {
		t.Fatalf("summary = succeeded %v failed %v, want 1/2", data["succeeded"], data["failed"])
	}
	byIndex := map[string]string{}
	for _, item := range data["results"].([]any) {
		result := item.(map[string]any)
		byIndex[result["auth_index"].(string)] = result["outcome"].(string)
	}
	if byIndex["auth-b1"] != "ok" || byIndex["auth-b2"] != "failed" || byIndex["auth-b3"] != "failed" {
		t.Fatalf("results = %v", byIndex)
	}
}

func TestBatchRefreshSkipsBusyAccounts(t *testing.T) {
	fixture := newManagementFixture(t)
	fixture.accountDoc(t, "auth-busy", "zcode-busy-user", "active", "key-b")

	unlock, ok := managementLocks.tryLock(identityLockKey("zcode-busy-user", "auth-busy"))
	if !ok {
		t.Fatal("could not hold the lock the test needs")
	}
	t.Cleanup(unlock)

	status, data := fixture.callAction(t, actionBatchRefresh, "")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if data["skipped"].(float64) != 1 || data["succeeded"].(float64) != 0 {
		t.Fatalf("summary = %v, want one skipped account", data)
	}
}

func TestOAuthRetryStartsSessionAndCompletesThroughPlugin(t *testing.T) {
	oauth := newUpstreamFixture(t)
	fixture := newManagementFixtureOver(t, oauth)
	fixture.accountDoc(t, "auth-retry", "zcode-retry-user", "invalid", "key-old")

	// One pending poll, then the ready verdict carrying the fresh JWT for the
	// same upstream identity.
	oauth.queuePoll(http.StatusOK, `{"data":{"status":"pending"}}`)
	newToken := makeJWT(t, map[string]any{"sub": "retry-user", "exp": 9999999999})
	oauth.queuePollReady(newToken)

	status, data := fixture.callAction(t, actionOAuthRetry, "auth-retry")
	if status != http.StatusOK {
		t.Fatalf("status = %d body %v, want 200", status, data)
	}
	session := data["session"].(map[string]any)
	if session["state"] != string(authSessionPending) {
		t.Fatalf("session = %v, want pending", session)
	}
	authorizeURL, ok := session["authorize_url"].(string)
	if !ok || !strings.HasPrefix(authorizeURL, "https://") {
		t.Fatalf("authorize_url = %v, want an https link", session["authorize_url"])
	}

	// The management loop completes the login and persists it through the
	// auth store under the identity's stable file name.
	deadline := time.Now().Add(3 * time.Second)
	for {
		fixture.store.mu.Lock()
		saves := len(fixture.store.saves)
		fixture.store.mu.Unlock()
		if saves > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the management retry loop never persisted the completed login")
		}
		time.Sleep(5 * time.Millisecond)
	}
	doc := fixture.savedDoc(t, authFileNameFor("zcode-retry-user"))
	if jwtStatusOf(t, doc) != jwtStatusActive {
		t.Fatalf("persisted jwt = %v, want active", doc["zcode"])
	}
	zcode := doc["zcode"].(map[string]any)
	if zcode["identity_id"] != "zcode-retry-user" {
		t.Fatalf("identity = %v, want zcode-retry-user", zcode["identity_id"])
	}

	// The completed session shows on the state page without any OAuth
	// parameter or secret.
	state := fixture.callState(t)
	rendered, err := json.Marshal(state["sessions"])
	if err != nil {
		t.Fatal(err)
	}
	sessionsJSON := string(rendered)
	if !strings.Contains(sessionsJSON, "completed") {
		t.Fatalf("sessions = %s, want a completed entry", sessionsJSON)
	}
	for _, forbidden := range []string{"authorize", "poll", "secret", newToken} {
		if strings.Contains(strings.ToLower(sessionsJSON), strings.ToLower(forbidden)) {
			t.Errorf("session view leaks %q", forbidden)
		}
	}
}

func TestOAuthRetryUpstreamFailureIsSanitized(t *testing.T) {
	oauth := newUpstreamFixture(t)
	fixture := newManagementFixtureOver(t, oauth)
	fixture.accountDoc(t, "auth-retry2", "zcode-retry2-user", "active", "")

	oauth.initStatus = http.StatusInternalServerError
	status, data := fixture.callAction(t, actionOAuthRetry, "auth-retry2")
	if status != http.StatusBadGateway {
		t.Fatalf("status = %d body %v, want 502", status, data)
	}
	if data["error"].(map[string]any)["code"] != "oauth_upstream_failed" {
		t.Fatalf("error = %v, want oauth_upstream_failed", data["error"])
	}
}
