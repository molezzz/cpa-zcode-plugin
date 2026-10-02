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

// fetchManagementPage serves one request through the ABI and returns the
// response body, so the tests exercise the same dispatch the host reaches
// rather than calling the router directly.
func fetchManagementPage(t *testing.T, method, path string) string {
	t.Helper()
	request, err := json.Marshal(managementHandleRPC{Method: method, Path: path})
	if err != nil {
		t.Fatal(err)
	}
	env := callMethod(t, pluginabi.MethodManagementHandle, request)
	if !env.OK {
		t.Fatalf("management.handle %s %s failed: %+v", method, path, env.Error)
	}
	var response pluginapi.ManagementResponse
	if err := json.Unmarshal(env.Result, &response); err != nil {
		t.Fatalf("decode management response: %v", err)
	}
	return string(response.Body)
}

func TestManagementRegisterDeclaresRoutes(t *testing.T) {
	env := callMethod(t, pluginabi.MethodManagementRegister, []byte(`{"BasePath":"/v0/management"}`))
	if !env.OK {
		t.Fatalf("management.register failed: %+v", env.Error)
	}
	var response struct {
		Routes    []pluginapi.ManagementRoute `json:"routes"`
		Resources []pluginapi.ResourceRoute   `json:"resources"`
	}
	if err := json.Unmarshal(env.Result, &response); err != nil {
		t.Fatalf("decode registration: %v", err)
	}
	paths := map[string]bool{}
	for _, route := range response.Routes {
		// No management route may declare a legacy Menu label: the host turns a
		// Menu-bearing GET into an unauthenticated resource route, which would
		// put account state and the credential-refresh action outside
		// management authentication. The menu entry comes from Resources.
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

	// Exactly one resource route, and it must carry the Menu label: an empty one
	// is discarded by the host and yields no navigation entry at all.
	if len(response.Resources) != 1 {
		t.Fatalf("resources = %d, want exactly 1 (the page shell): %+v", len(response.Resources), response.Resources)
	}
	shell := response.Resources[0]
	if strings.TrimSpace(shell.Menu) != managementResourceMenu {
		t.Errorf("resource Menu = %q, want %q", shell.Menu, managementResourceMenu)
	}
	if strings.TrimSpace(shell.Path) == "" {
		t.Error("resource route declares no path")
	}
	// The shell is the only unauthenticated surface, so it must not shadow a
	// data route: /zcode/state and /zcode/action must never appear here.
	for _, forbidden := range []string{managementStatePath, managementActionPath, "/state", "/action"} {
		if strings.Contains(shell.Path, forbidden) {
			t.Errorf("resource route %q exposes the data route %q without authentication", shell.Path, forbidden)
		}
	}
}

// TestManagementResourceShellCarriesNoData pins the security boundary of the
// navigation entry. The host serves resource routes without management
// authentication, so whatever this route returns is readable by anyone who can
// reach the port. The assertion is therefore not that the shell looks empty but
// that it contains no value a populated fixture holds: the identity, the
// secrets, and the label of a real account must all be absent.
func TestManagementResourceShellCarriesNoData(t *testing.T) {
	fixture := newManagementFixture(t)
	const (
		jwtSecret   = "shell-jwt-secret-value"
		keySecret   = "shell-key-secret-material"
		oauthSecret = "shell-oauth-secret-value"
	)
	doc := newTestAccountDoc(t, "zcode-shell-1", jwtSecret, "active", keySecret)
	addLabelledAccount(t, fixture.store, "zcode-shell-1", "Shell Visible Label", string(doc))

	// Prove the fixture really does hold the values the shell must not carry;
	// otherwise this test would pass against an empty store. Only the redacted
	// identity and label qualify: the secrets are deliberately absent from the
	// state document too, so their absence proves nothing on their own.
	state := buildManagementState(time.Now())
	if len(state.Accounts) != 1 {
		t.Fatalf("fixture holds %d accounts, want 1", len(state.Accounts))
	}
	encodedState, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	for _, carried := range []string{"Shell Visible Label", "zcode-shell-1"} {
		if !strings.Contains(string(encodedState), carried) {
			t.Fatalf("the state document does not carry %q, so the shell assertion below is vacuous", carried)
		}
	}

	shell := fetchManagementPage(t, http.MethodGet, managementResourcePagePath)
	for _, secret := range []string{jwtSecret, keySecret, oauthSecret, "Shell Visible Label", "zcode-shell-1"} {
		if strings.Contains(shell, secret) {
			t.Errorf("the unauthenticated shell carries the fixture value %q", secret)
		}
	}
	// No server-side interpolation at all: the shell must be the page constant,
	// byte for byte, since the host does not HTML-escape resource responses.
	if shell != managementPageHTML {
		t.Error("the resource route does not serve the page constant verbatim")
	}
}

// TestManagementResourceShellRejectsWriteMethods pins that the shell can never
// become a write endpoint. The host dispatches resource routes over GET only,
// and it carries no request body; refusing the method here as well keeps the
// plugin from depending on that host-side guarantee for a route that returns
// the credential-refresh entry point's page.
func TestManagementResourceShellRejectsWriteMethods(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		shell := fetchManagementPage(t, method, managementResourcePagePath)
		if strings.Contains(shell, "<!DOCTYPE html>") {
			t.Errorf("%s on the resource page served the page shell", method)
		}
	}
}

// TestManagementResourcePathNeverServesData closes the boundary the resource
// route is allowed to reach. The management router matches routes by suffix, so
// without the resource-prefix guard a request for
// /v0/resource/plugins/zcode/state — an unauthenticated path naming the state
// route — would satisfy the same suffix as the authenticated one and answer
// with account identities. The host does not register that resource route, so
// today the path is unreachable; the test exists so that registering one later,
// or reordering the routes, cannot turn the guard's absence into a leak that
// still passes every other test.
func TestManagementResourcePathNeverServesData(t *testing.T) {
	newManagementFixture(t)
	for _, suffix := range []string{"/state", "/action", "/page/", "/unknown"} {
		path := "/v0/resource/plugins/" + pluginID + suffix
		body := fetchManagementPage(t, http.MethodGet, path)
		if !strings.Contains(body, "unknown_route") {
			t.Errorf("GET %s answered with data or a shell (%d bytes), want a 404 route error", path, len(body))
		}
	}
	// The shell itself must keep answering: the guard must not swallow the one
	// resource route the plugin does register.
	if body := fetchManagementPage(t, http.MethodGet, managementResourcePagePath); body != managementPageHTML {
		t.Error("the registered resource page no longer serves the shell")
	}
}

// TestManagementPageAlignsEveryTable guards the rendered shape rather than the
// source text. A cell helper that returns its inner stack instead of its <td>
// still renders every word the operator reads, so only the structure shows the
// row lost a column. The assertion is therefore on the tag sequence the script
// produces: a row is one <td> per column, with no element parented straight to
// <tr>.
func TestManagementPageAlignsEveryTable(t *testing.T) {
	page := managementPageHTML
	scriptStart := strings.Index(page, "<script>")
	scriptEnd := strings.LastIndex(page, "</script>")
	if scriptStart < 0 || scriptEnd < scriptStart {
		t.Fatal("page carries no script body")
	}
	script := page[scriptStart:scriptEnd]

	// Every credential cell builder hands the caller a <td> to append. If one
	// returned the stack instead, its div would be parented directly to <tr> and
	// the table would silently lose a column. The check is that each builder is
	// actually consumed: an unappended builder renders a correct-looking row
	// with a column missing.
	for _, helper := range []string{"jwtCell", "apiKeyCell", "oauthCell", "quotaCell"} {
		if !strings.Contains(script, "function "+helper+"(") {
			t.Errorf("page is missing the %s builder", helper)
			continue
		}
		if !strings.Contains(script, "row.appendChild("+helper+"(") {
			t.Errorf("%s is built but never appended to a row; the table loses that column", helper)
		}
	}
	// appendStack must close by appending to the cell and returning that cell:
	// returning the stack nests a div under tr and drops the column.
	if !strings.Contains(script, "td.appendChild(stack);\n    return td;") {
		t.Error("appendStack must append the stack to the cell and return the cell, not the stack")
	}

	// Every appendStack call site passes plain strings. A pre-built element
	// would be stringified by the loop into [object HTMLDivElement], which still
	// renders and still passes a word-count check, so the check is that no call
	// site constructs its own line element.
	for _, call := range strings.Split(script, "appendStack(")[1:] {
		line := call[:min(len(call), 80)]
		if strings.Contains(line, "text(el(") {
			t.Errorf("appendStack is handed a built element: %s", strings.TrimSpace(line))
		}
	}
}

// TestManagementPageCarriesOnlyAnUnauthenticatedShellContract asserts the page's
// own rules, which are what make serving it without authentication safe: every
// request carries the operator's key, the key lives only in localStorage, and
// a rejected key is dropped rather than replayed.
func TestManagementPageCarriesOnlyAnUnauthenticatedShellContract(t *testing.T) {
	page := managementPageHTML

	// One network entry point, and it authenticates. A bare fetch() anywhere in
	// the script would be an unauthenticated read of the data routes.
	if got := strings.Count(page, "fetch("); got != 1 {
		t.Errorf("page performs %d network calls, want exactly 1 (the apiFetch helper)", got)
	}
	for _, want := range []string{
		`"Authorization": "Bearer " + key`,
		"function apiFetch(",
		"if (!key) {",
		"localStorage.setItem(KEY_STORAGE, key)",
		"localStorage.removeItem(KEY_STORAGE)",
		"reply.status === 401",
		"forgetKey(",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("page is missing the authenticated-fetch contract: %q", want)
		}
	}

	// The key must not leak into sessionStorage, a cookie, or the URL. Each entry
	// is a usage rather than a bare word: the page deliberately *names* the
	// stores it refuses in its comments, so only real accesses are forbidden.
	script := page
	if start := strings.Index(page, "<script>"); start >= 0 {
		if end := strings.LastIndex(page, "</script>"); end > start {
			script = page[start:end]
		}
	}
	for _, forbidden := range []string{"sessionStorage.", "sessionStorage[", "document.cookie", "management_key="} {
		if strings.Contains(script, forbidden) {
			t.Errorf("page stores or exposes the key through %q", forbidden)
		}
	}
}

// TestManagementPageTellsOneTimeBucketsFromRecurringOnes pins the acceptance
// requirement that the captured one_time bucket and a recurring window are two
// distinguishable readings. The trap is showing both a "重置" time: on a
// one_time grant the instant is when the grant lapses and nothing ever refills,
// so a reset time there sends an operator to wait for a refill that cannot
// come. The page therefore labels the same instant "到期" on a one-time grant
// and "重置" only on a recurring one.
func TestManagementPageTellsOneTimeBucketsFromRecurringOnes(t *testing.T) {
	page := managementPageHTML
	script := page
	if start := strings.Index(page, "<script>"); start >= 0 {
		if end := strings.LastIndex(page, "</script>"); end > start {
			script = page[start:end]
		}
	}

	// The one_time spelling is isolated in a named constant rather than matched
	// inline, because the label and the instant wording both read it.
	if !strings.Contains(script, `var ONE_TIME_PERIOD = "one_time";`) {
		t.Error("the one_time period spelling must be a named constant; the label and the instant wording both read it")
	}
	// The instant's meaning is decided by the period, and only by it: an
	// unread period must not be read as recurring, and a one_time grant must
	// not be told to wait for a refill.
	if !strings.Contains(script, "balance.period === ONE_TIME_PERIOD") {
		t.Error("what expires_at means must be decided by the bucket's period")
	}
	// An unread period reports the instant unlabelled rather than guessing it
	// into either reading.
	if !strings.Contains(script, "if (!balance.period) { return whenReading(balance.expires_at); }") {
		t.Error("an unread period must leave the instant's meaning unlabelled")
	}
	// Both words must exist: rendering either one for both shapes would satisfy
	// neither, and rendering neither would leave the instant unlabelled.
	for _, want := range []string{"重置", "到期"} {
		if !strings.Contains(script, want) {
			t.Errorf("the page is missing the %q wording", want)
		}
	}

	// The five-hour window is the shape the official client spends most of its
	// quota surface on, and the page must read any non-one_time period as
	// recurring without needing a table entry for it.
	if !strings.Contains(script, "PERIOD_READINGS[period] || period") {
		t.Error("an upstream period spelling the page has no translation for must still render as itself")
	}
}

// TestManagementPageRendersQuotaAsActionableEvidence pins the reading the quota
// column is required to give an operator. The page used to print one line of
// "name:59534117 / 100000000", which forces a mental division to answer "how
// much is left" and says nothing about when the bucket returns, whether it
// returns at all, or what the unit is. These are the source-level contracts
// that make the four facts visible; a plain unit count with none of them would
// still render a table that looks finished.
func TestManagementPageRendersQuotaAsActionableEvidence(t *testing.T) {
	page := managementPageHTML

	// The remaining share comes precomputed from the Go side. A page that
	// divides again can disagree with the host quota group about the same
	// bucket, and "the two surfaces tell different stories" is exactly the
	// confusion this reading exists to remove. Both operands are checked
	// because reordering defeats a single spelling: "remaining / total" and
	// "remaining * 100 / total" are the same mistake.
	for _, forbidden := range []string{"balance.remaining /", "balance.remaining/", "/ balance.total",
		"/balance.total"} {
		if strings.Contains(page, forbidden) {
			t.Errorf("the page divides remaining by total itself (%q); the fraction is computed on the Go side", forbidden)
		}
	}
	if !strings.Contains(page, "balance.remaining_fraction") {
		t.Error("the page must render the remaining_fraction the plugin already computed")
	}

	// Thousands separators: a raw 100000000 is precisely the mental arithmetic
	// the column exists to remove.
	if !strings.Contains(page, "toLocaleString()") {
		t.Error("unit counts must be grouped with a thousands separator")
	}

	// The instant is adaptive, matching the official client's semantics: today
	// shows only HH:mm (the clock is what makes it actionable), another day
	// shows the date (the day is what makes it actionable). The upstream's
	// expires_at was always in the payload and was never rendered at all.
	if !strings.Contains(page, "balance.expires_at") {
		t.Error("the page must render the bucket's expiry instant; expires_at was parsed but never shown")
	}
	if !strings.Contains(page, "toLocaleTimeString") && !strings.Contains(page, "toLocaleDateString") {
		t.Error("the instant must be formatted, not printed as a raw RFC3339 string")
	}

	// The one_time and recurring readings are different questions: "when does
	// this come back" for a recurring window, "this is a one-off grant" for a
	// one_time bucket. Rendering them identically would make an operator wait
	// for a reset that will never arrive, and an unread period must stay a
	// third reading rather than defaulting to either.
	for _, want := range []string{"one_time", "周期未知"} {
		if !strings.Contains(page, want) {
			t.Errorf("the page is missing the period reading %q", want)
		}
	}

	// Unknown stays unknown. Every optional numeric renders through one helper
	// so a missing field becomes "未知" instead of 0.
	if !strings.Contains(page, "unknownNumber") {
		t.Error("unread optional numbers must go through one unknown-aware helper")
	}

	// No currency semantics anywhere: this upstream meters model tokens and
	// tool calls, never money, so a currency symbol would assert a fact the
	// evidence does not contain. Each entry is checked where it would appear —
	// as a rendered prefix or suffix next to a number — rather than as a bare
	// word, because a comment naming what the page refuses is not a use of it.
	for _, forbidden := range []string{"¥", "$", "￥"} {
		if strings.Contains(page, forbidden) {
			t.Errorf("the page uses the currency symbol %q; the upstream meters tokens, not money", forbidden)
		}
	}
	if strings.Contains(page, "余额") {
		t.Error("the page uses the wording 余额, which reads as money; this upstream meters tokens")
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

func TestRefreshCredentialRestoresExhaustedAPIKey(t *testing.T) {
	fixture := newManagementFixture(t)
	fixture.accountDoc(t, "auth-keyexp", "zcode-keyexp-user", "active", "key-material-exp")

	// Mark the managed API key exhausted the way an upstream 402 would.
	doc := fixture.savedDoc(t, "auth-keyexp")
	zcode := doc["zcode"].(map[string]any)
	zcode["api_key"].(map[string]any)["status"] = apiKeyStatusExhausted
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	fixture.store.mu.Lock()
	fixture.store.docs["auth-keyexp"] = raw
	fixture.store.mu.Unlock()

	// The billing surface does not exist for the managed key, so the
	// credential refresh's successful probe is the only recovery evidence.
	status, data := fixture.callAction(t, actionRefreshCredential, "auth-keyexp")
	if status != http.StatusOK {
		t.Fatalf("status = %d body %v, want 200", status, data)
	}
	credentials := data["credentials"].([]any)
	var keyOutcome map[string]any
	for _, item := range credentials {
		view := item.(map[string]any)
		if view["credential"] == "api_key" {
			keyOutcome = view
		}
	}
	if keyOutcome == nil || keyOutcome["status"] != apiKeyStatusActive {
		t.Fatalf("api_key outcome = %v, want %q", keyOutcome, apiKeyStatusActive)
	}
	saved := fixture.savedDoc(t, "auth-keyexp")
	savedKey := saved["zcode"].(map[string]any)["api_key"].(map[string]any)
	if savedKey["status"] != apiKeyStatusActive {
		t.Fatalf("persisted api_key status = %v, want active", savedKey["status"])
	}
}

func TestRefreshQuotaExhaustedDoesNotOverwriteInvalid(t *testing.T) {
	fixture := newManagementFixture(t)
	fixture.accountDoc(t, "auth-stale", "zcode-stale-user", "invalid", "key-material-stale")
	// Explicit zero-balance evidence fetched while the persisted conclusion
	// is invalid: the older quota reading must not clear the newer invalid
	// state, because invalid recovers through a credential refresh only.
	fixture.billBody = balanceBody(balanceRow("GLM Coding", 100.0, 100.0, 0.0))

	status, data := fixture.callAction(t, actionRefreshQuota, "auth-stale")
	if status != http.StatusOK {
		t.Fatalf("status = %d body %v, want 200", status, data)
	}
	if got := jwtStatusOf(t, fixture.savedDoc(t, "auth-stale")); got != jwtStatusInvalid {
		t.Fatalf("persisted jwt status = %q, want invalid to survive the stale quota write", got)
	}
}

func TestQuotaViewKeepsMalformedBalanceRowsVisible(t *testing.T) {
	fixture := newManagementFixture(t)
	fixture.accountDoc(t, "auth-drift", "zcode-drift-user", "active", "key-material-drift")
	// One drifted row (string remaining_units) next to a well-typed row: the
	// drift shrinks that row's evidence to unknown but must not hide it.
	fixture.billBody = balanceBody(
		balanceRow("GLM Coding", 100.0, 30.0, 70.0),
		`{"show_name":"GLM Vision","remaining_units":"60"}`,
	)

	status, data := fixture.callAction(t, actionRefreshQuota, "auth-drift")
	if status != http.StatusOK {
		t.Fatalf("status = %d body %v, want 200", status, data)
	}
	quota := data["quota"].(map[string]any)
	if quota["state"] != "ok" {
		t.Fatalf("quota state = %v, want ok from the well-typed row", quota)
	}
	balances := quota["balances"].([]any)
	var drifted map[string]any
	for _, item := range balances {
		view := item.(map[string]any)
		if view["name"] == "GLM Vision" {
			drifted = view
		}
	}
	if drifted == nil {
		t.Fatalf("balances = %v, want the drifted row to stay visible", balances)
	}
	if drifted["malformed"] != true {
		t.Fatalf("drifted row = %v, want the malformed marker", drifted)
	}
	if drifted["remaining"] != nil || drifted["total"] != nil {
		t.Fatalf("drifted row = %v, want no coerced numbers", drifted)
	}
}

// TestQuotaViewCarriesTheBucketEvidence pins what one refreshed bucket reaches
// the page as. expires_at was already parsed and serialized but never read by
// the page, and the semantics fields were dropped at the parser, so a bucket
// could print a raw unit count while everything that makes it actionable — how
// much is left in share, when it comes back, what it meters, how often — was
// invisible.
func TestQuotaViewCarriesTheBucketEvidence(t *testing.T) {
	fixture := newManagementFixture(t)
	fixture.accountDoc(t, "auth-bucket", "zcode-bucket-user", "active", "key-material-bucket")
	// The grant lives on the plan's entitlement and the bucket inherits it, so
	// the fixture carries both — which is the only shape in which "how often
	// does this come back" and "what was it granted" are answerable at all.
	fixture.billBody = planBalanceBody(
		`[{"name":"ZCode Trust Build","status":"active","entitlements":[`+
			`{"entitlement_id":"zcode-v3-start-plan-trust-1002","show_name":"GLM-5.3-Flash",`+
			`"meter":"model_usage","unit_type":"token","grant_units":100000000,"period":"one_time"}]}]`,
		oneTimeBalanceRow)

	status, data := fixture.callAction(t, actionRefreshQuota, "auth-bucket")
	if status != http.StatusOK {
		t.Fatalf("status = %d body %v, want 200", status, data)
	}
	quota := data["quota"].(map[string]any)
	balances, _ := quota["balances"].([]any)
	if len(balances) != 1 {
		t.Fatalf("balances = %v, want the one refreshed bucket", balances)
	}
	bucket := balances[0].(map[string]any)

	if bucket["name"] != "GLM-5.3-Flash" {
		t.Fatalf("bucket name = %v, want the upstream's own display name", bucket["name"])
	}
	// The fraction is computed once, on the Go side, from the same reading the
	// host group renders: the page must never divide again.
	if !floatPtrEqual(balanceFloat(t, bucket, "remaining_fraction"), float64Ptr(0.59534117)) {
		t.Fatalf("remaining_fraction = %v, want 0.59534117", bucket["remaining_fraction"])
	}
	if bucket["expires_at"] == nil || bucket["expires_at"] == "" {
		t.Fatal("the bucket reset time is missing; the page has no way to say when it returns")
	}
	for _, want := range []struct {
		key   string
		value float64
	}{
		{"grant", 100000000},
		{"period_start", 1790893735},
		{"period_end", 1790956800},
	} {
		if !floatPtrEqual(balanceFloat(t, bucket, want.key), float64Ptr(want.value)) {
			t.Errorf("bucket[%q] = %v, want %v", want.key, bucket[want.key], want.value)
		}
	}
	for key, want := range map[string]string{
		"meter":     "model_usage",
		"unit_type": "token",
		"period":    "one_time",
	} {
		if bucket[key] != want {
			t.Errorf("bucket[%q] = %v, want %v", key, bucket[key], want)
		}
	}
}

// balanceFloat reads one numeric field out of a decoded bucket view, failing
// the test when the field is absent. It exists so every "the plugin read
// exactly this number" assertion in the management tests compares the same
// way instead of each hand-rolling a tolerance.
func balanceFloat(t *testing.T, bucket map[string]any, key string) *float64 {
	t.Helper()
	value, present := bucket[key]
	if !present {
		t.Fatalf("bucket has no %q field; the page cannot render what the plugin never sent", key)
	}
	number, ok := value.(float64)
	if !ok {
		t.Fatalf("bucket[%q] = %v (%T), want a JSON number", key, value, value)
	}
	return &number
}

// TestQuotaViewRendersUnknownEvidenceAsAbsent pins the other half of the
// unknown-is-not-zero rule at the JSON boundary: a field the upstream omitted
// has no key at all, so the page renders "未知" rather than a number that reads
// as a measurement.
func TestQuotaViewRendersUnknownEvidenceAsAbsent(t *testing.T) {
	fixture := newManagementFixture(t)
	fixture.accountDoc(t, "auth-unknown", "zcode-unknown-user", "active", "key-material-unknown")
	fixture.billBody = balanceBody(`{"remaining_units":42}`)

	status, data := fixture.callAction(t, actionRefreshQuota, "auth-unknown")
	if status != http.StatusOK {
		t.Fatalf("status = %d body %v, want 200", status, data)
	}
	quota := data["quota"].(map[string]any)
	bucket := quota["balances"].([]any)[0].(map[string]any)
	for _, key := range []string{"total", "used", "remaining_fraction", "grant", "period",
		"period_start", "period_end", "expires_at", "meter", "unit_type"} {
		if value, present := bucket[key]; present && value != nil && value != "" {
			t.Errorf("bucket[%q] = %v, want the field absent for an unstated value", key, value)
		}
	}
	// The bucket described no meter either, so it has no name to render rather
	// than the placeholder the parser used to invent.
	if bucket["name"] != "" {
		t.Fatalf("bucket name = %v, want blank for a bucket the upstream did not name", bucket["name"])
	}
}

// TestAccountViewSuggestsReauthForAnAgedJWT covers the operator-visible half of
// the age policy: the zcode-plan JWT states no expiry, so past the
// re-authorization age the plugin says so instead of letting the account fail
// requests quietly.
func TestAccountViewSuggestsReauthForAnAgedJWT(t *testing.T) {
	aged := time.Now().Add(-jwtReauthAfter - time.Hour)
	doc := accountDocWithJWT(t, makeJWTWithClaims(t, map[string]any{
		"sub": "aged-user",
		"iat": aged.Unix(),
	}), "active", "")

	namespace, err := readAccountNamespace(doc)
	if err != nil {
		t.Fatalf("read namespace: %v", err)
	}
	if namespace.JWT == nil || !namespace.JWT.ReauthSuggested {
		t.Fatalf("jwt view = %+v, want a re-authorization suggestion", namespace.JWT)
	}
	// A credential already recorded invalid says what is wrong more precisely,
	// so the age suggestion would only be noise.
	invalid := accountDocWithJWT(t, makeJWTWithClaims(t, map[string]any{
		"sub": "aged-user",
		"iat": aged.Unix(),
	}), jwtStatusInvalid, "")
	namespace, err = readAccountNamespace(invalid)
	if err != nil {
		t.Fatalf("read namespace: %v", err)
	}
	if namespace.JWT.ReauthSuggested {
		t.Error("an already-invalid credential must not also be suggested for re-auth")
	}
}

// TestAccountViewReportsLapsedBusinessAccess covers the other invisible
// failure: the Coding Plan JWT keeps working, so nothing else would tell the
// user their business-API access has lapsed and the subscription surface will
// answer 401.
func TestAccountViewReportsLapsedBusinessAccess(t *testing.T) {
	doc := accountDocWithJWT(t, makeJWTWithClaims(t, map[string]any{"sub": "user-1"}), "active", "")
	failed := recordBusinessTokenFailure(doc, time.Now())
	namespace, err := readAccountNamespace(failed)
	if err != nil {
		t.Fatalf("read namespace: %v", err)
	}
	if namespace.OAuth == nil || !namespace.OAuth.ReauthRequired {
		t.Fatalf("oauth view = %+v, want reauth required", namespace.OAuth)
	}
	if namespace.OAuth.Reason != errZaiOAuthRequired.Error() {
		t.Errorf("reason = %q, want the re-login requirement", namespace.OAuth.Reason)
	}
	// A later successful exchange clears the flag: it is cleared in the
	// document, so the view must not resurrect it from the error alone.
	recovered := writeBusinessToken(failed, businessToken{
		Token:     "biz-token",
		ExpiresAt: time.Now().Add(time.Hour),
	}, time.Now())
	namespace, err = readAccountNamespace(recovered)
	if err != nil {
		t.Fatalf("read namespace: %v", err)
	}
	if namespace.OAuth.ReauthRequired {
		t.Error("a recovered exchange must clear the reauth requirement")
	}
}

// accountDocWithJWT renders an account document carrying a JWT and, when the
// access token is present, the OAuth namespace.
func accountDocWithJWT(t *testing.T, jwt, status, accessToken string) []byte {
	t.Helper()
	zcode := map[string]any{
		"identity_id": "zcode-user-1",
		"jwt":         map[string]any{"token": jwt, "status": status},
	}
	if accessToken != "" {
		zcode["oauth"] = map[string]any{
			"access_token": accessToken,
			"received_at":  time.Now().UTC().Format(time.RFC3339),
		}
	}
	raw, err := json.Marshal(map[string]any{"zcode": zcode})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
