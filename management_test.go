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
	// A login completed through the management plane reads the candidate
	// credential's Start Plan entitlement before storing it, so this fixture's
	// billing endpoint answers a live Start Plan by default; a test about a
	// particular reading sets its own body.
	f.billBody = startPlanBalanceBody
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
	return f.callSiteAction(t, action, authIndex, "")
}

// callSiteAction is callAction with an explicit site. oauth_retry requires one:
// the recovery has to know which site's account it is re-authorizing, so the
// tests that exercise it use this rather than the two-argument form.
func (f *managementFixture) callSiteAction(t *testing.T, action, authIndex, site string) (int, map[string]any) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"action": action, "auth_index": authIndex, "site": site})
	if err != nil {
		t.Fatal(err)
	}
	response := serveManagementHTTP(http.MethodPost, "/v0/management/zcode/action", nil, body)
	return decodeManagementResponse(t, response)
}

// callState serves the state route and decodes the JSON body.
func (f *managementFixture) callState(t *testing.T) map[string]any {
	t.Helper()
	response := serveManagementHTTP(http.MethodGet, "/v0/management/zcode/state", nil, nil)
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

	// The chooser is a second resource route and must carry no Menu: a Menu is
	// what produces a navigation entry, and a login step is not a page an
	// operator browses to — the host reaches it by opening the URL that
	// auth.login.start returned. An empty Menu is discarded by the host, which is
	// exactly right here.
	if len(response.Resources) != 2 {
		t.Fatalf("resources = %d, want the page shell and the login chooser: %+v", len(response.Resources), response.Resources)
	}
	shell := response.Resources[0]
	if strings.TrimSpace(shell.Menu) != managementResourceMenu {
		t.Errorf("resource Menu = %q, want %q", shell.Menu, managementResourceMenu)
	}
	chooser := response.Resources[1]
	if chooser.Path != loginChooserPath {
		t.Errorf("chooser resource path = %q, want %q", chooser.Path, loginChooserPath)
	}
	if strings.TrimSpace(chooser.Menu) != "" {
		t.Errorf("chooser Menu = %q, want empty so it yields no navigation entry", chooser.Menu)
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

// TestManagementPageAlignsEveryAccountCard guards the rendered shape rather
// than the source text. The page replaced the wide account table with one card
// per account; the equivalent structural failure is a credential builder whose
// return value is dropped — the card renders plausible but missing a whole
// section. The assertion is therefore that every builder's result is consumed
// by the fact-row mount (or the quota slot), not merely invoked.
//
// Since the card-face fold (#20): the fact rows are evidence and mount inside
// the collapsed readings block, so the mount assertions pin the same calls
// inside renderAccount regardless of which container they land in.
func TestManagementPageAlignsEveryAccountCard(t *testing.T) {
	page := managementPageHTML
	scriptStart := strings.Index(page, "<script>")
	scriptEnd := strings.LastIndex(page, "</script>")
	if scriptStart < 0 || scriptEnd < scriptStart {
		t.Fatal("page carries no script body")
	}
	script := page[scriptStart:scriptEnd]

	// Every credential builder hands its result to factRow, which appends the
	// term and the built node to the card's fact list. A builder invoked but
	// discarded would render a card silently missing that credential section,
	// so the full call shape is pinned, not just the name.
	for _, mount := range []string{
		`factRow(facts, "Start Plan", planCard(account.plan))`,
		`factRow(facts, "JWT(主凭证)", jwtCard(account.jwt))`,
		`factRow(facts, "API Key(回退)", apiKeyCard(account.api_key))`,
		`factRow(facts, "OAuth", oauthCard(account.oauth))`,
		`factRow(facts, "登录账号", loginCard(account.login))`,
	} {
		if !strings.Contains(script, mount) {
			t.Errorf("page does not mount a credential section via %q; the card loses that section", mount)
		}
	}
	for _, builder := range []string{"jwtCard", "apiKeyCard", "oauthCard", "quotaCard", "planCard", "loginCard"} {
		if !strings.Contains(script, "function "+builder+"(") {
			t.Errorf("page is missing the %s builder", builder)
		}
	}
	// The quota slot is mounted through appendChild; pinning the statement
	// keeps a refactor from re-invoking quotaCard and dropping its result.
	if !strings.Contains(script, "appendChild(quotaCard(account.quota))") {
		t.Error("quotaCard is not appended to the account card; the card loses the quota section")
	}
	// The quota evidence is a separate render, not a second quotaCard pass:
	// dropping its mount would empty the readings block of the per-bucket
	// reading lines while the card face still looks finished.
	if !strings.Contains(script, "quotaEvidence(account.quota)") {
		t.Error("quotaEvidence is not mounted into the readings block; the card loses the quota reading lines")
	}
	// appendStack must close by appending to the container and returning that
	// container: returning the inner stack would strand the verdict outside
	// the slot it belongs to.
	if !strings.Contains(script, "container.appendChild(stack);\n    return container;") {
		t.Error("appendStack must append the stack to the container and return the container, not the stack")
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

// TestManagementPageFoldsEvidenceBehindTheVerdicts pins the card-face fold
// (#20): an account card must answer "is anything wrong" at face height, with
// every reading line collapsed into one details block.
func TestManagementPageFoldsEvidenceBehindTheVerdicts(t *testing.T) {
	page := managementPageHTML
	scriptStart := strings.Index(page, "<script>")
	scriptEnd := strings.LastIndex(page, "</script>")
	if scriptStart < 0 || scriptEnd < scriptStart {
		t.Fatal("page carries no script body")
	}
	script := page[scriptStart:scriptEnd]

	// The readings block exists, names its contents, and holds both kinds of
	// evidence: the quota reading lines and the credential fact rows.
	for _, want := range []string{
		`el("details", "readings")`,
		"额度读数与凭证明细",
		"body.appendChild(evidence)",
		"body.appendChild(facts)",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("the page is missing the readings-block contract: %q", want)
		}
	}

	// Auto-open follows the verdicts, not nothing: a warn or bad verdict —
	// including the quota verdict, which has no chip — must open the block by
	// itself, so a troubled account is never hidden behind a fold the operator
	// does not know to look behind.
	if !strings.Contains(script, "severity === \"warn\" || severity === \"bad\"") {
		t.Error("the readings block must open by itself on a warn or bad verdict")
	}
	// The chip row carries the per-credential verdicts, so the face still says
	// which slot is troubled without opening anything.
	for _, want := range []string{`el("div", "chips")`, "chipNode("} {
		if !strings.Contains(script, want) {
			t.Errorf("the page is missing the chip-row contract: %q", want)
		}
	}

	// The operator's own toggle wins over the auto rule and survives a refresh:
	// the choice is recorded per account on summary click, replayed before the
	// auto rule runs, and dropped with the rest of the page state when the key
	// is forgotten.
	for _, want := range []string{
		"var readingsOpen = {};",
		"readingsOpen[key] = !details.open;",
		"if (pinned === true || pinned === false) {\n      details.open = pinned;",
		"readingsOpen = {};",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("the page is missing the operator-toggle contract: %q", want)
		}
	}
	// The toggle is read at click time, before the browser flips the open
	// attribute: keying on the toggle event instead would let the auto rule
	// pin itself as an operator choice.
	if !strings.Contains(script, `summary.addEventListener("click"`) {
		t.Error("the operator's toggle must be captured on the summary click, not on the toggle event")
	}

	// The quota verdict joins the auto-open check even though it has no chip:
	// a troubled bucket must open the readings on its own.
	if !strings.Contains(script, "quotaVerdict(account.quota)") ||
		!strings.Contains(script, "{ term: \"额度\", verdict: quotaVerdict(account.quota), chip: false }") {
		t.Error("the quota verdict must join the auto-open check with chip: false")
	}

	// The face keeps the actions and the summary, so the fold does not cost an
	// operator the controls.
	for _, want := range []string{`"refresh_credential"`, `"oauth_retry"`} {
		if !strings.Contains(script, want) {
			t.Errorf("the card face lost the action %q behind the fold", want)
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

// TestManagementPageDrawsTheRemainingBarFromTheComputedFraction pins the
// progress-bar contract added with the card layout (#20). The bar exists to
// make the share readable at a glance, so it must be drawn from the fraction
// the Go side already computed — a page that divides again can disagree with
// the host quota group about the same bucket. A bucket without a fraction gets
// no bar at all: an unread share is not a zero, and a bar at 0% or 100% would
// assert a measurement the plugin never received.
func TestManagementPageDrawsTheRemainingBarFromTheComputedFraction(t *testing.T) {
	page := managementPageHTML
	if !strings.Contains(page, "balance.remaining_fraction") {
		t.Error("the bar must be drawn from the remaining_fraction the plugin already computed")
	}
	// The width assignment is the one place the fraction becomes pixels; pin it
	// so the bar cannot regress to a page-side derivation.
	if !strings.Contains(page, "fraction * 100") {
		t.Error("the bar width must come from the precomputed fraction, scaled once")
	}
	if !strings.Contains(page, "fill.style.width = percent") {
		t.Error("the bar's width must be set from the fraction-derived percent")
	}
	if !strings.Contains(page, "if (fraction === null || fraction === undefined) { return null; }") {
		t.Error("a bucket without a readable fraction must render no bar rather than a guessed one")
	}
	// The thresholds read on the remaining side; a near-empty bar is the danger.
	for _, want := range []string{`" danger"`, `" warn"`} {
		if !strings.Contains(page, want) {
			t.Errorf("the bar is missing the %s severity class", want)
		}
	}
}

// TestManagementPageHasNoAutoRefresh pins the no-timer contract (#20). A
// periodic re-fetch blanks the page under a reading operator and replays a
// revoked key; every fetch must have an operator behind it. The snapshot cache
// is the replacement: it paints instantly on open and is revalidated once.
func TestManagementPageHasNoAutoRefresh(t *testing.T) {
	page := managementPageHTML
	for _, forbidden := range []string{"setInterval(", "setTimeout(loadState"} {
		if strings.Contains(page, forbidden) {
			t.Errorf("the page auto-refreshes through %q; every fetch must be operator-initiated", forbidden)
		}
	}
	// The manual entry points must exist so removing the timer did not remove
	// the ability to refresh at all.
	for _, want := range []string{`"reload-state"`, `"batch-refresh"`} {
		if !strings.Contains(page, want) {
			t.Errorf("the page is missing the %s manual refresh control", want)
		}
	}
	// The snapshot cache with its saved_at stamp: instant paint plus an honest
	// age label, so stale data is never mistaken for a fresh reading.
	for _, want := range []string{"zcode_state_cache", "saved_at", "已显示上次缓存的状态"} {
		if !strings.Contains(page, want) {
			t.Errorf("the page is missing the snapshot-cache contract: %q", want)
		}
	}
	// Cached paint is optimistic only: actions stay locked until a fresh
	// authenticated response revalidates the accounts.
	if !strings.Contains(page, "statusVerified") || !strings.Contains(page, "setCardButtonsDisabled(accountsBox, !statusVerified)") {
		t.Error("cached cards must disable actions until a fresh state response revalidates them")
	}
}

// TestManagementPageOffersAKeyResetEntry pins the key re-entry contract (#20).
// A saved key used to hide its own replacement behind a tiny secondary button;
// the collapsed panel must carry an explicit, worded re-entry control, and
// saving must immediately verify the key against the live state so a typo is
// caught by the 401 path instead of silently stored.
func TestManagementPageOffersAKeyResetEntry(t *testing.T) {
	page := managementPageHTML
	if !strings.Contains(page, "🔑 管理密钥已保存，点击可重新设定") {
		t.Error("the collapsed key panel must carry an explicit re-entry control with wording")
	}
	if !strings.Contains(page, `keyShow.addEventListener("click"`) {
		t.Error("the re-entry control must expand the key panel")
	}
	// The key never persists beyond localStorage, and the panel still collapses
	// through the same showKeyPanel path used on first save.
	if !strings.Contains(page, "showKeyPanel(true)") {
		t.Error("saving a key must collapse the panel through showKeyPanel")
	}
}

// TestManagementPageKeepsTheAuthorizeLinkOutOfTheStatusLine pins the reason the
// login buttons appeared to do nothing (#26), and the reason the link then
// became a modal: a one-line link under the status bar was missed by the very
// operators it was rendered for.
//
// The authorize link was appended into #message, and show() assigns textContent
// to that element. The refresh that follows every action writes a status line of
// its own, which destroyed the link microseconds after it was rendered — so the
// link was created, briefly present in the DOM, and never seen or clicked. The
// link must therefore live in a container show() never touches, and it must be
// reachable without depending on any one status line surviving.
func TestManagementPageKeepsTheAuthorizeLinkOutOfTheStatusLine(t *testing.T) {
	page := managementPageHTML
	// The slot is a sibling of the status line, not a child of it.
	if !strings.Contains(page, `<div id="authorize-slot"></div>`) {
		t.Error("the page must carry a dedicated authorize-slot container")
	}
	slotAt := strings.Index(page, `id="authorize-slot"`)
	messageAt := strings.Index(page, `id="message"`)
	if slotAt < 0 || messageAt < 0 {
		t.Fatal("the page must carry both the status line and the authorize slot")
	}
	if strings.Contains(page, `<div id="message" role="status" aria-live="polite"><div id="authorize-slot">`) {
		t.Error("the authorize slot must not be nested inside #message")
	}
	// The render must target the slot. Appending to message.appendChild is the
	// exact defect, so it is forbidden by name rather than by behaviour.
	if strings.Contains(page, "message.appendChild(") {
		t.Error("the authorize link must not be appended into #message; show() assigns textContent and wipes it")
	}
	if !strings.Contains(page, "authorizeSlot.replaceChildren(backdrop)") {
		t.Error("renderAuthorizeLink must render the modal into the authorize slot")
	}
	// show() must remain a plain text writer, and loadState must keep writing one:
	// the fix is the link's location, not a change to how statuses are shown.
	if !strings.Contains(page, "message.textContent = text_;") {
		t.Error("show() must keep assigning textContent; the slot is what keeps the link safe")
	}
	// A dismissed prompt must not come back on the next refresh, and a forgotten
	// key must take the prompt with it rather than leave it on screen.
	if !strings.Contains(page, "authorizeSlot.replaceChildren(); }") {
		t.Error("dismissing the prompt must clear the slot")
	}
	if !strings.Contains(page, "forgetKey") || !strings.Contains(page, "authorizeSlot.replaceChildren();\n    renderEmpty();") {
		t.Error("forgetKey must clear the authorize slot along with the rest of the page")
	}
	// The prompt is the whole point of pressing a login button: it must be
	// unmissable (a modal dialog), show the full URL as text an operator on a
	// remote host can carry to another browser, offer both an open button and a
	// copy action, and survive every status line the page can write.
	for _, want := range []string{
		`modal.setAttribute("role", "dialog")`,
		`modal.setAttribute("aria-modal", "true")`,
		"text(urlBox, url);",
		"打开授权页面",
		"复制链接",
		"navigator.clipboard.writeText(url)",
		"session.authorize_url",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page is missing the authorize-modal contract: %q", want)
		}
	}
}

// TestManagementPageOffersCancellingAPendingLogin pins the cancel affordance:
// an authorization abandoned on purpose must be stoppable now, not at its TTL.
// The modal carries the button when the action reply names its session, the
// sessions table carries one for every pending row, and both go through one
// cancelSession helper that posts oauth_cancel and refreshes the state.
func TestManagementPageOffersCancellingAPendingLogin(t *testing.T) {
	page := managementPageHTML
	for _, want := range []string{
		"function cancelSession(",
		`action: "oauth_cancel"`,
		"session_id: sessionID",
		"取消本次授权",            // the modal's button label
		"session.session_id", // the modal button binds to the action reply's handle
		"取消等待",               // the sessions-table button label
		"session.cancellable", // only pending rows offer the button
		"已取消",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page is missing the cancel contract: %q", want)
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
		// A record that has been through the login preflight and a quota refresh:
		// the plan section names the products and the per-model allowance, and the
		// login section carries a digest of the account id. Neither may carry the
		// raw identifiers they were derived from.
		zcode["plan"] = map[string]any{
			"readable":       true,
			"checked_at":     "2026-01-02T00:00:00Z",
			"plan_ids":       []any{"zcode-v3-start-plan-0817"},
			"plan_instances": []any{"zcode-v3-start-plan-0817#0123456789ab"},
			"last_priority":  true,
			"models": map[string]any{
				"GLM-5.3-Flash": map[string]any{"allowance": "empty", "reset_at": "2026-01-03T00:00:00Z", "buckets": json.Number("1")},
			},
		}
		zcode["login"] = map[string]any{"user_id_hash": "7a917e45efea", "checked_at": "2026-01-02T00:00:00Z"}
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
	if account["auth_index"] != "auth-redacted" {
		t.Fatalf("account identity fields = %+v", account)
	}
	// The identity is rendered only as the shared digest: the raw value must not
	// survive into management data, and the digest must be the same one the
	// diagnostic lines show.
	if account["identity_hash"] != identityDiag("zcode-redacted-user") {
		t.Fatalf("identity_hash = %v, want the shared account digest", account["identity_hash"])
	}
	if _, raw := account["identity_id"]; raw {
		t.Fatalf("account view carries a raw identity_id: %+v", account)
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
	// The plan section is what tells an exhausted plan apart from a wrong-account
	// login, so it must reach the page intact.
	planView := account["plan"].(map[string]any)
	ids := planView["plan_ids"].([]any)
	if len(ids) != 1 || ids[0] != "zcode-v3-start-plan-0817" {
		t.Fatalf("plan ids = %+v", ids)
	}
	if planView["last_priority"] != true || planView["readable"] != true {
		t.Fatalf("plan view = %+v", planView)
	}
	flash := planView["models"].(map[string]any)["GLM-5.3-Flash"].(map[string]any)
	if flash["allowance"] != "empty" || flash["reset_at"] != "2026-01-03T00:00:00Z" {
		t.Fatalf("model allowance view = %+v", flash)
	}
	loginView := account["login"].(map[string]any)
	if loginView["user_id_hash"] != "7a917e45efea" {
		t.Fatalf("login view = %+v", loginView)
	}
}

// A record that has never been read carries no plan section at all, which the page
// renders as "not read" rather than as an account with no plan.
func TestManagementStateOmitsPlanForAnUnreadRecord(t *testing.T) {
	fixture := newManagementFixture(t)
	fixture.accountDoc(t, "auth-plain", "zcode-plain-user", "active", "key-material")
	state := fixture.callState(t)
	accounts := state["accounts"].([]any)
	account := accounts[0].(map[string]any)
	if _, present := account["plan"]; present {
		t.Fatalf("plan view = %+v, want absent for a record with no snapshot", account["plan"])
	}
	if _, present := account["login"]; present {
		t.Fatalf("login view = %+v, want absent for a record with no login section", account["login"])
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
			response := serveManagementHTTP(http.MethodPost, "/v0/management/zcode/action", nil, []byte(tc.body))
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
	response := serveManagementHTTP(http.MethodPost, "/v0/management/zcode/action", nil, []byte("{not json"))
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

	status, data := fixture.callSiteAction(t, actionOAuthRetry, "auth-retry", siteZai)
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
	status, data := fixture.callSiteAction(t, actionOAuthRetry, "auth-retry2", siteZai)
	if status != http.StatusBadGateway {
		t.Fatalf("status = %d body %v, want 502", status, data)
	}
	if data["error"].(map[string]any)["code"] != "oauth_upstream_failed" {
		t.Fatalf("error = %v, want oauth_upstream_failed", data["error"])
	}
}

// callSessionAction is callAction with an explicit session_id; it is how the
// tests speak to oauth_cancel, which names a session rather than an account.
func (f *managementFixture) callSessionAction(t *testing.T, action, sessionID string) (int, map[string]any) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"action": action, "auth_index": "", "site": "", "session_id": sessionID})
	if err != nil {
		t.Fatal(err)
	}
	response := serveManagementHTTP(http.MethodPost, "/v0/management/zcode/action", nil, body)
	return decodeManagementResponse(t, response)
}

// TestOAuthCancelStopsPendingSession pins the operator's way out of an
// abandoned login: the started session turns terminal "cancelled" immediately
// instead of sitting out its TTL, the state view reflects it, and a second
// cancel finds nothing left to stop.
func TestOAuthCancelStopsPendingSession(t *testing.T) {
	oauth := newUpstreamFixture(t)
	fixture := newManagementFixtureOver(t, oauth)
	fixture.accountDoc(t, "auth-cancel", "zcode-cancel-user", "invalid", "key-old")

	// The poll stays pending forever: without a cancel, this session would sit
	// out its whole TTL while the plugin polls every interval.
	oauth.queuePoll(http.StatusOK, `{"data":{"status":"pending"}}`)

	status, data := fixture.callSiteAction(t, actionOAuthRetry, "auth-cancel", siteZai)
	if status != http.StatusOK {
		t.Fatalf("status = %d body %v, want 200", status, data)
	}
	session := data["session"].(map[string]any)
	sessionID, ok := session["session_id"].(string)
	if !ok || sessionID == "" {
		t.Fatalf("action reply session = %v, want a session_id", session)
	}

	// The pending session appears in the state view as cancellable, and the
	// session id is the only handle the page needs.
	state := fixture.callState(t)
	var pending map[string]any
	for _, raw := range state["sessions"].([]any) {
		entry := raw.(map[string]any)
		if entry["id"] == sessionID {
			pending = entry
		}
	}
	if pending == nil {
		t.Fatal("the started session is missing from the state view")
	}
	if pending["state"] != string(authSessionPending) || pending["cancellable"] != true {
		t.Fatalf("pending session view = %v, want pending+cancellable", pending)
	}

	// The cancel itself.
	status, data = fixture.callSessionAction(t, actionOAuthCancel, sessionID)
	if status != http.StatusOK {
		t.Fatalf("cancel status = %d body %v, want 200", status, data)
	}
	cancelled := data["cancelled"].(map[string]any)
	if cancelled["session_id"] != sessionID || cancelled["state"] != string(authSessionCancelled) {
		t.Fatalf("cancel reply = %v", cancelled)
	}

	// The state view now reads cancelled and nothing is cancellable.
	state = fixture.callState(t)
	rendered, err := json.Marshal(state["sessions"])
	if err != nil {
		t.Fatal(err)
	}
	sessionsJSON := string(rendered)
	if strings.Contains(sessionsJSON, `"cancellable"`) {
		t.Errorf("no session may remain cancellable after the cancel: %s", sessionsJSON)
	}
	if !strings.Contains(sessionsJSON, string(authSessionCancelled)) {
		t.Fatalf("sessions = %s, want a cancelled entry", sessionsJSON)
	}

	// A second cancel finds an already-terminal session and says so.
	status, data = fixture.callSessionAction(t, actionOAuthCancel, sessionID)
	if status != http.StatusNotFound {
		t.Fatalf("second cancel status = %d body %v, want 404", status, data)
	}
	if data["error"].(map[string]any)["code"] != "unknown_session" {
		t.Fatalf("second cancel error = %v, want unknown_session", data["error"])
	}

	// oauth_cancel names a session, not an account: an auth_index is refused
	// before anything is looked up.
	status, data = fixture.callSessionActionWithIndex(t, actionOAuthCancel, sessionID, "auth-cancel")
	if status != http.StatusBadRequest {
		t.Fatalf("cancel with auth_index status = %d, want 400", status)
	}
	_ = data
}

// callSessionActionWithIndex is callSessionAction with an auth_index injected,
// for asserting the cancel route's refusal of account-granular spellings.
func (f *managementFixture) callSessionActionWithIndex(t *testing.T, action, sessionID, authIndex string) (int, map[string]any) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"action": action, "auth_index": authIndex, "site": "", "session_id": sessionID})
	if err != nil {
		t.Fatal(err)
	}
	response := serveManagementHTTP(http.MethodPost, "/v0/management/zcode/action", nil, body)
	return decodeManagementResponse(t, response)
}

// TestOAuthCancelRequiresSessionID pins the shape error: a cancel without a
// session id names nothing and must be refused before any lookup.
func TestOAuthCancelRequiresSessionID(t *testing.T) {
	fixture := newManagementFixture(t)
	status, data := fixture.callSessionAction(t, actionOAuthCancel, "")
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d body %v, want 400", status, data)
	}
	if data["error"].(map[string]any)["code"] != "invalid_request" {
		t.Fatalf("error = %v, want invalid_request", data["error"])
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

// TestQuotaViewForGroupsBucketsByPlanAxis covers the management plane's read of
// one quota refresh: the buckets carry the axis they belong to, and the page
// receives the groups in the order the upstream listed their buckets.
//
// The distinction it exists to protect is the one an operator cannot see in a
// flat list: a Start Plan allowance and a general Coding Plan allowance are
// different billing axes, and reporting both as "GLM 18% left" would leave no
// way to tell which one to act on.
func TestQuotaViewForGroupsBucketsByPlanAxis(t *testing.T) {
	now := time.Now()
	plans := []quotaPlan{
		{
			Name:       "ZCode V3 Start Plan",
			PlanID:     "zcode-v3-start-plan-trust-1003",
			UserPlanID: "upl_1",
			Status:     planStatusActive,
		},
		{Name: "GLM Coding Plan", PlanID: "zcode-v3-coding-plan", Status: planStatusActive},
	}
	observation := observationFor(quotaEvidence{
		Verdict: verdictAvailable,
		Plans:   plans,
		Plan:    "ZCode V3 Start Plan",
		Balances: []quotaBalance{
			{Name: "GLM Coding", PlanID: "zcode-v3-coding-plan", Total: float64Ptr(100), Remaining: float64Ptr(20)},
			{Name: "GLM-5.3-Flash", PlanID: "zcode-v3-start-plan-trust-1003", UserPlanID: "upl_1", Total: float64Ptr(200), Remaining: float64Ptr(150)},
		},
	}, now)

	view := quotaViewFor(observation)
	if len(view.PlanGroups) != 2 {
		t.Fatalf("plan groups = %d, want 2; two billing axes must not render as one", len(view.PlanGroups))
	}
	if view.PlanGroups[0].Label != "GLM Coding Plan" || view.PlanGroups[0].Kind != planGroupCodingPlan {
		t.Fatalf("first group = %+v; the upstream listed a coding-plan bucket first", view.PlanGroups[0])
	}
	if view.PlanGroups[1].Label != "ZCode V3 Start Plan" || view.PlanGroups[1].Kind != planGroupStartPlan {
		t.Fatalf("second group = %+v, want the Start Plan axis", view.PlanGroups[1])
	}
	// Each bucket points at the axis it belongs to by position, so a renderer
	// can group without re-deriving ownership from the plan list — and without
	// merging two plans that happen to share a display name.
	byName := map[string]quotaBalanceView{}
	for _, bucket := range view.Balances {
		byName[bucket.Name] = bucket
	}
	coding, startPlan := byName["GLM Coding"], byName["GLM-5.3-Flash"]
	if coding.GroupIndex == nil || *coding.GroupIndex != 0 {
		t.Fatalf("coding bucket group index = %v, want 0", coding.GroupIndex)
	}
	if startPlan.GroupIndex == nil || *startPlan.GroupIndex != 1 {
		t.Fatalf("start plan bucket group index = %v, want 1", startPlan.GroupIndex)
	}
	// The remaining share is still the one reading both surfaces render, and
	// grouping must not have moved it.
	if coding.RemainingFraction == nil || *coding.RemainingFraction != 0.2 {
		t.Fatalf("coding fraction = %v, want 0.2", coding.RemainingFraction)
	}
	if startPlan.RemainingFraction == nil || *startPlan.RemainingFraction != 0.75 {
		t.Fatalf("start plan fraction = %v, want 0.75", startPlan.RemainingFraction)
	}
}

// TestQuotaViewForLeavesOrphanBucketsUnassigned covers the bucket no plan
// claims. It still renders — the numbers are real — but under its own axis
// label, never under a plan the upstream did not name as its owner.
func TestQuotaViewForLeavesOrphanBucketsUnassigned(t *testing.T) {
	observation := observationFor(quotaEvidence{
		Verdict: verdictAvailable,
		Plans:   []quotaPlan{{Name: "GLM Coding Plan", PlanID: "zcode-v3-coding-plan", Status: planStatusActive}},
		Balances: []quotaBalance{
			{Name: "GLM Coding", PlanID: "zcode-v3-coding-plan", Total: float64Ptr(100), Remaining: float64Ptr(50)},
			{Name: "GLM-5.3-Flash", PlanID: "zcode-v3-start-plan-trust-1003", Total: float64Ptr(200), Remaining: float64Ptr(150)},
		},
	}, time.Now())

	view := quotaViewFor(observation)
	if len(view.PlanGroups) != 2 {
		t.Fatalf("plan groups = %d, want the coding group plus one orphan group", len(view.PlanGroups))
	}
	if view.PlanGroups[1].Kind != planGroupUnassigned {
		t.Fatalf("orphan group kind = %q, want %q", view.PlanGroups[1].Kind, planGroupUnassigned)
	}
	if view.PlanGroups[1].Label != "zcode-v3-start-plan-trust-1003" {
		t.Fatalf("orphan group label = %q, want the key the bucket itself stated", view.PlanGroups[1].Label)
	}
	if view.Balances[1].GroupIndex == nil || *view.Balances[1].GroupIndex != 1 {
		t.Fatalf("orphan bucket group index = %v, want the orphan group", view.Balances[1].GroupIndex)
	}
}

// TestManagementPageSeparatesQuotaByPlanAxis pins the page's read of the two
// billing axes. A Start Plan allowance and a general Coding Plan allowance are
// different things to act on, and rendering them as one flat run of buckets
// leaves "GLM 18% left" with no way to tell which plan is about to run out —
// the exact confusion the grouping on the Go side removes.
//
// The page must therefore read the group labels the plugin already resolved
// and must not re-derive ownership from the buckets themselves: that match is
// where the instance id versus the product id distinction lives, and a second
// implementation of it in the page could disagree with the host's.
func TestManagementPageSeparatesQuotaByPlanAxis(t *testing.T) {
	page := managementPageHTML
	if !strings.Contains(page, "plan_groups") {
		t.Error("the page must render the plan groups the plugin resolved")
	}
	// The buckets join their axis by the index the plugin resolved, not by its
	// label: two plans may share a display name, and a label join would merge two
	// separate allowances into one heading.
	if !strings.Contains(page, "balance.group_index === index") {
		t.Error("the page must place each bucket under its axis by the index the plugin resolved")
	}
	if strings.Contains(page, "balance.plan") {
		t.Error("the page must not rejoin buckets to axes by label; labels are not unique")
	}
	// The three kinds must each render a distinct heading. An operator reading
	// "unassigned" against "Start Plan" is being told something actionable;
	// collapsing both into one heading would discard that.
	for _, kind := range []string{planGroupStartPlan, planGroupCodingPlan, planGroupUnassigned} {
		if !strings.Contains(page, kind) {
			t.Errorf("the page has no reading for the %q axis", kind)
		}
	}
	// The Start Plan allowance and the general allowance are the whole point,
	// so their two headings must both be present and must not be the same
	// string.
	if !strings.Contains(page, "Start Plan 额度") {
		t.Error("the page must name the Start Plan axis distinctly from the general one")
	}
	if !strings.Contains(page, "通用额度") {
		t.Error("the page must name the general Coding Plan axis")
	}
}
