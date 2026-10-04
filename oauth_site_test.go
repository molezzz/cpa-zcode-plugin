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
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// The two sites serve one CLI OAuth protocol and differ only in the provider
// selector, so nothing in the flow itself can tell them apart. These tests drive
// a whole login through the host protocol for each site and assert the three
// things that must follow the selector: which access token the plugin kept, which
// origin it spent the managed key against, and what it recorded on the document.

// TestNativeLoginUsesConfiguredDefaultSite proves the host's native entry, which
// carries no site of its own, follows the configured default. The default is the
// only way an operator whose account is on the other site can reach it from the
// host's own login UI.
func TestNativeLoginUsesConfiguredDefaultSite(t *testing.T) {
	cases := []struct {
		site     string
		wantBody string
	}{
		{site: siteBigmodel, wantBody: `"provider":"bigmodel"`},
		{site: siteZai, wantBody: `"provider":"zai"`},
	}
	for _, tc := range cases {
		t.Run(tc.site, func(t *testing.T) {
			fixture := newUpstreamFixture(t)
			withOAuthConfig(t, func(cfg *Config) { cfg.OAuth.DefaultSite = tc.site })

			fixture.startLogin(t)

			if len(fixture.initBodies) != 1 {
				t.Fatalf("init calls = %d, want one", len(fixture.initBodies))
			}
			if !strings.Contains(fixture.initBodies[0], tc.wantBody) {
				t.Errorf("init body = %q, want it to select %s", fixture.initBodies[0], tc.wantBody)
			}
		})
	}
}

// A site this build does not know must stop the login at the native entry, not
// fall back to the first one. Falling back would send the operator to the wrong
// site's login page, and the only symptom would be an account they did not mean
// to authorize.
func TestNativeLoginRefusesUnknownConfiguredSite(t *testing.T) {
	newUpstreamFixture(t)
	withOAuthConfig(t, func(cfg *Config) { cfg.OAuth.DefaultSite = "big-model" })

	env := callMethod(t, pluginabi.MethodAuthLoginStart, []byte(`{"Provider":"zcode"}`))
	if env.OK {
		t.Fatal("a login started with an unknown default site")
	}
	if env.Error == nil || env.Error.Code != "invalid_config" {
		t.Errorf("error = %+v, want it to name the invalid configuration", env.Error)
	}
}

// TestLoginKeepsItsOwnSitesAccessToken is the core of the split: the same ready
// payload carries both providers' tokens, and each site must keep only its own.
// Reading the wrong one produces a credential that looks complete and fails
// every upstream call with no indication of which site was wrong.
func TestLoginKeepsItsOwnSitesAccessToken(t *testing.T) {
	cases := []struct {
		site       string
		wantToken  string
		rejectMark string
	}{
		{site: siteZai, wantToken: "zai-access-token-1", rejectMark: "bigmodel-access-token-1"},
		{site: siteBigmodel, wantToken: "bigmodel-access-token-1", rejectMark: "zai-access-token-1"},
	}
	for _, tc := range cases {
		t.Run(tc.site, func(t *testing.T) {
			fixture := newUpstreamFixture(t)
			withOAuthConfig(t, func(cfg *Config) { cfg.OAuth.DefaultSite = tc.site })
			token := makeJWT(t, map[string]any{"sub": "user-" + tc.site})
			fixture.queuePollReady(token)

			start := fixture.startLogin(t)
			env := pollLogin(t, start.State)
			if !env.OK {
				t.Fatalf("poll failed: %+v", env.Error)
			}
			response := decodePoll(t, env)
			if response.Status != pluginapi.AuthLoginStatusSuccess {
				t.Fatalf("status = %q (%s), want success", response.Status, response.Message)
			}
			stored := oauthAccessTokenOf(t, response.Auth.StorageJSON)
			if stored != tc.wantToken {
				t.Errorf("stored access token = %q, want %q", stored, tc.wantToken)
			}
			if stored == tc.rejectMark {
				t.Errorf("the login kept the other site's token %q", stored)
			}
		})
	}
}

// The document records the site it was authorized against, and the host's label
// says so too: with an account per site, the account list is the only place a
// user can tell which record is which before opening either one.
func TestLoginRecordsItsSiteOnTheDocument(t *testing.T) {
	cases := []struct {
		site      string
		wantLabel string
	}{
		{site: siteZai, wantLabel: "ZCode (Z.AI)"},
		{site: siteBigmodel, wantLabel: "ZCode (BigModel)"},
	}
	for _, tc := range cases {
		t.Run(tc.site, func(t *testing.T) {
			fixture := newUpstreamFixture(t)
			withOAuthConfig(t, func(cfg *Config) { cfg.OAuth.DefaultSite = tc.site })
			fixture.queuePollReady(makeJWT(t, map[string]any{"sub": "user-" + tc.site}))

			start := fixture.startLogin(t)
			env := pollLogin(t, start.State)
			if !env.OK {
				t.Fatalf("poll failed: %+v", env.Error)
			}
			response := decodePoll(t, env)
			if got := recordedSiteOf(t, response.Auth.StorageJSON); got != tc.site {
				t.Errorf("recorded site = %q, want %q", got, tc.site)
			}
			if response.Auth.Label != tc.wantLabel {
				t.Errorf("label = %q, want %q", response.Auth.Label, tc.wantLabel)
			}
		})
	}
}

// A domestic login must not spend its managed key against the international
// origin. The two sites run the same paths on different hosts, so a wrong base
// produces the same 401 a stale credential would — the failure would look like
// the account needs re-authorizing rather than like a site mix-up.
func TestManagedKeyExchangeRunsAgainstTheLoggedInSitesOrigin(t *testing.T) {
	fixture := newUpstreamFixture(t)
	bigmodelCalls := &countingHandler{}
	bigmodelSrv := newCountingServer(t, bigmodelCalls)
	originalZai, originalBigmodel := zaiAPIBase, bigmodelAPIBase
	zaiAPIBase = fixture.keys.srv.URL
	bigmodelAPIBase = bigmodelSrv
	t.Cleanup(func() { zaiAPIBase, bigmodelAPIBase = originalZai, originalBigmodel })

	withOAuthConfig(t, func(cfg *Config) { cfg.OAuth.DefaultSite = siteBigmodel })
	fixture.queuePollReady(makeJWT(t, map[string]any{"sub": "user-bm"}))

	start := fixture.startLogin(t)
	env := pollLogin(t, start.State)
	if !env.OK {
		t.Fatalf("poll failed: %+v", env.Error)
	}
	response := decodePoll(t, env)
	if response.Status != pluginapi.AuthLoginStatusSuccess {
		t.Fatalf("status = %q (%s), want success", response.Status, response.Message)
	}
	if _, _, create, _ := fixture.keys.counts(); create != 0 {
		t.Errorf("the international origin served %d key creations; a domestic login must not spend there", create)
	}

	// The key has to actually exist. Counting requests would pass on a chain that
	// ran and then failed, and a failed key stage is recorded as diagnosable
	// state on a login that otherwise looks perfect.
	keyDoc, ok := readAPIKeySection(response.Auth.StorageJSON)
	if !ok {
		t.Fatalf("no api_key section was written: %s", response.Auth.StorageJSON)
	}
	state := typedAPIKeyState(keyDoc)
	if state.Status != apiKeyStatusActive {
		t.Fatalf("api_key status = %q (%+v), want active", state.Status, state.LastError)
	}
	if state.KeyMaterial != "key-1.secret-1" {
		t.Errorf("key material = %q, want the domestic origin's key", state.KeyMaterial)
	}
	for _, path := range bigmodelCalls.servedPaths() {
		if strings.Contains(path, "/api/auth/z/login") {
			t.Errorf("the domestic origin was asked for a business-token exchange (%s); it serves none", path)
		}
	}
}

// A domestic login issues its key from an access token it already holds. The
// exchange step is not a formality there: the domestic business endpoints accept
// the access token directly, so a login that spent one would report a failure on
// a credential that works.
func TestDomesticLoginDoesNotSpendASecondExchange(t *testing.T) {
	fixture := newUpstreamFixture(t)
	withOAuthConfig(t, func(cfg *Config) { cfg.OAuth.DefaultSite = siteBigmodel })
	fixture.queuePollReady(makeJWT(t, map[string]any{"sub": "user-bm"}))

	start := fixture.startLogin(t)
	env := pollLogin(t, start.State)
	if !env.OK {
		t.Fatalf("poll failed: %+v", env.Error)
	}
	response := decodePoll(t, env)
	if response.Status != pluginapi.AuthLoginStatusSuccess {
		t.Fatalf("status = %q (%s), want success", response.Status, response.Message)
	}
	if login, _, _, _ := fixture.keys.counts(); login != 0 {
		t.Errorf("business-token exchanges = %d, want none for a site that issues the token directly", login)
	}
}

// ...and the international login still does, because its business endpoints
// refuse the OAuth token outright.
func TestInternationalLoginStillExchanges(t *testing.T) {
	fixture := newUpstreamFixture(t)
	withOAuthConfig(t, func(cfg *Config) { cfg.OAuth.DefaultSite = siteZai })
	fixture.queuePollReady(makeJWT(t, map[string]any{"sub": "user-zai"}))

	start := fixture.startLogin(t)
	env := pollLogin(t, start.State)
	if !env.OK {
		t.Fatalf("poll failed: %+v", env.Error)
	}
	if login, _, _, _ := fixture.keys.counts(); login == 0 {
		t.Error("the international login skipped the business-token exchange its endpoints require")
	}
}

// A re-authorization carries the caller's explicit site, so an operator with
// accounts on both can replace one without changing what the other defaults to.
func TestManagementReauthorizationTakesAnExplicitSite(t *testing.T) {
	// The retry starts a real upstream session, so the fixture has to own one.
	fixture := newManagementFixtureOver(t, newUpstreamFixture(t))
	fixture.accountDoc(t, "auth-retry", "zcode-retry-user", "invalid", "key-old")

	status, data := fixture.callSiteAction(t, actionOAuthRetry, "auth-retry", siteBigmodel)
	if status != 200 {
		t.Fatalf("status = %d (%v), want the session to start", status, data)
	}
	if got, _ := data["site"].(string); got != siteBigmodel {
		t.Errorf("reported site = %q, want %q", got, siteBigmodel)
	}
	session, _ := data["session"].(map[string]any)
	url, _ := session["authorize_url"].(string)
	if url == "" {
		t.Fatal("no authorize URL was returned; the operator cannot finish the login")
	}
	// The init body is the record of which site was actually selected.
	bodies := fixture.oauth.initBodies
	if len(bodies) == 0 || !strings.Contains(bodies[len(bodies)-1], `"provider":"bigmodel"`) {
		t.Errorf("init bodies = %v, want the retry to select bigmodel", bodies)
	}
}

// Without a site the action cannot know which account it is recovering, so it is
// refused. Defaulting it would be the one failure mode this whole change exists
// to prevent: a recovery that silently replaced a domestic credential with an
// international login.
func TestManagementReauthorizationRefusesAMissingOrUnknownSite(t *testing.T) {
	for _, site := range []string{"", "bigmodel.cn", "ZAI"} {
		fixture := newManagementFixtureOver(t, newUpstreamFixture(t))
		fixture.accountDoc(t, "auth-retry", "zcode-retry-user", "invalid", "key-old")
		status, data := fixture.callSiteAction(t, actionOAuthRetry, "auth-retry", site)
		if status == 200 {
			t.Fatalf("site %q was accepted; a re-authorization must name a known site", site)
		}
		if !strings.Contains(string(mustMarshal(t, data)), "unknown_site") {
			t.Errorf("site %q error = %v, want it to name the unknown site", site, data)
		}
		// Nothing may be started: the operator would only learn the site was
		// wrong after authorizing in a browser.
		if bodies := fixture.oauth.initBodies; len(bodies) != 0 {
			t.Errorf("site %q started %d upstream sessions; a refused site must start none", site, len(bodies))
		}
	}
}

// Both of one operator's accounts coexist as separate records, each keeping its
// own site: the site is what makes the second login a new account rather than an
// overwrite of the first.
func TestTwoSitesCoexistAsSeparateCredentials(t *testing.T) {
	zaiFixture := newUpstreamFixture(t)
	withOAuthConfig(t, func(cfg *Config) { cfg.OAuth.DefaultSite = siteZai })
	zaiFixture.queuePollReady(makeJWT(t, map[string]any{"sub": "intl-user"}))
	start := zaiFixture.startLogin(t)
	env := pollLogin(t, start.State)
	if !env.OK {
		t.Fatalf("zai poll failed: %+v", env.Error)
	}
	zaiAuth := decodePoll(t, env).Auth

	bmFixture := newUpstreamFixture(t)
	withOAuthConfig(t, func(cfg *Config) { cfg.OAuth.DefaultSite = siteBigmodel })
	bmFixture.queuePollReady(makeJWT(t, map[string]any{"sub": "12345678901234567"}))
	start = bmFixture.startLogin(t)
	env = pollLogin(t, start.State)
	if !env.OK {
		t.Fatalf("bigmodel poll failed: %+v", env.Error)
	}
	bmAuth := decodePoll(t, env).Auth

	if zaiAuth.ID == bmAuth.ID {
		t.Errorf("both logins produced identity %q; the two accounts must stay separate", zaiAuth.ID)
	}
	if zaiAuth.FileName == bmAuth.FileName {
		t.Errorf("both logins landed in %q; a second site must not overwrite the first account's file", zaiAuth.FileName)
	}
	// The domestic account's numeric subject and the international account's are
	// both preserved verbatim as identities: neither is hashed away, because the
	// upstream's own account id is the only stable handle for it.
	if got := recordedSiteOf(t, zaiAuth.StorageJSON); got != siteZai {
		t.Errorf("international record site = %q, want %q", got, siteZai)
	}
	if got := recordedSiteOf(t, bmAuth.StorageJSON); got != siteBigmodel {
		t.Errorf("domestic record site = %q, want %q", got, siteBigmodel)
	}
	if !strings.HasPrefix(bmAuth.ID, "zcode-12345678901234567") {
		t.Errorf("domestic identity = %q, want the upstream's numeric account id preserved", bmAuth.ID)
	}
}

// A refresh must not let the site drift. The state writer is the path every
// request's conclusion takes, so it is where a record written before the site
// was stored would otherwise be left reading as the international one forever.
func TestStateWriteMaterializesTheSiteOnALegacyRecord(t *testing.T) {
	legacy := []byte(`{"zcode":{"identity_id":"zcode-1","jwt":{"token":"t","status":"active"}}}`)
	patched, changed, err := applyCredentialState(legacy, []recordedState{{
		Kind: CredentialJWT, Status: jwtStatusExhausted, Code: "quota_exhausted",
	}}, time.Now())
	if err != nil {
		t.Fatalf("applyCredentialState: %v", err)
	}
	if !changed {
		t.Fatal("nothing was written; the exhaustion conclusion was dropped")
	}
	if got := recordedSiteOf(t, patched); got != siteZai {
		t.Errorf("site = %q, want the implied default %q materialized", got, siteZai)
	}
}

// The migration is the only write this path makes that no conclusion asked for,
// so it must happen on its own — even when every conclusion already matches what
// the record says. Otherwise a legacy credential that never fails and never
// refreshes a conclusion stays without a site forever.
func TestStateWriteMigratesALegacyRecordWithNoNewConclusions(t *testing.T) {
	legacy := []byte(`{"zcode":{"identity_id":"zcode-1","jwt":{"token":"t","status":"active"}}}`)
	active := []recordedState{{Kind: CredentialJWT, Status: jwtStatusActive, Code: ""}}

	patched, changed, err := applyCredentialState(legacy, active, time.Now())
	if err != nil {
		t.Fatalf("applyCredentialState: %v", err)
	}
	if !changed {
		t.Fatal("an already-active legacy record was left without a site")
	}
	if got := recordedSiteOf(t, patched); got != siteZai {
		t.Errorf("site = %q, want %q", got, siteZai)
	}
}

// A record that already names its site keeps it through a refresh — the refresh
// must re-pin the account's own site, not overwrite it with the default.
func TestStateWriteKeepsAnExplicitSite(t *testing.T) {
	doc := []byte(`{"zcode":{"identity_id":"zcode-1","site":"bigmodel","jwt":{"token":"t","status":"active"}}}`)
	patched, _, err := applyCredentialState(doc, []recordedState{{
		Kind: CredentialJWT, Status: jwtStatusExhausted, Code: "quota_exhausted",
	}}, time.Now())
	if err != nil {
		t.Fatalf("applyCredentialState: %v", err)
	}
	if got := recordedSiteOf(t, patched); got != siteBigmodel {
		t.Errorf("site = %q, want the record's own %q preserved", got, siteBigmodel)
	}
}

// A steady stream of conclusions must not churn the host auth file once per
// request. Re-pinning is part of that write path, so a document that already
// carries its site must still come out byte-identical.
func TestStateWriteIsByteStableOnceTheSiteIsStored(t *testing.T) {
	doc := []byte(`{"zcode":{"identity_id":"zcode-1","site":"bigmodel","jwt":{"token":"t","status":"active"}}}`)
	first, _, err := applyCredentialState(doc, []recordedState{{
		Kind: CredentialJWT, Status: jwtStatusExhausted, Code: "quota_exhausted",
	}}, time.Now())
	if err != nil {
		t.Fatalf("applyCredentialState: %v", err)
	}
	second, changed, err := applyCredentialState(first, []recordedState{{
		Kind: CredentialJWT, Status: jwtStatusExhausted, Code: "quota_exhausted",
	}}, time.Now())
	if err != nil {
		t.Fatalf("applyCredentialState second pass: %v", err)
	}
	if changed {
		t.Error("repeating an already-recorded conclusion rewrote the document")
	}
	if string(second) != string(first) {
		t.Error("the second write was not byte-identical; the host auth file churns per request")
	}
}

// A fresh login adds an account the store does not have yet, which is how a user
// holding accounts on both sites gets the second one. It differs from a
// re-authorization only in that no record is named.
func TestManagementLoginAddsAnAccountForTheChosenSite(t *testing.T) {
	fixture := newManagementFixtureOver(t, newUpstreamFixture(t))
	status, data := fixture.callSiteAction(t, actionOAuthLogin, "", siteBigmodel)
	if status != 200 {
		t.Fatalf("status = %d (%v), want the login session to start", status, data)
	}
	if got, _ := data["site"].(string); got != siteBigmodel {
		t.Errorf("reported site = %q, want %q", got, siteBigmodel)
	}
	bodies := fixture.oauth.initBodies
	if len(bodies) == 0 || !strings.Contains(bodies[len(bodies)-1], `"provider":"bigmodel"`) {
		t.Errorf("init bodies = %v, want the login to select bigmodel", bodies)
	}
	// The action names no account: it is not recovering one.
	if _, present := data["auth_index"]; present {
		t.Errorf("reply named an auth_index %v; a new login must not claim one", data["auth_index"])
	}
}

// The login entry refuses an unknown site for the same reason the retry does, and
// before it starts anything.
func TestManagementLoginRefusesAnUnknownSite(t *testing.T) {
	for _, site := range []string{"", "bigmodel.cn", "openai"} {
		fixture := newManagementFixtureOver(t, newUpstreamFixture(t))
		status, data := fixture.callSiteAction(t, actionOAuthLogin, "", site)
		if status == 200 {
			t.Fatalf("site %q was accepted for a new login", site)
		}
		if !strings.Contains(string(mustMarshal(t, data)), "unknown_site") {
			t.Errorf("site %q error = %v, want it to name the unknown site", site, data)
		}
		if bodies := fixture.oauth.initBodies; len(bodies) != 0 {
			t.Errorf("site %q started %d upstream sessions; a refused site must start none", site, len(bodies))
		}
	}
}

// The state page has to name each account's site: with one account per site the
// two records are otherwise indistinguishable on screen.
func TestAccountViewNamesItsSite(t *testing.T) {
	cases := []struct {
		name string
		doc  []byte
		want string
	}{
		{
			name: "bigmodel",
			doc:  []byte(`{"zcode":{"identity_id":"zcode-user-1","site":"bigmodel","jwt":{"token":"t","status":"active"}}}`),
			want: siteBigmodel,
		},
		{
			name: "zai",
			doc:  []byte(`{"zcode":{"identity_id":"zcode-user-1","site":"zai","jwt":{"token":"t","status":"active"}}}`),
			want: siteZai,
		},
		{
			name: "predates the site field",
			doc:  []byte(`{"zcode":{"identity_id":"zcode-user-1","jwt":{"token":"t","status":"active"}}}`),
			want: siteZai,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			namespace, err := readAccountNamespace(tc.doc)
			if err != nil {
				t.Fatalf("readAccountNamespace: %v", err)
			}
			if namespace.Site != tc.want {
				t.Errorf("site = %q, want %q", namespace.Site, tc.want)
			}
		})
	}
}

// helper: marshal a decoded response for a substring assertion.
func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// helper: read one field out of a stored document's oauth namespace.
func oauthAccessTokenOf(t *testing.T, doc []byte) string {
	t.Helper()
	material := readOAuthMaterial(doc)
	if material.AccessToken == "" {
		t.Fatalf("no OAuth access token was stored: %s", doc)
	}
	return material.AccessToken
}

// helper: read the recorded site out of a stored document.
func recordedSiteOf(t *testing.T, doc []byte) string {
	t.Helper()
	var root struct {
		Zcode struct {
			Site string `json:"site"`
		} `json:"zcode"`
	}
	if err := json.Unmarshal(doc, &root); err != nil {
		t.Fatalf("decode storage: %v", err)
	}
	if root.Zcode.Site == "" {
		t.Fatalf("no site was stored: %s", doc)
	}
	return root.Zcode.Site
}

// countingHandler is a business origin that serves only the endpoints the
// domestic site actually has. It 404s everything else rather than answering
// plausibly, because a double that answers the login endpoint too would hide
// exactly the bug this file exists to catch: the domestic site has no second
// token to exchange, so a request to that path is the plugin asking for
// something the site does not serve.
type countingHandler struct {
	mu    sync.Mutex
	calls int
	// paths records what this origin was asked for, so a test can assert the
	// chain it actually ran rather than only that it ran.
	paths []string
}

func (h *countingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.calls++
	h.paths = append(h.paths, r.URL.Path)
	h.mu.Unlock()
	// A healthy account with exactly one organization and one project, so the
	// exchange that reaches this origin completes rather than stopping on an
	// ambiguous choice.
	switch {
	case strings.HasSuffix(r.URL.Path, "/api/biz/customer/getCustomerInfo"):
		_, _ = w.Write([]byte(`{"data":{"organizations":[{"organizationId":"org-1",` +
			`"organizationName":"Org One","projects":[{"projectId":"proj-1",` +
			`"projectName":"Project One"}]}]}}`))
	case strings.Contains(r.URL.Path, "/api_keys/copy/"):
		_, _ = w.Write([]byte(`{"data":{"secretKey":"secret-1"}}`))
	case strings.HasSuffix(r.URL.Path, "/api_keys"):
		_, _ = w.Write([]byte(`{"data":{"apiKey":"key-1","name":"n"}}`))
	default:
		// The domestic site serves no business-token exchange, and answering
		// this path at all is the failure being pinned.
		http.NotFound(w, r)
	}
}

func (h *countingHandler) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls
}

func (h *countingHandler) servedPaths() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.paths...)
}

func newCountingServer(t *testing.T, handler http.Handler) string {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv.URL
}

// The plan writer is the other write path that runs on a record's own schedule,
// so a record that predates the site field has to gain one here too — otherwise
// a credential that never records a state conclusion stays unmigrated forever.
func TestPlanSnapshotWriteMaterializesTheSite(t *testing.T) {
	legacy := []byte(`{"zcode":{"identity_id":"zcode-1","jwt":{"token":"t","status":"active"}}}`)
	patched, err := writePlanSnapshotSection(legacy, planSnapshotSection{
		Readable:  true,
		CheckedAt: "2026-10-04T00:00:00Z",
		PlanIDs:   []string{"zcode-v3-start-plan-0817"},
	})
	if err != nil {
		t.Fatalf("writePlanSnapshotSection: %v", err)
	}
	if got := recordedSiteOf(t, patched); got != siteZai {
		t.Errorf("site = %q, want %q materialized", got, siteZai)
	}
}

// A record that names its own site keeps it through a plan refresh: the refresh
// re-pins the account's site, it does not reassign it.
func TestPlanSnapshotWriteKeepsAnExplicitSite(t *testing.T) {
	doc := []byte(`{"zcode":{"identity_id":"zcode-1","site":"bigmodel","jwt":{"token":"t","status":"active"}}}`)
	patched, err := writePlanSnapshotSection(doc, planSnapshotSection{
		Readable:  true,
		CheckedAt: "2026-10-04T00:00:00Z",
		PlanIDs:   []string{"zcode-v3-start-plan-trust-1004"},
	})
	if err != nil {
		t.Fatalf("writePlanSnapshotSection: %v", err)
	}
	if got := recordedSiteOf(t, patched); got != siteBigmodel {
		t.Errorf("site = %q, want the record's own %q preserved", got, siteBigmodel)
	}
}
