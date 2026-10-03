package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// makeJWT builds an unsigned three-part JWT for identity claim tests.
func makeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	return header + "." + body + ".c2lnbmF0dXJl"
}

// fakeAuthStore is an AuthStore with canned files, keyed by auth index.
type fakeAuthStore struct {
	mu      sync.Mutex
	entries []pluginapi.HostAuthFileEntry
	docs    map[string]json.RawMessage
	listErr error
	getErr  error
	saveErr error
	saves   []hostCall
}

func (f *fakeAuthStore) List(context.Context) ([]pluginapi.HostAuthFileEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	return append([]pluginapi.HostAuthFileEntry(nil), f.entries...), nil
}

func (f *fakeAuthStore) Get(_ context.Context, authIndex string) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, f.getErr
	}
	doc, ok := f.docs[authIndex]
	if !ok {
		return nil, fmt.Errorf("no auth document for %s", authIndex)
	}
	return doc, nil
}

func (f *fakeAuthStore) GetRuntime(_ context.Context, authIndex string) (pluginapi.HostAuthFileEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, entry := range f.entries {
		if entry.AuthIndex == authIndex {
			return entry, nil
		}
	}
	return pluginapi.HostAuthFileEntry{}, fmt.Errorf("no runtime auth for %s", authIndex)
}

func (f *fakeAuthStore) Save(_ context.Context, name string, document json.RawMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.saveErr != nil {
		return f.saveErr
	}
	f.saves = append(f.saves, hostCall{method: "save:" + name, request: document})
	// The host persists the document: later reads observe the save.
	f.docs[name] = json.RawMessage(document)
	return nil
}

// upstreamFixture wires the plugin against an httptest upstream and a fake
// host auth store. It records every upstream request for assertions. The
// managed key exchange endpoints live on their own fixture, reachable as
// fixture.keys.
type upstreamFixture struct {
	t     *testing.T
	srv   *httptest.Server
	store *fakeAuthStore
	keys  *keyExchangeFixture

	mu            sync.Mutex
	initAuth      []string
	initBodies    []string
	pollAuth      []string
	pollFlowIDs   []string
	pollResponses []func() (int, string)
	initStatus    int
	// balanceBody is the billing answer the login preflight reads. It defaults
	// to a live Start Plan so a ready poll reaches a stored credential; a test
	// about the preflight's refusals overrides it.
	balanceBody string
	// onPoll, when set, runs inside the upstream poll handler before the
	// reply is written; it lets tests interleave session state changes with
	// the plugin's poll handling.
	onPoll func()
}

// newUpstreamFixture redirects oauthUpstreamBase and the auth store to test
// doubles for the duration of the test. The managed key exchange upstream is
// redirected as well, so a ready poll exercises the whole login closure. The
// billing endpoint is served too: a completed login now reads the candidate
// credential's Start Plan entitlement before storing it, so a fixture that only
// answered the OAuth routes would exercise a login that never succeeds.
func newUpstreamFixture(t *testing.T) *upstreamFixture {
	t.Helper()
	resetSessions(t)
	fixture := &upstreamFixture{
		t:           t,
		store:       &fakeAuthStore{docs: map[string]json.RawMessage{}},
		balanceBody: startPlanBalanceBody,
	}
	fixture.keys = newKeyExchangeFixture(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/oauth/cli/init", fixture.serveInit)
	mux.HandleFunc("/api/v1/oauth/cli/poll/", fixture.servePoll)
	mux.HandleFunc("/api/v1/zcode-plan"+billingBalancePath, fixture.serveBalance)
	fixture.srv = httptest.NewServer(mux)
	t.Cleanup(fixture.srv.Close)

	originalBase := oauthUpstreamBase
	originalBilling := zcodePlanBillingBase
	originalStore := authStoreProvider
	oauthUpstreamBase = fixture.srv.URL + "/api/v1"
	zcodePlanBillingBase = fixture.srv.URL + "/api/v1/zcode-plan"
	authStoreProvider = func() AuthStore { return fixture.store }
	t.Cleanup(func() {
		oauthUpstreamBase = originalBase
		zcodePlanBillingBase = originalBilling
		authStoreProvider = originalStore
	})
	return fixture
}

// setBalanceBody sets the balance answer the login preflight will read.
func (f *upstreamFixture) setBalanceBody(body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.balanceBody = body
}

func (f *upstreamFixture) serveBalance(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	body := f.balanceBody
	f.mu.Unlock()
	writeBilling(w, 0, body)
}

// queuePoll appends one upstream poll reply (status code, JSON body).
func (f *upstreamFixture) queuePoll(status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pollResponses = append(f.pollResponses, func() (int, string) { return status, body })
}

// queuePollReady is shorthand for a ready poll reply carrying a JWT.
func (f *upstreamFixture) queuePollReady(token string) {
	body, err := json.Marshal(map[string]any{
		"data": map[string]any{
			"status": "ready",
			"token":  token,
			"zai":    map[string]any{"access_token": "zai-access-token-1"},
		},
	})
	if err != nil {
		f.t.Fatal(err)
	}
	f.queuePoll(http.StatusOK, string(body))
}

func (f *upstreamFixture) serveInit(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.initAuth = append(f.initAuth, r.Header.Get("Authorization"))
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		f.t.Logf("read init body: %v", err)
	}
	f.initBodies = append(f.initBodies, string(body))
	if f.initStatus != 0 {
		w.WriteHeader(f.initStatus)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"data":{"flow_id":"flow-123","authorize_url":"https://zcode.z.ai/authorize?flow_id=flow-123"}}`))
}

func (f *upstreamFixture) servePoll(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pollAuth = append(f.pollAuth, r.Header.Get("Authorization"))
	f.pollFlowIDs = append(f.pollFlowIDs, strings.TrimPrefix(r.URL.Path, "/api/v1/oauth/cli/poll/"))
	hook := f.onPoll
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	f.mu.Lock()
	if len(f.pollResponses) == 0 {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	next := f.pollResponses[0]
	f.pollResponses = f.pollResponses[1:]
	status, body := next()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// startLogin drives one auth.login.start call and returns the parsed result.
func (f *upstreamFixture) startLogin(t *testing.T) pluginapi.AuthLoginStartResponse {
	t.Helper()
	env := callMethod(t, pluginabi.MethodAuthLoginStart, []byte(`{"Provider":"zcode"}`))
	if !env.OK {
		t.Fatalf("auth.login.start failed: %+v", env.Error)
	}
	var response pluginapi.AuthLoginStartResponse
	if err := json.Unmarshal(env.Result, &response); err != nil {
		t.Fatalf("decode start response: %v", err)
	}
	return response
}

// pollLogin drives one auth.login.poll call for a state handle.
func pollLogin(t *testing.T, state string) pluginabi.Envelope {
	t.Helper()
	request, err := json.Marshal(map[string]string{"Provider": pluginID, "State": state})
	if err != nil {
		t.Fatal(err)
	}
	return callMethod(t, pluginabi.MethodAuthLoginPoll, request)
}

// decodePoll parses a poll envelope result.
func decodePoll(t *testing.T, env pluginabi.Envelope) pluginapi.AuthLoginPollResponse {
	t.Helper()
	var response pluginapi.AuthLoginPollResponse
	if err := json.Unmarshal(env.Result, &response); err != nil {
		t.Fatalf("decode poll response: %v", err)
	}
	return response
}

// assertNoLeak fails when any forbidden secret appears in the envelope text.
func assertNoLeak(t *testing.T, raw []byte, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		if strings.Contains(string(raw), secret) {
			t.Fatalf("envelope leaked a secret (%d chars of it) into: %s", len(secret), truncateForLog(string(raw), 200))
		}
	}
}

func TestAuthIdentifierReturnsPluginID(t *testing.T) {
	env := callMethod(t, pluginabi.MethodAuthIdentifier, nil)
	if !env.OK {
		t.Fatalf("auth.identifier failed: %+v", env.Error)
	}
	if !strings.Contains(string(env.Result), `"identifier":"zcode"`) {
		t.Fatalf("unexpected identifier payload: %s", env.Result)
	}
}

func TestAuthLoginStartReturnsBrowserLinkAndPollableState(t *testing.T) {
	fixture := newUpstreamFixture(t)
	response := fixture.startLogin(t)

	if response.Provider != pluginID {
		t.Fatalf("provider = %q", response.Provider)
	}
	if response.URL == "" || !strings.HasPrefix(response.URL, "https://zcode.z.ai/authorize") {
		t.Fatalf("authorize URL missing: %q", response.URL)
	}
	if !hexTokenPattern.MatchString(response.State) {
		t.Fatalf("state is not an unguessable handle: %q", response.State)
	}
	if response.ExpiresAt.IsZero() || !response.ExpiresAt.After(time.Now()) {
		t.Fatalf("expires_at must be in the future: %v", response.ExpiresAt)
	}
	if got := time.Until(response.ExpiresAt); got > time.Duration(defaultConfig().OAuth.SessionTTLSeconds)*time.Second+5*time.Second {
		t.Fatalf("session TTL too long: %v", got)
	}
	if len(fixture.initAuth) != 1 || !strings.HasPrefix(fixture.initAuth[0], "Bearer ") {
		t.Fatalf("init call must authenticate with the polling secret: %v", fixture.initAuth)
	}
	if !strings.Contains(fixture.initBodies[0], `"provider":"zai"`) {
		t.Fatalf("init body missing provider selector: %q", fixture.initBodies[0])
	}
	// The session handle must never equal the polling secret material.
	secret := strings.TrimPrefix(fixture.initAuth[0], "Bearer ")
	if response.State == secret {
		t.Fatal("state must be independent of the polling secret")
	}
	if activeSessions.lookup(response.State) == nil {
		t.Fatal("session must be registered for polling")
	}
}

func TestAuthLoginStartUpstreamFailureIsRedactedAndLeavesNoSession(t *testing.T) {
	fixture := newUpstreamFixture(t)
	fixture.mu.Lock()
	fixture.initStatus = http.StatusServiceUnavailable
	fixture.mu.Unlock()

	env := callMethod(t, pluginabi.MethodAuthLoginStart, []byte(`{"Provider":"zcode"}`))
	if env.OK {
		t.Fatal("start must fail when upstream rejects the init call")
	}
	if env.Error == nil || env.Error.Code != "oauth_upstream_failed" {
		t.Fatalf("expected oauth_upstream_failed, got %+v", env.Error)
	}
	if !strings.Contains(env.Error.Message, "http 503") {
		t.Fatalf("error should carry the upstream status: %q", env.Error.Message)
	}
	assertNoLeak(t, []byte(env.Error.Message), fixture.pollAuth...)
	activeSessions.mu.Lock()
	remaining := len(activeSessions.sessions)
	activeSessions.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("failed start must not create sessions, found %d", remaining)
	}
}

func TestAuthLoginStartRejectsForeignProvider(t *testing.T) {
	newUpstreamFixture(t)
	env := callMethod(t, pluginabi.MethodAuthLoginStart, []byte(`{"Provider":"other"}`))
	if env.OK || env.Error == nil || env.Error.Code != "unknown_provider" {
		t.Fatalf("expected unknown_provider error, got %+v", env.Error)
	}
}

func TestAuthLoginPollWaitsWhileUpstreamPending(t *testing.T) {
	fixture := newUpstreamFixture(t)
	body, err := json.Marshal(map[string]any{"data": map[string]any{"status": "waiting"}})
	if err != nil {
		t.Fatal(err)
	}
	fixture.queuePoll(http.StatusOK, string(body))
	start := fixture.startLogin(t)

	env := pollLogin(t, start.State)
	if !env.OK {
		t.Fatalf("poll failed: %+v", env.Error)
	}
	response := decodePoll(t, env)
	if response.Status != pluginapi.AuthLoginStatusPending {
		t.Fatalf("status = %q, want pending", response.Status)
	}
	if len(fixture.pollAuth) != 1 || !strings.HasPrefix(fixture.pollAuth[0], "Bearer ") {
		t.Fatalf("poll must authenticate with the session secret: %v", fixture.pollAuth)
	}
	if len(fixture.pollFlowIDs) != 1 || fixture.pollFlowIDs[0] != "flow-123" {
		t.Fatalf("poll must hit the session flow id: %v", fixture.pollFlowIDs)
	}
	if fixture.pollAuth[0] != fixture.initAuth[0] {
		t.Fatal("poll and init must share the session polling secret")
	}
}

func TestAuthLoginPollSuccessStoresJWTPreservingExistingAccount(t *testing.T) {
	fixture := newUpstreamFixture(t)
	token := makeJWT(t, map[string]any{"sub": "user-42", "exp": 9999999999})

	// An existing account for the same identity with managed key material
	// and an unknown host field must survive the re-login losslessly.
	existing := `{"type":"zcode","host_field":{"keep":1},"zcode":{"schema_version":1,` +
		`"identity_id":"zcode-user-42","api_key":{"credential":"old-key"},"jwt":{"token":"old"}}}`
	fixture.store.entries = []pluginapi.HostAuthFileEntry{{AuthIndex: "a1", Provider: pluginID, Name: "zcode-1.json"}}
	fixture.store.docs["a1"] = json.RawMessage(existing)

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
	auth := response.Auth
	if auth.Provider != pluginID || auth.ID != "zcode-user-42" {
		t.Fatalf("auth identity mismatch: %+v", auth)
	}
	if auth.FileName == "" || !strings.HasSuffix(auth.FileName, ".json") {
		t.Fatalf("auth file name missing: %q", auth.FileName)
	}
	var doc map[string]any
	if err := json.Unmarshal(auth.StorageJSON, &doc); err != nil {
		t.Fatalf("storage not JSON: %v", err)
	}
	zcode, ok := doc["zcode"].(map[string]any)
	if !ok {
		t.Fatalf("zcode namespace missing: %s", auth.StorageJSON)
	}
	if zcode["identity_id"] != "zcode-user-42" {
		t.Fatalf("identity_id = %v", zcode["identity_id"])
	}
	jwtDoc, ok := zcode["jwt"].(map[string]any)
	if !ok || jwtDoc["token"] != token || jwtDoc["status"] != "active" {
		t.Fatalf("jwt namespace incomplete: %v", zcode["jwt"])
	}
	oauthDoc, ok := zcode["oauth"].(map[string]any)
	if !ok || oauthDoc["access_token"] != "zai-access-token-1" {
		t.Fatalf("oauth exchange material missing: %v", zcode["oauth"])
	}
	// Lossless merge: previous plugin and host fields survive.
	if _, ok := doc["host_field"].(map[string]any); !ok {
		t.Fatalf("unknown host field lost: %s", auth.StorageJSON)
	}
	apiKey, ok := zcode["api_key"].(map[string]any)
	if !ok || apiKey["credential"] != "old-key" {
		t.Fatalf("managed api key lost: %v", zcode["api_key"])
	}

	// A second poll must replay the stored success without upstream traffic.
	pollsSoFar := len(fixture.pollFlowIDs)
	env2 := pollLogin(t, start.State)
	if !env2.OK {
		t.Fatalf("second poll failed: %+v", env2.Error)
	}
	response2 := decodePoll(t, env2)
	if response2.Status != pluginapi.AuthLoginStatusSuccess || response2.Auth.ID != "zcode-user-42" {
		t.Fatalf("second poll must be idempotent: %+v", response2)
	}
	if len(fixture.pollFlowIDs) != pollsSoFar {
		t.Fatal("terminal session must not poll upstream again")
	}
	// The plugin never writes credentials itself; the host saves the record
	// it received from the poll result.
	if len(fixture.store.saves) != 0 {
		t.Fatalf("plugin must not save credentials directly: %v", fixture.store.saves)
	}
}

func TestAuthLoginPollSuccessStoresManagedAPIKeyFallback(t *testing.T) {
	fixture := newUpstreamFixture(t)
	token := makeJWT(t, map[string]any{"sub": "user-keyed"})

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
	// One host account carries both credentials of the same upstream identity.
	var doc struct {
		Zcode struct {
			JWT    map[string]any `json:"jwt"`
			APIKey map[string]any `json:"api_key"`
		} `json:"zcode"`
	}
	if err := json.Unmarshal(response.Auth.StorageJSON, &doc); err != nil {
		t.Fatalf("storage not JSON: %v", err)
	}
	if doc.Zcode.JWT["token"] != token || doc.Zcode.JWT["status"] != "active" {
		t.Fatalf("primary JWT missing: %v", doc.Zcode.JWT)
	}
	if doc.Zcode.APIKey["status"] != apiKeyStatusActive || doc.Zcode.APIKey["managed"] != true {
		t.Fatalf("managed fallback key missing: %v", doc.Zcode.APIKey)
	}
	if doc.Zcode.APIKey["key_id"] != "key-1" || doc.Zcode.APIKey["key_material"] != "key-1.secret-1" {
		t.Fatalf("fallback key identity and material not recorded: %v", doc.Zcode.APIKey)
	}
	if _, _, create, _ := fixture.keys.counts(); create != 1 {
		t.Fatalf("create calls = %d, want exactly one key creation", create)
	}
}

func TestAuthLoginReLoginReusesManagedKeyWithoutNameSearch(t *testing.T) {
	fixture := newUpstreamFixture(t)
	token := makeJWT(t, map[string]any{"sub": "user-keyed"})

	// The account already carries the managed key of a previous login.
	existing := `{"type":"zcode","host_field":{"keep":1},"zcode":{"schema_version":1,` +
		`"identity_id":"zcode-user-keyed","jwt":{"token":"old"},"api_key":{` +
		`"status":"active","managed":true,"name":"cpa-zcode-recorded","key_id":"key-recorded",` +
		`"key_material":"key-recorded.secret-recorded","organization_id":"org-1","project_id":"proj-1"}}}`
	fixture.store.entries = []pluginapi.HostAuthFileEntry{{AuthIndex: "a1", Provider: pluginID, Name: "zcode-1.json"}}
	fixture.store.docs["a1"] = json.RawMessage(existing)

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
	var doc struct {
		Zcode struct {
			JWT    map[string]any `json:"jwt"`
			APIKey map[string]any `json:"api_key"`
		} `json:"zcode"`
	}
	if err := json.Unmarshal(response.Auth.StorageJSON, &doc); err != nil {
		t.Fatalf("storage not JSON: %v", err)
	}
	if doc.Zcode.JWT["token"] != token {
		t.Fatalf("the fresh JWT must replace the old one: %v", doc.Zcode.JWT)
	}
	if doc.Zcode.APIKey["key_id"] != "key-recorded" || doc.Zcode.APIKey["key_material"] != "key-recorded.secret-recorded" {
		t.Fatalf("the recorded managed key must be reused: %v", doc.Zcode.APIKey)
	}
	if doc.Zcode.APIKey["name"] != "cpa-zcode-recorded" {
		t.Fatalf("recorded key name changed: %v", doc.Zcode.APIKey)
	}
	var generic map[string]any
	if err := json.Unmarshal(response.Auth.StorageJSON, &generic); err != nil {
		t.Fatalf("storage not JSON: %v", err)
	}
	if _, ok := generic["host_field"].(map[string]any); !ok {
		t.Fatalf("unknown host field lost: %s", response.Auth.StorageJSON)
	}
	// Reuse means reuse: no business login, no discovery, no creation, no
	// adoption or modification of any existing upstream key.
	if login, info, create, copy := fixture.keys.counts(); login+info+create+copy != 0 {
		t.Fatalf("re-login with a recorded key must not touch the key exchange upstream (login %d info %d create %d copy %d)", login, info, create, copy)
	}
}

func TestAuthLoginPollReadyFinalizesExactlyOnce(t *testing.T) {
	fixture := newUpstreamFixture(t)
	token := makeJWT(t, map[string]any{"sub": "user-raced"})
	fixture.queuePollReady(token)
	fixture.queuePollReady(token)
	fixture.keys.createStarted = make(chan struct{}, 1)
	fixture.keys.blockCreate = make(chan struct{})
	releaseCreate := func() {
		fixture.keys.mu.Lock()
		block := fixture.keys.blockCreate
		fixture.keys.blockCreate = nil
		fixture.keys.mu.Unlock()
		if block != nil {
			close(block)
		}
	}
	defer releaseCreate()

	start := fixture.startLogin(t)

	first := make(chan pluginabi.Envelope, 1)
	go func() {
		first <- pollLogin(t, start.State)
	}()

	select {
	case <-fixture.keys.createStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("the first poll never reached key creation")
	}

	// An overlapping poll of the same session must stay pending instead of
	// racing a second exchange.
	second := pollLogin(t, start.State)
	if !second.OK {
		t.Fatalf("second poll failed: %+v", second.Error)
	}
	if response := decodePoll(t, second); response.Status != pluginapi.AuthLoginStatusPending {
		t.Fatalf("overlapping poll status = %q (%s), want pending while finalizing", response.Status, response.Message)
	}

	// Let the key creation finish so the finalizing poll can complete.
	releaseCreate()

	env := <-first
	if !env.OK {
		t.Fatalf("first poll failed: %+v", env.Error)
	}
	response := decodePoll(t, env)
	if response.Status != pluginapi.AuthLoginStatusSuccess {
		t.Fatalf("status = %q (%s), want success", response.Status, response.Message)
	}
	var doc struct {
		Zcode struct {
			APIKey map[string]any `json:"api_key"`
		} `json:"zcode"`
	}
	if err := json.Unmarshal(response.Auth.StorageJSON, &doc); err != nil {
		t.Fatalf("storage not JSON: %v", err)
	}
	if doc.Zcode.APIKey["key_id"] != "key-1" {
		t.Fatalf("first success must carry the managed key: %v", doc.Zcode.APIKey)
	}
	if login, _, create, copy := fixture.keys.counts(); login != 1 || create != 1 || copy != 1 {
		t.Fatalf("the ready path must exchange exactly once (login %d create %d copy %d)", login, create, copy)
	}

	// A later poll replays the completed result, managed key included.
	replay := pollLogin(t, start.State)
	if !replay.OK {
		t.Fatalf("replay poll failed: %+v", replay.Error)
	}
	replayed := decodePoll(t, replay)
	if replayed.Status != pluginapi.AuthLoginStatusSuccess {
		t.Fatalf("replay status = %q, want success", replayed.Status)
	}
	if !strings.Contains(string(replayed.Auth.StorageJSON), `"key_id":"key-1"`) {
		t.Fatalf("replayed result lost the managed key: %s", replayed.Auth.StorageJSON)
	}
}

func TestAuthLoginPollSuccessSurvivesManagedKeyExchangeFailure(t *testing.T) {
	fixture := newUpstreamFixture(t)
	token := makeJWT(t, map[string]any{"sub": "user-failed"})
	fixture.keys.mu.Lock()
	fixture.keys.loginStatus = http.StatusInternalServerError
	fixture.keys.mu.Unlock()

	fixture.queuePollReady(token)
	start := fixture.startLogin(t)

	env := pollLogin(t, start.State)
	if !env.OK {
		t.Fatalf("poll failed: %+v", env.Error)
	}
	response := decodePoll(t, env)
	if response.Status != pluginapi.AuthLoginStatusSuccess {
		t.Fatalf("a managed key exchange failure must not fail the JWT login: %q (%s)", response.Status, response.Message)
	}
	var doc struct {
		Zcode struct {
			JWT    map[string]any `json:"jwt"`
			APIKey map[string]any `json:"api_key"`
		} `json:"zcode"`
	}
	if err := json.Unmarshal(response.Auth.StorageJSON, &doc); err != nil {
		t.Fatalf("storage not JSON: %v", err)
	}
	if doc.Zcode.JWT["token"] != token || doc.Zcode.JWT["status"] != "active" {
		t.Fatalf("the saved JWT must be untouched by the exchange failure: %v", doc.Zcode.JWT)
	}
	if doc.Zcode.APIKey["status"] != apiKeyStatusFailed {
		t.Fatalf("api_key status = %v, want a diagnosable failed state", doc.Zcode.APIKey["status"])
	}
	raw, err := json.Marshal(doc.Zcode.APIKey["last_error"])
	if err != nil {
		t.Fatalf("last_error missing: %v", doc.Zcode.APIKey)
	}
	var failure keyOpError
	if err := json.Unmarshal(raw, &failure); err != nil || failure.Stage != apiKeyStageLogin {
		t.Fatalf("last_error stage = %+v, want the login stage", failure)
	}
}

func TestAuthLoginPollRejectsReadyWithoutCredential(t *testing.T) {
	fixture := newUpstreamFixture(t)
	fixture.queuePoll(http.StatusOK, `{"data":{"status":"ready"}}`)
	start := fixture.startLogin(t)

	env := pollLogin(t, start.State)
	if !env.OK {
		t.Fatalf("poll failed: %+v", env.Error)
	}
	response := decodePoll(t, env)
	if response.Status != pluginapi.AuthLoginStatusError {
		t.Fatalf("status = %q, want error", response.Status)
	}
	snap := activeSessions.lookup(start.State).snapshot()
	if snap.State != authSessionFailed {
		t.Fatalf("state = %q, want failed", snap.State)
	}
}

func TestAuthLoginPollReportsUpstreamRejection(t *testing.T) {
	fixture := newUpstreamFixture(t)
	fixture.queuePoll(http.StatusOK, `{"data":{"status":"failed"}}`)
	start := fixture.startLogin(t)

	env := pollLogin(t, start.State)
	response := decodePoll(t, env)
	if response.Status != pluginapi.AuthLoginStatusError {
		t.Fatalf("status = %q, want error", response.Status)
	}
	if response.Message == "" {
		t.Fatal("rejection must carry a message")
	}
	assertNoLeak(t, env.Result, "flow-123")
}

func TestAuthLoginPollStaysPendingOnTransientUpstreamErrors(t *testing.T) {
	fixture := newUpstreamFixture(t)
	fixture.queuePoll(http.StatusInternalServerError, `{"error":"boom"}`)
	fixture.queuePoll(http.StatusForbidden, `{"error":"no"}`)
	start := fixture.startLogin(t)

	for i := 0; i < 2; i++ {
		env := pollLogin(t, start.State)
		if !env.OK {
			t.Fatalf("poll %d failed: %+v", i, env.Error)
		}
		if response := decodePoll(t, env); response.Status != pluginapi.AuthLoginStatusPending {
			t.Fatalf("poll %d status = %q, want pending", i, response.Status)
		}
	}
	if activeSessions.lookup(start.State).snapshot().State != authSessionPending {
		t.Fatal("transient upstream errors must not terminate the session")
	}
	assertNoLeak(t, []byte{}, "boom")
}

func TestAuthLoginPollReportsExpiredInsteadOfBogusSuccessOnRace(t *testing.T) {
	fixture := newUpstreamFixture(t)
	token := makeJWT(t, map[string]any{"sub": "race-user"})
	fixture.queuePollReady(token)
	start := fixture.startLogin(t)

	// Simulate a concurrent poll whose lazy expiry flips the session to
	// expired while this poll was reading the upstream ready reply. The
	// reply must be the stable expired error, never a success carrying an
	// empty record.
	fixture.mu.Lock()
	fixture.onPoll = func() {
		if session := activeSessions.lookup(start.State); session != nil {
			session.expireIfDue(session.expiresAt.Add(time.Second))
		}
	}
	fixture.mu.Unlock()

	env := pollLogin(t, start.State)
	if !env.OK {
		t.Fatalf("poll failed: %+v", env.Error)
	}
	response := decodePoll(t, env)
	if response.Status != pluginapi.AuthLoginStatusError {
		t.Fatalf("status = %q, want error on expired race", response.Status)
	}
	if !strings.Contains(response.Message, "expired") {
		t.Fatalf("message = %q, want expired", response.Message)
	}
	if response.Auth.ID != "" || response.Auth.StorageJSON != nil {
		t.Fatalf("expired race must not return auth data: %+v", response.Auth)
	}
}

func TestAuthLoginPollExpiredSessionNeverTouchesUpstream(t *testing.T) {
	fixture := newUpstreamFixture(t)
	start := fixture.startLogin(t)

	// Age the clock past the session TTL.
	base := activeSessions.now()
	activeSessions.now = func() time.Time {
		return base.Add(time.Duration(defaultConfig().OAuth.SessionTTLSeconds)*time.Second + time.Second)
	}

	pollsSoFar := len(fixture.pollFlowIDs)
	env := pollLogin(t, start.State)
	if !env.OK {
		t.Fatalf("poll failed: %+v", env.Error)
	}
	response := decodePoll(t, env)
	if response.Status != pluginapi.AuthLoginStatusError {
		t.Fatalf("status = %q, want error", response.Status)
	}
	if !strings.Contains(response.Message, "expired") {
		t.Fatalf("expired message = %q", response.Message)
	}
	if len(fixture.pollFlowIDs) != pollsSoFar {
		t.Fatal("expired session must not poll upstream")
	}
}

func TestAuthLoginPollUnknownStateIsRejected(t *testing.T) {
	newUpstreamFixture(t)
	env := pollLogin(t, strings.Repeat("ab", 32))
	if !env.OK {
		t.Fatalf("unknown state must be a poll response, got %+v", env.Error)
	}
	if response := decodePoll(t, env); response.Status != pluginapi.AuthLoginStatusError {
		t.Fatalf("status = %q, want error", response.Status)
	}
}

func TestAuthLoginPollRequiresState(t *testing.T) {
	newUpstreamFixture(t)
	env := callMethod(t, pluginabi.MethodAuthLoginPoll, []byte(`{}`))
	if env.OK || env.Error == nil || env.Error.Code != "invalid_request" {
		t.Fatalf("expected invalid_request, got %+v", env.Error)
	}
}

func TestShutdownClearsAuthorizationSessions(t *testing.T) {
	fixture := newUpstreamFixture(t)
	start := fixture.startLogin(t)
	if activeSessions.lookup(start.State) == nil {
		t.Fatal("precondition: session exists")
	}
	// Earlier tests may already have exercised the once-guarded shutdown.
	shutdownOnce = sync.Once{}
	runShutdown()
	if activeSessions.lookup(start.State) != nil {
		t.Fatal("shutdown must clear authorization sessions")
	}
	env := pollLogin(t, start.State)
	response := decodePoll(t, env)
	if response.Status != pluginapi.AuthLoginStatusError {
		t.Fatalf("post-shutdown poll status = %q, want error", response.Status)
	}
}

func TestZcodeSubjectFromJWTUsesStableClaims(t *testing.T) {
	cases := []struct {
		name   string
		claims map[string]any
		want   string
	}{
		{"sub", map[string]any{"sub": "subject-1"}, "subject-1"},
		{"uid fallback", map[string]any{"uid": "uid-9"}, "uid-9"},
		{"user_id fallback", map[string]any{"user_id": "u-1"}, "u-1"},
		{"id fallback", map[string]any{"id": "i-1"}, "i-1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := zcodeSubjectFromJWT(makeJWT(t, tc.claims))
			if !ok || got != tc.want {
				t.Fatalf("subject = %q (ok=%v), want %q", got, ok, tc.want)
			}
		})
	}
	// A claim-less token has no stable input, so the login must be refused
	// instead of minting a new account on every re-login.
	if _, ok := zcodeSubjectFromJWT(makeJWT(t, map[string]any{"exp": 1})); ok {
		t.Fatal("claim-less tokens must not resolve to a subject")
	}
	// The same subject in two differently signed tokens must resolve to the
	// same identity.
	first, _ := zcodeSubjectFromJWT(makeJWT(t, map[string]any{"sub": "user-42"}))
	second, _ := zcodeSubjectFromJWT(makeJWT(t, map[string]any{"sub": "user-42", "exp": 1}))
	if identityIDFor(first) != identityIDFor(second) {
		t.Fatalf("identity must be stable per subject: %q vs %q", first, second)
	}
}

func TestAuthLoginPollRefusesCredentialWithoutStableIdentity(t *testing.T) {
	fixture := newUpstreamFixture(t)
	// No sub/uid/user_id/id claim: a token-hash identity would change on
	// every re-login and duplicate the host account.
	fixture.queuePollReady(makeJWT(t, map[string]any{"exp": 1234567890}))
	start := fixture.startLogin(t)

	env := pollLogin(t, start.State)
	if !env.OK {
		t.Fatalf("poll failed: %+v", env.Error)
	}
	response := decodePoll(t, env)
	if response.Status != pluginapi.AuthLoginStatusError {
		t.Fatalf("status = %q, want error", response.Status)
	}
	if !strings.Contains(response.Message, "stable identity") {
		t.Fatalf("refusal message = %q", response.Message)
	}
	if activeSessions.lookup(start.State).snapshot().State != authSessionFailed {
		t.Fatal("refused login must fail the session")
	}
}

func TestIdentityDigestIsDomainSeparated(t *testing.T) {
	if identityDigest("token-a") == identityDigest("token-b") {
		t.Fatal("different inputs must produce different digests")
	}
	if len(identityDigest(strings.Repeat("x", 500))) != 32 {
		t.Fatal("digest must be 32 hex chars")
	}
}

func TestAuthFileNameForIsStableAndSafe(t *testing.T) {
	first := authFileNameFor("zcode-user-42")
	second := authFileNameFor("zcode-user-42")
	if first != second {
		t.Fatalf("file name must be stable: %q vs %q", first, second)
	}
	if !strings.HasPrefix(first, "zcode-") || !strings.HasSuffix(first, ".json") {
		t.Fatalf("unexpected file name shape: %q", first)
	}
	if strings.ContainsAny(first, "/\\:*?\"<>| ") {
		t.Fatalf("file name must be filesystem-safe: %q", first)
	}
}

func TestBuildZcodeStorageMergesLosslessly(t *testing.T) {
	previous := []byte(`{"type":"zcode","unknown":{"n":12345678901234567890},"zcode":{"schema_version":1,"identity_id":"zcode-user-1","api_key":{"credential":"k"},"jwt":{"token":"old","status":"invalid"}}}`)
	token := makeJWT(t, map[string]any{"sub": "user-1"})
	doc, err := buildZcodeStorage(previous, "zcode-user-1", token, "access-1", time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(doc, &parsed); err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed["unknown"].(map[string]any); !ok {
		t.Fatalf("unknown host field lost: %s", doc)
	}
	zcode := parsed["zcode"].(map[string]any)
	if zcode["api_key"] == nil {
		t.Fatal("managed key lost on re-login")
	}
	jwtDoc := zcode["jwt"].(map[string]any)
	if jwtDoc["token"] != token || jwtDoc["status"] != "active" {
		t.Fatalf("jwt not refreshed: %v", jwtDoc)
	}
}

func TestAuthParseClaimsZcodeDocumentsOnly(t *testing.T) {
	token := makeJWT(t, map[string]any{"sub": "user-7"})
	doc := fmt.Sprintf(`{"type":"zcode","zcode":{"identity_id":"zcode-user-7","jwt":{"token":%q}}}`, token)

	env := callMethod(t, pluginabi.MethodAuthParse, []byte(fmt.Sprintf(`{"Provider":"zcode","FileName":"zcode-x.json","RawJSON":%q}`, base64.StdEncoding.EncodeToString([]byte(doc)))))
	if !env.OK {
		t.Fatalf("auth.parse failed: %+v", env.Error)
	}
	var parsed pluginapi.AuthParseResponse
	if err := json.Unmarshal(env.Result, &parsed); err != nil {
		t.Fatal(err)
	}
	if !parsed.Handled || parsed.Auth.Provider != pluginID || parsed.Auth.ID != "zcode-user-7" {
		t.Fatalf("zcode document not claimed: %+v", parsed)
	}
	if string(parsed.Auth.StorageJSON) != doc {
		t.Fatal("parse must preserve the stored document byte-exactly")
	}

	foreign := `{"type":"claude","api_key":"sk-ant"}`
	env = callMethod(t, pluginabi.MethodAuthParse, []byte(fmt.Sprintf(`{"RawJSON":%q}`, base64.StdEncoding.EncodeToString([]byte(foreign)))))
	if !env.OK {
		t.Fatalf("foreign parse failed: %+v", env.Error)
	}
	if err := json.Unmarshal(env.Result, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Handled {
		t.Fatal("foreign documents must stay unhandled")
	}

	broken := `{"type":"zcode","zcode":{"identity_id":"zcode-x"}}`
	env = callMethod(t, pluginabi.MethodAuthParse, []byte(fmt.Sprintf(`{"Provider":"zcode","RawJSON":%q}`, base64.StdEncoding.EncodeToString([]byte(broken)))))
	if !env.OK {
		t.Fatalf("broken zcode parse failed: %+v", env.Error)
	}
	if err := json.Unmarshal(env.Result, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Handled {
		t.Fatal("incomplete zcode documents must stay unhandled")
	}
}

func TestAuthRefreshEchoesStoredCredential(t *testing.T) {
	storage := []byte(`{"zcode":{"identity_id":"zcode-user-1","jwt":{"token":"t"}}}`)
	request, err := json.Marshal(map[string]any{
		"AuthID":       "zcode-user-1",
		"AuthProvider": pluginID,
		"StorageJSON":  storage,
		"Metadata":     map[string]any{"type": pluginID},
	})
	if err != nil {
		t.Fatal(err)
	}
	env := callMethod(t, pluginabi.MethodAuthRefresh, request)
	if !env.OK {
		t.Fatalf("auth.refresh failed: %+v", env.Error)
	}
	var response pluginapi.AuthRefreshResponse
	if err := json.Unmarshal(env.Result, &response); err != nil {
		t.Fatal(err)
	}
	if response.Auth.Provider != pluginID || response.Auth.ID != "zcode-user-1" {
		t.Fatalf("refresh must echo the record: %+v", response.Auth)
	}
	if string(response.Auth.StorageJSON) != string(storage) {
		t.Fatal("refresh must not alter the stored credential")
	}
}

func TestAuthLoginFlowNeverLeaksSecretsIntoResponses(t *testing.T) {
	fixture := newUpstreamFixture(t)
	token := makeJWT(t, map[string]any{"sub": "leak-check"})
	fixture.queuePollReady(token)

	start := fixture.startLogin(t)
	secret := strings.TrimPrefix(fixture.initAuth[0], "Bearer ")
	env := pollLogin(t, start.State)
	if !env.OK {
		t.Fatalf("poll failed: %+v", env.Error)
	}
	// The JWT itself is returned to the host inside the auth record (that is
	// the secure channel); the polling secret must never appear anywhere.
	assertNoLeak(t, env.Result, secret)
	// The authorize URL query is user-facing and belongs to the start
	// response, but must not be echoed by poll replies.
	if strings.Contains(string(env.Result), "authorize") {
		t.Fatal("poll replies must not echo the authorize URL")
	}
}
