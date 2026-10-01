package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// catalogDoc builds an auth document with explicit identity and credential
// material so catalog tests control exactly which environments are usable.
func catalogDoc(identity, jwtToken, jwtStatus, keyToken, keyStatus string) []byte {
	return []byte(`{"type":"zcode","zcode":{` +
		`"identity_id":"` + identity + `",` +
		`"jwt":{"token":"` + jwtToken + `","status":"` + jwtStatus + `"},` +
		`"api_key":{"key_material":"` + keyToken + `","status":"` + keyStatus + `"}}}`)
}

// overrideCatalogUpstreams points both upstream environments at one test
// server for the duration of the test.
func overrideCatalogUpstreams(t *testing.T, serverURL string) {
	t.Helper()
	originalPlan, originalAPI := zcodePlanUpstreamBase, zaiAPIBase
	zcodePlanUpstreamBase, zaiAPIBase = serverURL, serverURL
	t.Cleanup(func() { zcodePlanUpstreamBase, zaiAPIBase = originalPlan, originalAPI })
}

func modelIDs(models []pluginapi.ModelInfo) []string {
	ids := make([]string, 0, len(models))
	for _, model := range models {
		ids = append(ids, model.ID)
	}
	return ids
}

// --- cache seam ---------------------------------------------------------

func TestCatalogSuccessTTLOnlyServesFreshEntries(t *testing.T) {
	catalog := newModelCatalog()
	scope := catalogScope{Environment: environmentCodingPlan, Identity: "identity-1"}
	now := fixedNow()

	catalog.recordSuccess(scope, []string{"GLM-4.7"}, time.Hour, now)
	if ids, ok := catalog.models(scope, now.Add(59*time.Minute)); !ok || len(ids) != 1 || ids[0] != "GLM-4.7" {
		t.Fatalf("inside the ttl: ids=%v ok=%v, want a fresh hit", ids, ok)
	}
	if _, ok := catalog.models(scope, now.Add(2*time.Hour)); ok {
		t.Fatal("an expired success must not be served")
	}
}

func TestCatalogFailureCooldownExpires(t *testing.T) {
	catalog := newModelCatalog()
	scope := catalogScope{Environment: environmentZai, Identity: "identity-1"}
	now := fixedNow()

	catalog.recordFailure(scope, discoveryReasonUnreachable, 5*time.Minute, now)
	if !catalog.coolingDown(scope, now.Add(4*time.Minute)) {
		t.Fatal("inside the cooldown the environment must stay cooling")
	}
	if catalog.coolingDown(scope, now.Add(6*time.Minute)) {
		t.Fatal("an elapsed cooldown must release the environment")
	}
	if _, ok := catalog.models(scope, now); ok {
		t.Fatal("a failure must never be readable as a success")
	}
}

func TestCatalogScopesAreIsolated(t *testing.T) {
	catalog := newModelCatalog()
	now := fixedNow()
	plan := catalogScope{Environment: environmentCodingPlan, Identity: "identity-1"}
	zai := catalogScope{Environment: environmentZai, Identity: "identity-1"}
	other := catalogScope{Environment: environmentCodingPlan, Identity: "identity-2"}

	catalog.recordSuccess(plan, []string{"GLM-4.7"}, time.Hour, now)
	catalog.recordFailure(zai, discoveryReasonUnreachable, 5*time.Minute, now)

	if _, ok := catalog.models(zai, now); ok {
		t.Fatal("one environment's success must not serve another")
	}
	if !catalog.coolingDown(zai, now) {
		t.Fatal("the failed environment must cool down")
	}
	if catalog.coolingDown(plan, now) || catalog.coolingDown(other, now) {
		t.Fatal("a failure must never cool a different scope")
	}
	if _, ok := catalog.models(other, now); ok {
		t.Fatal("one identity's success must not serve another identity")
	}
}

func TestCatalogFailureReplacesExpiredSuccess(t *testing.T) {
	catalog := newModelCatalog()
	scope := catalogScope{Environment: environmentCodingPlan, Identity: "identity-1"}
	now := fixedNow()

	catalog.recordSuccess(scope, []string{"GLM-4.7"}, time.Hour, now)
	later := now.Add(2 * time.Hour)
	if _, ok := catalog.models(scope, later); ok {
		t.Fatal("the entry must be expired before the failure lands")
	}
	catalog.recordFailure(scope, discoveryReasonMalformed, 5*time.Minute, later)
	if _, ok := catalog.models(scope, later); ok {
		t.Fatal("a failed re-discovery must retire the stale success")
	}
	if !catalog.coolingDown(scope, later) {
		t.Fatal("the failed re-discovery must start a cooldown")
	}
}

func TestCatalogDefensiveCopies(t *testing.T) {
	catalog := newModelCatalog()
	scope := catalogScope{Environment: environmentCodingPlan, Identity: "identity-1"}
	now := fixedNow()

	ids := []string{"GLM-4.7"}
	catalog.recordSuccess(scope, ids, time.Hour, now)
	ids[0] = "mutated"
	served, _ := catalog.models(scope, now)
	if served[0] != "GLM-4.7" {
		t.Fatal("the catalog must store its own copy of discovered ids")
	}
	served[0] = "mutated"
	again, _ := catalog.models(scope, now)
	if again[0] != "GLM-4.7" {
		t.Fatal("the catalog must hand out copies, not its storage")
	}
}

func TestCatalogScopeNeverCarriesSecrets(t *testing.T) {
	doc := catalogDoc("identity-1", "jwt-secret-value", jwtStatusActive, "key-secret-value", apiKeyStatusActive)
	snap, err := readCredentialSnapshot(doc)
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	for _, kind := range []CredentialKind{CredentialJWT, CredentialAPIKey} {
		scope := catalogScopeFor("zcode-abc.json", snap, environmentForKind(kind))
		joined := scope.Environment + "\x00" + scope.Identity
		if strings.Contains(joined, "jwt-secret-value") || strings.Contains(joined, "key-secret-value") {
			t.Fatalf("cache scope %q carries credential material", joined)
		}
	}
	scope := catalogScopeFor("zcode-abc.json", snap, environmentCodingPlan)
	if scope.Identity != "identity-1" || scope.Environment != environmentCodingPlan {
		t.Fatalf("scope = %+v, want the identity id and the environment label", scope)
	}
}

func TestCatalogScopeFallsBackToAuthIndex(t *testing.T) {
	doc := []byte(`{"zcode":{"jwt":{"token":"jwt-secret-value"},"api_key":{}}}`)
	snap, err := readCredentialSnapshot(doc)
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	scope := catalogScopeFor("zcode-abc.json", snap, environmentCodingPlan)
	if scope.Identity != "auth:zcode-abc.json" {
		t.Fatalf("scope identity = %q, want the auth index fallback", scope.Identity)
	}
}

// --- endpoint derivation -------------------------------------------------

func TestModelsEndpointURLOverridesMessagesPath(t *testing.T) {
	overrideCatalogUpstreams(t, "https://upstream.test")

	plan := modelsEndpointURLFor(CredentialJWT)
	if plan != "https://upstream.test/api/v1/zcode-plan/anthropic/v1/models" {
		t.Fatalf("plan models url = %q", plan)
	}
	zai := modelsEndpointURLFor(CredentialAPIKey)
	if zai != "https://upstream.test/api/anthropic/v1/models" {
		t.Fatalf("zai models url = %q", zai)
	}
}

// --- upstream discovery --------------------------------------------------

func TestDiscoverModelsParsesTrimsAndDeduplicates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/zcode-plan/anthropic/v1/models" {
			t.Errorf("discovery path = %q, want the environment's models endpoint", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer jwt-secret-value" {
			t.Errorf("authorization = %q, want the plan bearer", got)
		}
		if got := r.Header.Get("anthropic-version"); got != anthropicVersionValue {
			t.Errorf("anthropic-version = %q", got)
		}
		fmt.Fprint(w, `{"data":[`+
			`{"id":" GLM-4.7 "},`+
			`{"id":""},`+
			`{"id":"   "},`+
			`{"id":"GLM-4.7"},`+
			`{"id":"glm-4.7"},`+
			`{"id":"GLM-5.2"},`+
			`{"type":"model"},`+
			`{"id":42}]}`)
	}))
	defer server.Close()
	overrideCatalogUpstreams(t, server.URL)

	target, ok := buildDiscoveryTarget(CredentialJWT, credentialSnapshot{
		IdentityID: "identity-1",
		JWTToken:   "jwt-secret-value",
	}, defaultConfig())
	if !ok {
		t.Fatal("a plan credential must build a discovery target")
	}
	ids, reason := discoverModels(context.Background(), server.Client(), target)
	if reason != "" {
		t.Fatalf("reason = %q, want success", reason)
	}
	if strings.Join(ids, ",") != "GLM-4.7,GLM-5.2" {
		t.Fatalf("ids = %v, want trimmed, deduplicated, defensively parsed ids", ids)
	}
}

func TestDiscoverModelsZaiEnvironmentAuthenticatesWithTheKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/anthropic/v1/models" {
			t.Errorf("discovery path = %q, want the zai models endpoint", r.URL.Path)
		}
		if got := r.Header.Get("x-api-key"); got != "key-secret-value" {
			t.Errorf("x-api-key = %q, want the managed key", got)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("authorization = %q, want none for the key environment", got)
		}
		fmt.Fprint(w, `{"data":[{"id":"GLM-5-Turbo"}]}`)
	}))
	defer server.Close()
	overrideCatalogUpstreams(t, server.URL)

	target, ok := buildDiscoveryTarget(CredentialAPIKey, credentialSnapshot{
		IdentityID:  "identity-1",
		APIKeyToken: "key-secret-value",
	}, defaultConfig())
	if !ok {
		t.Fatal("an api key credential must build a discovery target")
	}
	ids, reason := discoverModels(context.Background(), server.Client(), target)
	if reason != "" || strings.Join(ids, ",") != "GLM-5-Turbo" {
		t.Fatalf("ids=%v reason=%q, want the zai catalog", ids, reason)
	}
}

func TestDiscoverModelsRejectsOversizedResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":[{"id":"` + strings.Repeat("x", int(maxModelDiscoveryBytes)) + `"}]}`))
	}))
	defer server.Close()
	overrideCatalogUpstreams(t, server.URL)

	target, _ := buildDiscoveryTarget(CredentialJWT, credentialSnapshot{JWTToken: "jwt-secret-value"}, defaultConfig())
	ids, reason := discoverModels(context.Background(), server.Client(), target)
	if ids != nil || reason != discoveryReasonTooLarge {
		t.Fatalf("ids=%v reason=%q, want the size limit to reject the response", ids, reason)
	}
}

func TestDiscoverModelsMalformedBodyIsNotSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html>not a model list</html>`)
	}))
	defer server.Close()
	overrideCatalogUpstreams(t, server.URL)

	target, _ := buildDiscoveryTarget(CredentialJWT, credentialSnapshot{JWTToken: "jwt-secret-value"}, defaultConfig())
	ids, reason := discoverModels(context.Background(), server.Client(), target)
	if ids != nil || reason != discoveryReasonMalformed {
		t.Fatalf("ids=%v reason=%q, want a malformed response refusal", ids, reason)
	}
}

func TestDiscoverModelsEmptyCatalogIsNotSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":[]}`)
	}))
	defer server.Close()
	overrideCatalogUpstreams(t, server.URL)

	target, _ := buildDiscoveryTarget(CredentialJWT, credentialSnapshot{JWTToken: "jwt-secret-value"}, defaultConfig())
	ids, reason := discoverModels(context.Background(), server.Client(), target)
	if ids != nil || reason != discoveryReasonEmpty {
		t.Fatalf("ids=%v reason=%q, want an empty catalog refusal", ids, reason)
	}
}

func TestDiscoverModelsErrorStatusIsSanitized(t *testing.T) {
	body := `{"detail":"internal path /secret/vault leaked; account acc-123 is over drawn"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, body, http.StatusForbidden)
	}))
	defer server.Close()
	overrideCatalogUpstreams(t, server.URL)

	target, _ := buildDiscoveryTarget(CredentialJWT, credentialSnapshot{JWTToken: "jwt-secret-value"}, defaultConfig())
	ids, reason := discoverModels(context.Background(), server.Client(), target)
	if ids != nil {
		t.Fatalf("ids = %v, want none from a rejected discovery", ids)
	}
	if reason != "upstream_status_403" {
		t.Fatalf("reason = %q, want the bare status code without upstream body content", reason)
	}
}

func TestDiscoverModelsUnreachableUpstream(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	overrideCatalogUpstreams(t, server.URL)
	target, _ := buildDiscoveryTarget(CredentialJWT, credentialSnapshot{JWTToken: "jwt-secret-value"}, defaultConfig())
	server.Close()

	ids, reason := discoverModels(context.Background(), server.Client(), target)
	if ids != nil || reason != discoveryReasonUnreachable {
		t.Fatalf("ids=%v reason=%q, want the unreachable reason", ids, reason)
	}
}

func TestDiscoverModelsTimesOut(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer server.Close()
	defer close(release)
	overrideCatalogUpstreams(t, server.URL)

	bounded := &http.Client{Timeout: 50 * time.Millisecond}
	target, _ := buildDiscoveryTarget(CredentialJWT, credentialSnapshot{JWTToken: "jwt-secret-value"}, defaultConfig())
	done := make(chan struct{})
	var ids []string
	var reason string
	go func() {
		ids, reason = discoverModels(context.Background(), bounded, target)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("discovery outlived its client timeout")
	}
	if ids != nil || reason != discoveryReasonUnreachable {
		t.Fatalf("ids=%v reason=%q, want the bounded call to fail closed", ids, reason)
	}
}

func TestBuildDiscoveryTargetRequiresMaterial(t *testing.T) {
	if _, ok := buildDiscoveryTarget(CredentialJWT, credentialSnapshot{IdentityID: "identity-1"}, defaultConfig()); ok {
		t.Fatal("a plan environment without jwt material must not be discovered")
	}
	if _, ok := buildDiscoveryTarget(CredentialAPIKey, credentialSnapshot{IdentityID: "identity-1"}, defaultConfig()); ok {
		t.Fatal("a key environment without key material must not be discovered")
	}
}

// --- orchestration -------------------------------------------------------

// catalogUpstream scripts per-path discovery answers: the given path returns
// that many 200 responses before degrading, and unlisted paths always fail.
// Both environments discover concurrently, so success budgets must be keyed
// by path to stay deterministic.
type catalogUpstream struct {
	mu     sync.Mutex
	calls  map[string]*int32
	server *httptest.Server
}

func newCatalogUpstream(t *testing.T, successes map[string]int) *catalogUpstream {
	t.Helper()
	up := &catalogUpstream{calls: map[string]*int32{}}
	remaining := make(map[string]*int32, len(successes))
	for path, count := range successes {
		budget := int32(count)
		remaining[path] = &budget
	}
	up.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		counter := up.callCounter(r.URL.Path)
		atomic.AddInt32(counter, 1)
		if budget, ok := remaining[r.URL.Path]; ok && atomic.AddInt32(budget, -1) >= 0 {
			fmt.Fprint(w, `{"data":[{"id":"GLM-4.7"},{"id":"GLM-5.2"}]}`)
			return
		}
		http.Error(w, `{"error":{"message":"upstream degraded"}}`, http.StatusInternalServerError)
	}))
	t.Cleanup(up.server.Close)
	overrideCatalogUpstreams(t, up.server.URL)
	return up
}

func (u *catalogUpstream) callCounter(path string) *int32 {
	u.mu.Lock()
	defer u.mu.Unlock()
	if counter, ok := u.calls[path]; ok {
		return counter
	}
	counter := new(int32)
	u.calls[path] = counter
	return counter
}

func (u *catalogUpstream) callsFor(path string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	if counter, ok := u.calls[path]; ok {
		return int(atomic.LoadInt32(counter))
	}
	return 0
}

const (
	planModelsPath = "/api/v1/zcode-plan/anthropic/v1/models"
	zaiModelsPath  = "/api/anthropic/v1/models"
)

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return raw
}

func TestModelsForAuthStaticOnlyWhenNotLoggedIn(t *testing.T) {
	up := newCatalogUpstream(t, map[string]int{planModelsPath: 2, zaiModelsPath: 2})
	catalog := newModelCatalog()
	cfg := normalizeConfig(defaultConfig())

	for name, doc := range map[string][]byte{
		"empty document":     nil,
		"undecodable":        []byte(`not json`),
		"without credential": []byte(`{"other":"host-owned"}`),
	} {
		models := modelsForAuth(context.Background(), cfg, catalog, "zcode-abc.json", doc, fixedNow())
		if got := strings.Join(modelIDs(models), ","); got != "GLM-5.2,GLM-5-Turbo" {
			t.Fatalf("%s: ids = %q, want the static base", name, got)
		}
	}
	if total := up.callsFor(planModelsPath) + up.callsFor(zaiModelsPath); total != 0 {
		t.Fatalf("an anonymous identity must not discover, got %d calls", total)
	}
}

func TestModelsForAuthDiscoveryDisabledKeepsStatic(t *testing.T) {
	up := newCatalogUpstream(t, map[string]int{planModelsPath: 2, zaiModelsPath: 2})
	catalog := newModelCatalog()
	cfg := normalizeConfig(defaultConfig())
	cfg.ModelDiscovery.Enabled = boolPtr(false)

	doc := catalogDoc("identity-1", testJWT, jwtStatusActive, testAPIKeyMaterial, apiKeyStatusActive)
	models := modelsForAuth(context.Background(), cfg, catalog, "zcode-abc.json", doc, fixedNow())
	if got := strings.Join(modelIDs(models), ","); got != "GLM-5.2,GLM-5-Turbo" {
		t.Fatalf("ids = %q, want the static base", got)
	}
	if total := up.callsFor(planModelsPath) + up.callsFor(zaiModelsPath); total != 0 {
		t.Fatalf("disabled discovery must not reach the upstream, got %d calls", total)
	}
}

func TestModelsForAuthSupplementsStaticOnSuccess(t *testing.T) {
	up := newCatalogUpstream(t, map[string]int{planModelsPath: 2, zaiModelsPath: 2})
	catalog := newModelCatalog()
	cfg := normalizeConfig(defaultConfig())
	doc := catalogDoc("identity-1", testJWT, jwtStatusActive, testAPIKeyMaterial, apiKeyStatusActive)

	models := modelsForAuth(context.Background(), cfg, catalog, "zcode-abc.json", doc, fixedNow())
	if got := strings.Join(modelIDs(models), ","); got != "GLM-5.2,GLM-5-Turbo,GLM-4.7" {
		t.Fatalf("ids = %q, want the static base plus the discovered supplement", got)
	}
	for _, model := range models {
		if (model.ID == "GLM-5.2" || model.ID == "GLM-5-Turbo") && !model.UserDefined {
			t.Fatalf("static model %q must stay user-defined", model.ID)
		}
		if model.ID == "GLM-4.7" && model.UserDefined {
			t.Fatal("a discovered supplement must not be marked user-defined")
		}
	}

	// Inside the success TTL the cached answer serves without new calls.
	models = modelsForAuth(context.Background(), cfg, catalog, "zcode-abc.json", doc, fixedNow().Add(time.Minute))
	if got := strings.Join(modelIDs(models), ","); got != "GLM-5.2,GLM-5-Turbo,GLM-4.7" {
		t.Fatalf("cached ids = %q", got)
	}
	if total := up.callsFor(planModelsPath) + up.callsFor(zaiModelsPath); total != 2 {
		t.Fatalf("discovery calls = %d, want one per environment", total)
	}

	// After the TTL both environments discover again.
	models = modelsForAuth(context.Background(), cfg, catalog, "zcode-abc.json", doc, fixedNow().Add(2*time.Hour))
	if got := strings.Join(modelIDs(models), ","); got != "GLM-5.2,GLM-5-Turbo,GLM-4.7" {
		t.Fatalf("refreshed ids = %q", got)
	}
	if total := up.callsFor(planModelsPath) + up.callsFor(zaiModelsPath); total != 4 {
		t.Fatalf("discovery calls = %d, want one more per environment after the ttl", total)
	}
}

func TestModelsForAuthFailureKeepsStaticAndCoolsDown(t *testing.T) {
	up := newCatalogUpstream(t, map[string]int{}) // every discovery fails
	catalog := newModelCatalog()
	cfg := normalizeConfig(defaultConfig())
	doc := catalogDoc("identity-1", testJWT, jwtStatusActive, testAPIKeyMaterial, apiKeyStatusActive)

	models := modelsForAuth(context.Background(), cfg, catalog, "zcode-abc.json", doc, fixedNow())
	if got := strings.Join(modelIDs(models), ","); got != "GLM-5.2,GLM-5-Turbo" {
		t.Fatalf("ids = %q, want the static base after failed discovery", got)
	}
	if total := up.callsFor(planModelsPath) + up.callsFor(zaiModelsPath); total != 2 {
		t.Fatalf("discovery calls = %d, want one per environment", total)
	}

	// Inside the failure cooldown no environment is retried.
	models = modelsForAuth(context.Background(), cfg, catalog, "zcode-abc.json", doc, fixedNow().Add(time.Minute))
	if got := strings.Join(modelIDs(models), ","); got != "GLM-5.2,GLM-5-Turbo" {
		t.Fatalf("cooled ids = %q, want the static base", got)
	}
	if total := up.callsFor(planModelsPath) + up.callsFor(zaiModelsPath); total != 2 {
		t.Fatalf("a cooled environment must not rediscover, got %d calls", total)
	}

	// After the cooldown both environments try again.
	modelsForAuth(context.Background(), cfg, catalog, "zcode-abc.json", doc, fixedNow().Add(6*time.Minute))
	if total := up.callsFor(planModelsPath) + up.callsFor(zaiModelsPath); total != 4 {
		t.Fatalf("an elapsed cooldown must rediscover, got %d calls", total)
	}
}

func TestModelsForAuthInvalidResponseIsNotCachedAsSuccess(t *testing.T) {
	// The plan environment answers successfully once; the key environment
	// never does. Budgets are per path because both environments discover
	// concurrently.
	up := newCatalogUpstream(t, map[string]int{planModelsPath: 1})
	catalog := newModelCatalog()
	cfg := normalizeConfig(defaultConfig())
	doc := catalogDoc("identity-1", testJWT, jwtStatusActive, testAPIKeyMaterial, apiKeyStatusActive)

	models := modelsForAuth(context.Background(), cfg, catalog, "zcode-abc.json", doc, fixedNow())
	if got := strings.Join(modelIDs(models), ","); got != "GLM-5.2,GLM-5-Turbo,GLM-4.7" {
		t.Fatalf("ids = %q, want the healthy environment's supplement", got)
	}
	if calls := up.callsFor(zaiModelsPath); calls != 1 {
		t.Fatalf("zai discovery calls = %d, want the failed attempt", calls)
	}

	// The failed environment cools down instead of caching its failure as a
	// success; the healthy one keeps serving its cached ids.
	models = modelsForAuth(context.Background(), cfg, catalog, "zcode-abc.json", doc, fixedNow().Add(time.Minute))
	if got := strings.Join(modelIDs(models), ","); got != "GLM-5.2,GLM-5-Turbo,GLM-4.7" {
		t.Fatalf("ids = %q, want the cached supplement to survive the other's failure", got)
	}
	if calls := up.callsFor(zaiModelsPath); calls != 1 {
		t.Fatalf("a cooled environment must not rediscover, got %d calls", calls)
	}

	// After the cooldown the failed environment retries against the upstream
	// rather than promoting its failure to a cached answer.
	models = modelsForAuth(context.Background(), cfg, catalog, "zcode-abc.json", doc, fixedNow().Add(6*time.Minute))
	if got := strings.Join(modelIDs(models), ","); got != "GLM-5.2,GLM-5-Turbo,GLM-4.7" {
		t.Fatalf("ids = %q, want the still-healthy cached supplement", got)
	}
	if calls := up.callsFor(zaiModelsPath); calls != 2 {
		t.Fatalf("zai discovery calls = %d, want the cooled retry to have run", calls)
	}
	if calls := up.callsFor(planModelsPath); calls != 1 {
		t.Fatalf("plan discovery calls = %d, want the success ttl to keep serving", calls)
	}
}

func TestModelsForAuthIdentitiesDiscoverIndependently(t *testing.T) {
	up := newCatalogUpstream(t, map[string]int{planModelsPath: 2, zaiModelsPath: 2})
	catalog := newModelCatalog()
	cfg := normalizeConfig(defaultConfig())
	first := catalogDoc("identity-1", testJWT, jwtStatusActive, "", "")
	second := catalogDoc("identity-2", testJWT, jwtStatusActive, "", "")

	modelsForAuth(context.Background(), cfg, catalog, "zcode-a.json", first, fixedNow())
	if got := strings.Join(modelIDs(modelsForAuth(context.Background(), cfg, catalog, "zcode-b.json", second, fixedNow())), ","); got != "GLM-5.2,GLM-5-Turbo,GLM-4.7" {
		t.Fatalf("the second identity inherited the first's catalog: %q", got)
	}
	if total := up.callsFor(planModelsPath); total != 2 {
		t.Fatalf("plan discovery calls = %d, want one per identity", total)
	}
}

func TestModelsForAuthUnusableCredentialSkipsItsEnvironment(t *testing.T) {
	up := newCatalogUpstream(t, map[string]int{planModelsPath: 1, zaiModelsPath: 1})
	catalog := newModelCatalog()
	cfg := normalizeConfig(defaultConfig())
	// An invalid JWT skips the plan environment; the key environment still
	// discovers, mirroring how execution routes to the fallback credential.
	doc := catalogDoc("identity-1", testJWT, jwtStatusInvalid, testAPIKeyMaterial, apiKeyStatusActive)

	models := modelsForAuth(context.Background(), cfg, catalog, "zcode-abc.json", doc, fixedNow())
	if got := strings.Join(modelIDs(models), ","); got != "GLM-5.2,GLM-5-Turbo,GLM-4.7" {
		t.Fatalf("ids = %q, want the key environment's supplement", got)
	}
	if calls := up.callsFor(planModelsPath); calls != 0 {
		t.Fatalf("plan discovery calls = %d, want the unusable credential skipped", calls)
	}
	if calls := up.callsFor(zaiModelsPath); calls != 1 {
		t.Fatalf("zai discovery calls = %d, want the usable credential discovered", calls)
	}
}

func TestModelsForAuthLegacyDocumentWithoutIdentityStillCachesPerAuth(t *testing.T) {
	up := newCatalogUpstream(t, map[string]int{planModelsPath: 1, zaiModelsPath: 1})
	catalog := newModelCatalog()
	cfg := normalizeConfig(defaultConfig())
	doc := []byte(`{"zcode":{"jwt":{"token":"` + testJWT + `","status":"active"}}}`)

	models := modelsForAuth(context.Background(), cfg, catalog, "zcode-abc.json", doc, fixedNow())
	if got := strings.Join(modelIDs(models), ","); got != "GLM-5.2,GLM-5-Turbo,GLM-4.7" {
		t.Fatalf("ids = %q, want the discovered supplement", got)
	}
	// The same document again is served from the auth-index-scoped cache.
	modelsForAuth(context.Background(), cfg, catalog, "zcode-abc.json", doc, fixedNow().Add(time.Minute))
	if calls := up.callsFor(planModelsPath); calls != 1 {
		t.Fatalf("plan discovery calls = %d, want the auth-scoped cache to serve", calls)
	}
	// A different auth record is a different scope and discovers on its own.
	modelsForAuth(context.Background(), cfg, catalog, "zcode-other.json", doc, fixedNow().Add(time.Minute))
	if calls := up.callsFor(planModelsPath); calls != 2 {
		t.Fatalf("plan discovery calls = %d, want one per auth record", calls)
	}
}

// --- dispatch -------------------------------------------------------------

func TestHandleModelForAuthReturnsUnion(t *testing.T) {
	up := newCatalogUpstream(t, map[string]int{planModelsPath: 2, zaiModelsPath: 2})
	originalCatalog := activeModelCatalog
	activeModelCatalog = newModelCatalog()
	t.Cleanup(func() { activeModelCatalog = originalCatalog })

	request := mustJSON(t, pluginapi.AuthModelRequest{
		AuthID:      "zcode-abc.json",
		StorageJSON: catalogDoc("identity-1", testJWT, jwtStatusActive, testAPIKeyMaterial, apiKeyStatusActive),
	})
	env := callMethod(t, pluginabi.MethodModelForAuth, request)
	if !env.OK {
		t.Fatalf("model.for_auth failed: %+v", env.Error)
	}
	var response pluginapi.ModelResponse
	if err := json.Unmarshal(env.Result, &response); err != nil {
		t.Fatalf("decode model response: %v", err)
	}
	if response.Provider != pluginID {
		t.Fatalf("provider = %q, want %q", response.Provider, pluginID)
	}
	if got := strings.Join(modelIDs(response.Models), ","); got != "GLM-5.2,GLM-5-Turbo,GLM-4.7" {
		t.Fatalf("ids = %q, want the union catalog", got)
	}
	if total := up.callsFor(planModelsPath) + up.callsFor(zaiModelsPath); total != 2 {
		t.Fatalf("discovery calls = %d, want one per environment", total)
	}
}

func TestHandleModelForAuthSurvivesUndecodableRequest(t *testing.T) {
	originalCatalog := activeModelCatalog
	activeModelCatalog = newModelCatalog()
	t.Cleanup(func() { activeModelCatalog = originalCatalog })

	env := callMethod(t, pluginabi.MethodModelForAuth, []byte(`{"AuthID":`))
	if !env.OK {
		t.Fatalf("an undecodable request must still serve the static catalog, got %+v", env.Error)
	}
	var response pluginapi.ModelResponse
	if err := json.Unmarshal(env.Result, &response); err != nil {
		t.Fatalf("decode model response: %v", err)
	}
	if got := strings.Join(modelIDs(response.Models), ","); got != "GLM-5.2,GLM-5-Turbo" {
		t.Fatalf("ids = %q, want the static base", got)
	}
}

func TestModelStaticStaysStatic(t *testing.T) {
	up := newCatalogUpstream(t, map[string]int{planModelsPath: 2, zaiModelsPath: 2})
	env := callMethod(t, pluginabi.MethodModelStatic, nil)
	if !env.OK {
		t.Fatalf("model.static failed: %+v", env.Error)
	}
	var response pluginapi.ModelResponse
	if err := json.Unmarshal(env.Result, &response); err != nil {
		t.Fatalf("decode model response: %v", err)
	}
	if got := strings.Join(modelIDs(response.Models), ","); got != "GLM-5.2,GLM-5-Turbo" {
		t.Fatalf("ids = %q, want the static base only", got)
	}
	if total := up.callsFor(planModelsPath) + up.callsFor(zaiModelsPath); total != 0 {
		t.Fatalf("model.static must not discover, got %d calls", total)
	}
}
