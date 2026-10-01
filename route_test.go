package main

import (
	"net/http"
	"testing"
)

// The route resolver is the single seam for URL, authentication shape, billing
// domain, and gateway status. These tests pin its pure decisions: direct
// routes stay direct, the gateway rewrite matches its exact endpoint only,
// and the executor's cross-billing-domain fallback rule refuses request-level
// verdicts.

func TestResolveRoutePlanJWTIsTheDirectOfficialPath(t *testing.T) {
	// The Start Plan JWT route is the official client's own direct path
	// (source-confirmed). It is never gateway-rewritten and spends the plan's
	// entitlement.
	route := resolveRoute(CredentialJWT)
	if route.ID != routeIDPlanJWT {
		t.Errorf("route id = %q, want %q", route.ID, routeIDPlanJWT)
	}
	if route.URL != messagesEndpointURL() {
		t.Errorf("url = %q, want the direct zcode-plan messages endpoint", route.URL)
	}
	if route.AuthMode != authBearerJWT {
		t.Errorf("auth mode = %q, want %q", route.AuthMode, authBearerJWT)
	}
	if route.BillingDomain != billingPlanEntitlement {
		t.Errorf("billing domain = %q, want %q", route.BillingDomain, billingPlanEntitlement)
	}
	if route.GatewayRewritten {
		t.Error("the plan JWT route must never be gateway-rewritten")
	}
}

func TestResolveRouteManagedKeyIsTheDirectZAIPath(t *testing.T) {
	route := resolveRoute(CredentialAPIKey)
	if route.ID != routeIDManagedKey {
		t.Errorf("route id = %q, want %q", route.ID, routeIDManagedKey)
	}
	if route.URL != zaiMessagesEndpointURL() {
		t.Errorf("url = %q, want the direct z.ai messages endpoint", route.URL)
	}
	if route.AuthMode != authAPIKey {
		t.Errorf("auth mode = %q, want %q", route.AuthMode, authAPIKey)
	}
	if route.BillingDomain != billingAPIBalance {
		t.Errorf("billing domain = %q, want %q", route.BillingDomain, billingAPIBalance)
	}
	if route.GatewayRewritten {
		t.Error("no gateway route is registered, so nothing may be rewritten")
	}
}

func TestNewProfileMatchesItsRoute(t *testing.T) {
	doc := testAuthDoc("jwt-token-1", jwtStatusActive)
	doc2 := []byte(`{"zcode":{"identity_id":"zcode-user-1","api_key":{"status":"active","key_material":"key-1.secret"}}}`)
	for _, tc := range []struct {
		kind CredentialKind
		doc  []byte
	}{{CredentialJWT, doc}, {CredentialAPIKey, doc2}} {
		profile := newProfile(credentialSnapshot{
			IdentityID:  "id-1",
			JWTToken:    "jwt-token-1",
			APIKeyToken: "key-1.secret",
		}, tc.kind, normalizeConfig(testConfig()), "GLM-5.2", nil, "")
		if profile.MessagesURL != profile.Route.URL {
			t.Errorf("%s: profile url %q does not match its route url %q", tc.kind, profile.MessagesURL, profile.Route.URL)
		}
	}
}

func TestJWTProfileAuthenticatesWithBearerOnly(t *testing.T) {
	// The JWT's final wire shape — whether the route also wants the JWT in
	// x-api-key — is an open question pending an authorized capture. Until
	// then the profile declares only the bearer form, and this test pins that
	// default so it cannot drift silently.
	snap := credentialSnapshot{IdentityID: "id-1", JWTToken: "jwt-token-1"}
	profile := newProfile(snap, CredentialJWT, normalizeConfig(testConfig()), "GLM-5.2", nil, "")
	if got := profile.Headers.Get("Authorization"); got != "Bearer jwt-token-1" {
		t.Errorf("authorization = %q, want the bearer JWT", got)
	}
	if got := profile.Headers.Get("x-api-key"); got != "" {
		t.Errorf("x-api-key = %q, want it absent: an unproven wire detail is not a default", got)
	}
}

func TestApplyGatewayRoutesMatchesExactEndpointOnly(t *testing.T) {
	candidates := []gatewayRouteCandidate{
		{ProviderEndpoint: "https://api.z.ai/api/anthropic/v1/messages", GatewayPath: "/api/v1/ultra-zai/anthropic/v1/messages"},
	}
	const origin = "https://zcode.z.ai"

	// Exact endpoint match: rewritten onto the gateway origin, query kept.
	rewritten, ok := applyGatewayRoutes("https://api.z.ai/api/anthropic/v1/messages?beta=true", origin, candidates)
	if !ok || rewritten != "https://zcode.z.ai/api/v1/ultra-zai/anthropic/v1/messages?beta=true" {
		t.Fatalf("rewritten = %q ok=%v, want the gateway URL with the query preserved", rewritten, ok)
	}

	// An explicit default port matches the portless spelling.
	if _, ok := applyGatewayRoutes("https://api.z.ai:443/api/anthropic/v1/messages", origin, candidates); !ok {
		t.Fatal("an explicit 443 port must match the portless endpoint")
	}

	for name, raw := range map[string]string{
		"lookalike host suffix":   "https://api.z.ai.evil.example/api/anthropic/v1/messages",
		"lookalike host prefix":   "https://evil-api.z.ai/api/anthropic/v1/messages",
		"different host":          "https://evil.example/api/anthropic/v1/messages",
		"custom port":             "https://api.z.ai:8443/api/anthropic/v1/messages",
		"plain http":              "http://api.z.ai/api/anthropic/v1/messages",
		"extra path segment":      "https://api.z.ai/api/anthropic/v1/messages/extra",
		"shorter path":            "https://api.z.ai/api/anthropic/v1",
		"other official endpoint": "https://api.z.ai/api/anthropic/v1/models",
	} {
		if rewritten, ok := applyGatewayRoutes(raw, origin, candidates); ok {
			t.Errorf("%s: %q was rewritten to %q", name, raw, rewritten)
		}
	}

	// The Start Plan JWT messages path is never a gateway candidate, even
	// though it lives on the gateway origin itself.
	if _, ok := applyGatewayRoutes(messagesEndpointURL(), origin, candidates); ok {
		t.Error("the zcode-plan JWT route must never be rewritten")
	}

	// Billing endpoints are not Messages routes: the JWT-only balance path
	// stays direct even when the gateway table is populated.
	if _, ok := applyGatewayRoutes(balanceURL("3.14.4"), origin, candidates); ok {
		t.Error("the billing balance path must not be rewritten")
	}

	// An empty table rewrites nothing — the shipped default.
	if rewritten, ok := applyGatewayRoutes("https://api.z.ai/api/anthropic/v1/messages", origin, nil); ok || rewritten != "https://api.z.ai/api/anthropic/v1/messages" {
		t.Fatalf("empty table rewrote to %q ok=%v", rewritten, ok)
	}

	// The shipped table is empty: no gateway route is active by default.
	if len(officialGatewayRoutes) != 0 {
		t.Fatalf("officialGatewayRoutes = %d entries, want 0 until a capture proves the gateway contract", len(officialGatewayRoutes))
	}
}

func TestApplyGatewayRoutesNormalizesTrailingSlash(t *testing.T) {
	candidates := []gatewayRouteCandidate{
		{ProviderEndpoint: "https://api.z.ai/api/anthropic/v1/messages", GatewayPath: "/api/v1/ultra-zai/anthropic/v1/messages"},
	}
	if _, ok := applyGatewayRoutes("https://api.z.ai/api/anthropic/v1/messages/", "https://zcode.z.ai", candidates); !ok {
		t.Fatal("a trailing slash on the provider endpoint must match, as the official matcher normalizes it")
	}
}

func TestGatewayRequestHeadersDropOnlyExplicitHost(t *testing.T) {
	// The official client's gateway hit removes exactly the explicit Host
	// header — it would pin the request to the provider host — and passes
	// method, body, and every other header through unchanged.
	headers := http.Header{}
	headers.Set("Authorization", "Bearer jwt-token-1")
	headers.Set("x-api-key", "key-1.secret")
	headers.Set("anthropic-version", anthropicVersionValue)
	headers.Set("Host", "api.z.ai")

	out := gatewayRequestHeaders(headers)
	if got := out.Get("Host"); got != "" {
		t.Errorf("Host = %q, want it removed", got)
	}
	if got := out.Get("Authorization"); got != "Bearer jwt-token-1" {
		t.Errorf("Authorization = %q, want it preserved", got)
	}
	if got := out.Get("x-api-key"); got != "key-1.secret" {
		t.Errorf("x-api-key = %q, want it preserved", got)
	}
	if got := out.Get("anthropic-version"); got != anthropicVersionValue {
		t.Errorf("anthropic-version = %q, want it preserved", got)
	}
	// The original set is not mutated.
	if headers.Get("Host") == "" {
		t.Fatal("the input header set was mutated")
	}
}

func TestGatewayRequestHeadersPassesNilThrough(t *testing.T) {
	if out := gatewayRequestHeaders(nil); out != nil {
		t.Fatalf("nil headers became %v", out)
	}
}

func TestFallbackAllowedAcrossBillingDomains(t *testing.T) {
	plan := ResolvedProfile{Route: resolveRoute(CredentialJWT)}
	key := ResolvedProfile{Route: resolveRoute(CredentialAPIKey)}

	failure := func(class failureClass, retryable bool) *upstreamFailure {
		return &upstreamFailure{Class: class, RetryableBeforeOutput: retryable}
	}

	// Credential-level verdicts may cross the billing-domain boundary: a
	// different credential can actually cure them.
	for _, class := range []failureClass{
		failureVerificationBlocked, failureInvalid, failureExhausted, failurePlanExpired, failureCooldown,
	} {
		if !fallbackAllowed(plan, failure(class, true), key) {
			t.Errorf("class %q must be allowed to fall back across billing domains", class)
		}
	}

	// Request-level verdicts may not: a different credential cannot cure
	// them, and serving them on the key route would silently spend the
	// account's API balance for a request the plan route refused.
	if fallbackAllowed(plan, failure(failureRejected, true), key) {
		t.Error("a request-level rejection must not replay onto the API-key billing domain")
	}
	if fallbackAllowed(plan, failure(failureRejected, false), key) {
		t.Error("a non-retryable failure must not replay at all")
	}

	// Transport/host verdicts that permit no further attempt stay final.
	if fallbackAllowed(plan, failure(failureInterrupted, false), key) {
		t.Error("an interrupted execution must not replay")
	}
	if fallbackAllowed(plan, nil, key) {
		t.Error("a missing failure must not replay")
	}

	// The same billing domain needs no crossing, so any retryable failure may
	// move to the next credential on it.
	if !fallbackAllowed(plan, failure(failureRejected, true), ResolvedProfile{Route: resolveRoute(CredentialJWT)}) {
		t.Error("a retryable failure must replay within the same billing domain")
	}

	// The reverse crossing is symmetric: a key-route credential verdict may
	// hand back to a plan-domain route.
	if !fallbackAllowed(key, failure(failureCooldown, true), plan) {
		t.Error("the reverse crossing follows the same credential-verdict rule")
	}
	if fallbackAllowed(key, failure(failureRejected, true), plan) {
		t.Error("a request-level rejection must not cross back into the plan domain")
	}
}
