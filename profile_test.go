package main

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func testConfig() Config {
	return defaultConfig()
}

func testAuthDoc(token, status string) []byte {
	return []byte(`{"type":"zcode","other":"host-owned","zcode":{"identity_id":"zcode-user-1","jwt":{"token":"` + token + `","status":"` + status + `"}}}`)
}

func TestPrimaryProfileUsesJWTPrimaryCredential(t *testing.T) {
	original := zcodePlanUpstreamBase
	zcodePlanUpstreamBase = "https://upstream.test"
	t.Cleanup(func() { zcodePlanUpstreamBase = original })

	plan := executionPlan(testAuthDoc("jwt-token-1", jwtStatusActive), testConfig(), "glm-5.2", nil, time.Now())
	if plan.Failure != nil {
		t.Fatalf("executionPlan: %+v", plan.Failure)
	}
	profile := plan.Primary
	if profile.CredentialKind != CredentialJWT {
		t.Fatalf("credential kind = %q, want jwt", profile.CredentialKind)
	}
	if profile.IdentityID != "zcode-user-1" {
		t.Fatalf("identity = %q", profile.IdentityID)
	}
	if profile.MessagesURL != "https://upstream.test/api/v1/zcode-plan/anthropic/v1/messages" {
		t.Fatalf("messages url = %q", profile.MessagesURL)
	}
	if profile.ModelID != "GLM-5.2" {
		t.Fatalf("model = %q, want GLM-5.2", profile.ModelID)
	}
	if got := profile.Headers.Get("Authorization"); got != "Bearer jwt-token-1" {
		t.Fatalf("authorization = %q", got)
	}
	if got := profile.Headers.Get("x-api-key"); got != "" {
		t.Fatalf("the jwt profile must not carry an api key: %q", got)
	}
	if got := profile.Headers.Get("anthropic-version"); got != anthropicVersionValue {
		t.Fatalf("anthropic-version = %q", got)
	}
	if got := profile.Headers.Get("User-Agent"); got != zcodeUserAgent(testConfig().Product.AppVersion) {
		t.Fatalf("user agent = %q", got)
	}
	if profile.Headers.Get("X-ZCode-App-Version") == "" || profile.Headers.Get("X-ZCode-Agent") == "" {
		t.Fatalf("product headers missing: %v", profile.Headers)
	}
	cfg := normalizeConfig(testConfig())
	if profile.MaxResponseBytes != cfg.Upstream.MaxResponseBytes {
		t.Fatalf("max response bytes = %d, want %d", profile.MaxResponseBytes, cfg.Upstream.MaxResponseBytes)
	}
	if profile.ConnectTimeout != time.Duration(cfg.Upstream.ConnectTimeoutSeconds)*time.Second {
		t.Fatalf("connect timeout = %v", profile.ConnectTimeout)
	}
}

func TestFallbackProfileUsesManagedAPIKey(t *testing.T) {
	originalPlan, originalAPI := zcodePlanUpstreamBase, zaiAPIBase
	zcodePlanUpstreamBase = "https://upstream.test"
	zaiAPIBase = "https://api.test"
	t.Cleanup(func() { zcodePlanUpstreamBase, zaiAPIBase = originalPlan, originalAPI })

	doc := []byte(`{"zcode":{"identity_id":"zcode-user-1","jwt":{"token":"jwt-token-1","status":"` +
		jwtStatusInvalid + `"},"api_key":{"status":"active","key_material":"key-1.secret"}}}`)
	plan := executionPlan(doc, testConfig(), "glm-5.2", nil, time.Now())
	if plan.Failure != nil {
		t.Fatalf("executionPlan: %+v", plan.Failure)
	}
	primary, profiles := plan.Primary, plan.Attempts
	// The blocked jwt is skipped entirely: the managed key serves the request
	// on its own and the caller's failure, if any, is the jwt's block.
	if primary.CredentialKind != CredentialAPIKey {
		t.Fatalf("primary = %q, want the managed api key", primary.CredentialKind)
	}
	if len(profiles) != 1 || profiles[0].CredentialKind != CredentialAPIKey {
		t.Fatalf("profiles = %+v, want only the managed key", profiles)
	}
	if primary.MessagesURL != "https://api.test/api/anthropic/v1/messages" {
		t.Fatalf("messages url = %q", primary.MessagesURL)
	}
	if got := primary.Headers.Get("x-api-key"); got != "key-1.secret" {
		t.Fatalf("x-api-key = %q", got)
	}
	if got := primary.Headers.Get("Authorization"); got != "" {
		t.Fatalf("the key profile must not carry a bearer token: %q", got)
	}
	if primary.Headers.Get("anthropic-version") != anthropicVersionValue {
		t.Fatalf("product headers are missing from the key profile: %v", primary.Headers)
	}
}

func TestProfilesAreImmutablePerRequest(t *testing.T) {
	doc := testAuthDoc("jwt-token-1", "")
	first := executionPlan(doc, testConfig(), "GLM-5.2", nil, time.Now())
	if first.Failure != nil {
		t.Fatalf("executionPlan: %+v", first.Failure)
	}
	// Mutating one profile's headers must not affect the next request.
	first.Primary.Headers.Set("Authorization", "Bearer tampered")
	first.Primary.Headers.Set("X-Injected", "yes")
	second := executionPlan(doc, testConfig(), "GLM-5.2", nil, time.Now())
	if second.Failure != nil {
		t.Fatalf("executionPlan: %+v", second.Failure)
	}
	if got := second.Primary.Headers.Get("Authorization"); got != "Bearer jwt-token-1" {
		t.Fatalf("authorization = %q, want the untouched credential", got)
	}
	if second.Primary.Headers.Get("X-Injected") != "" {
		t.Fatal("mutation leaked into the next profile")
	}
}

func TestExecutionPlanRejectsMissingCredentials(t *testing.T) {
	for _, doc := range [][]byte{
		nil,
		[]byte(`{}`),
		[]byte(`{"zcode":{"identity_id":"x"}}`),
		[]byte(`not json`),
	} {
		if failure := executionPlan(doc, testConfig(), "GLM-5.2", nil, time.Now()).Failure; failure == nil {
			t.Fatalf("doc %q: expected an error", doc)
		} else if failure.Code != "no_credential" || failure.ClientStatus != http.StatusUnauthorized {
			t.Fatalf("doc %q: failure = %+v", doc, failure)
		}
	}
}

func TestExecutionPlanSkipsBlockedCredentialStates(t *testing.T) {
	cases := map[string]struct {
		status   string
		code     string
		class    failureClass
		client   int
		windowed bool
	}{
		"invalid":              {jwtStatusInvalid, "credential_invalid", failureInvalid, http.StatusUnauthorized, false},
		"exhausted":            {jwtStatusExhausted, "credential_quota_exhausted", failureExhausted, http.StatusPaymentRequired, false},
		"verification_blocked": {jwtStatusVerificationBlocked, "credential_verification_blocked", failureVerificationBlocked, http.StatusForbidden, true},
		"cooldown":             {jwtStatusCooldown, "credential_cooling_down", failureCooldown, http.StatusServiceUnavailable, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// A JWT-only record has no fallback: the blocked primary is the
			// caller's failure and the upstream is never contacted. The two
			// windowed states carry a deadline that has not elapsed, which is
			// what keeps them out of use; a windowed state with no recorded
			// deadline has already recovered and is covered by
			// TestVerificationBlockRetryWindowElapses.
			doc := testAuthDoc("jwt-token-1", tc.status)
			if tc.windowed {
				doc = withRetryWindow(t, doc, time.Now().Add(time.Minute))
			}
			failure := executionPlan(doc, testConfig(), "GLM-5.2", nil, time.Now()).Failure
			if failure == nil {
				t.Fatal("expected a classified failure")
			}
			if failure.Code != tc.code || failure.Class != tc.class || failure.ClientStatus != tc.client {
				t.Fatalf("failure = %+v, want code %s class %s status %d", failure, tc.code, tc.class, tc.client)
			}
			// Blocked-state errors are sanitized: they never quote the token.
			if strings.Contains(failure.Message, "jwt-token-1") {
				t.Fatalf("failure message leaks the credential: %q", failure.Message)
			}
		})
	}
}

func TestExecutionPlanAllowsActiveAndUnknownStatus(t *testing.T) {
	// Empty status (legacy document) and unknown status strings stay usable:
	// the upstream verifies the token on every request.
	for _, status := range []string{"", jwtStatusActive, "some-future-state"} {
		plan := executionPlan(testAuthDoc("jwt-token-1", status), testConfig(), "GLM-5.2", nil, time.Now())
		if plan.Failure != nil {
			t.Fatalf("status %q: executionPlan: %+v", status, plan.Failure)
		}
		primary, profiles := plan.Primary, plan.Attempts
		if primary.CredentialKind != CredentialJWT || profiles[0].CredentialKind != CredentialJWT {
			t.Fatalf("status %q: the jwt must stay primary", status)
		}
	}
}

func TestCallerHeaderAllowlist(t *testing.T) {
	caller := http.Header{}
	caller.Set("Authorization", "Bearer caller-secret")
	caller.Set("X-Api-Key", "caller-key")
	caller.Set("Cookie", "session=caller")
	caller.Set("Proxy-Authorization", "Basic proxy")
	caller.Set("Host", "evil.example")
	caller.Set("Connection", "close")
	caller.Set("X-ZCode-Agent", "spoofed")
	caller.Set("X-ZCode-App-Version", "9.9.9")
	caller.Set("X-Cpa-Host-Control", "internal")
	caller.Set("anthropic-beta", "feature-1,feature-2")

	headers := buildUpstreamHeaders(caller, testConfig().Product.AppVersion)
	for _, name := range []string{"X-Api-Key", "Cookie", "Proxy-Authorization", "Host", "Connection", "X-Cpa-Host-Control"} {
		if got := headers.Get(name); got != "" {
			t.Errorf("%s forwarded: %q", name, got)
		}
	}
	if got := headers.Get("X-Zcode-Agent"); got != zcodeAgentHeader {
		t.Errorf("X-ZCode-Agent = %q, want the plugin-built value", got)
	}
	if got := headers.Get("X-Zcode-App-Version"); got != testConfig().Product.AppVersion {
		t.Errorf("X-ZCode-App-Version = %q, want the plugin-built value", got)
	}
	// The caller's own Authorization never survives the filter; the credential
	// the profile authenticates with is added afterwards and never comes from
	// the caller.
	if got := headers.Get("Authorization"); got != "" {
		t.Errorf("caller authorization survived the filter: %q", got)
	}
	if got := headers.Get("Anthropic-Beta"); got != "feature-1,feature-2" {
		t.Errorf("anthropic-beta = %q, want the allowlisted caller value", got)
	}
	if got := headers.Get("Accept"); got != "text/event-stream" {
		t.Errorf("accept = %q, want text/event-stream", got)
	}
}

func TestCallerHeaderAllowlistDeniesByDefault(t *testing.T) {
	// Anything not explicitly allowlisted is denied, including headers that
	// do not exist yet.
	caller := http.Header{}
	caller.Set("X-Future-Host-Header", "value")
	if headers := buildUpstreamHeaders(caller, testConfig().Product.AppVersion); headers.Get("X-Future-Host-Header") != "" {
		t.Fatal("unknown caller header was forwarded")
	}
}

func TestNormalizeRequestModel(t *testing.T) {
	catalog := []string{"GLM-5.2", "GLM-5-Turbo"}
	cases := map[string]string{
		"GLM-5.2":            "GLM-5.2",
		"glm-5.2":            "GLM-5.2",
		"  glm-5-turbo  ":    "GLM-5-Turbo",
		"zcode/GLM-5.2":      "GLM-5.2",
		"openai/glm-5-turbo": "GLM-5-Turbo",
		"glm-turbo":          "GLM-5-Turbo",
		"unknown-model":      "unknown-model",
		"GLM-4.7":            "GLM-4.7",
		"":                   "",
		"   ":                "",
	}
	for input, want := range cases {
		if got := normalizeRequestModel(input, catalog); got != want {
			t.Errorf("normalizeRequestModel(%q) = %q, want %q", input, got, want)
		}
	}
}
