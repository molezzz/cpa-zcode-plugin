package main

import (
	"bytes"
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

func TestBuildProfileUsesJWTPrimaryCredential(t *testing.T) {
	original := zcodePlanUpstreamBase
	zcodePlanUpstreamBase = "https://upstream.test"
	t.Cleanup(func() { zcodePlanUpstreamBase = original })

	profile, err := buildProfile(testAuthDoc("jwt-token-1", jwtStatusActive), testConfig(), "glm-5.2", nil)
	if err != nil {
		t.Fatalf("buildProfile: %v", err)
	}
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
	if got := profile.Headers.Get("anthropic-version"); got != anthropicVersionValue {
		t.Fatalf("anthropic-version = %q", got)
	}
	if got := profile.Headers.Get("User-Agent"); got != zcodeUserAgent {
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

func TestBuildProfileIsImmutablePerRequest(t *testing.T) {
	profile, err := buildProfile(testAuthDoc("jwt-token-1", ""), testConfig(), "GLM-5.2", nil)
	if err != nil {
		t.Fatalf("buildProfile: %v", err)
	}
	// Mutating one profile's headers must not affect the next request.
	profile.Headers.Set("Authorization", "Bearer tampered")
	profile.Headers.Set("X-Injected", "yes")
	next, err := buildProfile(testAuthDoc("jwt-token-1", ""), testConfig(), "GLM-5.2", nil)
	if err != nil {
		t.Fatalf("second buildProfile: %v", err)
	}
	if got := next.Headers.Get("Authorization"); got != "Bearer jwt-token-1" {
		t.Fatalf("authorization = %q, want the untouched credential", got)
	}
	if next.Headers.Get("X-Injected") != "" {
		t.Fatal("mutation leaked into the next profile")
	}
}

func TestBuildProfileRejectsMissingJWT(t *testing.T) {
	for _, doc := range [][]byte{
		nil,
		[]byte(`{}`),
		[]byte(`{"zcode":{"identity_id":"x"}}`),
		[]byte(`not json`),
	} {
		if _, err := buildProfile(doc, testConfig(), "GLM-5.2", nil); err == nil {
			t.Fatalf("doc %q: expected an error", doc)
		}
	}
	profiles, failure := executionProfiles([]byte(`{}`), testConfig(), "GLM-5.2", nil)
	if profiles != nil || failure == nil {
		t.Fatalf("executionProfiles on missing credential = %v, %v", profiles, failure)
	}
	if failure.Code != "no_credential" || failure.ClientStatus != http.StatusUnauthorized {
		t.Fatalf("failure = %+v", failure)
	}
}

func TestBuildProfileRejectsBlockedJWTStates(t *testing.T) {
	cases := map[string]struct {
		status string
		code   string
		class  failureClass
		client int
	}{
		"invalid":              {jwtStatusInvalid, "credential_invalid", failureInvalid, http.StatusUnauthorized},
		"exhausted":            {jwtStatusExhausted, "credential_quota_exhausted", failureExhausted, http.StatusPaymentRequired},
		"verification_blocked": {jwtStatusVerificationBlocked, "credential_verification_blocked", failureVerificationBlocked, http.StatusForbidden},
		"cooldown":             {jwtStatusCooldown, "credential_cooling_down", failureCooldown, http.StatusServiceUnavailable},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := buildProfile(testAuthDoc("jwt-token-1", tc.status), testConfig(), "GLM-5.2", nil)
			if err == nil {
				t.Fatal("blocked credential must not build a profile")
			}
			_, failure := executionProfiles(testAuthDoc("jwt-token-1", tc.status), testConfig(), "GLM-5.2", nil)
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

func TestBuildProfileAllowsActiveAndUnknownStatus(t *testing.T) {
	// Empty status (legacy document) and unknown status strings stay usable:
	// the upstream verifies the token on every request.
	for _, status := range []string{"", jwtStatusActive, "some-future-state"} {
		if _, err := buildProfile(testAuthDoc("jwt-token-1", status), testConfig(), "GLM-5.2", nil); err != nil {
			t.Fatalf("status %q: buildProfile: %v", status, err)
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

	headers := buildUpstreamHeaders("jwt-token-1", caller)
	for _, name := range []string{"X-Api-Key", "Cookie", "Proxy-Authorization", "Host", "Connection", "X-Cpa-Host-Control"} {
		if got := headers.Get(name); got != "" {
			t.Errorf("%s forwarded: %q", name, got)
		}
	}
	if got := headers.Get("X-Zcode-Agent"); got != zcodeAgentHeader {
		t.Errorf("X-ZCode-Agent = %q, want the plugin-built value", got)
	}
	if got := headers.Get("X-Zcode-App-Version"); got != zcodeAppVersionHeader {
		t.Errorf("X-ZCode-App-Version = %q, want the plugin-built value", got)
	}
	if got := headers.Get("Authorization"); got != "Bearer jwt-token-1" {
		t.Errorf("authorization = %q, want the host-managed credential", got)
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
	if headers := buildUpstreamHeaders("jwt", caller); headers.Get("X-Future-Host-Header") != "" {
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

func TestNormalizeRequestModelInPayload(t *testing.T) {
	payload := []byte(`{"model":"glm-5.2","max_tokens":17000000000000000000,"messages":[{"role":"user","content":"hi"}]}`)
	out, model, err := normalizeRequestModelInPayload(payload, []string{"GLM-5.2", "GLM-5-Turbo"})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if model != "GLM-5.2" {
		t.Fatalf("model = %q", model)
	}
	if !bytes.Contains(out, []byte(`17000000000000000000`)) {
		t.Fatalf("big integer precision lost: %s", out)
	}
	if !bytes.Contains(out, []byte(`"messages"`)) {
		t.Fatalf("messages lost: %s", out)
	}
}

func TestNormalizeRequestModelInPayloadPassThrough(t *testing.T) {
	// Missing model and unknown models keep the payload byte-identical.
	for _, payload := range [][]byte{
		[]byte(`{"messages":[]}`),
		[]byte(`{"model":"custom-model","messages":[]}`),
	} {
		out, _, err := normalizeRequestModelInPayload(payload, []string{"GLM-5.2"})
		if err != nil {
			t.Fatalf("normalize(%s): %v", payload, err)
		}
		if !bytes.Equal(out, payload) {
			t.Errorf("payload %s changed to %s", payload, out)
		}
	}
	if _, _, err := normalizeRequestModelInPayload([]byte(`not json`), nil); err == nil {
		t.Error("invalid payload must be rejected")
	}
}
