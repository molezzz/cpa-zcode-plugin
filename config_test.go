package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
)

func resetConfigSnapshot() func() {
	return func() { activeConfig.Store(defaultConfig()) }
}

func TestDefaultConfigMatchesPlanBaseline(t *testing.T) {
	cfg := defaultConfig()
	if !cfg.IsEnabled() {
		t.Fatal("plugin must be enabled by default")
	}
	if cfg.Priority != 1 {
		t.Fatalf("priority = %d, want 1", cfg.Priority)
	}
	if len(cfg.Models) == 0 {
		t.Fatal("static model fallback must never be empty")
	}
	if !cfg.ModelDiscovery.IsEnabled() {
		t.Fatal("model discovery must default to enabled")
	}
	if cfg.ModelDiscovery.SuccessTTLSeconds != 3600 {
		t.Fatalf("success ttl = %d, want 3600", cfg.ModelDiscovery.SuccessTTLSeconds)
	}
	if cfg.ModelDiscovery.FailureCooldownSeconds != 300 {
		t.Fatalf("failure cooldown = %d, want 300", cfg.ModelDiscovery.FailureCooldownSeconds)
	}
	if cfg.OAuth.SessionTTLSeconds != 300 {
		t.Fatalf("oauth session ttl = %d, want 300", cfg.OAuth.SessionTTLSeconds)
	}
	if cfg.OAuth.ManagedKeyNamePrefix != "cpa-zcode" {
		t.Fatalf("managed key prefix = %q", cfg.OAuth.ManagedKeyNamePrefix)
	}
	if cfg.Upstream.ConnectTimeoutSeconds != 30 {
		t.Fatalf("connect timeout = %d, want 30", cfg.Upstream.ConnectTimeoutSeconds)
	}
	if cfg.Upstream.RequestTimeoutSeconds != 300 {
		t.Fatalf("request timeout = %d, want 300", cfg.Upstream.RequestTimeoutSeconds)
	}
	if cfg.Upstream.MaxResponseBytes != 64<<20 {
		t.Fatalf("max response bytes = %d, want 64MiB", cfg.Upstream.MaxResponseBytes)
	}
	if cfg.Quota.RefreshConcurrency != 4 {
		t.Fatalf("refresh concurrency = %d, want 4", cfg.Quota.RefreshConcurrency)
	}
}

func TestConfigureMergesOverridesOntoDefaults(t *testing.T) {
	yaml := `
enabled: false
models:
  - " GLM-5.2 "
  - ""
  - GLM-5.2
  - GLM-5-Turbo
model_discovery:
  success_ttl_seconds: 60
upstream:
  max_response_bytes: 1024
`
	cfg, err := parseConfig([]byte(yaml))
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	merged := mergeConfig(defaultConfig(), cfg)
	if merged.IsEnabled() {
		t.Error("enabled override lost")
	}
	// 去空、去重、保留顺序。
	if got := strings.Join(merged.Models, ","); got != "GLM-5.2,GLM-5-Turbo" {
		t.Fatalf("models = %v, want [GLM-5.2 GLM-5-Turbo]", merged.Models)
	}
	if merged.ModelDiscovery.SuccessTTLSeconds != 60 {
		t.Error("discovery ttl override lost")
	}
	if merged.ModelDiscovery.FailureCooldownSeconds != 300 {
		t.Error("unset discovery cooldown must keep default")
	}
	if merged.Upstream.MaxResponseBytes != 1024 {
		t.Error("max response bytes override lost")
	}
	if merged.Upstream.RequestTimeoutSeconds != 300 {
		t.Error("unset request timeout must keep default")
	}
}

func TestParseConfigRejectsGarbage(t *testing.T) {
	if _, err := parseConfig([]byte("models: [unterminated")); err == nil {
		t.Fatal("invalid YAML must error")
	}
	if _, err := parseConfig([]byte("models: 42")); err == nil {
		t.Fatal("type mismatch must error")
	}
}

func TestNormalizeConfigClampsNonsense(t *testing.T) {
	cfg := defaultConfig()
	cfg.Models = []string{"", "  ", "dup", "dup"}
	cfg.ModelDiscovery.SuccessTTLSeconds = -5
	cfg.ModelDiscovery.FailureCooldownSeconds = 0
	cfg.OAuth.SessionTTLSeconds = -1
	cfg.Upstream.ConnectTimeoutSeconds = 0
	cfg.Upstream.RequestTimeoutSeconds = -3
	cfg.Upstream.MaxResponseBytes = 0
	cfg.Quota.RefreshConcurrency = 0

	got := normalizeConfig(cfg)
	if len(got.Models) != 1 || got.Models[0] != "dup" {
		t.Fatalf("models = %v, want [dup]", got.Models)
	}
	if got.ModelDiscovery.SuccessTTLSeconds != 3600 {
		t.Error("negative ttl must clamp to default")
	}
	if got.ModelDiscovery.FailureCooldownSeconds != 300 {
		t.Error("zero cooldown must clamp to default")
	}
	if got.OAuth.SessionTTLSeconds != 300 {
		t.Error("negative session ttl must clamp to default")
	}
	if got.Upstream.ConnectTimeoutSeconds != 30 {
		t.Error("zero connect timeout must clamp to default")
	}
	if got.Upstream.RequestTimeoutSeconds != 300 {
		t.Error("negative request timeout must clamp to default")
	}
	if got.Upstream.MaxResponseBytes != 64<<20 {
		t.Error("zero max response bytes must clamp to default")
	}
	if got.Quota.RefreshConcurrency != 4 {
		t.Error("non-positive concurrency must clamp to default")
	}
}

func TestConfigureSnapshotIsAtomic(t *testing.T) {
	t.Cleanup(resetConfigSnapshot())
	before := currentConfig()
	request, err := json.Marshal(lifecycleRequest{ConfigYAML: []byte("models:\n  - Snapshot-Model\n")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handleMethod(pluginabi.MethodPluginReconfigure, request); err != nil {
		t.Fatal(err)
	}
	after := currentConfig()
	if len(before.Models) == 1 && before.Models[0] == "Snapshot-Model" {
		t.Fatal("test precondition broken")
	}
	if len(after.Models) != 1 || after.Models[0] != "Snapshot-Model" {
		t.Fatalf("snapshot not updated: %v", after.Models)
	}
	if after.Upstream.RequestTimeoutSeconds != 300 {
		t.Fatal("snapshot must be normalized")
	}
}

// TestProductAppVersionIsConfigurable covers the P3 requirement: the declared
// client version is configuration, not a constant, because the upstream applies
// the policy of the version a client claims.
func TestProductAppVersionIsConfigurable(t *testing.T) {
	base := normalizeConfig(defaultConfig())
	if base.Product.AppVersion != defaultAppVersion {
		t.Fatalf("default app version = %q, want %q", base.Product.AppVersion, defaultAppVersion)
	}

	override, err := parseConfig([]byte("product:\n  app_version: \"9.9.9\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	merged := normalizeConfig(mergeConfig(defaultConfig(), override))
	if merged.Product.AppVersion != "9.9.9" {
		t.Fatalf("merged app version = %q, want the configured value", merged.Product.AppVersion)
	}

	// An empty or whitespace value falls back to the documented default rather
	// than sending the upstream an empty version to judge capability by.
	blank, err := parseConfig([]byte("product:\n  app_version: \"   \"\n"))
	if err != nil {
		t.Fatal(err)
	}
	fallback := normalizeConfig(mergeConfig(defaultConfig(), blank))
	if fallback.Product.AppVersion != defaultAppVersion {
		t.Fatalf("blank app version = %q, want the default", fallback.Product.AppVersion)
	}
}

// TestProductAppVersionReachesEveryRequestHeader pins that one configured value
// drives the User-Agent and the version header together: the upstream compares
// them, and a profile that sent different versions would be incoherent.
func TestProductAppVersionReachesEveryRequestHeader(t *testing.T) {
	cfg := normalizeConfig(defaultConfig())
	cfg.Product.AppVersion = "9.9.9"
	profile := newProfile(credentialSnapshot{IdentityID: "id", JWTToken: "jwt"},
		CredentialJWT, cfg, "GLM-5.2", nil)
	if got := profile.Headers.Get("User-Agent"); got != "ZCode/9.9.9" {
		t.Errorf("user agent = %q", got)
	}
	if got := profile.Headers.Get("X-ZCode-App-Version"); got != "9.9.9" {
		t.Errorf("app version header = %q", got)
	}
	if got := zcodeUserAgent("9.9.9"); got != "ZCode/9.9.9" {
		t.Errorf("zcodeUserAgent = %q", got)
	}
}
