package main

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the plugin configuration snapshot declared in
// plugins.configs.zcode. Snapshots are immutable once stored; request-side
// code must read currentConfig() instead of mutating values.
type Config struct {
	// Enabled toggles the plugin for the host. Nil means "not configured".
	Enabled *bool `yaml:"enabled"`
	// Priority orders this provider against other host providers.
	Priority int `yaml:"priority"`
	// Models lists the static fallback model IDs; dynamic discovery may only
	// extend, never replace, this list.
	Models []string `yaml:"models"`

	ModelDiscovery ModelDiscoveryConfig `yaml:"model_discovery"`
	OAuth          OAuthConfig          `yaml:"oauth"`
	Upstream       UpstreamConfig       `yaml:"upstream"`
	Quota          QuotaConfig          `yaml:"quota"`
}

// ModelDiscoveryConfig controls identity-scoped dynamic model discovery.
type ModelDiscoveryConfig struct {
	Enabled                *bool `yaml:"enabled"`
	SuccessTTLSeconds      int   `yaml:"success_ttl_seconds"`
	FailureCooldownSeconds int   `yaml:"failure_cooldown_seconds"`
}

// OAuthConfig controls authorization sessions and the managed fallback key.
type OAuthConfig struct {
	SessionTTLSeconds    int    `yaml:"session_ttl_seconds"`
	ManagedKeyNamePrefix string `yaml:"managed_key_name_prefix"`
	// OrganizationID and ProjectID are explicit, non-secret upstream IDs used
	// only when the OAuth result cannot determine them; never guessed from
	// localized display names.
	OrganizationID string `yaml:"organization_id"`
	ProjectID      string `yaml:"project_id"`
}

// UpstreamConfig bounds upstream HTTP behaviour.
type UpstreamConfig struct {
	ConnectTimeoutSeconds int   `yaml:"connect_timeout_seconds"`
	RequestTimeoutSeconds int   `yaml:"request_timeout_seconds"`
	MaxResponseBytes      int64 `yaml:"max_response_bytes"`
}

// QuotaConfig controls managed quota refresh concurrency.
type QuotaConfig struct {
	RefreshConcurrency int `yaml:"refresh_concurrency"`
}

func boolPtr(value bool) *bool { return &value }

// IsEnabled reports whether the plugin is enabled; unset defaults to true.
func (c Config) IsEnabled() bool {
	return c.Enabled == nil || *c.Enabled
}

// IsEnabled reports whether dynamic discovery is enabled; unset defaults to true.
func (c ModelDiscoveryConfig) IsEnabled() bool {
	return c.Enabled == nil || *c.Enabled
}

const (
	defaultPriority                     = 1
	defaultSuccessTTLSeconds            = 3600
	defaultFailureCooldownSeconds       = 300
	defaultOAuthSessionTTLSeconds       = 300
	defaultManagedKeyNamePrefix         = "cpa-zcode"
	defaultConnectTimeoutSeconds        = 30
	defaultRequestTimeoutSeconds        = 300
	defaultMaxResponseBytes       int64 = 64 << 20
	defaultRefreshConcurrency           = 4
)

// parseConfig decodes the YAML override document. Unknown keys are ignored so
// the host may forward wider configuration trees.
func parseConfig(raw []byte) (Config, error) {
	var cfg Config
	if len(raw) == 0 {
		return cfg, nil
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func defaultConfig() Config {
	return Config{
		Enabled:  boolPtr(true),
		Priority: defaultPriority,
		Models:   []string{"GLM-5.2", "GLM-5-Turbo"},
		ModelDiscovery: ModelDiscoveryConfig{
			Enabled:                boolPtr(true),
			SuccessTTLSeconds:      defaultSuccessTTLSeconds,
			FailureCooldownSeconds: defaultFailureCooldownSeconds,
		},
		OAuth: OAuthConfig{
			SessionTTLSeconds:    defaultOAuthSessionTTLSeconds,
			ManagedKeyNamePrefix: defaultManagedKeyNamePrefix,
		},
		Upstream: UpstreamConfig{
			ConnectTimeoutSeconds: defaultConnectTimeoutSeconds,
			RequestTimeoutSeconds: defaultRequestTimeoutSeconds,
			MaxResponseBytes:      defaultMaxResponseBytes,
		},
		Quota: QuotaConfig{RefreshConcurrency: defaultRefreshConcurrency},
	}
}

// mergeConfig applies non-zero overrides from override onto base. Model IDs
// are normalized (trimmed, de-duplicated, order-preserving) here so callers
// never see whitespace or duplicate entries.
func mergeConfig(base, override Config) Config {
	if override.Enabled != nil {
		base.Enabled = override.Enabled
	}
	if override.Priority > 0 {
		base.Priority = override.Priority
	}
	if ids := normalizeModelIDs(override.Models); len(ids) > 0 {
		base.Models = ids
	}
	if override.ModelDiscovery.Enabled != nil {
		base.ModelDiscovery.Enabled = override.ModelDiscovery.Enabled
	}
	if override.ModelDiscovery.SuccessTTLSeconds > 0 {
		base.ModelDiscovery.SuccessTTLSeconds = override.ModelDiscovery.SuccessTTLSeconds
	}
	if override.ModelDiscovery.FailureCooldownSeconds > 0 {
		base.ModelDiscovery.FailureCooldownSeconds = override.ModelDiscovery.FailureCooldownSeconds
	}
	if override.OAuth.SessionTTLSeconds > 0 {
		base.OAuth.SessionTTLSeconds = override.OAuth.SessionTTLSeconds
	}
	if prefix := strings.TrimSpace(override.OAuth.ManagedKeyNamePrefix); prefix != "" {
		base.OAuth.ManagedKeyNamePrefix = prefix
	}
	if override.OAuth.OrganizationID != "" {
		base.OAuth.OrganizationID = override.OAuth.OrganizationID
	}
	if override.OAuth.ProjectID != "" {
		base.OAuth.ProjectID = override.OAuth.ProjectID
	}
	if override.Upstream.ConnectTimeoutSeconds > 0 {
		base.Upstream.ConnectTimeoutSeconds = override.Upstream.ConnectTimeoutSeconds
	}
	if override.Upstream.RequestTimeoutSeconds > 0 {
		base.Upstream.RequestTimeoutSeconds = override.Upstream.RequestTimeoutSeconds
	}
	if override.Upstream.MaxResponseBytes > 0 {
		base.Upstream.MaxResponseBytes = override.Upstream.MaxResponseBytes
	}
	if override.Quota.RefreshConcurrency > 0 {
		base.Quota.RefreshConcurrency = override.Quota.RefreshConcurrency
	}
	return base
}

// normalizeConfig clamps nonsense values onto defaults so every stored
// snapshot is directly usable without further checks.
func normalizeConfig(cfg Config) Config {
	if cfg.Enabled == nil {
		cfg.Enabled = boolPtr(true)
	}
	if cfg.Priority <= 0 {
		cfg.Priority = defaultPriority
	}
	cfg.Models = normalizeModelIDs(cfg.Models)
	if len(cfg.Models) == 0 {
		cfg.Models = append([]string(nil), defaultConfig().Models...)
	}
	if cfg.ModelDiscovery.Enabled == nil {
		cfg.ModelDiscovery.Enabled = boolPtr(true)
	}
	if cfg.ModelDiscovery.SuccessTTLSeconds <= 0 {
		cfg.ModelDiscovery.SuccessTTLSeconds = defaultSuccessTTLSeconds
	}
	if cfg.ModelDiscovery.FailureCooldownSeconds <= 0 {
		cfg.ModelDiscovery.FailureCooldownSeconds = defaultFailureCooldownSeconds
	}
	if cfg.OAuth.SessionTTLSeconds <= 0 {
		cfg.OAuth.SessionTTLSeconds = defaultOAuthSessionTTLSeconds
	}
	if cfg.OAuth.ManagedKeyNamePrefix == "" {
		cfg.OAuth.ManagedKeyNamePrefix = defaultManagedKeyNamePrefix
	}
	if cfg.Upstream.ConnectTimeoutSeconds <= 0 {
		cfg.Upstream.ConnectTimeoutSeconds = defaultConnectTimeoutSeconds
	}
	if cfg.Upstream.RequestTimeoutSeconds <= 0 {
		cfg.Upstream.RequestTimeoutSeconds = defaultRequestTimeoutSeconds
	}
	if cfg.Upstream.MaxResponseBytes <= 0 {
		cfg.Upstream.MaxResponseBytes = defaultMaxResponseBytes
	}
	if cfg.Quota.RefreshConcurrency <= 0 {
		cfg.Quota.RefreshConcurrency = defaultRefreshConcurrency
	}
	return cfg
}
