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
	// Debug turns per-request diagnostics on: each attempt logs its target,
	// sanitized headers, duration, and classified outcome, and each quota
	// refresh logs its verdict evidence. Default off.
	Debug *bool `yaml:"debug"`
	// InjectOfficialSystemPrefix controls the request-body integrity prefix
	// (system_prefix.go): the official ZCode system prompt's leading blocks
	// are prepended to the caller's system content so the Coding Plan gateway
	// admits the request. Unset defaults to true — without it the gateway
	// rejects every Messages request with 3012, so only an operator who has
	// decided against the injection for their deployment turns it off.
	InjectOfficialSystemPrefix *bool `yaml:"inject_official_system_prefix"`

	// AllowedStartPlanIDs restricts which Start Plan products a completed OAuth
	// preflight will accept as the account's entitlement. Empty — the default —
	// accepts every active Start Plan, because a Start Plan the plugin has
	// never heard of is a legitimate plan, and a candidate whose current bucket
	// happens to be empty is still a valid credential that will refill.
	AllowedStartPlanIDs     []string                      `yaml:"allowed_start_plan_ids"`
	StartPlanCredentialPool StartPlanCredentialPoolConfig `yaml:"start_plan_credential_pool"`

	Product        ProductConfig        `yaml:"product"`
	Client         ClientConfig         `yaml:"client"`
	ModelDiscovery ModelDiscoveryConfig `yaml:"model_discovery"`
	OAuth          OAuthConfig          `yaml:"oauth"`
	Upstream       UpstreamConfig       `yaml:"upstream"`
	Quota          QuotaConfig          `yaml:"quota"`
}

// ProductConfig declares how the plugin presents itself as a ZCode client.
// AppVersion is the value the upstream judges client capability by: it is sent
// as X-ZCode-App-Version, as the User-Agent suffix, and as the billing
// balance query parameter. It must match a real ZCode client release, because
// the upstream applies the policy of the declared version — a stale value both
// understates the client's capability and can bypass the policy of the version
// the user actually runs.
type ProductConfig struct {
	// AppVersion is the ZCode client version the plugin speaks as. The default
	// is the version documented in docs/ZCode; override it after checking a
	// working client's own app_version, which is the only authoritative source.
	AppVersion string `yaml:"app_version"`
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

// StartPlanCredentialPoolConfig declares the cross-credential Start Plan
// scheduling policy (credential_pool.go).
//
// The pool is enabled by default because one upstream account may hold several
// auth records, and scheduling only the record the host picked for this request
// would let one exhausted plan strand the account while another record's
// allowance is untouched. The policy is explicitly authorized, so it must also
// be visible and reversible: Enabled=false restores the previous
// single-host-selected-record behaviour exactly.
type StartPlanCredentialPoolConfig struct {
	Enabled *bool `yaml:"enabled"`
	// LastPriorityPlanIDs are the Start Plan products that may only be scheduled
	// once every other Start Plan record has been found unavailable for the
	// model at hand. It defaults to the plan this deployment discovered to be
	// a poor last resort; an unknown active Start Plan is never demoted into
	// this group, so a newly introduced plan is scheduled ahead of it.
	LastPriorityPlanIDs []string `yaml:"last_priority_plan_ids"`
}

// IsEnabled reports whether the cross-credential Start Plan pool is on;
// unset defaults to true.
func (c StartPlanCredentialPoolConfig) IsEnabled() bool {
	return c.Enabled == nil || *c.Enabled
}

// defaultLastPriorityPlanID is the Start Plan product this deployment records
// as the one that must only be spent when nothing else can serve a request.
const defaultLastPriorityPlanID = "zcode-v3-start-plan-0817"

func boolPtr(value bool) *bool { return &value }

// IsEnabled reports whether the plugin is enabled; unset defaults to true.
func (c Config) IsEnabled() bool {
	return c.Enabled == nil || *c.Enabled
}

// IsEnabled reports whether dynamic discovery is enabled; unset defaults to true.
func (c ModelDiscoveryConfig) IsEnabled() bool {
	return c.Enabled == nil || *c.Enabled
}

// IsDebugEnabled reports whether request diagnostics are on; unset defaults
// to false, because the lines are for troubleshooting, not for steady state.
func (c Config) IsDebugEnabled() bool {
	return c.Debug != nil && *c.Debug
}

// IsInjectOfficialSystemPrefixEnabled reports whether the request-body
// integrity prefix is injected; unset defaults to true, because a request
// without it is rejected by the gateway's client-integrity precheck (3012).
func (c Config) IsInjectOfficialSystemPrefixEnabled() bool {
	return c.InjectOfficialSystemPrefix == nil || *c.InjectOfficialSystemPrefix
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
	// defaultAppVersion is the ZCode client version the plugin declares by
	// default. It tracks the version the shipped desktop client reports, which
	// is one release ahead of the version in docs/ZCode (package.json) — that
	// tree is source, the installed app is the release.
	//
	// The billing balance endpoint turned out not to gate on this value: a
	// request carrying a device identity is answered the same way for any
	// version, including invented ones. It is still declared because it is the
	// client's own version and belongs on the wire, and because the Messages
	// path does read it back as User-Agent and X-ZCode-App-Version.
	defaultAppVersion = "3.14.4"
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
		// The static catalog is the floor the host falls back to whenever the
		// dynamic one is unusable — unlogged in, a discovery failure inside its
		// cooldown, or an identity the plugin cannot key a cache under — so it
		// carries the models the Coding Plan and the Start Plan are known to pay
		// for. The list mirrors the official client's Start Plan provider, which
		// declares exactly these three (docs/ZCode config/provider/
		// zcode-builtin.json); discovery through the balance endpoint's
		// capabilities may add to it, never narrow it.
		Models:  []string{"GLM-5.3-Flash", "GLM-5.2", "GLM-5-Turbo"},
		Product: ProductConfig{AppVersion: defaultAppVersion},
		Client:  normalizedClientConfig(ClientConfig{}),
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
		StartPlanCredentialPool: StartPlanCredentialPoolConfig{
			Enabled:             boolPtr(true),
			LastPriorityPlanIDs: []string{defaultLastPriorityPlanID},
		},
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
	if override.Debug != nil {
		base.Debug = override.Debug
	}
	if version := strings.TrimSpace(override.Product.AppVersion); version != "" {
		base.Product.AppVersion = version
	}
	if client := override.Client; client != (ClientConfig{}) {
		base.Client = normalizedClientConfig(client)
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
	if ids := normalizePlanIDs(override.AllowedStartPlanIDs); len(ids) > 0 {
		base.AllowedStartPlanIDs = ids
	}
	if pool := override.StartPlanCredentialPool; pool.Enabled != nil {
		base.StartPlanCredentialPool.Enabled = pool.Enabled
	}
	if ids := normalizePlanIDs(override.StartPlanCredentialPool.LastPriorityPlanIDs); len(ids) > 0 {
		base.StartPlanCredentialPool.LastPriorityPlanIDs = ids
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
	cfg.Product.AppVersion = strings.TrimSpace(cfg.Product.AppVersion)
	if cfg.Product.AppVersion == "" {
		cfg.Product.AppVersion = defaultAppVersion
	}
	cfg.Client = normalizedClientConfig(cfg.Client)
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
	cfg.AllowedStartPlanIDs = normalizePlanIDs(cfg.AllowedStartPlanIDs)
	if cfg.StartPlanCredentialPool.Enabled == nil {
		cfg.StartPlanCredentialPool.Enabled = boolPtr(true)
	}
	if ids := normalizePlanIDs(cfg.StartPlanCredentialPool.LastPriorityPlanIDs); len(ids) > 0 {
		cfg.StartPlanCredentialPool.LastPriorityPlanIDs = ids
	} else {
		cfg.StartPlanCredentialPool.LastPriorityPlanIDs = []string{defaultLastPriorityPlanID}
	}
	return cfg
}

// normalizePlanIDs trims, drops empties, and de-duplicates a plan-id list while
// preserving order. Plan ids are compared exactly, so no case folding happens
// here: the ids are opaque upstream identifiers, and folding them would let a
// configured id match a product it does not name.
func normalizePlanIDs(ids []string) []string {
	if len(ids) == 0 {
		return nil
	}
	out := make([]string, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		trimmed := strings.TrimSpace(id)
		if trimmed == "" {
			continue
		}
		if _, duplicate := seen[trimmed]; duplicate {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
