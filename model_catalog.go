package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// Upstream environment labels. They are the environment half of every catalog
// cache key: one upstream identity may serve models through both environments,
// and each is discovered, cached, and cooled down independently.
const (
	environmentCodingPlan = "zcode-plan"
	environmentZai        = "zai"
)

// Discovery bounds. A catalog query must never hang a host request or buffer
// an unbounded body: discovery is best-effort, and a slow or oversized
// upstream is treated as failed discovery, which the cooldown absorbs.
const (
	modelDiscoveryTimeout  = 10 * time.Second
	maxModelDiscoveryBytes = int64(1 << 20)
	maxDiscoveredModels    = 256
)

// Messages and models path suffixes. The models endpoint of an upstream
// environment is derived from the Messages endpoint the executor already
// uses: same base, conventional Anthropic /v1/models in place of
// /v1/messages.
const (
	messagesPathSuffix = "/v1/messages"
	modelsPathSuffix   = "/v1/models"
)

// Sanitized discovery failure reasons. They name the failure class only —
// never a status body, URL, credential, or identity — so they are safe to
// keep and later surface in the management plane.
const (
	discoveryReasonUnreachable = "upstream_unreachable"
	discoveryReasonTooLarge    = "response_too_large"
	discoveryReasonMalformed   = "malformed_response"
	discoveryReasonEmpty       = "empty_catalog"
)

// modelDiscoveryClient bounds one discovery call. Discovery rides the same
// upstream environments as execution but must never wait on execution's long
// stream timeouts.
var modelDiscoveryClient = &http.Client{Timeout: modelDiscoveryTimeout}

// catalogScope identifies one cache entry: an upstream environment plus the
// identity scope that discovered against it.
type catalogScope struct {
	Environment string
	Identity    string
}

// catalogIdentityFor resolves the identity half of a cache scope: the stable
// identity id, or on legacy documents without one the host auth record. Both
// are stable, non-secret identifiers; credential material never qualifies.
func catalogIdentityFor(authIndex string, snap credentialSnapshot) string {
	if id := strings.TrimSpace(snap.IdentityID); id != "" {
		return id
	}
	if index := strings.TrimSpace(authIndex); index != "" {
		return "auth:" + index
	}
	return ""
}

// catalogScopeFor projects one environment's scope for an identity.
func catalogScopeFor(authIndex string, snap credentialSnapshot, environment string) catalogScope {
	return catalogScope{Environment: environment, Identity: catalogIdentityFor(authIndex, snap)}
}

// cachedModels is one positive entry: the discovered ids and the instant they
// stop being trusted.
type cachedModels struct {
	ids       []string
	expiresAt time.Time
}

// catalogFailure is one negative entry: a sanitized reason and the instant
// the environment may be asked again.
type catalogFailure struct {
	reason string
	until  time.Time
}

// modelCatalog caches dynamic model discovery per identity and environment.
// Positive entries carry a success TTL; negative entries carry a failure
// cooldown. Time flows in through arguments, so expiry behaviour is tested
// without sleeping. The zero value is unusable; build with newModelCatalog.
type modelCatalog struct {
	mu        sync.Mutex
	successes map[catalogScope]cachedModels
	failures  map[catalogScope]catalogFailure
}

func newModelCatalog() *modelCatalog {
	return &modelCatalog{
		successes: make(map[catalogScope]cachedModels),
		failures:  make(map[catalogScope]catalogFailure),
	}
}

// models returns a scope's fresh discovered ids. An expired entry is refused
// so the caller rediscovers; it is kept in place until the next conclusion
// replaces it, because a rediscoscovery that fails must not resurrect it.
func (c *modelCatalog) models(scope catalogScope, now time.Time) ([]string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.successes[scope]
	if !ok || !now.Before(entry.expiresAt) {
		return nil, false
	}
	return append([]string(nil), entry.ids...), true
}

// coolingDown reports whether a scope is inside its failure cooldown.
func (c *modelCatalog) coolingDown(scope catalogScope, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	failure, ok := c.failures[scope]
	return ok && now.Before(failure.until)
}

// recordSuccess stores one discovery's ids under the success TTL and clears
// any stale failure for the scope.
func (c *modelCatalog) recordSuccess(scope catalogScope, ids []string, ttl time.Duration, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.successes[scope] = cachedModels{
		ids:       append([]string(nil), ids...),
		expiresAt: now.Add(ttl),
	}
	delete(c.failures, scope)
}

// recordFailure starts one cooldown and retires the scope's success entry: it
// has already expired (models refused it), and letting it resurrect after the
// cooldown would serve ids the upstream no longer answers for.
func (c *modelCatalog) recordFailure(scope catalogScope, reason string, cooldown time.Duration, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.successes, scope)
	c.failures[scope] = catalogFailure{reason: reason, until: now.Add(cooldown)}
}

// activeModelCatalog is the plugin-wide catalog. The host consults it per
// model.for_auth call; tests swap it for a fresh instance.
var activeModelCatalog = newModelCatalog()

// modelsEndpointURLFor derives the models-list endpoint of one credential
// kind's upstream environment. It is "" when the Messages URL no longer
// carries the expected suffix, because guessing an endpoint would be worse
// than discovering nothing.
func modelsEndpointURLFor(kind CredentialKind) string {
	return discoveryEnvironments[kind].modelsURL()
}

// modelsEndpointFrom derives the /v1/models endpoint of one Messages URL.
func modelsEndpointFrom(messagesURL string) string {
	base := strings.TrimSuffix(messagesURL, messagesPathSuffix)
	if base == messagesURL {
		return ""
	}
	return base + modelsPathSuffix
}

// discoveryEnvironment holds everything discovery needs to know about one
// upstream environment: its cache label, models endpoint, which snapshot
// field carries the credential material, the execution state machine that
// decides whether that material may be used, and how it authenticates. One
// row per credential kind keeps the per-environment facts in one place.
type discoveryEnvironment struct {
	label        string
	modelsURL    func() string
	material     func(credentialSnapshot) string
	usable       func(credentialSnapshot, time.Time) bool
	authenticate func(http.Header, string)
}

var discoveryEnvironments = map[CredentialKind]discoveryEnvironment{
	CredentialJWT: {
		label:     environmentCodingPlan,
		modelsURL: func() string { return modelsEndpointFrom(messagesEndpointURL()) },
		material:  func(snap credentialSnapshot) string { return snap.JWTToken },
		usable: func(snap credentialSnapshot, now time.Time) bool {
			return jwtUsable(snap.JWTStatus, snap.JWTRetryAfter, now)
		},
		authenticate: func(headers http.Header, material string) {
			headers.Set("Authorization", "Bearer "+material)
		},
	},
	CredentialAPIKey: {
		label:     environmentZai,
		modelsURL: func() string { return modelsEndpointFrom(zaiMessagesEndpointURL()) },
		material:  func(snap credentialSnapshot) string { return snap.APIKeyToken },
		usable: func(snap credentialSnapshot, now time.Time) bool {
			return apiKeyUsable(snap.APIKeyStatus, snap.APIKeyRetryAfter, now)
		},
		authenticate: func(headers http.Header, material string) {
			headers.Set("x-api-key", material)
		},
	},
}

// environmentForKind names the upstream environment one credential kind
// reaches: the Coding Plan for the JWT, the Z.AI business API for the
// managed fallback key.
func environmentForKind(kind CredentialKind) string {
	return discoveryEnvironments[kind].label
}

// discoveryTarget is one environment's discovery request, fully resolved.
// Headers carry the environment's own authentication, built the same way the
// executor builds its profiles.
type discoveryTarget struct {
	Environment string
	URL         string
	Headers     http.Header
}

// buildDiscoveryTarget resolves one environment's discovery request from a
// credential snapshot. ok is false when the credential carries no material or
// the environment has no derivable models endpoint.
func buildDiscoveryTarget(kind CredentialKind, snap credentialSnapshot, cfg Config, deviceID string) (discoveryTarget, bool) {
	env, ok := discoveryEnvironments[kind]
	if !ok {
		return discoveryTarget{}, false
	}
	material := strings.TrimSpace(env.material(snap))
	if material == "" {
		return discoveryTarget{}, false
	}
	url := env.modelsURL()
	if url == "" {
		return discoveryTarget{}, false
	}
	// The same product header set as the environment's Messages profile,
	// except discovery is a plain JSON GET rather than an SSE stream. A
	// discovery request serves no caller conversation, so its identity holds
	// only the device id and no session.
	headers := buildUpstreamHeaders(nil, cfg, requestIdentity{DeviceID: deviceID})
	headers.Set("Accept", "application/json")
	env.authenticate(headers, material)
	return discoveryTarget{
		Environment: env.label,
		URL:         url,
		Headers:     headers,
	}, true
}

// credentialUsableForDiscovery mirrors the execution state machine: a
// credential the executor would skip is not asked to discover either, and an
// environment whose credential is absent has nothing to authenticate with.
func credentialUsableForDiscovery(kind CredentialKind, snap credentialSnapshot, now time.Time) bool {
	env, ok := discoveryEnvironments[kind]
	if !ok {
		return false
	}
	return strings.TrimSpace(env.material(snap)) != "" && env.usable(snap, now)
}

// upstreamModelList is the Anthropic-conventional models response envelope.
// Entry ids stay raw until parsed individually, so one entry carrying a
// non-string id skips itself instead of invalidating the whole list.
type upstreamModelList struct {
	Data []struct {
		ID json.RawMessage `json:"id"`
	} `json:"data"`
}

var (
	errDiscoveryMalformed = errors.New("discovery response is not a model list")
	errDiscoveryEmpty     = errors.New("discovery response carries no model ids")
)

// parseDiscoveredModels extracts the usable model ids of a discovery body:
// trimmed, de-duplicated case-insensitively, empty entries dropped, and the
// count capped defensively. Anything but the expected envelope shape is an
// error, so a drifted upstream can never be cached as a success.
func parseDiscoveredModels(body []byte) ([]string, error) {
	var list upstreamModelList
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, errDiscoveryMalformed
	}
	raw := make([]string, 0, len(list.Data))
	for _, entry := range list.Data {
		if entry.ID == nil {
			continue
		}
		var id string
		if err := json.Unmarshal(entry.ID, &id); err != nil {
			continue
		}
		raw = append(raw, id)
	}
	ids := normalizeModelIDs(raw)
	// Upstream spellings are case-sensitive, so case variants fold onto their
	// first occurrence here — keeping the upstream's own casing — instead of
	// being counted apart by the cap or the cache.
	ids = dedupeCaseFolded(ids)
	if len(ids) == 0 {
		return nil, errDiscoveryEmpty
	}
	if len(ids) > maxDiscoveredModels {
		ids = ids[:maxDiscoveredModels]
	}
	return ids, nil
}

// dedupeCaseFolded folds case-variant duplicates onto their first occurrence.
func dedupeCaseFolded(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		key := strings.ToLower(id)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, id)
	}
	return out
}

// sanitizedDiscoveryStatus reduces a rejected discovery to its status code.
func sanitizedDiscoveryStatus(status int) string {
	return fmt.Sprintf("upstream_status_%d", status)
}

// discoverModels performs one bounded upstream discovery call. It returns the
// discovered ids, or a sanitized failure reason — never upstream body
// content — when the response is not a usable catalog.
func discoverModels(ctx context.Context, client *http.Client, target discoveryTarget) ([]string, string) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
	if err != nil {
		return nil, discoveryReasonUnreachable
	}
	request.Header = target.Headers.Clone()
	response, err := client.Do(request)
	if err != nil {
		// Transport failures and timeouts are indistinguishable at this
		// boundary on purpose: both mean "this environment could not be
		// discovered now".
		return nil, discoveryReasonUnreachable
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, sanitizedDiscoveryStatus(response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxModelDiscoveryBytes+1))
	if err != nil {
		return nil, discoveryReasonUnreachable
	}
	if int64(len(data)) > maxModelDiscoveryBytes {
		return nil, discoveryReasonTooLarge
	}
	ids, err := parseDiscoveredModels(data)
	if err != nil {
		if errors.Is(err, errDiscoveryEmpty) {
			return nil, discoveryReasonEmpty
		}
		return nil, discoveryReasonMalformed
	}
	return ids, ""
}

// discoveryAttempt is one environment's pending or completed discovery: its
// cache scope, resolved request, and outcome. reason is the sanitized failure
// class, and empty means the attempt succeeded.
type discoveryAttempt struct {
	scope  catalogScope
	target discoveryTarget
	ids    []string
	reason string
}

// modelsForAuth serves one identity's model catalog: the static base always,
// plus every upstream environment whose discovery currently yields a usable
// answer. Every failure mode — an undecodable document, an anonymous or
// unreadable credential, discovery disabled, failed, cooling down — returns
// the static catalog, so the host is never left without models.
func modelsForAuth(ctx context.Context, cfg Config, catalog *modelCatalog, authIndex string, doc []byte, now time.Time) []pluginapi.ModelInfo {
	static := staticModels(cfg)
	if !cfg.ModelDiscovery.IsEnabled() {
		return static
	}
	snap, err := readCredentialSnapshot(doc)
	if err != nil {
		return static
	}
	if catalogIdentityFor(authIndex, snap) == "" {
		return static
	}

	// Each usable environment consults its own cached answer first; the rest
	// discover concurrently, so the catalog waits on one round-trip rather
	// than one per environment.
	var (
		attempts []discoveryAttempt
		cached   [][]string
	)
	for _, kind := range []CredentialKind{CredentialJWT, CredentialAPIKey} {
		if !credentialUsableForDiscovery(kind, snap, now) {
			continue
		}
		scope := catalogScopeFor(authIndex, snap, environmentForKind(kind))
		if ids, ok := catalog.models(scope, now); ok {
			cached = append(cached, ids)
			continue
		}
		if catalog.coolingDown(scope, now) {
			continue
		}
		target, ok := buildDiscoveryTarget(kind, snap, cfg, deviceIdentity(authIndex, doc))
		if !ok {
			continue
		}
		attempts = append(attempts, discoveryAttempt{scope: scope, target: target})
	}

	var wg sync.WaitGroup
	for i := range attempts {
		attempt := &attempts[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			attempt.ids, attempt.reason = discoverModels(ctx, modelDiscoveryClient, attempt.target)
		}()
	}
	wg.Wait()

	successTTL := time.Duration(cfg.ModelDiscovery.SuccessTTLSeconds) * time.Second
	cooldown := time.Duration(cfg.ModelDiscovery.FailureCooldownSeconds) * time.Second
	// The Coding Plan's own model declaration is authoritative for the JWT
	// environment: the balance endpoint states which models the plan covers.
	// It supplements discovery rather than replacing it, so a billing endpoint
	// the plugin could not read costs nothing.
	supplements := append(cached, planModelIDs(snap, now))
	for i := range attempts {
		attempt := &attempts[i]
		if attempt.reason == "" {
			catalog.recordSuccess(attempt.scope, attempt.ids, successTTL, now)
			supplements = append(supplements, attempt.ids)
			continue
		}
		catalog.recordFailure(attempt.scope, attempt.reason, cooldown, now)
	}
	return catalogModelList(static, supplements)
}

// planModelIDs returns the model ids the identity's last quota refresh
// observed the plan covering. It reads the cached observation, so it costs no
// upstream call, and returns nothing whenever the observation is not a positive
// reading of a live plan: an unreadable or absent balance is not evidence about
// which models exist.
func planModelIDs(snap credentialSnapshot, now time.Time) []string {
	identity := strings.TrimSpace(snap.IdentityID)
	if identity == "" {
		return nil
	}
	observation, ok := activeQuotaCache.get(identity)
	if !ok {
		return nil
	}
	switch observation.State {
	case "ok", "exhausted":
	default:
		return nil
	}
	ids := make([]string, 0, len(observation.Balances))
	seen := map[string]struct{}{}
	for _, balance := range observation.Balances {
		if balance.Malformed {
			continue
		}
		for _, id := range balanceModelIDs(balance) {
			key := strings.ToLower(id)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			ids = append(ids, id)
		}
	}
	return ids
}

// handleModelForAuth serves one identity's catalog for the host's
// model.for_auth RPC. An undecodable request still answers with the static
// catalog: the host must never see an empty model list because discovery had
// a bad day.
func handleModelForAuth(request []byte) ([]byte, error) {
	var req pluginapi.AuthModelRequest
	if len(request) > 0 {
		if err := json.Unmarshal(request, &req); err != nil {
			req = pluginapi.AuthModelRequest{}
		}
	}
	models := modelsForAuth(context.Background(), currentConfig(), activeModelCatalog, req.AuthID, req.StorageJSON, time.Now())
	return okEnvelope(pluginapi.ModelResponse{Provider: pluginID, Models: models})
}

// catalogModelList builds the catalog from the static base plus discovered
// supplements. Static entries keep their user-defined marking; discovered
// ones do not. Deduplication is case-insensitive with static casing winning,
// so an upstream renaming an already-known model cannot split it in two.
func catalogModelList(static []pluginapi.ModelInfo, supplements [][]string) []pluginapi.ModelInfo {
	models := append([]pluginapi.ModelInfo(nil), static...)
	seen := make(map[string]struct{}, len(models))
	for _, model := range models {
		seen[strings.ToLower(model.ID)] = struct{}{}
	}
	for _, ids := range supplements {
		for _, id := range ids {
			key := strings.ToLower(id)
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			models = append(models, modelInfo(id, false))
		}
	}
	return models
}

// catalogViewEntry is the management-plane view of one cache scope. It names
// only non-secret scope parts — the stable identity and the environment
// label — and the sanitized lifecycle facts of the entry.
type catalogViewEntry struct {
	Identity      string `json:"identity"`
	Environment   string `json:"environment"`
	State         string `json:"state"` // "cached" | "cooldown"
	ModelCount    int    `json:"model_count,omitempty"`
	ExpiresAt     string `json:"expires_at,omitempty"`
	FailureReason string `json:"failure_reason,omitempty"`
	CooldownUntil string `json:"cooldown_until,omitempty"`
}

// view snapshots the catalog for the management plane. Expired positive
// entries are omitted: they would be rediscorvered on the next catalog query,
// so displaying them as cached would lie. Identities carry no credential
// material by construction (see catalogIdentityFor).
func (c *modelCatalog) view(now time.Time) []catalogViewEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	entries := make([]catalogViewEntry, 0, len(c.successes)+len(c.failures))
	for scope, entry := range c.successes {
		if !now.Before(entry.expiresAt) {
			continue
		}
		entries = append(entries, catalogViewEntry{
			Identity:    scope.Identity,
			Environment: scope.Environment,
			State:       "cached",
			ModelCount:  len(entry.ids),
			ExpiresAt:   entry.expiresAt.UTC().Format(time.RFC3339),
		})
	}
	for scope, failure := range c.failures {
		if !now.Before(failure.until) {
			continue
		}
		entries = append(entries, catalogViewEntry{
			Identity:      scope.Identity,
			Environment:   scope.Environment,
			State:         "cooldown",
			FailureReason: failure.reason,
			CooldownUntil: failure.until.UTC().Format(time.RFC3339),
		})
	}
	sortCatalogView(entries)
	return entries
}

// sortCatalogView orders the view by identity then environment so the
// management page renders a stable list.
func sortCatalogView(entries []catalogViewEntry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Identity != entries[j].Identity {
			return entries[i].Identity < entries[j].Identity
		}
		return entries[i].Environment < entries[j].Environment
	})
}

// modelRefreshOutcome is the sanitized result of one environment's forced
// model cache refresh.
type modelRefreshOutcome struct {
	Environment string `json:"environment,omitempty"`
	OK          bool   `json:"ok"`
	ModelCount  int    `json:"model_count,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// refreshAccountModels forces a model cache refresh for every environment the
// account's usable credentials can discover against. Unlike the passive
// path it bypasses the failure cooldown — an explicit operator action means
// "ask again now" — but it still refuses credentials the execution state
// machine would skip, so a refresh cannot hammer an upstream with a
// credential that account already records as unusable.
func refreshAccountModels(ctx context.Context, cfg Config, catalog *modelCatalog, authIndex string, doc []byte, now time.Time) []modelRefreshOutcome {
	outcomes := []modelRefreshOutcome{}
	snap, err := readCredentialSnapshot(doc)
	if err != nil {
		return []modelRefreshOutcome{{Reason: "credential_missing"}}
	}
	deviceID := deviceIdentity(authIndex, doc)
	for _, kind := range []CredentialKind{CredentialJWT, CredentialAPIKey} {
		environment := environmentForKind(kind)
		if !credentialUsableForDiscovery(kind, snap, now) {
			outcomes = append(outcomes, modelRefreshOutcome{
				Environment: environment,
				Reason:      "credential_unavailable",
			})
			continue
		}
		target, ok := buildDiscoveryTarget(kind, snap, cfg, deviceID)
		if !ok {
			outcomes = append(outcomes, modelRefreshOutcome{
				Environment: environment,
				Reason:      "credential_unavailable",
			})
			continue
		}
		ids, reason := discoverModels(ctx, modelDiscoveryClient, target)
		scope := catalogScopeFor(authIndex, snap, environment)
		if reason == "" {
			catalog.recordSuccess(scope, ids, time.Duration(cfg.ModelDiscovery.SuccessTTLSeconds)*time.Second, now)
			outcomes = append(outcomes, modelRefreshOutcome{
				Environment: environment,
				OK:          true,
				ModelCount:  len(ids),
			})
			continue
		}
		catalog.recordFailure(scope, reason, time.Duration(cfg.ModelDiscovery.FailureCooldownSeconds)*time.Second, now)
		outcomes = append(outcomes, modelRefreshOutcome{
			Environment: environment,
			Reason:      reason,
		})
	}
	return outcomes
}
