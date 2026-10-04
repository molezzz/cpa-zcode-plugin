package main

import (
	"net/http"
	neturl "net/url"
	"strings"
)

// The upstream route resolver is the single seam that decides where a request
// goes and what it spends. URL, authentication shape, billing/entitlement
// domain, and whether the URL is the product of a verified gateway rewrite are
// resolved once here, at profile construction; the executor consults only the
// resolved routes, and the error classifier never speculates about unproven
// server-side causes. Nothing outside this file may build a Messages URL or
// decide that two routes are interchangeable.

// billingDomain names whose money or entitlement a route's requests spend. The
// Coding Plan JWT spends the plan's entitlement; the managed API key bills the
// account's Z.AI API balance. The two are different billing domains: a request
// one route refused is not silently retried on the other, because a retry
// there consumes resources the first route was never allowed to spend.
type billingDomain string

const (
	billingPlanEntitlement billingDomain = "coding_plan_entitlement"
	billingAPIBalance      billingDomain = "zai_api_balance"
)

// authMode names how a route authenticates. newProfile builds the wire shape
// the route declares from the credential itself; an authentication header must
// never be added ad hoc at a request site, outside this decision.
type authMode string

const (
	authBearerJWT authMode = "bearer_jwt"
	authAPIKey    authMode = "api_key"
)

// Route identities. They are stable identifiers for diagnostics and for the
// executor's compatibility decision, so an operator reading a debug line can
// tell which surface produced a verdict without reverse-engineering URLs.
const (
	routeIDPlanJWT    = "zcode-plan-anthropic-messages"
	routeIDManagedKey = "zai-anthropic-messages"
)

// resolvedRoute is one credential kind's upstream route, resolved.
type resolvedRoute struct {
	ID string
	// URL is the absolute Messages URL requests are sent to.
	URL string
	// AuthMode declares how the route authenticates.
	AuthMode authMode
	// BillingDomain declares whose money or entitlement the route spends.
	BillingDomain billingDomain
	// GatewayRewritten reports whether URL is the product of a gateway route
	// rewrite rather than the credential's own direct endpoint. No route is
	// rewritten today: officialGatewayRoutes is empty (see below).
	GatewayRewritten bool
}

// resolveRoute resolves the route for one credential kind. The Start Plan JWT
// keeps the official direct zcode-plan path, which the official client also
// uses for Start Plan providers (source-confirmed); the managed key keeps the
// Z.AI business Anthropic path. The official API-key gateway rewrite is a
// candidate only: it is applied on an exact endpoint match and only once an
// authorized differential capture has proven the gateway's wire contract and
// billing domain (issue #14). The JWT route is never rewritten.
func resolveRoute(kind CredentialKind) resolvedRoute {
	if kind == CredentialAPIKey {
		url := zaiMessagesEndpointURL()
		route := resolvedRoute{
			ID:            routeIDManagedKey,
			URL:           url,
			AuthMode:      authAPIKey,
			BillingDomain: billingAPIBalance,
		}
		if rewritten, ok := applyGatewayRoutes(url, zcodeGatewayOrigin(), officialGatewayRoutes); ok {
			route.URL = rewritten
			route.GatewayRewritten = true
		}
		return route
	}
	return resolvedRoute{
		ID:            routeIDPlanJWT,
		URL:           messagesEndpointURL(),
		AuthMode:      authBearerJWT,
		BillingDomain: billingPlanEntitlement,
	}
}

// gatewayRouteCandidate is one exact-match rewrite of an official provider
// endpoint onto a path of the ZCode platform gateway.
type gatewayRouteCandidate struct {
	// ProviderEndpoint is the exact https endpoint that is rewritten.
	ProviderEndpoint string
	// GatewayPath is the absolute path on the gateway origin the request is
	// sent to instead.
	GatewayPath string
}

// officialGatewayRoutes holds the registered gateway rewrites. The official
// client performs two such rewrites for API-key Coding Plan traffic
// (docs/ZCode apps/zcode-cli/packages/adapters/src/model/official-coding-plan-gateway.ts):
// https://open.bigmodel.cn/api/anthropic/v1/messages → /api/v1/ultra/anthropic/v1/messages
// and https://api.z.ai/api/anthropic/v1/messages → /api/v1/ultra-zai/anthropic/v1/messages.
// Those are candidates for a future adapter, not registered routes: enabling
// one requires an authorized differential capture proving the gateway accepts
// the plugin's credential and bills the expected domain. Until then the table
// stays empty and every request goes to its direct endpoint.
var officialGatewayRoutes []gatewayRouteCandidate

// zcodeGatewayOrigin is the origin gateway rewrites target. The official
// client's gateway origin defaults to the same ZCode platform origin the Start
// Plan route uses.
func zcodeGatewayOrigin() string {
	return strings.TrimRight(zcodePlanUpstreamBase, "/")
}

// applyGatewayRoutes returns the gateway URL when rawURL exactly matches one
// candidate's provider endpoint, mirroring the official client's matcher:
// https only, scheme + lower-cased host + effective port (defaulting to 443)
// + path with trailing slashes normalized. The query string is preserved
// verbatim; lookalike hosts, custom ports, plain HTTP, and every path the
// candidate does not name — including billing endpoints — are returned
// unchanged. ok is false when no candidate matched.
func applyGatewayRoutes(rawURL string, origin string, candidates []gatewayRouteCandidate) (string, bool) {
	parsed, err := neturl.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
		return rawURL, false
	}
	originURL, err := neturl.Parse(origin)
	if err != nil || originURL.Scheme != "https" || originURL.Hostname() == "" {
		return rawURL, false
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	key := "https://" + strings.ToLower(parsed.Hostname()) + ":" + port + normalizedURLPath(parsed.Path)
	for _, candidate := range candidates {
		provider, err := neturl.Parse(candidate.ProviderEndpoint)
		if err != nil || provider.Scheme != "https" {
			continue
		}
		providerPort := provider.Port()
		if providerPort == "" {
			providerPort = "443"
		}
		providerKey := "https://" + strings.ToLower(provider.Hostname()) + ":" + providerPort + normalizedURLPath(provider.Path)
		if key != providerKey {
			continue
		}
		gateway := neturl.URL{
			Scheme:   "https",
			Host:     originURL.Host,
			Path:     candidate.GatewayPath,
			RawQuery: parsed.RawQuery,
		}
		return gateway.String(), true
	}
	return rawURL, false
}

// normalizedURLPath folds trailing slashes the way the official matcher does:
// the root stays "/", every other path loses its trailing slashes.
func normalizedURLPath(path string) string {
	if path == "" {
		return "/"
	}
	trimmed := strings.TrimRight(path, "/")
	if trimmed == "" {
		return "/"
	}
	return trimmed
}

// gatewayRequestHeaders returns the header set a gateway-routed request sends:
// the original headers minus an explicit Host entry, which would otherwise pin
// the request to the provider endpoint's host instead of the gateway's. The
// official client removes exactly that header on a gateway hit and passes
// method, body, and every other header — authentication included — through
// unchanged. The plugin's own header sets never contain Host (the caller
// allowlist denies it), so this is a no-op for them and a guard for anything
// that ever carries one.
func gatewayRequestHeaders(headers http.Header) http.Header {
	out := headers.Clone()
	if out == nil {
		return nil
	}
	out.Del("Host")
	return out
}

// fallbackAllowed is the executor's explicit decision whether a request that
// just failed on failed's route may be replayed on next's route. It separates
// two questions the failure classification used to answer with one flag:
//
//   - RetryableBeforeOutput says whether the failure permits another attempt
//     at all — a request-level rejection permits one, a failure after output
//     does not.
//   - This rule says whether the next route may serve it. Routes in the same
//     billing domain are interchangeable for any retryable failure. Crossing
//     a billing/entitlement boundary spends the other domain's money or
//     entitlement, so it is reserved for verdicts about the credential or its
//     availability — the conclusions a different credential can actually cure.
//     A request-level verdict (failureRejected: an invalid_request such as
//     3012, a plan-access refusal, an unclassified 4xx) belongs to the
//     request, not to the credential: the next route cannot cure it, and
//     serving it there would silently spend a different billing domain for a
//     request the first route refused.
//
// The allow-list is closed: a failure class must be named here before it may
// ever cross a billing domain.
//
// A cross-record attempt is confined to a strictly narrower list than a
// billing-domain crossing. Two auth records of one account are two accounts'
// worth of entitlement as far as the upstream is concerned, so presenting the
// second one spends its allowance for a request the first refused. Only a
// definite pre-output allowance verdict justifies that: this record's bucket is
// empty, or its plan has ended — precisely the conclusions a different record's
// allowance can cure. A verification block, an invalid request, a cooldown, an
// authentication failure, a network error or a request-level rejection says
// nothing about whether another account can serve the request, so replaying it
// would spend an entitlement to obtain the same answer. Every Start Plan record
// shares one billing domain, so a cross-record attempt also gets no same-domain
// shortcut.
func fallbackAllowed(failed ResolvedProfile, failure *upstreamFailure, next ResolvedProfile) bool {
	if failure == nil || !failure.RetryableBeforeOutput {
		return false
	}
	if failed.Record != next.Record {
		return failure.Class == failureExhausted || failure.Class == failurePlanExpired
	}
	if failed.Route.BillingDomain == next.Route.BillingDomain {
		return true
	}
	return failureCrossesBillingDomain(failure.Class)
}

// failureCrossesBillingDomain reports whether a failure class may spend a
// different billing domain's entitlement. The allow-list is closed: a class has
// to be named here before it may cross a boundary, because crossing one spends
// resources the failed route was never allowed to spend.
func failureCrossesBillingDomain(class failureClass) bool {
	switch class {
	case failureVerificationBlocked, failureInvalid, failureExhausted, failurePlanExpired, failureCooldown:
		return true
	default:
		return false
	}
}
