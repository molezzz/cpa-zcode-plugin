package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// Management route paths, relative to the host's /v0/management prefix.
//
// None of these three declares a legacy Menu label, and that is load-bearing
// rather than incidental: the host turns a Menu-bearing GET management route
// into an unauthenticated resource route, which would strip management
// authentication from the account state and from the action endpoint that
// refreshes credentials. The left-nav entry comes from the resource route
// below instead, which serves the page shell and nothing else.
const (
	managementPagePath   = "/zcode/page"
	managementStatePath  = "/zcode/state"
	managementActionPath = "/zcode/action"
)

// The resource page is the plugin's only unauthenticated surface. It is the
// shell behind the host control panel's "ZCode" left-nav entry: a Menu label on
// a resource route is what produces that entry, and the host serves resource
// routes without management authentication, over GET only, and without
// HTML-escaping the response body. The shell is therefore the page constant
// verbatim — no server-side interpolation, and every account value fetched at
// runtime from the authenticated routes above with the management key the
// operator supplies.
const (
	managementResourcePrefix = "/v0/resource/plugins/"
	managementResourcePage   = "/page"
	managementResourceMenu   = "ZCode"
)

// managementResourcePagePath is the route the host registers and serves. The
// prefix is spelled out in full because the plugin has to recognize resource
// paths on their own terms: a path under it carries no management
// authentication, so nothing authenticated may ever answer one.
var managementResourcePagePath = managementResourcePrefix + pluginID + managementResourcePage

// The fixed action vocabulary of the management plane. Account-granular
// actions require an explicit auth_index; the batch action refuses one
// because it snapshots every account instead.
const (
	actionRefreshCredential = "refresh_credential"
	actionRefreshQuota      = "refresh_quota"
	actionRefreshModels     = "refresh_models"
	actionOAuthRetry        = "oauth_retry"
	actionBatchRefresh      = "batch_refresh"
)

// handleManagementRegister declares the plugin's management routes. The
// handler of every route is filled in by the host adapter, which forwards
// matching requests through management.handle.
func handleManagementRegister(request []byte) ([]byte, error) {
	var req pluginapi.ManagementRegistrationRequest
	if len(request) > 0 {
		if err := json.Unmarshal(request, &req); err != nil {
			return errorEnvelope("invalid_request", "decode management.register request: "+err.Error(), http.StatusBadRequest), nil
		}
	}
	return okEnvelope(pluginapi.ManagementRegistrationResponse{
		Routes: []pluginapi.ManagementRoute{
			{
				Method:      http.MethodGet,
				Path:        managementPagePath,
				Description: "ZCode provider management page",
			},
			{
				Method:      http.MethodGet,
				Path:        managementStatePath,
				Description: "Redacted ZCode account, credential, session, and model cache state",
			},
			{
				Method:      http.MethodPost,
				Path:        managementActionPath,
				Description: "Perform a ZCode maintenance action (refresh_credential, refresh_quota, refresh_models, oauth_retry, batch_refresh)",
			},
		},
		Resources: []pluginapi.ResourceRoute{
			{
				Path:        managementResourcePagePath,
				Menu:        managementResourceMenu,
				Description: "ZCode provider management page",
			},
		},
	})
}

// managementHandleRPC mirrors the host's JSON encoding of a management
// request. Field names follow the host's Go type, which carries no JSON tags.
type managementHandleRPC struct {
	Method string
	Path   string
	Query  map[string][]string
	Body   []byte
}

// handleManagementHandle serves one management HTTP request. The response is
// the plugin's ManagementResponse; its Body crosses the RPC as base64, which
// the host decodes before writing it to the client.
func handleManagementHandle(request []byte) ([]byte, error) {
	var req managementHandleRPC
	if len(request) > 0 {
		if err := json.Unmarshal(request, &req); err != nil {
			return errorEnvelope("invalid_request", "decode management.handle request: "+err.Error(), http.StatusBadRequest), nil
		}
	}
	response := serveManagementHTTP(strings.ToUpper(strings.TrimSpace(req.Method)), strings.TrimSpace(req.Path), req.Body)
	return okEnvelope(response)
}

// serveManagementHTTP routes one management request to its handler. Unknown
// routes answer 404 with a sanitized JSON error, never a body echo.
//
// The host dispatches resource requests here too, with the full
// /v0/resource/plugins/<id>/ path and no body, which is why the resource
// surface is settled before the management routes rather than as one more case
// among them.
func serveManagementHTTP(method, path string, body []byte) pluginapi.ManagementResponse {
	if isResourcePath(path) {
		// A resource path is unauthenticated by construction. Only the shell may
		// answer one: the suffix matches below would otherwise serve account
		// state to any anonymous GET, which is the boundary this route exists to
		// keep intact rather than to erode.
		if method == http.MethodGet && strings.HasSuffix(path, managementResourcePagePath) {
			return managementPageResponse()
		}
		return managementErrorResponse(http.StatusNotFound, "unknown_route", "this management route does not exist")
	}
	switch {
	case method == http.MethodGet && strings.HasSuffix(path, managementPagePath):
		return managementPageResponse()
	case method == http.MethodGet && strings.HasSuffix(path, managementStatePath):
		return managementJSONResponse(buildManagementState(time.Now()))
	case method == http.MethodPost && strings.HasSuffix(path, managementActionPath):
		return runManagementAction(body, time.Now())
	default:
		return managementErrorResponse(http.StatusNotFound, "unknown_route", "this management route does not exist")
	}
}

// isResourcePath reports whether one request path is addressed to the host's
// unauthenticated resource surface. The check is by plugin prefix rather than by
// the shell's own path so that a resource path naming any other plugin route —
// a data route, or a path this plugin never registered — still reads as
// unauthenticated and is refused instead of falling through to a suffix match.
func isResourcePath(path string) bool {
	return strings.HasPrefix(path, managementResourcePrefix+pluginID+"/")
}

// managementPageResponse serves the page shell. It is shared by the
// authenticated management route and the unauthenticated resource route
// because the two must stay byte-identical: the resource route is what the
// navigation entry opens, and any difference would be a second page carrying
// different rules about where the shell's data comes from.
func managementPageResponse() pluginapi.ManagementResponse {
	return pluginapi.ManagementResponse{
		StatusCode: http.StatusOK,
		Headers:    http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
		Body:       []byte(managementPageHTML),
	}
}

// managementJSONResponse renders a value as an application/json response.
func managementJSONResponse(value any) pluginapi.ManagementResponse {
	raw, err := json.Marshal(value)
	if err != nil {
		return managementErrorResponse(http.StatusInternalServerError, "plugin_error", "the management response could not be encoded")
	}
	return pluginapi.ManagementResponse{
		StatusCode: http.StatusOK,
		Headers:    http.Header{"Content-Type": []string{"application/json"}},
		Body:       raw,
	}
}

// managementErrorResponse renders a sanitized JSON failure with a status code.
func managementErrorResponse(status int, code, message string) pluginapi.ManagementResponse {
	raw, err := json.Marshal(map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
	if err != nil {
		raw = []byte(`{"error":{"code":"plugin_error","message":"management error"}}`)
	}
	return pluginapi.ManagementResponse{
		StatusCode: status,
		Headers:    http.Header{"Content-Type": []string{"application/json"}},
		Body:       raw,
	}
}

// managementService wires one management request's dependencies. It is built
// per request from the current seams, so a reconfigured host is always
// reached through the live store, catalog, and config.
type managementService struct {
	store    AuthStore
	recorder *credentialStateRecorder
	catalog  *modelCatalog
	cfg      Config
}

func defaultManagementService() managementService {
	store := authStoreProvider()
	return managementService{
		store:    store,
		recorder: credentialStates.forStore(store),
		catalog:  activeModelCatalog,
		cfg:      currentConfig(),
	}
}

// managementState is the redacted state document the management page renders.
// Every field is either a stable non-secret identifier (auth index, identity
// id, file name), a lifecycle fact (status, timestamps), or a sanitized
// summary (bounded error codes and messages). Secrets, authorization
// parameters, upstream bodies, and prompts have no field to reach the page.
type managementState struct {
	GeneratedAt string             `json:"generated_at"`
	Accounts    []accountView      `json:"accounts"`
	Sessions    []sessionView      `json:"sessions"`
	ModelCache  []catalogViewEntry `json:"model_cache"`
}

// buildManagementState snapshots every account, the authorization sessions,
// and the model catalog into the redacted view.
func buildManagementState(now time.Time) managementState {
	svc := defaultManagementService()
	return svc.state(context.Background(), now)
}

func (s managementService) state(ctx context.Context, now time.Time) managementState {
	state := managementState{
		GeneratedAt: now.UTC().Format(time.RFC3339),
		Accounts:    []accountView{},
		Sessions:    activeSessions.view(now),
		ModelCache:  s.catalog.view(now),
	}
	entries, err := s.store.List(ctx)
	if err != nil {
		// A broken store read must not erase the rest of the page; the
		// accounts section reports the failure instead of silently appearing
		// empty.
		state.Accounts = append(state.Accounts, accountView{ReadError: "auth store could not be listed"})
		return state
	}
	for _, entry := range entries {
		if entry.Provider != pluginID && entry.Type != pluginID {
			continue
		}
		state.Accounts = append(state.Accounts, s.accountView(ctx, entry))
	}
	return state
}

// accountView is the redacted view of one account: its identity, both
// credential states, the OAuth material's presence, and the last quota
// observation.
type accountView struct {
	AuthIndex  string      `json:"auth_index"`
	FileName   string      `json:"file_name,omitempty"`
	Label      string      `json:"label,omitempty"`
	IdentityID string      `json:"identity_id,omitempty"`
	Disabled   bool        `json:"disabled,omitempty"`
	JWT        *jwtView    `json:"jwt,omitempty"`
	APIKey     *apiKeyView `json:"api_key,omitempty"`
	OAuth      *oauthView  `json:"oauth,omitempty"`
	Quota      *quotaView  `json:"quota,omitempty"`
	// Plan is the record's Start Plan reading: which products it holds and, per
	// model, whether an allowance is funded, spent, or unknown. It is the section
	// that makes a wrong-account login and an exhausted plan tell themselves
	// apart, which the JWT status alone cannot do — both read "not serving".
	Plan *planSnapshotView `json:"plan,omitempty"`
	// Login carries the account identity the upstream stated for this login, as a
	// digest. It is what correlates a record with the account a user believes they
	// authorized, without the page ever holding the account's own identifier.
	Login     *loginView `json:"login,omitempty"`
	ReadError string     `json:"read_error,omitempty"`
}

// planSnapshotView is one record's persisted Start Plan reading.
type planSnapshotView struct {
	CheckedAt string `json:"checked_at,omitempty"`
	// Readable is false when the last refresh could not interpret the billing
	// answer. The page shows that rather than an empty plan list, because "could
	// not read" and "read: nothing there" call for different operator actions.
	Readable bool     `json:"readable"`
	PlanIDs  []string `json:"plan_ids,omitempty"`
	// Instances references the individual subscription instances as a product id
	// plus a digest, so two plans of one product stay distinguishable.
	Instances []string `json:"plan_instances,omitempty"`
	// LastPriority says this record's plan is configured to be scheduled only when
	// nothing else can serve a request. It is shown on the page because a
	// surprising scheduling decision is otherwise invisible.
	LastPriority bool                          `json:"last_priority,omitempty"`
	Models       map[string]modelAllowanceView `json:"models,omitempty"`
}

type modelAllowanceView struct {
	Allowance string `json:"allowance"`
	ResetAt   string `json:"reset_at,omitempty"`
	Buckets   int    `json:"buckets"`
	Funded    int    `json:"funded_buckets,omitempty"`
}

// loginView is the account identity one login produced.
type loginView struct {
	// UserIDHash is a domain-separated digest of the upstream account id. The raw
	// id is never stored, so the page can show that two records belong to different
	// accounts without either record carrying the account's own identifier.
	UserIDHash string `json:"user_id_hash,omitempty"`
	CheckedAt  string `json:"checked_at,omitempty"`
}

type jwtView struct {
	Present       bool   `json:"present"`
	Status        string `json:"status,omitempty"`
	RetryAfter    string `json:"retry_after,omitempty"`
	LastCheckedAt string `json:"last_checked_at,omitempty"`
	LastErrorCode string `json:"last_error_code,omitempty"`
	// ReauthSuggested asks the user to authorize again. The zcode-plan JWT
	// states no expiry, so the plugin cannot know the credential has been
	// revoked; past the re-authorization age it stops preferring it and says so
	// here, rather than letting the account fail requests silently.
	ReauthSuggested bool `json:"reauth_suggested,omitempty"`
}

type apiKeyView struct {
	Present    bool        `json:"present"`
	Managed    bool        `json:"managed,omitempty"`
	Status     string      `json:"status,omitempty"`
	RetryAfter string      `json:"retry_after,omitempty"`
	UpdatedAt  string      `json:"updated_at,omitempty"`
	Name       string      `json:"name,omitempty"`
	KeyID      string      `json:"key_id,omitempty"`
	LastError  *keyOpError `json:"last_error,omitempty"`
}

type oauthView struct {
	HasAccessToken bool   `json:"has_access_token"`
	ReceivedAt     string `json:"received_at,omitempty"`
	// ReauthRequired reports that the OAuth material can no longer produce a
	// Z.AI business token, so the subscription and quota surfaces that need one
	// will answer 401 until the user authorizes again. It is surfaced rather
	// than logged because the failure it describes is otherwise invisible: the
	// Coding Plan JWT keeps working, so nothing else tells the user their
	// business-side access has lapsed.
	ReauthRequired bool   `json:"reauth_required,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

type quotaView struct {
	State     string             `json:"state"`
	Reason    string             `json:"reason,omitempty"`
	CheckedAt string             `json:"checked_at,omitempty"`
	Plan      string             `json:"plan,omitempty"`
	PlanCount int                `json:"plan_count"`
	Balances  []quotaBalanceView `json:"balances,omitempty"`
	// PlanGroups are the billing axes the buckets fall into, in the order the
	// upstream listed their buckets. The page renders one section per group so
	// a Start Plan allowance and a general Coding Plan allowance are never read
	// as one number; each bucket's own `plan` field names the group it belongs
	// to, so the page never re-derives ownership.
	PlanGroups []quotaPlanGroupView `json:"plan_groups,omitempty"`
}

// quotaPlanGroupView names one billing axis on the page: its display label and
// the kind of plan it is. The kind lets the page put the axis in the operator's
// terms — a Start Plan allowance and a general Coding Plan allowance are
// different things to act on — without the page knowing how ownership was
// resolved.
type quotaPlanGroupView struct {
	Label string `json:"label,omitempty"`
	Kind  string `json:"kind"`
}

type quotaBalanceView struct {
	Name string `json:"name"`
	// GroupIndex is the position of the billing axis this bucket's numbers come
	// from, matching an entry of PlanGroups. It is positional rather than a
	// label because two plans may share a display name, and rejoining buckets
	// to axes by name would silently merge two separate allowances. Absent only
	// when PlanGroups is empty, which is the same signal the page reads to
	// decide it has no axes to render.
	GroupIndex *int     `json:"group_index,omitempty"`
	Total      *float64 `json:"total,omitempty"`
	Used       *float64 `json:"used,omitempty"`
	Remaining  *float64 `json:"remaining,omitempty"`
	ExpiresAt  string   `json:"expires_at,omitempty"`
	// RemainingFraction is the bucket's remaining share of its own total,
	// computed once on the Go side so the page renders the same number the host
	// quota group does instead of dividing again. Absent whenever either end is
	// unread, so the page shows "未知" rather than a fraction of nothing.
	RemainingFraction *float64 `json:"remaining_fraction,omitempty"`
	// Meter and UnitType are what the bucket counts and in what unit. They are
	// the difference between "59534117 left" and "59534117 model tokens left",
	// and both stay absent when the upstream stated neither.
	Meter    string `json:"meter,omitempty"`
	UnitType string `json:"unit_type,omitempty"`
	// Period is the bucket's recurrence as the upstream spells it, folded in
	// from the granting entitlement. Absent means the plugin could not read it,
	// which the page renders as unknown rather than as a non-recurring bucket.
	Period string `json:"period,omitempty"`
	// Grant is the amount the entitlement granted, which is not the bucket
	// total: a bucket whose grant spans several windows may spend less at once
	// than it was granted.
	Grant *float64 `json:"grant,omitempty"`
	// PeriodStart and PeriodEnd bound the window the numbers belong to. A
	// recurring bucket restarts at PeriodEnd; a one-time grant does not.
	PeriodStart *float64 `json:"period_start,omitempty"`
	PeriodEnd   *float64 `json:"period_end,omitempty"`
	// Malformed marks a row whose numeric fields drifted from the observed
	// schema. It stays visible with its unknown values instead of vanishing,
	// so the page shows the drift rather than silently hiding a balance.
	Malformed bool `json:"malformed,omitempty"`
}

// accountView reads one auth record and renders its redacted view. A record
// the plugin cannot read keeps its place on the page with a sanitized
// read-error summary instead of vanishing.
func (s managementService) accountView(ctx context.Context, entry pluginapi.HostAuthFileEntry) accountView {
	view := accountView{
		AuthIndex: entry.AuthIndex,
		FileName:  entry.Name,
		Label:     entry.Label,
		Disabled:  entry.Disabled,
	}
	doc, err := s.store.Get(ctx, entry.AuthIndex)
	if err != nil {
		view.ReadError = "auth document could not be read"
		return view
	}
	namespace, err := readAccountNamespace(doc)
	if err != nil {
		view.ReadError = "auth document is not a readable ZCode record"
		return view
	}
	view.IdentityID = namespace.IdentityID
	view.JWT = namespace.JWT
	view.APIKey = namespace.APIKey
	view.OAuth = namespace.OAuth
	view.Plan = planViewFor(readPlanSnapshotSection(doc))
	view.Login = loginViewFor(doc)
	if namespace.IdentityID != "" {
		if observation, ok := activeQuotaCache.get(namespace.IdentityID); ok {
			view.Quota = quotaViewFor(observation)
		}
	}
	return view
}

// accountNamespace is the typed redacted view of one record's zcode
// namespace. Its reader copies only the fields below — the JWT token, the
// key material, and the OAuth access token have no field here by
// construction.
type accountNamespace struct {
	IdentityID string
	JWT        *jwtView
	APIKey     *apiKeyView
	OAuth      *oauthView
}

// readAccountNamespace decodes the plugin-owned namespace of an auth document
// into its redacted view. Unknown host-owned fields around it are ignored,
// and sections that are not objects render as absent rather than failing the
// whole record.
func readAccountNamespace(doc []byte) (accountNamespace, error) {
	var root struct {
		Zcode struct {
			IdentityID string         `json:"identity_id"`
			JWT        map[string]any `json:"jwt"`
			APIKey     map[string]any `json:"api_key"`
			OAuth      map[string]any `json:"oauth"`
		} `json:"zcode"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(doc), &root); err != nil {
		return accountNamespace{}, errAuthDocument
	}
	if strings.TrimSpace(root.Zcode.IdentityID) == "" {
		return accountNamespace{}, errAuthDocument
	}
	namespace := accountNamespace{IdentityID: strings.TrimSpace(root.Zcode.IdentityID)}
	if root.Zcode.JWT != nil {
		namespace.JWT = &jwtView{
			Present:       strings.TrimSpace(stringField(root.Zcode.JWT, "token")) != "",
			Status:        normalizeStatus(stringField(root.Zcode.JWT, "status")),
			RetryAfter:    stringField(root.Zcode.JWT, "retry_after"),
			LastCheckedAt: stringField(root.Zcode.JWT, "last_checked_at"),
			LastErrorCode: stringField(root.Zcode.JWT, "last_error_code"),
		}
		// The suggestion is only meaningful for a credential that is otherwise
		// usable: one already recorded invalid or exhausted says what is wrong
		// more precisely than an age would.
		if namespace.JWT.Present && jwtUsable(namespace.JWT.Status, namespace.JWT.RetryAfter, time.Now()) {
			namespace.JWT.ReauthSuggested = jwtPastReauth(
				strings.TrimSpace(stringField(root.Zcode.JWT, "token")),
				readOAuthMaterial(doc), time.Now())
		}
	}
	if root.Zcode.APIKey != nil {
		view := &apiKeyView{
			Present:    strings.TrimSpace(stringField(root.Zcode.APIKey, "key_material")) != "",
			Managed:    boolField(root.Zcode.APIKey, "managed"),
			Status:     normalizeStatus(stringField(root.Zcode.APIKey, "status")),
			RetryAfter: stringField(root.Zcode.APIKey, "retry_after"),
			UpdatedAt:  stringField(root.Zcode.APIKey, "updated_at"),
			Name:       stringField(root.Zcode.APIKey, "name"),
			KeyID:      stringField(root.Zcode.APIKey, "key_id"),
		}
		if lastError, ok := root.Zcode.APIKey["last_error"].(map[string]any); ok {
			view.LastError = &keyOpError{
				Stage:   stringField(lastError, "stage"),
				Message: stringField(lastError, "message"),
				At:      stringField(lastError, "at"),
			}
		}
		namespace.APIKey = view
	}
	if root.Zcode.OAuth != nil {
		namespace.OAuth = &oauthView{
			HasAccessToken: strings.TrimSpace(stringField(root.Zcode.OAuth, "access_token")) != "",
			ReceivedAt:     stringField(root.Zcode.OAuth, "received_at"),
		}
		// A recorded exchange failure is only still true when no business token
		// has been obtained since; a later successful exchange clears both.
		if reason := stringField(root.Zcode.OAuth, "business_token_error"); reason != "" &&
			strings.TrimSpace(stringField(root.Zcode.OAuth, "business_token")) == "" {
			namespace.OAuth.ReauthRequired = true
			namespace.OAuth.Reason = reason
		}
	}
	return namespace, nil
}

// planViewFor renders a persisted Start Plan reading for the page. It copies the
// section as stored rather than re-deriving anything: the page must not present
// a second opinion of the entitlement, only the one the plugin actually
// scheduled from.
func planViewFor(section planSnapshotSection) *planSnapshotView {
	if section.CheckedAt == "" && len(section.PlanIDs) == 0 && len(section.Models) == 0 {
		// A record with no snapshot at all has never been read, which is not the
		// same as having been read as empty. The page says so instead of showing a
		// plan list of nothing.
		return nil
	}
	view := &planSnapshotView{
		CheckedAt:    section.CheckedAt,
		Readable:     section.Readable,
		PlanIDs:      section.PlanIDs,
		Instances:    section.Instances,
		LastPriority: section.LastTried,
	}
	if len(section.Models) > 0 {
		view.Models = make(map[string]modelAllowanceView, len(section.Models))
		for model, line := range section.Models {
			view.Models[model] = modelAllowanceView{
				Allowance: line.Allowance,
				ResetAt:   line.ResetAt,
				Buckets:   line.BucketCount,
				Funded:    line.FundedCount,
			}
		}
	}
	return view
}

// loginViewFor renders the account identity one login produced. A record with no
// login section predates this and is rendered as absent rather than as an empty
// digest, which would read as though an account id had been recorded and lost.
func loginViewFor(doc []byte) *loginView {
	var root struct {
		Zcode struct {
			Login map[string]any `json:"login"`
		} `json:"zcode"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(doc), &root); err != nil || root.Zcode.Login == nil {
		return nil
	}
	hash := stringField(root.Zcode.Login, "user_id_hash")
	if hash == "" {
		return nil
	}
	return &loginView{UserIDHash: hash, CheckedAt: stringField(root.Zcode.Login, "checked_at")}
}

// boolField reads a boolean field, tolerating a section that holds another
// JSON type for it.
func boolField(section map[string]any, key string) bool {
	value, _ := section[key].(bool)
	return value
}

// quotaViewFor renders a cached observation for the account view. The buckets
// keep the order the upstream listed them and each names the axis it belongs
// to, so the page can group them without re-deriving ownership from a plan
// list it never receives.
func quotaViewFor(observation quotaObservation) *quotaView {
	view := &quotaView{
		State:     observation.State,
		Reason:    observation.Reason,
		CheckedAt: observation.CheckedAt.UTC().Format(time.RFC3339),
		Plan:      observation.Plan,
		PlanCount: observation.PlanCount,
	}
	groups, axis := placeBucketsByPlan(observation.Plans, observation.Balances)
	for i, balance := range observation.Balances {
		view.Balances = append(view.Balances, quotaBalanceView{
			Name:              balanceDisplayName(balance),
			GroupIndex:        &axis[i],
			Total:             balance.Total,
			Used:              balance.Used,
			Remaining:         balance.Remaining,
			ExpiresAt:         balance.ExpiresAt,
			RemainingFraction: quotaFractionPointer(balance),
			Meter:             balance.Meter,
			UnitType:          balance.UnitType,
			Period:            balance.Period,
			Grant:             balance.GrantUnits,
			PeriodStart:       balance.PeriodStart,
			PeriodEnd:         balance.PeriodEnd,
			Malformed:         balance.Malformed,
		})
	}
	for _, group := range groups {
		view.PlanGroups = append(view.PlanGroups, quotaPlanGroupView{
			Label: group.Label,
			Kind:  group.Kind,
		})
	}
	return view
}

// quotaFractionPointer adapts the shared remaining-share reading to the JSON
// document's absent-means-unknown convention: an unreadable share is no key at
// all, never a zero the page would render as an empty bucket.
func quotaFractionPointer(balance quotaBalance) *float64 {
	fraction, ok := balanceRemainingFraction(balance)
	if !ok {
		return nil
	}
	return &fraction
}

// managementActionRequest is the fixed contract of the action route.
type managementActionRequest struct {
	Action    string `json:"action"`
	AuthIndex string `json:"auth_index"`
}

// runManagementAction dispatches one action POST. Malformed input, unknown
// actions, and missing or unknown auth indexes answer with normalized status
// codes and sanitized messages.
func runManagementAction(body []byte, now time.Time) pluginapi.ManagementResponse {
	svc := defaultManagementService()
	return svc.action(context.Background(), body, now)
}

// managementLocks serializes management actions per account. It is
// deliberately separate from the credential recorder's identity locks: a
// management action holds its lock across upstream probes, and holding the
// recorder's lock that long would stall request-side state writes for the
// whole probe. The recorder's writes stay atomic under its own registry, and
// the guarded recovery (OnlyIfStatus) makes any interleaving of a management
// refresh with a concurrent execution conclusion safe.
var managementLocks = newIdentityLocks()

func (s managementService) action(ctx context.Context, body []byte, now time.Time) pluginapi.ManagementResponse {
	var req managementActionRequest
	if trimmed := bytes.TrimSpace(body); len(trimmed) > 0 {
		if err := json.Unmarshal(trimmed, &req); err != nil {
			return managementErrorResponse(http.StatusBadRequest, "invalid_request", "the action body is not valid JSON")
		}
	}
	req.Action = strings.TrimSpace(req.Action)
	req.AuthIndex = strings.TrimSpace(req.AuthIndex)

	if req.Action == actionBatchRefresh {
		if req.AuthIndex != "" {
			return managementErrorResponse(http.StatusBadRequest, "invalid_request", "batch_refresh operates on every account and takes no auth_index")
		}
		return s.batchRefresh(ctx, now)
	}

	switch req.Action {
	case actionRefreshCredential, actionRefreshQuota, actionRefreshModels, actionOAuthRetry:
	default:
		return managementErrorResponse(http.StatusBadRequest, "unknown_action", "unknown action: "+req.Action)
	}
	if req.AuthIndex == "" {
		return managementErrorResponse(http.StatusBadRequest, "invalid_request", "this action requires an explicit auth_index")
	}

	// The snapshot happens before the lock: the action validates the account
	// it was asked for, then serializes against everything else that touches
	// the same identity.
	doc, err := s.store.Get(ctx, req.AuthIndex)
	if err != nil {
		return managementErrorResponse(http.StatusNotFound, "unknown_auth_index", "no ZCode account matches this auth_index")
	}
	namespace, err := readAccountNamespace(doc)
	if err != nil {
		return managementErrorResponse(http.StatusNotFound, "unknown_auth_index", "no ZCode account matches this auth_index")
	}
	// A re-authorization is the recovery path for a record whose credentials
	// are gone entirely, so only oauth_retry may act on a record that holds
	// no readable credential; the state-touching actions need the snapshot.
	var snap credentialSnapshot
	if req.Action != actionOAuthRetry {
		snap, err = readCredentialSnapshot(doc)
		if err != nil {
			return managementErrorResponse(http.StatusConflict, "account_unreadable", "the account's credential record could not be read")
		}
	}

	unlock, ok := managementLocks.tryLock(identityLockKey(namespace.IdentityID, req.AuthIndex))
	if !ok {
		return managementErrorResponse(http.StatusConflict, "operation_conflict", "another operation for this account is already running")
	}
	defer unlock()

	switch req.Action {
	case actionRefreshCredential:
		return s.refreshCredential(ctx, req.AuthIndex, doc, snap, now)
	case actionRefreshQuota:
		return s.refreshQuota(ctx, req.AuthIndex, doc, snap, now)
	case actionRefreshModels:
		return s.refreshModels(ctx, req.AuthIndex, doc, now)
	case actionOAuthRetry:
		return s.oauthRetry(req.AuthIndex)
	default:
		return managementErrorResponse(http.StatusBadRequest, "unknown_action", "unknown action: "+req.Action)
	}
}

// actionResult is the success envelope of a management action.
func actionResult(payload map[string]any) pluginapi.ManagementResponse {
	payload["ok"] = true
	return managementJSONResponse(payload)
}

// credentialOutcomeView reports one credential's refresh conclusion.
type credentialOutcomeView struct {
	Credential string `json:"credential"`
	Attempted  bool   `json:"attempted"`
	Status     string `json:"status,omitempty"`
	Code       string `json:"code,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// refreshCredential re-validates every credential the account holds against
// its own upstream environment and records the conclusions through the shared
// state machine. It is the manual recovery path for invalid and exhausted
// states that a quota refresh may not touch.
func (s managementService) refreshCredential(ctx context.Context, authIndex string, doc []byte, snap credentialSnapshot, now time.Time) pluginapi.ManagementResponse {
	outcomes := refreshCredentialsForAccount(ctx, s.recorder, s.cfg, authIndex, doc, snap, now)
	payload := map[string]any{
		"action":      actionRefreshCredential,
		"auth_index":  authIndex,
		"credentials": outcomes,
	}
	return actionResult(payload)
}

// refreshCredentialsForAccount performs the bounded upstream re-validation of
// both credentials. The models endpoint of each environment is the verified
// lightweight authenticated call — the same transport discovery uses — so a
// refresh cannot diverge from what execution observes. Unlike the model
// cache path, an unusable credential is probed anyway: re-testing it is the
// point of the action.
func refreshCredentialsForAccount(ctx context.Context, recorder *credentialStateRecorder, cfg Config, authIndex string, doc []byte, snap credentialSnapshot, now time.Time) []credentialOutcomeView {
	outcomes := []credentialOutcomeView{}
	for _, kind := range []CredentialKind{CredentialJWT, CredentialAPIKey} {
		env := discoveryEnvironments[kind]
		view := credentialOutcomeView{Credential: string(kind)}
		if strings.TrimSpace(env.material(snap)) == "" {
			view.Reason = "credential_missing"
			outcomes = append(outcomes, view)
			continue
		}
		target, ok := buildDiscoveryTarget(kind, snap, cfg, deviceIdentity(authIndex, doc))
		if !ok {
			view.Reason = "credential_unavailable"
			outcomes = append(outcomes, view)
			continue
		}
		view.Attempted = true
		failure := probeCredential(ctx, target)
		if failure == nil {
			// A successful probe proves the credential authenticates. For the
			// JWT that is no evidence about quota — exhausted recovers through
			// the quota refresh alone, so the conclusion is guarded against
			// clearing it. The managed API key has no billing surface at all,
			// so its probe is the only explicit recovery evidence that exists:
			// after a 402 the same endpoint accepting the key again is what
			// "the exhaustion cleared" observably means.
			conclusion := recordedState{
				Kind:   kind,
				Status: activeStatusFor(kind),
			}
			if kind == CredentialJWT {
				conclusion.NotIfStatus = jwtStatusExhausted
			}
			writeErr := recordConclusion(ctx, recorder, authIndex, snap, doc, conclusion)
			view.Status = conclusion.Status
			if writeErr != nil {
				view.Reason = "state_write_failed"
			}
			outcomes = append(outcomes, view)
			continue
		}
		conclusion := conclusionFor(kind, failure, now)
		if conclusion.Status == "" {
			// A class that says nothing about the credential — a plain
			// request rejection — records no state, exactly like execution.
			view.Reason = failure.Code
			outcomes = append(outcomes, view)
			continue
		}
		writeErr := recordConclusion(ctx, recorder, authIndex, snap, doc, conclusion)
		view.Status = conclusion.Status
		view.Code = conclusion.Code
		if writeErr != nil {
			view.Reason = "state_write_failed"
		}
		outcomes = append(outcomes, view)
	}
	return outcomes
}

// probeCredential performs one bounded authenticated GET against a
// credential's models endpoint and classifies the outcome with the shared
// upstream failure vocabulary. A nil result means the credential
// authenticated successfully.
func probeCredential(ctx context.Context, target discoveryTarget) *upstreamFailure {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
	if err != nil {
		return transportFailure(err)
	}
	req.Header = target.Headers.Clone()
	resp, err := quotaHTTPClient.Do(req)
	if err != nil {
		return transportFailure(err)
	}
	defer drainAndClose(resp.Body)
	body, readErr := readLimited(resp.Body, maxQuotaBodyBytes)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if readErr != nil {
			return transportFailure(readErr)
		}
		return classifyUpstreamFailure(resp.StatusCode, body)
	}
	if readErr != nil {
		return transportFailure(readErr)
	}
	return nil
}

// recordConclusion applies one conclusion through the recorder. The request's
// own document rides along as the read fallback. A write loss is returned to
// the caller; the observation itself was already made and is rendered either
// way.
func recordConclusion(ctx context.Context, recorder *credentialStateRecorder, authIndex string, snap credentialSnapshot, doc []byte, conclusion recordedState) error {
	return recorder.record(ctx, credentialRef{
		AuthIndex:  authIndex,
		IdentityID: snap.IdentityID,
		Document:   doc,
	}, conclusion)
}

// refreshQuota performs one quota refresh and reports the evidence and the
// state conclusions it produced.
func (s managementService) refreshQuota(ctx context.Context, authIndex string, doc []byte, snap credentialSnapshot, now time.Time) pluginapi.ManagementResponse {
	if snap.JWTToken == "" {
		return managementErrorResponse(http.StatusConflict, "no_jwt_credential", "this account holds no Coding Plan JWT, which is the only credential with a verified billing endpoint")
	}
	scope := quotaRefreshScope{
		AuthIndex:  authIndex,
		IdentityID: snap.IdentityID,
		JWT:        snap.JWTToken,
		AppVersion: s.cfg.Product.AppVersion,
		Document:   doc,
	}
	evidence, recordErr := runQuotaRefresh(ctx, s.store, scope, now)
	payload := map[string]any{
		"action":     actionRefreshQuota,
		"auth_index": authIndex,
		"quota":      quotaViewFor(observationFor(evidence, now)),
	}
	// Only a conclusion that actually applies to the credential's recorded
	// state is reported. The recovery conclusions are guarded on that state, so
	// a refresh that cleared exhaustion must not also claim to have cleared an
	// unrelated conclusion it never matched.
	conclusions := []string{}
	for _, update := range quotaStateUpdates(evidence, now) {
		if !conclusionApplies(update, snap.JWTStatus) {
			continue
		}
		conclusions = append(conclusions, update.Status)
	}
	payload["recorded"] = conclusions
	// The upstream reading succeeded even when its state write did not, so
	// the evidence is reported with the write loss named instead of turning
	// the whole action into an error that hides the observation.
	if recordErr != nil {
		payload["state_write_failed"] = true
	}
	return actionResult(payload)
}

// refreshModels forces a model cache refresh for the account.
func (s managementService) refreshModels(ctx context.Context, authIndex string, doc []byte, now time.Time) pluginapi.ManagementResponse {
	outcomes := refreshAccountModels(ctx, s.cfg, s.catalog, authIndex, doc, now)
	payload := map[string]any{
		"action":       actionRefreshModels,
		"auth_index":   authIndex,
		"environments": outcomes,
	}
	return actionResult(payload)
}

// oauthRetry re-initiates the OAuth authorization for one existing account.
// It creates a fresh authorization session through the same path the host's
// native login entry uses, returns the browser authorization link, and lets
// the plugin's own bounded poll loop complete the login into the host auth
// store — the management page is a second entry, never a third flow. The
// authorize URL is returned here deliberately: it is the one artifact the
// operator must open to finish the retry, it belongs to this session alone,
// and it dies with the session TTL. The redacted state views still never
// carry it.
func (s managementService) oauthRetry(authIndex string) pluginapi.ManagementResponse {
	session, err := startAuthorizationSession(s.cfg)
	if err != nil {
		if errors.Is(err, errOAuthUpstream) {
			return managementErrorResponse(http.StatusBadGateway, "oauth_upstream_failed", "the authorization upstream could not start a session; try again")
		}
		return managementErrorResponse(http.StatusInternalServerError, "plugin_error", "could not create authorization session")
	}
	managementOAuth.start(session, s.store, s.cfg)
	return actionResult(map[string]any{
		"action":     actionOAuthRetry,
		"auth_index": authIndex,
		"session": map[string]any{
			"state":         string(authSessionPending),
			"authorize_url": session.authorizeURL,
			"expires_at":    session.expiresAt.UTC().Format(time.RFC3339),
		},
	})
}

// batchOutcomeView is one account's line in a batch summary.
type batchOutcomeView struct {
	AuthIndex  string `json:"auth_index"`
	IdentityID string `json:"identity_id,omitempty"`
	Outcome    string `json:"outcome"` // "ok" | "failed" | "skipped"
	Message    string `json:"message,omitempty"`
}

// batchRefresh snapshots every account first, then refreshes credentials and
// quota for each within that account's identity lock, in bounded concurrency.
// One account's failure never stops the others; the summary names every
// outcome.
func (s managementService) batchRefresh(ctx context.Context, now time.Time) pluginapi.ManagementResponse {
	entries, err := s.store.List(ctx)
	if err != nil {
		return managementErrorResponse(http.StatusBadGateway, "auth_store_unavailable", "the host auth store could not be listed")
	}
	// The snapshot: the accounts the batch will touch, fixed before any work
	// starts, so accounts added or removed mid-batch are not pulled in.
	type batchItem struct {
		authIndex  string
		identityID string
		doc        []byte
	}
	items := []batchItem{}
	for _, entry := range entries {
		if entry.Provider != pluginID && entry.Type != pluginID {
			continue
		}
		if strings.TrimSpace(entry.AuthIndex) == "" {
			continue
		}
		item := batchItem{authIndex: entry.AuthIndex}
		if doc, err := s.store.Get(ctx, entry.AuthIndex); err == nil {
			if namespace, err := readAccountNamespace(doc); err == nil {
				item.identityID = namespace.IdentityID
				item.doc = doc
			}
		}
		items = append(items, item)
	}

	concurrency := s.cfg.Quota.RefreshConcurrency
	if concurrency <= 0 {
		concurrency = defaultRefreshConcurrency
	}
	results := make([]batchOutcomeView, len(items))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, item := range items {
		wg.Add(1)
		go func(i int, item batchItem) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = s.batchRefreshOne(ctx, item.authIndex, item.identityID, item.doc, now)
		}(i, item)
	}
	wg.Wait()

	succeeded, failed, skipped := 0, 0, 0
	for _, result := range results {
		switch result.Outcome {
		case "ok":
			succeeded++
		case "skipped":
			skipped++
		default:
			failed++
		}
	}
	return actionResult(map[string]any{
		"action":    actionBatchRefresh,
		"total":     len(results),
		"succeeded": succeeded,
		"failed":    failed,
		"skipped":   skipped,
		"results":   results,
	})
}

// batchRefreshOne refreshes one snapshotted account: its credentials and,
// when a JWT exists, its quota. A busy identity lock is a skip, not an
// error — the batch reports it and moves on.
func (s managementService) batchRefreshOne(ctx context.Context, authIndex, identityID string, doc []byte, now time.Time) batchOutcomeView {
	result := batchOutcomeView{AuthIndex: authIndex, IdentityID: identityID}
	if len(bytes.TrimSpace(doc)) == 0 {
		result.Outcome = "failed"
		result.Message = "the account's credential record could not be read"
		return result
	}
	unlock, ok := managementLocks.tryLock(identityLockKey(identityID, authIndex))
	if !ok {
		result.Outcome = "skipped"
		result.Message = "another operation for this account is already running"
		return result
	}
	defer unlock()

	snap, err := readCredentialSnapshot(doc)
	if err != nil {
		result.Outcome = "failed"
		result.Message = "the account's credential record could not be read"
		return result
	}
	credentialOutcomes := refreshCredentialsForAccount(ctx, s.recorder, s.cfg, authIndex, doc, snap, now)
	attempted := 0
	for _, outcome := range credentialOutcomes {
		if outcome.Attempted {
			attempted++
		}
	}
	if snap.JWTToken != "" {
		scope := quotaRefreshScope{
			AuthIndex:  authIndex,
			IdentityID: snap.IdentityID,
			JWT:        snap.JWTToken,
			AppVersion: s.cfg.Product.AppVersion,
			Document:   doc,
		}
		if _, err := runQuotaRefresh(ctx, s.store, scope, now); err != nil {
			result.Outcome = "failed"
			result.Message = "the quota result could not be recorded"
			return result
		}
	}
	if attempted == 0 && snap.JWTToken == "" {
		result.Outcome = "failed"
		result.Message = "the account holds no credential to refresh"
		return result
	}
	result.Outcome = "ok"
	return result
}

// oauthRetryRunner drives management-initiated authorization sessions: it
// polls the session upstream on a fixed cadence until the flow reaches a
// terminal state, persisting the completed credentials through the auth
// store — the step the host performs for native logins.
type oauthRetryRunner struct {
	mu      sync.Mutex
	cancels map[string]context.CancelFunc
}

func newOAuthRetryRunner() *oauthRetryRunner {
	return &oauthRetryRunner{cancels: map[string]context.CancelFunc{}}
}

// managementOAuth drives every management-initiated authorization session.
var managementOAuth = newOAuthRetryRunner()

// managementPollInterval is the upstream poll cadence of a
// management-initiated session. The host's own poll cadence is whatever the
// native login UI chooses; this one only needs to observe the flow promptly
// without leaning on the upstream.
var managementPollInterval = 3 * time.Second

// start begins the completion loop for one session, replacing any loop a
// previous action left for the same session id.
func (r *oauthRetryRunner) start(session *authSession, store AuthStore, cfg Config) {
	r.stop(session.id)
	ctx, cancel := context.WithCancel(context.Background())
	r.mu.Lock()
	r.cancels[session.id] = cancel
	r.mu.Unlock()
	go func() {
		defer func() {
			r.mu.Lock()
			delete(r.cancels, session.id)
			r.mu.Unlock()
			cancel()
		}()
		r.run(ctx, session, store, cfg)
	}()
}

// stop cancels one session's loop.
func (r *oauthRetryRunner) stop(sessionID string) {
	r.mu.Lock()
	cancel, ok := r.cancels[sessionID]
	delete(r.cancels, sessionID)
	r.mu.Unlock()
	if ok {
		cancel()
	}
}

// stopAll cancels every loop; it runs from plugin shutdown.
func (r *oauthRetryRunner) stopAll() {
	r.mu.Lock()
	cancels := r.cancels
	r.cancels = map[string]context.CancelFunc{}
	r.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
}

// running reports whether a loop is active for one session id.
func (r *oauthRetryRunner) running(sessionID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.cancels[sessionID]
	return ok
}

// run polls one session until it reaches a terminal state, the session
// expires, or the plugin shuts down. Transient upstream trouble keeps the
// loop going — the session TTL bounds the wait — and a completed login is
// persisted through the auth store under the identity's stable file name.
func (r *oauthRetryRunner) run(ctx context.Context, session *authSession, store AuthStore, cfg Config) {
	ticker := time.NewTicker(managementPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if session.expireIfDue(time.Now()) != authSessionPending {
			return
		}
		pollCtx, cancel, ok := session.sessionRequestContext(ctx, oauthRequestTimeout)
		if !ok {
			return
		}
		body, statusCode, err := session.pollUpstream(pollCtx, oauthUpstreamBase, min(maxOAuthBodyBytes, cfg.Upstream.MaxResponseBytes))
		cancel()
		if err != nil || statusCode < 200 || statusCode > 299 {
			// Transient upstream or network trouble: keep polling until the
			// session TTL ends the flow.
			continue
		}
		outcome := applyPollVerdict(session, body, func(identityID string, storage []byte) error {
			// The completed login replaces the record's document wholesale, so
			// the save must hold the same per-identity lock the credential
			// recorder holds across its read-patch-save: without it, a request
			// whose state write was snapshotted before this save could land
			// last and clobber the fresh login with the stale document.
			unlock := identityLockRegistry.lock(identityLockKey(identityID, ""))
			defer unlock()
			return store.Save(ctx, authFileNameFor(identityID), json.RawMessage(storage))
		})
		if outcome.Kind != pollPending {
			return
		}
	}
}
