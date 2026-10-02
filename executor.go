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

// hostProvider is the seam resolving the Host facade for execution work, so
// tests can inject a fake host instead of the CGO bridge. It mirrors the
// authStoreProvider seam used by the OAuth flow.
var hostProvider = func() Host { return pluginHost() }

// activeExecutions tracks in-flight execution work so plugin shutdown can
// cancel it; a shared library must never keep pumping into a stopped host.
var activeExecutions = newExecutionRegistry()

// executionRegistry tracks in-flight execution work so plugin shutdown can
// cancel it; a shared library must never keep pumping into a stopped host.
type executionRegistry struct {
	mu     sync.Mutex
	active map[*registryEntry]struct{}
}

// registryEntry is a comparable handle for one registered cancellation.
type registryEntry struct {
	cancel context.CancelFunc
}

func newExecutionRegistry() *executionRegistry {
	return &executionRegistry{active: map[*registryEntry]struct{}{}}
}

// add registers one cancel func and returns the matching remove func.
func (r *executionRegistry) add(cancel context.CancelFunc) func() {
	entry := &registryEntry{cancel: cancel}
	r.mu.Lock()
	r.active[entry] = struct{}{}
	r.mu.Unlock()
	return func() {
		r.mu.Lock()
		delete(r.active, entry)
		r.mu.Unlock()
	}
}

// cancelAll cancels every in-flight execution. Registered cancels whose
// remove func runs later are no-ops.
func (r *executionRegistry) cancelAll() {
	r.mu.Lock()
	entries := make([]*registryEntry, 0, len(r.active))
	for entry := range r.active {
		entries = append(entries, entry)
	}
	r.active = map[*registryEntry]struct{}{}
	r.mu.Unlock()
	for _, entry := range entries {
		entry.cancel()
	}
}

// executorRequestRPC mirrors the host RPC schema for executor.execute and
// executor.execute_stream: the pluginapi.ExecutorRequest fields use Go field
// names, extended by the host-assigned stream identity.
type executorRequestRPC struct {
	pluginapi.ExecutorRequest
	StreamID       string `json:"stream_id"`
	HostCallbackID string `json:"host_callback_id"`
}

// executorStreamResponseRPC mirrors the host RPC schema of the
// executor.execute_stream result. Chunks stay empty: this plugin streams
// asynchronously through host.stream.emit and closes the stream exactly once.
type executorStreamResponseRPC struct {
	Headers http.Header                     `json:"headers,omitempty"`
	Chunks  []pluginapi.ExecutorStreamChunk `json:"chunks,omitempty"`
}

// handleExecutorIdentifier answers the host's executor discovery call.
func handleExecutorIdentifier() ([]byte, error) {
	return okEnvelope(struct {
		Identifier string `json:"identifier"`
	}{Identifier: pluginID})
}

// handleExecutorExecute serves one non-streaming request by aggregating the
// shared upstream SSE pump under the configured response size limit.
func handleExecutorExecute(request []byte) ([]byte, error) {
	req, envErr := decodeExecutorRequest(request)
	if envErr != nil {
		return envErr, nil
	}
	cfg := currentConfig()
	tag := diagRequestTag()
	authIndex := strings.TrimSpace(req.AuthID)
	// The document is read once and the identity resolved from that same read,
	// so the payload's metadata.device_id and the profile's X-Device-Mid
	// header come from one resolution and can never describe two devices.
	doc := currentAuthDocument(authIndex, req.StorageJSON)
	identity := requestIdentityFor(authIndex, doc)
	payload, model, envErr := prepareUpstreamPayload(req.Payload, req.Model, cfg.Models, identity, cfg.IsInjectOfficialSystemPrefixEnabled())
	if envErr != nil {
		diagf("request tag=%s mode=aggregate rejected: payload could not be prepared", tag)
		return envErr, nil
	}
	diagf("request tag=%s mode=aggregate auth=%s model_in=%q model_out=%q payload=%dB",
		tag, strings.TrimSpace(req.AuthID), req.Model, model, len(payload))
	scope, profiles, failure := newExecutionScope(req, cfg, model, doc, identity, tag)
	if failure != nil {
		diagf("plan tag=%s auth=%s no-credential class=%s code=%s msg=%q",
			tag, strings.TrimSpace(req.AuthID), failure.Class, failure.Code, failure.Message)
		return failureEnvelope(failure), nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	remove := activeExecutions.add(cancel)
	defer remove()
	defer cancel()

	// The aggregate of the attempt that answered the request is the one the
	// caller receives, so the loop hands it back with the outcome.
	outcome, sink := runExecution(ctx, scope, profiles, payload, func() answerSink {
		agg := newAggregateForwarder(scope.Primary.MaxResponseBytes)
		return answerSink{forwarder: agg, render: agg.finish}
	})
	if outcome.Failure != nil {
		diagf("request tag=%s outcome=failure class=%s code=%s msg=%q",
			tag, outcome.Failure.Class, outcome.Failure.Code, outcome.Failure.Message)
		return failureEnvelope(outcome.Failure), nil
	}
	payloadOut, err := sink.render()
	if err != nil {
		diagf("request tag=%s outcome=failure render_error msg=%q", tag, err)
		return failureEnvelope(failureFromError(err)), nil
	}
	diagf("request tag=%s outcome=ok response=%dB", tag, len(payloadOut))
	return okEnvelope(pluginapi.ExecutorResponse{
		Payload: payloadOut,
		Headers: http.Header{"Content-Type": []string{"application/json"}},
	})
}

// newExecutionScope resolves the credential attempts of one request and the
// auth record their states belong to. The document and the request identity
// are resolved once by the entry point and passed in, so the plan, the payload
// metadata, and the profile headers all consume the same read of the record
// and the same identity. The scope is the only place the credential recorder
// is wired in, so the attempt loop itself stays free of host handles. It
// returns a non-nil failure only when no credential at all could be attempted.
func newExecutionScope(req executorRequestRPC, cfg Config, model string, doc []byte, identity requestIdentity, diagTag string) (executionScope, []ResolvedProfile, *upstreamFailure) {
	now := time.Now()
	authIndex := strings.TrimSpace(req.AuthID)
	plan := executionPlan(doc, cfg, model, req.Headers, identity, now)
	if plan.Failure != nil {
		return executionScope{}, nil, plan.Failure
	}
	// The window is the one already recorded on the record, never a freshly
	// anchored one: re-anchoring it on every downgraded request would slide the
	// deadline forward indefinitely and a sustained stream of fallback traffic
	// would keep the primary blocked forever.
	skipBlockStatus, skipBlockRetry := "", time.Time{}
	if plan.SkipBlockStatus != "" {
		skipBlockStatus, skipBlockRetry = skipBlockConclusion(doc, plan.SkipBlockStatus, now)
	}
	return executionScope{
		AuthIndex:       authIndex,
		IdentityID:      plan.Primary.IdentityID,
		Document:        doc,
		Primary:         plan.Primary,
		DiagTag:         diagTag,
		SkipBlockStatus: skipBlockStatus,
		SkipBlockRetry:  skipBlockRetry,
		Recorder:        credentialStates.forStore(authStoreProvider()),
		Now:             func() time.Time { return now },
	}, plan.Attempts, nil
}

// currentAuthDocument returns the credential document one request should plan
// against.
//
// The host hands each request the document as it was when the request was
// scheduled, but the upstream rotates and revokes credentials underneath the
// plugin: a re-login replaces the JWT, a state conclusion from another request
// lands on the record, and none of it is visible in a copy captured earlier. So
// the record is re-read here, once per request, and that fresh copy is what
// plans the attempt and what the request's own state conclusions are written
// against. This is the plugin's equivalent of the official client's
// shouldRefreshBeforeModelRequest, which never caches a credential across
// requests either.
//
// A store that cannot be read, or a record that is gone, falls back to the
// document the host supplied: a request the plugin can still act on is better
// than a failed one, and the store read is bounded so a slow host cannot stall
// execution.
func currentAuthDocument(authIndex string, supplied []byte) []byte {
	if authIndex == "" {
		return supplied
	}
	ctx, cancel := context.WithTimeout(context.Background(), credentialRefreshReadTimeout)
	defer cancel()
	doc, err := authStoreProvider().Get(ctx, authIndex)
	if err != nil || len(bytes.TrimSpace(doc)) == 0 {
		return supplied
	}
	return bytes.TrimSpace(doc)
}

// credentialRefreshReadTimeout bounds the per-request credential re-read.
const credentialRefreshReadTimeout = 5 * time.Second

// handleExecutorExecuteStream acknowledges the stream immediately and pumps
// upstream SSE frames through host callbacks in the background. The stream
// is closed exactly once on end, error, or cancellation.
func handleExecutorExecuteStream(request []byte) ([]byte, error) {
	req, envErr := decodeExecutorRequest(request)
	if envErr != nil {
		return envErr, nil
	}
	streamID := strings.TrimSpace(req.StreamID)
	if streamID == "" {
		return errorEnvelope("invalid_request", "executor.execute_stream requires the host stream id", http.StatusBadRequest), nil
	}
	cfg := currentConfig()
	tag := diagRequestTag()
	authIndex := strings.TrimSpace(req.AuthID)
	// Same single resolution as the aggregate path: one document read, one
	// identity, shared by the payload metadata and the profile headers.
	doc := currentAuthDocument(authIndex, req.StorageJSON)
	identity := requestIdentityFor(authIndex, doc)
	payload, model, envErr := prepareUpstreamPayload(req.Payload, req.Model, cfg.Models, identity, cfg.IsInjectOfficialSystemPrefixEnabled())
	if envErr != nil {
		diagf("request tag=%s mode=stream rejected: payload could not be prepared", tag)
		return envErr, nil
	}
	diagf("request tag=%s mode=stream stream_id=%s auth=%s model_in=%q model_out=%q payload=%dB",
		tag, streamID, strings.TrimSpace(req.AuthID), req.Model, model, len(payload))
	scope, profiles, failure := newExecutionScope(req, cfg, model, doc, identity, tag)
	if failure != nil {
		diagf("plan tag=%s auth=%s no-credential class=%s code=%s msg=%q",
			tag, strings.TrimSpace(req.AuthID), failure.Class, failure.Code, failure.Message)
		return failureEnvelope(failure), nil
	}

	sink := hostProvider().Streams()
	ctx, cancel := context.WithCancel(context.Background())
	remove := activeExecutions.add(cancel)
	go func() {
		defer remove()
		defer cancel()
		outcome, _ := runExecution(ctx, scope, profiles, payload, func() answerSink {
			return answerSink{forwarder: newStreamForwarder(sink, streamID)}
		})
		closer := newStreamCloser(sink, streamID)
		if outcome.Failure != nil {
			diagf("request tag=%s outcome=failure class=%s code=%s msg=%q",
				tag, outcome.Failure.Class, outcome.Failure.Code, outcome.Failure.Message)
			closer.Close(outcome.Failure.Message)
			return
		}
		diagf("request tag=%s outcome=ok", tag)
		closer.Close("")
	}()
	return okEnvelope(executorStreamResponseRPC{
		Headers: http.Header{"Content-Type": []string{"text/event-stream"}},
	})
}

// handleExecutorCountTokens and handleExecutorHTTPRequest keep the executor
// method surface dispatched: they return a coded refusal instead of falling
// through to unknown_method, which would signal a registration bug.
func handleExecutorCountTokens() ([]byte, error) {
	return errorEnvelope("not_supported", "count_tokens is not supported by the zcode provider", http.StatusNotImplemented), nil
}

func handleExecutorHTTPRequest() ([]byte, error) {
	return errorEnvelope("not_supported", "executor-owned HTTP requests are not supported by the zcode provider", http.StatusNotImplemented), nil
}

// decodeExecutorRequest decodes one host executor RPC request. The returned
// envelope is non-nil for malformed requests.
func decodeExecutorRequest(request []byte) (executorRequestRPC, []byte) {
	var req executorRequestRPC
	if len(bytes.TrimSpace(request)) > 0 {
		if err := json.Unmarshal(request, &req); err != nil {
			return req, errorEnvelope("invalid_request", "decode executor request: "+err.Error(), http.StatusBadRequest)
		}
	}
	return req, nil
}

// prepareUpstreamPayload normalizes the payload's model id, forces upstream
// streaming, injects the request-body identity, and applies the official
// system prefix: both streaming and non-streaming callers consume the same
// upstream SSE pump, the official client writes its identity into every
// Anthropic request body, and the gateway's integrity precheck admits only
// requests whose system leads with the official ZCode system prompt blocks
// (system_prefix.go, issue #16). The failure envelope carries the sanitized
// reason.
func prepareUpstreamPayload(payload []byte, model string, catalog []string, identity requestIdentity, injectSystemPrefix bool) ([]byte, string, []byte) {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return nil, "", errorEnvelope("invalid_request", "request payload is empty", http.StatusBadRequest)
	}
	var body map[string]any
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	if err := dec.Decode(&body); err != nil {
		return nil, "", errorEnvelope("invalid_request", "request payload is not valid JSON", http.StatusBadRequest)
	}
	if raw, ok := body["model"].(string); ok && strings.TrimSpace(raw) != "" {
		model = raw
	}
	normalizedModel := normalizeRequestModel(model, catalog)
	if normalizedModel != "" {
		body["model"] = normalizedModel
	}
	body["stream"] = true
	applyRequestMetadata(body, identity)
	if injectSystemPrefix {
		injectOfficialSystemPrefix(body)
	}
	out, err := json.Marshal(body)
	if err != nil {
		return nil, "", errorEnvelope("invalid_request", "request payload could not be encoded", http.StatusBadRequest)
	}
	return out, normalizedModel, nil
}

// credentialPlan is what one request resolved to before any upstream call: the
// credential to try first, the ordered attempts, the state that caused a
// downgrade, and the failure when no credential is usable at all.
type credentialPlan struct {
	// Primary is the credential the request runs on, which is the fallback
	// itself when the recorded primary is blocked.
	Primary ResolvedProfile
	// Attempts are the profiles to try, in order.
	Attempts []ResolvedProfile
	// SkipBlockStatus is the recorded JWT state that kept the Coding Plan JWT
	// out of this request, so the attempt loop can persist that state even
	// though the loop never runs the primary. It travels as the state itself
	// rather than as a re-rendered failure, so recording it never depends on
	// failure-code spelling, and it carries no code of its own: the persisted
	// reason belongs to the failure that produced the state.
	SkipBlockStatus string
	// Failure is non-nil only when no credential could be attempted at all.
	Failure *upstreamFailure
}

// executionPlan lists the credential attempts for one request in priority order.
// The Coding Plan JWT is the primary credential; the managed API key of the same
// upstream identity is the single fallback. A JWT that an earlier request
// recorded as unusable is skipped in favour of the key, and a key that is not
// recorded as usable removes the fallback entirely. Failures are classified and
// sanitized. now is the clock the recorded retry windows are measured against.
func executionPlan(doc []byte, cfg Config, model string, callerHeaders http.Header, identity requestIdentity, now time.Time) credentialPlan {
	snap, err := readCredentialSnapshot(doc)
	if err != nil {
		return credentialPlan{Failure: credentialProfileFailure(err)}
	}
	cfg = normalizeConfig(cfg)

	primary, primaryErr := primaryProfile(snap, cfg, model, callerHeaders, identity, now)
	fallback, fallbackErr := fallbackProfile(snap, cfg, model, callerHeaders, identity, now)

	// A JWT past its re-authorization age is still attempted — the upstream may
	// well accept it, and skipping a possibly-working primary would spend a
	// working fallback for nothing. But the fallback is then guaranteed a turn,
	// so a credential the upstream has quietly stopped honouring costs one
	// extra request rather than every subsequent one.
	if primaryErr == nil && fallbackErr == nil && jwtPastReauth(snap.JWTToken, readOAuthMaterial(doc), now) {
		return credentialPlan{Primary: primary, Attempts: []ResolvedProfile{primary, fallback}}
	}

	switch {
	case primaryErr == nil:
		// The primary is attempted first. The fallback is added only when it
		// is a genuinely usable second credential, so the attempt loop never
		// retries the same credential or an unusable one.
		attempts := []ResolvedProfile{primary}
		if fallbackErr == nil {
			attempts = append(attempts, fallback)
		}
		return credentialPlan{Primary: primary, Attempts: attempts}
	case fallbackErr == nil:
		var blocked credentialStatusError
		_ = errors.As(primaryErr, &blocked)
		return credentialPlan{
			Primary:         fallback,
			Attempts:        []ResolvedProfile{fallback},
			SkipBlockStatus: blocked.Status,
		}
	default:
		// Neither credential can be attempted. The primary's own conclusion is
		// the actionable one: a missing fallback is not the problem the caller
		// can act on.
		return credentialPlan{Failure: credentialProfileFailure(primaryErr)}
	}
}

// primaryProfile builds the Coding Plan JWT profile, or the classified failure
// explaining why this credential may not be attempted.
func primaryProfile(snap credentialSnapshot, cfg Config, model string, callerHeaders http.Header, identity requestIdentity, now time.Time) (ResolvedProfile, error) {
	if strings.TrimSpace(snap.JWTToken) == "" {
		return ResolvedProfile{}, errNoCredential
	}
	if !jwtUsable(snap.JWTStatus, snap.JWTRetryAfter, now) {
		return ResolvedProfile{}, credentialStatusError{Status: snap.JWTStatus}
	}
	return newProfile(snap, CredentialJWT, cfg, model, callerHeaders, identity), nil
}

// fallbackProfile builds the managed API key profile, or the classified failure
// explaining why no fallback credential is available.
func fallbackProfile(snap credentialSnapshot, cfg Config, model string, callerHeaders http.Header, identity requestIdentity, now time.Time) (ResolvedProfile, error) {
	if strings.TrimSpace(snap.APIKeyToken) == "" {
		return ResolvedProfile{}, credentialStatusError{Status: apiKeyStatusUnavailable}
	}
	if !apiKeyUsable(snap.APIKeyStatus, snap.APIKeyRetryAfter, now) {
		return ResolvedProfile{}, credentialStatusError{Status: snap.APIKeyStatus}
	}
	return newProfile(snap, CredentialAPIKey, cfg, model, callerHeaders, identity), nil
}

// credentialProfileFailure maps profile construction errors onto sanitized,
// classified failures. No document content or secret material is included. A
// document that is absent, truncated, or not JSON at all is reported as a
// missing credential, which is the actionable reading of a record the plugin
// cannot read.
func credentialProfileFailure(err error) *upstreamFailure {
	var unavailable credentialStatusError
	if errors.As(err, &unavailable) {
		return unavailable.failure()
	}
	if errors.Is(err, errNoCredential) || errors.Is(err, errCredentialUnavailable) ||
		errors.Is(err, errAuthDocument) {
		return &upstreamFailure{
			Class:        failureInvalid,
			ClientStatus: http.StatusUnauthorized,
			Code:         "no_credential",
			Message:      errNoCredential.Error(),
		}
	}
	return &upstreamFailure{
		Class:        failureRejected,
		ClientStatus: http.StatusInternalServerError,
		Code:         "profile_error",
		Message:      "upstream profile could not be built from the selected auth record",
	}
}

// skipBlockConclusion is the primary's recorded state, together with the
// window already on the record that the skip was decided against. A state
// this build does not know concludes nothing: recording a permanent
// conclusion for an unrecognized status would strand the account, which is
// worse than recording nothing.
func skipBlockConclusion(doc []byte, status string, now time.Time) (string, time.Time) {
	switch status {
	case jwtStatusVerificationBlocked, jwtStatusExhausted, jwtStatusPlanExpired, jwtStatusCooldown, jwtStatusInvalid:
	default:
		return "", time.Time{}
	}
	snap, err := readCredentialSnapshot(doc)
	if err != nil {
		return "", time.Time{}
	}
	if snap.JWTStatus == status && isSelfHealingStatus(status) {
		// The window is the one already on the record. Re-anchoring it here
		// would slide the deadline forward on every downgraded request, so a
		// sustained stream of fallback traffic would keep the primary blocked
		// long after it recovered. A permanent conclusion has no window at all,
		// and recovering it is a credential or quota refresh rather than time.
		return status, recordedRetryAfter(snap.JWTRetryAfter, now)
	}
	return status, time.Time{}
}

// recordedRetryAfter recovers a persisted retry window as an instant. An
// unparsable one is treated as absent so the caller falls back to anchoring a
// fresh window rather than persisting a deadline nobody can read.
func recordedRetryAfter(retryAfter string, now time.Time) time.Time {
	deadline, err := time.Parse(time.RFC3339, strings.TrimSpace(retryAfter))
	if err != nil {
		return time.Time{}
	}
	return deadline
}

// credentialStatusError marks why a credential is unavailable. The error itself
// is opaque; the recorded state travels as a wrapped field so the caller-facing
// message is always about a real credential of this account.
type credentialStatusError struct {
	Status string
}

func (e credentialStatusError) Error() string { return errCredentialUnavailable.Error() }

func (e credentialStatusError) Unwrap() error { return errCredentialUnavailable }

// failure renders a recorded credential state as the sanitized failure the
// caller sees. The wording always comes from the primary credential's state
// vocabulary: the managed key exists to take over from the Coding Plan JWT, so
// a block that skipped the primary is the actionable conclusion, and the
// fallback's own attempt — if it ran — is what produced the last failure.
func (e credentialStatusError) failure() *upstreamFailure {
	return jwtStateFailure(e.Status)
}

// jwtStateFailure is the caller-facing failure for a recorded JWT state.
func jwtStateFailure(status string) *upstreamFailure {
	switch status {
	case jwtStatusVerificationBlocked:
		return &upstreamFailure{
			Class:        failureVerificationBlocked,
			ClientStatus: http.StatusForbidden,
			Code:         "credential_verification_blocked",
			Message:      "zcode credential is waiting out a verification block; it is retried automatically",
		}
	case jwtStatusExhausted:
		return &upstreamFailure{
			Class:        failureExhausted,
			ClientStatus: http.StatusPaymentRequired,
			Code:         "credential_quota_exhausted",
			Message:      "zcode credential quota is exhausted; refresh the quota to restore it",
		}
	case jwtStatusCooldown:
		return &upstreamFailure{
			Class:        failureCooldown,
			ClientStatus: http.StatusServiceUnavailable,
			Code:         "credential_cooling_down",
			Message:      "zcode credential is cooling down after a temporary upstream failure; retry later",
		}
	default:
		return &upstreamFailure{
			Class:        failureInvalid,
			ClientStatus: http.StatusUnauthorized,
			Code:         "credential_invalid",
			Message:      errCredentialUnavailable.Error(),
		}
	}
}

// frameForwarder consumes one upstream SSE frame and reports whether any
// output already reached the caller.
type frameForwarder interface {
	Forward(ctx context.Context, frame []byte) error
	OutputStarted() bool
}

// answerSink is one attempt's output target: the frame forwarder the pump
// feeds, plus the render step for a forwarder that aggregates the answer. The
// streaming path closes through the host stream callback instead, so its
// render is nil and the returned sink is discarded.
type answerSink struct {
	forwarder frameForwarder
	render    func() ([]byte, error)
}

// executionOutcome reports one credential attempt loop's result.
type executionOutcome struct {
	// OutputStarted is true once any output reached the caller.
	OutputStarted bool
	Failure       *upstreamFailure
}

// executionScope is everything one attempt loop needs beyond the profiles: the
// auth record the credential states belong to, the config snapshot that
// decides the retry windows, the state recorder, and the clock. It carries no
// host handle, so the loop stays testable without the CGO bridge.
type executionScope struct {
	AuthIndex  string
	IdentityID string
	Document   []byte
	Primary    ResolvedProfile
	// DiagTag is the request's debug correlation tag. It is display-only:
	// debug lines interleave across concurrent requests, and the tag is what
	// ties a plan line to its attempt and outcome lines.
	DiagTag string
	// SkipBlockStatus is the recorded JWT state that skipped the primary,
	// together with the block's retry window. It is the reason this request is
	// running on a credential it would not otherwise use, so the loop records
	// it as the windowed state even when the fallback that served the request
	// itself failed for a reason of its own.
	SkipBlockStatus string
	SkipBlockRetry  time.Time
	Recorder        credentialRecorder
	// batch is the request's own conclusion accumulator, built by runExecution
	// so a request that tries both credentials still lands one save.
	batch *stateBatch
	Now   func() time.Time
}

// credentialRef projects the scope onto the host auth record.
func (s executionScope) credentialRef() credentialRef {
	return credentialRef{AuthIndex: s.AuthIndex, IdentityID: s.IdentityID, Document: s.Document}
}

// stateBatch accumulates one request's credential conclusions so a request
// that tries both credentials still lands its states as exactly one lossless
// save. add tolerates a nil batch so the attempt loop needs no guards.
type stateBatch struct {
	recorder credentialRecorder
	ref      credentialRef
	pending  []recordedState
}

func (b *stateBatch) add(state recordedState) {
	if b == nil {
		return
	}
	b.pending = append(b.pending, state)
}

// flush persists every accumulated conclusion in one recorder call. The write
// outlives the request on purpose: a conclusion reached as a stream ends must
// still land, and state is a recovery input rather than part of the caller's
// response, so a host store that cannot take the write leaves this request's
// upstream result exactly as it was.
func (b *stateBatch) flush(ctx context.Context) {
	if b == nil || b.recorder == nil {
		return
	}
	_ = b.recorder.record(context.WithoutCancel(ctx), b.ref, b.pending...)
}

// runExecution performs the credential attempt loop over the immutable
// profiles. Profiles are attempted in order; a failed attempt is retried on
// the next profile only while nothing has been forwarded to the caller, the
// failure classification permits another attempt, and the route compatibility
// rule (fallbackAllowed) allows the next profile's route to serve the request
// — which across a billing/entitlement boundary it may not, so a request-level
// verdict on one route stays an honest terminal failure instead of silently
// spending another domain. Once output started, the failure is final: a
// response must never mix output from two upstream attempts.
//
// newSink builds the output target of one attempt. Each attempt gets its own,
// so a failed attempt's partial output is discarded rather than merged into
// the next credential's answer.
func runExecution(ctx context.Context, scope executionScope, profiles []ResolvedProfile, payload []byte, newSink func() answerSink) (executionOutcome, answerSink) {
	// Every conclusion this request reaches — the skip block and both
	// credentials' outcomes — lands as exactly one save, taken after the loop
	// so one request can never interleave two state writes for one identity.
	scope.batch = &stateBatch{recorder: scope.Recorder, ref: scope.credentialRef()}
	defer scope.batch.flush(ctx)

	attemptKinds := make([]string, 0, len(profiles))
	for _, profile := range profiles {
		attemptKinds = append(attemptKinds, profile.Route.ID+"("+string(profile.Route.BillingDomain)+")")
	}
	skipBlock := scope.SkipBlockStatus
	if skipBlock == "" {
		skipBlock = "(none)"
	}
	diagf("plan tag=%s auth=%s skip_block=%s retry_after=%s attempts=[%s]",
		scope.DiagTag, scope.AuthIndex, skipBlock, diagRetryAfter(scope.SkipBlockRetry), strings.Join(attemptKinds, " "))

	if scope.SkipBlockStatus != "" {
		// The primary's block is recorded once, before the first attempt runs:
		// it is the reason this request is running on a credential it would not
		// otherwise use. The window it carries was resolved from the record, so
		// the flush re-asserts it instead of re-anchoring it.
		scope.batch.add(recordedState{Kind: CredentialJWT, Status: scope.SkipBlockStatus, RetryAfter: scope.SkipBlockRetry})
	}
	// The payload is the request exactly as the caller built it. Every
	// credential attempt below replays this one buffer, so a fallback can
	// never mutate what the caller sent.
	var lastFailure *upstreamFailure
	for i, profile := range profiles {
		sink := newSink()
		outcome := attemptProfile(ctx, scope, profile, payload, sink.forwarder)
		if outcome.Failure == nil {
			return executionOutcome{OutputStarted: outcome.OutputStarted}, sink
		}
		if outcome.OutputStarted {
			return outcome, sink
		}
		if i+1 < len(profiles) {
			next := profiles[i+1]
			if !fallbackAllowed(profile, outcome.Failure, next) {
				diagf("fallback tag=%s decision=denied class=%s logid=%q from=%s(%s) to=%s(%s)",
					scope.DiagTag, outcome.Failure.Class, outcome.Failure.LogID,
					profile.Route.ID, profile.Route.BillingDomain, next.Route.ID, next.Route.BillingDomain)
				return outcome, sink
			}
			diagf("fallback tag=%s decision=replay class=%s logid=%q from=%s(%s) to=%s(%s)",
				scope.DiagTag, outcome.Failure.Class, outcome.Failure.LogID,
				profile.Route.ID, profile.Route.BillingDomain, next.Route.ID, next.Route.BillingDomain)
		}
		lastFailure = outcome.Failure
	}
	if lastFailure == nil {
		lastFailure = &upstreamFailure{
			Class:        failureInterrupted,
			ClientStatus: http.StatusBadGateway,
			Code:         "execution_failed",
			Message:      "execution failed without a classified upstream error",
		}
	}
	return executionOutcome{Failure: lastFailure}, answerSink{}
}

// attemptProfile runs one upstream attempt against an immutable profile, reports
// whether output reached the caller, and queues the credential's conclusion for
// the request's single save. Debug lines record what went out (route, billing
// domain, sanitized headers) and what came back (classified outcome, upstream
// status, business code, bounded msg, correlation id) — the evidence an
// operator needs to compare this attempt against the official client's, without
// any credential material, prompt content, or raw bodies.
func attemptProfile(ctx context.Context, scope executionScope, profile ResolvedProfile, payload []byte, forwarder frameForwarder) executionOutcome {
	diagf("attempt tag=%s cred=%s route=%s domain=%s url=%s model=%q payload=%dB headers=[%s]",
		scope.DiagTag, profile.CredentialKind, profile.Route.ID, profile.Route.BillingDomain, profile.MessagesURL,
		profile.ModelID, len(payload), diagHeaderView(profile.Headers))
	started := time.Now()
	forwardedFrames, forwardedBytes := 0, 0
	client := upstreamClient(profile)
	err := pumpUpstream(ctx, client, profile, payload, func(frame []byte) error {
		forwardedFrames++
		forwardedBytes += len(frame)
		return forwarder.Forward(ctx, frame)
	})
	duration := time.Since(started).Round(time.Millisecond)
	if err == nil {
		diagf("attempt tag=%s cred=%s result=ok duration=%s frames=%d forwarded=%dB output_started=%v",
			scope.DiagTag, profile.CredentialKind, duration, forwardedFrames, forwardedBytes, forwarder.OutputStarted())
		scope.batch.add(recordedState{Kind: profile.CredentialKind, Status: activeStatusFor(profile.CredentialKind)})
		return executionOutcome{OutputStarted: forwarder.OutputStarted()}
	}
	failure := failureFromError(err)
	diagf("attempt tag=%s cred=%s result=failure duration=%s upstream_status=%d class=%s code=%s logid=%q output_started=%v frames=%d msg=%q",
		scope.DiagTag, profile.CredentialKind, duration, failure.UpstreamStatus, failure.Class, failure.Code,
		failure.LogID, forwarder.OutputStarted(), forwardedFrames, failure.Message)
	scope.batch.add(conclusionFor(profile.CredentialKind, failure, scope.Now()))
	return executionOutcome{Failure: failure, OutputStarted: forwarder.OutputStarted()}
}

// diagRetryAfter renders a recorded retry window for a debug line; a zero
// time means the recorded state carries no window at all.
func diagRetryAfter(retryAfter time.Time) string {
	if retryAfter.IsZero() {
		return "-"
	}
	return retryAfter.UTC().Format(time.RFC3339)
}

// activeStatusFor is the conclusion of a successful attempt: the credential is
// usable again, which also clears a windowed block whose window has passed.
func activeStatusFor(kind CredentialKind) string {
	if kind == CredentialAPIKey {
		return apiKeyStatusActive
	}
	return jwtStatusActive
}

// The two windowed states recover on their own. A verification block retries
// the JWT after five minutes, which is what keeps a blocked primary from
// stranding the account; a temporary cooldown backs off for one minute.
// Permanent conclusions carry no window: they are recovered by a credential
// refresh or a quota refresh instead.
const (
	verificationRetryWindow = 5 * time.Minute
	temporaryCooldownWindow = 1 * time.Minute
)

// conclusionFor maps one classified failure onto the credential state it
// implies. Classes that say nothing about this credential — a schema
// rejection, a cancelled request, an oversized response, a broken host
// callback — record no state at all, so a malformed request can never be
// mistaken for a credential problem. A failure recorded against the fallback
// key only ever moves the key's own state.
func conclusionFor(kind CredentialKind, failure *upstreamFailure, now time.Time) recordedState {
	conclusion := recordedState{Kind: kind, Status: statusForClass(kind, failure.Class)}
	if conclusion.Status == "" {
		return conclusion
	}
	conclusion.RetryAfter = retryWindowFor(conclusion.Status, now)
	conclusion.Code = failure.Code
	return conclusion
}

// statusVocabulary is each credential kind's translation of a failure class
// into its own state vocabulary. The fallback key is never verification-gated
// the way the Coding Plan JWT is, so a verification requirement against it is
// recorded as the temporary condition it actually is.
var statusVocabulary = map[CredentialKind]map[failureClass]string{
	CredentialJWT: {
		failureVerificationBlocked: jwtStatusVerificationBlocked,
		failureInvalid:             jwtStatusInvalid,
		failureExhausted:           jwtStatusExhausted,
		failurePlanExpired:         jwtStatusPlanExpired,
		failureCooldown:            jwtStatusCooldown,
		// A request-level rejection (failureRejected) is deliberately absent:
		// it is a statement about the request, not about the credential, so it
		// records no state and leaves both the credential and its quota valid.
	},
	CredentialAPIKey: {
		failureVerificationBlocked: apiKeyStatusCooldown,
		failureInvalid:             apiKeyStatusInvalid,
		failureExhausted:           apiKeyStatusExhausted,
		// The managed key is not held against a Coding Plan term, so an expired
		// plan says nothing about it: the key is temporary as far as the
		// upstream is concerned.
		failurePlanExpired: apiKeyStatusCooldown,
		failureCooldown:    apiKeyStatusCooldown,
	},
}

// statusForClass is the state one failure class implies for one credential. A
// class the upstream did not attribute to the credential records nothing: an
// error event the upstream streams is a statement about that request, not
// about the credential that sent it.
func statusForClass(kind CredentialKind, class failureClass) string {
	return statusVocabulary[kind][class]
}

// retryWindowFor is the automatic recovery delay of a windowed state. Only the
// two windowed states have one: a permanent conclusion recovers through a
// credential or quota refresh instead of through time.
func retryWindowFor(status string, now time.Time) time.Time {
	switch status {
	case jwtStatusVerificationBlocked:
		return now.Add(verificationRetryWindow)
	case credentialStatusCooldown:
		// One constant serves both credential schemas because both spell a
		// temporary cooldown the same way.
		return now.Add(temporaryCooldownWindow)
	default:
		return time.Time{}
	}
}

// failureFromError converts a pump error into a sanitized failure.
func failureFromError(err error) *upstreamFailure {
	var failure *upstreamFailure
	if errors.As(err, &failure) {
		return failure
	}
	var hostErr hostStreamError
	if errors.As(err, &hostErr) {
		return &upstreamFailure{
			Class:        failureInterrupted,
			ClientStatus: http.StatusBadGateway,
			Code:         "stream_forwarding_failed",
			Message:      "stream forwarding to the host failed",
		}
	}
	return transportFailure(err)
}

// streamForwarder forwards upstream frames through the host stream callback
// and tracks whether any frame reached the host.
type streamForwarder struct {
	sink     StreamSink
	streamID string
	started  bool
}

func newStreamForwarder(sink StreamSink, streamID string) *streamForwarder {
	return &streamForwarder{sink: sink, streamID: streamID}
}

func (f *streamForwarder) Forward(ctx context.Context, frame []byte) error {
	// An in-band error frame is checked before it is emitted, so a request the
	// upstream itself failed is never handed to the caller as stream content.
	if err := frameFailure(frame); err != nil {
		return err
	}
	if err := f.sink.Emit(ctx, f.streamID, frame); err != nil {
		return hostStreamError{err: err}
	}
	f.started = true
	return nil
}

func (f *streamForwarder) OutputStarted() bool { return f.started }

// hostStreamError marks a host stream callback failure; it must never be
// reported as an upstream problem.
type hostStreamError struct{ err error }

func (e hostStreamError) Error() string { return "host stream emit failed: " + e.err.Error() }

// aggregateForwarder feeds the upstream stream into the non-streaming
// response aggregator. Nothing is output until the pump finished, so the
// caller may still retry on failure.
type aggregateForwarder struct {
	agg *messageAggregator
}

func newAggregateForwarder(limit int64) *aggregateForwarder {
	return &aggregateForwarder{agg: newMessageAggregator(limit)}
}

func (f *aggregateForwarder) Forward(_ context.Context, frame []byte) error {
	return f.agg.observe(frame)
}

func (f *aggregateForwarder) OutputStarted() bool { return false }

func (f *aggregateForwarder) finish() ([]byte, error) { return f.agg.finish() }

// streamCloser closes a host stream exactly once, no matter how the pump
// ended.
type streamCloser struct {
	sink     StreamSink
	streamID string
	once     sync.Once
}

func newStreamCloser(sink StreamSink, streamID string) *streamCloser {
	return &streamCloser{sink: sink, streamID: streamID}
}

// Close forwards the terminal close to the host on the first call only; the
// error is intentionally dropped because the host may already be gone.
func (c *streamCloser) Close(errorMessage string) {
	c.once.Do(func() {
		_ = c.sink.Close(context.Background(), c.streamID, errorMessage)
	})
}

// failureEnvelope renders a classified failure as the RPC error envelope.
func failureEnvelope(failure *upstreamFailure) []byte {
	return errorEnvelope(failure.Code, failure.Message, failure.ClientStatus)
}
