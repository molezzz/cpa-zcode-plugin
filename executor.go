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
	payload, model, envErr := prepareUpstreamPayload(req.Payload, req.Model, cfg.Models)
	if envErr != nil {
		return envErr, nil
	}
	scope, profiles, failure := newExecutionScope(req, cfg, model)
	if failure != nil {
		return failureEnvelope(failure), nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	remove := activeExecutions.add(cancel)
	defer remove()
	defer cancel()

	// The aggregate of the attempt that answered the request is the one the
	// caller receives, so the loop hands it back with the outcome.
	outcome, answer := runExecution(ctx, scope, profiles, payload, func() answerForwarder {
		return newAggregateForwarder(scope.Primary.MaxResponseBytes)
	})
	if outcome.Failure != nil {
		return failureEnvelope(outcome.Failure), nil
	}
	payloadOut, err := answer.finish()
	if err != nil {
		return failureEnvelope(failureFromError(err)), nil
	}
	return okEnvelope(pluginapi.ExecutorResponse{
		Payload: payloadOut,
		Headers: http.Header{"Content-Type": []string{"application/json"}},
	})
}

// newExecutionScope resolves the credential attempts of one request and the
// auth record their states belong to. The scope is the only place the
// credential recorder is wired in, so the attempt loop itself stays free of
// host handles. It returns a non-nil failure only when no credential at all
// could be attempted.
func newExecutionScope(req executorRequestRPC, cfg Config, model string) (executionScope, []ResolvedProfile, *upstreamFailure) {
	now := time.Now()
	plan := executionPlan(req.StorageJSON, cfg, model, req.Headers, now)
	if plan.Failure != nil {
		return executionScope{}, nil, plan.Failure
	}
	// The window is the one already recorded on the record, never a freshly
	// anchored one: re-anchoring it on every downgraded request would slide the
	// deadline forward indefinitely and a sustained stream of fallback traffic
	// would keep the primary blocked forever.
	skipBlockStatus, skipBlockRetry := "", time.Time{}
	if plan.SkipBlock != nil {
		skipBlockStatus, skipBlockRetry = skipBlockConclusion(req.StorageJSON, plan.SkipBlock, now)
	}
	return executionScope{
		AuthIndex:       strings.TrimSpace(req.AuthID),
		IdentityID:      plan.Primary.IdentityID,
		Document:        req.StorageJSON,
		Primary:         plan.Primary,
		SkipBlock:       plan.SkipBlock,
		SkipBlockStatus: skipBlockStatus,
		SkipBlockRetry:  skipBlockRetry,
		Recorder:        credentialStates.forStore(authStoreProvider()),
		Now:             func() time.Time { return now },
	}, plan.Attempts, nil
}

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
	payload, model, envErr := prepareUpstreamPayload(req.Payload, req.Model, cfg.Models)
	if envErr != nil {
		return envErr, nil
	}
	scope, profiles, failure := newExecutionScope(req, cfg, model)
	if failure != nil {
		return failureEnvelope(failure), nil
	}

	sink := hostProvider().Streams()
	ctx, cancel := context.WithCancel(context.Background())
	remove := activeExecutions.add(cancel)
	go func() {
		defer remove()
		defer cancel()
		outcome, _ := runExecution(ctx, scope, profiles, payload, func() answerForwarder {
			return newStreamForwarder(sink, streamID)
		})
		closer := newStreamCloser(sink, streamID)
		if outcome.Failure != nil {
			closer.Close(outcome.Failure.Message)
			return
		}
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

// prepareUpstreamPayload normalizes the payload's model id and forces
// upstream streaming: both streaming and non-streaming callers consume the
// same upstream SSE pump. The failure envelope carries the sanitized reason.
func prepareUpstreamPayload(payload []byte, model string, catalog []string) ([]byte, string, []byte) {
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
	out, err := json.Marshal(body)
	if err != nil {
		return nil, "", errorEnvelope("invalid_request", "request payload could not be encoded", http.StatusBadRequest)
	}
	return out, normalizedModel, nil
}

// credentialPlan is what one request resolved to before any upstream call: the
// credential to try first, the ordered attempts, the block that caused a
// downgrade, and the failure when no credential is usable at all.
type credentialPlan struct {
	// Primary is the credential the request runs on, which is the fallback
	// itself when the recorded primary is blocked.
	Primary ResolvedProfile
	// Attempts are the profiles to try, in order.
	Attempts []ResolvedProfile
	// SkipBlock is the classified block that kept the Coding Plan JWT out of
	// this request, so the attempt loop can persist that block even though the
	// loop never runs the primary.
	SkipBlock *upstreamFailure
	// Failure is non-nil only when no credential could be attempted at all.
	Failure *upstreamFailure
}

// executionPlan lists the credential attempts for one request in priority order.
// The Coding Plan JWT is the primary credential; the managed API key of the same
// upstream identity is the single fallback. A JWT that an earlier request
// recorded as unusable is skipped in favour of the key, and a key that is not
// recorded as usable removes the fallback entirely. Failures are classified and
// sanitized. now is the clock the recorded retry windows are measured against.
func executionPlan(doc []byte, cfg Config, model string, callerHeaders http.Header, now time.Time) credentialPlan {
	snap, err := readCredentialSnapshot(doc)
	if err != nil {
		return credentialPlan{Failure: credentialProfileFailure(err)}
	}
	cfg = normalizeConfig(cfg)

	primary, primaryErr := primaryProfile(snap, cfg, model, callerHeaders, now)
	fallback, fallbackErr := fallbackProfile(snap, cfg, model, callerHeaders, now)

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
		return credentialPlan{
			Primary:   fallback,
			Attempts:  []ResolvedProfile{fallback},
			SkipBlock: credentialProfileFailure(primaryErr),
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
func primaryProfile(snap credentialSnapshot, cfg Config, model string, callerHeaders http.Header, now time.Time) (ResolvedProfile, error) {
	if strings.TrimSpace(snap.JWTToken) == "" {
		return ResolvedProfile{}, errNoCredential
	}
	if !jwtUsable(snap.JWTStatus, snap.JWTRetryAfter, now) {
		return ResolvedProfile{}, credentialStatusError{Status: snap.JWTStatus}
	}
	return newProfile(snap, CredentialJWT, cfg, model, callerHeaders), nil
}

// fallbackProfile builds the managed API key profile, or the classified failure
// explaining why no fallback credential is available.
func fallbackProfile(snap credentialSnapshot, cfg Config, model string, callerHeaders http.Header, now time.Time) (ResolvedProfile, error) {
	if strings.TrimSpace(snap.APIKeyToken) == "" {
		return ResolvedProfile{}, credentialStatusError{Status: apiKeyStatusUnavailable}
	}
	if !apiKeyUsable(snap.APIKeyStatus, snap.APIKeyRetryAfter, now) {
		return ResolvedProfile{}, credentialStatusError{Status: snap.APIKeyStatus}
	}
	return newProfile(snap, CredentialAPIKey, cfg, model, callerHeaders), nil
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
// window already on the record that the skip was decided against. A block whose
// code this build does not know concludes nothing: recording a permanent
// conclusion for an unrecognized code would strand the account, which is worse
// than recording nothing.
func skipBlockConclusion(doc []byte, skipBlock *upstreamFailure, now time.Time) (string, time.Time) {
	status := skipBlockStatus(skipBlock)
	if status == "" {
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

// skipBlockStatus recovers the primary state a skip block describes, so the
// loop can record that state without re-reading the document. The codes are
// the ones jwtStateFailure renders; anything else maps to no state at all.
func skipBlockStatus(skipBlock *upstreamFailure) string {
	if skipBlock == nil {
		return ""
	}
	switch skipBlock.Code {
	case "credential_verification_blocked":
		return jwtStatusVerificationBlocked
	case "credential_quota_exhausted":
		return jwtStatusExhausted
	case "credential_cooling_down":
		return jwtStatusCooldown
	case "credential_invalid":
		return jwtStatusInvalid
	default:
		return ""
	}
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

// answerForwarder is a frameForwarder that also holds the non-streaming
// response it aggregated. The attempt loop hands back the forwarder that
// actually produced the answer, so a caller is never served an aggregate that
// a discarded attempt had already written into.
type answerForwarder interface {
	frameForwarder
	finish() ([]byte, error)
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
	// SkipBlock is the classified block that skipped the primary, together with
	// the block's retry window. It is the reason this request is running on a
	// credential it would not otherwise use, so the loop records it as the
	// windowed state even when the fallback that served the request itself
	// failed for a reason of its own.
	SkipBlock       *upstreamFailure
	SkipBlockStatus string
	SkipBlockRetry  time.Time
	Recorder        credentialRecorder
	Now             func() time.Time
}

// credentialRef projects the scope onto the host auth record.
func (s executionScope) credentialRef() credentialRef {
	return credentialRef{AuthIndex: s.AuthIndex, IdentityID: s.IdentityID, Document: s.Document}
}

// runExecution performs the credential attempt loop over the immutable
// profiles. Profiles are attempted in order; a failed attempt is retried on
// the next profile only while nothing has been forwarded to the caller and the
// failure classification allows a pre-output retry. Once output started, the
// failure is final: a response must never mix output from two upstream
// attempts.
//
// newForwarder builds the sink for one attempt. Each attempt gets its own, so
// a failed attempt's partial output is discarded rather than merged into the
// next credential's answer.
func runExecution(ctx context.Context, scope executionScope, profiles []ResolvedProfile, payload []byte, newForwarder func() answerForwarder) (executionOutcome, answerForwarder) {
	// The payload is the request exactly as the caller built it. Every
	// credential attempt replays this one buffer, so a fallback can never
	// mutate what the caller sent.
	request := payload
	var lastFailure *upstreamFailure
	for _, profile := range profiles {
		// The primary's block is recorded once, before the first attempt runs:
		// it is the reason this request is running on a credential it would not
		// otherwise use, and repeating it per attempt would take the identity
		// lock once per credential for a conclusion that never changes.
		scope.recordSkipBlock(ctx)
		forwarder := newForwarder()
		outcome := attemptProfile(ctx, scope, profile, request, forwarder)
		if outcome.Failure == nil {
			return executionOutcome{OutputStarted: outcome.OutputStarted}, forwarder
		}
		if outcome.OutputStarted || !outcome.Failure.RetryableBeforeOutput {
			return outcome, forwarder
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
	return executionOutcome{Failure: lastFailure}, nil
}

// attemptProfile runs one upstream attempt against an immutable profile, reports
// whether output reached the caller, and records the credential's conclusion
// before the next credential is considered.
func attemptProfile(ctx context.Context, scope executionScope, profile ResolvedProfile, payload []byte, forwarder frameForwarder) executionOutcome {
	client := upstreamClient(profile)
	err := pumpUpstream(ctx, client, profile, payload, func(frame []byte) error {
		return forwarder.Forward(ctx, frame)
	})
	kind := profile.CredentialKind
	if err == nil {
		scope.record(ctx, recordedState{Kind: kind, Status: activeStatusFor(kind)})
		return executionOutcome{OutputStarted: forwarder.OutputStarted()}
	}
	failure := failureFromError(err)
	scope.record(ctx, conclusionFor(kind, failure, scope.Now()))
	return executionOutcome{Failure: failure, OutputStarted: forwarder.OutputStarted()}
}

// recordSkipBlock persists the primary's own block. The attempt loop never runs
// the primary, so without this the state that caused the downgrade would exist
// only in memory and the next request would repeat the blocked credential. The
// recorder is a no-op when the persisted state already says the same thing.
func (s executionScope) recordSkipBlock(ctx context.Context) {
	if s.Recorder == nil || s.SkipBlock == nil || s.SkipBlockStatus == "" {
		return
	}
	_ = s.Recorder.record(context.WithoutCancel(ctx), s.credentialRef(), recordedState{
		Kind:       CredentialJWT,
		Status:     s.SkipBlockStatus,
		RetryAfter: s.SkipBlockRetry,
		Code:       s.SkipBlock.Code,
	})
}

// record persists one credential's conclusion. The write outlives the request
// on purpose: a conclusion reached as a stream ends must still land, and state
// is a recovery input rather than part of the caller's response, so a host
// store that cannot take the write leaves this request's upstream result
// exactly as it was.
func (s executionScope) record(ctx context.Context, state recordedState) {
	if s.Recorder == nil {
		return
	}
	_ = s.Recorder.record(context.WithoutCancel(ctx), s.credentialRef(), state)
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

// statusForClass translates a failure class into one credential's own state
// vocabulary. A class the upstream did not attribute to the credential records
// nothing: an error event the upstream streams is a statement about that
// request, not about the credential that sent it. The fallback key is never
// verification-gated the way the Coding Plan JWT is, so a verification
// requirement against it is recorded as the temporary condition it actually is.
func statusForClass(kind CredentialKind, class failureClass) string {
	if kind == CredentialAPIKey {
		switch class {
		case failureVerificationBlocked:
			return apiKeyStatusCooldown
		case failureInvalid:
			return apiKeyStatusInvalid
		case failureExhausted:
			return apiKeyStatusExhausted
		case failureCooldown:
			return apiKeyStatusCooldown
		default:
			return ""
		}
	}
	switch class {
	case failureVerificationBlocked:
		return jwtStatusVerificationBlocked
	case failureInvalid:
		return jwtStatusInvalid
	case failureExhausted:
		return jwtStatusExhausted
	case failureCooldown:
		return jwtStatusCooldown
	default:
		return ""
	}
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

// finish satisfies answerForwarder for the streaming path, where it is never
// called: a stream's frames were emitted as they arrived, so there is no
// aggregate to render and the forwarder the loop hands back is discarded.
func (f *streamForwarder) finish() ([]byte, error) { return nil, nil }

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
