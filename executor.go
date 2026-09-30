package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"

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
	profiles, failure := executionProfiles(req.StorageJSON, cfg, model, req.Headers)
	if failure != nil {
		return failureEnvelope(failure), nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	remove := activeExecutions.add(cancel)
	defer remove()
	defer cancel()

	forwarder := newAggregateForwarder(profiles[0].MaxResponseBytes)
	outcome := runExecution(ctx, profiles, payload, forwarder)
	if outcome.Failure != nil {
		return failureEnvelope(outcome.Failure), nil
	}
	payloadOut, err := forwarder.finish()
	if err != nil {
		return failureEnvelope(failureFromError(err)), nil
	}
	return okEnvelope(pluginapi.ExecutorResponse{
		Payload: payloadOut,
		Headers: http.Header{"Content-Type": []string{"application/json"}},
	})
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
	profiles, failure := executionProfiles(req.StorageJSON, cfg, model, req.Headers)
	if failure != nil {
		return failureEnvelope(failure), nil
	}

	sink := hostProvider().Streams()
	forwarder := newStreamForwarder(sink, streamID)
	ctx, cancel := context.WithCancel(context.Background())
	remove := activeExecutions.add(cancel)
	go func() {
		defer remove()
		defer cancel()
		outcome := runExecution(ctx, profiles, payload, forwarder)
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

// executionProfiles lists the credential attempts for one request in priority
// order. This slice attempts only the primary JWT profile; the managed API
// key fallback plugs in here in a later milestone. Failures are classified
// and sanitized.
func executionProfiles(doc []byte, cfg Config, model string, callerHeaders http.Header) ([]ResolvedProfile, *upstreamFailure) {
	profile, err := buildProfile(doc, cfg, model, callerHeaders)
	if err != nil {
		return nil, credentialProfileFailure(err)
	}
	return []ResolvedProfile{profile}, nil
}

// credentialProfileFailure maps profile construction errors onto sanitized,
// classified failures. No document content or secret material is included.
func credentialProfileFailure(err error) *upstreamFailure {
	if errors.Is(err, errNoCredential) {
		return &upstreamFailure{
			Class:        failureInvalid,
			ClientStatus: http.StatusUnauthorized,
			Code:         "no_credential",
			Message:      errNoCredential.Error(),
		}
	}
	if errors.Is(err, errCredentialUnavailable) {
		switch credentialUnavailableStatus(err) {
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
	return &upstreamFailure{
		Class:        failureRejected,
		ClientStatus: http.StatusInternalServerError,
		Code:         "profile_error",
		Message:      "upstream profile could not be built from the selected auth record",
	}
}

// credentialUnavailableStatus recovers which blocked state was recorded. The
// error itself is opaque; the status travels as a wrapped marker error.
func credentialUnavailableStatus(err error) string {
	var statusErr credentialStatusError
	if errors.As(err, &statusErr) {
		return statusErr.Status
	}
	return ""
}

// credentialStatusError marks why a credential is unavailable.
type credentialStatusError struct {
	Status string
}

func (e credentialStatusError) Error() string { return errCredentialUnavailable.Error() }

func (e credentialStatusError) Unwrap() error { return errCredentialUnavailable }

// frameForwarder consumes one upstream SSE frame and reports whether any
// output already reached the caller.
type frameForwarder interface {
	Forward(ctx context.Context, frame []byte) error
	OutputStarted() bool
}

// executionOutcome reports one credential attempt loop's result.
type executionOutcome struct {
	// OutputStarted is true once any output reached the caller.
	OutputStarted bool
	Failure       *upstreamFailure
}

// runExecution performs the credential attempt loop over the immutable
// profiles. Profiles are attempted in order; a failed attempt is retried on
// the next profile only while nothing has been forwarded to the caller and
// the failure classification allows a pre-output retry. Once output started,
// the failure is final: a response must never mix output from two upstream
// attempts.
func runExecution(ctx context.Context, profiles []ResolvedProfile, payload []byte, forwarder frameForwarder) executionOutcome {
	var lastFailure *upstreamFailure
	for _, profile := range profiles {
		outcome := attemptProfile(ctx, profile, payload, forwarder)
		if outcome.Failure == nil {
			return executionOutcome{OutputStarted: outcome.OutputStarted}
		}
		if outcome.OutputStarted || !outcome.Failure.RetryableBeforeOutput {
			return outcome
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
	return executionOutcome{Failure: lastFailure}
}

// attemptProfile runs one upstream attempt against an immutable profile and
// reports whether output reached the caller.
func attemptProfile(ctx context.Context, profile ResolvedProfile, payload []byte, forwarder frameForwarder) executionOutcome {
	client := upstreamClient(profile)
	err := pumpUpstream(ctx, client, profile, payload, func(frame []byte) error {
		return forwarder.Forward(ctx, frame)
	})
	if err == nil {
		return executionOutcome{OutputStarted: forwarder.OutputStarted()}
	}
	failure := failureFromError(err)
	return executionOutcome{Failure: failure, OutputStarted: forwarder.OutputStarted()}
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
