package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const testAPIKeyMaterial = "key-1.secret-material"

// testFallbackDoc is an auth document whose identity holds both credential
// forms: an active JWT and the plugin-managed fallback key.
func testFallbackDoc(jwtStatus, apiKeyStatus string) []byte {
	return []byte(`{"type":"zcode","other":"host-owned","zcode":{` +
		`"identity_id":"zcode-user-1",` +
		`"jwt":{"token":"` + testJWT + `","status":"` + jwtStatus + `"},` +
		`"api_key":{"status":"` + apiKeyStatus + `","managed":true,` +
		`"key_id":"key-1","key_material":"` + testAPIKeyMaterial + `"}}}`)
}

// blockedWithFallback is an account whose primary is recorded in a blocked
// state whose retry window has not elapsed yet, so the managed key is what
// serves this request. The window is anchored to wall time because that is the
// clock a real request reads it against; a blocked state with no window at all
// is the self-healing case TestVerificationBlockRetryWindowElapses covers.
func blockedWithFallback(t *testing.T, jwtStatus, apiKeyStatus string) []byte {
	t.Helper()
	return withRetryWindow(t, testFallbackDoc(jwtStatus, apiKeyStatus), time.Now().Add(verificationRetryWindow))
}

// blockedWithoutFallback is an account whose primary is blocked and whose
// exchange never produced a key: no credential at all is usable.
func blockedWithoutFallback(t *testing.T, jwtStatus string) []byte {
	t.Helper()
	doc := []byte(`{"type":"zcode","zcode":{"identity_id":"zcode-user-1",` +
		`"jwt":{"token":"` + testJWT + `","status":"` + jwtStatus + `"},` +
		`"api_key":{"status":"` + apiKeyStatusUnavailable + `"}}}`)
	return withRetryWindow(t, doc, time.Now().Add(verificationRetryWindow))
}

// withRetryWindow records a retry window on the JWT section of a document.
func withRetryWindow(t *testing.T, doc []byte, deadline time.Time) []byte {
	t.Helper()
	patched, err := patchZcodeNamespace(doc, func(zcode map[string]any) error {
		jwt, _ := zcode["jwt"].(map[string]any)
		jwt["retry_after"] = deadline.Format(time.RFC3339)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return patched
}

// upstreamScript is one scripted upstream response. status rejects the
// request; frames stream a partial message; abort drops the connection after
// the frames so the attempt fails with output already delivered.
type upstreamScript struct {
	status int
	body   string
	frames string
	abort  bool
}

// observedCall is what one upstream attempt actually sent and authenticated
// with. The fallback must reuse the primary's request body byte for byte.
type observedCall struct {
	endpoint string
	auth     string
	apiKey   string
	body     string
}

// scriptedUpstream answers one scripted response per request, in order, and
// records what every attempt sent.
type scriptedUpstream struct {
	server   *httptest.Server
	mu       sync.Mutex
	scripts  []upstreamScript
	observed []observedCall
}

func newScriptedUpstream(t *testing.T, scripts ...upstreamScript) *scriptedUpstream {
	t.Helper()
	up := &scriptedUpstream{scripts: scripts}
	up.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 0, 4096)
		buf := make([]byte, 2048)
		for {
			n, err := r.Body.Read(buf)
			body = append(body, buf[:n]...)
			if err != nil {
				break
			}
		}
		up.mu.Lock()
		call := len(up.observed)
		up.observed = append(up.observed, observedCall{
			endpoint: r.URL.Path,
			auth:     r.Header.Get("Authorization"),
			apiKey:   r.Header.Get("x-api-key"),
			body:     string(body),
		})
		var script upstreamScript
		if call < len(up.scripts) {
			script = up.scripts[call]
		} else if len(up.scripts) > 0 {
			script = up.scripts[len(up.scripts)-1]
		}
		up.mu.Unlock()

		if script.status != 0 {
			w.WriteHeader(script.status)
			_, _ = w.Write([]byte(script.body))
			return
		}
		if script.frames != "" {
			writeSSE(w, script.frames)
		}
		if script.abort {
			panic(http.ErrAbortHandler)
		}
	}))
	t.Cleanup(up.server.Close)

	originalPlan := zcodePlanUpstreamBase
	zcodePlanUpstreamBase = up.server.URL
	t.Cleanup(func() { zcodePlanUpstreamBase = originalPlan })
	originalAPI := zaiAPIBase
	zaiAPIBase = up.server.URL
	t.Cleanup(func() { zaiAPIBase = originalAPI })
	return up
}

func (up *scriptedUpstream) calls() []observedCall {
	up.mu.Lock()
	defer up.mu.Unlock()
	out := make([]observedCall, len(up.observed))
	copy(out, up.observed)
	return out
}

// count is the number of upstream requests the server has served.
func (up *scriptedUpstream) count() int {
	up.mu.Lock()
	defer up.mu.Unlock()
	return len(up.observed)
}

// recordingForwarder collects forwarded frames and can be told when the caller
// should observe output as started.
type recordingForwarder struct {
	frames     []string
	startAfter int
}

func (f *recordingForwarder) Forward(_ context.Context, frame []byte) error {
	f.frames = append(f.frames, string(frame))
	return nil
}

func (f *recordingForwarder) OutputStarted() bool {
	return f.startAfter > 0 && len(f.frames) >= f.startAfter
}

// finish satisfies answerForwarder; these tests read the frames directly.
func (f *recordingForwarder) finish() ([]byte, error) { return nil, nil }

// stateRecorderStub captures the persisted state transitions without touching
// the host auth store.
type stateRecorderStub struct {
	mu      sync.Mutex
	records []recordedState
}

func (r *stateRecorderStub) record(_ context.Context, _ credentialRef, updates ...recordedState) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	// A conclusion the state machine drops must never reach the store, so the
	// stub applies the same filter the recorder does.
	r.records = append(r.records, stateConclusions(updates)...)
	return nil
}

func (r *stateRecorderStub) all() []recordedState {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]recordedState, len(r.records))
	copy(out, r.records)
	return out
}

func (r *stateRecorderStub) forKind(kind CredentialKind) []recordedState {
	var out []recordedState
	for _, record := range r.all() {
		if record.Kind == kind {
			out = append(out, record)
		}
	}
	return out
}

// runFallbackAttempt drives one execution attempt loop against the scripted
// upstream and returns the caller-facing failure, the forwarded frames, and
// the persisted state transitions.
func runFallbackAttempt(t *testing.T, doc []byte, forwarder *recordingForwarder) (*upstreamFailure, []string, *stateRecorderStub) {
	t.Helper()
	recorder := &stateRecorderStub{}
	scope := executionScope{
		IdentityID: "zcode-user-1",
		AuthIndex:  "auth-1",
		Document:   doc,
		Recorder:   recorder,
		Now:        fixedNow,
	}
	cfg := normalizeConfig(defaultConfig())
	plan := executionPlan(doc, cfg, "GLM-5.2", nil, time.Now())
	scope.Primary = plan.Primary
	scope.SkipBlock = plan.SkipBlock
	scope.SkipBlockStatus, scope.SkipBlockRetry = skipBlockConclusion(doc, plan.SkipBlock, fixedNow())
	if plan.Failure != nil {
		return plan.Failure, nil, recorder
	}
	outcome, _ := runExecution(context.Background(), scope, plan.Attempts, testRequestPayload(), func() answerForwarder {
		return forwarder
	})
	return outcome.Failure, forwarder.frames, recorder
}

// credentialSections is the persisted shape both credential states are
// asserted against.
type credentialSections struct {
	JWT struct {
		Status     string `json:"status"`
		RetryAfter string `json:"retry_after"`
	} `json:"jwt"`
	APIKey struct {
		Status     string `json:"status"`
		RetryAfter string `json:"retry_after"`
	} `json:"api_key"`
}

// isWindowedState reports whether a state heals on its own once its retry
// window has passed.
func isWindowedState(status string) bool {
	return status == jwtStatusVerificationBlocked || status == jwtStatusCooldown
}

func fixedNow() time.Time {
	return time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
}

const partialStream = "event: content_block_delta\n" +
	`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"partial"}}` + "\n\n"

// TestCredentialStateClassificationMatrix pins the complete state transition
// matrix of issue #6: which upstream outcome moves which credential into which
// state, and what the caller is told. The two credential states must never
// overwrite each other.
// TestFallbackDoesNotSpliceAggregatedOutput is the non-streaming form of the
// anti-corruption rule. Nothing has reached the caller yet when the primary
// fails, so the fallback may answer — but the partial answer the failed attempt
// had already aggregated must not appear in the response the caller receives.
func TestFallbackDoesNotSpliceAggregatedOutput(t *testing.T) {
	newScriptedUpstream(t,
		upstreamScript{frames: partialStream, abort: true},
		upstreamScript{frames: completeAnthropicSSE()},
	)
	overrideHost(t)

	env := callMethod(t, pluginabi.MethodExecutorExecute, executorRequestJSON(t, testFallbackDoc(jwtStatusActive, apiKeyStatusActive), testRequestPayload(), "", nil))
	if !env.OK {
		t.Fatalf("execute failed: %+v", env.Error)
	}
	var response pluginapi.ExecutorResponse
	if err := json.Unmarshal(env.Result, &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if strings.Contains(string(response.Payload), "partial") {
		t.Fatalf("the failed attempt's partial output reached the caller: %s", response.Payload)
	}
	if !strings.Contains(string(response.Payload), `"text":"Hello"`) {
		t.Fatalf("the fallback answer did not reach the caller: %s", response.Payload)
	}
	var message map[string]any
	if err := json.Unmarshal(response.Payload, &message); err != nil {
		t.Fatal(err)
	}
	if blocks := message["content"].([]any); len(blocks) != 1 {
		t.Fatalf("content was spliced from two attempts: %v", blocks)
	}
}

// TestNetworkFailureFallsBackAndCoolsTheCredential covers the transport side of
// the classification matrix: an upstream the plugin cannot reach is a
// temporary condition on the credential that tried it, so the key takes over
// and the JWT is recorded as cooling down.
func TestNetworkFailureFallsBackAndCoolsTheCredential(t *testing.T) {
	dead := closedAddress(t)
	// The managed key serves this request, so its own upstream must be the
	// live one; only the Coding Plan origin is made unreachable.
	apiKey := newScriptedUpstream(t, upstreamScript{frames: completeAnthropicSSE()})
	original := zcodePlanUpstreamBase
	zcodePlanUpstreamBase = "http://" + dead
	t.Cleanup(func() { zcodePlanUpstreamBase = original })
	overrideConfig(t, func(cfg *Config) { cfg.Upstream.ConnectTimeoutSeconds = 1 })
	overrideHost(t)

	env := callMethod(t, pluginabi.MethodExecutorExecute, executorRequestJSON(t, testFallbackDoc(jwtStatusActive, apiKeyStatusActive), testRequestPayload(), "", nil))
	if !env.OK {
		t.Fatalf("the fallback should have answered after a network failure, got %+v", env.Error)
	}
	if len(apiKey.calls()) != 1 {
		t.Fatalf("fallback attempts = %d, want 1", len(apiKey.calls()))
	}
	if apiKey.calls()[0].apiKey != testAPIKeyMaterial {
		t.Errorf("the fallback did not authenticate with the managed key: %+v", apiKey.calls()[0])
	}
}

// TestNetworkFailureWithoutFallbackIsReported asserts the single-credential
// version: an unreachable upstream cools the JWT and the caller is told the
// upstream could not be reached.
func TestNetworkFailureWithoutFallbackIsReported(t *testing.T) {
	dead := closedAddress(t)
	originalPlan, originalAPI := zcodePlanUpstreamBase, zaiAPIBase
	zcodePlanUpstreamBase = "http://" + dead
	zaiAPIBase = "http://" + dead
	t.Cleanup(func() { zcodePlanUpstreamBase, zaiAPIBase = originalPlan, originalAPI })
	overrideConfig(t, func(cfg *Config) { cfg.Upstream.ConnectTimeoutSeconds = 1 })
	overrideHost(t)

	env := callMethod(t, pluginabi.MethodExecutorExecute, executorRequestJSON(t, testAuthDoc(testJWT, jwtStatusActive), testRequestPayload(), "", nil))
	if env.OK {
		t.Fatal("an unreachable upstream must fail")
	}
	if env.Error.Code != "upstream_unreachable" {
		t.Fatalf("error = %+v", env.Error)
	}
}

// closedAddress returns a loopback address nothing is listening on, so a dial
// to it fails immediately instead of reaching a real service.
func closedAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// TestUpstreamStreamErrorEventRecordsNoState pins the last row of the matrix: a
// stream the upstream itself ends with an error event is a statement about that
// request, not about the credential, so no credential is cooled and no second
// credential is tried.
func TestUpstreamStreamErrorEventRecordsNoState(t *testing.T) {
	recorder := &stateRecorderStub{}
	scope := executionScope{
		IdentityID: "zcode-user-1",
		Document:   testFallbackDoc(jwtStatusActive, apiKeyStatusActive),
		Recorder:   recorder,
		Now:        fixedNow,
	}
	upstream := newScriptedUpstream(t,
		upstreamScript{frames: "event: error\n" + `data: {"type":"error","error":{"type":"invalid_request_error","message":"upstream refused this request"}}` + "\n\n"},
		upstreamScript{frames: completeAnthropicSSE()},
	)
	cfg := normalizeConfig(defaultConfig())
	plan := executionPlan(scope.Document, cfg, "GLM-5.2", nil, time.Now())
	if plan.Failure != nil {
		t.Fatalf("executionPlan: %+v", plan.Failure)
	}
	// The aggregate forwarder is the one that turns the error event into the
	// loop's failure, so the loop must be driven through it.
	outcome, _ := runExecution(context.Background(), scope, plan.Attempts, testRequestPayload(), func() answerForwarder {
		return newAggregateForwarder(cfg.Upstream.MaxResponseBytes)
	})
	if outcome.Failure == nil || outcome.Failure.Code != "upstream_stream_error" {
		t.Fatalf("failure = %+v, want the upstream stream error", outcome.Failure)
	}
	if len(upstream.calls()) != 1 {
		t.Fatalf("upstream attempts = %d, want 1: a definitive rejection is not retried", len(upstream.calls()))
	}
	if len(recorder.all()) != 0 {
		t.Fatalf("an upstream error event must record no credential state, got %+v", recorder.all())
	}
}

// TestSuccessfulRequestsDoNotRewriteTheAuthFile keeps the state machine from
// churning the host auth file: a stream of successes leaves the record alone
// once the recorded state already says the credential is active.
func TestSuccessfulRequestsDoNotRewriteTheAuthFile(t *testing.T) {
	fake, _ := newFakeHost(t)
	recorder := newCredentialStateRecorderOver(newRPCHost(fake).AuthStore())
	recorder.now = fixedNow

	var saves int
	fake.response = func(call hostCall) ([]byte, error) {
		if call.method == pluginabi.MethodHostAuthSave {
			saves++
		}
		return okEnvelopeBytes(json.RawMessage(`{"auth":{"name":"zcode-abc.json"}}`))
	}
	ref := credentialRef{AuthIndex: "auth-1", IdentityID: "zcode-user-1", Document: testFallbackDoc(jwtStatusActive, apiKeyStatusActive)}
	for range 5 {
		if err := recorder.record(context.Background(), ref, recordedState{Kind: CredentialJWT, Status: jwtStatusActive}); err != nil {
			t.Fatal(err)
		}
	}
	if saves != 0 {
		t.Fatalf("an already-active credential was rewritten %d times, want 0", saves)
	}
	// A real transition is still written.
	if err := recorder.record(context.Background(), ref, recordedState{
		Kind: CredentialJWT, Status: jwtStatusVerificationBlocked, Code: "upstream_verification_required",
	}); err != nil {
		t.Fatal(err)
	}
	if saves != 1 {
		t.Fatalf("a real transition produced %d writes, want 1", saves)
	}
}

// TestRetryWindowsAreTheDefinedDurations pins the automatic recovery windows so
// neither can drift silently.
func TestRetryWindowsAreTheDefinedDurations(t *testing.T) {
	if verificationRetryWindow != 5*time.Minute {
		t.Errorf("verification retry window = %v, want 5m", verificationRetryWindow)
	}
	if temporaryCooldownWindow != time.Minute {
		t.Errorf("temporary cooldown window = %v, want 1m", temporaryCooldownWindow)
	}
	now := fixedNow()
	cases := map[string]struct {
		class failureClass
		kind  CredentialKind
		want  time.Time
	}{
		"captcha on the jwt":    {failureVerificationBlocked, CredentialJWT, now.Add(5 * time.Minute)},
		"rate limit on the jwt": {failureCooldown, CredentialJWT, now.Add(time.Minute)},
		"rate limit on a key":   {failureCooldown, CredentialAPIKey, now.Add(time.Minute)},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			conclusion := conclusionFor(tc.kind, &upstreamFailure{Class: tc.class}, now)
			if !conclusion.RetryAfter.Equal(tc.want) {
				t.Fatalf("retry window = %v, want %v", conclusion.RetryAfter, tc.want)
			}
		})
	}
	// A class the upstream did not attribute to the credential records neither
	// a status nor a window.
	if got := conclusionFor(CredentialJWT, &upstreamFailure{Class: failureRejected}, now); got.Status != "" {
		t.Fatalf("a plain rejection must record no state, got %+v", got)
	}
	if got := conclusionFor(CredentialJWT, &upstreamFailure{Class: failureUnavailable}, now); got.Status != "" {
		t.Fatalf("an upstream error event must record no state, got %+v", got)
	}
}

// TestStreamErrorEventFailsTheRequestAndRecordsNoState is the streaming twin of
// the aggregate's in-band error handling: a stream the upstream ends with an
// error event is a failed request, not a successful stream, and it must not be
// acknowledged as a healthy credential.
func TestStreamErrorEventFailsTheRequestAndRecordsNoState(t *testing.T) {
	newScriptedUpstream(t, upstreamScript{frames: partialStream + "event: error\n" +
		`data: {"type":"error","error":{"type":"invalid_request_error","message":"upstream refused this request"}}` + "\n\n"})
	fake, _ := overrideHost(t)
	rec := newStreamRecorder()
	rec.bind(fake)

	env := callMethod(t, pluginabi.MethodExecutorExecuteStream, executorRequestJSON(t, testFallbackDoc(jwtStatusActive, apiKeyStatusActive), testRequestPayload(), "stream-7", nil))
	if !env.OK {
		t.Fatalf("stream start failed: %+v", env.Error)
	}
	if !rec.waitDone(5 * time.Second) {
		t.Fatal("stream was never closed")
	}
	closes := rec.closed()
	if len(closes) != 1 {
		t.Fatalf("close called %d times, want exactly once", len(closes))
	}
	if closes[0] == "" {
		t.Fatal("a stream that ended in an upstream error must close with one")
	}
	// The upstream excerpt is bounded and single-line by design; what must
	// never appear is the raw body or anything unbounded.
	if len(closes[0]) > maxSanitizedExcerpt+len("upstream reported a stream error (): ") ||
		strings.ContainsAny(closes[0], "\n\r") {
		t.Fatalf("the close message is not a bounded single line: %q", closes[0])
	}
	// The error frame itself must not have been handed to the caller.
	for _, frame := range rec.emitted() {
		if strings.Contains(string(frame), `"type":"error"`) {
			t.Fatalf("the error frame was forwarded as content: %s", frame)
		}
	}
}

// TestStateWriteRefusesADocumentWithoutCredentials guards the read side of the
// write path: whatever the host answers, a record the plugin does not own is
// never patched, and the attempt's own document is used instead.
func TestStateWriteRefusesADocumentWithoutCredentials(t *testing.T) {
	foreign := []string{
		`{"auth_index":"auth-1","json":{}}`,
		`{"auth_index":"auth-1","json":{"zcode":{"identity_id":"someone-else"}}}`,
		`{"auth_index":"auth-1","json":{"other_provider":{"token":"keep-me"}}}`,
	}
	for _, answer := range foreign {
		t.Run(answer, func(t *testing.T) {
			fake, _ := newFakeHost(t)
			recorder := newCredentialStateRecorderOver(newRPCHost(fake).AuthStore())
			recorder.now = fixedNow

			var saved json.RawMessage
			fake.response = func(call hostCall) ([]byte, error) {
				switch call.method {
				case pluginabi.MethodHostAuthGet:
					return okEnvelopeBytes(json.RawMessage(answer))
				case pluginabi.MethodHostAuthSave:
					var req struct {
						JSON json.RawMessage `json:"json"`
					}
					if err := json.Unmarshal(call.request, &req); err != nil {
						return nil, err
					}
					saved = req.JSON
				}
				return okEnvelopeBytes(json.RawMessage(`{"auth":{"name":"zcode-abc.json"}}`))
			}
			ref := credentialRef{AuthIndex: "auth-1", IdentityID: "zcode-user-1", Document: testFallbackDoc(jwtStatusActive, apiKeyStatusActive)}
			if err := recorder.record(context.Background(), ref, recordedState{Kind: CredentialJWT, Status: jwtStatusInvalid, Code: "credential_invalid"}); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(saved), testJWT) {
				t.Fatalf("the write did not fall back to the attempt's own record: %s", saved)
			}
			if strings.Contains(string(saved), "keep-me") {
				t.Fatalf("the plugin patched a record it does not own: %s", saved)
			}
		})
	}
}

// TestStateWriteIsDeclinedWithoutAHostSuppliedFileName keeps a state write from
// minting a second auth file for a record the host already stores under another
// name, which the identity-derived name would do.
func TestStateWriteIsDeclinedWithoutAHostSuppliedFileName(t *testing.T) {
	fake, _ := newFakeHost(t)
	recorder := newCredentialStateRecorderOver(newRPCHost(fake).AuthStore())
	recorder.now = fixedNow

	var savedNames []string
	fake.response = func(call hostCall) ([]byte, error) {
		switch call.method {
		case pluginabi.MethodHostAuthGetRuntime:
			// The host knows the record but reports no file name.
			return okEnvelopeBytes(json.RawMessage(`{"auth":{"auth_index":"auth-1"}}`))
		case pluginabi.MethodHostAuthGet:
			raw, err := json.Marshal(map[string]any{"auth_index": "auth-1", "json": json.RawMessage(testFallbackDoc(jwtStatusActive, apiKeyStatusActive))})
			if err != nil {
				return nil, err
			}
			return okEnvelopeBytes(raw)
		case pluginabi.MethodHostAuthSave:
			var req struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(call.request, &req); err != nil {
				return nil, err
			}
			savedNames = append(savedNames, req.Name)
		}
		return okEnvelopeBytes(nil)
	}
	ref := credentialRef{AuthIndex: "auth-1", IdentityID: "zcode-user-1", Document: testFallbackDoc(jwtStatusActive, apiKeyStatusActive)}
	err := recorder.record(context.Background(), ref, recordedState{Kind: CredentialJWT, Status: jwtStatusInvalid, Code: "credential_invalid"})
	if !errors.Is(err, errAuthFileNameUnknown) {
		t.Fatalf("record error = %v, want errAuthFileNameUnknown", err)
	}
	if len(savedNames) != 0 {
		t.Fatalf("a write was made under a guessed file name: %v", savedNames)
	}
}

// TestUnknownCredentialKindIsNotWrittenSilently keeps a conclusion for an
// unrecognized credential from being filed under the JWT section, where it
// would move one credential's availability onto another.
func TestUnknownCredentialKindIsNotWrittenSilently(t *testing.T) {
	defer func() {
		if recovered := recover(); recovered == nil {
			t.Fatal("an unknown credential kind must not be written silently")
		}
	}()
	applyCredentialState(testFallbackDoc(jwtStatusActive, apiKeyStatusActive),
		[]recordedState{{Kind: CredentialKind("other"), Status: jwtStatusInvalid}}, fixedNow())
}

// TestOwnedRecordIsWrittenEvenWithoutCredentials is the other side of the
// ownership guard: a record this plugin owns is writable even when it holds no
// credential yet, so its state is never stranded and its host-owned fields are
// never replaced by a stale snapshot.
func TestOwnedRecordIsWrittenEvenWithoutCredentials(t *testing.T) {
	fake, _ := newFakeHost(t)
	recorder := newCredentialStateRecorderOver(newRPCHost(fake).AuthStore())
	recorder.now = fixedNow

	owned := `{"type":"zcode","account":{"email":"host-owned@example.com"},"zcode":{"identity_id":"zcode-user-1"}}`
	var saved json.RawMessage
	fake.response = func(call hostCall) ([]byte, error) {
		switch call.method {
		case pluginabi.MethodHostAuthGet:
			var inner any
			if err := json.Unmarshal([]byte(owned), &inner); err != nil {
				return nil, err
			}
			raw, err := json.Marshal(map[string]any{"auth_index": "auth-1", "json": inner})
			if err != nil {
				return nil, err
			}
			return okEnvelopeBytes(raw)
		case pluginabi.MethodHostAuthSave:
			var req struct {
				JSON json.RawMessage `json:"json"`
			}
			if err := json.Unmarshal(call.request, &req); err != nil {
				return nil, err
			}
			saved = req.JSON
		}
		return okEnvelopeBytes(json.RawMessage(`{"auth":{"name":"zcode-abc.json"}}`))
	}
	ref := credentialRef{AuthIndex: "auth-1", IdentityID: "zcode-user-1", Document: testFallbackDoc(jwtStatusActive, apiKeyStatusActive)}
	if err := recorder.record(context.Background(), ref, recordedState{Kind: CredentialJWT, Status: jwtStatusInvalid, Code: "credential_invalid"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(saved), "host-owned@example.com") {
		t.Fatalf("the host's own fields were lost to the request snapshot: %s", saved)
	}
	if !strings.Contains(string(saved), jwtStatusInvalid) {
		t.Fatalf("an owned record must still be writable: %s", saved)
	}
}

// TestDowngradedRequestsDoNotSlideTheRetryWindow is the recovery guarantee
// under load: a sustained stream of requests served by the fallback must not
// keep pushing the primary's retry deadline further out, or a blocked primary
// would never get its automatic retry.
func TestDowngradedRequestsDoNotSlideTheRetryWindow(t *testing.T) {
	blockedAt := time.Now()
	// The record was written when the captcha block happened, so its window
	// is the deadline that recovery is measured against.
	doc := withRetryWindow(t, testFallbackDoc(jwtStatusVerificationBlocked, apiKeyStatusActive),
		blockedAt.Add(verificationRetryWindow))

	var first time.Time
	for _, elapsed := range []time.Duration{time.Minute, 2 * time.Minute, 3 * time.Minute} {
		now := blockedAt.Add(elapsed)
		status, retry := skipBlockConclusion(doc, &upstreamFailure{Code: "credential_verification_blocked"}, now)
		if status != jwtStatusVerificationBlocked {
			t.Fatalf("status = %q, want the blocked state preserved", status)
		}
		if first.IsZero() {
			first = retry
		}
		if !retry.Equal(first) {
			t.Fatalf("the retry window slid from %v to %v after %v", first, retry, elapsed)
		}
		// The record stores RFC3339, so the deadline is compared at the
		// resolution the format actually keeps.
		want := blockedAt.Add(verificationRetryWindow).UTC().Truncate(time.Second)
		if !retry.UTC().Truncate(time.Second).Equal(want) {
			t.Fatalf("retry window = %v, want the deadline recorded on the record (%v)", retry, want)
		}
		// The primary is still skipped, and once the window has passed it is
		// tried again.
		snap, err := readCredentialSnapshot(doc)
		if err != nil {
			t.Fatal(err)
		}
		if jwtUsable(snap.JWTStatus, snap.JWTRetryAfter, now) != (elapsed >= verificationRetryWindow) {
			t.Fatalf("after %v the primary usability is wrong", elapsed)
		}
	}
}

// TestUnknownPreconditionCodeRecordsNothing keeps a state this build does not
// recognize from stranding an account: an unhandled conclusion is left to the
// upstream rather than recorded as a permanent one.
func TestUnknownPreconditionCodeRecordsNothing(t *testing.T) {
	status, retry := skipBlockConclusion(testFallbackDoc(jwtStatusActive, apiKeyStatusActive),
		&upstreamFailure{Code: "a_code_this_build_does_not_know"}, fixedNow())
	if status != "" || !retry.IsZero() {
		t.Fatalf("an unknown precondition recorded %q with window %v, want nothing", status, retry)
	}
}

// TestCooldownStatesHoldTheCredentialOutOfUseForTheirWindow covers the states
// the matrix records as a temporary cooldown: the window is what actually keeps
// the credential out of the request path, so a cooldown without one would put
// it straight back into use on the next request.
func TestCooldownStatesHoldTheCredentialOutOfUseForTheirWindow(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name    string
		status  string
		retryAt string
	}{
		{"a windowed cooldown holds the credential", jwtStatusCooldown, formatRetryAfter(retryWindowFor(jwtStatusCooldown, now))},
		{"an elapsed window releases the credential", jwtStatusCooldown, formatRetryAfter(now.Add(-time.Second))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			usable := jwtUsable(tc.status, tc.retryAt, now)
			if usable != (tc.name == "an elapsed window releases the credential") {
				t.Fatalf("jwtUsable(%q, %q) = %v", tc.status, tc.retryAt, usable)
			}
		})
	}
	if retryWindowFor(jwtStatusCooldown, now) != now.Add(temporaryCooldownWindow) {
		t.Fatal("a jwt cooldown must carry its own window")
	}
	if retryWindowFor(apiKeyStatusCooldown, now) != now.Add(temporaryCooldownWindow) {
		t.Fatal("a key cooldown must carry its own window")
	}
	// A 429 and a 5xx both land on a windowed cooldown.
	for _, status := range []int{http.StatusTooManyRequests, http.StatusBadGateway} {
		conclusion := conclusionFor(CredentialJWT, classifyUpstreamFailure(status, []byte(`{}`)), now)
		if conclusion.Status != jwtStatusCooldown || conclusion.RetryAfter.IsZero() {
			t.Fatalf("status %d recorded %+v, want a windowed cooldown", status, conclusion)
		}
	}
	// A transport failure is what the classification of an unreachable upstream
	// produces, and it must still hold the credential out for its window.
	transport := transportFailure(errors.New("connection refused"))
	if transport.Class != failureCooldown {
		t.Fatalf("transport failure class = %s, want cooldown", transport.Class)
	}
	conclusion := conclusionFor(CredentialJWT, transport, now)
	if conclusion.Status != jwtStatusCooldown || conclusion.RetryAfter.IsZero() {
		t.Fatalf("a transport failure recorded %+v, want a windowed cooldown", conclusion)
	}
}

func TestCredentialStateClassificationMatrix(t *testing.T) {
	cases := []struct {
		name string
		// primary is the upstream outcome of the JWT attempt.
		primary upstreamScript
		// fallback is the upstream outcome of the managed API key attempt.
		fallback upstreamScript
		// wantAttempts is the number of upstream requests, including the
		// key attempt.
		wantAttempts int
		// wantJWTStatus and wantKeyStatus are the persisted states. An empty
		// string means the credential's state must not change at all.
		wantJWTStatus string
		wantJWTRetry  bool
		wantKeyStatus string
		wantKeyRetry  bool
		wantCode      string
		wantClient    int
		// wantNoState asserts that no credential state changed at all, which
		// is distinct from a status that happens to equal the recorded one.
		wantNoState     bool
		wantSuccessPath bool
	}{
		{
			name:            "captcha block falls back immediately and retries the jwt after five minutes",
			primary:         upstreamScript{status: http.StatusForbidden, body: `{"error":{"message":"captcha verification required"}}`},
			fallback:        upstreamScript{frames: completeAnthropicSSE()},
			wantAttempts:    2,
			wantJWTStatus:   jwtStatusVerificationBlocked,
			wantJWTRetry:    true,
			wantKeyStatus:   apiKeyStatusActive,
			wantSuccessPath: true,
		},
		{
			name:            "verify token rejection is treated as verification blocked",
			primary:         upstreamScript{status: http.StatusForbidden, body: `{"error":{"message":"verify token missing"}}`},
			fallback:        upstreamScript{frames: completeAnthropicSSE()},
			wantAttempts:    2,
			wantJWTStatus:   jwtStatusVerificationBlocked,
			wantJWTRetry:    true,
			wantKeyStatus:   apiKeyStatusActive,
			wantSuccessPath: true,
		},
		{
			name:            "plain 403 without a verification marker invalidates the jwt",
			primary:         upstreamScript{status: http.StatusForbidden, body: `{"error":{"message":"forbidden"}}`},
			fallback:        upstreamScript{frames: completeAnthropicSSE()},
			wantAttempts:    2,
			wantJWTStatus:   jwtStatusInvalid,
			wantKeyStatus:   apiKeyStatusActive,
			wantSuccessPath: true,
		},
		{
			name:            "401 invalidates the jwt",
			primary:         upstreamScript{status: http.StatusUnauthorized, body: `{"error":{"message":"invalid token"}}`},
			fallback:        upstreamScript{frames: completeAnthropicSSE()},
			wantAttempts:    2,
			wantJWTStatus:   jwtStatusInvalid,
			wantKeyStatus:   apiKeyStatusActive,
			wantSuccessPath: true,
		},
		{
			name:            "402 records exhaustion",
			primary:         upstreamScript{status: http.StatusPaymentRequired, body: `{"error":{"message":"insufficient quota"}}`},
			fallback:        upstreamScript{frames: completeAnthropicSSE()},
			wantAttempts:    2,
			wantJWTStatus:   jwtStatusExhausted,
			wantKeyStatus:   apiKeyStatusActive,
			wantSuccessPath: true,
		},
		{
			name:            "429 cools the jwt down",
			primary:         upstreamScript{status: http.StatusTooManyRequests, body: `{}`},
			fallback:        upstreamScript{frames: completeAnthropicSSE()},
			wantAttempts:    2,
			wantJWTStatus:   jwtStatusCooldown,
			wantJWTRetry:    true,
			wantKeyStatus:   apiKeyStatusActive,
			wantSuccessPath: true,
		},
		{
			name:            "5xx cools the jwt down",
			primary:         upstreamScript{status: http.StatusBadGateway, body: `{}`},
			fallback:        upstreamScript{frames: completeAnthropicSSE()},
			wantAttempts:    2,
			wantJWTStatus:   jwtStatusCooldown,
			wantJWTRetry:    true,
			wantKeyStatus:   apiKeyStatusActive,
			wantSuccessPath: true,
		},
		{
			name:            "a stalled stream cools the jwt down",
			primary:         upstreamScript{frames: partialStream, abort: true},
			fallback:        upstreamScript{frames: completeAnthropicSSE()},
			wantAttempts:    2,
			wantJWTStatus:   jwtStatusCooldown,
			wantJWTRetry:    true,
			wantKeyStatus:   apiKeyStatusActive,
			wantSuccessPath: true,
		},
		{
			name:            "a schema rejection is reported as a rejection and changes no credential state",
			primary:         upstreamScript{status: http.StatusBadRequest, body: `{"error":{"message":"max_tokens must be positive"}}`},
			wantAttempts:    1,
			wantNoState:     true,
			wantCode:        "upstream_rejected",
			wantClient:      http.StatusBadRequest,
			wantSuccessPath: false,
		},
		{
			name:            "a failed fallback records only the api key failure",
			primary:         upstreamScript{status: http.StatusUnauthorized, body: `{}`},
			fallback:        upstreamScript{status: http.StatusUnauthorized, body: `{}`},
			wantAttempts:    2,
			wantJWTStatus:   jwtStatusInvalid,
			wantKeyStatus:   apiKeyStatusInvalid,
			wantCode:        "credential_invalid",
			wantClient:      http.StatusUnauthorized,
			wantSuccessPath: false,
		},
		{
			name:            "an exhausted fallback reports its own exhaustion",
			primary:         upstreamScript{status: http.StatusPaymentRequired, body: `{"error":{"message":"insufficient quota"}}`},
			fallback:        upstreamScript{status: http.StatusPaymentRequired, body: `{"error":{"message":"insufficient quota"}}`},
			wantAttempts:    2,
			wantJWTStatus:   jwtStatusExhausted,
			wantKeyStatus:   apiKeyStatusExhausted,
			wantCode:        "upstream_quota_exhausted",
			wantClient:      http.StatusPaymentRequired,
			wantSuccessPath: false,
		},
		{
			// Exhaustion carries no retry window, so it must be confirmed by the
			// body rather than assumed from the status: a 402 raised for another
			// reason would otherwise disable the credential until a quota
			// refresh recovered it.
			name:         "a 402 without an exhaustion marker records no credential state",
			primary:      upstreamScript{status: http.StatusPaymentRequired, body: `{"error":{"message":"this account requires a billing profile"}}`},
			wantAttempts: 1,
			wantNoState:  true,
			wantCode:     "upstream_rejected",
			wantClient:   http.StatusPaymentRequired,
		},
		{
			name:         "a 402 with an unparsable body records no credential state",
			primary:      upstreamScript{status: http.StatusPaymentRequired, body: `payment required`},
			wantAttempts: 1,
			wantNoState:  true,
			wantCode:     "upstream_rejected",
			wantClient:   http.StatusPaymentRequired,
		},
		{
			name:            "a successful primary never touches the fallback key",
			primary:         upstreamScript{frames: completeAnthropicSSE()},
			wantAttempts:    1,
			wantJWTStatus:   jwtStatusActive,
			wantKeyStatus:   "",
			wantSuccessPath: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstream := newScriptedUpstream(t, tc.primary, tc.fallback)
			failure, frames, recorder := runFallbackAttempt(t, testFallbackDoc(jwtStatusActive, apiKeyStatusActive), &recordingForwarder{})

			if got := len(upstream.calls()); got != tc.wantAttempts {
				t.Fatalf("upstream attempts = %d, want %d", got, tc.wantAttempts)
			}
			if tc.wantSuccessPath {
				if failure != nil {
					t.Fatalf("expected the attempt loop to succeed, got %+v", failure)
				}
				if len(frames) == 0 {
					t.Fatal("a successful attempt must forward upstream frames")
				}
			} else {
				if failure == nil {
					t.Fatal("expected a caller-facing failure")
				}
				if failure.Code != tc.wantCode || failure.ClientStatus != tc.wantClient {
					t.Fatalf("failure = %+v, want code %s status %d", failure, tc.wantCode, tc.wantClient)
				}
			}
			if tc.wantNoState {
				if len(recorder.all()) != 0 {
					t.Fatalf("no credential state may change, got %+v", recorder.all())
				}
			}
			assertRecordedState(t, recorder.forKind(CredentialJWT), tc.wantJWTStatus, tc.wantJWTRetry)
			assertRecordedState(t, recorder.forKind(CredentialAPIKey), tc.wantKeyStatus, tc.wantKeyRetry)
		})
	}
}

// assertRecordedState checks the single state transition recorded for one
// credential: the expected status and whether a retry window was persisted.
func assertRecordedState(t *testing.T, records []recordedState, wantStatus string, wantRetry bool) {
	t.Helper()
	if wantStatus == "" {
		if len(records) != 0 {
			t.Fatalf("credential state must not change, got %+v", records)
		}
		return
	}
	if len(records) != 1 {
		t.Fatalf("recorded %d state transitions, want exactly 1: %+v", len(records), records)
	}
	if records[0].Status != wantStatus {
		t.Fatalf("recorded status = %q, want %q", records[0].Status, wantStatus)
	}
	if got := !records[0].RetryAfter.IsZero(); got != wantRetry {
		t.Fatalf("retry window recorded = %v, want %v (retry_after %v)", got, wantRetry, records[0].RetryAfter)
	}
	// The persisted reason is a bounded code, never upstream prose.
	if len(records[0].Code) > 64 {
		t.Fatalf("persisted reason is unbounded: %q", records[0].Code)
	}
}

// TestFallbackReusesTheSameUnmutatedRequestBody is the core anti-corruption
// guarantee of the fallback: the retry must be the identical request, sent to
// the API key upstream with the API key's own authentication.
func TestFallbackReusesTheSameUnmutatedRequestBody(t *testing.T) {
	upstream := newScriptedUpstream(t,
		upstreamScript{status: http.StatusForbidden, body: `{"error":{"message":"captcha verification required"}}`},
		upstreamScript{frames: completeAnthropicSSE()},
	)
	failure, frames, _ := runFallbackAttempt(t, testFallbackDoc(jwtStatusActive, apiKeyStatusActive), &recordingForwarder{})
	if failure != nil {
		t.Fatalf("fallback should have succeeded, got %+v", failure)
	}
	calls := upstream.calls()
	if len(calls) != 2 {
		t.Fatalf("upstream attempts = %d, want 2", len(calls))
	}
	if calls[0].auth != "Bearer "+testJWT {
		t.Errorf("primary authentication = %q, want the JWT", calls[0].auth)
	}
	if calls[0].apiKey != "" {
		t.Errorf("primary attempt must not send an api key: %q", calls[0].apiKey)
	}
	if calls[1].apiKey != testAPIKeyMaterial {
		t.Errorf("fallback x-api-key = %q, want the managed key material", calls[1].apiKey)
	}
	if calls[1].auth != "" {
		t.Errorf("fallback must not send a bearer token: %q", calls[1].auth)
	}
	if calls[0].body != calls[1].body {
		t.Errorf("fallback body was mutated:\n primary: %s\nfallback: %s", calls[0].body, calls[1].body)
	}
	if calls[0].endpoint != zcodeMessagesPath {
		t.Errorf("primary endpoint = %q, want %q", calls[0].endpoint, zcodeMessagesPath)
	}
	if calls[1].endpoint != zaiMessagesPath {
		t.Errorf("fallback endpoint = %q, want %q", calls[1].endpoint, zaiMessagesPath)
	}
	if len(frames) == 0 {
		t.Fatal("the fallback attempt must forward the upstream frames")
	}
}

// TestNoFallbackOnceOutputReachedTheCaller is the other half of the rule: a
// response must never mix output from two credentials, so nothing is retried
// or spliced after the first frame is visible.
func TestNoFallbackOnceOutputReachedTheCaller(t *testing.T) {
	upstream := newScriptedUpstream(t,
		upstreamScript{frames: partialStream, abort: true},
		upstreamScript{frames: completeAnthropicSSE()},
	)
	forwarder := &recordingForwarder{startAfter: 1}
	failure, frames, recorder := runFallbackAttempt(t, testFallbackDoc(jwtStatusActive, apiKeyStatusActive), forwarder)

	if failure == nil {
		t.Fatal("an aborted stream must fail")
	}
	if len(upstream.calls()) != 1 {
		t.Fatalf("upstream attempts = %d, want 1: no retry after output", len(upstream.calls()))
	}
	if len(frames) != 1 || !strings.Contains(frames[0], "partial") {
		t.Fatalf("forwarded frames = %v, want only the primary's partial output", frames)
	}
	// The primary's own state is still recorded; the fallback key is not
	// touched at all, because it was never attempted.
	assertRecordedState(t, recorder.forKind(CredentialJWT), jwtStatusCooldown, true)
	assertRecordedState(t, recorder.forKind(CredentialAPIKey), "", false)
}

// TestBlockedPrimarySkipsUpstreamAndFallsBack covers the states persisted by
// an earlier request: a blocked JWT must not reach the upstream at all.
func TestBlockedPrimarySkipsUpstreamAndFallsBack(t *testing.T) {
	cases := map[string]struct {
		jwtStatus string
		wantCode  string
		wantClass failureClass
	}{
		"invalid":              {jwtStatusInvalid, "credential_invalid", failureInvalid},
		"exhausted":            {jwtStatusExhausted, "credential_quota_exhausted", failureExhausted},
		"verification_blocked": {jwtStatusVerificationBlocked, "credential_verification_blocked", failureVerificationBlocked},
		"cooldown":             {jwtStatusCooldown, "credential_cooling_down", failureCooldown},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			doc := blockedWithFallback(t, tc.jwtStatus, apiKeyStatusActive)
			upstream := newScriptedUpstream(t, upstreamScript{frames: completeAnthropicSSE()})
			failure, _, recorder := runFallbackAttempt(t, doc, &recordingForwarder{})
			if failure != nil {
				t.Fatalf("the fallback credential should have served the request, got %+v", failure)
			}
			// The block that skipped the primary is persisted rather than
			// substituted for the fallback's own conclusion.
			cfg := normalizeConfig(defaultConfig())
			if skip := executionPlan(doc, cfg, "GLM-5.2", nil, time.Now()).SkipBlock; skip == nil || skip.Code != tc.wantCode || skip.Class != tc.wantClass {
				t.Fatalf("skip block = %+v, want code %s class %s", skip, tc.wantCode, tc.wantClass)
			}
			calls := upstream.calls()
			if len(calls) != 1 {
				t.Fatalf("upstream attempts = %d, want 1: the blocked jwt must not be tried", len(calls))
			}
			if calls[0].apiKey != testAPIKeyMaterial {
				t.Errorf("upstream attempt authenticated with %q/%q, want the managed key", calls[0].auth, calls[0].apiKey)
			}
			// The primary keeps its own block — with a window, so it recovers
			// on its own — and the fallback records its own success. Neither
			// conclusion touches the other credential.
			assertRecordedState(t, recorder.forKind(CredentialJWT), tc.jwtStatus, isWindowedState(tc.jwtStatus))
			assertRecordedState(t, recorder.forKind(CredentialAPIKey), apiKeyStatusActive, false)
		})
	}
}

// TestBlockedPrimaryWithoutFallbackReportsTheJwtState checks the degraded
// path: with no usable fallback, the caller learns why the primary is blocked
// and the upstream is never contacted.
func TestBlockedPrimaryWithoutFallbackReportsTheJwtState(t *testing.T) {
	cases := map[string]struct {
		jwtStatus string
		wantCode  string
		wantClass failureClass
		wantHTTP  int
	}{
		"invalid":              {jwtStatusInvalid, "credential_invalid", failureInvalid, http.StatusUnauthorized},
		"exhausted":            {jwtStatusExhausted, "credential_quota_exhausted", failureExhausted, http.StatusPaymentRequired},
		"verification_blocked": {jwtStatusVerificationBlocked, "credential_verification_blocked", failureVerificationBlocked, http.StatusForbidden},
		"cooldown":             {jwtStatusCooldown, "credential_cooling_down", failureCooldown, http.StatusServiceUnavailable},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			upstream := newScriptedUpstream(t, upstreamScript{frames: completeAnthropicSSE()})
			failure, _, recorder := runFallbackAttempt(t, blockedWithoutFallback(t, tc.jwtStatus), &recordingForwarder{})
			if failure == nil {
				t.Fatal("a blocked primary with no fallback must fail")
			}
			if failure.Code != tc.wantCode || failure.Class != tc.wantClass || failure.ClientStatus != tc.wantHTTP {
				t.Fatalf("failure = %+v, want code %s class %s status %d", failure, tc.wantCode, tc.wantClass, tc.wantHTTP)
			}
			if strings.Contains(failure.Message, testJWT) || strings.Contains(failure.Message, testAPIKeyMaterial) {
				t.Fatalf("failure message leaks credential material: %q", failure.Message)
			}
			if len(upstream.calls()) != 0 {
				t.Fatalf("upstream attempts = %d, want 0", len(upstream.calls()))
			}
			assertRecordedState(t, recorder.all(), "", false)
		})
	}
}

// TestVerificationBlockRetryWindowElapses is the recovery half of the
// verification rule: five minutes after a captcha block the JWT is retried
// again, while the same block still inside the window keeps it skipped.
func TestVerificationBlockRetryWindowElapses(t *testing.T) {
	if verificationRetryWindow != 5*time.Minute {
		t.Fatalf("verification retry window = %v, want 5m", verificationRetryWindow)
	}
	window := verificationRetryWindow

	now := time.Now().UTC().Truncate(time.Second)
	blocked := testFallbackDoc(jwtStatusVerificationBlocked, apiKeyStatusActive)
	withRetry, err := patchZcodeNamespace(blocked, func(zcode map[string]any) error {
		jwt, _ := zcode["jwt"].(map[string]any)
		jwt["retry_after"] = now.Add(window).Format(time.RFC3339)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Inside the window the JWT stays skipped.
	newScriptedUpstream(t, upstreamScript{frames: completeAnthropicSSE()})
	plan := executionPlan(withRetry, testConfig(), "GLM-5.2", nil, now)
	if plan.Failure != nil {
		t.Fatalf("the fallback should serve the request, got %+v", plan.Failure)
	}
	if plan.Primary.CredentialKind != CredentialAPIKey || len(plan.Attempts) != 1 || plan.Attempts[0].CredentialKind != CredentialAPIKey {
		t.Fatalf("inside the retry window the jwt must be skipped: %+v", plan)
	}
	// The block that skipped the jwt is persisted so the loop can record it.
	if plan.SkipBlock == nil || plan.SkipBlock.Code != "credential_verification_blocked" {
		t.Fatalf("inside the retry window the jwt block must be carried as the skip, got %+v", plan.SkipBlock)
	}

	// After the window the JWT is primary again, and its recorded state is
	// cleared by the attempt's success.
	elapsed, err := patchZcodeNamespace(withRetry, func(zcode map[string]any) error {
		jwt, _ := zcode["jwt"].(map[string]any)
		jwt["retry_after"] = now.Add(-time.Second).Format(time.RFC3339)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	plan = executionPlan(elapsed, testConfig(), "GLM-5.2", nil, now)
	if plan.Failure != nil {
		t.Fatalf("after the retry window the jwt must be primary, got %+v", plan.Failure)
	}
	if plan.Primary.CredentialKind != CredentialJWT || len(plan.Attempts) != 2 ||
		plan.Attempts[0].CredentialKind != CredentialJWT || plan.Attempts[1].CredentialKind != CredentialAPIKey {
		t.Fatalf("after the retry window: %+v", plan)
	}
	if plan.SkipBlock != nil {
		t.Fatalf("a recovered jwt blocks nothing, want no skip block, got %+v", plan.SkipBlock)
	}
}

// TestCredentialStatesPersistIndependently is the storage-level guarantee:
// one recorded attempt writes the two credential states in a single lossless
// save, and the JWT state is never overwritten by a fallback failure.
func TestCredentialStatesPersistIndependently(t *testing.T) {
	fake, _ := newFakeHost(t)
	recorder := newCredentialStateRecorderOver(newRPCHost(fake).AuthStore())
	recorder.now = fixedNow

	var saved []json.RawMessage
	var names []string
	fake.response = func(call hostCall) ([]byte, error) {
		switch call.method {
		case "host.auth.get_runtime":
			return okEnvelopeBytes(json.RawMessage(`{"auth":{"name":"zcode-abc.json"}}`))
		case "host.auth.save":
			var req struct {
				Name string          `json:"name"`
				JSON json.RawMessage `json:"json"`
			}
			if err := json.Unmarshal(call.request, &req); err != nil {
				return nil, err
			}
			names = append(names, req.Name)
			saved = append(saved, req.JSON)
			return okEnvelopeBytes(json.RawMessage(`{"name":"zcode-abc.json"}`))
		}
		return okEnvelopeBytes(nil)
	}

	err := recorder.record(context.Background(), credentialRef{
		AuthIndex:  "auth-1",
		IdentityID: "zcode-user-1",
		Document:   testFallbackDoc(jwtStatusActive, apiKeyStatusActive),
	},
		recordedState{
			Kind:       CredentialJWT,
			Status:     jwtStatusVerificationBlocked,
			RetryAfter: fixedNow().Add(5 * time.Minute),
			Code:       "upstream_verification_required",
		},
		recordedState{
			Kind:   CredentialAPIKey,
			Status: "invalid",
			Code:   "credential_invalid",
		},
	)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if len(saved) != 1 {
		t.Fatalf("saved %d documents, want exactly 1 per attempt", len(saved))
	}
	if names[0] != "zcode-abc.json" {
		t.Fatalf("save name = %q, want the host auth file name", names[0])
	}

	// Host-owned fields and the credential material survive the rewrite.
	var document map[string]any
	if err := json.Unmarshal(saved[0], &document); err != nil {
		t.Fatal(err)
	}
	if document["other"] != "host-owned" {
		t.Errorf("host-owned field lost: %v", document["other"])
	}
	zcode, _ := document["zcode"].(map[string]any)
	jwt, _ := zcode["jwt"].(map[string]any)
	if jwt["token"] != testJWT {
		t.Errorf("jwt token lost: %v", jwt["token"])
	}
	if jwt["status"] != jwtStatusVerificationBlocked {
		t.Errorf("jwt status = %v, want %s", jwt["status"], jwtStatusVerificationBlocked)
	}
	if jwt["retry_after"] != fixedNow().Add(5*time.Minute).Format(time.RFC3339) {
		t.Errorf("jwt retry_after = %v", jwt["retry_after"])
	}
	apiKey, _ := zcode["api_key"].(map[string]any)
	if apiKey["key_material"] != testAPIKeyMaterial {
		t.Errorf("managed key material lost: %v", apiKey["key_material"])
	}
	if apiKey["key_id"] != "key-1" {
		t.Errorf("managed key id lost: %v", apiKey["key_id"])
	}
	if apiKey["status"] != "invalid" {
		t.Errorf("api key status = %v, want invalid", apiKey["status"])
	}

	// An identical repeat within the window is one save, not two.
	if err := recorder.record(context.Background(), credentialRef{
		AuthIndex:  "auth-1",
		IdentityID: "zcode-user-1",
		Document:   saved[0],
	},
		recordedState{
			Kind:       CredentialJWT,
			Status:     jwtStatusVerificationBlocked,
			RetryAfter: fixedNow().Add(5 * time.Minute),
			Code:       "upstream_verification_required",
		},
		recordedState{Kind: CredentialAPIKey, Status: "invalid", Code: "credential_invalid"},
	); err != nil {
		t.Fatal(err)
	}
	if len(saved) != 1 {
		t.Fatalf("identical repeated state was written %d times, want 1", len(saved))
	}
}

// TestCredentialStateRecoveryClearsExpiredWindows proves the persisted state
// self-heals: a cooldown whose window has passed is written back as active, so
// a later reader never has to re-derive the clock.
func TestCredentialStateRecoveryClearsExpiredWindows(t *testing.T) {
	fake, _ := newFakeHost(t)
	recorder := newCredentialStateRecorderOver(newRPCHost(fake).AuthStore())
	now := fixedNow()
	recorder.now = func() time.Time { return now }

	var saved json.RawMessage
	// The runtime lookup names the record and the record lookup returns the
	// document itself, which is what the real adapter does.
	document := testFallbackDoc(jwtStatusCooldown, apiKeyStatusActive)
	fake.response = func(call hostCall) ([]byte, error) {
		switch call.method {
		case pluginabi.MethodHostAuthGet:
			raw, err := json.Marshal(map[string]any{"auth_index": "auth-1", "json": json.RawMessage(document)})
			if err != nil {
				return nil, err
			}
			return okEnvelopeBytes(raw)
		case pluginabi.MethodHostAuthSave:
			var req struct {
				JSON json.RawMessage `json:"json"`
			}
			if err := json.Unmarshal(call.request, &req); err != nil {
				return nil, err
			}
			document = req.JSON
			saved = req.JSON
		}
		return okEnvelopeBytes(json.RawMessage(`{"auth":{"name":"zcode-abc.json"}}`))
	}
	ref := credentialRef{AuthIndex: "auth-1", IdentityID: "zcode-user-1", Document: document}
	if err := recorder.record(context.Background(), ref,
		recordedState{Kind: CredentialJWT, Status: jwtStatusActive, Code: ""},
		recordedState{Kind: CredentialAPIKey, Status: apiKeyStatusCooldown, RetryAfter: now.Add(time.Minute), Code: "upstream_rate_limited"},
	); err != nil {
		t.Fatal(err)
	}
	// Each check decodes into a fresh value: encoding/json leaves a struct
	// field untouched when the key is absent, so reusing one would report the
	// previous document's window.
	readStates := func(t *testing.T) credentialSections {
		t.Helper()
		var root struct {
			Zcode credentialSections `json:"zcode"`
		}
		if err := json.Unmarshal(saved, &root); err != nil {
			t.Fatal(err)
		}
		return root.Zcode
	}
	states := readStates(t)
	if states.JWT.Status != jwtStatusActive || states.JWT.RetryAfter != "" {
		t.Errorf("a successful jwt must be recorded as active with no retry window: %+v", states.JWT)
	}
	if states.APIKey.Status != apiKeyStatusCooldown || states.APIKey.RetryAfter == "" {
		t.Errorf("the key cooldown was not recorded: %+v", states.APIKey)
	}

	// Once the window has passed, a successful key attempt clears the state.
	now = now.Add(2 * time.Minute)
	ref.Document = saved
	if err := recorder.record(context.Background(), ref,
		recordedState{Kind: CredentialAPIKey, Status: apiKeyStatusActive},
	); err != nil {
		t.Fatal(err)
	}
	states = readStates(t)
	if states.APIKey.Status != apiKeyStatusActive || states.APIKey.RetryAfter != "" {
		t.Errorf("an expired key cooldown must be recovered: %+v", states.APIKey)
	}
	if states.JWT.Status != jwtStatusActive {
		t.Errorf("recovering the key must not touch the jwt: %+v", states.JWT)
	}
}

// TestCredentialStateNeverOverwritesTheRecordWithAnEmptyDocument guards the
// write path against the one read that is worse than a failure: a host that
// answers the record lookup with nothing must not leave a saved document that
// has neither a JWT nor a managed key.
func TestCredentialStateNeverOverwritesTheRecordWithAnEmptyDocument(t *testing.T) {
	fake, _ := newFakeHost(t)
	recorder := newCredentialStateRecorderOver(newRPCHost(fake).AuthStore())
	recorder.now = fixedNow

	var saved json.RawMessage
	fake.response = func(call hostCall) ([]byte, error) {
		switch call.method {
		case pluginabi.MethodHostAuthGet:
			// The store answers, but with an empty document.
			return okEnvelopeBytes(json.RawMessage(`{}`))
		case pluginabi.MethodHostAuthSave:
			var req struct {
				JSON json.RawMessage `json:"json"`
			}
			if err := json.Unmarshal(call.request, &req); err != nil {
				return nil, err
			}
			saved = req.JSON
		}
		return okEnvelopeBytes(json.RawMessage(`{"auth":{"name":"zcode-abc.json"}}`))
	}

	ref := credentialRef{AuthIndex: "auth-1", IdentityID: "zcode-user-1", Document: testFallbackDoc(jwtStatusActive, apiKeyStatusActive)}
	if err := recorder.record(context.Background(), ref, recordedState{Kind: CredentialJWT, Status: jwtStatusInvalid, Code: "credential_invalid"}); err != nil {
		t.Fatal(err)
	}
	// The write fell back to the attempt's own document, so the credential
	// material is still there.
	if !strings.Contains(string(saved), testJWT) || !strings.Contains(string(saved), testAPIKeyMaterial) {
		t.Fatalf("the saved record lost its credentials: %s", saved)
	}
}

// TestCredentialStateUpdatesAreSerialPerIdentity proves the per-identity
// serialization: a request that must wait for the identity lock does so, and
// the save still happens exactly once per attempt.
func TestCredentialStateUpdatesAreSerialPerIdentity(t *testing.T) {
	fake, _ := newFakeHost(t)
	recorder := newCredentialStateRecorderOver(newRPCHost(fake).AuthStore())
	recorder.now = fixedNow

	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	var saves int
	var mu sync.Mutex
	fake.response = func(call hostCall) ([]byte, error) {
		if call.method == "host.auth.get_runtime" {
			mu.Lock()
			blocked := saves == 0
			mu.Unlock()
			if blocked {
				entered <- struct{}{}
				<-release
			}
		}
		if call.method == "host.auth.save" {
			mu.Lock()
			saves++
			mu.Unlock()
		}
		return okEnvelopeBytes(json.RawMessage(`{"auth":{"name":"zcode-abc.json"}}`))
	}

	document := testFallbackDoc(jwtStatusActive, apiKeyStatusActive)
	first := make(chan error, 1)
	go func() {
		first <- recorder.record(context.Background(), credentialRef{AuthIndex: "auth-1", IdentityID: "zcode-user-1", Document: document},
			recordedState{Kind: CredentialJWT, Status: jwtStatusInvalid, Code: "credential_invalid"})
	}()
	<-entered

	// A second attempt on the same identity must not reach the host while the
	// first one is still writing.
	secondReached := make(chan struct{})
	go func() {
		_ = recorder.record(context.Background(), credentialRef{AuthIndex: "auth-1", IdentityID: "zcode-user-1", Document: document},
			recordedState{Kind: CredentialJWT, Status: jwtStatusInvalid, Code: "credential_invalid"})
		close(secondReached)
	}()
	select {
	case <-secondReached:
		t.Fatal("a concurrent state update for the same identity was not serialized")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatalf("first record: %v", err)
	}
	select {
	case <-secondReached:
	case <-time.After(2 * time.Second):
		t.Fatal("the serialized update never completed")
	}
}

// TestCredentialStateSaveFailureNeverFailsTheRequest keeps a broken host auth
// store from turning a working upstream request into a caller-visible error.
func TestCredentialStateSaveFailureNeverFailsTheRequest(t *testing.T) {
	fake, _ := newFakeHost(t)
	recorder := newCredentialStateRecorderOver(newRPCHost(fake).AuthStore())
	recorder.now = fixedNow
	fake.response = func(call hostCall) ([]byte, error) {
		if call.method == "host.auth.save" {
			return errorEnvelopeBytes("auth_save_failed", "disk is full")
		}
		return okEnvelopeBytes(json.RawMessage(`{"auth":{"name":"zcode-abc.json"}}`))
	}
	err := recorder.record(context.Background(), credentialRef{IdentityID: "zcode-user-1", Document: testFallbackDoc(jwtStatusActive, apiKeyStatusActive)},
		recordedState{Kind: CredentialJWT, Status: jwtStatusInvalid, Code: "credential_invalid"})
	if err == nil {
		t.Fatal("record must report the save failure to its caller")
	}
	if strings.Contains(err.Error(), testJWT) {
		t.Fatalf("the save error leaks credential material: %v", err)
	}
}
