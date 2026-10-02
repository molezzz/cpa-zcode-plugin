package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// streamRecorder captures what the executor forwards through the fake host.
type streamRecorder struct {
	mu     sync.Mutex
	emits  [][]byte
	closes []string
	done   chan struct{}
}

func newStreamRecorder() *streamRecorder {
	return &streamRecorder{done: make(chan struct{})}
}

// bind makes the fake host caller act as the stream callback endpoint.
func (r *streamRecorder) bind(fake *fakeHostCaller) {
	fake.response = func(call hostCall) ([]byte, error) {
		switch call.method {
		case pluginabi.MethodHostStreamEmit:
			var req streamEmitRequest
			if err := json.Unmarshal(call.request, &req); err != nil {
				return errorEnvelopeBytes("invalid_request", err.Error())
			}
			r.mu.Lock()
			r.emits = append(r.emits, append([]byte(nil), req.Payload...))
			r.mu.Unlock()
			return okEnvelopeBytes(nil)
		case pluginabi.MethodHostStreamClose:
			var req streamCloseRequest
			if err := json.Unmarshal(call.request, &req); err != nil {
				return errorEnvelopeBytes("invalid_request", err.Error())
			}
			r.mu.Lock()
			r.closes = append(r.closes, req.Error)
			r.mu.Unlock()
			select {
			case <-r.done:
			default:
				close(r.done)
			}
			return okEnvelopeBytes(nil)
		default:
			return okEnvelopeBytes(nil)
		}
	}
}

func (r *streamRecorder) emitted() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]byte, len(r.emits))
	copy(out, r.emits)
	return out
}

func (r *streamRecorder) closed() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.closes))
	copy(out, r.closes)
	return out
}

func (r *streamRecorder) waitDone(timeout time.Duration) bool {
	select {
	case <-r.done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// upstreamRecorder is an httptest server standing in for the ZCode upstream.
type upstreamRecorder struct {
	server   *httptest.Server
	mu       sync.Mutex
	requests int
	headers  http.Header
	bodies   []string
	// handler is replaceable per test; defaults to serving a complete
	// Anthropic SSE stream.
	handler func(w http.ResponseWriter, r *http.Request, call int)
}

func newUpstreamRecorder(t *testing.T) *upstreamRecorder {
	t.Helper()
	rec := &upstreamRecorder{}
	rec.handler = func(w http.ResponseWriter, r *http.Request, call int) {
		rec.record(r)
		writeSSE(w, completeAnthropicSSE())
	}
	rec.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		call := rec.requests
		rec.requests++
		rec.mu.Unlock()
		rec.handler(w, r, call)
	}))
	t.Cleanup(rec.server.Close)

	original := zcodePlanUpstreamBase
	zcodePlanUpstreamBase = rec.server.URL
	t.Cleanup(func() { zcodePlanUpstreamBase = original })
	return rec
}

func (r *upstreamRecorder) record(r2 *http.Request) {
	body := make([]byte, 0, 4096)
	buf := make([]byte, 2048)
	for {
		n, err := r2.Body.Read(buf)
		body = append(body, buf[:n]...)
		if err != nil {
			break
		}
	}
	r.mu.Lock()
	r.bodies = append(r.bodies, string(body))
	r.headers = r2.Header.Clone()
	r.mu.Unlock()
}

// requestBodies returns the raw bodies of upstream requests in order.
func (r *upstreamRecorder) requestBodies() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.bodies))
	copy(out, r.bodies)
	return out
}

func (r *upstreamRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.requests
}

func (r *upstreamRecorder) lastHeader(name string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.headers.Get(name)
}

func writeSSE(w http.ResponseWriter, frames string) {
	w.Header().Set("Content-Type", "text/event-stream")
	fmt.Fprint(w, frames)
	w.(http.Flusher).Flush()
}

func completeAnthropicSSE() string {
	return strings.Join([]string{
		"event: message_start\n",
		`data: {"type":"message_start","message":{"id":"msg_1","model":"GLM-5.2","role":"assistant","usage":{"input_tokens":21}}}` + "\n\n",
		"event: content_block_start\n",
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}` + "\n\n",
		"event: content_block_delta\n",
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}` + "\n\n",
		"event: content_block_stop\n",
		`data: {"type":"content_block_stop","index":0}` + "\n\n",
		"event: message_delta\n",
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":7}}` + "\n\n",
		"event: message_stop\n",
		`data: {"type":"message_stop"}` + "\n\n",
	}, "")
}

// overrideHost points both host seams at one fake host for the test's
// duration. The credential state recorder reads and writes through
// authStoreProvider rather than hostProvider, so overriding only the latter
// would leave the recorder calling the real CGO bridge.
func overrideHost(t *testing.T) (*fakeHostCaller, Host) {
	t.Helper()
	fake := &fakeHostCaller{}
	host := newRPCHost(fake)
	original := hostProvider
	hostProvider = func() Host { return host }
	t.Cleanup(func() { hostProvider = original })
	originalStore := authStoreProvider
	authStoreProvider = func() AuthStore { return host.AuthStore() }
	t.Cleanup(func() { authStoreProvider = originalStore })
	return fake, host
}

// overrideConfig stores a normalized config snapshot for the test's duration.
func overrideConfig(t *testing.T, mutate func(*Config)) {
	t.Helper()
	cfg := defaultConfig()
	if mutate != nil {
		mutate(&cfg)
	}
	original := currentConfig()
	activeConfig.Store(normalizeConfig(cfg))
	t.Cleanup(func() { activeConfig.Store(original) })
}

func executorRequestJSON(t *testing.T, doc, payload []byte, streamID string, headers map[string][]string) []byte {
	t.Helper()
	req := map[string]any{
		"AuthID":       "auth-1",
		"AuthProvider": pluginID,
		"Model":        "GLM-5.2",
		"Format":       "claude",
		"Stream":       streamID != "",
		"Payload":      payload,
		"StorageJSON":  doc,
	}
	if streamID != "" {
		req["stream_id"] = streamID
	}
	if headers != nil {
		req["Headers"] = headers
	}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

const testJWT = "jwt-header.payload.signature"

func testExecutorDoc() []byte {
	return testAuthDoc(testJWT, jwtStatusActive)
}

func testRequestPayload() []byte {
	return []byte(`{"model":"glm-5.2","max_tokens":64,"messages":[{"role":"user","content":"hi"}]}`)
}

func TestExecutorIdentifier(t *testing.T) {
	env := callMethod(t, pluginabi.MethodExecutorIdentifier, nil)
	if !env.OK {
		t.Fatalf("identifier failed: %+v", env.Error)
	}
	var response struct {
		Identifier string `json:"identifier"`
	}
	if err := json.Unmarshal(env.Result, &response); err != nil {
		t.Fatal(err)
	}
	if response.Identifier != pluginID {
		t.Fatalf("identifier = %q, want zcode", response.Identifier)
	}
}

func TestExecutorExecuteAggregatesUpstreamStream(t *testing.T) {
	upstream := newUpstreamRecorder(t)
	overrideHost(t)

	env := callMethod(t, pluginabi.MethodExecutorExecute, executorRequestJSON(t, testExecutorDoc(), testRequestPayload(), "", nil))
	if !env.OK {
		t.Fatalf("execute failed: %+v", env.Error)
	}
	var response pluginapi.ExecutorResponse
	if err := json.Unmarshal(env.Result, &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	var message map[string]any
	if err := json.Unmarshal(response.Payload, &message); err != nil {
		t.Fatalf("aggregated payload is not JSON: %v", err)
	}
	if message["type"] != "message" || message["id"] != "msg_1" {
		t.Fatalf("message = %v", message)
	}
	content := message["content"].([]any)
	if content[0].(map[string]any)["text"] != "Hello" {
		t.Fatalf("content = %v", content)
	}
	if message["stop_reason"] != "end_turn" {
		t.Fatalf("stop_reason = %v", message["stop_reason"])
	}

	// The upstream observed exactly one request with the normalized model,
	// forced streaming, and the plugin-built authentication.
	if upstream.count() != 1 {
		t.Fatalf("upstream request count = %d, want 1", upstream.count())
	}
	body := upstream.requestBodies()[0]
	var sent map[string]any
	if err := json.Unmarshal([]byte(body), &sent); err != nil {
		t.Fatalf("upstream body not JSON: %v", err)
	}
	if sent["model"] != "GLM-5.2" {
		t.Errorf("upstream model = %v, want the normalized GLM-5.2", sent["model"])
	}
	if sent["stream"] != true {
		t.Errorf("upstream stream = %v, want forced true", sent["stream"])
	}
	if upstream.lastHeader("Authorization") != "Bearer "+testJWT {
		t.Errorf("authorization = %q", upstream.lastHeader("Authorization"))
	}
}

func TestExecutorExecuteCarriesOneIdentityInBodyAndHeaders(t *testing.T) {
	// The official client describes one installation and one session in both
	// places the upstream reads: the body's metadata.user_id and the
	// fingerprint/attribution headers. The plugin must present the same
	// resolved identity in both, keep it stable across the requests of one
	// caller session, and rotate only the per-request attribution ids.
	upstream := newUpstreamRecorder(t)
	overrideHost(t)

	env := callMethod(t, pluginabi.MethodExecutorExecute, executorRequestJSON(t, testExecutorDoc(), testRequestPayload(), "", nil))
	if !env.OK {
		t.Fatalf("execute failed: %+v", env.Error)
	}
	if upstream.count() != 1 {
		t.Fatalf("upstream request count = %d, want 1", upstream.count())
	}

	deviceID := upstream.lastHeader(deviceMidHeader)
	if deviceID == "" {
		t.Fatalf("%s = empty, want the credential's device identity", deviceMidHeader)
	}
	firstRequestID := upstream.lastHeader(requestIDHeader)
	userID := upstreamBodyUserID(t, upstream.requestBodies()[0])
	if got := userID["device_id"]; got != deviceID {
		t.Errorf("body device_id = %v, want the header's %q", got, deviceID)
	}
	if got, want := userID["account_uuid"], ""; got != want {
		t.Errorf("account_uuid = %v, want the official empty string", got)
	}
	sessionID, ok := userID["session_id"].(string)
	if !ok || sessionID == "" {
		t.Fatalf("session_id = %v, want the derived session id", userID["session_id"])
	}
	if got := upstream.lastHeader(sessionIDHeader); got != sessionID {
		t.Errorf("header session %q != body session %q; one request must describe one session", got, sessionID)
	}
	if got := upstream.lastHeader(sessionTypeHeader); got != mainSessionType {
		t.Errorf("%s = %q, want %q", sessionTypeHeader, got, mainSessionType)
	}

	env = callMethod(t, pluginabi.MethodExecutorExecute, executorRequestJSON(t, testExecutorDoc(), testRequestPayload(), "", nil))
	if !env.OK {
		t.Fatalf("second execute failed: %+v", env.Error)
	}
	secondUserID := upstreamBodyUserID(t, upstream.requestBodies()[1])
	if secondUserID["session_id"] != sessionID {
		t.Errorf("session id drifted across requests: %q then %v", sessionID, secondUserID["session_id"])
	}
	if secondUserID["device_id"] != deviceID {
		t.Errorf("device id drifted: %q then %v", deviceID, secondUserID["device_id"])
	}
	if upstream.lastHeader(requestIDHeader) == firstRequestID {
		t.Error("request attribution id was reused across requests, want a fresh one per request")
	}
}

// upstreamBodyUserID extracts the parsed metadata.user_id of one recorded
// upstream body.
func upstreamBodyUserID(t *testing.T, body string) map[string]any {
	t.Helper()
	var sent map[string]any
	if err := json.Unmarshal([]byte(body), &sent); err != nil {
		t.Fatalf("upstream body not JSON: %v", err)
	}
	metadata, ok := sent["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("upstream body carries no metadata: %v", sent["metadata"])
	}
	raw, ok := metadata["user_id"].(string)
	if !ok {
		t.Fatalf("metadata.user_id = %T, want the official stringified JSON form", metadata["user_id"])
	}
	var userID map[string]any
	if err := json.Unmarshal([]byte(raw), &userID); err != nil {
		t.Fatalf("metadata.user_id is not JSON: %v", err)
	}
	return userID
}

func TestExecutorExecuteOnlyForwardsAllowlistedHeaders(t *testing.T) {
	upstream := newUpstreamRecorder(t)
	overrideHost(t)

	callerHeaders := map[string][]string{
		"Authorization":       {"Bearer caller-secret"},
		"X-Api-Key":           {"caller-api-key"},
		"Cookie":              {"session=caller"},
		"Proxy-Authorization": {"Basic proxy"},
		"Host":                {"evil.example"},
		"Connection":          {"close"},
		"X-Zcode-Agent":       {"spoofed"},
		"Anthropic-Beta":      {"feature-1"},
	}
	env := callMethod(t, pluginabi.MethodExecutorExecute, executorRequestJSON(t, testExecutorDoc(), testRequestPayload(), "", callerHeaders))
	if !env.OK {
		t.Fatalf("execute failed: %+v", env.Error)
	}
	for _, name := range []string{"X-Api-Key", "Cookie", "Proxy-Authorization", "Host", "Connection"} {
		if got := upstream.lastHeader(name); got != "" {
			t.Errorf("%s reached the upstream: %q", name, got)
		}
	}
	if upstream.lastHeader("Authorization") != "Bearer "+testJWT {
		t.Errorf("authorization = %q, want the host-managed credential", upstream.lastHeader("Authorization"))
	}
	if upstream.lastHeader("Anthropic-Beta") != "feature-1" {
		t.Errorf("anthropic-beta = %q, want the allowlisted value", upstream.lastHeader("Anthropic-Beta"))
	}
	if upstream.lastHeader("X-Zcode-Agent") != zcodeAgentHeader {
		t.Errorf("x-zcode-agent = %q, want the plugin-built value", upstream.lastHeader("X-Zcode-Agent"))
	}
}

func TestExecutorExecuteUpstreamRejectionBeforeOutput(t *testing.T) {
	upstream := newUpstreamRecorder(t)
	upstream.handler = func(w http.ResponseWriter, r *http.Request, call int) {
		upstream.record(r)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"invalid token"}}`))
	}
	overrideHost(t)

	env := callMethod(t, pluginabi.MethodExecutorExecute, executorRequestJSON(t, testExecutorDoc(), testRequestPayload(), "", nil))
	if env.OK {
		t.Fatal("401 must produce an error envelope")
	}
	// A JWT-only record has no fallback credential, so the rejection is final.
	if env.Error.Code != "credential_invalid" || env.Error.HTTPStatus != http.StatusUnauthorized {
		t.Fatalf("error = %+v", env.Error)
	}
	if upstream.count() != 1 {
		t.Fatalf("upstream request count = %d, want 1", upstream.count())
	}
}

// TestExecutorExecuteFallsBackToManagedAPIKey drives the whole RPC path: the
// upstream rejects the Coding Plan credential with a verification requirement,
// and the same unmutated request is answered through the managed key's own
// Z.AI endpoint and authentication.
func TestExecutorExecuteFallsBackToManagedAPIKey(t *testing.T) {
	upstream := newScriptedUpstream(t,
		upstreamScript{status: http.StatusForbidden, body: `{"error":{"message":"captcha verification required"}}`},
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
	var message map[string]any
	if err := json.Unmarshal(response.Payload, &message); err != nil {
		t.Fatalf("aggregated payload is not JSON: %v", err)
	}
	if message["id"] != "msg_1" {
		t.Fatalf("the fallback answer did not reach the caller: %v", message)
	}

	calls := upstream.calls()
	if len(calls) != 2 {
		t.Fatalf("upstream attempts = %d, want 2", len(calls))
	}
	if calls[0].auth != "Bearer "+testJWT || calls[0].endpoint != zcodeMessagesPath {
		t.Errorf("the primary attempt did not use the Coding Plan endpoint with the jwt: %+v", calls[0])
	}
	if calls[1].apiKey != testAPIKeyMaterial || calls[1].auth != "" || calls[1].endpoint != zaiMessagesPath {
		t.Errorf("the fallback attempt did not use the managed key on the zai endpoint: %+v", calls[1])
	}
	if calls[0].body != calls[1].body {
		t.Errorf("the fallback replayed a mutated body:\n jwt: %s\n key: %s", calls[0].body, calls[1].body)
	}
}

// TestExecutorExecuteStreamDoesNotSpliceAfterOutput is the streaming half of the
// same rule: once a frame is visible, a failed attempt is final even though the
// failure would otherwise be retryable.
func TestExecutorExecuteStreamDoesNotSpliceAfterOutput(t *testing.T) {
	upstream := newScriptedUpstream(t,
		upstreamScript{frames: partialStream, abort: true},
		upstreamScript{frames: completeAnthropicSSE()},
	)
	fake, _ := overrideHost(t)
	rec := newStreamRecorder()
	rec.bind(fake)

	env := callMethod(t, pluginabi.MethodExecutorExecuteStream, executorRequestJSON(t, testFallbackDoc(jwtStatusActive, apiKeyStatusActive), testRequestPayload(), "stream-6", nil))
	if !env.OK {
		t.Fatalf("stream start failed: %+v", env.Error)
	}
	if !rec.waitDone(5 * time.Second) {
		t.Fatal("stream was never closed")
	}
	emits := rec.emitted()
	if len(emits) != 1 || !strings.Contains(string(emits[0]), "partial") {
		t.Fatalf("forwarded frames = %v, want only the primary's partial output", emitStrings(emits))
	}
	closes := rec.closed()
	if len(closes) != 1 || closes[0] == "" {
		t.Fatalf("the aborted stream must close exactly once with an error: %v", closes)
	}
	if upstream.count() != 1 {
		t.Fatalf("upstream request count = %d, want 1: nothing may follow visible output", upstream.count())
	}
}

func TestExecutorExecuteRateLimitedFallsBack(t *testing.T) {
	upstream := newScriptedUpstream(t,
		upstreamScript{status: http.StatusTooManyRequests, body: `{}`},
		upstreamScript{frames: completeAnthropicSSE()},
	)
	overrideHost(t)

	env := callMethod(t, pluginabi.MethodExecutorExecute, executorRequestJSON(t, testFallbackDoc(jwtStatusActive, apiKeyStatusActive), testRequestPayload(), "", nil))
	if !env.OK {
		t.Fatalf("execute failed: %+v", env.Error)
	}
	if upstream.count() != 2 {
		t.Fatalf("upstream request count = %d, want 2", upstream.count())
	}
}

func TestExecutorExecuteNoFallbackKeyReportsThePrimaryBlock(t *testing.T) {
	upstream := newScriptedUpstream(t,
		upstreamScript{status: http.StatusForbidden, body: `{"error":{"message":"captcha verification required"}}`},
	)
	overrideHost(t)

	env := callMethod(t, pluginabi.MethodExecutorExecute, executorRequestJSON(t, testFallbackDoc(jwtStatusActive, apiKeyStatusUnavailable), testRequestPayload(), "", nil))
	if env.OK {
		t.Fatal("a blocked primary with no fallback must produce an error envelope")
	}
	// The caller is told the Coding Plan credential is verification blocked,
	// which is the actionable reason, and never hears upstream prose.
	if env.Error.Code != "upstream_verification_required" || env.Error.HTTPStatus != http.StatusForbidden {
		t.Fatalf("error = %+v", env.Error)
	}
	if strings.Contains(env.Error.Message, "captcha verification required") {
		t.Fatalf("the upstream body leaked into the envelope: %q", env.Error.Message)
	}
	if upstream.count() != 1 {
		t.Fatalf("upstream request count = %d, want 1", upstream.count())
	}
}

// TestExecutorHasNoCaptchaAutomation pins the negative requirement of the
// milestone. The first version of this scan was tripped by its own needle list
// and by the plain word "browser" in unrelated prose, so it matches on
// automation-shaped identifiers only and skips the file that carries the scan.
func TestExecutorHasNoCaptchaAutomation(t *testing.T) {
	forbidden := []string{
		"captcha_solver", "captchasolver", "solve_captcha", "solver.js",
		"playwright", "puppeteer", "chromedp", "rod.Chrome", "webdriver",
		"tesseract", "recaptcha", "hcaptcha", "turnstile",
		"aliyun-captcha", "captcha-verify-param", "x-captcha-verify",
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || entry.Name() == "executor_test.go" {
			continue
		}
		raw, err := os.ReadFile(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		lower := strings.ToLower(string(raw))
		for _, needle := range forbidden {
			if strings.Contains(lower, strings.ToLower(needle)) {
				t.Errorf("%s references %q; captcha automation is out of scope", entry.Name(), needle)
			}
		}
	}
}

func TestExecutorExecuteStreamForwardsAndClosesExactlyOnce(t *testing.T) {
	upstream := newUpstreamRecorder(t)
	fake, _ := overrideHost(t)
	rec := newStreamRecorder()
	rec.bind(fake)

	env := callMethod(t, pluginabi.MethodExecutorExecuteStream, executorRequestJSON(t, testExecutorDoc(), testRequestPayload(), "stream-1", nil))
	if !env.OK {
		t.Fatalf("execute_stream failed: %+v", env.Error)
	}
	// The response acknowledges the stream immediately with SSE headers.
	var streamed executorStreamResponseRPC
	if err := json.Unmarshal(env.Result, &streamed); err != nil {
		t.Fatalf("decode stream response: %v", err)
	}
	if got := streamed.Headers.Get("Content-Type"); got != "text/event-stream" {
		t.Fatalf("stream content type = %q", got)
	}

	if !rec.waitDone(5 * time.Second) {
		t.Fatal("stream was never closed")
	}
	emits := rec.emitted()
	if len(emits) == 0 {
		t.Fatal("no frames were forwarded")
	}
	// Frames reach the host verbatim and in order.
	joined := strings.Join([]string{
		"event: message_start\n",
		`data: {"type":"message_start","message":{"id":"msg_1","model":"GLM-5.2","role":"assistant","usage":{"input_tokens":21}}}` + "\n\n",
		"event: content_block_start\n",
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}` + "\n\n",
		"event: content_block_delta\n",
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}` + "\n\n",
		"event: content_block_stop\n",
		`data: {"type":"content_block_stop","index":0}` + "\n\n",
		"event: message_delta\n",
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":7}}` + "\n\n",
		"event: message_stop\n",
		`data: {"type":"message_stop"}` + "\n\n",
	}, "")
	if got := strings.Join(emitStrings(emits), ""); got != joined {
		t.Fatalf("forwarded stream mismatch:\n got %q\nwant %q", got, joined)
	}
	closes := rec.closed()
	if len(closes) != 1 {
		t.Fatalf("close called %d times with %v, want exactly once", len(closes), closes)
	}
	if closes[0] != "" {
		t.Fatalf("clean stream closed with error %q", closes[0])
	}
	if upstream.count() != 1 {
		t.Fatalf("upstream request count = %d, want 1", upstream.count())
	}
}

func emitStrings(frames [][]byte) []string {
	out := make([]string, len(frames))
	for i, frame := range frames {
		out[i] = string(frame)
	}
	return out
}

func TestExecutorExecuteStreamUpstreamRejectsBeforeStart(t *testing.T) {
	upstream := newUpstreamRecorder(t)
	upstream.handler = func(w http.ResponseWriter, r *http.Request, call int) {
		upstream.record(r)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"message":"captcha verification required"}}`))
	}
	fake, _ := overrideHost(t)
	rec := newStreamRecorder()
	rec.bind(fake)

	env := callMethod(t, pluginabi.MethodExecutorExecuteStream, executorRequestJSON(t, testExecutorDoc(), testRequestPayload(), "stream-2", nil))
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
	if closes[0] == "" || strings.Contains(closes[0], "captcha verification required") {
		t.Fatalf("close error not sanitized: %q", closes[0])
	}
	// Nothing was emitted before the failure.
	if len(rec.emitted()) != 0 {
		t.Fatalf("frames emitted despite upstream rejection: %d", len(rec.emitted()))
	}
	if upstream.count() != 1 {
		t.Fatalf("upstream request count = %d, want 1", upstream.count())
	}
}

func TestExecutorExecuteStreamNoRetryAfterOutput(t *testing.T) {
	upstream := newUpstreamRecorder(t)
	upstream.handler = func(w http.ResponseWriter, r *http.Request, call int) {
		upstream.record(r)
		writeSSE(w, "event: content_block_delta\n"+
			`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"partial"}}`+"\n\n")
		// Abort the connection mid-stream: a retryable transport failure
		// after output already reached the caller.
		panic(http.ErrAbortHandler)
	}
	fake, _ := overrideHost(t)
	rec := newStreamRecorder()
	rec.bind(fake)

	env := callMethod(t, pluginabi.MethodExecutorExecuteStream, executorRequestJSON(t, testExecutorDoc(), testRequestPayload(), "stream-3", nil))
	if !env.OK {
		t.Fatalf("stream start failed: %+v", env.Error)
	}
	if !rec.waitDone(5 * time.Second) {
		t.Fatal("stream was never closed")
	}
	if len(rec.emitted()) == 0 {
		t.Fatal("output must have started before the upstream abort")
	}
	closes := rec.closed()
	if len(closes) != 1 {
		t.Fatalf("close called %d times, want exactly once", len(closes))
	}
	if closes[0] == "" {
		t.Fatal("aborted stream must close with an error message")
	}
	// 输出开始后绝不重试:即使失败可重试,上游也只被请求一次。
	if upstream.count() != 1 {
		t.Fatalf("upstream request count = %d, want 1 (no retry after output)", upstream.count())
	}
}

func TestExecutorExecuteStreamRequiresStreamID(t *testing.T) {
	upstream := newUpstreamRecorder(t)
	overrideHost(t)

	env := callMethod(t, pluginabi.MethodExecutorExecuteStream, executorRequestJSON(t, testExecutorDoc(), testRequestPayload(), "", nil))
	if env.OK {
		t.Fatal("missing stream id must produce an error envelope")
	}
	if env.Error.Code != "invalid_request" {
		t.Fatalf("error = %+v", env.Error)
	}
	if upstream.count() != 0 {
		t.Fatalf("upstream request count = %d, want 0", upstream.count())
	}
}

func TestExecutorExecuteStreamProfileFailure(t *testing.T) {
	upstream := newUpstreamRecorder(t)
	fake, _ := overrideHost(t)
	rec := newStreamRecorder()
	rec.bind(fake)

	// Blocked JWT state: no upstream attempt, no stream activity.
	doc := testAuthDoc(testJWT, jwtStatusInvalid)
	env := callMethod(t, pluginabi.MethodExecutorExecuteStream, executorRequestJSON(t, doc, testRequestPayload(), "stream-4", nil))
	if env.OK {
		t.Fatal("blocked credential must produce an error envelope")
	}
	if env.Error.Code != "credential_invalid" {
		t.Fatalf("error = %+v", env.Error)
	}
	if upstream.count() != 0 {
		t.Fatalf("upstream request count = %d, want 0", upstream.count())
	}
	if len(rec.emitted()) != 0 || len(rec.closed()) != 0 {
		t.Fatal("stream callbacks must not fire when the profile fails")
	}
}

func TestExecutorStreamShutdownCancelsPump(t *testing.T) {
	release := make(chan struct{})
	upstream := newUpstreamRecorder(t)
	upstream.handler = func(w http.ResponseWriter, r *http.Request, call int) {
		upstream.record(r)
		writeSSE(w, "event: message_start\ndata: {}\n\n")
		<-release
	}
	fake, _ := overrideHost(t)
	rec := newStreamRecorder()
	rec.bind(fake)

	env := callMethod(t, pluginabi.MethodExecutorExecuteStream, executorRequestJSON(t, testExecutorDoc(), testRequestPayload(), "stream-5", nil))
	if !env.OK {
		t.Fatalf("stream start failed: %+v", env.Error)
	}
	// Wait until the first frame was forwarded, then simulate shutdown.
	deadline := time.Now().Add(5 * time.Second)
	for len(rec.emitted()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	activeExecutions.cancelAll()
	if !rec.waitDone(5 * time.Second) {
		t.Fatal("stream was never closed after shutdown")
	}
	closes := rec.closed()
	if len(closes) != 1 {
		t.Fatalf("close called %d times, want exactly once", len(closes))
	}
	close(release)
}

func TestExecutorCountTokensAndHTTPRequestNotSupported(t *testing.T) {
	for _, method := range []string{pluginabi.MethodExecutorCountTokens, pluginabi.MethodExecutorHTTPRequest} {
		env := callMethod(t, method, []byte(`{}`))
		if env.OK {
			t.Errorf("%s unexpectedly succeeded", method)
		}
		if env.Error == nil || env.Error.Code != "not_supported" {
			t.Errorf("%s error = %+v, want not_supported", method, env.Error)
		}
	}
}

func TestExecutionRegistryCancelAll(t *testing.T) {
	registry := newExecutionRegistry()
	canceled := make(chan struct{}, 2)
	ctx, cancel := context.WithCancel(context.Background())
	remove := registry.add(cancel)
	go func() {
		<-ctx.Done()
		canceled <- struct{}{}
	}()
	registry.cancelAll()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("cancelAll did not cancel registered work")
	}
	remove() // must not panic or resurrect the entry
	registry.cancelAll()
}

func TestExecutionRegistryRemove(t *testing.T) {
	registry := newExecutionRegistry()
	ctx, cancel := context.WithCancel(context.Background())
	remove := registry.add(cancel)
	remove()
	registry.cancelAll()
	select {
	case <-ctx.Done():
		t.Fatal("removed execution must not be canceled by cancelAll")
	default:
	}
	cancel()
}

func TestExecutorExecutePlan3012IsTerminalWithoutCrossDomainFallback(t *testing.T) {
	upstream := newUpstreamRecorder(t)
	fake, _ := overrideHost(t)
	overrideConfig(t, func(cfg *Config) {})

	// The Coding Plan route answers 405 carrying the request-level business
	// code 3012. The cause is not established and no challenge is claimed:
	// the caller gets the upstream's own bounded reading of the rejection.
	upstream.handler = func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = w.Write([]byte(`{"code":3012,"msg":"request has been blocked due to unusual activity.","logid":"log-1"}`))
	}
	// A second server stands in for the managed-key route, a different billing
	// domain. A request-level verdict cannot be cured by another credential,
	// so the loop must end before that route can spend the account's balance.
	fallback := newKeyRouteRecorder(t)

	doc := []byte(`{"zcode":{"identity_id":"zcode-user-1","jwt":{"token":"` + testJWT + `","status":"` +
		jwtStatusActive + `"},"api_key":{"status":"active","key_material":"key-1.secret"}}}`)
	env := callMethod(t, pluginabi.MethodExecutorExecute, executorRequestJSON(t, doc, testRequestPayload(), "", nil))
	if env.OK {
		t.Fatalf("execute unexpectedly succeeded: %+v", env.Result)
	}
	if env.Error == nil {
		t.Fatal("failure envelope missing an error")
	}
	if env.Error.Code != "upstream_rejected_invalid_request" {
		t.Fatalf("error code = %q, want the request-level business classification", env.Error.Code)
	}
	if env.Error.HTTPStatus != http.StatusBadRequest {
		t.Fatalf("error status = %d, want 400 instead of the 405 carrier", env.Error.HTTPStatus)
	}
	if !strings.Contains(env.Error.Message, "unusual activity") || !strings.Contains(env.Error.Message, "3012") {
		t.Fatalf("message = %q, want the bounded upstream msg and business code", env.Error.Message)
	}
	if strings.Contains(strings.ToLower(env.Error.Message), "challenge") {
		t.Fatalf("message = %q, must not claim an unproven challenge diagnosis", env.Error.Message)
	}
	if upstream.count() != 1 {
		t.Fatalf("coding plan route requests = %d, want exactly 1", upstream.count())
	}
	if fallback.count() != 0 {
		t.Fatalf("fallback route requests = %d, want 0: a request-level verdict must not spend the API-key billing domain", fallback.count())
	}
	// Neither credential's state may move: the verdict is about the request,
	// not about the credential, so the recorded states stay byte-identical.
	for _, call := range fake.calls {
		if call.method == pluginabi.MethodHostAuthSave {
			t.Fatalf("credential state written for a request-level rejection: %s", call.request)
		}
	}
}

func TestExecutorExecuteVerificationBlockedStillFallsBack(t *testing.T) {
	upstream := newUpstreamRecorder(t)
	overrideHost(t)
	overrideConfig(t, func(cfg *Config) {})

	// The one credential-level verdict that changes nothing about the JWT's
	// validity: a 403 whose body carries explicit captcha/verify evidence.
	// Its fallback across the billing-domain boundary is the existing,
	// evidence-backed flow and must not regress.
	upstream.handler = func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"type":"risk_control","message":"captcha verification required"}}`))
	}
	fallback := newKeyRouteRecorder(t)

	doc := []byte(`{"zcode":{"identity_id":"zcode-user-1","jwt":{"token":"` + testJWT + `","status":"` +
		jwtStatusActive + `"},"api_key":{"status":"active","key_material":"key-1.secret"}}}`)
	env := callMethod(t, pluginabi.MethodExecutorExecute, executorRequestJSON(t, doc, testRequestPayload(), "", nil))
	if !env.OK {
		t.Fatalf("the fallback key should serve the request: %+v", env.Error)
	}
	if upstream.count() != 1 {
		t.Fatalf("coding plan route requests = %d, want exactly 1", upstream.count())
	}
	if fallback.count() != 1 {
		t.Fatalf("fallback route requests = %d, want exactly 1", fallback.count())
	}
}

// newKeyRouteRecorder redirects zaiAPIBase at a local server and counts the
// requests it receives.
func newKeyRouteRecorder(t *testing.T) *upstreamRecorder {
	t.Helper()
	rec := &upstreamRecorder{}
	rec.handler = func(w http.ResponseWriter, _ *http.Request, _ int) {
		writeSSE(w, completeAnthropicSSE())
	}
	rec.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.requests++
		rec.mu.Unlock()
		rec.handler(w, r, 0)
	}))
	t.Cleanup(rec.server.Close)
	original := zaiAPIBase
	zaiAPIBase = rec.server.URL
	t.Cleanup(func() { zaiAPIBase = original })
	return rec
}

func TestExecutorDiagnosticsCarryEvidenceWithoutSecrets(t *testing.T) {
	upstream := newUpstreamRecorder(t)
	overrideHost(t)
	// Debug is off by default; this test turns it on to inspect the evidence
	// the lines carry.
	defer storeDebugConfig(true)()
	buf := captureDiagLog(t)

	const jwtToken = "jwt-evidence-token.payload.signature"
	const apiKeyMaterial = "key-evidence.secret"
	upstream.handler = func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = w.Write([]byte(`{"code":3012,"msg":"request has been blocked due to unusual activity.","logid":"log-evidence-1"}`))
	}
	doc := []byte(`{"zcode":{"identity_id":"zcode-user-1","jwt":{"token":"` + jwtToken + `","status":"` +
		jwtStatusActive + `"},"api_key":{"status":"active","key_material":"` + apiKeyMaterial + `"}}}`)
	payload := testRequestPayload()
	env := callMethod(t, pluginabi.MethodExecutorExecute, executorRequestJSON(t, doc, payload, "", nil))
	if env.OK {
		t.Fatalf("execute unexpectedly succeeded: %+v", env.Result)
	}

	log := buf.String()
	// The necessary evidence fields: route, billing domain, credential kind,
	// upstream status, class, code, bounded msg, correlation id, and the
	// fallback decision.
	for _, want := range []string{
		"route=" + routeIDPlanJWT,
		"domain=" + string(billingPlanEntitlement),
		"cred=jwt",
		"upstream_status=405",
		"class=" + string(failureRejected),
		"code=upstream_rejected_invalid_request",
		`logid="log-evidence-1"`,
		"unusual activity",
		"decision=denied",
		routeIDManagedKey,
		string(billingAPIBalance),
	} {
		if !strings.Contains(log, want) {
			t.Errorf("diagnostics missing evidence %q: %q", want, log)
		}
	}
	// The forbidden material: credential values and the request payload never
	// enter the log.
	for _, forbidden := range []string{
		jwtToken, apiKeyMaterial, "Bearer ", "evidence-token", "max_tokens",
	} {
		if strings.Contains(log, forbidden) {
			t.Errorf("diagnostics leaked forbidden material %q: %q", forbidden, log)
		}
	}
	// The device identity header never renders: the plan's header view names
	// every header it carries, and X-Device-Mid must appear only redacted.
	if strings.Contains(log, "X-Device-Mid=") && !strings.Contains(log, "X-Device-Mid=<redacted>") {
		t.Errorf("device identity rendered unredacted: %q", log)
	}
}
