package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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

// overrideHost points hostProvider at a fake host for the test's duration.
func overrideHost(t *testing.T) (*fakeHostCaller, Host) {
	t.Helper()
	fake := &fakeHostCaller{}
	original := hostProvider
	hostProvider = func() Host { return newRPCHost(fake) }
	t.Cleanup(func() { hostProvider = original })
	return fake, newRPCHost(fake)
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
	if env.Error.Code != "credential_invalid" || env.Error.HTTPStatus != http.StatusUnauthorized {
		t.Fatalf("error = %+v", env.Error)
	}
	// No same-credential retry and no fallback in this milestone: one
	// upstream request total.
	if upstream.count() != 1 {
		t.Fatalf("upstream request count = %d, want 1", upstream.count())
	}
}

func TestExecutorExecuteRateLimitedFailsWithoutRetry(t *testing.T) {
	upstream := newUpstreamRecorder(t)
	upstream.handler = func(w http.ResponseWriter, r *http.Request, call int) {
		upstream.record(r)
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{}`))
	}
	overrideHost(t)

	env := callMethod(t, pluginabi.MethodExecutorExecute, executorRequestJSON(t, testExecutorDoc(), testRequestPayload(), "", nil))
	if env.OK {
		t.Fatal("429 must produce an error envelope")
	}
	if env.Error.Code != "upstream_rate_limited" {
		t.Fatalf("error = %+v", env.Error)
	}
	if upstream.count() != 1 {
		t.Fatalf("upstream request count = %d, want 1 (no retry within one credential)", upstream.count())
	}
}

func TestExecutorExecuteResponseTooLarge(t *testing.T) {
	newUpstreamRecorder(t)
	overrideConfig(t, func(cfg *Config) { cfg.Upstream.MaxResponseBytes = 128 })
	overrideHost(t)

	env := callMethod(t, pluginabi.MethodExecutorExecute, executorRequestJSON(t, testExecutorDoc(), testRequestPayload(), "", nil))
	if env.OK {
		t.Fatal("an oversized aggregated response must fail")
	}
	if env.Error.Code != "response_too_large" {
		t.Fatalf("error = %+v", env.Error)
	}
}

func TestExecutorExecuteInvalidPayload(t *testing.T) {
	upstream := newUpstreamRecorder(t)
	overrideHost(t)

	env := callMethod(t, pluginabi.MethodExecutorExecute, executorRequestJSON(t, testExecutorDoc(), []byte(`not json`), "", nil))
	if env.OK {
		t.Fatal("invalid payload must produce an error envelope")
	}
	if env.Error.Code != "invalid_request" {
		t.Fatalf("error = %+v", env.Error)
	}
	if upstream.count() != 0 {
		t.Fatalf("upstream request count = %d, want 0", upstream.count())
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
