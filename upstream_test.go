package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testProfile builds an immutable profile aimed at an httptest server.
func testProfile(t *testing.T, serverURL string, mutate func(*ResolvedProfile)) ResolvedProfile {
	t.Helper()
	plan := executionPlan(testAuthDoc("jwt-token-1", jwtStatusActive), testConfig(), "GLM-5.2", nil, requestIdentity{}, time.Now())
	if plan.Failure != nil {
		t.Fatalf("executionPlan: %+v", plan.Failure)
	}
	profile := plan.Primary
	profile.MessagesURL = serverURL + "/api/v1/zcode-plan/anthropic/v1/messages"
	if mutate != nil {
		mutate(&profile)
	}
	return profile
}

func TestSSEFrameReaderSplitsFramesVerbatim(t *testing.T) {
	input := "event: message_start\ndata: {\"a\":1}\n\nevent: ping\r\ndata: {}\r\n\r\ndata: tail"
	reader := newSSEFrameReader(strings.NewReader(input), 1<<20)
	want := []string{
		"event: message_start\ndata: {\"a\":1}\n\n",
		"event: ping\r\ndata: {}\r\n\r\n",
		"data: tail",
	}
	for i, expected := range want {
		frame, err := reader.next()
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if string(frame) != expected {
			t.Errorf("frame %d = %q, want %q", i, frame, expected)
		}
	}
	if _, err := reader.next(); !errors.Is(err, io.EOF) {
		t.Fatalf("final next = %v, want io.EOF", err)
	}
}

func TestSSEFrameReaderSkipsStrayBlankLines(t *testing.T) {
	reader := newSSEFrameReader(strings.NewReader("\n\nevent: x\ndata: 1\n\n\n"), 1<<20)
	frame, err := reader.next()
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	if !bytes.Contains(frame, []byte("data: 1")) {
		t.Fatalf("frame = %q", frame)
	}
	if _, err := reader.next(); !errors.Is(err, io.EOF) {
		t.Fatalf("next = %v, want io.EOF", err)
	}
}

func TestSSEFrameReaderRejectsOversizedFrame(t *testing.T) {
	reader := newSSEFrameReader(strings.NewReader("data: "+strings.Repeat("x", 100)+"\n\n"), 32)
	if _, err := reader.next(); !errors.Is(err, sseFrameTooLarge) {
		t.Fatalf("next = %v, want sseFrameTooLarge", err)
	}
}

func TestParseSSEFrame(t *testing.T) {
	event, data, ok := parseSSEFrame([]byte("event: content_block_delta\ndata: {\"i\":1}\n\n"))
	if !ok || event != "content_block_delta" || string(data) != `{"i":1}` {
		t.Fatalf("parse = %q %q %v", event, data, ok)
	}
	// Comment-only frames carry nothing.
	if _, _, ok := parseSSEFrame([]byte(": keepalive\n\n")); ok {
		t.Fatal("comment-only frame must not produce data")
	}
	// Multi-line data joins with newlines.
	_, data, ok = parseSSEFrame([]byte("data: a\ndata: b\n\n"))
	if !ok || string(data) != "a\nb" {
		t.Fatalf("multi-line data = %q %v", data, ok)
	}
}

func TestPumpUpstreamForwardsFramesAndSendsProfileHeaders(t *testing.T) {
	var gotHeaders http.Header
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		fmt.Fprint(w, "event: message_start\ndata: {\"type\":\"message_start\"}\n\n")
		flusher.Flush()
		fmt.Fprint(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	}))
	defer srv.Close()

	var frames [][]byte
	profile := testProfile(t, srv.URL, nil)
	err := pumpUpstream(context.Background(), srv.Client(), profile, []byte(`{"model":"GLM-5.2"}`), func(frame []byte) error {
		frames = append(frames, append([]byte(nil), frame...))
		return nil
	})
	if err != nil {
		t.Fatalf("pumpUpstream: %v", err)
	}
	if len(frames) != 2 {
		t.Fatalf("frames = %d, want 2", len(frames))
	}
	if !bytes.HasPrefix(frames[0], []byte("event: message_start")) {
		t.Fatalf("frame 0 = %q", frames[0])
	}
	if got := gotHeaders.Get("Authorization"); got != "Bearer jwt-token-1" {
		t.Errorf("upstream authorization = %q", got)
	}
	if got := gotHeaders.Get("Accept"); got != "text/event-stream" {
		t.Errorf("upstream accept = %q", got)
	}
	if !strings.Contains(string(gotBody), `"model":"GLM-5.2"`) {
		t.Errorf("upstream body = %s", gotBody)
	}
}

func TestPumpUpstreamClassifiesNon2xx(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		body       string
		wantClass  failureClass
		wantCode   string
		wantClient int
	}{
		{"unauthorized", 401, `{"error":{"message":"bad token"}}`, failureInvalid, "credential_invalid", 401},
		{"forbidden", 403, `{"error":{"message":"forbidden"}}`, failureInvalid, "credential_invalid", 403},
		{"captcha", 403, `{"error":{"message":"captcha verification required"}}`, failureVerificationBlocked, "upstream_verification_required", 403},
		{"verify token", 403, "verify token missing", failureVerificationBlocked, "upstream_verification_required", 403},
		{"payment required with a confirmed quota", 402, `{"error":{"message":"insufficient balance"}}`, failureExhausted, "upstream_quota_exhausted", 402},
		// A 402 is the upstream's own payment conclusion, so the status itself
		// — not a body marker — records the exhausted state.
		{"payment required for another reason", 402, `{"error":{"message":"this account requires a billing profile"}}`, failureExhausted, "upstream_quota_exhausted", 402},
		{"payment required with an empty body", 402, `{}`, failureExhausted, "upstream_quota_exhausted", 402},
		{"verification required", 403, `{"error":{"message":"verification required"}}`, failureVerificationBlocked, "upstream_verification_required", 403},
		{"verify token missing", 403, `{"error":{"message":"verify token missing"}}`, failureVerificationBlocked, "upstream_verification_required", 403},
		{"quota keyword on 400 stays a rejection", 400, `{"error":{"message":"quota insufficient for this request"}}`, failureRejected, "upstream_rejected", 400},
		{"rate limited", 429, `{}`, failureCooldown, "upstream_rate_limited", 429},
		{"server error", 500, `{}`, failureCooldown, "upstream_unavailable", 502},
		{"bad request", 400, `{"error":{"message":"messages: field required"}}`, failureRejected, "upstream_rejected", 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			err := pumpUpstream(context.Background(), srv.Client(), testProfile(t, srv.URL, nil), []byte(`{}`), func([]byte) error { return nil })
			var failure *upstreamFailure
			if !errors.As(err, &failure) {
				t.Fatalf("pumpUpstream = %v, want *upstreamFailure", err)
			}
			if failure.Class != tc.wantClass || failure.Code != tc.wantCode || failure.ClientStatus != tc.wantClient {
				t.Fatalf("failure = %+v, want class %s code %s client %d", failure, tc.wantClass, tc.wantCode, tc.wantClient)
			}
			// Sanitized errors never include the upstream body verbatim.
			if strings.Contains(failure.Message, tc.body) && tc.body != `{}` {
				t.Fatalf("message leaks the upstream body: %q", failure.Message)
			}
		})
	}
}

func TestClassifyUpstreamFailureSanitizesRejectionExcerpt(t *testing.T) {
	body := `{"error":{"message":"messages: field required\nand a very long explanation that should be truncated because it exceeds the configured excerpt length limit for sanitized messages"}}`
	failure := classifyUpstreamFailure(400, []byte(body))
	if failure.Class != failureRejected {
		t.Fatalf("class = %q", failure.Class)
	}
	if !strings.Contains(failure.Message, "messages: field required") {
		t.Fatalf("message lacks the actionable excerpt: %q", failure.Message)
	}
	if strings.Contains(failure.Message, "\n") {
		t.Fatalf("message must be single-line: %q", failure.Message)
	}
	if len(failure.Message) > 300 {
		t.Fatalf("message unbounded: %q", failure.Message)
	}
	// Unparsable bodies stay generic.
	failure = classifyUpstreamFailure(400, []byte("<html>raw body with jwt-token-1</html>"))
	if strings.Contains(failure.Message, "jwt-token-1") || strings.Contains(failure.Message, "<html>") {
		t.Fatalf("message leaks the raw body: %q", failure.Message)
	}
}

func TestPumpUpstreamIdleTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "event: message_start\ndata: {}\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	}))
	defer srv.Close()

	profile := testProfile(t, srv.URL, func(p *ResolvedProfile) { p.IdleReadTimeout = 60 * time.Millisecond })
	start := time.Now()
	err := pumpUpstream(context.Background(), srv.Client(), profile, []byte(`{}`), func([]byte) error { return nil })
	var failure *upstreamFailure
	if !errors.As(err, &failure) {
		t.Fatalf("pumpUpstream = %v, want *upstreamFailure", err)
	}
	if failure.Code != "upstream_stream_stalled" {
		t.Fatalf("code = %q", failure.Code)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("idle watchdog fired too slowly: %v", elapsed)
	}
}

func TestPumpUpstreamContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "event: message_start\ndata: {}\n\n")
		w.(http.Flusher).Flush()
		// Hold the stream open until the client goes away.
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	err := pumpUpstream(ctx, srv.Client(), testProfile(t, srv.URL, nil), []byte(`{}`), func([]byte) error { return nil })
	var failure *upstreamFailure
	if !errors.As(err, &failure) {
		t.Fatalf("pumpUpstream = %v, want *upstreamFailure", err)
	}
	if failure.Code != "request_canceled" {
		t.Fatalf("code = %q, want request_canceled", failure.Code)
	}
}

func TestPumpUpstreamOnFrameErrorAborts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: 1\n\ndata: 2\n\ndata: 3\n\n")
	}))
	defer srv.Close()

	count := 0
	profile := testProfile(t, srv.URL, nil)
	err := pumpUpstream(context.Background(), srv.Client(), profile, []byte(`{}`), func([]byte) error {
		count++
		return errors.New("stop pumping")
	})
	if err == nil {
		t.Fatal("expected the onFrame error to abort the pump")
	}
	if count != 1 {
		t.Fatalf("onFrame called %d times, want 1", count)
	}
}

func TestMessageAggregatorBuildsAnthropicMessage(t *testing.T) {
	frames := []string{
		"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"GLM-5.2\",\"usage\":{\"input_tokens\":21}}}\n\n",
		"event: ping\ndata: {\"type\":\"ping\"}\n\n",
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hel\"}}\n\n",
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"lo\"}}\n\n",
		"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
		"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":7}}\n\n",
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
	}
	agg := newMessageAggregator(1 << 20)
	for _, frame := range frames {
		if err := agg.observe([]byte(frame)); err != nil {
			t.Fatalf("observe: %v", err)
		}
	}
	out, err := agg.finish()
	if err != nil {
		t.Fatalf("finish: %v", err)
	}
	var message map[string]any
	if err := json.Unmarshal(out, &message); err != nil {
		t.Fatalf("decode aggregated message: %v", err)
	}
	if message["id"] != "msg_1" || message["type"] != "message" || message["role"] != "assistant" || message["model"] != "GLM-5.2" {
		t.Fatalf("message head = %v", message)
	}
	content, ok := message["content"].([]any)
	if !ok || len(content) != 1 {
		t.Fatalf("content = %v", message["content"])
	}
	block := content[0].(map[string]any)
	if block["text"] != "Hello" {
		t.Fatalf("aggregated text = %v", block["text"])
	}
	if message["stop_reason"] != "end_turn" {
		t.Fatalf("stop_reason = %v", message["stop_reason"])
	}
	usage := message["usage"].(map[string]any)
	if usage["input_tokens"] != float64(21) || usage["output_tokens"] != float64(7) {
		t.Fatalf("usage = %v", usage)
	}
}

func TestMessageAggregatorMergesBlockKinds(t *testing.T) {
	frames := []string{
		`event: message_start` + "\n" + `data: {"type":"message_start","message":{"id":"m"}}` + "\n\n",
		`event: content_block_start` + "\n" + `data: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}` + "\n\n",
		`event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"think"}}` + "\n\n",
		`event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"sig"}}` + "\n\n",
		`event: content_block_start` + "\n" + `data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"tool_1","name":"calc","input":{}}}` + "\n\n",
		`event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"a\":"}}` + "\n\n",
		`event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"1}"}}` + "\n\n",
	}
	agg := newMessageAggregator(1 << 20)
	for _, frame := range frames {
		if err := agg.observe([]byte(frame)); err != nil {
			t.Fatalf("observe: %v", err)
		}
	}
	out, err := agg.finish()
	if err != nil {
		t.Fatalf("finish: %v", err)
	}
	var message struct {
		Content []map[string]any `json:"content"`
	}
	if err := json.Unmarshal(out, &message); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(message.Content) != 2 {
		t.Fatalf("content = %+v", message.Content)
	}
	if message.Content[0]["thinking"] != "think" || message.Content[0]["signature"] != "sig" {
		t.Fatalf("thinking block = %+v", message.Content[0])
	}
	if message.Content[1]["partial_json"] != `{"a":1}` {
		t.Fatalf("tool block = %+v", message.Content[1])
	}
}

func TestMessageAggregatorFailures(t *testing.T) {
	t.Run("no message start", func(t *testing.T) {
		agg := newMessageAggregator(1 << 20)
		if err := agg.observe([]byte("data: {\"type\":\"message_stop\"}\n\n")); err != nil {
			t.Fatalf("observe: %v", err)
		}
		if _, err := agg.finish(); err == nil {
			t.Fatal("finish must fail without message_start")
		}
	})
	t.Run("malformed event", func(t *testing.T) {
		agg := newMessageAggregator(1 << 20)
		if err := agg.observe([]byte("data: not-json\n\n")); err == nil {
			t.Fatal("malformed event data must fail")
		}
	})
	t.Run("size limit", func(t *testing.T) {
		agg := newMessageAggregator(16)
		err := agg.observe([]byte("data: {\"type\":\"message_start\",\"message\":{\"pad\":\"aaaaaaaaaaaaaaaaaaaaaaaaaa\"}}\n\n"))
		var failure *upstreamFailure
		if !errors.As(err, &failure) || failure.Code != "response_too_large" {
			t.Fatalf("observe = %v, want response_too_large", err)
		}
	})
	t.Run("error event", func(t *testing.T) {
		agg := newMessageAggregator(1 << 20)
		err := agg.observe([]byte("event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"Overloaded\"}}\n\n"))
		var failure *upstreamFailure
		if !errors.As(err, &failure) || failure.Class != failureCooldown {
			t.Fatalf("observe = %v, want cooldown", err)
		}
	})
}

func TestPumpUpstreamSlowTrickleKeepsStreamAlive(t *testing.T) {
	// Lines trickle in slower than the idle window would allow per frame,
	// but each line arrives well inside the window: per-line progress must
	// keep the stream alive until it completes.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		parts := []string{
			"event: message_start\n",
			`data: {"type":"message_start","message":{"id":"m"}}` + "\n",
			"\n",
			"event: message_stop\n",
			`data: {"type":"message_stop"}` + "\n",
			"\n",
		}
		for _, part := range parts {
			fmt.Fprint(w, part)
			flusher.Flush()
			time.Sleep(100 * time.Millisecond)
		}
	}))
	defer srv.Close()

	var frames int
	profile := testProfile(t, srv.URL, func(p *ResolvedProfile) { p.IdleReadTimeout = 150 * time.Millisecond })
	err := pumpUpstream(context.Background(), srv.Client(), profile, []byte(`{}`), func([]byte) error {
		frames++
		return nil
	})
	if err != nil {
		t.Fatalf("pumpUpstream: %v", err)
	}
	if frames != 2 {
		t.Fatalf("frames = %d, want 2", frames)
	}
}

func TestPumpUpstreamClassifiesPlanRoute3012AsRequestRejection(t *testing.T) {
	// The observed upstream answer on the Coding Plan route: HTTP 405 carrying
	// business code 3012. Per the official client's own attribution table the
	// code is a request-level invalid_request; its cause is not established,
	// so the classifier reads only what the answer says and speculates
	// nothing. The 405 carrier is folded to 400 — 405 would tell the caller
	// the method was wrong, which it never was.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = w.Write([]byte(`{"code":3012,"msg":"request has been blocked due to unusual activity.","logid":"log-1"}`))
	}))
	defer srv.Close()
	err := pumpUpstream(context.Background(), srv.Client(), testProfile(t, srv.URL, nil), []byte(`{}`), func([]byte) error { return nil })
	var failure *upstreamFailure
	if !errors.As(err, &failure) {
		t.Fatalf("pumpUpstream = %v, want *upstreamFailure", err)
	}
	if failure.Class != failureRejected {
		t.Fatalf("class = %q, want %q", failure.Class, failureRejected)
	}
	if failure.Code != "upstream_rejected_invalid_request" {
		t.Fatalf("code = %q, want the invalid_request business code", failure.Code)
	}
	if failure.UpstreamStatus != http.StatusMethodNotAllowed {
		t.Fatalf("upstream status = %d, want the carrier preserved for evidence", failure.UpstreamStatus)
	}
	if failure.ClientStatus != http.StatusBadRequest {
		t.Fatalf("client status = %d, want 400: the host answers request faults immediately and must not hold the caller for a cooldown retry", failure.ClientStatus)
	}
	if !failure.RetryableBeforeOutput {
		t.Fatal("a request-level rejection permits another attempt; whether any other route may serve it is the executor's route decision")
	}
	if !strings.Contains(failure.Message, "unusual activity") || !strings.Contains(failure.Message, "3012") {
		t.Fatalf("message = %q, want the bounded upstream msg and the business code", failure.Message)
	}
	if failure.LogID != "log-1" {
		t.Fatalf("logid = %q, want the upstream correlation id as debug evidence", failure.LogID)
	}
	if strings.Contains(strings.ToLower(failure.Message), "challenge") || strings.Contains(strings.ToLower(failure.Message), "trust") {
		t.Fatalf("message = %q, must not claim an unproven challenge diagnosis", failure.Message)
	}
}

func TestPumpUpstreamKeepsKeyRoute3012AsRejection(t *testing.T) {
	// The same answer on the managed-key route is the same request-level
	// rejection: the business code table is not route-specific.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = w.Write([]byte(`{"code":3012,"msg":"blocked","logid":"log-1"}`))
	}))
	defer srv.Close()
	profile := testProfile(t, srv.URL, func(p *ResolvedProfile) {
		p.CredentialKind = CredentialAPIKey
		p.MessagesURL = srv.URL + "/api/anthropic/v1/messages"
		p.Route = resolveRoute(CredentialAPIKey)
		p.Route.URL = p.MessagesURL
	})
	err := pumpUpstream(context.Background(), srv.Client(), profile, []byte(`{}`), func([]byte) error { return nil })
	var failure *upstreamFailure
	if !errors.As(err, &failure) {
		t.Fatalf("pumpUpstream = %v, want *upstreamFailure", err)
	}
	if failure.Class != failureRejected || !failure.RetryableBeforeOutput {
		t.Fatalf("failure = %+v, want a retryable request-level rejection", failure)
	}
}

func TestPumpUpstreamDoesNotReclassifyOtherBusinessCodes(t *testing.T) {
	// Every other request-level code keeps the same ordinary rejection
	// semantics; 3012 is not special-cased anywhere.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = w.Write([]byte(`{"code":3001,"msg":"parameter error","logid":"log-1"}`))
	}))
	defer srv.Close()
	err := pumpUpstream(context.Background(), srv.Client(), testProfile(t, srv.URL, nil), []byte(`{}`), func([]byte) error { return nil })
	var failure *upstreamFailure
	if !errors.As(err, &failure) {
		t.Fatalf("pumpUpstream = %v, want *upstreamFailure", err)
	}
	if failure.Class != failureRejected {
		t.Fatalf("class = %q, want %q", failure.Class, failureRejected)
	}
}

func TestPumpUpstream3012OnAnotherCarrierKeepsTheRealStatus(t *testing.T) {
	// 405 is only one observed carrier; the same code on a real 4xx keeps
	// that status for the caller.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":3012,"msg":"blocked","logid":"log-1"}`))
	}))
	defer srv.Close()
	err := pumpUpstream(context.Background(), srv.Client(), testProfile(t, srv.URL, nil), []byte(`{}`), func([]byte) error { return nil })
	var failure *upstreamFailure
	if !errors.As(err, &failure) {
		t.Fatalf("pumpUpstream = %v, want *upstreamFailure", err)
	}
	if failure.Class != failureRejected || failure.ClientStatus != http.StatusBadRequest {
		t.Fatalf("failure = %+v, want a rejection with the upstream's own 400", failure)
	}
}
