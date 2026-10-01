package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// maxUpstreamErrorBodyBytes bounds how much of a non-2xx upstream body is read
// for classification. Only classified excerpts may survive into error
// messages; the raw body never does.
const maxUpstreamErrorBodyBytes = 64 << 10

// maxSanitizedExcerpt bounds an extracted upstream error message before it may
// appear in a sanitized error envelope.
const maxSanitizedExcerpt = 200

// sseFrameTooLarge reports an upstream frame beyond the configured read limit.
var sseFrameTooLarge = errors.New("upstream stream frame exceeds the response size limit")

// sseFrameReader splits an upstream SSE body into frames verbatim, including
// each frame's terminating blank line. Frames are separated by a blank line
// ("\n\n" or "\r\n\r\n"); a trailing partial frame at EOF is returned as a
// final frame. Every line and every frame is bounded by limit, so a hostile
// or malformed upstream cannot grow memory without bound.
type sseFrameReader struct {
	reader *bufio.Reader
	limit  int64
	buf    bytes.Buffer
	// onProgress, when set, runs after every successful line read so the
	// caller's idle watchdog sees progress inside long frames.
	onProgress func()
}

func newSSEFrameReader(reader io.Reader, limit int64) *sseFrameReader {
	return &sseFrameReader{reader: bufio.NewReader(reader), limit: limit}
}

// next returns the next complete frame. io.EOF signals a clean stream end.
func (r *sseFrameReader) next() ([]byte, error) {
	r.buf.Reset()
	sawContent := false
	for {
		line, err := r.reader.ReadBytes('\n')
		if len(line) > 0 {
			if r.onProgress != nil {
				r.onProgress()
			}
			if int64(len(line)) > r.limit || int64(r.buf.Len())+int64(len(line)) > r.limit {
				return nil, sseFrameTooLarge
			}
			r.buf.Write(line)
			if !isBlankSSELine(line) {
				sawContent = true
			}
		}
		if errors.Is(err, io.EOF) {
			if !sawContent {
				return nil, io.EOF
			}
			frame := make([]byte, r.buf.Len())
			copy(frame, r.buf.Bytes())
			return frame, nil
		}
		if err != nil {
			return nil, err
		}
		if isBlankSSELine(line) {
			if !sawContent {
				// A stray blank line between frames terminates an empty
				// event; skip it instead of forwarding an empty frame.
				r.buf.Reset()
				continue
			}
			frame := make([]byte, r.buf.Len())
			copy(frame, r.buf.Bytes())
			return frame, nil
		}
	}
}

func isBlankSSELine(line []byte) bool {
	switch len(line) {
	case 1:
		return line[0] == '\n'
	case 2:
		return line[0] == '\r' && line[1] == '\n'
	default:
		return false
	}
}

// parseSSEFrame extracts the event name and joined data payload of one SSE
// frame. ok is false for frames without data (comments and keepalives), which
// carry nothing to aggregate.
func parseSSEFrame(frame []byte) (event string, data []byte, ok bool) {
	var dataBuf bytes.Buffer
	for _, rawLine := range bytes.Split(frame, []byte("\n")) {
		line := strings.TrimSuffix(string(rawLine), "\r")
		switch {
		case strings.HasPrefix(line, "event:"):
			if event == "" {
				event = strings.TrimSpace(line[len("event:"):])
			}
		case strings.HasPrefix(line, "data:"):
			value := strings.TrimPrefix(line[len("data:"):], " ")
			if dataBuf.Len() > 0 {
				dataBuf.WriteByte('\n')
			}
			dataBuf.WriteString(value)
		}
	}
	if dataBuf.Len() == 0 {
		return event, nil, false
	}
	return event, dataBuf.Bytes(), true
}

// failureClass is the observable classification of an upstream attempt
// failure. Classes map onto the credential state machine and onto the
// sanitized message the caller receives.
type failureClass string

const (
	failureVerificationBlocked failureClass = "verification_blocked"
	failureInvalid             failureClass = "invalid"
	failureExhausted           failureClass = "exhausted"
	failurePlanExpired         failureClass = "plan_expired"
	failureCooldown            failureClass = "cooldown"
	failureRejected            failureClass = "upstream_rejected"
	failureUnavailable         failureClass = "upstream_unavailable"
	failureInterrupted         failureClass = "stream_interrupted"
	failureTooLarge            failureClass = "response_too_large"
)

// upstreamFailure is a sanitized upstream outcome. Message is bounded and
// free of credentials, upstream bodies, URLs, and prompt content.
type upstreamFailure struct {
	Class          failureClass
	UpstreamStatus int
	ClientStatus   int
	Code           string
	Message        string
	// LogID is the upstream's own request correlation id ("logid" in a Z.AI
	// business envelope), when the answer carried one. It is display-only
	// evidence for debug lines — what ties a plugin attempt to an upstream
	// log entry — and never enters a caller-facing envelope.
	LogID string
	// RetryableBeforeOutput reports whether this classification permits
	// another attempt before anything was output. It says nothing about which
	// credential or route may serve the retry: the executor's route
	// compatibility rule (fallbackAllowed) owns that decision, because a
	// retry that crosses a billing/entitlement boundary spends resources the
	// failed route was never allowed to spend.
	RetryableBeforeOutput bool
}

func (f *upstreamFailure) Error() string { return f.Message }

// captchaMarkers are the observed upstream body markers for verification
// rejections. The upstream signals verification requirements inside the
// response body rather than only in the status code. Each marker is checked
// for a specific way the upstream asks for verification, so a 403 whose body
// merely mentions an unrelated kind of "check" is still classified as a
// credential rejection rather than as verification blocked.
var captchaMarkers = []string{
	"captcha",
	"verify token",
	"verify failed",
	"verification required",
	"verification failed",
	"needs verification",
	"requires verification",
	"risk control",
}

// exhaustion is concluded from the 402 status itself, not from body markers:
// the credential state machine spells the 402 payment requirement as the
// quota-exhausted verdict, so any 402 records it. Exhaustion recovers through
// a quota refresh rather than through time or a retry.

func containsMarker(body string, markers []string) bool {
	lower := strings.ToLower(body)
	for _, marker := range markers {
		if strings.Contains(lower, strings.ToLower(marker)) {
			return true
		}
	}
	return false
}

// credentialRejectionClass reports the failure class one upstream status
// implies about the credential itself, as opposed to the request or the
// transport. Any 401/403 rejects the credential, and the 402 status itself is
// the payment verdict. Everything else — rate limits, 5xx, request problems —
// says nothing about the credential, so ok is false. Every caller that maps an
// upstream rejection onto a credential conclusion shares this one ruleset, so
// the Messages executor and the billing checks cannot drift apart.
//
// A captcha-bearing 403 is not handled here: classifyUpstreamFailure settles
// the verification requirement before it consults this, because that conclusion
// takes precedence over whatever status or business code accompanies it.
func credentialRejectionClass(status int, bodyText string) (failureClass, bool) {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return failureInvalid, true
	case status == http.StatusPaymentRequired:
		return failureExhausted, true
	default:
		return "", false
	}
}

// classifyUpstreamFailure turns a non-2xx upstream response into a sanitized,
// classified failure. The answer is read in a fixed precedence, each step
// because the one below it would otherwise misread it:
//
//  1. A captcha/verify requirement in the body. The upstream signals
//     verification from the body, and it is the one conclusion that is always
//     about this credential — a verification block must never be re-read as
//     whatever business code happens to ride along with it, because that
//     would trade a five-minute automatic retry for a permanent conclusion.
//  2. The Z.AI business verdict. The upstream reuses HTTP statuses as carriers
//     for business outcomes — 405 has been observed carrying a request-level
//     business rejection — so a recognised code describes the rejection better
//     than its status does. The classifier reads only what the answer says
//     (status, code, bounded msg); it never speculates an unproven server-side
//     cause such as a client-integrity challenge.
//  3. HTTP semantics, for an answer that carries neither.
func classifyUpstreamFailure(status int, body []byte) *upstreamFailure {
	bodyText := string(body)
	if status == http.StatusForbidden && containsMarker(bodyText, captchaMarkers) {
		// A verification requirement is a definitive conclusion about this
		// credential, so the request moves on to the fallback credential
		// instead of repeating the primary.
		return &upstreamFailure{
			Class:                 failureVerificationBlocked,
			UpstreamStatus:        status,
			ClientStatus:          http.StatusForbidden,
			Code:                  "upstream_verification_required",
			Message:               "upstream verification is required before the Coding Plan credential can be used; no verification is automated",
			RetryableBeforeOutput: true,
		}
	}
	if failure := classifyBusinessFailure(status, body); failure != nil {
		return failure
	}
	if class, rejected := credentialRejectionClass(status, bodyText); rejected {
		switch class {
		case failureVerificationBlocked:
			// A verification requirement is a definitive conclusion about this
			// credential, so the request moves on to the fallback credential
			// instead of repeating the primary.
			return &upstreamFailure{
				Class:                 failureVerificationBlocked,
				UpstreamStatus:        status,
				ClientStatus:          http.StatusForbidden,
				Code:                  "upstream_verification_required",
				Message:               "upstream verification is required before the Coding Plan credential can be used; no verification is automated",
				RetryableBeforeOutput: true,
			}
		case failureInvalid:
			return &upstreamFailure{
				Class:                 failureInvalid,
				UpstreamStatus:        status,
				ClientStatus:          status,
				Code:                  "credential_invalid",
				Message:               "upstream rejected the credential; refresh it or complete the ZCode login again",
				RetryableBeforeOutput: true,
			}
		case failureExhausted:
			// A 402 is the upstream's own payment conclusion, so the credential
			// is recorded as exhausted regardless of what the body says: the
			// state machine spells the status itself as the quota verdict, and
			// the fallback key takes over the request.
			return &upstreamFailure{
				Class:                 failureExhausted,
				UpstreamStatus:        status,
				ClientStatus:          http.StatusPaymentRequired,
				Code:                  "upstream_quota_exhausted",
				Message:               "upstream quota is exhausted for this credential; refresh the quota to restore it",
				RetryableBeforeOutput: true,
			}
		}
	}
	switch {
	case status == http.StatusTooManyRequests:
		return &upstreamFailure{
			Class:                 failureCooldown,
			UpstreamStatus:        status,
			ClientStatus:          status,
			Code:                  "upstream_rate_limited",
			Message:               "upstream rate limit reached; retry later",
			RetryableBeforeOutput: true,
		}
	case status >= 500:
		return &upstreamFailure{
			Class:                 failureCooldown,
			UpstreamStatus:        status,
			ClientStatus:          http.StatusBadGateway,
			Code:                  "upstream_unavailable",
			Message:               "upstream is temporarily unavailable",
			RetryableBeforeOutput: true,
		}
	default:
		return &upstreamFailure{
			Class:          failureRejected,
			UpstreamStatus: status,
			ClientStatus:   status,
			Code:           "upstream_rejected",
			Message:        sanitizedRejectionMessage(status, body),
		}
	}
}

// classifyBusinessFailure classifies one upstream answer from the Z.AI business
// verdict it carries. It returns nil when the answer carries no recognised
// verdict, which leaves the caller on HTTP semantics.
//
// The two halves of the result are deliberately separate. The failure class
// says whether the answer is a statement about the credential, and therefore
// whether the state machine may move a credential; RetryableBeforeOutput says
// whether another attempt may serve this request before anything reached the
// caller — not which route may serve it. A request-level rejection such as
// 3012 concludes nothing about the credential, so it records no state; whether
// the request may be replayed across the billing-domain boundary is the
// executor's route compatibility decision, and by default it is not.
func classifyBusinessFailure(status int, body []byte) *upstreamFailure {
	semantics, code, ok := zaiBusinessSemanticsFor(body)
	if !ok {
		return nil
	}
	class, credentialVerdict := failureClassForSemantics(semantics)
	if !credentialVerdict {
		return &upstreamFailure{
			Class:          failureRejected,
			UpstreamStatus: status,
			ClientStatus:   clientStatusForSemantics(semantics, status),
			Code:           "upstream_rejected_" + string(semantics),
			Message:        businessRejectionMessage(semantics, code, body),
			LogID:          zaiBusinessLogID(body),
			// A rejection about the request rather than the credential permits
			// another attempt; the executor's route compatibility rule decides
			// whether any other route may serve it.
			RetryableBeforeOutput: true,
		}
	}
	return &upstreamFailure{
		Class:                 class,
		UpstreamStatus:        status,
		ClientStatus:          clientStatusForSemantics(semantics, status),
		Code:                  "upstream_" + string(semantics),
		Message:               businessRejectionMessage(semantics, code, body),
		LogID:                 zaiBusinessLogID(body),
		RetryableBeforeOutput: true,
	}
}

// businessRejectionMessage renders the sanitized message for a business
// verdict, preferring the upstream's own explanation so an operator can see
// what the upstream actually said, and naming the code so two rejections of
// the same class stay distinguishable. The message is bounded and reduced to
// a single line; no body content beyond that excerpt can reach the caller.
func businessRejectionMessage(semantics zaiBusinessSemantics, code zaiBusinessCode, body []byte) string {
	lead := businessVerdictPhrase(semantics)
	if excerpt := zaiBusinessMessage(body); excerpt != "" {
		return lead + ": " + excerpt + " (upstream code " + normalizeZaiBusinessCode(string(code)) + ")"
	}
	return lead + " (upstream code " + normalizeZaiBusinessCode(string(code)) + ")"
}

// businessVerdictPhrase is the plugin's own one-line reading of each business
// meaning. It says what the plugin concluded, so the operator is not left
// reading only the upstream's prose.
func businessVerdictPhrase(semantics zaiBusinessSemantics) string {
	switch semantics {
	case zaiSemQuotaExhausted:
		return "upstream reports no remaining quota for this credential"
	case zaiSemPlanExpired:
		return "upstream reports the Coding Plan subscription has expired"
	case zaiSemPlanAccessDenied:
		return "upstream denies this plan access to the requested model"
	case zaiSemAuthFailed:
		return "upstream rejected the credential"
	case zaiSemRateLimited:
		return "upstream rate limit reached; retry later"
	case zaiSemProviderOverloaded:
		return "upstream is at capacity; retry later"
	case zaiSemUpstreamError:
		return "upstream reported an internal error; retry later"
	case zaiSemRequestRejected:
		return "upstream rejected the request"
	default:
		return "upstream rejected the request"
	}
}

// sanitizedRejectionMessage builds the message for plain request rejections
// (typically 4xx schema errors). It extracts only a bounded, single-line
// message field from a JSON error body; unparsable bodies stay generic so
// raw upstream content can never reach the caller.
func sanitizedRejectionMessage(status int, body []byte) string {
	base := fmt.Sprintf("upstream rejected the request (http %d)", status)
	var parsed struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(body), &parsed); err != nil {
		return base
	}
	excerpt := parsed.Error.Message
	if strings.TrimSpace(excerpt) == "" {
		excerpt = parsed.Message
	}
	// Z.AI spells its explanation "msg" at the top level rather than "message"
	// or under "error"; without this the upstream's only description of a
	// rejection is discarded and the caller sees the bare status.
	if strings.TrimSpace(excerpt) == "" {
		excerpt = zaiBusinessMessage(body)
	}
	excerpt = strings.TrimSpace(singleLine(excerpt))
	if excerpt == "" {
		return base
	}
	return base + ": " + truncateForLog(excerpt, maxSanitizedExcerpt)
}

func singleLine(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

// transportFailure classifies connection and read failures. Cancellation is
// reported distinctly so it is never mistaken for an upstream problem.
func transportFailure(err error) *upstreamFailure {
	if errors.Is(err, context.Canceled) {
		return &upstreamFailure{
			Class:        failureInterrupted,
			ClientStatus: http.StatusBadGateway,
			Code:         "request_canceled",
			Message:      "request canceled",
		}
	}
	if errors.Is(err, sseFrameTooLarge) {
		return &upstreamFailure{
			Class:        failureTooLarge,
			ClientStatus: http.StatusBadGateway,
			Code:         "response_too_large",
			Message:      "upstream response exceeds the configured size limit",
		}
	}
	return &upstreamFailure{
		Class:                 failureCooldown,
		ClientStatus:          http.StatusBadGateway,
		Code:                  "upstream_unreachable",
		Message:               "upstream is unreachable or the stream ended unexpectedly",
		RetryableBeforeOutput: true,
	}
}

// upstreamClient builds the HTTP client one execution attempt uses. Limits
// come from the immutable profile; streaming bodies are never bounded by a
// total timeout, only by the idle-read watchdog and caller cancellation.
func upstreamClient(profile ResolvedProfile) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: profile.ConnectTimeout}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   profile.ConnectTimeout,
			ResponseHeaderTimeout: profile.HeaderTimeout,
		},
	}
}

// pumpUpstream performs one upstream attempt: it posts the payload as an SSE
// request and forwards every response frame to onFrame. Non-2xx responses
// become classified failures. The returned error is either nil, an
// *upstreamFailure, or a raw transport error for attemptProfile to classify;
// onFrame may abort the pump by returning any error.
func pumpUpstream(ctx context.Context, client *http.Client, profile ResolvedProfile, payload []byte, onFrame func(frame []byte) error) error {
	// The pump context is bound to the request so the idle watchdog and the
	// caller's cancellation both interrupt in-flight body reads.
	pumpCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(pumpCtx, http.MethodPost, profile.MessagesURL, bytes.NewReader(payload))
	if err != nil {
		return &upstreamFailure{
			Class:        failureRejected,
			ClientStatus: http.StatusInternalServerError,
			Code:         "invalid_request",
			Message:      "upstream request could not be built",
		}
	}
	for name, values := range profile.Headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return transportFailure(err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, readErr := readLimited(resp.Body, min(profile.MaxResponseBytes, maxUpstreamErrorBodyBytes))
		drainAndClose(resp.Body)
		if readErr != nil {
			return transportFailure(readErr)
		}
		return classifyUpstreamFailure(resp.StatusCode, body)
	}

	// Idle watchdog: cancel the pump context when the upstream stops
	// producing bytes for longer than the configured idle window.
	var lastReadNano atomic.Int64
	lastReadNano.Store(time.Now().UnixNano())
	var watchdogFired atomic.Bool
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		tick := profile.IdleReadTimeout / 4
		if tick > 250*time.Millisecond {
			tick = 250 * time.Millisecond
		}
		if tick < 10*time.Millisecond {
			tick = 10 * time.Millisecond
		}
		ticker := time.NewTicker(tick)
		defer ticker.Stop()
		for {
			select {
			case <-pumpCtx.Done():
				return
			case <-ticker.C:
				last := time.Since(time.Unix(0, lastReadNano.Load()))
				if last > profile.IdleReadTimeout {
					watchdogFired.Store(true)
					cancel()
					return
				}
			}
		}
	}()

	reader := newSSEFrameReader(resp.Body, profile.MaxResponseBytes)
	// Refresh the idle clock per line, not per frame: a slow, healthy
	// trickle inside one long frame must not trip the watchdog.
	reader.onProgress = func() { lastReadNano.Store(time.Now().UnixNano()) }
	var pumpErr error
	for {
		frame, err := reader.next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			pumpErr = err
			break
		}
		if err := onFrame(frame); err != nil {
			pumpErr = err
			break
		}
	}
	// Stop the watchdog, then wait for it to observe the cancel, so the
	// response body and context are released without a use-after-cancel
	// race on the connection.
	cancel()
	<-watchDone
	drainAndClose(resp.Body)
	if pumpErr != nil {
		var hostErr hostStreamError
		if errors.As(pumpErr, &hostErr) {
			// Forwarder aborts (host stream failures) are never upstream
			// problems; the executor classifies them.
			return pumpErr
		}
		if watchdogFired.Load() && ctx.Err() == nil {
			// The watchdog canceled the pump: the upstream stalled
			// mid-stream while the caller was still waiting.
			return stalledFailure()
		}
		var failure *upstreamFailure
		if errors.As(pumpErr, &failure) {
			return failure
		}
		return transportFailure(pumpErr)
	}
	return nil
}

// stalledFailure classifies an idle-watchdog shutdown of the stream.
func stalledFailure() *upstreamFailure {
	return &upstreamFailure{
		Class:                 failureCooldown,
		ClientStatus:          http.StatusBadGateway,
		Code:                  "upstream_stream_stalled",
		Message:               "upstream stream stalled and timed out",
		RetryableBeforeOutput: true,
	}
}
