package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// errSSEFrameWithoutData marks a frame that carries no data payload (comments
// and keepalives), which callers treat as "nothing to interpret" rather than
// as an error.
var errSSEFrameWithoutData = errors.New("sse frame has no data payload")

// messageAggregator rebuilds one Anthropic Messages response object from the
// upstream SSE event stream. It is the non-streaming side of the shared
// upstream pump: instead of forwarding frames, it merges message_start,
// content blocks, and message_delta into the single JSON document a
// non-streaming caller expects.
//
// Upstream fields the plugin does not model are preserved from the
// message_start document, so upstream schema additions survive aggregation.
// All numbers are decoded as json.Number to keep their exact text.
type messageAggregator struct {
	limit    int64
	consumed int64

	base       map[string]any
	blocks     map[int]map[string]any
	blockOrder []int
	stopReason any
	stopSeq    any
	usage      map[string]any
	done       bool
}

func newMessageAggregator(limit int64) *messageAggregator {
	return &messageAggregator{limit: limit, blocks: map[int]map[string]any{}}
}

// observe consumes one SSE frame. Frames without data (comments, pings) are
// ignored. A malformed or oversized stream returns an *upstreamFailure.
func (a *messageAggregator) observe(frame []byte) error {
	eventType, data, payload, err := decodeSSEEvent(frame)
	if errors.Is(err, errSSEFrameWithoutData) {
		return nil
	}
	if a.consumed+int64(len(data)) > a.limit {
		return &upstreamFailure{
			Class:        failureTooLarge,
			ClientStatus: http.StatusBadGateway,
			Code:         "response_too_large",
			Message:      "upstream response exceeds the configured size limit",
		}
	}
	a.consumed += int64(len(data))
	if err != nil {
		return &upstreamFailure{
			Class:        failureInterrupted,
			ClientStatus: http.StatusBadGateway,
			Code:         "upstream_stream_invalid",
			Message:      "upstream stream contained a malformed event",
		}
	}
	switch eventType {
	case "message_start":
		if message, ok := payload["message"].(map[string]any); ok {
			a.base = message
			if usage, ok := message["usage"].(map[string]any); ok {
				a.mergeUsage(usage)
			}
		}
	case "content_block_start":
		index := sseIndex(payload["index"])
		if block, ok := payload["content_block"].(map[string]any); ok {
			a.blocks[index] = block
			a.blockOrder = appendOrder(a.blockOrder, index)
		}
	case "content_block_delta":
		index := sseIndex(payload["index"])
		block, ok := a.blocks[index]
		if !ok {
			// A delta without a start is tolerated as a self-describing
			// block so a partial upstream stream still aggregates.
			block = map[string]any{}
			a.blocks[index] = block
			a.blockOrder = appendOrder(a.blockOrder, index)
		}
		delta, ok := payload["delta"].(map[string]any)
		if !ok {
			return nil
		}
		a.applyDelta(block, delta)
	case "message_delta":
		if delta, ok := payload["delta"].(map[string]any); ok {
			if a.stopReason == nil {
				a.stopReason = delta["stop_reason"]
			}
			if a.stopSeq == nil {
				a.stopSeq = delta["stop_sequence"]
			}
		}
		if usage, ok := payload["usage"].(map[string]any); ok {
			a.mergeUsage(usage)
		}
	case "message_stop":
		a.done = true
	case "error":
		return upstreamErrorEvent(payload)
	default:
		// ping and unknown event types carry no aggregated state.
	}
	return nil
}

// decodeSSEEvent splits one frame and decodes its data payload as a JSON
// object, resolving the event type from the payload's own "type" field and
// falling back to the frame's event name. Frames without data fail with
// errSSEFrameWithoutData; a malformed payload fails with the decode error.
// data is returned in both cases, so a caller can still measure the frame.
func decodeSSEEvent(frame []byte) (eventType string, data []byte, payload map[string]any, err error) {
	event, data, ok := parseSSEFrame(frame)
	if !ok {
		return "", nil, nil, errSSEFrameWithoutData
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil {
		return "", data, nil, err
	}
	eventType = sseString(payload["type"])
	if eventType == "" {
		eventType = event
	}
	return eventType, data, payload, nil
}

// frameFailure classifies an upstream SSE frame that reports a failure in
// band. The streaming forwarder consults it before emitting, because a stream
// the upstream itself ends with an error event is not a successful stream and
// must never reach the caller as content. The aggregate reaches the same
// verdict in its own event dispatch, which is where the rest of the stream is
// interpreted.
func frameFailure(frame []byte) error {
	eventType, _, payload, err := decodeSSEEvent(frame)
	if err != nil || eventType != "error" {
		return nil
	}
	return upstreamErrorEvent(payload)
}

// applyDelta merges one content-block delta into its block.
func (a *messageAggregator) applyDelta(block map[string]any, delta map[string]any) {
	textKey := ""
	switch delta["type"] {
	case "text_delta":
		textKey = "text"
	case "thinking_delta":
		textKey = "thinking"
	case "input_json_delta":
		textKey = "partial_json"
	case "signature_delta":
		textKey = "signature"
	default:
		// Unknown delta types carry no state this aggregator can merge.
		return
	}
	_ = appendDeltaField(block, textKey, delta)
}

func appendDeltaField(block map[string]any, key string, delta map[string]any) error {
	chunk, ok := delta[key].(string)
	if !ok {
		return nil
	}
	previous, _ := block[key].(string)
	block[key] = previous + chunk
	return nil
}

func (a *messageAggregator) mergeUsage(usage map[string]any) {
	if a.usage == nil {
		a.usage = map[string]any{}
	}
	for key, value := range usage {
		a.usage[key] = value
	}
}

// finish renders the aggregated Anthropic Messages response document.
func (a *messageAggregator) finish() ([]byte, error) {
	if a.base == nil {
		return nil, &upstreamFailure{
			Class:        failureInterrupted,
			ClientStatus: http.StatusBadGateway,
			Code:         "upstream_stream_invalid",
			Message:      "upstream stream ended without a message",
		}
	}
	result := make(map[string]any, len(a.base)+3)
	for key, value := range a.base {
		result[key] = value
	}
	result["type"] = "message"
	if _, ok := result["role"]; !ok {
		result["role"] = "assistant"
	}
	content := make([]map[string]any, 0, len(a.blockOrder))
	for _, index := range a.blockOrder {
		content = append(content, a.blocks[index])
	}
	result["content"] = content
	if a.stopReason != nil {
		result["stop_reason"] = a.stopReason
	}
	if a.stopSeq != nil {
		result["stop_sequence"] = a.stopSeq
	}
	if a.usage != nil {
		result["usage"] = a.usage
	}
	out, err := json.Marshal(result)
	if err != nil {
		return nil, &upstreamFailure{
			Class:        failureInterrupted,
			ClientStatus: http.StatusBadGateway,
			Code:         "upstream_stream_invalid",
			Message:      "aggregated upstream response could not be encoded",
		}
	}
	return out, nil
}

// upstreamErrorEvent converts an upstream error event into a classified,
// sanitized failure. Overloaded streams are retryable cooldowns; other error
// events keep a bounded, single-line excerpt.
func upstreamErrorEvent(payload map[string]any) *upstreamFailure {
	errObj, _ := payload["error"].(map[string]any)
	errType := sseString(errObj["type"])
	message := sanitizeEventExcerpt(sseString(errObj["message"]))
	switch errType {
	case "overloaded_error":
		return &upstreamFailure{
			Class:                 failureCooldown,
			ClientStatus:          http.StatusBadGateway,
			Code:                  "upstream_overloaded",
			Message:               "upstream is overloaded; retry later",
			RetryableBeforeOutput: true,
		}
	default:
		msg := "upstream reported a stream error"
		if errType != "" {
			msg += " (" + errType + ")"
		}
		if message != "" {
			msg += ": " + message
		}
		return &upstreamFailure{
			Class:        failureUnavailable,
			ClientStatus: http.StatusBadGateway,
			Code:         "upstream_stream_error",
			Message:      msg,
		}
	}
}

// sanitizeEventExcerpt bounds and flattens an upstream-provided message so it
// can appear in a sanitized error envelope.
func sanitizeEventExcerpt(value string) string {
	value = strings.TrimSpace(singleLine(value))
	if value == "" {
		return ""
	}
	return truncateForLog(value, maxSanitizedExcerpt)
}

func sseString(value any) string {
	text, _ := value.(string)
	return strings.TrimSpace(text)
}

func sseIndex(value any) int {
	switch v := value.(type) {
	case float64:
		return int(v)
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return int(n)
		}
	case int:
		return v
	}
	return -1
}

func appendOrder(order []int, index int) []int {
	for _, existing := range order {
		if existing == index {
			return order
		}
	}
	return append(order, index)
}
