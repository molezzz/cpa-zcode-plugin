package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// hostCaller is the seam between plugin business code and the C ABI bridge.
// Business code must depend on this interface (and the Host/AuthStore/
// StreamSink interfaces below), never on CGO details.
type hostCaller interface {
	// call invokes one host RPC method and returns the raw response envelope.
	call(method string, request []byte) ([]byte, error)
}

// hostCallError carries a coded host-side failure across the adapter boundary.
type hostCallError struct {
	Code       string
	Message    string
	HTTPStatus int
}

func (e *hostCallError) Error() string {
	if e.HTTPStatus > 0 {
		return fmt.Sprintf("host call failed: %s: %s (http %d)", e.Code, e.Message, e.HTTPStatus)
	}
	return fmt.Sprintf("host call failed: %s: %s", e.Code, e.Message)
}

// Host exposes the host capabilities the plugin consumes, isolated from the
// C ABI. Contexts are accepted now for future cancellation wiring; the
// current C bridge carries no cancellation, so calls are uninterruptible.
type Host interface {
	AuthStore() AuthStore
	Streams() StreamSink
}

// AuthStore provides host auth record access. Documents are opaque JSON the
// plugin owns a namespace of; see patchZcodeNamespace for lossless updates.
type AuthStore interface {
	List(ctx context.Context) ([]pluginapi.HostAuthFileEntry, error)
	Get(ctx context.Context, authIndex string) (json.RawMessage, error)
	GetRuntime(ctx context.Context, authIndex string) (pluginapi.HostAuthFileEntry, error)
	Save(ctx context.Context, name string, document json.RawMessage) error
}

// StreamSink forwards streaming chunks to the host for a request stream.
type StreamSink interface {
	Emit(ctx context.Context, streamID string, payload []byte) error
	Close(ctx context.Context, streamID, errorMessage string) error
}

// newRPCHost builds the Host facade over one hostCaller.
func newRPCHost(caller hostCaller) Host {
	return rpcHost{caller: caller}
}

type rpcHost struct {
	caller hostCaller
}

func (h rpcHost) AuthStore() AuthStore { return authStore{rpcHost{caller: h.caller}} }
func (h rpcHost) Streams() StreamSink  { return streamSink{rpcHost{caller: h.caller}} }

// invoke marshals request (nil sends an empty payload), performs the host
// call, decodes the envelope, and returns the result payload.
func (h rpcHost) invoke(method string, request any) (json.RawMessage, error) {
	var raw []byte
	if request != nil {
		encoded, err := json.Marshal(request)
		if err != nil {
			return nil, fmt.Errorf("marshal %s request: %w", method, err)
		}
		raw = encoded
	}
	resp, err := h.caller.call(method, raw)
	if err != nil {
		return nil, fmt.Errorf("host call %s: %w", method, err)
	}
	var env pluginabi.Envelope
	if err := json.NewDecoder(bytes.NewReader(resp)).Decode(&env); err != nil {
		return nil, fmt.Errorf("decode host response for %s: %w", method, err)
	}
	if !env.OK {
		failure := &hostCallError{Code: "host_error", Message: "host call failed"}
		if env.Error != nil {
			failure.Code = env.Error.Code
			failure.Message = env.Error.Message
			failure.HTTPStatus = env.Error.HTTPStatus
		}
		return nil, failure
	}
	return env.Result, nil
}

// requireValue rejects blank identifiers before they cross the host boundary.
func requireValue(value, field string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", fmt.Errorf("%s is required", field)
	}
	return trimmed, nil
}

type authStore struct {
	rpcHost
}

func (s authStore) List(ctx context.Context) ([]pluginapi.HostAuthFileEntry, error) {
	result, err := s.invoke(pluginabi.MethodHostAuthList, nil)
	if err != nil {
		return nil, err
	}
	var response struct {
		Files []pluginapi.HostAuthFileEntry `json:"files"`
	}
	if err := json.Unmarshal(result, &response); err != nil {
		return nil, fmt.Errorf("decode host auth list: %w", err)
	}
	return response.Files, nil
}

func (s authStore) Get(ctx context.Context, authIndex string) (json.RawMessage, error) {
	if _, err := requireValue(authIndex, "auth index"); err != nil {
		return nil, err
	}
	result, err := s.invoke(pluginabi.MethodHostAuthGet, pluginapi.HostAuthGetRequest{AuthIndex: authIndex})
	if err != nil {
		return nil, err
	}
	var response pluginapi.HostAuthGetResponse
	if err := json.Unmarshal(result, &response); err != nil {
		return nil, fmt.Errorf("decode host auth get: %w", err)
	}
	return response.JSON, nil
}

func (s authStore) GetRuntime(ctx context.Context, authIndex string) (pluginapi.HostAuthFileEntry, error) {
	if _, err := requireValue(authIndex, "auth index"); err != nil {
		return pluginapi.HostAuthFileEntry{}, err
	}
	result, err := s.invoke(pluginabi.MethodHostAuthGetRuntime, pluginapi.HostAuthGetRequest{AuthIndex: authIndex})
	if err != nil {
		return pluginapi.HostAuthFileEntry{}, err
	}
	var response pluginapi.HostAuthGetRuntimeResponse
	if err := json.Unmarshal(result, &response); err != nil {
		return pluginapi.HostAuthFileEntry{}, fmt.Errorf("decode host auth get_runtime: %w", err)
	}
	return response.Auth, nil
}

func (s authStore) Save(ctx context.Context, name string, document json.RawMessage) error {
	if !strings.HasSuffix(name, ".json") {
		return fmt.Errorf("auth file name %q must end with .json", name)
	}
	_, err := s.invoke(pluginabi.MethodHostAuthSave, pluginapi.HostAuthSaveRequest{Name: name, JSON: document})
	return err
}

type streamSink struct {
	rpcHost
}

// streamEmitRequest mirrors the host-side RPC schema for stream chunks.
type streamEmitRequest struct {
	StreamID string `json:"stream_id"`
	Payload  []byte `json:"payload,omitempty"`
	Error    string `json:"error,omitempty"`
}

// streamCloseRequest mirrors the host-side RPC schema for stream completion.
type streamCloseRequest struct {
	StreamID string `json:"stream_id"`
	Error    string `json:"error,omitempty"`
}

func (s streamSink) Emit(ctx context.Context, streamID string, payload []byte) error {
	if _, err := requireValue(streamID, "stream id"); err != nil {
		return err
	}
	_, err := s.invoke(pluginabi.MethodHostStreamEmit, streamEmitRequest{StreamID: streamID, Payload: payload})
	return err
}

func (s streamSink) Close(ctx context.Context, streamID, errorMessage string) error {
	if _, err := requireValue(streamID, "stream id"); err != nil {
		return err
	}
	_, err := s.invoke(pluginabi.MethodHostStreamClose, streamCloseRequest{StreamID: streamID, Error: errorMessage})
	return err
}
