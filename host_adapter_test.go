package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
)

// fakeHostCaller records host method calls and returns canned envelopes.
type fakeHostCaller struct {
	calls    []hostCall
	response func(call hostCall) ([]byte, error)
}

type hostCall struct {
	method  string
	request []byte
}

func (f *fakeHostCaller) call(method string, request []byte) ([]byte, error) {
	record := hostCall{method: method, request: append([]byte(nil), request...)}
	f.calls = append(f.calls, record)
	if f.response == nil {
		return okEnvelopeBytes(nil)
	}
	return f.response(record)
}

func okEnvelopeBytes(result json.RawMessage) ([]byte, error) {
	raw, err := json.Marshal(pluginabi.Envelope{OK: true, Result: result})
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func errorEnvelopeBytes(code, message string) ([]byte, error) {
	return json.Marshal(pluginabi.Envelope{OK: false, Error: &pluginabi.Error{Code: code, Message: message}})
}

func newFakeHost(t *testing.T) (*fakeHostCaller, Host) {
	t.Helper()
	fake := &fakeHostCaller{}
	return fake, newRPCHost(fake)
}

func TestAuthStoreList(t *testing.T) {
	fake, host := newFakeHost(t)
	fake.response = func(call hostCall) ([]byte, error) {
		if call.method != pluginabi.MethodHostAuthList {
			t.Errorf("unexpected method %s", call.method)
		}
		return okEnvelopeBytes(json.RawMessage(`{"files":[{"auth_index":"a1","name":"zcode-1.json","type":"zcode"}]}`))
	}
	entries, err := host.AuthStore().List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || entries[0].AuthIndex != "a1" || entries[0].Name != "zcode-1.json" {
		t.Fatalf("entries = %+v", entries)
	}
}

func TestAuthStoreGetReturnsCredentialJSON(t *testing.T) {
	fake, host := newFakeHost(t)
	fake.response = func(call hostCall) ([]byte, error) {
		if string(call.request) != `{"auth_index":"a1"}` {
			t.Errorf("request = %s", call.request)
		}
		return okEnvelopeBytes(json.RawMessage(`{"auth_index":"a1","name":"zcode-1.json","json":{"type":"zcode","zcode":{"jwt":{"token":"s"}}}}`))
	}
	doc, err := host.AuthStore().Get(context.Background(), "a1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !strings.Contains(string(doc), `"token":"s"`) {
		t.Fatalf("doc = %s", doc)
	}
}

func TestAuthStoreGetRuntime(t *testing.T) {
	fake, host := newFakeHost(t)
	fake.response = func(call hostCall) ([]byte, error) {
		return okEnvelopeBytes(json.RawMessage(`{"auth":{"auth_index":"a1","name":"zcode-1.json","status":"active"}}`))
	}
	entry, err := host.AuthStore().GetRuntime(context.Background(), "a1")
	if err != nil {
		t.Fatalf("GetRuntime: %v", err)
	}
	if entry.AuthIndex != "a1" || entry.Status != "active" {
		t.Fatalf("entry = %+v", entry)
	}
}

func TestAuthStoreSaveRequiresJSONSuffix(t *testing.T) {
	_, host := newFakeHost(t)
	err := host.AuthStore().Save(context.Background(), "zcode-1", json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), ".json") {
		t.Fatalf("non-.json name must be rejected, got %v", err)
	}
}

func TestAuthStoreSaveSendsNameAndDoc(t *testing.T) {
	fake, host := newFakeHost(t)
	var gotRequest hostCall
	fake.response = func(call hostCall) ([]byte, error) {
		gotRequest = call
		return okEnvelopeBytes(json.RawMessage(`{"name":"zcode-1.json","path":"/auth/zcode-1.json"}`))
	}
	if err := host.AuthStore().Save(context.Background(), "zcode-1.json", json.RawMessage(`{"zcode":{}}`)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	var sent struct {
		Name string          `json:"name"`
		JSON json.RawMessage `json:"json"`
	}
	if err := json.Unmarshal(gotRequest.request, &sent); err != nil {
		t.Fatalf("decode save request: %v", err)
	}
	if sent.Name != "zcode-1.json" || string(sent.JSON) != `{"zcode":{}}` {
		t.Fatalf("save request = %s", gotRequest.request)
	}
	if gotRequest.method != pluginabi.MethodHostAuthSave {
		t.Fatalf("method = %s", gotRequest.method)
	}
}

func TestAuthStoreErrorsCarryHostCode(t *testing.T) {
	fake, host := newFakeHost(t)
	fake.response = func(call hostCall) ([]byte, error) {
		return errorEnvelopeBytes("auth_not_found", "no such auth")
	}
	if _, err := host.AuthStore().Get(context.Background(), "missing"); err == nil {
		t.Fatal("expected error")
	} else {
		var hostErr *hostCallError
		if !errors.As(err, &hostErr) {
			t.Fatalf("error is %T, want *hostCallError", err)
		}
		if hostErr.Code != "auth_not_found" {
			t.Fatalf("code = %q", hostErr.Code)
		}
	}
}

func TestStreamSinkEmitAndClose(t *testing.T) {
	fake, host := newFakeHost(t)
	var methods []string
	var payloads [][]byte
	fake.response = func(call hostCall) ([]byte, error) {
		methods = append(methods, call.method)
		payloads = append(payloads, append([]byte(nil), call.request...))
		return okEnvelopeBytes(nil)
	}
	sink := host.Streams()
	if err := sink.Emit(context.Background(), "s1", []byte(`{"delta":1}`)); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if err := sink.Close(context.Background(), "s1", ""); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if len(methods) != 2 || methods[0] != pluginabi.MethodHostStreamEmit || methods[1] != pluginabi.MethodHostStreamClose {
		t.Fatalf("methods = %v", methods)
	}
	var emitReq struct {
		StreamID string `json:"stream_id"`
		Payload  []byte `json:"payload"`
	}
	if err := json.Unmarshal(payloads[0], &emitReq); err != nil {
		t.Fatal(err)
	}
	if emitReq.StreamID != "s1" || string(emitReq.Payload) != `{"delta":1}` {
		t.Fatalf("emit request = %s", payloads[0])
	}
}

func TestHostCallerErrorWrapped(t *testing.T) {
	fake, host := newFakeHost(t)
	fake.response = func(call hostCall) ([]byte, error) {
		return nil, errors.New("transport down")
	}
	if _, err := host.AuthStore().List(context.Background()); err == nil {
		t.Fatal("transport failure must surface")
	}
}
