package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	void* call;
	void* free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

static const cliproxy_host_api* stored_host;

static void store_host_api(const cliproxy_host_api* host) {
	stored_host = host;
}

static int call_host_api(const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	if (stored_host == NULL || stored_host->call == NULL) {
		return 1;
	}
	return ((int (*)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*))stored_host->call)(stored_host->host_ctx, method, request, request_len, response);
}

static void free_host_buffer(void* ptr, size_t len) {
	if (stored_host != NULL && stored_host->free_buffer != NULL && ptr != NULL) {
		((void (*)(void*, size_t))stored_host->free_buffer)(ptr, len);
	}
}

extern int cliproxy_plugin_init(cliproxy_host_api*, cliproxy_plugin_api*);
extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);
*/
import "C"

import (
	"errors"
	"fmt"
	"net/http"
	"unsafe"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
)

// cliproxy_plugin_init is the single entry point the CPA host resolves after
// dlopen. It stores the host callback table and fills the plugin function
// table. Only this file and the hostCaller below may touch C types.
//
//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if plugin == nil {
		return 1
	}
	if host == nil || host.call == nil {
		return 1
	}
	C.store_host_api(host)
	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

// cliproxyPluginCall dispatches one host RPC method. Return code 0 means the
// response buffer carries a decodable envelope; code 1 means either no
// envelope could be produced or the envelope is a plugin error. The response
// buffer is allocated here and must be released through cliproxyPluginFree
// (the host calls it with the plugin's own free_buffer pointer).
//
//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writeResponse(response, errorEnvelope("invalid_method", "method is required", http.StatusBadRequest))
		return 1
	}
	if requestLen > C.size_t(int(^uint(0)>>1)) {
		writeResponse(response, errorEnvelope("invalid_request", "request too large", http.StatusBadRequest))
		return 1
	}

	var requestBytes []byte
	if request != nil && requestLen > 0 {
		requestBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}

	raw, err := invokeWithRecover(C.GoString(method), requestBytes)
	if err != nil {
		writeResponse(response, errorEnvelope("plugin_error", truncateForLog(err.Error(), 512), http.StatusInternalServerError))
		return 1
	}
	writeResponse(response, raw)
	return 0
}

// invokeWithRecover guarantees no Go panic crosses the C ABI boundary.
func invokeWithRecover(method string, request []byte) (raw []byte, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			raw = nil
			err = fmt.Errorf("plugin panic in %s: %v", method, recovered)
		}
	}()
	return handleMethod(method, request)
}

// cliproxyPluginFree releases response buffers this plugin allocated.
//
//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, _ C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
}

// cliproxyPluginShutdown is the native unload hook.
//
//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {
	runShutdown()
}

func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}

// cgoHostCaller is the only hostCaller implementation that talks to the C
// ABI. Everything above it uses the hostAdapter interfaces.
type cgoHostCaller struct{}

func (cgoHostCaller) call(method string, request []byte) ([]byte, error) {
	cMethod := C.CString(method)
	defer C.free(unsafe.Pointer(cMethod))

	var cRequest *C.uint8_t
	if len(request) > 0 {
		cRequest = (*C.uint8_t)(unsafe.Pointer(&request[0]))
	}

	var response C.cliproxy_buffer
	rc := C.call_host_api(cMethod, cRequest, C.size_t(len(request)), &response)

	var out []byte
	if response.ptr != nil && response.len > 0 {
		out = C.GoBytes(response.ptr, C.int(response.len))
	}
	if response.ptr != nil {
		C.free_host_buffer(response.ptr, response.len)
	}
	if rc != 0 && len(out) == 0 {
		return nil, fmt.Errorf("host call %s returned status %d", method, int(rc))
	}
	if rc != 0 {
		// The host may signal failure with a coded error envelope; let the
		// caller's envelope decoder surface it.
		return out, nil
	}
	if len(out) == 0 {
		return nil, errors.New("host call " + method + " returned an empty response")
	}
	return out, nil
}

// pluginHost is the Host facade handed to business code. The host callback
// table lives in the C static `stored_host`, populated by cliproxy_plugin_init,
// so the facade needs no additional state; calls before init fail per-call.
func pluginHost() Host {
	return rpcHost{caller: cgoHostCaller{}}
}
