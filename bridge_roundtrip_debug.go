//go:build cgobridge_test

package main

/*
#define _GNU_SOURCE
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Test-only driver for the real plugin->host C callback bridge, compiled
// solely under -tags cgobridge_test so production artifacts carry none of
// this. It initializes the plugin against a stub host table (linked through
// the exported cliproxy_plugin_init symbol) and counts every host-side
// allocation/free so the buffer-release contract is verified, not assumed.

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

static const char* bridge_test_response = "{\"ok\":true,\"result\":{\"files\":[]}}";
static int bridge_test_calls = 0;
static int bridge_test_frees = 0;

static int bridge_test_call(void* ctx, const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	(void)ctx; (void)method; (void)request; (void)request_len;
	if (response == NULL) {
		return 1;
	}
	size_t len = strlen(bridge_test_response);
	char* out = malloc(len + 1);
	if (out == NULL) {
		return 1;
	}
	memcpy(out, bridge_test_response, len + 1);
	response->ptr = out;
	response->len = len;
	bridge_test_calls++;
	return 0;
}

static void bridge_test_free(void* ptr, size_t len) {
	(void)len;
	if (ptr != NULL) {
		free(ptr);
	}
	bridge_test_frees++;
}

static cliproxy_host_api bridge_test_host_api(void) {
	cliproxy_host_api host;
	memset(&host, 0, sizeof host);
	host.abi_version = 1;
	host.call = (void*)bridge_test_call;
	host.free_buffer = (void*)bridge_test_free;
	return host;
}

extern int cliproxy_plugin_init(cliproxy_host_api*, cliproxy_plugin_api*);

static int bridge_test_init_plugin(cliproxy_host_api* host) {
	cliproxy_plugin_api plugin;
	memset(&plugin, 0, sizeof plugin);
	return cliproxy_plugin_init(host, &plugin);
}

static int bridge_test_call_count(void) { return bridge_test_calls; }

static int bridge_test_free_count(void) { return bridge_test_frees; }
*/
import "C"

import (
	"context"
	"fmt"
)

// debugBridgeRoundTrip initializes the plugin against the native stub host,
// pushes one auth list call through the real C bridge, and returns the
// observed host callback/free counters.
func debugBridgeRoundTrip() (calls, frees int, err error) {
	cHost := C.bridge_test_host_api()
	if rc := C.bridge_test_init_plugin(&cHost); rc != 0 {
		return 0, 0, fmt.Errorf("cliproxy_plugin_init returned %d", int(rc))
	}
	host := newRPCHost(cgoHostCaller{})
	if _, err := host.AuthStore().List(context.Background()); err != nil {
		return int(C.bridge_test_call_count()), int(C.bridge_test_free_count()), fmt.Errorf("auth list through C bridge: %w", err)
	}
	return int(C.bridge_test_call_count()), int(C.bridge_test_free_count()), nil
}
