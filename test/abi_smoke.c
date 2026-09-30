#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * ABI smoke harness: loads the plugin shared library the same way the CPA
 * host does, initializes it against a stub host callback table, exercises
 * plugin.register / model.static / unknown methods, and releases every
 * response buffer through the plugin's own free function.
 */

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

typedef int (*cliproxy_plugin_init_fn)(const cliproxy_host_api*, cliproxy_plugin_api*);

static const char* canned_host_response = "{\"ok\":true,\"result\":{}}";
static int host_call_invocations = 0;

static int host_call(void* ctx, const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	(void)ctx;
	(void)method;
	(void)request;
	(void)request_len;
	if (response == NULL) {
		return 1;
	}
	size_t len = strlen(canned_host_response);
	char* out = malloc(len + 1);
	if (out == NULL) {
		return 1;
	}
	memcpy(out, canned_host_response, len + 1);
	response->ptr = out;
	response->len = len;
	host_call_invocations++;
	return 0;
}

static int failures = 0;

static void check(int condition, const char* what) {
	if (condition) {
		printf("ok: %s\n", what);
	} else {
		fprintf(stderr, "FAIL: %s\n", what);
		failures++;
	}
}

static int contains(const cliproxy_buffer* buffer, const char* needle) {
	if (buffer == NULL || buffer->ptr == NULL) {
		return 0;
	}
	const char* text = (const char*)buffer->ptr;
	size_t needle_len = strlen(needle);
	if (buffer->len < needle_len) {
		return 0;
	}
	return memmem(text, buffer->len, needle, needle_len) != NULL;
}

int main(int argc, char** argv) {
	if (argc != 2) {
		fprintf(stderr, "usage: %s <plugin library>\n", argv[0]);
		return 2;
	}

	void* handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
	if (handle == NULL) {
		fprintf(stderr, "dlopen failed: %s\n", dlerror());
		return 1;
	}

	void* init_symbol = dlsym(handle, "cliproxy_plugin_init");
	if (init_symbol == NULL) {
		fprintf(stderr, "missing cliproxy_plugin_init: %s\n", dlerror());
		return 1;
	}

	cliproxy_host_api host;
	memset(&host, 0, sizeof host);
	host.abi_version = 1;
	host.call = (void*)host_call;

	cliproxy_plugin_api plugin;
	memset(&plugin, 0, sizeof plugin);
	int rc = ((cliproxy_plugin_init_fn)init_symbol)(&host, &plugin);
	check(rc == 0, "cliproxy_plugin_init returns 0");
	check(plugin.abi_version == 1, "plugin reports abi_version 1");
	check(plugin.call != NULL && plugin.free_buffer != NULL && plugin.shutdown != NULL, "plugin function table complete");

	cliproxy_buffer response;
	memset(&response, 0, sizeof response);

	char register_method[] = "plugin.register";
	const char* register_request = "{}";
	rc = plugin.call(register_method, (uint8_t*)register_request, strlen(register_request), &response);
	check(rc == 0, "plugin.register returns 0");
	check(contains(&response, "\"ok\":true"), "plugin.register envelope is ok");
	check(contains(&response, "\"model_registrar\":true"), "registration declares model_registrar");
	check(contains(&response, "\"model_provider\":true"), "registration declares model_provider");
	check(contains(&response, "\"auth_provider\":true"), "registration declares auth_provider");
	check(contains(&response, "\"executor\":true"), "registration declares executor");
	check(contains(&response, "\"executor_input_formats\":[\"claude\"]"), "registration declares claude input format");
	check(contains(&response, "\"management_api\":true"), "registration declares management_api");
	check(contains(&response, "\"quota_provider\":true"), "registration declares quota_provider");
	plugin.free_buffer(response.ptr, response.len);
	response.ptr = NULL;
	response.len = 0;

	char static_method[] = "model.static";
	rc = plugin.call(static_method, NULL, 0, &response);
	check(rc == 0, "model.static returns 0");
	check(contains(&response, "\"ok\":true"), "model.static envelope is ok");
	check(contains(&response, "GLM-"), "model.static lists static models");
	plugin.free_buffer(response.ptr, response.len);
	response.ptr = NULL;
	response.len = 0;

	char bogus_method[] = "bogus.method";
	rc = plugin.call(bogus_method, NULL, 0, &response);
	check(contains(&response, "\"ok\":false"), "unknown method refused with error envelope");
	check(contains(&response, "unknown_method"), "refusal carries unknown_method code");
	plugin.free_buffer(response.ptr, response.len);
	response.ptr = NULL;
	response.len = 0;

	rc = plugin.call(NULL, NULL, 0, &response);
	check(contains(&response, "invalid_method"), "NULL method reports invalid_method");
	plugin.free_buffer(response.ptr, response.len);
	response.ptr = NULL;
	response.len = 0;

	plugin.shutdown();
	check(1, "plugin.shutdown callable");

	dlclose(handle);
	check(1, "dlclose without crashes");

	if (failures > 0) {
		fprintf(stderr, "%d smoke checks failed\n", failures);
		return 1;
	}
	printf("abi smoke passed\n");
	return 0;
}
