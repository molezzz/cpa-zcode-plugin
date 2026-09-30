package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func decodeEnvelope(t *testing.T, raw []byte) pluginabi.Envelope {
	t.Helper()
	var env pluginabi.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	return env
}

func callMethod(t *testing.T, method string, request []byte) pluginabi.Envelope {
	t.Helper()
	raw, err := handleMethod(method, request)
	if err != nil {
		t.Fatalf("handleMethod(%q) returned Go error: %v", method, err)
	}
	return decodeEnvelope(t, raw)
}

func TestRegisterReturnsImplementedCapabilitiesOnly(t *testing.T) {
	env := callMethod(t, pluginabi.MethodPluginRegister, nil)
	if !env.OK {
		t.Fatalf("register failed: %+v", env.Error)
	}

	var reg registration
	if err := json.Unmarshal(env.Result, &reg); err != nil {
		t.Fatalf("decode registration: %v", err)
	}
	if reg.SchemaVersion != pluginabi.SchemaVersion {
		t.Fatalf("schema_version = %d, want %d", reg.SchemaVersion, pluginabi.SchemaVersion)
	}
	if reg.Metadata.Name != "ZCode" || reg.Metadata.Version == "" {
		t.Fatalf("unexpected metadata: %+v", reg.Metadata)
	}
	caps := reg.Capabilities
	if !caps.ModelRegistrar || !caps.ModelProvider {
		t.Fatalf("implemented capabilities missing: %+v", caps)
	}
	for name, value := range map[string]bool{
		"auth_provider":          caps.AuthProvider,
		"executor":               caps.Executor,
		"model_router":           caps.ModelRouter,
		"scheduler":              caps.Scheduler,
		"management_api":         caps.ManagementAPI,
		"quota_provider":         caps.QuotaProvider,
		"frontend_auth_provider": caps.FrontendAuthProvider,
		"request_translator":     caps.RequestTranslator,
		"response_translator":    caps.ResponseTranslator,
		"usage_plugin":           caps.UsagePlugin,
		"command_line_plugin":    caps.CommandLinePlugin,
		"websocket_response_obs": caps.WebSocketResponseObserver,
	} {
		if value {
			t.Errorf("capability %s declared but not implemented", name)
		}
	}
}

func TestReconfigureUpdatesSnapshotAndReturnsRegistration(t *testing.T) {
	t.Cleanup(func() { activeConfig.Store(defaultConfig()) })
	request, err := json.Marshal(lifecycleRequest{ConfigYAML: []byte("models:\n  - GLM-5.2\n")})
	if err != nil {
		t.Fatal(err)
	}
	env := callMethod(t, pluginabi.MethodPluginReconfigure, request)
	if !env.OK {
		t.Fatalf("reconfigure failed: %+v", env.Error)
	}
	got := currentConfig()
	if len(got.Models) != 1 || got.Models[0] != "GLM-5.2" {
		t.Fatalf("config snapshot not applied: %+v", got.Models)
	}
}

func TestReconfigureRejectsInvalidYAML(t *testing.T) {
	env := callMethod(t, pluginabi.MethodPluginReconfigure, []byte(`{"config_yaml":"models: [unterminated"}`))
	if env.OK {
		t.Fatal("invalid YAML must not be accepted")
	}
	if env.Error == nil || env.Error.Code == "" {
		t.Fatalf("expected coded error, got %+v", env.Error)
	}
}

func TestModelMethodsReturnStaticCatalog(t *testing.T) {
	for _, method := range []string{pluginabi.MethodModelRegister, pluginabi.MethodModelStatic, pluginabi.MethodModelForAuth} {
		env := callMethod(t, method, nil)
		if !env.OK {
			t.Fatalf("%s failed: %+v", method, env.Error)
		}
		var response struct {
			Provider string                `json:"Provider"`
			Models   []pluginapi.ModelInfo `json:"Models"`
		}
		if err := json.Unmarshal(env.Result, &response); err != nil {
			t.Fatalf("decode %s result: %v", method, err)
		}
		if response.Provider != "zcode" {
			t.Fatalf("%s provider = %q, want zcode", method, response.Provider)
		}
		if len(response.Models) == 0 {
			t.Fatalf("%s returned no models", method)
		}
	}
}

func TestUnimplementedCapabilityMethodsAreUnknown(t *testing.T) {
	// 契约：未声明的能力对应的方法绝不路由到任何实现。
	for _, method := range []string{
		pluginabi.MethodExecutorExecute,
		pluginabi.MethodExecutorExecuteStream,
		pluginabi.MethodExecutorIdentifier,
		pluginabi.MethodAuthIdentifier,
		pluginabi.MethodAuthLoginStart,
		pluginabi.MethodAuthLoginPoll,
		pluginabi.MethodAuthRefresh,
		pluginabi.MethodManagementRegister,
		pluginabi.MethodManagementHandle,
		pluginabi.MethodQuotaFetch,
		pluginabi.MethodRequestTranslate,
		pluginabi.MethodResponseTranslate,
		"totally.bogus.method",
	} {
		env := callMethod(t, method, []byte(`{}`))
		if env.OK {
			t.Errorf("%s unexpectedly succeeded on unimplemented capability", method)
		}
		if env.Error == nil || env.Error.Code != "unknown_method" {
			t.Errorf("%s error = %+v, want unknown_method", method, env.Error)
		}
	}
}

func TestLifecycleMethodsAcknowledge(t *testing.T) {
	for _, method := range []string{pluginabi.MethodPluginQuiesce, pluginabi.MethodPluginShutdown} {
		env := callMethod(t, method, nil)
		if !env.OK {
			t.Errorf("%s failed: %+v", method, env.Error)
		}
	}
}

// TestConfigFieldsMatchConfigSchema guards the single source of truth: the
// config fields advertised at registration must be exactly the yaml keys of
// the config snapshot, so renaming one side fails here instead of rotting.
func TestConfigFieldsMatchConfigSchema(t *testing.T) {
	declared := map[string]bool{}
	for _, field := range pluginRegistration().Metadata.ConfigFields {
		declared[field.Name] = true
	}
	yamlKeys := map[string]bool{}
	configType := reflect.TypeOf(Config{})
	for i := 0; i < configType.NumField(); i++ {
		tag := configType.Field(i).Tag.Get("yaml")
		name := strings.Split(tag, ",")[0]
		if name != "" && name != "-" {
			yamlKeys[name] = true
		}
	}
	for name := range declared {
		if !yamlKeys[name] {
			t.Errorf("declared config field %q has no yaml key in Config", name)
		}
	}
	for name := range yamlKeys {
		if !declared[name] {
			t.Errorf("config yaml key %q is not advertised in registration ConfigFields", name)
		}
	}
}
