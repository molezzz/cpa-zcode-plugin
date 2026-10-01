package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// pluginVersion is overridden at build time via -ldflags "-X main.pluginVersion=...".
var pluginVersion = "0.1.0"

var activeConfig atomic.Value // stores Config

func init() {
	activeConfig.Store(defaultConfig())
}

// lifecycleRequest mirrors the host RPC schema for plugin.register and
// plugin.reconfigure.
type lifecycleRequest struct {
	ConfigYAML []byte `json:"config_yaml"`
}

// registration mirrors the host RPC schema of the plugin.register result.
// Capabilities must stay aligned with what this plugin actually implements
// and contract-tests; never declare a capability for an unimplemented method.
type registration struct {
	SchemaVersion uint32                   `json:"schema_version"`
	Metadata      pluginapi.Metadata       `json:"metadata"`
	Capabilities  registrationCapabilities `json:"capabilities"`
}

// registrationCapabilities mirrors the host-side RPC schema field for field.
type registrationCapabilities struct {
	ModelRegistrar                bool                         `json:"model_registrar"`
	ModelProvider                 bool                         `json:"model_provider"`
	AuthProvider                  bool                         `json:"auth_provider"`
	FrontendAuthProvider          bool                         `json:"frontend_auth_provider"`
	FrontendAuthProviderExclusive bool                         `json:"frontend_auth_provider_exclusive"`
	Scheduler                     bool                         `json:"scheduler"`
	SchedulerAcrossPriorities     bool                         `json:"scheduler_across_priorities,omitempty"`
	ModelRouter                   bool                         `json:"model_router"`
	Executor                      bool                         `json:"executor"`
	ExecutorModelScope            pluginapi.ExecutorModelScope `json:"executor_model_scope"`
	ExecutorInputFormats          []string                     `json:"executor_input_formats,omitempty"`
	ExecutorOutputFormats         []string                     `json:"executor_output_formats,omitempty"`
	RequestTranslator             bool                         `json:"request_translator"`
	RequestNormalizer             bool                         `json:"request_normalizer"`
	RequestInterceptor            bool                         `json:"request_interceptor"`
	RequestLifecyclePlugin        bool                         `json:"request_lifecycle_plugin"`
	ResponseTranslator            bool                         `json:"response_translator"`
	ResponseBeforeTranslator      bool                         `json:"response_before_translator"`
	ResponseAfterTranslator       bool                         `json:"response_after_translator"`
	ResponseInterceptor           bool                         `json:"response_interceptor"`
	StreamChunkInterceptor        bool                         `json:"response_stream_interceptor"`
	WebSocketResponseObserver     bool                         `json:"websocket_response_observer"`
	ThinkingApplier               bool                         `json:"thinking_applier"`
	UsagePlugin                   bool                         `json:"usage_plugin"`
	CommandLinePlugin             bool                         `json:"command_line_plugin"`
	ManagementAPI                 bool                         `json:"management_api"`
	QuotaProvider                 bool                         `json:"quota_provider"`
}

// handleMethod routes one host RPC method. It always returns an envelope for
// handled methods; a Go error means the ABI layer must synthesize a generic
// plugin_error envelope instead.
func handleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		if err := configure(request); err != nil {
			return errorEnvelope("invalid_config", err.Error(), http.StatusBadRequest), nil
		}
		return okEnvelope(pluginRegistration())
	case pluginabi.MethodModelRegister:
		return okEnvelope(pluginapi.ModelRegistrationResponse{
			Provider: pluginID,
			Models:   staticModels(currentConfig()),
		})
	case pluginabi.MethodModelStatic:
		return okEnvelope(pluginapi.ModelResponse{
			Provider: pluginID,
			Models:   staticModels(currentConfig()),
		})
	case pluginabi.MethodModelForAuth:
		return handleModelForAuth(request)
	case pluginabi.MethodAuthIdentifier:
		return handleAuthIdentifier()
	case pluginabi.MethodAuthParse:
		return handleAuthParse(request)
	case pluginabi.MethodAuthLoginStart:
		return handleAuthLoginStart(request)
	case pluginabi.MethodAuthLoginPoll:
		return handleAuthLoginPoll(request)
	case pluginabi.MethodAuthRefresh:
		return handleAuthRefresh(request)
	case pluginabi.MethodExecutorIdentifier:
		return handleExecutorIdentifier()
	case pluginabi.MethodExecutorExecute:
		return handleExecutorExecute(request)
	case pluginabi.MethodExecutorExecuteStream:
		return handleExecutorExecuteStream(request)
	case pluginabi.MethodExecutorCountTokens:
		return handleExecutorCountTokens()
	case pluginabi.MethodExecutorHTTPRequest:
		return handleExecutorHTTPRequest()
	case pluginabi.MethodManagementRegister:
		return handleManagementRegister(request)
	case pluginabi.MethodManagementHandle:
		return handleManagementHandle(request)
	case pluginabi.MethodQuotaIdentifier:
		return handleQuotaIdentifier()
	case pluginabi.MethodQuotaDescribe:
		return handleQuotaDescribe()
	case pluginabi.MethodQuotaFetch:
		return handleQuotaFetch(request)
	case pluginabi.MethodQuotaReset:
		return handleQuotaReset(request)
	case pluginabi.MethodPluginQuiesce:
		return okEnvelope(struct{}{})
	case pluginabi.MethodPluginShutdown:
		runShutdown()
		return okEnvelope(struct{}{})
	default:
		// Anything not implemented above is refused, whether or not some other
		// plugin declares a capability for it: this plugin never answers a
		// method it does not implement.
		return errorEnvelope("unknown_method", "unknown method: "+method, 0), nil
	}
}

// configure decodes the config YAML override and stores a normalized snapshot.
func configure(request []byte) error {
	var req lifecycleRequest
	if len(request) > 0 {
		if err := json.Unmarshal(request, &req); err != nil {
			return fmt.Errorf("decode lifecycle request: %w", err)
		}
	}
	override, err := parseConfig(req.ConfigYAML)
	if err != nil {
		return fmt.Errorf("parse plugin config: %w", err)
	}
	activeConfig.Store(normalizeConfig(mergeConfig(defaultConfig(), override)))
	return nil
}

func currentConfig() Config {
	if cfg, ok := activeConfig.Load().(Config); ok {
		return cfg
	}
	return defaultConfig()
}

// pluginRegistration is the single source of truth for what this plugin
// declares to the host: metadata, config fields, and capabilities.
func pluginRegistration() registration {
	return registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             "ZCode",
			Version:          pluginVersion,
			Author:           "molezz",
			GitHubRepository: "https://github.com/molezzz/cpa-zcode-plugin",
			ConfigFields: []pluginapi.ConfigField{
				{Name: "enabled", Type: pluginapi.ConfigFieldTypeBoolean, Description: "Enable the ZCode provider plugin."},
				{Name: "priority", Type: pluginapi.ConfigFieldTypeInteger, Description: "Provider priority relative to other host providers."},
				{Name: "models", Type: pluginapi.ConfigFieldTypeArray, Description: "Static fallback model IDs, always available when discovery is off or fails."},
				{Name: "product", Type: pluginapi.ConfigFieldTypeObject, Description: "Client identity settings (app_version). The upstream judges capability and billing entitlement by the declared version, so set it to a real ZCode client release."},
				{Name: "model_discovery", Type: pluginapi.ConfigFieldTypeObject, Description: "Identity-scoped dynamic model discovery settings (enabled, success_ttl_seconds, failure_cooldown_seconds)."},
				{Name: "oauth", Type: pluginapi.ConfigFieldTypeObject, Description: "Authorization session settings (session_ttl_seconds, managed_key_name_prefix, organization_id, project_id)."},
				{Name: "upstream", Type: pluginapi.ConfigFieldTypeObject, Description: "Upstream HTTP limits (connect_timeout_seconds, request_timeout_seconds, max_response_bytes)."},
				{Name: "quota", Type: pluginapi.ConfigFieldTypeObject, Description: "Quota refresh settings (refresh_concurrency)."},
			},
		},
		Capabilities: registrationCapabilities{
			// Implemented and contract-tested in this baseline.
			ModelRegistrar: true,
			ModelProvider:  true,
			// Native provider authentication: authorization sessions with
			// browser login, pollable status, and JWT credential storage.
			AuthProvider: true,
			// Anthropic Messages executor over the Coding Plan JWT primary
			// credential; the upstream speaks the claude format, so the host
			// translates other client formats in and out.
			Executor:              true,
			ExecutorModelScope:    pluginapi.ExecutorModelScopeBoth,
			ExecutorInputFormats:  []string{"claude"},
			ExecutorOutputFormats: []string{"claude"},
			// Authenticated management routes: the redacted state page and
			// the fixed maintenance action vocabulary.
			ManagementAPI: true,
			// Normalized quota reporting for the Coding Plan JWT credential,
			// with conservative evidence-based state recovery. Reset is
			// declared unsupported upstream and answers accordingly.
			QuotaProvider: true,
		},
	}
}

func okEnvelope(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return json.Marshal(pluginabi.Envelope{OK: true, Result: raw})
}

func errorEnvelope(code, message string, status int) []byte {
	raw, err := json.Marshal(pluginabi.Envelope{
		OK:    false,
		Error: &pluginabi.Error{Code: code, Message: message, HTTPStatus: status},
	})
	if err != nil {
		// Marshalling a plain struct cannot fail in practice; the fallback
		// keeps the ABI contract "a non-zero return code carries an envelope".
		return []byte(`{"ok":false,"error":{"code":"plugin_error","message":"plugin error envelope failed to encode"}}`)
	}
	return raw
}

// runShutdown tears down plugin-owned runtime state exactly once. Later
// milestones must extend this hook (active streams, host callback contexts).
var shutdownOnce sync.Once

func runShutdown() {
	shutdownOnce.Do(func() {
		// Authorization sessions hold OAuth secrets and must never outlive
		// the plugin.
		activeSessions.shutdownAll()
		// Management-initiated authorization loops poll the upstream and save
		// through the host; cancel them before the library can unload.
		managementOAuth.stopAll()
		// In-flight executions pump into host callbacks; cancel them so the
		// shared library unloads without calling a stopped host.
		activeExecutions.cancelAll()
	})
}
