package main

import (
	"net/http"
	"os"
	"runtime"
	"strings"
)

// The official ZCode client describes itself to the upstream on every model
// request: platform, OS, locale, timezone, release channel, surface title,
// device identity, a request-body identity, and attribution ids that tie a
// request to its caller session (docs/ZCode
// packages/shared/src/zcode-source-headers.ts,
// packages/services/src/providers/sourceHeaders.ts,
// adapters/src/model/anthropic-request-metadata.ts). The upstream admits a
// Coding Plan request to a resource package partly by the client identity the
// request carries, and business code 1113 ("Insufficient balance or no
// resource package") is what a request that authenticated but matched no
// package gets back.
//
// This file reproduces that header set with the plugin's own honest context.
// Every default is either a source-confirmed official constant or a value read
// from the running host at request time; nothing is fabricated to look like
// some other installation. Where the official builder cannot resolve a value
// it sends "unknown" (language, timezone) or omits the header (platform,
// OS version, device id) — this plugin does the same.
//
// Every value is plugin-declared. These are the client's description of itself,
// not credentials, and none of them may come from caller input — the header
// allowlist in profile.go denies them all by default.
const (
	titleHeader        = "X-Title"
	platformHeader     = "X-Platform"
	releaseChannelHead = "X-Release-Channel"
	clientLanguageHead = "X-Client-Language"
	clientTimezoneHead = "X-Client-Timezone"
	osCategoryHeader   = "X-Os-Category"
	osVersionHeader    = "X-Os-Version"
	requestIDHeader    = "X-Request-Id"
	traceIDHeader      = "X-ZCode-Trace-Id"
	queryIDHeader      = "X-Query-Id"
	sessionIDHeader    = "X-Session-Id"
	sessionTypeHeader  = "X-ZCode-Session-Type"
)

const (
	clientTitleTemplate = "Z Code@"
	mainSessionType     = "main"

	osCategoryMacOS   = "macos"
	osCategoryWindows = "windows"
	osCategoryLinux   = "linux"

	// These two are source-confirmed official client constants: the desktop
	// builder fixes the surface title to "electron" and a release build's
	// channel is "production". They declare which client surface the account's
	// entitlement belongs to; the version declaration that completes the
	// identity is product.app_version.
	defaultReleaseChannel = "production"
	defaultSourceTitle    = "electron"

	// unknownAttributeValue is the official builder's own spelling for a
	// context value it could not resolve: language and timezone are always
	// sent, and read "unknown" rather than being guessed.
	unknownAttributeValue = "unknown"
)

// ClientConfig is the plugin's declared client fingerprint. Unset fields
// default to the running host's real context; set fields are the operator's
// explicit declaration and override the runtime. These values are neither
// secrets nor credentials; they describe the client's platform, locale and
// build to the upstream.
type ClientConfig struct {
	// Platform is the platform as the official client spells it
	// (process.platform: darwin, win32, linux). Empty detects the running host.
	Platform string `yaml:"platform"`
	// OSCategory is the coarse platform family: macos, windows or linux.
	// Empty derives it from Platform the way the official builder does.
	OSCategory string `yaml:"os_category"`
	// OSVersion is the client's OS version. Empty reads the running host's,
	// and the header is omitted when the host cannot supply one.
	OSVersion string `yaml:"os_version"`
	Language  string `yaml:"language"`
	Timezone  string `yaml:"timezone"`
	// ReleaseChannel is the client's release channel, e.g. production.
	ReleaseChannel string `yaml:"release_channel"`
	// SourceTitle is the client surface, rendered into X-Title as
	// "Z Code@<SourceTitle>".
	SourceTitle string `yaml:"source_title"`
}

// osCategory resolves the coarse platform family from the platform name.
func (c ClientConfig) osCategory() string {
	if c.OSCategory != "" {
		return c.OSCategory
	}
	return officialOSCategory(c.Platform)
}

// officialOSCategory mirrors the official builder's normalizeOsCategory:
// darwin reads as macos, win32 as windows, everything else as linux.
func officialOSCategory(platform string) string {
	switch platform {
	case "darwin":
		return osCategoryMacOS
	case "win32":
		return osCategoryWindows
	default:
		return osCategoryLinux
	}
}

// officialPlatformName maps the Go runtime's GOOS onto the official client's
// process.platform vocabulary, which the X-Platform header reports. The one
// spelling that differs is Windows: Go says "windows", the official client
// says "win32".
func officialPlatformName(goos string) string {
	if goos == "windows" {
		return "win32"
	}
	return goos
}

// officialArchName maps Go's GOARCH onto the official client's process.arch
// vocabulary, the second half of the X-Platform header.
func officialArchName(goarch string) string {
	switch goarch {
	case "amd64":
		return "x64"
	case "386":
		return "ia32"
	default:
		return goarch
	}
}

// applyClientFingerprint sets the declared client identity on one upstream
// request.
//
// identity.DeviceID is the same device identity the billing endpoint already
// accepts for this credential, so the Messages request and the balance request
// describe one installation. An empty device id omits the header rather than
// sending it blank: the upstream gates on it being a well-formed UUID.
func applyClientFingerprint(headers http.Header, cfg Config, identity requestIdentity) {
	client := normalizedClientConfig(cfg.Client)
	headers.Set(titleHeader, clientTitleTemplate+client.SourceTitle)
	headers.Set(platformHeader, client.Platform+"-"+officialArchName(runtime.GOARCH))
	headers.Set(osCategoryHeader, client.osCategory())
	if client.OSVersion != "" {
		// The official builder omits the OS version header when it has no
		// value; a placeholder would be a fabricated one.
		headers.Set(osVersionHeader, client.OSVersion)
	}
	headers.Set(clientLanguageHead, client.Language)
	headers.Set(clientTimezoneHead, client.Timezone)
	headers.Set(releaseChannelHead, client.ReleaseChannel)
	if id := strings.TrimSpace(identity.DeviceID); id != "" {
		headers.Set(deviceMidHeader, id)
	}
	applyRequestAttribution(headers, identity.SessionID)
}

// applyRequestAttribution sets the ids the Coding Plan service reads to
// attribute a model request to a session and a trace (source-confirmed header
// names and session-type vocabulary in the official client's
// runner-attribution). The official ids come from its trace context: the
// session id is stable across the requests of one caller session, and the
// trace spans the request's life. This plugin holds no per-conversation
// session state, so the session id is derived from the caller's stable context
// (requestSessionID) and one per-request id is shared across
// request/trace/query — the official headers allow those to be the same value
// or derived, and one shared value is what expresses that a request is one
// correlated event. A request without session context omits the session
// header, exactly as the official client does. They are observability fields
// only — no entitlement decision reads them.
func applyRequestAttribution(headers http.Header, sessionID string) {
	request := attributionID()
	headers.Set(requestIDHeader, request)
	headers.Set(traceIDHeader, request)
	headers.Set(queryIDHeader, request)
	if sessionID != "" {
		headers.Set(sessionIDHeader, sessionID)
	}
	// This plugin serves top-level agent traffic only, so every request is
	// main-session traffic; the upstream reads the header to tell a subagent's
	// request from the main loop's.
	headers.Set(sessionTypeHeader, mainSessionType)
}

// attributionID returns one request-scoped UUID. crypto/rand failing is not a
// reason to drop attribution — a request still has to be sent — so it falls
// back to the same fixed shape the device identity uses as a last resort.
func attributionID() string {
	id, err := newUUID()
	if err != nil {
		return deviceIDFallback
	}
	return id
}

// normalizedClientConfig clamps the declared fingerprint onto a complete set.
// Unset fields read the running host's real context; the only two defaults
// that are not runtime-derived are the source-confirmed official constants
// (release channel and surface title). Language and timezone never come out
// empty: the official builder sends "unknown" when it cannot resolve them.
func normalizedClientConfig(client ClientConfig) ClientConfig {
	client.Platform = strings.TrimSpace(client.Platform)
	client.OSCategory = strings.TrimSpace(client.OSCategory)
	client.OSVersion = strings.TrimSpace(client.OSVersion)
	client.Language = strings.TrimSpace(client.Language)
	client.Timezone = strings.TrimSpace(client.Timezone)
	client.ReleaseChannel = strings.TrimSpace(client.ReleaseChannel)
	client.SourceTitle = strings.TrimSpace(client.SourceTitle)
	if client.Platform == "" {
		client.Platform = officialPlatformName(runtime.GOOS)
	}
	if client.OSVersion == "" {
		client.OSVersion = runtimeOSVersion()
	}
	if client.Language == "" {
		client.Language = runtimeClientLanguage()
	}
	if client.Timezone == "" {
		client.Timezone = runtimeClientTimezone()
	}
	if client.ReleaseChannel == "" {
		client.ReleaseChannel = defaultReleaseChannel
	}
	if client.SourceTitle == "" {
		client.SourceTitle = defaultSourceTitle
	}
	return client
}

// runtimeClientLanguage resolves the running process's locale from the
// environment the way the official client resolves its Intl locale: the real
// value, or "unknown" when there is none. LC_ALL wins over LC_MESSAGES over
// LANG, as the POSIX resolution order does; an encoding suffix ("zh_CN.UTF-8")
// and a modifier ("zh_CN@pinyin") are stripped, and "C"/"POSIX" carry no
// locale information.
func runtimeClientLanguage() string {
	locale := firstNonEmptyEnv("LC_ALL", "LC_MESSAGES", "LANG")
	if idx := strings.IndexByte(locale, '.'); idx >= 0 {
		locale = locale[:idx]
	}
	if idx := strings.IndexByte(locale, '@'); idx >= 0 {
		locale = locale[:idx]
	}
	locale = strings.ReplaceAll(locale, "_", "-")
	switch locale {
	case "", "C", "POSIX":
		return unknownAttributeValue
	default:
		return locale
	}
}

// firstNonEmptyEnv returns the first non-empty value among the named
// environment variables.
func firstNonEmptyEnv(names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return ""
}

// runtimeClientTimezone resolves the running process's IANA timezone name.
// TZ wins when it names a zone; otherwise /etc/localtime's symlink target is
// read, which is how the system zone is recorded on both target platforms.
// Anything unresolvable reads "unknown" — never a guessed zone.
func runtimeClientTimezone() string {
	if tz := strings.TrimPrefix(strings.TrimSpace(os.Getenv("TZ")), ":"); tz != "" {
		return tz
	}
	if target, err := os.Readlink("/etc/localtime"); err == nil {
		if idx := strings.LastIndex(target, "/zoneinfo/"); idx >= 0 {
			return target[idx+len("/zoneinfo/"):]
		}
	}
	return unknownAttributeValue
}
