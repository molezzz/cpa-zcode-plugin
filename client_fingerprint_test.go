package main

import (
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The upstream admits a Coding Plan request to a resource package partly by
// the declared client identity, and reports a request that matched no package
// as business code 1113. These tests pin the fingerprint the plugin declares
// and the three invariants that keep it honest: it never comes from caller
// input, it never fabricates a context value the running host cannot supply,
// and the Messages request carries the same device identity the billing
// request already proved the upstream accepts.

func TestUpstreamRequestCarriesDeclaredClientFingerprint(t *testing.T) {
	cfg := normalizeConfig(defaultConfig())
	headers := buildUpstreamHeaders(nil, cfg, "11111111-2222-4333-8444-555555555555")

	want := map[string]string{
		titleHeader:        "Z Code@" + defaultSourceTitle,
		platformHeader:     officialPlatformName(runtime.GOOS) + "-" + officialArchName(runtime.GOARCH),
		osCategoryHeader:   officialOSCategory(officialPlatformName(runtime.GOOS)),
		clientLanguageHead: runtimeClientLanguage(),
		clientTimezoneHead: runtimeClientTimezone(),
		releaseChannelHead: defaultReleaseChannel,
		sessionTypeHeader:  mainSessionType,
		deviceMidHeader:    "11111111-2222-4333-8444-555555555555",
	}
	for name, value := range want {
		if got := headers.Get(name); got != value {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
	}
	// The OS version is the running host's real value, and the header is
	// omitted when the host cannot supply one — never a placeholder.
	if real := runtimeOSVersion(); real != "" {
		if got := headers.Get(osVersionHeader); got != real {
			t.Errorf("%s = %q, want the running host's %q", osVersionHeader, got, real)
		}
	} else if got := headers.Get(osVersionHeader); got != "" {
		t.Errorf("%s = %q, want it omitted on a host without a readable version", osVersionHeader, got)
	}
	if got := headers.Get("User-Agent"); got != zcodeUserAgent(cfg.Product.AppVersion) {
		t.Errorf("User-Agent = %q, want the declared app version", got)
	}
	if got := headers.Get("X-ZCode-App-Version"); got != cfg.Product.AppVersion {
		t.Errorf("X-ZCode-App-Version = %q, want %q", got, cfg.Product.AppVersion)
	}
}

func TestRequestAttributionIDsArePresentAndUUIDShaped(t *testing.T) {
	headers := http.Header{}
	applyRequestAttribution(headers)

	uuidForm := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	seen := map[string]bool{}
	for _, name := range []string{requestIDHeader, traceIDHeader, queryIDHeader, sessionIDHeader} {
		value := headers.Get(name)
		if !uuidForm.MatchString(value) {
			t.Errorf("%s = %q, want a UUID", name, value)
		}
		if seen[value] {
			t.Errorf("%s reuses %q across attribution ids; they must be distinct", name, value)
		}
		seen[value] = true
	}
}

func TestCallerCannotForgeClientFingerprint(t *testing.T) {
	// The fingerprint is how the plugin declares its own identity. A caller that
	// could set it would let any client borrow this account's declared identity,
	// so every fingerprint header must be dropped and then rebuilt.
	caller := http.Header{}
	for _, name := range []string{
		titleHeader, platformHeader, osCategoryHeader, osVersionHeader,
		clientLanguageHead, clientTimezoneHead, releaseChannelHead,
		deviceMidHeader, sessionTypeHeader, requestIDHeader,
		traceIDHeader, queryIDHeader, sessionIDHeader,
		"X-Title", "X-Platform", "X-Os-Category", "X-Device-Mid",
	} {
		caller.Set(name, "attacker-value")
	}

	headers := buildUpstreamHeaders(caller, normalizeConfig(defaultConfig()), "99999999-8888-4777-8666-555555555555")

	for _, name := range []string{titleHeader, platformHeader, osCategoryHeader, clientTimezoneHead, sessionTypeHeader, requestIDHeader, traceIDHeader, queryIDHeader, sessionIDHeader} {
		if got := headers.Get(name); got == "attacker-value" {
			t.Errorf("%s = %q, want the plugin-declared value", name, got)
		}
	}
	if got := headers.Get(deviceMidHeader); got != "99999999-8888-4777-8666-555555555555" {
		t.Errorf("%s = %q, want the credential's own device identity", deviceMidHeader, got)
	}
}

func TestMessagesAndBalanceShareOneDeviceIdentity(t *testing.T) {
	// The billing endpoint already accepted this identity and returned a real
	// plan, so the Messages request has to present the same one. A freshly
	// generated id would describe a second installation and could miss the
	// package the balance just proved exists.
	doc := []byte(`{"zcode":{"identity_id":"zcode-user-1","jwt":{"token":"t","status":"active"},"device_mid":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"}}`)
	recorded := deviceIdentity("auth-index-1", doc)
	if recorded != "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" {
		t.Fatalf("deviceIdentity = %q, want the recorded id", recorded)
	}

	plan := executionPlan(doc, normalizeConfig(defaultConfig()), "GLM-5.2", nil, recorded, time.Now())
	if len(plan.Attempts) == 0 {
		t.Fatal("no credential attempt was planned")
	}
	for _, profile := range plan.Attempts {
		if got := profile.Headers.Get(deviceMidHeader); got != recorded {
			t.Errorf("%s attempt carries device %q, want the credential's own %q", profile.CredentialKind, got, recorded)
		}
	}
}

func TestEmptyDeviceIdentityOmitsTheHeader(t *testing.T) {
	// The upstream gates on the header being a well-formed UUID and answers a
	// blank one as a parameter error, so an absent identity is omitted instead.
	headers := buildUpstreamHeaders(nil, normalizeConfig(defaultConfig()), "")
	if got := headers.Get(deviceMidHeader); got != "" {
		t.Errorf("%s = %q, want it omitted", deviceMidHeader, got)
	}
}

func TestClientFingerprintDefaultsToTheRunningHost(t *testing.T) {
	// The identity defaults must describe the running host, never a fabricated
	// installation: a hardcoded platform, locale, or OS version would describe
	// a client that does not exist.
	client := normalizedClientConfig(ClientConfig{})
	if client.Platform != officialPlatformName(runtime.GOOS) {
		t.Errorf("platform = %q, want the running host's %q", client.Platform, officialPlatformName(runtime.GOOS))
	}
	if client.OSVersion != runtimeOSVersion() {
		t.Errorf("os version = %q, want the running host's %q", client.OSVersion, runtimeOSVersion())
	}
	if client.Language != runtimeClientLanguage() || client.Timezone != runtimeClientTimezone() {
		t.Errorf("locale = %q/%q, want the running host's %q/%q",
			client.Language, client.Timezone, runtimeClientLanguage(), runtimeClientTimezone())
	}
	// The two defaults that are not runtime-derived are the official client's
	// own constants (source-confirmed), not an invented identity.
	if client.ReleaseChannel != defaultReleaseChannel || client.SourceTitle != defaultSourceTitle {
		t.Errorf("channel/title = %q/%q, want the official client's %q/%q", client.ReleaseChannel, client.SourceTitle, defaultReleaseChannel, defaultSourceTitle)
	}
}

func TestClientFingerprintNeverFabricatesALocale(t *testing.T) {
	// A host with no locale context reads "unknown", the official builder's
	// own spelling for an unresolvable value — not a guessed locale.
	client := normalizedClientConfig(ClientConfig{})
	for name, value := range map[string]string{"language": client.Language, "timezone": client.Timezone} {
		if value == "" {
			t.Errorf("%s = empty, want a value or %q", name, unknownAttributeValue)
		}
	}
}

func TestRuntimeClientLanguageReadsTheEnvironment(t *testing.T) {
	set := func(name, value string) func() {
		original, had := os.LookupEnv(name)
		if value == "" {
			_ = os.Unsetenv(name)
		} else {
			_ = os.Setenv(name, value)
		}
		return func() {
			if had {
				_ = os.Setenv(name, original)
			} else {
				_ = os.Unsetenv(name)
			}
		}
	}

	defer set("LC_ALL", "zh_CN.UTF-8")()
	defer set("LC_MESSAGES", "")()
	defer set("LANG", "en_US.UTF-8")()
	if got := runtimeClientLanguage(); got != "zh-CN" {
		t.Errorf("LC_ALL wins: language = %q, want zh-CN", got)
	}

	defer set("LC_ALL", "")()
	defer set("LC_MESSAGES", "pt_BR")()
	if got := runtimeClientLanguage(); got != "pt-BR" {
		t.Errorf("LC_MESSAGES next: language = %q, want pt-BR", got)
	}

	defer set("LC_MESSAGES", "")()
	defer set("LANG", "C")()
	if got := runtimeClientLanguage(); got != unknownAttributeValue {
		t.Errorf("POSIX C: language = %q, want %q", got, unknownAttributeValue)
	}

	defer set("LANG", "")()
	if got := runtimeClientLanguage(); got != unknownAttributeValue {
		t.Errorf("no locale env: language = %q, want %q", got, unknownAttributeValue)
	}
}

func TestRuntimeClientTimezoneReadsTheEnvironment(t *testing.T) {
	original, had := os.LookupEnv("TZ")
	defer func() {
		if had {
			_ = os.Setenv("TZ", original)
		} else {
			_ = os.Unsetenv("TZ")
		}
	}()

	_ = os.Setenv("TZ", "Asia/Tokyo")
	if got := runtimeClientTimezone(); got != "Asia/Tokyo" {
		t.Errorf("TZ wins: timezone = %q, want Asia/Tokyo", got)
	}
	// A ":<path>" TZ spelling (a file path form) is not a zone name.
	_ = os.Setenv("TZ", ":/etc/zoneinfo/Europe/Berlin")
	if got := runtimeClientTimezone(); got == ":/etc/zoneinfo/Europe/Berlin" {
		t.Errorf("timezone = %q, want the colon prefix stripped", got)
	}
}

func TestPlatformAndArchFollowTheOfficialVocabulary(t *testing.T) {
	// The X-Platform header reports the official client's process.platform and
	// process.arch spellings, so a Windows host must read win32 and an amd64
	// host x64 — not Go's own names for the same platforms.
	cases := []struct {
		goos, goarch string
		wantPlatform string
		wantArch     string
		wantCategory string
	}{
		{"darwin", "arm64", "darwin", "arm64", osCategoryMacOS},
		{"windows", "amd64", "win32", "x64", osCategoryWindows},
		{"linux", "amd64", "linux", "x64", osCategoryLinux},
		{"linux", "arm64", "linux", "arm64", osCategoryLinux},
		{"freebsd", "amd64", "freebsd", "x64", osCategoryLinux},
	}
	for _, tc := range cases {
		if got := officialPlatformName(tc.goos); got != tc.wantPlatform {
			t.Errorf("officialPlatformName(%q) = %q, want %q", tc.goos, got, tc.wantPlatform)
		}
		if got := officialArchName(tc.goarch); got != tc.wantArch {
			t.Errorf("officialArchName(%q) = %q, want %q", tc.goarch, got, tc.wantArch)
		}
		if got := officialOSCategory(tc.wantPlatform); got != tc.wantCategory {
			t.Errorf("officialOSCategory(%q) = %q, want %q", tc.wantPlatform, got, tc.wantCategory)
		}
	}
}

func TestClientFingerprintConfigOverrideIsApplied(t *testing.T) {
	cfg := normalizeConfig(defaultConfig())
	cfg.Client = normalizedClientConfig(ClientConfig{
		Platform:       "win32",
		OSVersion:      "10.0.19045",
		Language:       "en-US",
		Timezone:       "UTC",
		ReleaseChannel: "beta",
		SourceTitle:    "cli",
	})
	headers := buildUpstreamHeaders(nil, cfg, "")
	if got := headers.Get(titleHeader); got != "Z Code@cli" {
		t.Errorf("%s = %q, want the configured surface", titleHeader, got)
	}
	if got := headers.Get(osCategoryHeader); got != osCategoryWindows {
		t.Errorf("%s = %q, want windows for win32", osCategoryHeader, got)
	}
	if got := headers.Get(clientLanguageHead); got != "en-US" {
		t.Errorf("%s = %q, want the configured language", clientLanguageHead, got)
	}
}

func TestOSCategoryMapsPlatformsLikeTheOfficialClient(t *testing.T) {
	cases := map[string]string{
		"darwin": osCategoryMacOS,
		"win32":  osCategoryWindows,
		"linux":  osCategoryLinux,
		// Anything the official client does not name reads as linux there, so
		// an unrecognized platform must not produce an empty header.
		"freebsd": osCategoryLinux,
	}
	for platform, want := range cases {
		if got := (ClientConfig{Platform: platform}).osCategory(); got != want {
			t.Errorf("osCategory(%q) = %q, want %q", platform, got, want)
		}
	}
}

func TestAttributionFailureStillProducesARequest(t *testing.T) {
	// crypto/rand is not expected to fail, but a request must never be left
	// without attribution because of it.
	if got := attributionID(); strings.TrimSpace(got) == "" {
		t.Error("attributionID returned an empty value")
	}
}
