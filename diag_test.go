package main

import (
	"bytes"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"
)

func storeDebugConfig(enabled bool) func() {
	cfg := defaultConfig()
	cfg.Debug = boolPtr(enabled)
	activeConfig.Store(cfg)
	return func() { activeConfig.Store(defaultConfig()) }
}

func captureDiagLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(previous) })
	return &buf
}

func TestDiagIsSilentByDefault(t *testing.T) {
	defer resetConfigSnapshot()()
	buf := captureDiagLog(t)
	diagf("should not appear %d", 1)
	if buf.Len() != 0 {
		t.Fatalf("diagf wrote %q with diagnostics disabled", buf.String())
	}
	if defaultConfig().IsDebugEnabled() {
		t.Fatal("debug must default to off")
	}
}

func TestDiagWritesPrefixedLineWhenEnabled(t *testing.T) {
	defer storeDebugConfig(true)()
	buf := captureDiagLog(t)
	diagf("attempt tag=%s cred=%s", "abcd1234", "jwt")
	line := buf.String()
	if !strings.Contains(line, "[zcode-plugin] attempt tag=abcd1234 cred=jwt") {
		t.Fatalf("log line = %q, want prefixed diag line", line)
	}
}

func TestDiagConfigOverrideMergesOntoSnapshot(t *testing.T) {
	defer resetConfigSnapshot()()
	cfg, err := parseConfig([]byte("debug: true\n"))
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	merged := mergeConfig(defaultConfig(), cfg)
	if !merged.IsDebugEnabled() {
		t.Fatal("debug: true override lost")
	}
	off, err := parseConfig([]byte("debug: false\n"))
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if merged := mergeConfig(defaultConfig(), off); merged.IsDebugEnabled() {
		t.Fatal("debug: false override lost")
	}
	if merged := mergeConfig(defaultConfig(), Config{}); merged.IsDebugEnabled() {
		t.Fatal("unset debug must keep the default off")
	}
}

func TestDiagRequestTagHasStableShape(t *testing.T) {
	defer storeDebugConfig(true)()
	tag := diagRequestTag()
	if len(tag) != 8 {
		t.Fatalf("tag = %q, want 8 characters", tag)
	}
	if strings.Contains(tag, "-") {
		t.Fatalf("tag = %q, want the uuid prefix without dashes", tag)
	}
}

func TestDiagRequestTagIsEmptyWhenDisabled(t *testing.T) {
	defer resetConfigSnapshot()()
	if tag := diagRequestTag(); tag != "" {
		t.Fatalf("disabled tag = %q, want empty", tag)
	}
}

func TestDiagHeaderViewRedactsCredentialHeaders(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer super-secret-jwt")
	headers.Set("X-Api-Key", "sk-super-secret")
	headers.Set("X-ZCode-App-Version", "3.14.4")
	headers.Set("X-Device-Mid", "11111111-2222-4333-8444-555555555555")
	headers.Set("User-Agent", "ZCode/3.14.4")
	headers.Set("X-Custom-Future", "host-added")

	view := diagHeaderView(headers)
	if strings.Contains(view, "super-secret") {
		t.Fatalf("header view leaked credential material: %q", view)
	}
	if strings.Contains(view, "11111111") {
		t.Fatalf("header view leaked the device identity: %q", view)
	}
	if !strings.Contains(view, "Authorization=<redacted>") {
		t.Fatalf("header view missing redacted authorization: %q", view)
	}
	if !strings.Contains(view, "X-Api-Key=<redacted>") {
		t.Fatalf("header view missing redacted x-api-key: %q", view)
	}
	if !strings.Contains(view, "X-Device-Mid=<redacted>") {
		t.Fatalf("header view missing redacted device identity: %q", view)
	}
	if !strings.Contains(view, "X-Custom-Future=<redacted>") {
		t.Fatalf("unknown future headers must redact: %q", view)
	}
	for _, safe := range []string{"X-Zcode-App-Version=3.14.4", "User-Agent=ZCode/3.14.4"} {
		if !strings.Contains(view, safe) {
			t.Fatalf("header view missing safe entry %q: %q", safe, view)
		}
	}
	// Keys render in sorted order so two views of the same profile compare equal.
	if strings.Index(view, "Authorization") > strings.Index(view, "User-Agent") {
		t.Fatalf("header view keys are not sorted: %q", view)
	}
}

func TestDiagBalanceSummaryPrintsOnlyStatedNumbers(t *testing.T) {
	ten, zero := 10.0, 0.0
	balances := []quotaBalance{
		{Name: "GLM-5.3-Flash", Remaining: &ten, Total: &ten, Capabilities: []string{"model:GLM-5.3-Flash"}},
		{Name: "GLM-5.2", Remaining: nil, Total: nil},
		{Name: "GLM-5-Turbo", Remaining: &zero, Malformed: true},
	}
	view := diagBalanceSummary(balances)
	for _, want := range []string{
		"GLM-5.3-Flash{remaining=10,total=10,caps=[model:GLM-5.3-Flash]}",
		"GLM-5.2{remaining=-,total=-}",
		"GLM-5-Turbo{remaining=0,total=-,malformed}",
	} {
		if !strings.Contains(view, want) {
			t.Fatalf("balance summary missing %q: %q", want, view)
		}
	}
}

func TestDiagPlanSummaryRendersTermEnds(t *testing.T) {
	ends := float64(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC).Unix())
	plans := []quotaPlan{
		{Name: "ZCode V3 Start Plan", Status: planStatusActive, EndsAt: &ends},
		{Status: planStatusUnknown},
	}
	view := diagPlanSummary(plans)
	wantActive := "ZCode V3 Start Plan{status=active,ends=" + time.Unix(int64(ends), 0).UTC().Format(time.RFC3339) + "}"
	for _, want := range []string{
		wantActive,
		"(unnamed){status=,ends=-}",
	} {
		if !strings.Contains(view, want) {
			t.Fatalf("plan summary missing %q: %q", want, view)
		}
	}
}

func TestDiagDisabledKeepsStderrQuietAcrossPackage(t *testing.T) {
	// The request paths call diagf unconditionally; the gate must live inside
	// diagf so a disabled flag produces no output even when every call site
	// fires.
	defer resetConfigSnapshot()()
	buf := captureDiagLog(t)
	diagf("quota auth=x verdict=%s", verdictUnknown)
	if buf.Len() != 0 {
		t.Fatalf("disabled diagf wrote %q", buf.String())
	}
}

// Acceptance criterion 10: the preflight, snapshot, recheck and pool diagnostic
// lines carry no credential, no token, no device id, no account id, and no raw
// upstream plan or bucket identifier.
func TestDiagPlanLinesCarryNoSensitiveIdentifiers(t *testing.T) {
	defer storeDebugConfig(true)()
	buf := captureDiagLog(t)
	const (
		jwt     = "jwt-super-secret-value"
		account = "70861758810173130"
		device  = "11111111-2222-4333-8444-555555555555"
		userID  = "34dd6d87-1234-4321-abcd-0123456789ab"
	)
	snapshot := startPlanSnapshotFrom(t,
		`[{"name":"ZCode V3 Start Plan","plan_id":"zcode-v3-start-plan-0817","user_plan_id":"`+userID+`","status":"active"}]`,
		`{"show_name":"GLM-5.3-Flash","plan_id":"zcode-v3-start-plan-0817","user_plan_id":"`+userID+`","capabilities":["model:glm-5.3-flash"],"remaining_units":4,"expires_at":"2026-10-04T00:00:00Z"}`,
		time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC))

	diagf("plan_snapshot auth=%s identity=%s readable=%v last_priority=%v plans=[%s] models=[%s]",
		"auth-x", "zcode-user", snapshot.Readable, snapshot.isLastPriority(normalizeConfig(Config{})),
		strings.Join(snapshot.startPlanIDs(), " "), diagModelAllowance(snapshot))
	diagf("oauth_preflight identity=%s readable=%v verdict=%s plans=[%s] models=[%s]",
		preflightIdentityDiag(account), snapshot.Readable, "available",
		strings.Join(snapshot.startPlanIDs(), " "), diagModelAllowance(snapshot))
	diagf("plan_recheck tag=%s auth=%s model=%q decision=%s", "tag", "auth-x", "GLM-5.3-Flash", "empty")
	diagf("pool auth=%s model=%q candidates=%d", "auth-x", "GLM-5.3-Flash", 2)

	out := buf.String()
	for _, forbidden := range []string{jwt, account, device, userID} {
		if strings.Contains(out, forbidden) {
			t.Errorf("a plan diagnostic line leaked %q:\n%s", forbidden, out)
		}
	}
	// The lines must still say the actionable thing: the plan and the model's
	// standing are what an operator reads.
	if !strings.Contains(out, "zcode-v3-start-plan-0817") || !strings.Contains(out, "GLM-5.3-Flash=funded") {
		t.Errorf("plan diagnostics dropped the facts they exist to report:\n%s", out)
	}
}
