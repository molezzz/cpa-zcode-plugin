package main

import (
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"
)

// diagPrefix marks every plugin debug line in the host process log, so an
// operator can grep the plugin's view out of the container's mixed output.
const diagPrefix = "[zcode-plugin]"

// diagDebugEnabled reports whether the active configuration snapshot turned
// request diagnostics on. The flag is read per line, so flipping
// plugins.configs.zcode.debug takes effect on the next stored snapshot
// without touching any request path that does not log.
func diagDebugEnabled() bool {
	return currentConfig().IsDebugEnabled()
}

// diagf writes one debug line to the process log (stderr) when diagnostics
// are enabled. Lines are written for the operator reading the host's log, so
// they carry only sanitized facts: no credential material, no caller prompt
// content, no raw upstream bodies — the same discipline as the sanitized
// error envelopes.
func diagf(format string, args ...any) {
	if !diagDebugEnabled() {
		return
	}
	log.Printf("%s %s", diagPrefix, fmt.Sprintf(format, args...))
}

// diagRequestTag returns the short per-request correlation tag debug lines
// carry, so interleaved concurrent requests stay readable in the log. An
// empty tag means diagnostics are off — no line will ever carry it — and no
// random material is spent.
func diagRequestTag() string {
	if !diagDebugEnabled() {
		return ""
	}
	return attributionID()[:8]
}

// diagValueLimit caps one field value in a debug line — a header value, a
// capability list, any other single rendered field. The only values long
// enough to reach this are caller-supplied anthropic-beta lists.
const diagValueLimit = 120

// diagSafeHeaderNames are the header values that may be printed in a debug
// line. The set holds only identifiers and protocol metadata the plugin builds
// itself or the caller allowlists; every other header — authentication,
// cookies, anything added by future host versions — prints as redacted.
//
// X-Device-Mid is deliberately absent: the device identity is the account's
// installation token, and debug lines are evidence, not identity leakage. The
// per-request attribution ids are present on purpose — they are the plugin's
// own request/trace/session correlation ids and part of the evidence.
var diagSafeHeaderNames = map[string]struct{}{
	"Accept":               {},
	"Content-Type":         {},
	"Anthropic-Version":    {},
	"Anthropic-Beta":       {},
	"User-Agent":           {},
	"Http-Referer":         {},
	"X-Title":              {},
	"X-Zcode-App-Version":  {},
	"X-Zcode-Agent":        {},
	"X-Platform":           {},
	"X-Release-Channel":    {},
	"X-Client-Language":    {},
	"X-Client-Timezone":    {},
	"X-Os-Category":        {},
	"X-Os-Version":         {},
	"X-Request-Id":         {},
	"X-Zcode-Trace-Id":     {},
	"X-Query-Id":           {},
	"X-Session-Id":         {},
	"X-Zcode-Session-Type": {},
}

// diagHeaderView renders one profile's header set for a debug line: keys in
// stable order, values printed only for the safe allowlist, everything else
// reduced to a redaction marker. The rendering never includes credential
// material, because the profile's authentication header is not on the list.
func diagHeaderView(headers http.Header) string {
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		if _, safe := diagSafeHeaderNames[name]; !safe {
			parts = append(parts, name+"=<redacted>")
			continue
		}
		value := strings.Join(headers.Values(name), ",")
		value = strings.ReplaceAll(value, "\n", " ")
		value = strings.ReplaceAll(value, "\r", " ")
		parts = append(parts, name+"="+truncateForLog(value, diagValueLimit))
	}
	return strings.Join(parts, " ")
}

// diagBalanceSummary renders the balance rows one quota refresh saw, for the
// operator to compare against what the Messages endpoint concluded. Numbers
// are printed only when the upstream stated them; a nil pointer prints as a
// dash rather than a false zero. Capability entries are model ids the
// upstream itself declared.
func diagBalanceSummary(balances []quotaBalance) string {
	const maxRows = 8
	parts := make([]string, 0, len(balances))
	for i, balance := range balances {
		if i == maxRows {
			parts = append(parts, fmt.Sprintf("(+%d more)", len(balances)-maxRows))
			break
		}
		remaining := "-"
		if balance.Remaining != nil {
			remaining = fmt.Sprintf("%g", *balance.Remaining)
		}
		total := "-"
		if balance.Total != nil {
			total = fmt.Sprintf("%g", *balance.Total)
		}
		row := fmt.Sprintf("%s{remaining=%s,total=%s", balance.Name, remaining, total)
		if len(balance.Capabilities) > 0 {
			row += ",caps=[" + truncateForLog(strings.Join(balance.Capabilities, ","), diagValueLimit) + "]"
		}
		if balance.Malformed {
			row += ",malformed"
		}
		row += "}"
		parts = append(parts, row)
	}
	return strings.Join(parts, " ")
}

// diagPlanSummary renders the plan rows one quota refresh saw, with the
// effective status the term-end check settled — the fact that decides whether
// the plugin reads the account as entitled at all.
func diagPlanSummary(plans []quotaPlan) string {
	parts := make([]string, 0, len(plans))
	for _, plan := range plans {
		ends := "-"
		if plan.EndsAt != nil {
			ends = time.Unix(int64(*plan.EndsAt), 0).UTC().Format(time.RFC3339)
		}
		name := plan.Name
		if name == "" {
			name = "(unnamed)"
		}
		parts = append(parts, fmt.Sprintf("%s{status=%s,ends=%s}", name, plan.Status, ends))
	}
	return strings.Join(parts, " ")
}
