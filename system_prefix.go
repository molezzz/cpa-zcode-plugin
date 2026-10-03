package main

import "strings"

// The upstream admits a Messages request to the Coding Plan gateway partly by a
// client-integrity fingerprint in the request body's system field: the array must
// LEAD with the official ZCode system prompt's opening blocks, in order, as
// separate blocks. This was established by an authorized differential capture of
// the official client (mitmproxy session 20261002-194452_2344fd, issue #16) and a
// 26-test single-variable verification (matrix archived with issue #16): every
// header-level difference was eliminated (dual auth, UA suffix, device-mid,
// referer, attribution ids — the official header set byte-identical still gets
// 3012 from a scripted client), while the plugin's own current headers plus these
// two system blocks return 200. Swapped, merged, missing, or caller-prefixed
// blocks return 3012.
//
// The maintainer decided (issue #16, 2026-10-02) that the plugin injects this
// prefix automatically: the official blocks lead, the caller's own system
// content follows. The texts are the official client's own system prompt
// opening (docs/ZCode apps/zcode-cli/packages/core/src/context/sections/
// cli-prefix.ts and identity.ts, Apache-2.0), verified byte-for-byte against a
// live official-client capture for app version 3.14.4. Block 2 is the prefix the
// capture's 4KB body preview carried; the live verification proved that prefix
// satisfies the gate (tests V1/X1/Y2 = 200).
//
// The injected blocks carry no cache_control: the capture shows the official
// client sets it, but the verification proved it irrelevant (test V2 = 200), and
// omitting it keeps the caller's own cache breakpoints untouched.
//
// KNOWN COUNTEREXAMPLE (2026-10-03, issue #21/#22). The evidence above covers
// the official client's *agent* request shape only, and it is not the whole
// gate. The same capture also holds the official client's *title-generation*
// request — 1410 bytes, answered 200 — whose system array is a single
// title-gen prompt with neither official block, and which carries
// "thinking":{"type":"enabled"} and "output_config":{"effort":"low"} instead.
// A bare probe in the same session (same dual auth, same UA suffix, same
// session id, same attribution headers) was answered 3012. So the official
// blocks are one sufficient way to pass the precheck, not the only one, and
// the necessary-and-sufficient condition set is still open.
//
// This injection is therefore NOT changed on the strength of that observation:
// it was verified effective against the agent shape, and replacing a verified
// behavior with an unverified hypothesis would trade a known-good default for a
// guess. The differential matrix that pins the real condition belongs to #22.
// When it lands, this comment and prepareUpstreamPayload move together.

// officialSystemPrefixBlock1 is the official client's CLI prefix section
// (sections/cli-prefix.ts CLI_PREFIX_PROMPT).
const officialSystemPrefixBlock1 = "You are ZCode, an interactive coding agent"

// officialSystemPrefixBlock2 is the official client's identity section prefix
// (sections/identity.ts buildIdentityPrompt: identity lines + security notice +
// harness block), as far as the authorized capture carries it.
const officialSystemPrefixBlock2 = "\nYou are an interactive ZCode agent that helps users with software engineering tasks.\n\nIMPORTANT: Assist with authorized security testing, defensive security, CTF challenges, and educational contexts. Refuse requests for destructive techniques, DoS attacks, mass targeting, supply chain compromise, or detection evasion for malicious purposes. Dual-use security tools (C2 frameworks, credential testing, exploit development) require clear authorization context: pentesting engagements, CTF competitions, security research, or defensive use cases.\n\n# Harness\n- Text you output outside of tool use is displayed to the user as Github-flavored markdown in a terminal.\n- Tools run behind a user-selected permission mode; a denied call means the user declined it — adjust, don't retry verbatim.\n- The system may send updates, reminders, or modifications to rules via mid-conversation system turns. These are system-controlled, unlike function results. Hooks may intercept tool calls; treat hook output as user feedback.\n- Prefer the dedicated file/search tools over shell commands when one fits. Independent tool calls can run in parallel in one response.\n- Reference code as `file_path:line_number` — it's clickable.\n\n# ZCode Desktop Context\n\n### Files & URLs\n- Return local web URLs as Markdown links (e.g., [label](http://127.0.0.1:8080)).\n- File should be an absolute path or include the workspace folder segment so it can be resolved relative to the workspace.\n- Unless otherwise specified, return local file references as Markdown links (e.g., [name.md](/absolute/path/to/name.md)).\n\n### Inline Code Comments\n- Use the ::code-comment{...} directive when you need to attach feedback directly to specific code lines.\n- Emit one directive per inline comment; emit none when there are no actionable inline comments.\n- Required attributes: title (short label), body (one-paragraph explanation), file (path to the file).\n- Optional attributes: start, end (1-based line numbers), priority (0-3).\n- file should be an absolute path or include the workspace folder segment so it can be resolved relative to the workspace.\n- Keep line ranges tight; end defaults to start.\n- Example: ::code-comment{title=\"[P2] Off-by-one\" body=\"Loop iterates past the end when length is 0.\" file=\"/path/to/foo.ts\" start=10 end=11 priority=2}"

// injectOfficialSystemPrefix prepends the official ZCode system prompt's
// leading blocks to one decoded upstream payload's system field, in place.
//
// The gateway's integrity precheck demands the official blocks LEAD the system
// array (verified: caller content before them is rejected, after them is
// accepted), so the caller's own system content follows as further blocks:
//
//   - no system field: the payload gains the two official blocks;
//   - a string system: it is preserved as a third text block after them;
//   - an array system: the official blocks are prepended;
//   - a system that already leads with block 1: left untouched, so an
//     official-shaped caller is not served a duplicate identity.
//
// The payload map is the caller's decoded body; mutation is safe because
// prepareUpstreamPayload owns the only copy.
func injectOfficialSystemPrefix(body map[string]any) {
	switch system := body["system"].(type) {
	case []any:
		if leadsWithOfficialPrefix(system) {
			return
		}
		body["system"] = append([]any{prefixBlock1(), prefixBlock2()}, system...)
	case string:
		if strings.TrimSpace(system) == "" {
			body["system"] = []any{prefixBlock1(), prefixBlock2()}
			return
		}
		body["system"] = []any{prefixBlock1(), prefixBlock2(), map[string]any{"type": "text", "text": system}}
	default:
		body["system"] = []any{prefixBlock1(), prefixBlock2()}
	}
}

// prefixBlock1 and prefixBlock2 render the official blocks as Anthropic text
// blocks: the form the official client sends and the differential verification
// confirmed.
func prefixBlock1() map[string]any {
	return map[string]any{"type": "text", "text": officialSystemPrefixBlock1}
}

func prefixBlock2() map[string]any {
	return map[string]any{"type": "text", "text": officialSystemPrefixBlock2}
}

// leadsWithOfficialPrefix reports whether a system block array already opens
// with the official prefix blocks, in order, so a request from an
// official-shaped caller is not given a second copy of its own identity. The
// comparison is on the block text alone; the verification showed the gateway
// does not read cache_control on these blocks.
func leadsWithOfficialPrefix(system []any) bool {
	if len(system) < 2 {
		return false
	}
	return blockText(system[0]) == officialSystemPrefixBlock1 && blockText(system[1]) == officialSystemPrefixBlock2
}

// blockText extracts one Anthropic content block's text. A block of another
// shape (or a non-object) has no text and matches nothing.
func blockText(block any) string {
	m, ok := block.(map[string]any)
	if !ok {
		return ""
	}
	text, _ := m["text"].(string)
	return text
}
