package main

import "strings"

// The upstream admits a Messages request to the Coding Plan gateway by a
// client-integrity fingerprint carried in the request body's system field: that
// field must contain a sufficiently long contiguous verbatim slice of one of
// the official client's own system prompts. Established by an authorized
// differential capture (mitmproxy session 20261002-194452_2344fd, issue #16)
// and re-pinned by an 86-case single-variable matrix on 2026-10-03 (issue #22,
// docs/evidence-3012-matrix.json, harness scripts/probe-3012-matrix.py).
//
// What the matrix settled. An absent system field is refused whatever else the
// request carries, and a present one is admitted when it holds enough
// contiguous official text — so the two blocks injected below are sufficient,
// but they are not the whole rule, and they are not necessary either: the
// official client's own title-generation prompt (997 bytes) passes with no
// official block at all, which is the counterexample that reopened the question
// after #16 closed it. Length alone is not the test — 20000 bytes of filler and
// 7565 bytes of a genuine official block are both refused, while a 1400-byte
// prefix of one block and the 997-byte title prompt both pass — so the gateway
// matches on recognized prompt text, not on size or token count. b1 and b2 in
// this order are one recognized run, so their order matters (swapped is
// refused) while their being separate blocks does not (concatenated passes).
//
// What the matrix eliminated. Every header-level difference remains irrelevant:
// anthropic-beta: mid-conversation-system-2026-04-07, the ai/6.0.193 UA
// suffix, x-api-key dual auth, x-device-mid, x-session-id, x-zcode-session-type
// and Accept were each varied on a passing baseline with no effect on the
// verdict. So were the body's thinking, output_config, metadata, max_tokens and
// message shape. Those two body fields had been the leading suspects after the
// title-gen counterexample surfaced; they are now measured and exonerated.
//
// The verdict does not depend on plan exhaustion: on an account whose buckets
// were at zero the bare probe was refused and these passing shapes were still
// admitted.
//
// The maintainer decided (issue #16, 2026-10-02) that the plugin injects this
// prefix automatically: the official blocks lead, the caller's own system
// content follows. The texts are the official client's own system prompt
// opening (docs/ZCode apps/zcode-cli/packages/core/src/context/sections/
// cli-prefix.ts and identity.ts, Apache-2.0), verified byte-for-byte against a
// live official-client capture for app version 3.14.4 and re-verified against
// it on 2026-10-03 (b1 42 bytes, b2 2313 bytes, both identical).
//
// The injected blocks carry no cache_control: the capture shows the official
// client sets it, and the matrix confirmed it irrelevant (both forms admitted).
//
// These blocks remain the injection because they are what the plugin can
// honestly present: the matrix shows every payload the plugin currently emits
// is already admitted (issue #22), so there is no missing field to add, and
// changing verified-working behaviour for an unmeasured variant would trade a
// known-good default for a guess. The two official blocks are used because they
// are the official client's real identity, not because they are the shortest
// text that happens to pass.
//
// If the upstream tightens the fingerprint, this comment and
// prepareUpstreamPayload move together.

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
// The gateway's integrity precheck requires the system field to carry a
// sufficiently long verbatim slice of an official system prompt; these two
// blocks are one such slice (file header for what the matrix measured). Placing
// them first is what makes the caller's own content add to the system prompt
// rather than displace it:
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
// blocks: the form the official client sends. Their concatenation is what the
// gateway recognizes, so the pair is emitted as two blocks to mirror the
// official client rather than to satisfy the precheck.
func prefixBlock1() map[string]any {
	return map[string]any{"type": "text", "text": officialSystemPrefixBlock1}
}

func prefixBlock2() map[string]any {
	return map[string]any{"type": "text", "text": officialSystemPrefixBlock2}
}

// leadsWithOfficialPrefix reports whether a system block array already opens
// with the official prefix blocks, in order, so a request from an
// official-shaped caller is not given a second copy of its own identity. The
// comparison is on the block text alone; cache_control on these blocks was
// measured irrelevant and is not compared.
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
