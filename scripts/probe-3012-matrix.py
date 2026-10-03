#!/usr/bin/env python3
"""3012 differential matrix probe for the ZCode Coding Plan gateway.

Sends single-variable variants of the Messages request against the live
upstream and records the verdict (200 / 3012 / other) for each, so the gate
condition can be read off the table rather than inferred. The account's plan
buckets are read before and after the run so a billed 200 can be told apart
from an admitted-but-refused one.

Every system-block text is loaded from a file rather than inlined here: the
gate reads block text byte-for-byte, so a truncated or hand-typed block would
test the wrong thing.

Usage:
    probe-3012-matrix.py --jwt-file <path> --device-mid <uuid> \\
        --blocks-dir <dir> [--out <path>]
"""

import argparse
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request
import uuid

MESSAGES_URL = "https://zcode.z.ai/api/v1/zcode-plan/anthropic/v1/messages"
BALANCE_URL = "https://zcode.z.ai/api/v1/zcode-plan/billing/balance?app_version=3.14.4"

UA_FULL = "ZCode/3.14.4 ai/6.0.193 ai-sdk/provider-utils/4.0.27 runtime/node.js/24"
UA_NO_AI = "ZCode/3.14.4 ai-sdk/provider-utils/4.0.27 runtime/node.js/24"


def unverified_ctx():
    # This probe reads the gateway's verdict as evidence; the transport's own
    # authentication is not what is under test.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def base_headers(jwt, device_mid, session_id):
    """The header set the official client used on its captured 200 requests."""
    rid = str(uuid.uuid4())
    return {
        "authorization": "Bearer " + jwt,
        "x-api-key": jwt,
        "content-type": "application/json",
        "anthropic-version": "2023-06-01",
        "http-referer": "https://zcode.z.ai",
        "user-agent": UA_FULL,
        "x-zcode-app-version": "3.14.4",
        "x-zcode-agent": "glm",
        "x-title": "Z Code@electron",
        "x-platform": "win32-x64",
        "x-os-category": "windows",
        "x-os-version": "Windows 11 Pro",
        "x-client-language": "zh-CN",
        "x-client-timezone": "Asia/Shanghai",
        "x-release-channel": "production",
        "x-device-mid": device_mid,
        "x-request-id": rid,
        "x-query-id": rid,
        "x-zcode-trace-id": rid,
        "x-session-id": session_id,
        "x-zcode-session-type": "main",
    }


def block(text, cache_control=None):
    b = {"type": "text", "text": text}
    if cache_control is not None:
        b["cache_control"] = cache_control
    return b


def title_gen_body(b1, b2, title_system, **over):
    """The captured 200 baseline (event 115), rebuilt field by field."""
    body = {
        "model": "GLM-5.3-Flash",
        "max_tokens": 5000,
        "metadata": {"user_id": "{}"},
        "system": [block(title_system)],
        "messages": [{"role": "user", "content": [{"type": "text", "text": "Reply with OK."}]}],
        "thinking": {"type": "enabled"},
        "output_config": {"effort": "low"},
    }
    return apply_over(body, over)


def bare_probe_body(**over):
    """The shape that drew 3012 in the capture (event 124)."""
    body = {
        "model": "GLM-5.3-Flash",
        "max_tokens": 16,
        "stream": True,
        "messages": [{"role": "user", "content": "Reply with OK."}],
        "metadata": {"user_id": "{}"},
    }
    return apply_over(body, over)


def agent_body(b1, b2, **over):
    """The captured agent shape (event 109): official b1+b2 leading."""
    body = {
        "model": "GLM-5.3-Flash",
        "max_tokens": 128000,
        "stream": True,
        "metadata": {"user_id": "{}"},
        "system": [block(b1, {"type": "ephemeral"}), block(b2, {"type": "ephemeral"})],
        "messages": [{"role": "user", "content": [{"type": "text", "text": "Reply with OK."}]}],
        "thinking": {"type": "enabled"},
        "output_config": {"effort": "max"},
    }
    return apply_over(body, over)


def apply_over(body, over):
    for k, v in over.items():
        if v is None:
            body.pop(k, None)
        else:
            body[k] = v
    return body


def post(url, body, headers, ctx, timeout=90):
    data = json.dumps(body, separators=(",", ":")).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001 - "no answer" is a verdict, not a crash
        return None, repr(e)


def get_buckets(url, jwt, device_mid, session_id, ctx):
    headers = base_headers(jwt, device_mid, session_id)
    for drop in ("x-api-key", "x-zcode-agent", "anthropic-version", "content-type"):
        headers.pop(drop, None)
    headers["accept"] = "*/*"
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=40, context=ctx) as r:
            payload = json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}", "body": e.read().decode("utf-8", "replace")[:200]}
    except Exception as e:  # noqa: BLE001
        return {"error": repr(e)}
    return {b.get("show_name"): b.get("remaining_units")
            for b in (payload.get("data") or {}).get("balances") or []}


def classify(status, text):
    if status is None:
        return "no-answer"
    if re.search(r'"code"\s*:\s*3012', text):
        return "3012"
    if status == 200:
        return "200"
    if status == 405:
        return "405-no-business-code"
    return f"http-{status}"


def build_cases(b1, b2, title_system, b3=""):
    cases = []

    def case(name, body, header_over=None, note=""):
        cases.append({"name": name, "body": body,
                      "drop": (header_over or {}).pop("__drop__", []),
                      "set": {k: v for k, v in (header_over or {}).items()
                              if k != "__drop__"},
                      "note": note})

    off = lambda: [block(b1), block(b2)]
    off_cc = lambda: [block(b1, {"type": "ephemeral"}), block(b2, {"type": "ephemeral"})]
    plugin_meta = {"user_id": json.dumps(
        {"device_id": "d544db64-8bc3-4e44-9b73-7c7b7f7d1499", "account_uuid": "",
         "session_id": "16ae09d4-2381-4762-a1ba-8112b77db599"}, separators=(",", ":"))}

    # --- Row A: baselines replayed. ---
    case("A1 title-gen baseline replay (captured 200)", title_gen_body(b1, b2, title_system))
    case("A2 agent baseline replay (official b1+b2)",
         agent_body(b1, b2, metadata=plugin_meta))

    # --- Row B: single-variable removals from the title-gen 200 baseline. ---
    case("B1  200 baseline - thinking", title_gen_body(b1, b2, title_system, thinking=None))
    case("B2  200 baseline - output_config", title_gen_body(b1, b2, title_system, output_config=None))
    case("B3  200 baseline - thinking - output_config",
         title_gen_body(b1, b2, title_system, thinking=None, output_config=None))
    case("B4  200 baseline - system", title_gen_body(b1, b2, title_system, system=None))
    case("B5  200 baseline - metadata", title_gen_body(b1, b2, title_system, metadata=None))
    case("B6  200 baseline - max_tokens (dropped)",
         title_gen_body(b1, b2, title_system, max_tokens=None))
    case("B7  200 baseline - model (dropped)", title_gen_body(b1, b2, title_system, model=None))

    # --- Row C: build up from the captured 3012 shape. ---
    case("C1 captured-3012 shape verbatim", bare_probe_body())
    case("C2 C1 + system=official b1+b2", bare_probe_body(system=off()))
    case("C3 C1 + system=official b1+b2 +cache_control", bare_probe_body(system=off_cc()))
    case("C4 C1 + system=title-gen prompt", bare_probe_body(system=[block(title_system)]))
    case("C5 C1 + thinking + output_config",
         bare_probe_body(thinking={"type": "enabled"}, output_config={"effort": "low"}))
    case("C6 C1 + system=official b1+b2 + thinking + output_config",
         bare_probe_body(system=off(), thinking={"type": "enabled"}, output_config={"effort": "low"}))
    case("C7 C1 + system=title-gen + thinking + output_config",
         bare_probe_body(system=[block(title_system)], thinking={"type": "enabled"},
                         output_config={"effort": "low"}))
    case("C8 C1 + content as text block (not bare string)",
         bare_probe_body(messages=[{"role": "user",
                                    "content": [{"type": "text", "text": "Reply with OK."}]}]))

    # --- Row D: header variables on the 200 baseline. ---
    case("D1 200 baseline + anthropic-beta", title_gen_body(b1, b2, title_system),
         {"anthropic-beta": "mid-conversation-system-2026-04-07"})
    case("D2 200 baseline - ai/6.0.193 UA suffix", title_gen_body(b1, b2, title_system),
         {"user-agent": UA_NO_AI})
    case("D3 200 baseline - x-api-key dual auth", title_gen_body(b1, b2, title_system),
         {"__drop__": ["x-api-key"]})
    case("D4 200 baseline + Accept: text/event-stream", title_gen_body(b1, b2, title_system),
         {"accept": "text/event-stream"})
    case("D5 200 baseline - x-device-mid", title_gen_body(b1, b2, title_system),
         {"__drop__": ["x-device-mid"]})
    case("D6 200 baseline - x-session-id", title_gen_body(b1, b2, title_system),
         {"__drop__": ["x-session-id"]})
    case("D7 200 baseline - x-zcode-session-type", title_gen_body(b1, b2, title_system),
         {"__drop__": ["x-zcode-session-type"]})

    # --- Row E: what the plugin actually emits (prepareUpstreamPayload). ---
    plugin_base = {
        "model": "GLM-5.3-Flash",
        "max_tokens": 16,
        "stream": True,
        "metadata": plugin_meta,
        "messages": [{"role": "user", "content": [{"type": "text", "text": "Reply with OK."}]}],
        "system": off(),
    }
    case("E1 plugin shape (as emitted today)", dict(plugin_base))
    case("E2 plugin shape + thinking", dict(plugin_base, thinking={"type": "enabled"}))
    case("E3 plugin shape + thinking + output_config",
         dict(plugin_base, thinking={"type": "enabled"}, output_config={"effort": "low"}))
    case("E4 plugin shape + output_config only",
         dict(plugin_base, output_config={"effort": "low"}))
    case("E5 plugin shape, max_tokens=128000",
         dict(plugin_base, max_tokens=128000))
    case("E6 plugin shape + thinking + max_tokens=128000",
         dict(plugin_base, max_tokens=128000, thinking={"type": "enabled"}))

    # --- Row F: what must the system field actually be? ---
    # B4/C1/C5 show system is NECESSARY; C2/C3/C4 show the official blocks are
    # not the only accepted content. These isolate size, array shape, order.
    filler = lambda n, ch="A": block(ch * n)
    case("F1  system = one tiny block (42B)", bare_probe_body(system=[block(b1)]))
    case("F2  system = one 997B filler block", bare_probe_body(system=[filler(997)]))
    case("F3  system = one 4096B filler block", bare_probe_body(system=[filler(4096)]))
    case("F4  system = title prompt, first 500B", bare_probe_body(system=[block(title_system[:500])]))
    case("F5  system = title prompt, last 597B", bare_probe_body(system=[block(title_system[400:])]))
    case("F6  system = title prompt as a bare STRING",
         bare_probe_body(system=title_system))
    case("F7  system = official b1+b2, b2 cut to 500B",
         bare_probe_body(system=[block(b1), block(b2[:500])]))
    case("F8  system = official b2+b1 swapped (#16 V3)",
         bare_probe_body(system=[block(b2), block(b1)]))
    case("F9  system = tiny caller block BEFORE official b1+b2 (#16 Y1)",
         bare_probe_body(system=[block("You are a helpful assistant.")] + off()))
    case("F10 system = title block BEFORE official b1+b2",
         bare_probe_body(system=[block(title_system)] + off()))
    case("F11 system = official b1 alone, 42B", bare_probe_body(system=[block(b1)]))
    case("F12 system = official b2 alone, 2313B", bare_probe_body(system=[block(b2)]))
    case("F13 system = b1+b2 merged into one block",
         bare_probe_body(system=[block(b1 + b2)]))

    # --- Row G: message shape, with system held present and official. ---
    # C8 drew 3012 but differed from C1 in content shape AND had no system,
    # so it does not isolate content shape.
    case("G1 system official + content bare string (#16-era shape)", bare_probe_body(system=off()))
    case("G2 system official + content text block",
         bare_probe_body(system=off(),
                         messages=[{"role": "user", "content": [{"type": "text", "text": "Reply with OK."}]}]))
    case("G3 system official + content empty block list",
         bare_probe_body(system=off(),
                         messages=[{"role": "user", "content": [{"type": "text", "text": "Hi"}]}]))

    # --- Row H: does max_tokens interact with the gate? ---
    case("H1 system official, max_tokens=1", bare_probe_body(system=off(), max_tokens=1))
    case("H2 system official, max_tokens=200000", bare_probe_body(system=off(), max_tokens=200000))
    case("H3 system official, GLM-5.2", bare_probe_body(system=off(), model="GLM-5.2"))
    case("H4 system official, GLM-5.3", bare_probe_body(system=off(), model="GLM-5.3"))

    # --- Row I: is the gate a size threshold or content recognition? ---
    # Same text, progressively longer prefix, for two unrelated official
    # prompts. If both cross at the same length the gate reads size; if they
    # disagree it reads content.
    for n in (600, 800, 1000, 1400, 1800, 2000, 2200, 2300):
        case(f"I-b2[:{n}] official b1 + b2 prefix ({len(b1) + n}B)",
             bare_probe_body(system=[block(b1), block(b2[:n])]))
    for n in (300, 500, 600, 700, 800, 900, 950, 997):
        case(f"I-title[:{n}] title prompt prefix ({n}B)",
             bare_probe_body(system=[block(title_system[:n])]))

    # --- Row J: bytes or tokens? Same byte size, different token density. ---
    prose = (b2 + " " + title_system)
    while len(prose) < 20000:
        prose += " " + b2
    prose = prose[:20000]
    case("J1  20000B of 'A' (very low token density)",
         bare_probe_body(system=[block("A" * 20000)]))
    case("J2  20000B of natural prose (high token density)",
         bare_probe_body(system=[block(prose)]))
    case("J3  7565B official b3 block verbatim",
         bare_probe_body(system=[block(b3)]))
    case("J4  7565B of 'A' (same bytes as b3, opposite density)",
         bare_probe_body(system=[block("A" * len(b3))]))
    case("J5  b3 verbatim + padding blocks of 'A'",
         bare_probe_body(system=[block(b3)] + [block("A" * 4000)] * 3))

    # --- Row K: the plugin's own code paths (injectOfficialSystemPrefix). ---
    # Each of these is what prepareUpstreamPayload emits for one caller shape.
    caller_text = "You are a helpful coding assistant."
    case("K1 caller has NO system -> plugin emits [b1,b2]", bare_probe_body(system=off()))
    case("K2 caller system STRING -> plugin emits [b1,b2,caller]",
         bare_probe_body(system=off() + [block(caller_text)]))
    case("K3 caller system ARRAY not official -> plugin emits [b1,b2,caller]",
         bare_probe_body(system=off() + [block(caller_text)]))
    case("K4 caller already official -> plugin leaves untouched", bare_probe_body(system=off()))
    case("K5 caller system [b2,b1] swapped -> plugin prepends b1,b2",
         bare_probe_body(system=[block(b1), block(b2), block(b2), block(b1)]))
    case("K6 full agent flow: b1+b2+thinking+effort max+stream+metadata",
         bare_probe_body(system=off(), max_tokens=128000,
                         thinking={"type": "enabled"}, output_config={"effort": "max"},
                         metadata=plugin_meta))

    # --- Row L: order sensitivity and the b1/b2 relationship. ---
    case("L1 b1+b2 as ONE merged block (#16 V4)", bare_probe_body(system=[block(b1 + b2)]))
    case("L2 b1 only, repeated 3x", bare_probe_body(system=[block(b1)] * 3))
    case("L3 b2 alone", bare_probe_body(system=[block(b2)]))
    case("L4 b2 + b1 (swapped)", bare_probe_body(system=[block(b2), block(b1)]))

    # --- Row M: contiguous run vs position vs total length. ---
    # Discriminates "the system must contain a long contiguous slice of some
    # known official prompt" from "the system must open with a specific text".
    case("M1 b2[:1400] alone, no b1", bare_probe_body(system=[block(b2[:1400])]))
    case("M2 b1 + b2 middle slice [900:1400], no official head",
         bare_probe_body(system=[block(b1), block(b2[900:1400])]))
    case("M3 b1 + title_system complete (two official texts)",
         bare_probe_body(system=[block(b1), block(title_system)]))
    case("M4 b1 + title_system[:950]", bare_probe_body(system=[block(b1), block(title_system[:950])]))
    case("M5 title_system complete + trailing filler",
         bare_probe_body(system=[block(title_system), block("A" * 5000)]))
    case("M6 b1 + b2[:1400] + caller block", bare_probe_body(
        system=[block(b1), block(b2[:1400]), block("You are a helpful assistant.")]))
    case("M7 b1 + b2[:1200]", bare_probe_body(system=[block(b1), block(b2[:1200])]))
    case("M8 b1 + b2[:1100]", bare_probe_body(system=[block(b1), block(b2[:1100])]))
    case("M9 b1 + b2[:1050]", bare_probe_body(system=[block(b1), block(b2[:1050])]))

    return cases


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jwt-file", required=True)
    ap.add_argument("--device-mid", required=True)
    ap.add_argument("--blocks-dir", required=True,
                    help="dir with b1.txt, b2.txt, title_system.txt extracted from the capture")
    ap.add_argument("--out", required=True)
    ap.add_argument("--only", default="", help="substring filter on case name")
    args = ap.parse_args()

    def load(name):
        with open(os.path.join(args.blocks_dir, name), encoding="utf-8") as fh:
            return fh.read()

    b1, b2, title_system = load("b1.txt"), load("b2.txt"), load("title_system.txt")
    b3 = load("b3.txt") if os.path.exists(os.path.join(args.blocks_dir, "b3.txt")) else ""
    print(f"blocks: b1={len(b1)}B b2={len(b2)}B b3={len(b3)}B title_system={len(title_system)}B", flush=True)

    jwt = open(args.jwt_file).read().strip()
    ctx = unverified_ctx()
    session_id = str(uuid.uuid4())

    before = get_buckets(BALANCE_URL, jwt, args.device_mid, session_id, ctx)
    print("buckets before:", before, flush=True)

    results = []
    for c in build_cases(b1, b2, title_system, b3):
        if args.only and args.only not in c["name"]:
            continue
        headers = base_headers(jwt, args.device_mid, session_id)
        for name in c["drop"]:
            headers.pop(name, None)
        headers.update(c["set"])
        status, text = post(MESSAGES_URL, c["body"], headers, ctx)
        verdict = classify(status, text)
        m = re.search(r'"logid":"([^"]+)"', text)
        results.append({
            "name": c["name"], "verdict": verdict, "status": status,
            "logid": m.group(1) if m else "",
            "body_bytes": len(json.dumps(c["body"], separators=(",", ":"))),
            "resp_head": text[:200].replace("\n", " "),
        })
        print(f"{verdict:>6}  HTTP {str(status):>4}  {c['name']}", flush=True)
        if verdict not in ("200", "3012"):
            print("        resp:", text[:200], flush=True)

    after = get_buckets(BALANCE_URL, jwt, args.device_mid, session_id, ctx)
    print("buckets after:", after, flush=True)

    with open(args.out, "w") as fh:
        json.dump({
            "messages_url": MESSAGES_URL,
            "device_mid": args.device_mid,
            "session_id": session_id,
            "block_lengths": {"b1": len(b1), "b2": len(b2), "b3": len(b3), "title_system": len(title_system)},
            "buckets_before": before,
            "buckets_after": after,
            "results": results,
        }, fh, indent=2, ensure_ascii=False)
    print("wrote", args.out)


if __name__ == "__main__":
    sys.exit(main())