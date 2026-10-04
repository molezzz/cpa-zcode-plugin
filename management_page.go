package main

// managementPageHTML is the static management page. It carries no data and no
// secret: everything dynamic is fetched from the authenticated management
// routes with the operator's management key and written through DOM
// textContent / attribute assignments, never HTML interpolation.
//
// The page is also served from the unauthenticated resource route that carries
// the host's navigation entry, so the shell must stay a constant: the host does
// not HTML-escape resource responses, and anything interpolated here would reach
// every unauthenticated visitor. That is also why the resource route serves no
// data and the key is supplied by the operator at runtime — the page opens with
// no accounts rendered and stays that way until a key is entered.
//
// Operator-facing copy is Chinese; protocol identifiers (action names, JSON
// field names, the localStorage keys) stay verbatim in English because they are
// the wire contract, and a translated action name would be rejected by the
// route.
//
// Layout follows the workbuddy-cliproxy-plus management page: dark surfaces,
// one card per account on a responsive grid, a remaining-quota progress bar per
// bucket, and a status message line instead of a JSON dump area. There is no
// auto-refresh timer: the page paints a cached snapshot (kept in localStorage)
// with actions disabled, then revalidates once against the live state, and
// every later reload is operator-initiated.
//
// Asynchronous responses guard on a generation counter so a slow older reply
// can never overwrite newer state, and action buttons disable themselves while
// a request is in flight so an action cannot be submitted twice.
const managementPageHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ZCode 管理</title>
<style>
  :root {
    color-scheme: dark;
    --bg: #0a0a0d;
    --surface: #17171a;
    --surface-raised: #09090b;
    --border: #303034;
    --text: #dedfe0;
    --text-muted: #a1a1aa;
    --primary: #c8ff00;
    --primary-press: #d9ff57;
    --ok: #00bf6f;
    --warn: #ffc41f;
    --bad: #ff2d55;
    --info: #fcfcfe;
    --radius: 10px;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 24px 20px 48px;
    background: var(--bg); color: var(--text);
    font: 14px/1.6 system-ui, -apple-system, "PingFang SC", "Microsoft YaHei", sans-serif;
  }
  .page { max-width: 1180px; margin: 0 auto; }
  h1 { margin: 0; font-size: 20px; font-weight: 650; letter-spacing: -.01em; color: var(--primary); }
  h2 { margin: 0; font-size: 15px; font-weight: 600; }
  .subtitle { margin: 6px 0 4px; color: var(--text-muted); font-size: 13px; }

  /* One status line for everything the operator must read now: results,
     failures, and the snapshot notice all land here with a severity class. */
  #message { min-height: 1.5rem; margin: 8px 0 16px; font-size: 13px; color: var(--ok); }
  #message.error { color: var(--bad); }
  #message.pending { color: var(--text-muted); }

  .card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); margin-bottom: 16px; overflow: hidden;
  }
  .card-head {
    display: flex; align-items: center; justify-content: space-between; gap: 12px;
    padding: 14px 16px; border-bottom: 1px solid var(--border);
  }
  .card-head .count { color: var(--text-muted); font-size: 12px; font-weight: 400; }
  .card-body.padded { padding: 16px; }

  table { border-collapse: collapse; width: 100%; }
  th {
    text-align: left; font-size: 12px; font-weight: 600; color: var(--text-muted);
    padding: 9px 16px; border-bottom: 1px solid var(--border); white-space: nowrap;
  }
  td { padding: 11px 16px; border-bottom: 1px solid var(--border); vertical-align: top; font-size: 13px; }
  tbody tr:last-child td { border-bottom: none; }
  .empty { padding: 28px 16px; text-align: center; color: var(--text-muted); font-size: 13px; }

  /* Status pills carry the verdict as text, not only as colour, so the state
     stays legible to a reader who cannot distinguish the hues. */
  .pill {
    display: inline-block; padding: 2px 9px; border-radius: 999px;
    font-size: 12px; font-weight: 600; line-height: 1.7; white-space: nowrap;
    background: #26262b; color: var(--text-muted); border: 1px solid transparent;
  }
  .pill-ok { background: rgba(0,191,111,.12); color: var(--ok); border-color: rgba(0,191,111,.45); }
  .pill-warn { background: rgba(255,196,31,.1); color: var(--warn); border-color: rgba(255,196,31,.45); }
  .pill-bad { background: rgba(255,45,85,.12); color: var(--bad); border-color: rgba(255,45,85,.45); }

  .stack { display: flex; flex-direction: column; gap: 3px; }
  .sub { font-size: 12px; color: var(--text-muted); }
  /* align-items: center keeps a text sibling (the item count) on the same
     optical line as the buttons next to it. Without it flex stretches that
     span to the button's height and pins its text to the top of the box. */
  .actions { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }

  button {
    font: inherit; font-size: 12px; cursor: pointer; border-radius: 7px;
    border: 1px solid var(--border); background: var(--surface-raised); color: var(--text);
    padding: 5px 11px; transition: background .12s, border-color .12s;
  }
  button:hover:not(:disabled) { border-color: var(--primary); color: var(--primary); }
  button:disabled { opacity: .45; cursor: default; }
  button.primary { background: var(--primary); border-color: var(--primary); color: #0a0a0d; font-weight: 600; }
  button.primary:hover:not(:disabled) { background: var(--primary-press); border-color: var(--primary-press); color: #0a0a0d; }
  button.loading { opacity: .8; cursor: progress; }
  button.loading::before {
    content: ""; display: inline-block; width: .65em; height: .65em; margin-right: .35rem;
    border: .125em solid currentColor; border-right-color: transparent; border-radius: 50%;
    vertical-align: .05em; animation: button-spin .7s linear infinite;
  }
  @keyframes button-spin { to { transform: rotate(360deg); } }

  input {
    font: inherit; font-size: 13px; padding: 6px 10px; border-radius: 7px;
    border: 1px solid var(--border); background: var(--bg); color: var(--text); min-width: 260px;
  }
  input:focus { outline: none; border-color: var(--primary); }

  details.raw {
    margin-top: 12px; border: 1px solid var(--border); border-radius: var(--radius);
    background: var(--surface); padding: 10px 14px;
  }
  details.raw summary { cursor: pointer; color: var(--text-muted); font-size: 12px; }
  details.raw pre {
    margin: 10px 0 0; font: 12px/1.6 ui-monospace, SFMono-Regular, Menlo, monospace;
    white-space: pre-wrap; overflow-wrap: anywhere; color: var(--text);
  }
  .link-cell { margin-top: 10px; }
  .link-cell a { color: var(--primary); }

  /* Account cards: one card per account on a responsive grid, replacing the
     wide one-row-per-account table that forced horizontal scanning. */
  #accounts { display: grid; grid-template-columns: repeat(auto-fill, minmax(20rem, 1fr)); gap: .75rem; }
  .account {
    border: 1px solid var(--border); border-radius: var(--radius);
    background: var(--surface); padding: 14px; min-width: 0;
  }
  .account h2 { font-size: 14px; color: var(--info); overflow-wrap: anywhere; }
  .account .identity { font: 11px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace; color: var(--text-muted); overflow-wrap: anywhere; }
  .account .unreadable { margin-top: 8px; }

  /* Quota bucket: a "remaining" bar coloured by share, with the full bucket
     evidence kept as text below it. The bar is drawn only when the plugin
     already computed remaining_fraction; an unread share is never drawn. */
  .bucket { margin: 10px 0 0; }
  .bucket-head {
    display: flex; justify-content: space-between; gap: 8px;
    font-size: 12px; color: var(--text-muted);
  }
  .bucket-head .bucket-name { color: var(--text); overflow-wrap: anywhere; }
  .bar { height: .5rem; margin-top: .3rem; border-radius: 999px; background: #26262b; overflow: hidden; }
  .bar-fill { height: 100%; border-radius: 999px; background: var(--primary); transition: width .3s ease; }
  .bar-fill.warn { background: var(--warn); }
  .bar-fill.danger { background: var(--bad); }
  .bucket-lines { margin-top: 4px; font-size: 12px; color: var(--text-muted); line-height: 1.55; }

  /* Quota axes: one section per billing plan. A Start Plan allowance and a
     general Coding Plan allowance are different things to act on, so they get
     their own headings instead of one flat run of buckets where "18% left"
     names no plan. */
  .quota-axis { margin-top: 12px; padding-top: 8px; border-top: 1px solid var(--border); }
  .quota-axis:first-child { border-top: 0; padding-top: 0; margin-top: 8px; }
  .axis-head { display: flex; align-items: baseline; gap: 8px; font-size: 12px; }
  .axis-head .axis-kind { color: var(--text); }
  .axis-head .axis-plan { color: var(--text-muted); overflow-wrap: anywhere; }

  dl.facts {
    display: grid; grid-template-columns: max-content minmax(0, 1fr);
    gap: 4px 12px; margin: 12px 0 0; font-size: 12.5px;
  }
  dl.facts dt { color: var(--text-muted); white-space: nowrap; }
  dl.facts dd { margin: 0; min-width: 0; overflow-wrap: anywhere; }
</style>
</head>
<body>
<div class="page">
<h1>ZCode 管理</h1>
<p class="subtitle">上游身份、凭证与额度的脱敏运行状态。密钥、授权参数、上游响应原文与用户 prompt 永不展示。</p>

<div id="message" role="status" aria-live="polite"></div>

<div class="card">
  <div class="card-head">
    <h2>管理密钥</h2>
    <span id="key-state" class="count"></span>
  </div>
  <div class="card-body padded">
    <div id="key-fields">
      <div class="actions" style="align-items:center">
        <input id="management-key" type="password" autocomplete="off" spellcheck="false" placeholder="粘贴管理密钥">
        <button id="save-key" class="primary" type="button">保存</button>
        <button id="clear-key" type="button">清除</button>
      </div>
      <p class="sub" style="margin:10px 0 0">
        本页只是静态外壳：下方所有账号、额度与凭证状态都用这里填入的密钥取回。密钥只保存在本浏览器的
        localStorage，以 Bearer 方式发送，一旦请求被拒绝即从本地删除。
      </p>
    </div>
    <button id="key-show" type="button" hidden>🔑 管理密钥已保存，点击可重新设定</button>
  </div>
</div>

<div class="card">
  <div class="card-head">
    <h2>账号</h2>
    <div class="actions">
      <span id="accounts-count" class="count"></span>
      <button id="login-zai" type="button">国际站 z.ai 登录</button>
      <button id="login-bigmodel" type="button">国内站 bigmodel 登录</button>
      <button id="reload-state" class="primary" type="button">刷新状态</button>
      <button id="batch-refresh" type="button">刷新全部账号</button>
    </div>
  </div>
  <div class="card-body padded">
    <div id="accounts"></div>
  </div>
</div>

<div class="card">
  <div class="card-head">
    <h2>授权会话</h2>
    <span id="sessions-count" class="count"></span>
  </div>
  <div class="card-body">
    <table>
      <thead><tr><th>状态</th><th>上游身份</th><th>创建时间</th><th>到期时间</th><th>说明</th></tr></thead>
      <tbody id="sessions"></tbody>
    </table>
  </div>
</div>

<div class="card">
  <div class="card-head">
    <h2>模型缓存</h2>
    <span id="cache-count" class="count"></span>
  </div>
  <div class="card-body">
    <table>
      <thead><tr><th>上游身份</th><th>环境</th><th>状态</th><th>模型数</th><th>有效期至</th><th>原因</th></tr></thead>
      <tbody id="model-cache"></tbody>
    </table>
  </div>
</div>

<details id="raw" class="raw" hidden>
  <summary>最近一次操作结果(原始 JSON)</summary>
  <pre id="raw-body"></pre>
</details>

<script>
"use strict";
(function () {
  var STATE_URL = "/v0/management/zcode/state";
  var ACTION_URL = "/v0/management/zcode/action";
  var KEY_STORAGE = "zcode_management_key";
  var STATE_CACHE = "zcode_state_cache";
  var generation = 0;      // bumped per state fetch; stale replies are dropped

  var keyInput = document.getElementById("management-key");
  var keyFields = document.getElementById("key-fields");
  var keyState = document.getElementById("key-state");
  var keyShow = document.getElementById("key-show");
  var message = document.getElementById("message");
  var rawDetails = document.getElementById("raw");
  var rawBody = document.getElementById("raw-body");

  // localStorage is the only store the key may live in: sessionStorage dies
  // with the tab and a cookie would ride along on every host request. Each
  // access is guarded because a blocked or full store is an ordinary browser
  // state, not an error worth breaking the page over. The state snapshot is an
  // acceleration layer with the same guards: if it cannot be read or written,
  // the page falls back to the network path without complaint.
  function storedKey() {
    try {
      return window.localStorage.getItem(KEY_STORAGE) || "";
    } catch (error) {
      return "";
    }
  }

  function storeKey(key) {
    try {
      window.localStorage.setItem(KEY_STORAGE, key);
      return true;
    } catch (error) {
      return false;
    }
  }

  function clearStoredKey() {
    try {
      window.localStorage.removeItem(KEY_STORAGE);
      return true;
    } catch (error) {
      return false;
    }
  }

  function readCache() {
    try {
      var parsed = JSON.parse(window.localStorage.getItem(STATE_CACHE) || "null");
      return parsed && Array.isArray(parsed.accounts) ? parsed : null;
    } catch (error) {
      return null;
    }
  }

  function writeCache(data) {
    if (!data || !Array.isArray(data.accounts)) { return false; }
    try {
      window.localStorage.setItem(STATE_CACHE, JSON.stringify({ saved_at: Date.now(), data: data }));
      return true;
    } catch (error) {
      return false;
    }
  }

  function clearStateCache() {
    try {
      window.localStorage.removeItem(STATE_CACHE);
      return true;
    } catch (error) {
      return false;
    }
  }

  function show(text_, kind) {
    message.textContent = text_;
    message.className = kind || "";
  }

  // A saved key collapses the input row to one explicit re-entry button, so
  // the credential is not left sitting on screen while the operator reads
  // status — and re-setting it stays discoverable instead of hidden behind a
  // tiny secondary control.
  function showKeyPanel(collapsed) {
    keyFields.hidden = collapsed;
    keyShow.hidden = !collapsed;
    text(keyState, collapsed ? "已保存在本浏览器" : "");
  }

  // forgetKey drops a key that the host rejected or that the operator asked to
  // drop. Rendering is cleared with it: leaving the previous accounts on screen
  // after the key is gone would keep showing data the page can no longer
  // re-fetch or prove is still authorized.
  function forgetKey(text_, kind) {
    clearStoredKey();
    clearStateCache();
    generation += 1;
    keyInput.value = "";
    renderEmpty();
    hideRaw();
    showKeyPanel(false);
    keyInput.focus();
    if (text_) { show(text_, kind); }
  }

  // apiFetch is the page's only network entry point. Refusing to send without a
  // key is the point: the shell answers every visitor, and the data behind it
  // must not be requested at all until an operator supplies the key. A 401
  // means the stored key is wrong or revoked, so it is discarded rather than
  // retried — the page has no timer that would replay it anyway.
  function apiFetch(url, method, body) {
    var key = storedKey();
    if (!key) {
      return Promise.reject(new Error("请先填写并保存管理密钥"));
    }
    return fetch(url, {
      method: method,
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer " + key
      },
      body: body === undefined ? undefined : JSON.stringify(body)
    }).then(function (reply) {
      if (reply.status === 401) {
        forgetKey("管理密钥缺失或无效，请重新填写。", "error");
        return Promise.reject(new Error("unauthorized"));
      }
      return reply.json().catch(function () {
        return null;
      }).then(function (data) {
        return { ok: reply.ok, data: data };
      });
    });
  }

  function describeFailure(failure) {
    if (failure && failure.message === "unauthorized") { return ""; }
    return failure && failure.message ? failure.message : "请求未能发出";
  }

  function el(tag, className) {
    var node = document.createElement(tag);
    if (className) { node.className = className; }
    return node;
  }

  function text(node, value) {
    node.textContent = value === null || value === undefined ? "" : String(value);
    return node;
  }

  function cell(row, value, className) {
    var td = el("td", className);
    text(td, value);
    row.appendChild(td);
    return td;
  }

  function hideRaw() {
    rawDetails.hidden = true;
    text(rawBody, "");
  }

  function showRaw(label, data) {
    text(rawDetails.querySelector("summary"), "最近一次操作结果(原始 JSON)" + (label ? " · " + label : ""));
    text(rawBody, JSON.stringify(data, null, 2));
    rawDetails.hidden = false;
  }

  // The wire vocabulary is English; only the reading an operator acts on is
  // translated. Each verdict keeps its severity as a pill colour, and the
  // Chinese word carries the same information so the state is legible without
  // relying on hue.
  var CREDENTIAL_STATES = {
    active: ["可用", "pill-ok"],
    invalid: ["已失效", "pill-bad"],
    exhausted: ["额度耗尽", "pill-bad"],
    unavailable: ["不可用", "pill-bad"],
    verification_blocked: ["验证受阻", "pill-warn"],
    cooldown: ["冷却中", "pill-warn"],
    needs_selection: ["待选择", "pill-warn"],
    failed: ["失败", "pill-bad"],
    unknown: ["未知", ""]
  };

  function credentialPill(value) {
    var known = CREDENTIAL_STATES[value] || [value || "未知", ""];
    return statusSpan(known[0], known[1]);
  }

  function statusSpan(label, className) {
    var span = el("span", className ? "pill " + className : "pill");
    text(span, label);
    return span;
  }

  // appendStack writes a verdict plus optional secondary lines into one block,
  // so a credential's state, its error code and its age read as one fact rather
  // than as three unrelated fragments. It returns the block so a caller can
  // append it where it belongs.
  function appendStack(container, pill, lines) {
    var stack = el("div", "stack");
    stack.appendChild(pill);
    (lines || []).forEach(function (line) {
      if (line) { stack.appendChild(text(el("div", "sub"), line)); }
    });
    container.appendChild(stack);
    return container;
  }

  function jwtLines(jwt) {
    var lines = [];
    if (!jwt) { return lines; }
    if (jwt.last_error_code) { lines.push("错误码 " + jwt.last_error_code); }
    if (jwt.retry_after) { lines.push(jwt.retry_after + " 后可重试"); }
    if (jwt.last_checked_at) { lines.push("检查于 " + jwt.last_checked_at); }
    if (jwt.reauth_suggested) { lines.push("已超过重新授权期限,建议重新授权"); }
    return lines;
  }

  function apiKeyLines(key) {
    var lines = [];
    if (!key) { return lines; }
    if (key.name) { lines.push(key.name); }
    if (key.last_error && key.last_error.stage) {
      lines.push(key.last_error.stage + (key.last_error.message ? ":" + key.last_error.message : ""));
    }
    if (key.updated_at) { lines.push("更新于 " + key.updated_at); }
    return lines;
  }

  // Quota bucket recurrence as the page reads it. A one_time grant does not
  // come back, so showing it a reset time would tell an operator to wait for
  // something that will never arrive; a recurring window comes back on its own
  // and the reset time is what decides whether to switch accounts now. An
  // unread period is neither of those, and says so.
  //
  // The map is a translation, not a whitelist: an upstream spelling this page
  // does not know still renders as itself, because it is a real statement
  // about the bucket and hiding it behind "未知" would be worse than showing an
  // operator a term they have not seen before.
  var PERIOD_READINGS = {
    one_time: "一次性额度",
    daily: "每日额度",
    weekly: "每周额度",
    monthly: "每月额度"
  };
  var ONE_TIME_PERIOD = "one_time";

  function periodReading(period) {
    if (!period) { return "周期未知"; }
    return PERIOD_READINGS[period] || period;
  }

  // bucketInstant labels the upstream's expires_at by what that instant means
  // for this bucket. It is one instant and one reading: a one_time grant lapses
  // at it and never refills, so "到期" is the whole truth; a recurring window
  // refills at it, so "重置" is. An unread period proves neither, and the
  // instant is reported unlabelled rather than guessed into one of the two.
  function bucketInstant(balance) {
    if (!balance.period) { return whenReading(balance.expires_at); }
    return (balance.period === ONE_TIME_PERIOD ? "到期 " : "") + whenReading(balance.expires_at) +
      (balance.period === ONE_TIME_PERIOD ? "" : " 重置");
  }

  // An instant is formatted adaptively, matching the official client's rule: a
  // moment later today is actionable by its clock time alone, and one on
  // another day by its date alone. Printing the raw RFC3339 string would make an
  // operator do the timezone and comparison themselves. An instant in another
  // year keeps its year, because "1/1" read next to today's date is ambiguous
  // rather than merely terse.
  function whenReading(instant) {
    var when = new Date(instant);
    if (isNaN(when.getTime())) { return "时间未知"; }
    var now = new Date();
    var sameDay = when.getFullYear() === now.getFullYear() &&
      when.getMonth() === now.getMonth() && when.getDate() === now.getDate();
    if (sameDay) { return "今日 " + when.toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit", hour12: false }); }
    var sameYear = when.getFullYear() === now.getFullYear();
    return when.toLocaleDateString("zh-CN", sameYear
      ? { month: "numeric", day: "numeric" }
      : { year: "numeric", month: "numeric", day: "numeric" });
  }

  // An unreadable number is not a zero. Every optional field the upstream may
  // omit renders through this one helper, so a missing value reads as "未知"
  // rather than as a measurement the plugin never received.
  function unknownNumber(value) {
    return value === null || value === undefined ? "未知" : value.toLocaleString();
  }

  // quotaBucket renders one bucket: a remaining-share bar when the plugin
  // computed one, then the evidence lines. The bar width is the fraction the
  // Go side already derived — this page never divides remaining by total, so
  // it cannot disagree with the host quota group about the same bucket. A
  // bucket with no readable share keeps its text evidence and gets no bar:
  // an unread fraction is not a zero, and a bar drawn at 0% or 100% would
  // assert a measurement the plugin never received.
  function quotaBucket(balance) {
    var lines = [];
    var unit = balance.unit_type ? " " + balance.unit_type : "";
    lines.push(unknownNumber(balance.remaining) + " / " + unknownNumber(balance.total) + unit);
    // The upstream always states expires_at, but what it means depends on the
    // period: the same instant is a refill for a recurring window and a lapse
    // for a one_time grant.
    if (balance.expires_at) {
      lines.push(periodReading(balance.period) + "，" + bucketInstant(balance));
    } else {
      lines.push(periodReading(balance.period));
    }
    if (balance.meter) { lines.push("计量 " + balance.meter); }
    // The granted amount is not the bucket total: it is what the entitlement
    // handed over, and the gap between the two is how much of the grant this
    // window may spend. It is shown only when it differs, because for a bucket
    // sized to its own grant it repeats the total one line above.
    if (balance.grant !== null && balance.grant !== undefined &&
        balance.grant !== balance.total) {
      lines.push("授予 " + unknownNumber(balance.grant) + unit);
    }
    return lines;
  }

  // quotaBar builds the remaining-share bar for one bucket, or null when the
  // plugin did not hand over a fraction. The share is what remains, so a
  // nearly-empty bar is the danger state; thresholds read on the remaining
  // side (>=50% fine, 20–50% warn, <20% danger).
  function quotaBar(balance) {
    var fraction = balance.remaining_fraction;
    if (fraction === null || fraction === undefined) { return null; }
    var percent = Math.min(100, Math.max(0, fraction * 100));
    var wrap = el("div", "bucket");
    var head = el("div", "bucket-head");
    head.appendChild(text(el("span", "bucket-name"),
      (balance.name || "未命名额度") + (balance.malformed ? "(字段漂移)" : "")));
    head.appendChild(text(el("span"), "剩余 " + percent.toFixed(1) + "%"));
    var bar = el("div", "bar");
    var fill = el("div", "bar-fill" + (percent < 20 ? " danger" : percent < 50 ? " warn" : ""));
    fill.style.width = percent + "%";
    bar.appendChild(fill);
    wrap.appendChild(head);
    wrap.appendChild(bar);
    return wrap;
  }

  // quotaCard renders the quota slot of one account card: the entitlement
  // verdict, then one section per billing axis with its buckets. The four
  // readings an operator must tell apart — a plan with quota, an account the
  // upstream positively reports as having no plan, a lapsed plan, and a reading
  // the plugin could not make — stay distinct as pills before any bucket is
  // drawn.
  var QUOTA_STATES = {
    ok: ["有套餐且有额度", "pill-ok"],
    exhausted: ["套餐额度耗尽", "pill-bad"],
    no_plan: ["该账号没有 Coding Plan", "pill-warn"],
    plan_expired: ["套餐已到期", "pill-bad"],
    unknown: ["未知(上游返回无法解析)", "pill-warn"],
    unavailable: ["不可用(凭证被拒绝)", "pill-bad"]
  };

  // The three axes a bucket can belong to, in the operator's terms. Start Plan
  // and the general Coding Plan are separate allowances on the same account,
  // and an unassigned bucket is one the upstream did not tie to a plan it
  // described — said plainly, because silently folding it into either plan
  // would report the wrong billing axis.
  //
  // The map is a translation, not a whitelist: a kind this page has not seen
  // renders as its own identifier rather than being hidden, because it is still
  // a real statement about which axis the numbers are on.
  var QUOTA_AXIS_KINDS = {
    start_plan: "Start Plan 额度",
    coding_plan: "通用额度",
    unassigned: "未归属套餐额度"
  };

  function axisReading(kind) {
    return QUOTA_AXIS_KINDS[kind] || kind;
  }

  // quotaAxis renders one billing axis: a heading naming the axis in the
  // operator's terms plus the plan's own label, then that axis's buckets. The
  // group labels come from the plugin because that is where ownership was
  // resolved — the instance-id versus product-id match lives there, and a
  // second copy of it here could disagree with the host's own quota groups.
  function quotaAxis(group, balances) {
    var section = el("div", "quota-axis");
    var head = el("div", "axis-head");
    head.appendChild(text(el("span", "axis-kind"), axisReading(group.kind)));
    if (group.label) { head.appendChild(text(el("span", "axis-plan"), group.label)); }
    section.appendChild(head);
    balances.forEach(function (balance) {
      var bar = quotaBar(balance);
      if (bar) { section.appendChild(bar); }
      var block = el("div", "bucket-lines");
      quotaBucket(balance).forEach(function (line) {
        block.appendChild(text(el("div"), line));
      });
      section.appendChild(block);
    });
    return section;
  }

  function quotaCard(quota) {
    var box = el("div");
    if (!quota) {
      appendStack(box, statusSpan("未查询", ""), []);
      return box;
    }
    var known = QUOTA_STATES[quota.state] || [quota.state || "未知", ""];
    var lines = [];
    if (quota.plan) { lines.push(quota.plan); }
    else if (quota.plan_count > 0) { lines.push(quota.plan_count + " 个未命名套餐"); }
    if (quota.reason) { lines.push(quota.reason); }
    if (quota.checked_at) { lines.push("查询于 " + quota.checked_at); }
    appendStack(box, statusSpan(known[0], known[1]), lines);

    var balances = quota.balances || [];
    var groups = quota.plan_groups || [];
    if (!groups.length) {
      // No axis resolved — a response with buckets but no readable plan, or a
      // pre-grouping snapshot cached before a reload. The buckets are still
      // real numbers, so they render under one unnamed axis rather than
      // disappearing.
      if (balances.length) { box.appendChild(quotaAxis({ kind: "", label: "" }, balances)); }
      return box;
    }
    // Buckets join their axis by index, which the plugin resolved from the
    // plan each one names. Joining by label instead would merge two plans that
    // happen to share a display name, and re-deriving ownership here would
    // duplicate the rule that distinguishes two instances of one product.
    groups.forEach(function (group, index) {
      box.appendChild(quotaAxis(group, balances.filter(function (balance) {
        return balance.group_index === index;
      })));
    });
    return box;
  }

  // Account cards are built from semantic facts. Each credential slot has a
  // dedicated builder returning one element the card must mount: a test can
  // then assert every builder is consumed, because a builder whose return
  // value is dropped renders a plausible card missing a whole section.
  function jwtCard(jwt) {
    var dd = el("dd");
    if (!jwt) { dd.appendChild(statusSpan("未记录", "")); return dd; }
    appendStack(dd, credentialPill(jwt.status), jwtLines(jwt));
    return dd;
  }

  function apiKeyCard(key) {
    var dd = el("dd");
    if (!key) { dd.appendChild(statusSpan("未记录", "")); return dd; }
    appendStack(dd, credentialPill(key.status), apiKeyLines(key));
    return dd;
  }

  function oauthCard(oauth) {
    var dd = el("dd");
    if (!oauth) { dd.appendChild(statusSpan("无", "")); return dd; }
    if (oauth.reauth_required) {
      appendStack(dd, statusSpan("需重新授权", "pill-bad"), [oauth.reason || "业务 API 访问已失效"]);
      return dd;
    }
    var lines = [];
    if (oauth.received_at) { lines.push("获取于 " + oauth.received_at); }
    appendStack(dd, statusSpan(oauth.has_access_token ? "材料完整" : "无材料", "pill-ok"), lines);
    return dd;
  }

  function factRow(list, label, valueNode) {
    var dt = el("dt");
    text(dt, label);
    list.appendChild(dt);
    list.appendChild(valueNode);
  }

  // ALLOWANCE_STATES translate the plugin's per-model allowance into the
  // operator's terms. A model the plugin has no reading for is not an empty one:
  // the billing answer may simply not have named it, so it renders as unknown
  // rather than as spent.
  var ALLOWANCE_STATES = {
    funded: ["有额度", "pill-ok"],
    empty: ["额度已用完", "pill-bad"],
    unknown: ["未知", "pill-warn"]
  };

  // SITE_NAMES label the two ZCode sites on the page. An operator may hold an
  // account on each, and the site is the only thing that tells the two records
  // apart: their identities, credentials, and plan views are otherwise the same
  // shape.
  var SITE_NAMES = {
    zai: "国际站 z.ai",
    bigmodel: "国内站 bigmodel"
  };

  // planCard renders which Start Plan products this record holds and, per model,
  // whether an allowance is left. It is the section that tells a wrong-account
  // login and an exhausted plan apart: the JWT status alone reports both as "not
  // serving", and only this one says which happened.
  function planCard(plan) {
    var dd = el("dd");
    if (!plan) { dd.appendChild(statusSpan("未读取", "")); return dd; }
    if (!plan.readable) {
      appendStack(dd, statusSpan("上次读取失败", "pill-warn"), ["配额接口的返回无法解析；此前的读数已保留"]);
      return dd;
    }
    var stack = [];
    if (plan.plan_ids && plan.plan_ids.length) {
      stack.push("套餐 " + plan.plan_ids.join("、"));
    } else {
      stack.push("未读到 Start Plan");
    }
    if (plan.last_priority) {
      stack.push("末位优先：仅在其他记录都无法服务时才调度");
    }
    Object.keys(plan.models || {}).sort().forEach(function (model) {
      var line = plan.models[model];
      var label = ALLOWANCE_STATES[line.allowance] || [line.allowance, ""];
      var parts = [statusSpan(label[0], label[1])];
      if (line.reset_at) { parts.push("恢复 " + line.reset_at); }
      parts.push(text(el("span"), " " + unknownNumber(line.buckets) + " 个额度桶"));
      stack.push(parts);
    });
    appendStack(dd, statusSpan(plan.plan_ids && plan.plan_ids.length ? "已识别" : "无套餐", ""), stack);
    return dd;
  }

  function loginCard(login) {
    var dd = el("dd");
    if (!login) { dd.appendChild(statusSpan("未记录", "")); return dd; }
    var lines = ["账号 " + login.user_id_hash];
    if (login.checked_at) { lines.push("登录于 " + login.checked_at); }
    appendStack(dd, statusSpan("已关联", "pill-ok"), lines);
    return dd;
  }

  // siteName renders one site's name. An unrecognized site shows as itself
  // rather than as the international one: the plugin keeps an unrecognized site
  // verbatim, and silently relabelling it here would contradict that and promise
  // a re-authorization the action is going to refuse.
  function siteName(site) {
    return SITE_NAMES[site] || site || SITE_NAMES.zai;
  }

  function actionButton(label, action, authIndex, site) {
    var button = el("button");
    text(button, label);
    button.type = "button";
    button.addEventListener("click", function () { runAction(action, authIndex, button, site); });
    return button;
  }

  // renderAccount mounts one account card. Each credential builder is appended
  // exactly once; dropping one of these lines would silently lose that
  // credential section while the card still looks finished.
  function renderAccount(account) {
    var card = el("article", "account");
    card.appendChild(text(el("h2"), account.label || account.auth_index || "(未命名)"));
    card.appendChild(text(el("div", "identity"), account.identity_id || "—"));
    card.appendChild(text(el("div", "identity"), "站点 " + siteName(account.site)));

    if (account.read_error) {
      var note = el("div", "unreadable");
      appendStack(note, statusSpan("无法读取该记录", "pill-bad"), [account.read_error]);
      card.appendChild(note);
      return card;
    }

    var quotaSlot = el("div");
    quotaSlot.appendChild(quotaCard(account.quota));
    card.appendChild(quotaSlot);

    var facts = el("dl", "facts");
    factRow(facts, "Start Plan", planCard(account.plan));
    factRow(facts, "JWT(主凭证)", jwtCard(account.jwt));
    factRow(facts, "API Key(回退)", apiKeyCard(account.api_key));
    factRow(facts, "OAuth", oauthCard(account.oauth));
    factRow(facts, "登录账号", loginCard(account.login));
    card.appendChild(facts);

    var authIndex = account.auth_index || "";
    var group = el("div", "actions");
    group.appendChild(actionButton("刷新凭证", "refresh_credential", authIndex));
    group.appendChild(actionButton("刷新额度", "refresh_quota", authIndex));
    group.appendChild(actionButton("刷新模型", "refresh_models", authIndex));
    // Re-authorization names its site, because a recovery that picked one for
    // the operator could swap a domestic credential for an international login
    // and leave the account looking healthy until every request failed.
    group.appendChild(actionButton("用 " + siteName(account.site) + " 重新授权", "oauth_retry", authIndex, account.site));
    card.appendChild(group);
    return card;
  }

  // Cached cards are optimistic paint only: no action is clickable until a
  // fresh authenticated state response has revalidated the accounts.
  var statusVerified = false;

  function setCardButtonsDisabled(container, disabled) {
    var buttons = container.querySelectorAll("button");
    for (var i = 0; i < buttons.length; i += 1) {
      if (disabled) {
        buttons[i].disabled = true;
        buttons[i].title = "正在刷新真实状态，请稍候。";
      } else {
        buttons[i].disabled = false;
        buttons[i].removeAttribute("title");
      }
    }
  }

  var SESSION_STATES = { pending: ["等待授权", "pill-warn"], complete: ["已完成", "pill-ok"] };

  var CACHE_STATES = {
    cached: ["已缓存", "pill-ok"],
    cooldown: ["冷却中", "pill-warn"],
    failed: ["失败", "pill-bad"],
    empty: ["无模型", ""]
  };

  // renderSection fills one table and updates its header count, so an empty
  // section still reads as "checked, nothing found" rather than as a broken
  // table.
  function renderSection(tbodyID, countID, rows, renderRow, emptyText, colSpan) {
    var body = document.getElementById(tbodyID);
    while (body.firstChild) { body.removeChild(body.firstChild); }
    if (!rows.length) {
      var tr = el("tr");
      var td = el("td");
      td.colSpan = colSpan;
      td.className = "empty";
      text(td, emptyText);
      tr.appendChild(td);
      body.appendChild(tr);
    } else {
      rows.forEach(function (item) {
        var row = el("tr");
        renderRow(row, item);
        body.appendChild(row);
      });
    }
    text(document.getElementById(countID), rows.length ? rows.length + " 项" : "");
  }

  var accountsBox = document.getElementById("accounts");

  function renderAccounts(data) {
    var list = data.accounts || [];
    while (accountsBox.firstChild) { accountsBox.removeChild(accountsBox.firstChild); }
    if (!list.length) {
      accountsBox.appendChild(text(el("p", "empty"), "没有账号"));
    } else {
      list.forEach(function (account) {
        accountsBox.appendChild(renderAccount(account));
      });
    }
    text(document.getElementById("accounts-count"), list.length ? list.length + " 个账号" : "");
  }

  function renderEmpty() {
    renderAccounts({});
    renderSection("sessions", "sessions-count", [], null, "没有进行中的授权会话", 5);
    renderSection("model-cache", "cache-count", [], null, "没有模型缓存记录", 6);
  }

  function render(data) {
    renderAccounts(data);
    renderSection("sessions", "sessions-count", data.sessions || [], function (row, session) {
      var known = SESSION_STATES[session.state] || [session.state || "未知", ""];
      var td = el("td");
      td.appendChild(statusSpan(known[0], known[1]));
      row.appendChild(td);
      cell(row, session.identity_id || "—");
      cell(row, session.created_at || "—");
      cell(row, session.expires_at || "—");
      cell(row, session.message || "—");
    }, "没有进行中的授权会话", 5);

    renderSection("model-cache", "cache-count", data.model_cache || [], function (row, entry) {
      var known = CACHE_STATES[entry.state] || [entry.state || "未知", ""];
      cell(row, entry.identity || "—");
      cell(row, entry.environment || "—");
      var td = el("td");
      td.appendChild(statusSpan(known[0], known[1]));
      row.appendChild(td);
      cell(row, entry.state === "cached" ? entry.model_count : "—");
      cell(row, entry.expires_at || entry.cooldown_until || "—");
      cell(row, entry.failure_reason || "—");
    }, "没有模型缓存记录", 6);

    setCardButtonsDisabled(accountsBox, !statusVerified);
  }

  var ACTION_LABELS = {
    refresh_credential: "刷新凭证",
    refresh_quota: "刷新额度",
    refresh_models: "刷新模型缓存",
    oauth_retry: "重新授权",
    oauth_login: "登录",
    batch_refresh: "刷新全部账号"
  };

  function actionName(action) {
    return ACTION_LABELS[action] || action;
  }

  function runAction(action, authIndex, button, site) {
    if (button.disabled) { return; }
    generation += 1;              // in-flight replies from earlier renders are void
    var localGeneration = generation;
    setBusy(button, true);
    if (button === document.getElementById("batch-refresh")) {
      document.getElementById("reload-state").disabled = true;
    }
    show("正在执行" + actionName(action) + (authIndex ? "(" + authIndex + ")" : "") + "…", "pending");
    apiFetch(ACTION_URL, "POST", { action: action, auth_index: authIndex || "", site: site || "" })
    .then(function (outcome) {
      // A newer action or state fetch superseded this reply; rendering it
      // would put a stale result over a fresh one.
      if (localGeneration !== generation) { return; }
      if (outcome.ok) {
        showRaw(actionName(action), outcome.data);
        show(actionName(action) + (authIndex ? "(" + authIndex + ")" : "") + " 完成。", "");
        var session = outcome.data && outcome.data.session;
        if (session && session.authorize_url) { renderAuthorizeLink(session); }
      } else {
        var error = (outcome.data && outcome.data.error) || {};
        show(actionName(action) + " 失败:" + (error.message || error.code || "未知错误"), "error");
      }
    }).catch(function (failure) {
      if (localGeneration !== generation) { return; }
      var reason = describeFailure(failure);
      if (reason) { show(actionName(action) + " 未能执行:" + reason, "error"); }
    }).then(function () {
      setBusy(button, false);
      document.getElementById("reload-state").disabled = false;
      loadState({ silent: true });
    });
  }

  function setBusy(button, busy) {
    if (busy) {
      button.disabled = true;
      button.classList.add("loading");
      button.setAttribute("aria-busy", "true");
    } else {
      button.disabled = false;
      button.classList.remove("loading");
      button.removeAttribute("aria-busy");
    }
  }

  function renderAuthorizeLink(session) {
    var url = session.authorize_url;
    if (typeof url !== "string" || url.slice(0, 8) !== "https://") { return; }
    var line = el("p", "link-cell");
    var anchor = document.createElement("a");
    anchor.setAttribute("href", url);
    anchor.setAttribute("target", "_blank");
    anchor.setAttribute("rel", "noopener noreferrer");
    text(anchor, "打开授权页面以完成登录");
    line.appendChild(anchor);
    message.appendChild(line);
  }

  // loadState is the page's only refresh path, and it runs when an operator
  // acts: on save, on the reload button, and after each management action.
  // There is deliberately no interval — a periodic full re-fetch would blank
  // the page under the reader and replay a revoked key for no reason.
  function loadState(options) {
    generation += 1;
    var localGeneration = generation;
    show("正在加载状态…", "pending");
    apiFetch(STATE_URL, "GET")
      .then(function (outcome) {
        // A newer fetch or action superseded this reply; applying it would
        // overwrite fresh state with stale state.
        if (localGeneration !== generation) { return; }
        if (!outcome.ok) {
          var error = (outcome.data && outcome.data.error) || {};
          show("状态加载失败:" + (error.message || error.code || "未知错误"), "error");
          return;
        }
        statusVerified = true;
        render(outcome.data);
        writeCache(outcome.data);
        if (!options || !options.silent) {
          show("状态已加载。", "");
        }
      })
      .catch(function (failure) {
        if (localGeneration !== generation) { return; }
        var reason = describeFailure(failure);
        // Without a key this is the expected opening state, not a failure: the
        // shell is public, so the prompt is the page's first job.
        if (reason) { show(reason, "error"); }
      });
  }

  document.getElementById("reload-state").addEventListener("click", function () {
    loadState();
  });

  document.getElementById("batch-refresh").addEventListener("click", function () {
    runAction("batch_refresh", "", document.getElementById("batch-refresh"));
  });

  // The two login entries differ only in the site they authorize against. Each
  // names its own, so an operator with accounts on both adds the second one
  // without changing what the first defaults to.
  document.getElementById("login-zai").addEventListener("click", function () {
    runAction("oauth_login", "", document.getElementById("login-zai"), "zai");
  });

  document.getElementById("login-bigmodel").addEventListener("click", function () {
    runAction("oauth_login", "", document.getElementById("login-bigmodel"), "bigmodel");
  });

  document.getElementById("save-key").addEventListener("click", function () {
    var key = keyInput.value.trim();
    if (!key) {
      show("请先填写管理密钥再保存。", "error");
      keyInput.focus();
      return;
    }
    if (!storeKey(key)) {
      show("管理密钥无法保存在此浏览器。", "error");
      return;
    }
    keyInput.value = "";
    showKeyPanel(true);
    // Saving a key is a claim, not a proof: the first fetch under it decides
    // whether it stays. A wrong key answers 401 and forgetKey removes it.
    loadState();
  });

  document.getElementById("clear-key").addEventListener("click", function () {
    forgetKey("管理密钥已清除,请重新填写。", "");
  });

  // Re-setting the key re-opens the same panel the key was first entered in;
  // the saved value is replaced only when the operator saves again.
  keyShow.addEventListener("click", function () {
    showKeyPanel(false);
    keyInput.focus();
  });

  // Opening paint. A saved key plus a cached snapshot renders instantly with
  // actions locked, and the snapshot notice names its age so stale data is
  // never mistaken for a fresh reading; a live revalidation follows either
  // way. Nothing here retries on a timer — every later fetch has an operator
  // behind it.
  (function boot() {
    var hasKey = !!storedKey();
    var cached = hasKey ? readCache() : null;
    if (cached) {
      render(cached.data);
      var cachedAt = cached.saved_at ? new Date(cached.saved_at).toLocaleString() : "";
      show("已显示上次缓存的状态" + (cachedAt ? "（" + cachedAt + "）" : "") + "，正在刷新真实状态…", "pending");
      loadState({ silent: true });
    } else if (hasKey) {
      showKeyPanel(true);
      loadState();
    } else {
      clearStateCache();
      renderEmpty();
      showKeyPanel(false);
      show("请先填写并保存管理密钥。", "pending");
    }
  }());
}());
</script>
</body>
</html>
`
