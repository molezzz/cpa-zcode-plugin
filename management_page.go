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
// field names, the localStorage key) stay verbatim in English because they are
// the wire contract, and a translated action name would be rejected by the
// route.
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
    color-scheme: light;
    --bg: #f4f5f7;
    --surface: #ffffff;
    --surface-sunken: #fafbfc;
    --border: #e3e6ea;
    --border-strong: #d0d5dd;
    --text: #1a1d21;
    --text-muted: #667085;
    --accent: #2f6feb;
    --ok: #067647;
    --ok-bg: #ecfdf3;
    --warn: #b54708;
    --warn-bg: #fffaeb;
    --bad: #b42318;
    --bad-bg: #fef3f2;
    --radius: 10px;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 24px 20px 48px;
    background: var(--bg); color: var(--text);
    font: 14px/1.6 system-ui, -apple-system, "PingFang SC", "Microsoft YaHei", sans-serif;
  }
  .page { max-width: 1180px; margin: 0 auto; }
  h1 { margin: 0; font-size: 20px; font-weight: 650; letter-spacing: -.01em; }
  h2 { margin: 0; font-size: 15px; font-weight: 600; }
  .subtitle { margin: 6px 0 20px; color: var(--text-muted); font-size: 13px; }
  .muted { color: var(--text-muted); }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }

  .card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); margin-bottom: 16px; overflow: hidden;
  }
  .card-head {
    display: flex; align-items: center; justify-content: space-between; gap: 12px;
    padding: 14px 16px; border-bottom: 1px solid var(--border); background: var(--surface-sunken);
  }
  .card-head .count { color: var(--text-muted); font-size: 12px; font-weight: 400; }
  .card-body { padding: 0; }
  .card-body.padded { padding: 16px; }

  table { border-collapse: collapse; width: 100%; }
  th {
    text-align: left; font-size: 12px; font-weight: 600; color: var(--text-muted);
    padding: 9px 16px; background: var(--surface-sunken);
    border-bottom: 1px solid var(--border); white-space: nowrap;
  }
  td { padding: 11px 16px; border-bottom: 1px solid var(--border); vertical-align: top; font-size: 13px; }
  tbody tr:last-child td { border-bottom: none; }
  tbody tr:hover { background: #fcfcfd; }
  .empty { padding: 28px 16px; text-align: center; color: var(--text-muted); font-size: 13px; }

  /* Status pills carry the verdict as text, not only as colour, so the state
     stays legible to a reader who cannot distinguish the hues. */
  .pill {
    display: inline-block; padding: 2px 9px; border-radius: 999px;
    font-size: 12px; font-weight: 600; line-height: 1.7; white-space: nowrap;
    background: #f2f4f7; color: var(--text-muted); border: 1px solid transparent;
  }
  .pill-ok { background: var(--ok-bg); color: var(--ok); }
  .pill-warn { background: var(--warn-bg); color: var(--warn); }
  .pill-bad { background: var(--bad-bg); color: var(--bad); }

  .stack { display: flex; flex-direction: column; gap: 3px; }
  .sub { font-size: 12px; color: var(--text-muted); }
  .actions { display: flex; flex-wrap: wrap; gap: 6px; }

  button {
    font: inherit; font-size: 12px; cursor: pointer; border-radius: 7px;
    border: 1px solid var(--border-strong); background: var(--surface); color: var(--text);
    padding: 5px 11px; transition: background .12s, border-color .12s;
  }
  button:hover:not(:disabled) { background: var(--surface-sunken); border-color: #b9c0ca; }
  button:disabled { opacity: .45; cursor: default; }
  button.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
  button.primary:hover:not(:disabled) { background: #2559c4; border-color: #2559c4; }

  input {
    font: inherit; font-size: 13px; padding: 6px 10px; border-radius: 7px;
    border: 1px solid var(--border-strong); background: var(--surface); color: var(--text); min-width: 260px;
  }
  input:focus { outline: 2px solid #bfd3f7; outline-offset: 1px; border-color: var(--accent); }

  #error:not(:empty) {
    margin-bottom: 16px; padding: 10px 14px; border-radius: var(--radius);
    background: var(--bad-bg); color: var(--bad); border: 1px solid #fbd5d2; font-size: 13px;
  }
  #result:not(:empty) {
    margin-top: 16px; padding: 14px 16px; border-radius: var(--radius);
    background: var(--surface); border: 1px solid var(--border);
    font: 12px/1.6 ui-monospace, SFMono-Regular, Menlo, monospace;
    white-space: pre-wrap; overflow-wrap: anywhere;
  }
  .link-cell { margin-top: 10px; }
  .link-cell a { color: var(--accent); }

  .empty-hint { color: var(--text-muted); font-size: 13px; padding: 4px 0; }
</style>
</head>
<body>
<div class="page">
<h1>ZCode 管理</h1>
<p class="subtitle">上游身份、凭证与额度的脱敏运行状态。密钥、授权参数、上游响应原文与用户 prompt 永不展示。</p>

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
        <button id="key-show" type="button" hidden>更换密钥</button>
      </div>
      <p class="sub" style="margin:10px 0 0">
        本页只是静态外壳：下方所有账号、额度与凭证状态都用这里填入的密钥取回。密钥只保存在本浏览器的
        localStorage，以 Bearer 方式发送，一旦请求被拒绝即从本地删除。
      </p>
    </div>
  </div>
</div>

<div id="error" role="alert"></div>

<div class="card">
  <div class="card-head">
    <h2>账号</h2>
    <div class="actions">
      <span id="accounts-count" class="count"></span>
      <button id="batch-refresh" class="primary" type="button">刷新全部账号</button>
    </div>
  </div>
  <div class="card-body">
    <table>
      <thead>
        <tr><th>账号</th><th>上游身份</th><th>JWT(主凭证)</th><th>API Key(回退)</th><th>OAuth</th><th>额度</th><th>操作</th></tr>
      </thead>
      <tbody id="accounts"></tbody>
    </table>
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

<div id="result"></div>

<script>
"use strict";
(function () {
  var STATE_URL = "/v0/management/zcode/state";
  var ACTION_URL = "/v0/management/zcode/action";
  var KEY_STORAGE = "zcode_management_key";
  var generation = 0;      // bumped per state fetch; stale replies are dropped
  var busy = 0;            // in-flight action count for global batch guard

  var keyInput = document.getElementById("management-key");
  var keyFields = document.getElementById("key-fields");
  var keyState = document.getElementById("key-state");

  // localStorage is the only store the key may live in: sessionStorage dies
  // with the tab and a cookie would ride along on every host request. Each
  // access is guarded because a blocked or full store is an ordinary browser
  // state, not an error worth breaking the page over.
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

  // forgetKey drops a key that the host rejected or that the operator asked to
  // drop. Rendering is cleared with it: leaving the previous accounts on screen
  // after the key is gone would keep showing data the page can no longer
  // re-fetch or prove is still authorized.
  function forgetKey(message) {
    clearStoredKey();
    generation += 1;
    keyInput.value = "";
    clearTables();
    text(document.getElementById("result"), "");
    showKeyPanel(false);
    keyInput.focus();
    if (message) { showError(message); }
  }

  // A saved key collapses the input row to a single confirmation line, so the
  // credential is not left sitting on screen while the operator reads status.
  function showKeyPanel(collapsed) {
    keyFields.hidden = collapsed;
    document.getElementById("key-show").hidden = !collapsed;
    text(keyState, collapsed ? "已保存在本浏览器" : "");
  }

  // apiFetch is the page's only network entry point. Refusing to send without a
  // key is the point: the shell answers every visitor, and the data behind it
  // must not be requested at all until an operator supplies the key. A 401
  // means the stored key is wrong or revoked, so it is discarded rather than
  // retried — a wrong key would otherwise be replayed on every timer tick.
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
        forgetKey("管理密钥缺失或无效，请重新填写。");
        return Promise.reject(new Error("unauthorized"));
      }
      return reply.json().catch(function () {
        return null;
      }).then(function (data) {
        return { ok: reply.ok, data: data };
      });
    });
  }

  // describeFailure keeps the message an operator sees about a request that
  // never reached the host, as opposed to one the host answered and refused.
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

  function show(message) {
    text(document.getElementById("result"), message);
  }

  function showError(message) {
    text(document.getElementById("error"), message);
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

  // appendPill writes a verdict plus optional secondary lines into one cell, so
  // a credential's state, its error code and its age read as one fact rather
  // than as three unrelated fragments. It returns the cell so a caller can
  // append it to the row; the caller must do that itself, because appending the
  // stack instead would put a div directly under tr.
  function appendStack(td, pill, lines) {
    var stack = el("div", "stack");
    stack.appendChild(pill);
    (lines || []).forEach(function (line) {
      if (line) { stack.appendChild(text(el("div", "sub"), line)); }
    });
    td.appendChild(stack);
    return td;
  }

  function jwtCell(jwt) {
    var td = el("td");
    if (!jwt) { td.appendChild(statusSpan("未记录", "")); return td; }
    var lines = [];
    if (jwt.last_error_code) { lines.push("错误码 " + jwt.last_error_code); }
    if (jwt.retry_after) { lines.push(jwt.retry_after + " 后可重试"); }
    if (jwt.last_checked_at) { lines.push("检查于 " + jwt.last_checked_at); }
    if (jwt.reauth_suggested) { lines.push("已超过重新授权期限,建议重新授权"); }
    return appendStack(td, credentialPill(jwt.status), lines);
  }

  function apiKeyCell(key) {
    var td = el("td");
    if (!key) { td.appendChild(statusSpan("未记录", "")); return td; }
    var lines = [];
    if (key.name) { lines.push(key.name); }
    if (key.last_error && key.last_error.stage) {
      lines.push(key.last_error.stage + (key.last_error.message ? ":" + key.last_error.message : ""));
    }
    if (key.updated_at) { lines.push("更新于 " + key.updated_at); }
    return appendStack(td, credentialPill(key.status), lines);
  }

  function oauthCell(oauth) {
    var td = el("td");
    if (!oauth) { td.appendChild(statusSpan("无", "")); return td; }
    if (oauth.reauth_required) {
      appendStack(td, statusSpan("需重新授权", "pill-bad"), [oauth.reason || "业务 API 访问已失效"]);
      return td;
    }
    var lines = [];
    if (oauth.received_at) { lines.push("获取于 " + oauth.received_at); }
    appendStack(td, statusSpan(oauth.has_access_token ? "材料完整" : "无材料", "pill-ok"), lines);
    return td;
  }

  // quotaText renders the entitlement state. The three readings an operator
  // must be able to tell apart are kept visually distinct: a plan with quota
  // ("ok"), an account the upstream positively reports as having no plan
  // ("no_plan" / "plan_expired"), and a reading the plugin could not make
  // ("unknown"). Collapsing the last two into one "unknown" is what made the
  // earlier empty billing answer look like a missing subscription.
  var QUOTA_STATES = {
    ok: ["有套餐且有额度", "pill-ok"],
    exhausted: ["套餐额度耗尽", "pill-bad"],
    no_plan: ["该账号没有 Coding Plan", "pill-warn"],
    plan_expired: ["套餐已到期", "pill-bad"],
    unknown: ["未知(上游返回无法解析)", "pill-warn"],
    unavailable: ["不可用(凭证被拒绝)", "pill-bad"]
  };

  // An unreadable number is not a zero. Every optional field the upstream may
  // omit renders through this one helper, so a missing value reads as "未知"
  // rather than as a measurement the plugin never received.
  function unknownNumber(value) {
    return value === null || value === undefined ? "未知" : value.toLocaleString();
  }

  // Bucket recurrence as the page reads it. A one_time grant does not come
  // back, so showing it a reset time would tell an operator to wait for
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

  // quotaBucket renders one evidence line per bucket. The order is what an
  // operator acts on: how much is left in share first (the fraction is
  // computed by the plugin so this page cannot disagree with the host about
  // it), then whether waiting is an option at all, then the raw counts — which
  // are what the share was derived from and what an operator checks the
  // upstream against.
  function quotaBucket(balance) {
    var lines = [];
    var fraction = balance.remaining_fraction;
    var share = fraction === null || fraction === undefined
      ? "剩余比例未知"
      : "剩余 " + (fraction * 100).toFixed(1) + "%";
    lines.push((balance.name || "未命名额度") + (balance.malformed ? "(字段漂移)" : "") + " " + share);
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

  function quotaCell(quota) {
    var td = el("td");
    if (!quota) { td.appendChild(statusSpan("未查询", "")); return td; }
    var known = QUOTA_STATES[quota.state] || [quota.state || "未知", ""];
    var lines = [];
    if (quota.plan) { lines.push(quota.plan); }
    else if (quota.plan_count > 0) { lines.push(quota.plan_count + " 个未命名套餐"); }
    if (quota.reason) { lines.push(quota.reason); }
    if (quota.checked_at) { lines.push("查询于 " + quota.checked_at); }
    (quota.balances || []).forEach(function (balance) {
      lines.push.apply(lines, quotaBucket(balance));
    });
    return appendStack(td, statusSpan(known[0], known[1]), lines);
  }

  function actionButton(label, action, authIndex, row) {
    var button = el("button");
    text(button, label);
    button.type = "button";
    button.addEventListener("click", function () { runAction(action, authIndex, button, row); });
    return button;
  }

  function setRowDisabled(row, disabled) {
    var buttons = row.querySelectorAll("button");
    for (var i = 0; i < buttons.length; i += 1) { buttons[i].disabled = disabled; }
  }

  function setBatchDisabled(disabled) {
    document.getElementById("batch-refresh").disabled = disabled;
  }

  // ACTION_LABELS names an operation in the operator's language while the
  // request keeps sending the wire name, so a log line and the button that
  // produced it still match.
  var ACTION_LABELS = {
    refresh_credential: "刷新凭证",
    refresh_quota: "刷新额度",
    refresh_models: "刷新模型缓存",
    oauth_retry: "重新授权",
    batch_refresh: "刷新全部账号"
  };

  function actionName(action) {
    return ACTION_LABELS[action] || action;
  }

  function runAction(action, authIndex, button, row) {
    if (button.disabled) { return; }
    generation += 1;              // in-flight replies from earlier renders are void
    var localGeneration = generation;
    busy += 1;
    setBatchDisabled(true);
    if (row) { setRowDisabled(row, true); }
    showError("");
    apiFetch(ACTION_URL, "POST", { action: action, auth_index: authIndex || "" })
    .then(function (outcome) {
      // A newer action or state fetch superseded this reply; rendering it
      // would put a stale result over a fresh one.
      if (localGeneration !== generation) { return; }
      if (outcome.ok) {
        show(actionName(action) + (authIndex ? "(" + authIndex + ")" : "") + " 完成:\n" +
          JSON.stringify(outcome.data, null, 2));
        var session = outcome.data && outcome.data.session;
        if (session && session.authorize_url) { renderAuthorizeLink(session); }
      } else {
        var error = (outcome.data && outcome.data.error) || {};
        showError(actionName(action) + " 失败:" + (error.message || error.code || "未知错误"));
      }
    }).catch(function (failure) {
      if (localGeneration !== generation) { return; }
      var reason = describeFailure(failure);
      if (reason) { showError(actionName(action) + " 未能执行:" + reason); }
    }).then(function () {
      busy -= 1;
      setBatchDisabled(false);
      if (row) { setRowDisabled(row, false); }
      loadState();
    });
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
    document.getElementById("result").appendChild(line);
  }

  // A record the plugin could not read keeps its row and says so, instead of
  // collapsing into a blank cell that reads like "no credential".
  function renderUnreadable(row, account) {
    cell(row, account.label || account.auth_index || "(未命名)");
    cell(row, account.identity_id || "—");
    var note = el("td");
    note.colSpan = 5;
    appendStack(note, statusSpan("无法读取该记录", "pill-bad"), [account.read_error]);
    row.appendChild(note);
  }

  function renderAccount(row, account) {
    if (account.read_error) { renderUnreadable(row, account); return; }
    cell(row, account.label || account.auth_index || "(未命名)");
    cell(row, account.identity_id || "—");
    row.appendChild(jwtCell(account.jwt));
    row.appendChild(apiKeyCell(account.api_key));
    row.appendChild(oauthCell(account.oauth));
    row.appendChild(quotaCell(account.quota));

    var authIndex = account.auth_index || "";
    var actions = el("td");
    var group = el("div", "actions");
    group.appendChild(actionButton("刷新凭证", "refresh_credential", authIndex, row));
    group.appendChild(actionButton("刷新额度", "refresh_quota", authIndex, row));
    group.appendChild(actionButton("刷新模型", "refresh_models", authIndex, row));
    group.appendChild(actionButton("重新授权", "oauth_retry", authIndex, row));
    actions.appendChild(group);
    row.appendChild(actions);
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
  function renderSection(tbodyID, countID, rows, renderRow, emptyText) {
    var body = document.getElementById(tbodyID);
    while (body.firstChild) { body.removeChild(body.firstChild); }
    if (!rows.length) {
      var tr = el("tr");
      var td = el("td");
      td.colSpan = 8;
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

  function render(data) {
    renderSection("accounts", "accounts-count", data.accounts || [], renderAccount, "没有账号");
    renderSection("sessions", "sessions-count", data.sessions || [], function (row, session) {
      var known = SESSION_STATES[session.state] || [session.state || "未知", ""];
      var td = el("td");
      td.appendChild(statusSpan(known[0], known[1]));
      row.appendChild(td);
      cell(row, session.identity_id || "—");
      cell(row, session.created_at || "—");
      cell(row, session.expires_at || "—");
      cell(row, session.message || "—");
    }, "没有进行中的授权会话");

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
    }, "没有模型缓存记录");
  }

  function loadState() {
    generation += 1;
    var localGeneration = generation;
    // Rendering is cleared before the fetch so the tables never show one
    // generation's accounts while the next request is in flight.
    clearTables();
    apiFetch(STATE_URL, "GET")
      .then(function (outcome) {
        // A newer fetch or action superseded this reply; applying it would
        // overwrite fresh state with stale state.
        if (localGeneration !== generation) { return; }
        if (!outcome.ok) {
          var error = (outcome.data && outcome.data.error) || {};
          showError("状态加载失败:" + (error.message || error.code || "未知错误"));
          return;
        }
        showError("");
        render(outcome.data);
      })
      .catch(function (failure) {
        if (localGeneration !== generation) { return; }
        var reason = describeFailure(failure);
        // Without a key this is the expected opening state, not a failure: the
        // shell is public, so the prompt is the page's first job.
        if (reason) { showError(reason); }
      });
  }

  function clearTables() {
    var sections = ["accounts", "sessions", "model-cache"];
    for (var i = 0; i < sections.length; i += 1) {
      var body = document.getElementById(sections[i]);
      while (body.firstChild) { body.removeChild(body.firstChild); }
    }
    ["accounts-count", "sessions-count", "cache-count"].forEach(function (id) {
      text(document.getElementById(id), "");
    });
  }

  document.getElementById("batch-refresh").addEventListener("click", function () {
    runAction("batch_refresh", "", document.getElementById("batch-refresh"), null);
  });

  document.getElementById("save-key").addEventListener("click", function () {
    var key = keyInput.value.trim();
    if (!key) {
      showError("请先填写管理密钥再保存。");
      keyInput.focus();
      return;
    }
    if (!storeKey(key)) {
      showError("管理密钥无法保存在此浏览器。");
      return;
    }
    keyInput.value = "";
    showKeyPanel(true);
    showError("");
    loadState();
  });

  document.getElementById("clear-key").addEventListener("click", function () {
    forgetKey("管理密钥已清除,请重新填写。");
  });

  document.getElementById("key-show").addEventListener("click", function () {
    showKeyPanel(false);
    keyInput.focus();
  });

  showKeyPanel(!!storedKey());
  loadState();
  setInterval(loadState, 20000);
}());
</script>
</body>
</html>
`
