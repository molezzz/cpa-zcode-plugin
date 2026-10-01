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
// Asynchronous responses guard on a generation counter so a slow older reply
// can never overwrite newer state, and action buttons disable themselves while
// a request is in flight so an action cannot be submitted twice.
const managementPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ZCode Provider</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 1rem 2rem; color: #1c1c1e; }
  h1 { font-size: 1.3rem; } h2 { font-size: 1.05rem; margin-top: 1.6rem; }
  table { border-collapse: collapse; width: 100%; margin-top: .5rem; }
  th, td { border: 1px solid #d8d8dc; padding: .35rem .55rem; text-align: left; vertical-align: top; font-size: .85rem; }
  th { background: #f2f2f7; }
  code { font-size: .8rem; }
  .status-active { color: #1a7f37; font-weight: 600; }
  .status-invalid, .status-exhausted, .status-unavailable { color: #c0392b; font-weight: 600; }
  .status-verification_blocked, .status-cooldown, .status-needs_selection, .status-failed { color: #b06000; font-weight: 600; }
  .muted { color: #6e6e73; }
  button { margin: .1rem .15rem; padding: .25rem .6rem; font-size: .8rem; cursor: pointer; }
  button:disabled { opacity: .45; cursor: default; }
  #result { white-space: pre-wrap; background: #f2f2f7; padding: .6rem; margin-top: .8rem; font-size: .8rem; min-height: 1.2rem; }
  #error { color: #c0392b; margin-top: .5rem; font-size: .85rem; min-height: 1.1rem; }
  .link-cell a { word-break: break-all; }
  #key-panel { border: 1px solid #d8d8dc; background: #fafafc; padding: .7rem .8rem; margin: .8rem 0 1rem; }
  #key-panel.collapsed { display: flex; align-items: center; gap: .6rem; padding: .4rem .6rem; }
  #key-panel.collapsed #key-fields, #key-panel.collapsed #key-hint { display: none; }
  #key-panel label { font-size: .85rem; margin-right: .4rem; }
  #management-key { padding: .25rem .5rem; font-size: .85rem; border: 1px solid #d8d8dc; min-width: 18rem; }
  #key-hint { margin: .5rem 0 0; }
</style>
</head>
<body>
<h1>ZCode Provider</h1>
<p class="muted">Redacted operational state. Secrets, authorization parameters, upstream bodies, and prompts are never shown.</p>

<div id="key-panel">
  <div id="key-fields">
    <label for="management-key">Management key</label>
    <input id="management-key" type="password" autocomplete="off" spellcheck="false">
    <button id="save-key" type="button">Save</button>
    <button id="clear-key" type="button">Forget</button>
    <p id="key-hint" class="muted">This page is a static shell: every account, quota, and credential value below is
      fetched with the management key you enter here. The key is kept in this browser's local storage only, is sent as a
      bearer token, and is never sent again after a request is rejected.</p>
  </div>
  <button id="key-show" type="button" hidden>Change key</button>
  <span id="key-state" class="muted"></span>
</div>

<div id="error" role="alert"></div>

<h2>Accounts</h2>
<button id="batch-refresh" type="button">Refresh all accounts</button>
<table>
  <thead>
    <tr><th>Account</th><th>Identity</th><th>JWT (primary)</th><th>API key (fallback)</th><th>OAuth</th><th>Quota</th><th>Actions</th></tr>
  </thead>
  <tbody id="accounts"></tbody>
</table>

<h2>Authorization sessions</h2>
<table>
  <thead><tr><th>State</th><th>Identity</th><th>Created</th><th>Expires</th><th>Message</th></tr></thead>
  <tbody id="sessions"></tbody>
</table>

<h2>Model cache</h2>
<table>
  <thead><tr><th>Identity</th><th>Environment</th><th>State</th><th>Models</th><th>Until</th><th>Reason</th></tr></thead>
  <tbody id="model-cache"></tbody>
</table>

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
  var keyPanel = document.getElementById("key-panel");
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
    var sections = ["accounts", "sessions", "model-cache"];
    for (var i = 0; i < sections.length; i += 1) {
      var body = document.getElementById(sections[i]);
      while (body.firstChild) { body.removeChild(body.firstChild); }
    }
    text(document.getElementById("result"), "");
    showKeyPanel(false);
    keyInput.focus();
    if (message) { showError(message); }
  }

  function showKeyPanel(collapsed) {
    keyPanel.classList.toggle("collapsed", collapsed);
    document.getElementById("key-show").hidden = !collapsed;
    text(keyState, collapsed ? "Management key saved in this browser." : "");
  }

  // apiFetch is the page's only network entry point. Refusing to send without a
  // key is the point: the shell answers every visitor, and the data behind it
  // must not be requested at all until an operator supplies the key. A 401
  // means the stored key is wrong or revoked, so it is discarded rather than
  // retried — a wrong key would otherwise be replayed on every timer tick.
  function apiFetch(url, method, body) {
    var key = storedKey();
    if (!key) {
      return Promise.reject(new Error("Enter and save the management key to load any data."));
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
        forgetKey("The management key was rejected. Enter it again to continue.");
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
    return failure && failure.message ? failure.message : "the request could not be sent";
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

  function statusSpan(value) {
    var span = el("span", value ? "status-" + value : "");
    text(span, value || "\u2014");
    return span;
  }

  function jwtText(jwt) {
    if (!jwt) { return "\u2014"; }
    var parts = [jwt.status || "unknown"];
    if (jwt.last_error_code) { parts.push(jwt.last_error_code); }
    if (jwt.retry_after) { parts.push("retry after " + jwt.retry_after); }
    return parts.join(" \u00b7 ");
  }

  function apiKeyText(key) {
    if (!key) { return "\u2014"; }
    var parts = [key.status || "unknown"];
    if (key.name) { parts.push(key.name); }
    if (key.last_error && key.last_error.stage) {
      parts.push(key.last_error.stage + (key.last_error.message ? ": " + key.last_error.message : ""));
    }
    return parts.join(" \u00b7 ");
  }

  function oauthText(oauth) {
    if (!oauth) { return "none"; }
    if (oauth.reauth_required) {
      return "re-authorization required (business API access lapsed)";
    }
    return oauth.has_access_token ? "material present" : "no material";
  }

  // quotaText renders the entitlement state. The three readings an operator
  // must be able to tell apart are kept visually distinct: a plan with quota
  // ("ok"), an account the upstream positively reports as having no plan
  // ("no_plan" / "plan_expired"), and a reading the plugin could not make
  // ("unknown"). Collapsing the last two into one "unknown" is what made the
  // earlier empty billing answer look like a missing subscription.
  var QUOTA_STATES = {
    ok: "plan with quota",
    exhausted: "plan exhausted",
    no_plan: "no Coding Plan on this account",
    plan_expired: "plan expired",
    unknown: "unknown (upstream answer not readable)",
    unavailable: "unavailable (credential rejected)"
  };

  function quotaText(quota) {
    if (!quota) { return "not checked"; }
    var state = QUOTA_STATES[quota.state] || quota.state;
    var parts = [state];
    if (quota.plan) { parts.push(quota.plan); }
    else if (quota.plan_count > 0) { parts.push(quota.plan_count + " unnamed plan(s)"); }
    if (quota.reason) { parts.push(quota.reason); }
    return parts.join(" \u00b7 ");
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
        show("Action " + action + (authIndex ? " for " + authIndex : "") + " finished: " +
          JSON.stringify(outcome.data, null, 2));
        var session = outcome.data && outcome.data.session;
        if (session && session.authorize_url) { renderAuthorizeLink(session); }
      } else {
        var error = (outcome.data && outcome.data.error) || {};
        showError("Action " + action + " failed: " + (error.message || error.code || "unknown error"));
      }
    }).catch(function (failure) {
      if (localGeneration !== generation) { return; }
      var reason = describeFailure(failure);
      if (reason) { showError("Action " + action + " could not be sent: " + reason); }
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
    text(anchor, "Open the authorization page to finish the login");
    line.appendChild(anchor);
    document.getElementById("result").appendChild(line);
  }

  function renderAccount(row, account) {
    cell(row, account.label || account.auth_index || "(unknown)");
    cell(row, account.identity_id || "\u2014");
    if (account.read_error) {
      cell(row, account.read_error);
      cell(row, "");
      cell(row, "");
      cell(row, "");
      cell(row, "");
      return;
    }
    var jwtCell = cell(row, "", "");
    jwtCell.appendChild(statusSpan(jwtText(account.jwt)));
    if (account.jwt && account.jwt.last_checked_at) {
      jwtCell.appendChild(el("br"));
      text(jwtCell, "checked " + account.jwt.last_checked_at);
    }
    if (account.jwt && account.jwt.reauth_suggested) {
      jwtCell.appendChild(el("br"));
      text(jwtCell, "past the re-authorization age \u00b7 Re-auth to keep using it");
    }
    var keyCell = cell(row, "", "");
    keyCell.appendChild(statusSpan(apiKeyText(account.api_key)));
    var oauthCell = cell(row, "", "");
    text(oauthCell, oauthText(account.oauth));
    if (account.oauth && account.oauth.received_at) {
      oauthCell.appendChild(el("br"));
      text(oauthCell, "received " + account.oauth.received_at);
    }
    var quotaCell = cell(row, "", "");
    quotaCell.appendChild(statusSpan(quotaText(account.quota)));
    if (account.quota && account.quota.balances && account.quota.balances.length) {
      account.quota.balances.forEach(function (balance) {
        quotaCell.appendChild(el("br"));
        text(quotaCell, balance.name + (balance.malformed ? " (schema drift)" : "") + ": " +
          (balance.remaining === null || balance.remaining === undefined ? "unknown" : balance.remaining) +
          " / " + (balance.total === null || balance.total === undefined ? "unknown" : balance.total));
      });
    }
    var actions = el("td");
    var authIndex = account.auth_index || "";
    actions.appendChild(actionButton("Credential", "refresh_credential", authIndex, row));
    actions.appendChild(actionButton("Quota", "refresh_quota", authIndex, row));
    actions.appendChild(actionButton("Models", "refresh_models", authIndex, row));
    actions.appendChild(actionButton("Re-auth", "oauth_retry", authIndex, row));
    row.appendChild(actions);
  }

  function render(data) {
    var accounts = document.getElementById("accounts");
    while (accounts.firstChild) { accounts.removeChild(accounts.firstChild); }
    (data.accounts || []).forEach(function (account) {
      var row = el("tr");
      renderAccount(row, account);
      accounts.appendChild(row);
    });

    var sessions = document.getElementById("sessions");
    while (sessions.firstChild) { sessions.removeChild(sessions.firstChild); }
    (data.sessions || []).forEach(function (session) {
      var row = el("tr");
      cell(row, session.state, session.state ? "status-" + session.state : "");
      cell(row, session.identity_id || "\u2014");
      cell(row, session.created_at || "\u2014");
      cell(row, session.expires_at || "\u2014");
      cell(row, session.message || "\u2014");
      sessions.appendChild(row);
    });

    var cache = document.getElementById("model-cache");
    while (cache.firstChild) { cache.removeChild(cache.firstChild); }
    (data.model_cache || []).forEach(function (entry) {
      var row = el("tr");
      cell(row, entry.identity || "\u2014");
      cell(row, entry.environment || "\u2014");
      cell(row, entry.state || "\u2014", entry.state ? "status-" + entry.state : "");
      cell(row, entry.state === "cached" ? entry.model_count : "\u2014");
      cell(row, entry.expires_at || entry.cooldown_until || "\u2014");
      cell(row, entry.failure_reason || "\u2014");
      cache.appendChild(row);
    });
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
          showError("State could not be loaded: " + (error.message || error.code || "unknown error"));
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
  }

  document.getElementById("batch-refresh").addEventListener("click", function () {
    runAction("batch_refresh", "", document.getElementById("batch-refresh"), null);
  });

  document.getElementById("save-key").addEventListener("click", function () {
    var key = keyInput.value.trim();
    if (!key) {
      showError("Enter the management key before saving.");
      keyInput.focus();
      return;
    }
    if (!storeKey(key)) {
      showError("The management key could not be saved in this browser.");
      return;
    }
    keyInput.value = "";
    showKeyPanel(true);
    showError("");
    loadState();
  });

  document.getElementById("clear-key").addEventListener("click", function () {
    forgetKey("The management key was cleared. Enter it again to continue.");
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
