package main

// managementPageHTML is the static management page. It carries no data and no
// secret: everything dynamic is fetched from the authenticated management
// routes and written through DOM textContent / attribute assignments, never
// HTML interpolation. Asynchronous responses guard on a generation counter so
// a slow older reply can never overwrite newer state, and action buttons
// disable themselves while a request is in flight so an action cannot be
// submitted twice.
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
</style>
</head>
<body>
<h1>ZCode Provider</h1>
<p class="muted">Redacted operational state. Secrets, authorization parameters, upstream bodies, and prompts are never shown.</p>
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
  var generation = 0;      // bumped per state fetch; stale replies are dropped
  var busy = 0;            // in-flight action count for global batch guard

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
    fetch(ACTION_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: action, auth_index: authIndex || "" })
    }).then(function (reply) {
      return reply.json().then(function (data) { return { ok: reply.ok, data: data }; });
    }).then(function (outcome) {
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
    }).catch(function () {
      if (localGeneration !== generation) { return; }
      showError("Action " + action + " could not be sent");
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
    fetch(STATE_URL, { headers: { "Accept": "application/json" } })
      .then(function (reply) {
        if (!reply.ok) { throw new Error("state request failed"); }
        return reply.json();
      })
      .then(function (data) {
        // A newer fetch or action superseded this reply; applying it would
        // overwrite fresh state with stale state.
        if (localGeneration !== generation) { return; }
        showError("");
        render(data);
      })
      .catch(function (failure) {
        if (localGeneration !== generation) { return; }
        showError("State could not be loaded: " + failure.message);
      });
  }

  document.getElementById("batch-refresh").addEventListener("click", function () {
    runAction("batch_refresh", "", document.getElementById("batch-refresh"), null);
  });

  loadState();
  setInterval(loadState, 20000);
}());
</script>
</body>
</html>
`
