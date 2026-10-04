package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// The host's own "add account" entry opens whatever URL auth.login.start
// returned, with no way to tell it which site the operator meant: its request
// carries a provider and nothing else. Sending an authorization URL straight
// back therefore makes the configured default the only reachable site, and a
// user holding accounts on both cannot reach the second one from where the host
// actually starts a login.
//
// So the start response points at a chooser the plugin serves instead, and the
// chooser is what asks. The operator picks a site, the plugin opens the login at
// that site, and the configured default becomes the choice highlighted on that
// page rather than the site the login goes to. This is the same two-step
// workbuddy-cliproxy-plus uses, and it is the only place a site is chosen for a
// host-driven login: the management page's own buttons still name a site
// outright and never come through here.

// loginChooserPath is the resource route the chooser is served on. It sits
// beside the management page so the two unauthenticated surfaces are the same
// kind of thing: a fixed route the plugin declares, carrying no account state.
//
// The path carries no query of its own — the one-time choice token rides in the
// query string the host forwards, and never in the route.
var loginChooserPath = managementResourcePrefix + pluginID + "/login"

// pendingLoginChoiceTTL bounds how long a started-but-unchosen login may wait
// for the operator to pick a site.
//
// It is shorter than an authorization session's life on purpose. A chooser token
// is a capability to open a login at a site of the operator's choosing, held
// before any site is known; the session TTL governs the wait for a human at an
// authorization page, which is a longer and different wait. Expiring the choice
// first means a link left open in a browser cannot be used much later to open a
// fresh authorization at whichever site is configured by then.
const pendingLoginChoiceTTL = 10 * time.Minute

// pendingLoginChoice is one host-driven login waiting for its site.
//
// The token is the future session's own id, not a separate handle: the host
// already holds it as the login State and will poll auth.login.poll with it, so
// minting it up front and letting the session adopt it when the site is chosen
// is what lets the host keep polling across the chooser without a second
// handshake. It is unguessable for the same reason a session id is.
type pendingLoginChoice struct {
	expires time.Time
}

// loginChoiceStore holds the unchosen host-driven logins.
//
// The host can start a login the operator never finishes choosing, so entries
// expire on their own and are swept when the plugin shuts down, exactly as
// sessions are. It is a separate table from activeSessions because a choice has
// no upstream flow yet: there is no flow id to poll and no authorization URL to
// open until a site is picked.
type loginChoiceStore struct {
	mu      sync.Mutex
	choices map[string]pendingLoginChoice
	timers  map[string]*time.Timer
	now     func() time.Time
}

func newLoginChoiceStore() *loginChoiceStore {
	return &loginChoiceStore{
		choices: map[string]pendingLoginChoice{},
		timers:  map[string]*time.Timer{},
		now:     time.Now,
	}
}

// pendingLoginChoices holds plugin-wide unchosen host-driven logins; shutdown
// clears it.
var pendingLoginChoices = newLoginChoiceStore()

// create mints a token for one unchosen login and schedules its expiry. It
// fails only on local randomness errors.
func (s *loginChoiceStore) create() (string, time.Time, error) {
	token, err := randomHexToken(sessionIDBytes)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("generate login choice id: %w", err)
	}
	now := s.now()
	expires := now.Add(pendingLoginChoiceTTL)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.choices[token] = pendingLoginChoice{expires: expires}
	s.timers[token] = time.AfterFunc(pendingLoginChoiceTTL, func() { s.remove(token) })
	return token, expires, nil
}

// consume takes the token for one choice attempt and gives it back when the
// attempt cannot proceed, so a site that fails to start is retryable from the
// same page. It returns false for an unknown or expired token.
//
// This is the one-shot property of the capability: a successful choice spends
// the token, and the login it opens is the only one it can ever open. An
// unspendable token is worth nothing to anyone who finds it, and a spent one
// cannot be replayed into a second login.
func (s *loginChoiceStore) consume(token string) (pendingLoginChoice, bool) {
	s.mu.Lock()
	choice, ok := s.choices[token]
	if ok {
		delete(s.choices, token)
		if timer := s.timers[token]; timer != nil {
			timer.Stop()
			delete(s.timers, token)
		}
	}
	s.mu.Unlock()
	if !ok {
		return pendingLoginChoice{}, false
	}
	if s.now().After(choice.expires) {
		s.remove(token)
		return pendingLoginChoice{}, false
	}
	return choice, true
}

// peek reports an unchosen login's remaining life without consuming it, so the
// chooser can re-offer the choice when the operator simply reopened the page.
func (s *loginChoiceStore) peek(token string) (pendingLoginChoice, bool) {
	s.mu.Lock()
	choice, ok := s.choices[token]
	s.mu.Unlock()
	if !ok {
		return pendingLoginChoice{}, false
	}
	if s.now().After(choice.expires) {
		s.remove(token)
		return pendingLoginChoice{}, false
	}
	return choice, true
}

// restore puts a consumed token back after a choice that could not open its
// login, so one unreachable site does not cost the operator the whole login.
// The expiry is recomputed rather than the old one restored, so a refund cannot
// extend the window past the TTL the token was minted with.
func (s *loginChoiceStore) restore(token string) {
	now := s.now()
	expires := now.Add(pendingLoginChoiceTTL)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.choices[token] = pendingLoginChoice{expires: expires}
	s.timers[token] = time.AfterFunc(pendingLoginChoiceTTL, func() { s.remove(token) })
}

// remove deletes one unchosen login and stops its cleanup timer.
func (s *loginChoiceStore) remove(token string) {
	s.mu.Lock()
	delete(s.choices, token)
	if timer := s.timers[token]; timer != nil {
		timer.Stop()
		delete(s.timers, token)
	}
	s.mu.Unlock()
}

// drain clears every unchosen login and stops its timer. Shutdown calls it so a
// timer cannot fire after the host unloads the dynamic library.
func (s *loginChoiceStore) drain() {
	s.mu.Lock()
	timers := s.timers
	s.choices = map[string]pendingLoginChoice{}
	s.timers = map[string]*time.Timer{}
	s.mu.Unlock()
	for _, timer := range timers {
		timer.Stop()
	}
}

// startLoginChooser opens one unchosen host-driven login and returns the token
// the host will poll with, plus the moment the choice expires.
//
// No upstream authorization has started yet, so the caller learns its deadline
// from the chooser rather than from a session TTL.
func startLoginChooser() (string, time.Time, error) {
	token, expires, err := pendingLoginChoices.create()
	if err != nil {
		return "", time.Time{}, errors.New("could not create authorization session")
	}
	return token, expires, nil
}

// loginChooserKind is what the chooser page has to say: a site to pick, or why
// it cannot ask.
type loginChooserKind string

const (
	loginChooserPick  loginChooserKind = "pick"
	loginChooserError loginChooserKind = "error"
)

// loginChooserView is one chooser page.
type loginChooserView struct {
	Kind    loginChooserKind
	Message string
	Token   string
	// DefaultSite is the configured site, shown as the page's highlighted
	// choice. It is a starting point for the operator, never the site the login
	// goes to without being chosen.
	DefaultSite    string
	DefaultLabel   string
	DefaultInvalid bool
}

// handleLoginChooser serves the site-selection step of a host-driven login.
//
// The host opens this in the operator's browser; it is a resource route, so it
// is unauthenticated by construction and must never render account state. Its
// only input is the one-time choice token, and that token is itself the entire
// capability — it can open one login, at one site of the operator's choosing,
// and nothing else. An explicit site in the query consumes it and opens the
// login; without one the page asks.
func handleLoginChooser(query map[string][]string) pluginapi.ManagementResponse {
	values := url.Values{}
	for key, list := range query {
		for _, value := range list {
			values.Add(key, value)
		}
	}
	token := strings.TrimSpace(values.Get("state"))
	if token == "" {
		return loginChooserPage(loginChooserView{
			Kind:    loginChooserError,
			Message: "登录链接缺少标识，请回到 CPA 重新点击“添加账号”。",
		})
	}
	// A site in the query is the operator's choice, made by following one of the
	// page's links or by re-entering the URL. It consumes the token.
	if site := strings.TrimSpace(values.Get("site")); site != "" {
		return handleLoginChoice(token, site)
	}
	// A token whose login already started re-opens the authorization page, so a
	// lost or closed tab costs nothing while the wait window lasts. This is why
	// consuming on choice rather than on first view is the right order: the
	// operator may legitimately load the chooser more than once.
	if session := activeSessions.lookup(token); session != nil && session.authorizeURL != "" {
		if session.expireIfDue(time.Now()) == authSessionPending {
			return redirectResponse(session.authorizeURL)
		}
	}
	if _, ok := pendingLoginChoices.peek(token); ok {
		defaultSite, label, invalid := configuredLoginDefault()
		return loginChooserPage(loginChooserView{
			Kind:           loginChooserPick,
			Token:          token,
			DefaultSite:    defaultSite,
			DefaultLabel:   label,
			DefaultInvalid: invalid,
		})
	}
	return loginChooserPage(loginChooserView{
		Kind:    loginChooserError,
		Message: "登录会话不存在或已过期，请回到 CPA 重新点击“添加账号”。",
	})
}

// handleLoginChoice consumes the token and opens the real login at the chosen
// site. A choice that cannot proceed gives the token back, so the operator may
// retry from the same page rather than starting over.
//
// An unrecognized site is refused before anything is spent: it must not be able
// to turn a bad link into a login at whichever site happens to be configured.
func handleLoginChoice(token, site string) pluginapi.ManagementResponse {
	if _, ok := siteProfileFor(site); !ok {
		if _, stillPending := pendingLoginChoices.peek(token); stillPending {
			return loginChooserPage(loginChooserView{
				Kind:    loginChooserError,
				Message: "未知的登录站点，请返回重新选择。",
			})
		}
		return loginChooserPage(loginChooserView{
			Kind:    loginChooserError,
			Message: "该登录已选择过站点，请回到 CPA 重新点击“添加账号”。",
		})
	}
	if _, ok := pendingLoginChoices.consume(token); !ok {
		return loginChooserPage(loginChooserView{
			Kind:    loginChooserError,
			Message: "该登录已选择过站点或已过期，请回到 CPA 重新点击“添加账号”。",
		})
	}
	cfg := currentConfig()
	session, err := startAuthorizationSessionWithID(cfg, site, token)
	if err != nil {
		// The choice is refunded rather than lost: a site whose authorization
		// upstream is briefly unreachable should be retryable from this page,
		// not a dead end that costs the operator a fresh add-account click. The
		// upstream's own detail stays in the plugin log; the page says only that
		// this site could not be reached.
		pendingLoginChoices.restore(token)
		diagf("login_chooser site=%q start_failed err=%q", site, err.Error())
		return loginChooserPage(loginChooserView{
			Kind:    loginChooserError,
			Message: "登录站点连接失败，请返回重选或稍后重试。",
		})
	}
	return redirectResponse(session.authorizeURL)
}

// configuredLoginDefault resolves the configured default site for display on the
// chooser page. invalid is true when the configuration names a site this build
// does not know, which the page states rather than silently substituting one —
// an operator whose config is wrong must see it, not be sent to a site they did
// not pick.
func configuredLoginDefault() (site, label string, invalid bool) {
	defaultSite, err := currentConfig().OAuth.SiteOrDefault()
	if err != nil {
		return "", "", true
	}
	profile, ok := siteProfileFor(defaultSite)
	if !ok {
		return "", "", true
	}
	return profile.Site, profile.AuthLabel, false
}

// redirectResponse hands a 302 back through the resource route; the host writes
// custom status codes and headers verbatim.
//
// The target is the plugin-derived upstream authorization URL. Only its scheme
// is constrained here — the upstream owns the exact login host and it may
// legitimately differ from the API base — so a compromised or misconfigured
// upstream answer can at most redirect the operator to another web page, never
// to a script URI.
func redirectResponse(location string) pluginapi.ManagementResponse {
	parsed, err := url.Parse(location)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return loginChooserPage(loginChooserView{
			Kind:    loginChooserError,
			Message: "登录站点返回了无效的授权地址，请重新发起登录。",
		})
	}
	return pluginapi.ManagementResponse{
		StatusCode: http.StatusFound,
		Headers:    http.Header{"Location": []string{location}},
		Body: []byte(`<!doctype html><html lang="zh-CN"><meta charset="utf-8">` +
			`<body><p>正在跳转到登录页面…</p><p><a href="` + htmlEscape(location) + `">如未自动跳转，请点这里</a></p></body></html>`),
	}
}

func htmlEscape(value string) string {
	return strings.NewReplacer(
		"&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;",
	).Replace(value)
}

// loginChooserPage renders the chooser (or an error notice) as one HTML page.
//
// The choice links are query-only relative links, so they resolve against
// whatever address the operator used to reach CPA rather than against an
// assumption about how it is deployed.
func loginChooserPage(view loginChooserView) pluginapi.ManagementResponse {
	var body string
	switch view.Kind {
	case loginChooserPick:
		choices := ""
		for _, profile := range siteProfiles() {
			hint := ""
			if profile.Site == view.DefaultSite && !view.DefaultInvalid {
				hint = `<span class="hint">当前默认（` + htmlEscape(view.DefaultLabel) + `）</span>`
			}
			choices += `<a class="choice" href="?state=` + url.QueryEscape(view.Token) +
				`&amp;site=` + url.QueryEscape(profile.Site) + `">` +
				`<strong>` + htmlEscape(profile.AuthLabel) + `</strong>` + hint + `</a>`
		}
		footer := "选择只作用于本次登录；凭据会永久标记该站点，之后的刷新不会改写它。"
		if view.DefaultInvalid {
			footer = "配置的默认站点无效，请手动选择。" + footer
		}
		body = `<h1>选择登录站点</h1><p class="lead">本次登录将发往所选站点。</p>` +
			`<div class="choices">` + choices + `</div><p class="footer">` + footer + `</p>`
	default:
		body = `<h1>无法继续本次登录</h1><p class="lead">` + htmlEscape(view.Message) + `</p>` +
			`<p class="footer">回到 CPA 的“添加账号”重新发起即可。</p>`
	}
	page := `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>ZCode 登录站点选择</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0a0a0d;color:#dedfe0;font-family:system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;line-height:1.6}
.card{max-width:26rem;padding:2rem;border:1px solid #303034;border-radius:.75rem;background:#17171a}
h1{margin:0 0 .5rem;font-size:1.2rem;color:#c8ff00}
.lead{margin:0 0 1.25rem;color:#a1a1aa;font-size:.9rem}
.choices{display:grid;gap:.6rem}
.choice{display:block;padding:.8rem .9rem;border:1px solid #303034;border-radius:.5rem;background:#09090b;color:#dedfe0;text-decoration:none;font-size:.95rem}
.choice:hover{border-color:#c8ff00}
.choice .hint{display:block;color:#c8ff00;font-size:.75rem;margin-top:.2rem}
.footer{margin:1.25rem 0 0;color:#a1a1aa;font-size:.78rem}
</style>
</head>
<body><div class="card">` + body + `</div></body>
</html>`
	return pluginapi.ManagementResponse{
		StatusCode: http.StatusOK,
		Headers:    http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
		Body:       []byte(page),
	}
}
