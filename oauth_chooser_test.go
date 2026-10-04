package main

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// The chooser is an unauthenticated resource route, so its page is the one
// place where a mistake is public rather than merely wrong. These tests pin the
// three properties that makes safe: it renders no account state, it acts only on
// the one-time token it was handed, and that token buys exactly one login.

// chooserGet drives one chooser request the way the host's resource dispatch
// does: a GET on the resource path with the query forwarded separately.
func chooserGet(query map[string][]string) pluginapi.ManagementResponse {
	return serveManagementHTTP(http.MethodGet, loginChooserPath, query, nil)
}

func TestChooserPageOffersEverySiteAndNamesTheConfiguredDefault(t *testing.T) {
	fixture := newUpstreamFixture(t)
	withOAuthConfig(t, func(cfg *Config) { cfg.OAuth.DefaultSite = siteBigmodel })
	start := fixture.startLogin(t)
	t.Cleanup(pendingLoginChoices.drain)

	page := chooserGet(map[string][]string{"state": {start.State}})
	if page.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want the chooser page", page.StatusCode)
	}
	body := string(page.Body)
	for _, profile := range siteProfiles() {
		if !strings.Contains(body, profile.AuthLabel) {
			t.Errorf("chooser does not offer %q:\n%s", profile.AuthLabel, body)
		}
		if !strings.Contains(body, "site="+profile.Site) {
			t.Errorf("chooser has no choice link for %q:\n%s", profile.Site, body)
		}
	}
	// The configured default is offered as the page's starting point, marked as
	// such. It is not what the login will use: the operator still chooses.
	if !strings.Contains(body, "当前默认（"+bigmodelSiteProfile.AuthLabel+"）") {
		t.Errorf("chooser does not mark the configured default:\n%s", body)
	}
	// Nothing about an account may appear on an unauthenticated page.
	assertNoLeak(t, page.Body, fixture.pollAuth...)
	for _, forbidden := range []string{"identity_id", "user_id", "jwt", "access_token"} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Errorf("chooser mentions %q; it must render no account state:\n%s", forbidden, body)
		}
	}
}

// The token is the whole capability, and it is spent by choosing: a second
// choice on the same token must not open a second login.
func TestChooserTokenIsSingleUse(t *testing.T) {
	fixture := newUpstreamFixture(t)
	start := fixture.startLogin(t)
	t.Cleanup(pendingLoginChoices.drain)

	chooseSite(t, start.State, siteZai)

	replay := chooserGet(map[string][]string{"state": {start.State}, "site": {siteBigmodel}})
	if replay.StatusCode != http.StatusOK {
		t.Fatalf("replay status = %d, want the notice page", replay.StatusCode)
	}
	if body := string(replay.Body); !strings.Contains(body, "重新点击") {
		t.Errorf("a spent token must not open another login:\n%s", body)
	}
	if len(fixture.initBodies) != 1 {
		t.Fatalf("init calls = %d, want only the first choice to reach the upstream: %v", len(fixture.initBodies), fixture.initBodies)
	}
}

// An unrecognized site must be refused without spending the token, so a mistyped
// or tampered link costs the operator nothing and authorizes nothing.
func TestChooserRefusesUnknownSiteWithoutSpendingTheToken(t *testing.T) {
	fixture := newUpstreamFixture(t)
	start := fixture.startLogin(t)
	t.Cleanup(pendingLoginChoices.drain)

	page := chooserGet(map[string][]string{"state": {start.State}, "site": {"big-model"}})
	if page.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want the notice page", page.StatusCode)
	}
	if len(fixture.initBodies) != 0 {
		t.Fatalf("an unknown site reached the upstream: %v", fixture.initBodies)
	}
	if _, ok := pendingLoginChoices.peek(start.State); !ok {
		t.Fatal("an unknown site must leave the login unspent and retryable")
	}
	// And the real choice still works afterwards, which is the point of not
	// spending it.
	chooseSite(t, start.State, siteBigmodel)
	if len(fixture.initBodies) != 1 || !strings.Contains(fixture.initBodies[0], `"provider":"bigmodel"`) {
		t.Fatalf("init bodies = %v, want the retry to select bigmodel", fixture.initBodies)
	}
}

// A chooser link left open in a browser must stop working on its own. The token
// is a capability to open a login at a site of the operator's choosing, and a
// stale one that never expires would let anyone who later saw it authorize at
// whichever site is configured by then.
func TestChooserTokenExpires(t *testing.T) {
	fixture := newUpstreamFixture(t)
	base := time.Now()
	store := newLoginChoiceStore()
	store.now = func() time.Time { return base }
	token, _, err := store.create()
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, ok := store.peek(token); !ok {
		t.Fatal("a fresh token must be usable")
	}

	store.now = func() time.Time { return base.Add(pendingLoginChoiceTTL + time.Second) }
	if _, ok := store.peek(token); ok {
		t.Error("an expired token must not be usable")
	}
	if _, ok := store.consume(token); ok {
		t.Error("an expired token must not be spendable")
	}
	if len(fixture.initBodies) != 0 {
		t.Errorf("an expired token reached the upstream: %v", fixture.initBodies)
	}
}

// Reopening the chooser before choosing must still work: an operator who closed
// the tab, or whose browser restored it, has not failed at anything yet.
func TestChooserSurvivesRepeatedViewsBeforeAChoice(t *testing.T) {
	fixture := newUpstreamFixture(t)
	start := fixture.startLogin(t)
	t.Cleanup(pendingLoginChoices.drain)

	for i := 0; i < 3; i++ {
		page := chooserGet(map[string][]string{"state": {start.State}})
		if page.StatusCode != http.StatusOK {
			t.Fatalf("view %d status = %d, want the chooser page", i, page.StatusCode)
		}
	}
	chooseSite(t, start.State, siteZai)
	if len(fixture.initBodies) != 1 {
		t.Fatalf("init calls = %d, want one", len(fixture.initBodies))
	}
}

// After the login has started, the same URL re-opens the authorization page: a
// closed tab mid-login should cost the operator nothing while the wait lasts.
func TestChooserReopensTheAuthorizationPageOnceTheLoginStarted(t *testing.T) {
	fixture := newUpstreamFixture(t)
	start := fixture.startLogin(t)
	t.Cleanup(pendingLoginChoices.drain)
	chosen := chooseSite(t, start.State, siteZai)

	page := chooserGet(map[string][]string{"state": {start.State}})
	if page.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want a redirect back to the authorization page", page.StatusCode)
	}
	if got := page.Headers.Get("Location"); got != chosen.URL {
		t.Errorf("redirect = %q, want the authorize URL %q", got, chosen.URL)
	}
}

// A missing or unknown token is a notice, never a login: the route is
// unauthenticated, so an anonymous visitor must not be able to open one by
// guessing.
func TestChooserRefusesUnknownTokens(t *testing.T) {
	newUpstreamFixture(t)
	t.Cleanup(pendingLoginChoices.drain)

	for name, query := range map[string]map[string][]string{
		"no token":    {},
		"blank":       {"state": {"  "}},
		"not a token": {"state": {"forged-token"}},
	} {
		t.Run(name, func(t *testing.T) {
			page := chooserGet(query)
			if page.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want the notice page", page.StatusCode)
			}
			if body := string(page.Body); !strings.Contains(body, "重新点击") {
				t.Errorf("an unknown token must not offer a site choice:\n%s", body)
			}
		})
	}
}

// The chooser's redirect target is the plugin-derived upstream URL, so only its
// scheme is constrained — but a non-web scheme is refused outright rather than
// handed to the browser.
func TestChooserRefusesNonWebRedirectTargets(t *testing.T) {
	for _, location := range []string{"javascript:alert(1)", "file:///etc/passwd", "not a url at all", ""} {
		page := redirectResponse(location)
		if page.StatusCode == http.StatusFound {
			t.Errorf("redirect to %q was allowed", location)
		}
		if len(page.Headers.Get("Location")) != 0 {
			t.Errorf("a refused redirect still carried a Location header: %q", page.Headers.Get("Location"))
		}
	}
}

// The host starts polling the moment it is handed the chooser URL, so it polls
// before the operator has picked a site — when no authorization session exists
// yet. That wait has to read as a login in progress: reporting it as an unknown
// session makes the host declare the login failed while the operator is still
// completing it in their browser, which is what made the two-step login look
// broken end to end.
func TestPollDuringTheSiteChoiceIsPendingNotUnknown(t *testing.T) {
	fixture := newUpstreamFixture(t)
	start := fixture.startLogin(t)
	t.Cleanup(pendingLoginChoices.drain)

	// Polled with no site chosen and no session: pending, not an error.
	env := pollLogin(t, start.State)
	if !env.OK {
		t.Fatalf("poll failed: %+v", env.Error)
	}
	if response := decodePoll(t, env); response.Status != pluginapi.AuthLoginStatusPending {
		t.Fatalf("status = %q (%s), want pending until a site is chosen", response.Status, response.Message)
	}

	// And once a site is chosen the same handle polls the real session, so the
	// host's single State keeps working across the choice.
	chooseSite(t, start.State, siteZai)
	fixture.queuePoll(http.StatusOK, `{"data":{"status":"pending"}}`)
	env = pollLogin(t, start.State)
	if !env.OK {
		t.Fatalf("poll after choosing failed: %+v", env.Error)
	}
	if response := decodePoll(t, env); response.Status != pluginapi.AuthLoginStatusPending {
		t.Fatalf("status after choosing = %q, want pending", response.Status)
	}
}

// A handle that is neither an unchosen login nor a session really is unknown,
// and the two must stay told apart: the first is a login in progress, the second
// is one that cannot be recovered.
func TestPollForATokenThatIsNeitherChoiceNorSessionIsUnknown(t *testing.T) {
	newUpstreamFixture(t)
	env := pollLogin(t, strings.Repeat("a", 64))
	if !env.OK {
		t.Fatalf("poll failed: %+v", env.Error)
	}
	if response := decodePoll(t, env); response.Status != pluginapi.AuthLoginStatusError {
		t.Fatalf("status = %q, want error for an unknown handle", response.Status)
	}
}
