package main

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// mustParseURL is a test helper for cookie jar assertions.
func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

// hexTokenPattern matches a 64-character lowercase hex token.
var hexTokenPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// newTestSession builds one pending session with a real client and inserts
// it into the given manager, bypassing upstream init.
func newTestSession(t *testing.T, m *sessionManager, flowID string) (*authSession, string) {
	t.Helper()
	secret, err := randomHexToken(pollSecretBytes)
	if err != nil {
		t.Fatal(err)
	}
	session, err := m.create(flowID, "https://zcode.z.ai/authorize?flow="+flowID, secret, newSessionHTTPClient(defaultConfig()), time.Duration(defaultConfig().OAuth.SessionTTLSeconds)*time.Second, siteZai)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.remove(session.id) })
	return session, secret
}

// resetSessions returns the process-wide session manager to a clean state.
func resetSessions(t *testing.T) {
	t.Helper()
	activeSessions.shutdownAll()
	activeSessions.now = time.Now
	t.Cleanup(func() {
		activeSessions.shutdownAll()
		activeSessions.now = time.Now
	})
}

func TestSessionCreateGeneratesIndependentUnguessableIDs(t *testing.T) {
	resetSessions(t)
	first, firstSecret := newTestSession(t, activeSessions, "flow-a")
	second, secondSecret := newTestSession(t, activeSessions, "flow-b")

	if !hexTokenPattern.MatchString(first.id) {
		t.Fatalf("session id is not 64 hex chars: %q", first.id)
	}
	if !hexTokenPattern.MatchString(firstSecret) {
		t.Fatalf("poll secret is not 64 hex chars: %q", firstSecret)
	}
	if first.id == second.id {
		t.Fatal("two sessions share one id")
	}
	if firstSecret == secondSecret {
		t.Fatal("two sessions share one polling secret")
	}
	if first.id == firstSecret {
		t.Fatal("session id must differ from the polling secret")
	}
	if first.flowID != "flow-a" || second.flowID != "flow-b" {
		t.Fatalf("flow data not bound to sessions: %q %q", first.flowID, second.flowID)
	}
}

func TestSessionOwnsIndependentHTTPClientAndCookieJar(t *testing.T) {
	resetSessions(t)
	first := newSessionHTTPClient(defaultConfig())
	second := newSessionHTTPClient(defaultConfig())
	if first == second {
		t.Fatal("each session must receive its own HTTP client")
	}
	if first.Jar == nil || second.Jar == nil {
		t.Fatal("each session client must have a cookie jar")
	}
	// Distinct cookie jar containers: setting a cookie on one client's jar
	// must not be visible through the other's.
	url := mustParseURL(t, "https://zcode.z.ai")
	first.Jar.SetCookies(url, []*http.Cookie{{Name: "sid", Value: "one"}})
	if cookies := second.Jar.Cookies(url); len(cookies) != 0 {
		t.Fatalf("cookie jar leaked across clients: %v", cookies)
	}
}

func TestSessionCompletesExactlyOnce(t *testing.T) {
	resetSessions(t)
	session, _ := newTestSession(t, activeSessions, "flow-once")
	result := completedLogin{IdentityID: "zcode-user-1", Storage: []byte(`{"zcode":{}}`)}

	got, isNew := session.complete(result)
	if !isNew {
		t.Fatal("first completion must be new")
	}
	if string(got.Storage) != string(result.Storage) || got.IdentityID != result.IdentityID {
		t.Fatalf("completion result mismatch: %+v", got)
	}
	replay, isNew := session.complete(completedLogin{IdentityID: "zcode-other", Storage: []byte(`{"zcode":{"other":1}}`)})
	if isNew {
		t.Fatal("second completion must be rejected")
	}
	if replay.IdentityID != result.IdentityID || string(replay.Storage) != string(result.Storage) {
		t.Fatalf("second completion returned a different result: %+v", replay)
	}
	snap := session.snapshot()
	if snap.State != authSessionCompleted {
		t.Fatalf("state = %q, want completed", snap.State)
	}
	if session.pollSecret != "" || session.flowID != "" || session.client != nil {
		t.Fatal("terminal session must not retain secrets or a client")
	}
}

func TestSessionFinalizationIsClaimedExactlyOnce(t *testing.T) {
	resetSessions(t)
	session, _ := newTestSession(t, activeSessions, "flow-claim")

	if !session.beginFinalization() {
		t.Fatal("first finalization claim must win")
	}
	if session.beginFinalization() {
		t.Fatal("second finalization claim must lose: the ready path must never run twice")
	}
	// The claim does not change the lifecycle state; completion still governs.
	if snap := session.snapshot(); snap.State != authSessionPending {
		t.Fatalf("state = %q after claiming, want pending", snap.State)
	}
}

func TestSessionFailureIsFinalAndProtected(t *testing.T) {
	resetSessions(t)
	session, _ := newTestSession(t, activeSessions, "flow-fail")
	session.fail("upstream rejected")

	snap := session.snapshot()
	if snap.State != authSessionFailed || snap.Message != "upstream rejected" {
		t.Fatalf("unexpected failed session: %+v", snap)
	}
	// A late completion must not resurrect a failed session.
	if _, isNew := session.complete(completedLogin{IdentityID: "x"}); isNew {
		t.Fatal("failed session must not complete afterwards")
	}
	if session.pollSecret != "" {
		t.Fatal("failed session must drop its polling secret")
	}
}

func TestSessionExpiresAfterTTLAndKeepsTerminalStatus(t *testing.T) {
	resetSessions(t)
	now := time.Now()
	activeSessions.now = func() time.Time { return now }
	session, _ := newTestSession(t, activeSessions, "flow-expire")

	now = now.Add(time.Duration(defaultConfig().OAuth.SessionTTLSeconds)*time.Second + time.Second)
	if state := session.expireIfDue(activeSessions.now()); state != authSessionExpired {
		t.Fatalf("state = %q, want expired after TTL", state)
	}
	snap := session.snapshot()
	if snap.Message != "authorization session expired" {
		t.Fatalf("expired message = %q", snap.Message)
	}
	if session.pollSecret != "" || session.client != nil {
		t.Fatal("expired session must drop secrets and client")
	}
	// Late completion must not resurrect the expired session.
	if _, isNew := session.complete(completedLogin{IdentityID: "x"}); isNew {
		t.Fatal("expired session must not complete afterwards")
	}
}

func TestSessionBeforeTTLStaysPending(t *testing.T) {
	resetSessions(t)
	now := time.Now()
	activeSessions.now = func() time.Time { return now }
	session, _ := newTestSession(t, activeSessions, "flow-alive")

	now = now.Add(time.Duration(defaultConfig().OAuth.SessionTTLSeconds)*time.Second - time.Minute)
	if state := session.expireIfDue(activeSessions.now()); state != authSessionPending {
		t.Fatalf("state = %q, want pending before TTL", state)
	}
}

func TestSessionCancelIsTerminalAndReleasesSecrets(t *testing.T) {
	resetSessions(t)
	session, _ := newTestSession(t, activeSessions, "flow-cancel")

	if !activeSessions.cancel(session.id) {
		t.Fatal("cancelling a pending session must succeed")
	}
	snap := session.snapshot()
	if snap.State != authSessionCancelled {
		t.Fatalf("state = %q, want cancelled", snap.State)
	}
	if snap.Message != "authorization cancelled by operator" {
		t.Fatalf("cancelled message = %q", snap.Message)
	}
	if session.pollSecret != "" || session.flowID != "" || session.authorizeURL != "" || session.client != nil {
		t.Fatal("cancelled session must drop every secret and client")
	}
	// Cancel is a terminal state: a completion and a second cancel must both
	// be refused, exactly as they are for failed and expired sessions.
	if _, isNew := session.complete(completedLogin{IdentityID: "x"}); isNew {
		t.Fatal("cancelled session must not complete afterwards")
	}
	if activeSessions.cancel(session.id) {
		t.Fatal("cancelling an already-cancelled session must report false")
	}
}

func TestSessionCancelDoesNotOverwriteCompletion(t *testing.T) {
	resetSessions(t)
	session, _ := newTestSession(t, activeSessions, "flow-cancel-race")
	if _, isNew := session.complete(completedLogin{IdentityID: "zcode-user", Storage: []byte(`{"zcode":{}}`)}); !isNew {
		t.Fatal("completion must land first")
	}
	// A cancel racing a landed credential loses: the login is real and the
	// operator must never see "cancelled" over it.
	if activeSessions.cancel(session.id) {
		t.Fatal("cancelling a completed session must report false")
	}
	if state := session.snapshot().State; state != authSessionCompleted {
		t.Fatalf("state = %q, want completed after the lost cancel", state)
	}
}

func TestSessionManagerCancelUnknownIDIsFalse(t *testing.T) {
	resetSessions(t)
	if activeSessions.cancel("00000000000000000000000000000000") {
		t.Fatal("cancelling an unknown session id must report false")
	}
}

func TestSessionManagerRemoveDropsSecrets(t *testing.T) {
	resetSessions(t)
	session, _ := newTestSession(t, activeSessions, "flow-remove")
	id := session.id
	if activeSessions.lookup(id) == nil {
		t.Fatal("session must be findable after creation")
	}
	activeSessions.remove(id)
	if activeSessions.lookup(id) != nil {
		t.Fatal("removed session must not be findable")
	}
	if session.pollSecret != "" || session.client != nil {
		t.Fatal("removed session must drop secrets and client")
	}
}

func TestSessionManagerShutdownClearsEverything(t *testing.T) {
	resetSessions(t)
	newTestSession(t, activeSessions, "flow-shutdown-a")
	newTestSession(t, activeSessions, "flow-shutdown-b")
	activeSessions.shutdownAll()
	activeSessions.mu.Lock()
	remaining := len(activeSessions.sessions)
	timerCount := len(activeSessions.timers)
	activeSessions.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("shutdown left %d sessions", remaining)
	}
	if timerCount != 0 {
		// A cleanup timer surviving shutdown would fire after the host
		// unloads the dynamic library and crash the process.
		t.Fatalf("shutdown left %d cleanup timers", timerCount)
	}
}

func TestSessionManagerRemoveStopsItsCleanupTimer(t *testing.T) {
	resetSessions(t)
	session, _ := newTestSession(t, activeSessions, "flow-timer-remove")
	activeSessions.mu.Lock()
	count := len(activeSessions.timers)
	activeSessions.mu.Unlock()
	if count != 1 {
		t.Fatalf("timers after create = %d, want 1", count)
	}
	activeSessions.remove(session.id)
	activeSessions.mu.Lock()
	count = len(activeSessions.timers)
	activeSessions.mu.Unlock()
	if count != 0 {
		t.Fatalf("timers after remove = %d, want 0", count)
	}
}

func TestSessionLookupExpiryIsLazy(t *testing.T) {
	resetSessions(t)
	now := time.Now()
	activeSessions.now = func() time.Time { return now }
	session, _ := newTestSession(t, activeSessions, "flow-lazy")

	now = now.Add(time.Duration(defaultConfig().OAuth.SessionTTLSeconds)*time.Second + 2*time.Second)
	if activeSessions.lookup(session.id) == nil {
		t.Fatal("expired-but-kept session must stay reachable for terminal status")
	}
	if session.snapshot().State != authSessionExpired {
		t.Fatalf("state = %q, want expired via lazy lookup", session.snapshot().State)
	}
	// After the grace window the cleanup timer reclaims the record; remove
	// simulates that deterministic part of the janitor.
	activeSessions.remove(session.id)
	if activeSessions.lookup(session.id) != nil {
		t.Fatal("reclaimed session must be gone")
	}
}

func TestPollSecretNeverAppearsInSessionState(t *testing.T) {
	resetSessions(t)
	session, secret := newTestSession(t, activeSessions, "flow-secret")
	snap := session.snapshot()
	if strings.Contains(snap.Message, secret) {
		t.Fatal("message must not carry the polling secret")
	}
	if snap.State != authSessionPending {
		t.Fatalf("fresh session state = %q", snap.State)
	}
	if session.authorizeURL == "" {
		t.Fatal("pending session must expose the authorize URL")
	}
}
