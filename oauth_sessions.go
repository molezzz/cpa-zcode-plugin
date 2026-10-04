package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"sort"
	"strings"
	"sync"
	"time"
)

// authSessionState is the lifecycle state of one authorization session.
// pending sessions may still drive the upstream OAuth flow; terminal states
// are kept read-only so a repeated poll observes an idempotent result.
type authSessionState string

const (
	authSessionPending   authSessionState = "pending"
	authSessionCompleted authSessionState = "completed"
	authSessionFailed    authSessionState = "failed"
	authSessionExpired   authSessionState = "expired"
)

// pollSecretBytes is the upstream polling secret length. It authenticates
// every OAuth init/poll call for exactly one session and must never be
// persisted, logged, or returned to the host.
const pollSecretBytes = 32

// sessionIDBytes is the handle length returned to the host as login State.
// Only a caller holding this unguessable value can complete or read the
// session, which is what restricts the session to its creator.
const sessionIDBytes = 32

// sessionGrace keeps terminal sessions readable for a short window past
// expiry so concurrent host polls observe a stable terminal status instead
// of a spurious "unknown state" error; a later cleanup reclaims them.
const sessionGrace = time.Minute

// completedLogin is the one-time successful result of a session.
type completedLogin struct {
	IdentityID string
	Storage    []byte
}

// authSession is one short-lived, single-completion ZCode OAuth flow. It owns
// an independent polling secret, HTTP client, and cookie jar so no state can
// leak between sessions even if a future flow starts using cookies.
type authSession struct {
	id           string
	flowID       string
	authorizeURL string
	pollSecret   string
	client       *http.Client
	// site is the site this flow authorizes against, fixed when the session was
	// created. The ready payload's access token is read against it, so a session
	// must not re-read a configured default: the config may change while the
	// browser is still on the authorize page, and a token read under the other
	// site's key belongs to an account this session never authorized.
	site string

	createdAt time.Time
	expiresAt time.Time

	mu      sync.Mutex
	state   authSessionState
	message string
	result  *completedLogin
	// finalizing marks the one poll that claimed the right to process an
	// upstream "ready" verdict. The claimant runs the credential completion,
	// including the managed key exchange; overlapping polls of the same
	// session stay pending instead of racing a duplicate exchange.
	finalizing bool
}

// newState builds a session with its own random identifiers, HTTP client,
// and cookie jar. The caller must have validated the flow data.
func newState(id, flowID, authorizeURL, pollSecret string, client *http.Client, now time.Time, ttl time.Duration, site string) *authSession {
	return &authSession{
		id:           id,
		flowID:       flowID,
		authorizeURL: authorizeURL,
		pollSecret:   pollSecret,
		client:       client,
		site:         site,
		createdAt:    now,
		expiresAt:    now.Add(ttl),
		state:        authSessionPending,
	}
}

// profile resolves the session's site. The site is fixed when the flow starts
// and only ever read, so an unrecognized value falls back the same way a stored
// credential's does: this build cannot know a site it has no profile for, and
// reading it as the international one keeps a pending poll readable.
func (s *authSession) profile() siteProfile {
	return siteProfileOrDefault(strings.TrimSpace(s.site))
}

// pollUpstream performs one upstream poll using only this session's client
// and secret. It returns the raw response payload and HTTP status; callers
// interpret the upstream status field. The context must already carry the
// request deadline (see sessionRequestContext).
func (s *authSession) pollUpstream(ctx context.Context, baseURL string, maxBytes int64) ([]byte, int, error) {
	s.mu.Lock()
	secret := s.pollSecret
	flowID := s.flowID
	client := s.client
	s.mu.Unlock()
	if secret == "" || flowID == "" || client == nil {
		return nil, 0, errors.New("authorization session is no longer usable")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pollEndpointURL(baseURL, flowID), nil)
	if err != nil {
		return nil, 0, fmt.Errorf("build authorization poll request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer drainAndClose(resp.Body)
	body, err := readLimited(resp.Body, maxBytes)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read authorization poll response: %w", err)
	}
	return body, resp.StatusCode, nil
}

// sessionRequestContext bounds one upstream call by both the request timeout
// and the remaining session lifetime. It fails when the session is already
// terminal or expired, so callers never hit upstream with a dead session.
func (s *authSession) sessionRequestContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc, bool) {
	s.mu.Lock()
	state := s.state
	expiresAt := s.expiresAt
	s.mu.Unlock()
	if state != authSessionPending {
		return nil, nil, false
	}
	remaining := time.Until(expiresAt)
	if remaining <= 0 {
		return nil, nil, false
	}
	if timeout <= 0 || timeout > remaining {
		timeout = remaining
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	return ctx, cancel, true
}

// beginFinalization claims the one-time right to process an upstream "ready"
// verdict for this session. Exactly one caller wins; every other concurrent
// poll must report pending so the host retries and observes the single,
// consistent completion — the ready path performs upstream side effects
// (the managed key exchange), so it must never run twice.
func (s *authSession) beginFinalization() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finalizing {
		return false
	}
	s.finalizing = true
	return true
}

// complete transitions a pending session to completed exactly once and
// returns the stored result. A session that already reached a terminal state
// returns its existing outcome without changing anything, so concurrent
// polls observe one consistent completion and the credential is produced a
// single time.
func (s *authSession) complete(result completedLogin) (completedLogin, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != authSessionPending {
		if s.result != nil {
			return *s.result, false
		}
		return completedLogin{}, false
	}
	s.state = authSessionCompleted
	s.result = &result
	s.clearSecretsLocked()
	return result, true
}

// fail transitions a pending session to failed exactly once. The message
// must already be redacted; it becomes visible to the host.
func (s *authSession) fail(message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != authSessionPending {
		return
	}
	s.state = authSessionFailed
	s.message = message
	s.clearSecretsLocked()
}

// expireIfDue moves a still-pending session past its deadline into the
// expired terminal state. It reports the current state after the check.
func (s *authSession) expireIfDue(now time.Time) authSessionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == authSessionPending && !now.Before(s.expiresAt) {
		s.state = authSessionExpired
		s.message = "authorization session expired"
		s.clearSecretsLocked()
	}
	return s.state
}

// destroy releases the session's secrets and connections; it is idempotent
// and safe to call for cleanup on remove and shutdown paths.
func (s *authSession) destroy() {
	s.mu.Lock()
	s.clearSecretsLocked()
	s.mu.Unlock()
}

// clearSecretsLocked drops every secret-bearing field of a terminal session.
// The completed result stays readable for idempotent re-polls until cleanup.
func (s *authSession) clearSecretsLocked() {
	s.pollSecret = ""
	s.flowID = ""
	s.authorizeURL = ""
	if s.client != nil {
		s.client.CloseIdleConnections()
	}
	s.client = nil
}

// sessionSnapshot is a read-only view of the session state for poll replies.
type sessionSnapshot struct {
	State   authSessionState
	Message string
	Result  *completedLogin
}

// snapshot reads the session state under lock.
func (s *authSession) snapshot() sessionSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return sessionSnapshot{State: s.state, Message: s.message, Result: s.result}
}

// sessionManager owns every live authorization session. Creation, lookup,
// expiry, and shutdown are serialized by one mutex; the per-session
// completion guard lives on the session itself.
type sessionManager struct {
	mu       sync.Mutex
	sessions map[string]*authSession
	// timers tracks every per-session cleanup timer so shutdown can stop
	// them: a timer firing after the host unloads the dynamic library would
	// jump into unmapped code.
	timers map[string]*time.Timer
	// now is a test seam for expiry behaviour.
	now func() time.Time
}

func newSessionManager() *sessionManager {
	return &sessionManager{
		sessions: map[string]*authSession{},
		timers:   map[string]*time.Timer{},
		now:      time.Now,
	}
}

// activeSessions holds plugin-wide authorization sessions; shutdown clears it.
var activeSessions = newSessionManager()

// create registers a new pending session that already holds its upstream
// flow data, poll secret, and the dedicated HTTP client used for the init
// call, and schedules its cleanup. It fails only on local randomness errors.
func (m *sessionManager) create(flowID, authorizeURL, pollSecret string, client *http.Client, ttl time.Duration, site string) (*authSession, error) {
	sessionID, err := randomHexToken(sessionIDBytes)
	if err != nil {
		return nil, fmt.Errorf("generate authorization session id: %w", err)
	}
	session := newState(sessionID, flowID, authorizeURL, pollSecret, client, m.now(), ttl, site)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[sessionID] = session
	m.timers[sessionID] = time.AfterFunc(ttl+sessionGrace, func() { m.remove(sessionID) })
	return session, nil
}

// lookup returns the session for an unguessable handle, lazily expiring
// pending sessions whose TTL has passed. Unknown handles return nil.
func (m *sessionManager) lookup(sessionID string) *authSession {
	m.mu.Lock()
	session := m.sessions[sessionID]
	m.mu.Unlock()
	if session == nil {
		return nil
	}
	session.expireIfDue(m.now())
	return session
}

// remove deletes one session, releasing its secrets, connections, and the
// pending cleanup timer if it has not fired yet.
func (m *sessionManager) remove(sessionID string) {
	m.mu.Lock()
	session := m.sessions[sessionID]
	delete(m.sessions, sessionID)
	timer := m.timers[sessionID]
	delete(m.timers, sessionID)
	m.mu.Unlock()
	if timer != nil {
		timer.Stop()
	}
	if session != nil {
		session.destroy()
	}
}

// shutdownAll clears every session; it runs from runShutdown.
func (m *sessionManager) shutdownAll() {
	m.mu.Lock()
	sessions := m.sessions
	timers := m.timers
	m.sessions = map[string]*authSession{}
	m.timers = map[string]*time.Timer{}
	m.mu.Unlock()
	for _, timer := range timers {
		timer.Stop()
	}
	for _, session := range sessions {
		session.destroy()
	}
}

// sessionView is the management-plane view of one authorization session. It
// carries lifecycle facts and a sanitized message only: the authorize URL,
// flow identifier, and polling secret are authorization parameters that never
// appear in management data.
type sessionView struct {
	State      string `json:"state"`
	Message    string `json:"message,omitempty"`
	CreatedAt  string `json:"created_at,omitempty"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	IdentityID string `json:"identity_id,omitempty"`
}

// view lists the redacted state of every live session, settling pending
// sessions whose TTL has passed first so the page never shows a stale
// pending entry.
func (m *sessionManager) view(now time.Time) []sessionView {
	m.mu.Lock()
	ids := make([]string, 0, len(m.sessions))
	for id := range m.sessions {
		ids = append(ids, id)
	}
	sessions := make([]*authSession, 0, len(ids))
	for _, id := range ids {
		sessions = append(sessions, m.sessions[id])
	}
	m.mu.Unlock()

	views := make([]sessionView, 0, len(sessions))
	for _, session := range sessions {
		session.expireIfDue(now)
		snap := session.snapshot()
		view := sessionView{
			State:     string(snap.State),
			Message:   snap.Message,
			CreatedAt: session.createdAt.UTC().Format(time.RFC3339),
			ExpiresAt: session.expiresAt.UTC().Format(time.RFC3339),
		}
		if snap.Result != nil {
			view.IdentityID = snap.Result.IdentityID
		}
		views = append(views, view)
	}
	sort.Slice(views, func(i, j int) bool {
		if views[i].CreatedAt != views[j].CreatedAt {
			return views[i].CreatedAt > views[j].CreatedAt
		}
		return views[i].State < views[j].State
	})
	return views
}

// randomHexToken returns 2*bytes hex characters from crypto/rand.
func randomHexToken(nBytes int) (string, error) {
	raw := make([]byte, nBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("read crypto/rand: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// newSessionHTTPClient builds the per-session client: its own cookie jar so
// cookies can never leak across sessions, the configured connect timeout,
// and standard environment proxy handling.
func newSessionHTTPClient(cfg Config) *http.Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		// cookiejar.New(nil) never fails today; fall back to no jar rather
		// than blocking login on an unreachable code path.
		jar = nil
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout: time.Duration(cfg.Upstream.ConnectTimeoutSeconds) * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			ForceAttemptHTTP2:     true,
		},
		Jar:     jar,
		Timeout: time.Duration(cfg.Upstream.RequestTimeoutSeconds) * time.Second,
	}
}
