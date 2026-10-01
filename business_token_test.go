package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// bizTokenFixture serves the Z.AI business login and counts how often it was
// called, so a test can assert that caching actually avoided the exchange.
type bizTokenFixture struct {
	srv    *httptest.Server
	calls  atomic.Int64
	bodies atomic.Value // []string
}

func newBizTokenFixture(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *bizTokenFixture {
	t.Helper()
	fixture := &bizTokenFixture{}
	fixture.bodies.Store([]string(nil))
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/z/login", func(w http.ResponseWriter, r *http.Request) {
		fixture.calls.Add(1)
		handler(w, r)
	})
	fixture.srv = httptest.NewServer(mux)
	t.Cleanup(fixture.srv.Close)

	original := zaiAPIBase
	zaiAPIBase = fixture.srv.URL
	t.Cleanup(func() { zaiAPIBase = original })
	// The cache is plugin-wide, so each test starts from an empty one.
	t.Cleanup(func() { activeBusinessTokens = newBusinessTokenStore() })
	activeBusinessTokens = newBusinessTokenStore()
	return fixture
}

func bizLoginOK(expiresIn int) string {
	return `{"code":200,"success":true,"data":{"access_token":"biz-token-1","expires_in":` +
		strconv.Itoa(expiresIn) + `,"userType":"PERSONAL"}}`
}

func authDocWith(t *testing.T, accessToken, receivedAt string) []byte {
	t.Helper()
	doc := map[string]any{"zcode": map[string]any{
		"identity_id": "zcode-user-1",
		"jwt":         map[string]any{"token": "jwt-token-1", "status": "active"},
	}}
	if accessToken != "" {
		doc["zcode"].(map[string]any)["oauth"] = map[string]any{
			"access_token": accessToken,
			"received_at":  receivedAt,
		}
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestResolveBusinessTokenExchangesOAuthToken covers the gap the issue reports:
// the OAuth access token is not what the business API accepts, and using it
// directly answers 401 moments after a successful login.
func TestResolveBusinessTokenExchangesOAuthToken(t *testing.T) {
	fixture := newBizTokenFixture(t, func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("login body not JSON: %v", err)
		}
		if body["token"] != "oauth-access-token" {
			t.Errorf("login token = %q, want the OAuth access token", body["token"])
		}
		w.Write([]byte(bizLoginOK(525600)))
	})
	doc := authDocWith(t, "oauth-access-token", time.Now().UTC().Format(time.RFC3339))
	token, err := resolveBusinessToken(context.Background(), fixture.srv.Client(),
		"zcode-user-1", doc, time.Now())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if token != "biz-token-1" {
		t.Fatalf("token = %q, want the exchanged business token", token)
	}
	if fixture.calls.Load() != 1 {
		t.Fatalf("login calls = %d, want exactly one exchange", fixture.calls.Load())
	}
}

// TestResolveBusinessTokenCachesWithinLifetime asserts the cache actually
// prevents repeat exchanges while the token is inside its window.
func TestResolveBusinessTokenCachesWithinLifetime(t *testing.T) {
	fixture := newBizTokenFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(bizLoginOK(3600)))
	})
	now := time.Now()
	doc := authDocWith(t, "oauth-access-token", now.UTC().Format(time.RFC3339))
	for i := 0; i < 3; i++ {
		if _, err := resolveBusinessToken(context.Background(), fixture.srv.Client(),
			"zcode-user-1", doc, now); err != nil {
			t.Fatalf("resolve %d: %v", i, err)
		}
	}
	if fixture.calls.Load() != 1 {
		t.Fatalf("login calls = %d, want one exchange for three resolutions", fixture.calls.Load())
	}
}

// TestResolveBusinessTokenRefreshesBeforeExpiry is the point of the skew: a
// token inside the last five minutes of its life is refreshed rather than used
// on a request that would be rejected mid-flight.
func TestResolveBusinessTokenRefreshesBeforeExpiry(t *testing.T) {
	fixture := newBizTokenFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(bizLoginOK(600)))
	})
	issued := time.Now()
	doc := authDocWith(t, "oauth-access-token", issued.UTC().Format(time.RFC3339))
	// Just outside the skew: the cached token is still good.
	if _, err := resolveBusinessToken(context.Background(), fixture.srv.Client(),
		"zcode-user-1", doc, issued); err != nil {
		t.Fatalf("initial resolve: %v", err)
	}
	// Nine minutes later the token has 60s left, inside the 5-minute skew.
	if _, err := resolveBusinessToken(context.Background(), fixture.srv.Client(),
		"zcode-user-1", doc, issued.Add(9*time.Minute)); err != nil {
		t.Fatalf("reskew resolve: %v", err)
	}
	if fixture.calls.Load() != 2 {
		t.Fatalf("login calls = %d, want a re-exchange inside the skew", fixture.calls.Load())
	}
}

// TestResolveBusinessTokenIgnoresTokenFromOlderLogin keeps a cached business
// token from outliving the OAuth token it was exchanged from: a re-login
// replaces the source, and the old token must not be served for it.
func TestResolveBusinessTokenIgnoresTokenFromOlderLogin(t *testing.T) {
	fixture := newBizTokenFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(bizLoginOK(3600)))
	})
	now := time.Now()
	old := authDocWith(t, "oauth-access-token-old", now.UTC().Format(time.RFC3339))
	if _, err := resolveBusinessToken(context.Background(), fixture.srv.Client(),
		"zcode-user-1", old, now); err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	fresh := authDocWith(t, "oauth-access-token-new", now.UTC().Format(time.RFC3339))
	if _, err := resolveBusinessToken(context.Background(), fixture.srv.Client(),
		"zcode-user-1", fresh, now); err != nil {
		t.Fatalf("resolve after re-login: %v", err)
	}
	if fixture.calls.Load() != 2 {
		t.Fatalf("login calls = %d, want a re-exchange after the source changed", fixture.calls.Load())
	}
}

// TestResolveBusinessTokenReadsPersistedToken covers the restart case: the
// exchange result is written to the auth document, so a restarted plugin serves
// the stored token without paying for the exchange again.
func TestResolveBusinessTokenReadsPersistedToken(t *testing.T) {
	fixture := newBizTokenFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(bizLoginOK(3600)))
	})
	now := time.Now()
	token, err := exchangeBusinessTokenWithExpiry(context.Background(), fixture.srv.Client(), "oauth-access-token")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	// A fresh process: the cache is empty, only the document carries the token.
	activeBusinessTokens = newBusinessTokenStore()
	doc := writeBusinessToken(authDocWith(t, "oauth-access-token", now.UTC().Format(time.RFC3339)), token, now)
	got, err := resolveBusinessToken(context.Background(), fixture.srv.Client(), "zcode-user-1", doc, now)
	if err != nil {
		t.Fatalf("resolve after restart: %v", err)
	}
	if got != token.Token {
		t.Fatalf("token = %q, want the persisted %q", got, token.Token)
	}
	// Only the setup exchange ran; serving the persisted token cost nothing.
	if fixture.calls.Load() != 1 {
		t.Fatalf("login calls = %d, want only the setup exchange", fixture.calls.Load())
	}
}

// TestResolveBusinessTokenRequiresReauth pins the issue's requirement that
// every exchange failure collapses to the one condition the user can act on.
func TestResolveBusinessTokenRequiresReauth(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
		doc     []byte
	}{
		{
			name: "no oauth material at all",
			doc:  authDocWith(t, "", ""),
		},
		{
			name: "exchange refused with a business code",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Write([]byte(`{"code":401,"msg":"token expired or incorrect"}`))
			},
			doc: authDocWith(t, "oauth-access-token", ""),
		},
		{
			name: "exchange succeeded but carried no token",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Write([]byte(`{"code":200,"success":true,"data":{"expires_in":3600}}`))
			},
			doc: authDocWith(t, "oauth-access-token", ""),
		},
		{
			name: "success flag contradicts the payload",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Write([]byte(`{"code":200,"success":false,"data":{"access_token":"x"}}`))
			},
			doc: authDocWith(t, "oauth-access-token", ""),
		},
		{
			name: "unparsable answer",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Write([]byte(`<html>gateway</html>`))
			},
			doc: authDocWith(t, "oauth-access-token", ""),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var fixture *bizTokenFixture
			if tc.handler == nil {
				fixture = newBizTokenFixture(t, func(w http.ResponseWriter, _ *http.Request) {
					t.Error("no exchange may run without OAuth material")
				})
			} else {
				fixture = newBizTokenFixture(t, tc.handler)
			}
			if _, err := resolveBusinessToken(context.Background(), fixture.srv.Client(),
				"zcode-user-1", tc.doc, time.Now()); err != errZaiOAuthRequired {
				t.Fatalf("err = %v, want errZaiOAuthRequired", err)
			}
		})
	}
}

// TestExpiresAtFromNowNeverInventsALifetime keeps an unknown expiry from being
// turned into a long cache window, which would keep a dead token in circulation
// for as long as the window lasted.
func TestExpiresAtFromNowNeverInventsALifetime(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"explicit lifetime", `3600`, true},
		{"absent", ``, false},
		{"null", `null`, false},
		{"zero", `0`, false},
		{"negative", `-5`, false},
		{"quoted", `"3600"`, false},
		{"not a number", `"soon"`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := expiresAtFromNow(json.RawMessage(tc.raw), now)
			if got.IsZero() == tc.want {
				t.Fatalf("expiresAtFromNow(%s) = %v, want zero=%v", tc.raw, got, !tc.want)
			}
		})
	}
}

// TestWriteBusinessTokenPreservesExchangeMaterial keeps the OAuth token and its
// receipt time: they are the renewable source for the next exchange, so
// recording a business token must never consume them.
func TestWriteBusinessTokenPreservesExchangeMaterial(t *testing.T) {
	now := time.Now()
	doc := authDocWith(t, "oauth-access-token", now.UTC().Format(time.RFC3339))
	doc = writeBusinessToken(doc, businessToken{
		Token:     "biz-token",
		ExpiresAt: now.Add(time.Hour),
	}, now)
	material := readOAuthMaterial(doc)
	if material.AccessToken != "oauth-access-token" {
		t.Fatalf("access token = %q, want it preserved", material.AccessToken)
	}
	if material.ReceivedAt == "" {
		t.Fatal("received_at must be preserved for the next exchange")
	}
	if material.BusinessToken != "biz-token" {
		t.Fatalf("business token = %q", material.BusinessToken)
	}
	usable, ok := material.usableBusinessToken(now)
	if !ok || usable.Token != "biz-token" {
		t.Fatalf("usableBusinessToken = %+v ok=%v, want the recorded token", usable, ok)
	}
	// The lifetime must ride along: a caller that re-caches this entry needs
	// it, and an entry without it reads as unknown-lived and expires on sight.
	if usable.ExpiresAt.IsZero() {
		t.Error("usableBusinessToken lost the recorded lifetime")
	}
}

// TestWriteBusinessTokenClearsStaleExpiry covers the case where a previous
// exchange stated a lifetime and the new one does not: the old deadline must
// not be left behind to vouch for a token whose lifetime is unknown.
func TestWriteBusinessTokenClearsStaleExpiry(t *testing.T) {
	now := time.Now()
	doc := authDocWith(t, "oauth-access-token", now.UTC().Format(time.RFC3339))
	doc = writeBusinessToken(doc, businessToken{Token: "old", ExpiresAt: now.Add(time.Hour)}, now)
	doc = writeBusinessToken(doc, businessToken{Token: "new"}, now)
	material := readOAuthMaterial(doc)
	if material.BusinessExpires != "" {
		t.Fatalf("business_token_expires_at = %q, want it cleared", material.BusinessExpires)
	}
	if _, ok := material.usableBusinessToken(now); ok {
		t.Fatal("a token with an unknown lifetime must not be served from the document")
	}
}

// TestLoginPersistsTheBusinessTokenLifetime is the regression test for a lost
// lifetime: the managed key exchange performs the login and caches the result
// with the upstream's expires_in, and the recording step then read that cache.
// When the cache handed back only the token string, the expiry was dropped and
// the token was written with no deadline — which reads as unknown-lived, so the
// skew could never be applied and every restart paid for a fresh exchange.
func TestLoginPersistsTheBusinessTokenLifetime(t *testing.T) {
	fixture := newBizTokenFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(bizLoginOK(3600)))
	})
	now := time.Now()
	// A freshly exchanged token, as the managed key exchange caches it.
	exchanged, err := exchangeBusinessTokenWithExpiry(context.Background(), fixture.srv.Client(), "oauth-access-token")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if exchanged.ExpiresAt.IsZero() {
		t.Fatal("the exchange dropped the upstream's expires_in")
	}
	activeBusinessTokens.put("zcode-user-1", "oauth-access-token", exchanged)

	// The recording step takes that cache hit and must carry the lifetime over.
	doc := attachBusinessToken(
		authDocWith(t, "oauth-access-token", now.UTC().Format(time.RFC3339)),
		"zcode-user-1", "oauth-access-token", now)
	material := readOAuthMaterial(doc)
	if material.BusinessExpires == "" {
		t.Fatal("the persisted business token has no expiry; the lifetime was dropped on the way to disk")
	}
	// And it must be usable: an entry whose deadline is missing would be
	// refused, and one whose deadline is wrong would expire early.
	cached, ok := material.usableBusinessToken(now)
	if !ok {
		t.Fatal("the persisted business token is not usable on the next start")
	}
	if !cached.ExpiresAt.Equal(exchanged.ExpiresAt.Truncate(time.Second)) &&
		!cached.ExpiresAt.Equal(exchanged.ExpiresAt) {
		t.Errorf("persisted expiry = %v, want the exchanged %v", cached.ExpiresAt, exchanged.ExpiresAt)
	}
}
