package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

// The OAuth access token the upstream returns at login is not itself the
// credential every business endpoint accepts, but how far it has to be carried
// is a property of the site:
//
//   - On the international site the token is issued for the identity service.
//     The api.z.ai business endpoints expect a different token, obtained by
//     exchanging the OAuth token at POST /api/auth/z/login. Calling a business
//     endpoint with the OAuth token answers 401 "token expired or incorrect" even
//     moments after a successful login, which reads exactly like a stale
//     credential and sends the operator to re-authenticate for nothing.
//   - On the domestic site the business endpoints accept the access token
//     itself; the capture shows every getCustomerInfo and api_keys call carrying
//     it directly and answering 200 (session 20261004-085036_a4f2e8). There is no
//     second token to obtain, and looking for one would record an exchange
//     failure on a perfectly good login.
//
// The plugin therefore keeps both where the site has both: the OAuth token as the
// renewable exchange material (it carries an exp claim), and the exchanged
// business token as the material that calls the business API.

// businessTokenRefreshSkew is how long before its stated expiry a cached
// business token is treated as expired. The upstream rejects an expired token
// mid-request; refreshing ahead of the deadline turns that from a failed
// request into a background exchange.
const businessTokenRefreshSkew = 5 * time.Minute

// errZaiOAuthRequired reports that the OAuth material is absent, expired, or
// was refused by the exchange, so no business token can be obtained. It is the
// one condition that requires the user to log in again: nothing the plugin can
// do short of a fresh authorization produces the missing material.
var errZaiOAuthRequired = errors.New("zai_oauth_required")

// businessToken is one exchanged Z.AI business token together with the instant
// it stops being usable. A zero ExpiresAt means the upstream stated no expiry,
// so the token is used for this pass and not cached for a later one.
type businessToken struct {
	Token     string
	ExpiresAt time.Time
}

// oauthMaterial is the plugin-owned OAuth namespace of one auth document: the
// renewable exchange material and the business token exchanged from it.
type oauthMaterial struct {
	AccessToken string
	// ReceivedAt is when the OAuth token arrived. It is the only age signal
	// available for the zcode-plan JWT, which carries no exp claim.
	ReceivedAt string
	// BusinessToken is the last successful exchange, with the instant it stops
	// being usable. Persisting it means a restart does not have to re-exchange.
	BusinessToken   string
	BusinessExpires string
}

// readOAuthMaterial reads the OAuth namespace of an auth document. It never
// fails the caller: a document without an OAuth namespace reads as absent
// material, which the resolver turns into a re-login request.
func readOAuthMaterial(doc []byte) oauthMaterial {
	var root struct {
		Zcode struct {
			OAuth struct {
				AccessToken     string `json:"access_token"`
				ReceivedAt      string `json:"received_at"`
				BusinessToken   string `json:"business_token"`
				BusinessExpires string `json:"business_token_expires_at"`
				BusinessChecked string `json:"business_token_checked_at"`
				ExchangeError   string `json:"business_token_error"`
				ExchangeErrorAt string `json:"business_token_error_at"`
			} `json:"oauth"`
		} `json:"zcode"`
	}
	if err := json.Unmarshal(doc, &root); err != nil {
		return oauthMaterial{}
	}
	oauth := root.Zcode.OAuth
	return oauthMaterial{
		AccessToken:     strings.TrimSpace(oauth.AccessToken),
		ReceivedAt:      strings.TrimSpace(oauth.ReceivedAt),
		BusinessToken:   strings.TrimSpace(oauth.BusinessToken),
		BusinessExpires: strings.TrimSpace(oauth.BusinessExpires),
	}
}

// usableBusinessToken returns the recorded business token when it is still
// inside its window. The skew is subtracted so a token is never used within the
// last five minutes of its life. The lifetime rides along with the token: a
// caller that re-caches this entry needs it, and dropping it would make the
// cache entry read as unknown-lived.
func (m oauthMaterial) usableBusinessToken(now time.Time) (businessToken, bool) {
	if m.BusinessToken == "" {
		return businessToken{}, false
	}
	expiresAt, err := time.Parse(time.RFC3339, m.BusinessExpires)
	if err != nil {
		// An unparsable expiry means the token's lifetime is unknown, which is
		// not evidence it is still good.
		return businessToken{}, false
	}
	if !now.Before(expiresAt.Add(-businessTokenRefreshSkew)) {
		return businessToken{}, false
	}
	return businessToken{Token: m.BusinessToken, ExpiresAt: expiresAt}, true
}

// knownOAuthFields lists every field the plugin writes into the oauth
// namespace. The merge drops exactly these before applying the new value, so
// unknown fields recorded by other plugin versions survive untouched.
var knownOAuthFields = []string{
	"access_token", "received_at",
	"business_token", "business_token_expires_at", "business_token_checked_at",
	"business_token_error", "business_token_error_at",
}

// writeBusinessToken records one successful exchange into the document's OAuth
// namespace. A patch failure returns the document unchanged: the token is
// cached in memory instead, which costs one extra exchange rather than the
// business credential.
func writeBusinessToken(doc []byte, token businessToken, now time.Time) []byte {
	patched, err := patchZcodeNamespace(doc, func(zcode map[string]any) error {
		oauth, _ := zcode["oauth"].(map[string]any)
		if oauth == nil {
			oauth = map[string]any{}
		}
		for _, field := range knownOAuthFields {
			if field != "access_token" && field != "received_at" {
				delete(oauth, field)
			}
		}
		oauth["business_token"] = token.Token
		if !token.ExpiresAt.IsZero() {
			oauth["business_token_expires_at"] = token.ExpiresAt.UTC().Format(time.RFC3339)
		} else {
			delete(oauth, "business_token_expires_at")
		}
		oauth["business_token_checked_at"] = now.UTC().Format(time.RFC3339)
		delete(oauth, "business_token_error")
		delete(oauth, "business_token_error_at")
		zcode["oauth"] = oauth
		return nil
	})
	if err != nil {
		return doc
	}
	return patched
}

// recordBusinessTokenFailure notes in the document that the OAuth material
// could not produce a business token. It is what the management page reads to
// tell the user their business-side access has lapsed: the Coding Plan JWT
// keeps working throughout, so nothing else would say so.
func recordBusinessTokenFailure(doc []byte, now time.Time) []byte {
	patched, err := patchZcodeNamespace(doc, func(zcode map[string]any) error {
		oauth, _ := zcode["oauth"].(map[string]any)
		if oauth == nil {
			oauth = map[string]any{}
		}
		oauth["business_token_error"] = errZaiOAuthRequired.Error()
		oauth["business_token_error_at"] = now.UTC().Format(time.RFC3339)
		zcode["oauth"] = oauth
		return nil
	})
	if err != nil {
		return doc
	}
	return patched
}

// businessTokenState is the plugin-wide business token cache. It holds the
// freshly exchanged token of an identity so the requests that follow a login
// do not each pay for an exchange, and so a restart reads the persisted copy
// back instead of re-exchanging immediately.
type businessTokenState struct {
	mu      sync.Mutex
	entries map[string]cachedBusinessToken
}

type cachedBusinessToken struct {
	// SourceToken is the OAuth token this business token was exchanged from.
	// A newer login replaces the source, so a cache entry can never outlive
	// the material it was derived from.
	SourceToken string
	Token       businessToken
}

// businessTokenStore is the plugin-wide cache.
var activeBusinessTokens = newBusinessTokenStore()

// newBusinessTokenStore builds an empty cache. Tests use it to isolate runs
// from the plugin-wide instance.
func newBusinessTokenStore() *businessTokenState {
	return &businessTokenState{entries: map[string]cachedBusinessToken{}}
}

// get returns the cached business token together with its whole recorded
// lifetime. Callers persist that lifetime, so handing back only the token
// string would drop it — and a token persisted without an expiry reads as
// unknown-lived, which costs an exchange on every restart.
func (s *businessTokenState) get(identity, sourceToken string, now time.Time) (businessToken, bool) {
	if strings.TrimSpace(identity) == "" || strings.TrimSpace(sourceToken) == "" {
		return businessToken{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[identity]
	if !ok || entry.SourceToken != sourceToken {
		return businessToken{}, false
	}
	if !entry.Token.ExpiresAt.IsZero() && !now.Before(entry.Token.ExpiresAt.Add(-businessTokenRefreshSkew)) {
		return businessToken{}, false
	}
	return entry.Token, true
}

func (s *businessTokenState) put(identity, sourceToken string, token businessToken) {
	if strings.TrimSpace(identity) == "" || strings.TrimSpace(sourceToken) == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[identity] = cachedBusinessToken{SourceToken: sourceToken, Token: token}
}

// resolveBusinessToken returns a usable business token for one auth document,
// exchanging the OAuth token when the site requires it and no cached one is
// inside its window.
//
// The three sources are tried in order of cost: the in-memory cache, the token
// persisted on the document, and finally the exchange itself. Only the exchange
// is a network call, so a warm plugin performs none.
//
// A site whose business endpoints accept the access token directly skips all of
// it: there is nothing to exchange and nothing to cache, so the cheapest correct
// answer is the material the login already produced.
//
// Every failure mode — absent OAuth material, an exchange the upstream refuses,
// an unparsable answer — collapses to errZaiOAuthRequired, because each of them
// means the same actionable thing to the user and none of them should be
// mistaken for a business-endpoint rejection.
func resolveBusinessToken(ctx context.Context, client *http.Client, identityID string, doc []byte, profile siteProfile, now time.Time) (string, error) {
	material := readOAuthMaterial(doc)
	accessToken := material.AccessToken
	if accessToken == "" {
		return "", errZaiOAuthRequired
	}
	if !profile.ExchangesBusinessToken {
		return accessToken, nil
	}
	if cached, ok := activeBusinessTokens.get(identityID, accessToken, now); ok {
		return cached.Token, nil
	}
	if cached, ok := material.usableBusinessToken(now); ok {
		activeBusinessTokens.put(identityID, accessToken, cached)
		return cached.Token, nil
	}

	token, err := exchangeBusinessTokenWithExpiry(ctx, client, accessToken, profile)
	if err != nil {
		return "", err
	}
	activeBusinessTokens.put(identityID, accessToken, token)
	return token.Token, nil
}

// businessTokenFor returns the credential the site's business endpoints accept,
// together with the lifetime that goes with it.
//
// It is the one place that answers "does this site need an exchange?", so the key
// exchange, the recording step, and the resolver cannot disagree about it: three
// callers answering that question separately is how a site ends up being sent to
// a login endpoint it does not have. A directly-issued token carries no stated
// expiry, so its lifetime is the zero instant — usable now, never cached.
func businessTokenFor(ctx context.Context, client *http.Client, accessToken string, profile siteProfile) (businessToken, error) {
	if !profile.ExchangesBusinessToken {
		return businessToken{Token: accessToken}, nil
	}
	return exchangeBusinessTokenWithExpiry(ctx, client, accessToken, profile)
}

// exchangeBusinessTokenWithExpiry trades the OAuth access token for a business
// token and reads the lifetime the upstream states.
//
// The upstream answers business outcomes inside HTTP 200 as readily as in 4xx,
// so the envelope's own code decides success rather than the status. A response
// whose code is absent or successful and whose success flag is not false is
// accepted; anything else is a refusal and becomes errZaiOAuthRequired.
func exchangeBusinessTokenWithExpiry(ctx context.Context, client *http.Client, accessToken string, profile siteProfile) (businessToken, error) {
	payload, err := json.Marshal(map[string]string{"token": accessToken})
	if err != nil {
		return businessToken{}, errZaiOAuthRequired
	}
	body, err := managedKeyRequest(ctx, client, http.MethodPost, siteBusinessLoginURL(profile), payload, "")
	if err != nil {
		return businessToken{}, errZaiOAuthRequired
	}
	if !zaiBusinessSuccess(body) {
		return businessToken{}, errZaiOAuthRequired
	}
	var parsed struct {
		Data struct {
			AccessToken      string          `json:"access_token"`
			AccessTokenCamel string          `json:"accessToken"`
			ExpiresIn        json.RawMessage `json:"expires_in"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return businessToken{}, errZaiOAuthRequired
	}
	token := strings.TrimSpace(parsed.Data.AccessToken)
	if token == "" {
		token = strings.TrimSpace(parsed.Data.AccessTokenCamel)
	}
	if token == "" {
		return businessToken{}, errZaiOAuthRequired
	}
	return businessToken{Token: token, ExpiresAt: expiresAtFromNow(parsed.Data.ExpiresIn, time.Now())}, nil
}

// expiresAtFromNow reads an expires_in lifetime in seconds. A missing,
// non-numeric, or non-positive lifetime yields the zero instant, which callers
// treat as "usable now, not cacheable": an unknown lifetime must not be invented
// into a long window that would keep an expired token in circulation.
func expiresAtFromNow(raw json.RawMessage, now time.Time) time.Time {
	seconds, _, ok := optionalNumber(raw)
	if !ok || seconds == nil || *seconds <= 0 {
		return time.Time{}
	}
	return now.Add(time.Duration(*seconds * float64(time.Second)))
}
