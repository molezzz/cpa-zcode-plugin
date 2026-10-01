package main

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// The zcode-plan JWT carries no exp claim. It states only when it was issued
// (iat), so nothing in the credential itself says when it stops working: the
// upstream decides, silently, and the only symptom is a rejection that states
// nothing about an expiry.
//
// Inventing a JWT expiry would be worse than the problem. The official client
// does not track one either — it watches the OAuth access token's lifetime and
// re-authorizes on that. So the plugin does the same thing with the one signal
// it does have: the age of the credential, measured from the moment the login
// recorded it. Once that age passes a deliberately generous bound, the JWT is
// no longer used for new requests, and the request is answered by the fallback
// credential while the management plane asks for a fresh authorization.
//
// The bound is long enough that no working session is cut short, and the
// consequence is mild — one credential stops being preferred, and a re-login
// restores it. A wrong guess in this direction costs a renewal; a guess in the
// other direction, marking a live JWT invalid, would strand the account.

// jwtReauthAfter is how long a JWT with no stated expiry is used before the
// plugin prefers to re-authorize. It is a ceiling, not a schedule: nothing
// expires at this instant, the credential simply stops being the first choice
// afterwards.
const jwtReauthAfter = 7 * 24 * time.Hour

// jwtIssuedAt reads the credential's issue time, preferring the JWT's own iat
// claim and falling back to the login's recorded receipt time. The claim is
// authoritative when present; the recorded time covers a credential whose
// claims could not be read at login.
func jwtIssuedAt(token string, material oauthMaterial) (time.Time, bool) {
	claims := decodeJWTPayload(token)
	if issued, ok := numericClaim(claims, "iat"); ok && issued > 0 {
		return time.Unix(issued, 0).UTC(), true
	}
	if received, err := time.Parse(time.RFC3339, strings.TrimSpace(material.ReceivedAt)); err == nil {
		return received.UTC(), true
	}
	return time.Time{}, false
}

// numericClaim reads a numeric JWT claim, accepting both the JSON number the
// spec defines and the string some issuers use.
func numericClaim(claims map[string]any, key string) (int64, bool) {
	raw, ok := claims[key]
	if !ok {
		return 0, false
	}
	switch value := raw.(type) {
	case float64:
		return int64(value), true
	case json.Number:
		number, err := value.Int64()
		if err != nil {
			return 0, false
		}
		return number, true
	case string:
		number, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return 0, false
		}
		return number, true
	default:
		return 0, false
	}
}

// jwtExpiry is what the plugin knows about when a Coding Plan JWT stops working.
// ok is false when the credential states its own expiry; the plugin then defers
// entirely to that claim rather than applying any bound of its own.
func jwtExpiry(token string, material oauthMaterial) (time.Time, bool) {
	claims := decodeJWTPayload(token)
	if expiry, ok := numericClaim(claims, "exp"); ok && expiry > 0 {
		return time.Unix(expiry, 0).UTC(), true
	}
	issued, ok := jwtIssuedAt(token, material)
	if !ok {
		// Neither a claim nor a recorded time: the credential's age is unknown,
		// and guessing an issue time would cut a live credential short.
		return time.Time{}, false
	}
	return issued.Add(jwtReauthAfter), true
}

// jwtPastReauth reports whether an exp-less JWT has reached the re-authorization
// age. The second result is the instant the verdict was measured against, so a
// caller that records it does not re-derive the clock.
func jwtPastReauth(token string, material oauthMaterial, now time.Time) bool {
	expiry, ok := jwtExpiry(token, material)
	if !ok {
		return false
	}
	return !now.Before(expiry)
}
