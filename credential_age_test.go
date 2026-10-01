package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// makeJWTWithClaims builds an unsigned JWT carrying exactly the given claims.
// The signature is never verified by the plugin, so the tests only need a
// well-formed payload.
func makeJWTWithClaims(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".signature-not-verified"
}

// TestJWTWithoutExpIsNotStrandedByAge covers the case the issue names: the
// zcode-plan JWT states no exp, so nothing in the credential says when it
// stops working. A fresh one must be used normally.
func TestJWTWithoutExpIsNotStrandedByAge(t *testing.T) {
	now := time.Now()
	token := makeJWTWithClaims(t, map[string]any{"sub": "user-1", "iat": now.Add(-time.Minute).Unix()})
	material := oauthMaterial{ReceivedAt: now.Add(-time.Minute).UTC().Format(time.RFC3339)}
	if jwtPastReauth(token, material, now) {
		t.Fatal("a JWT issued a minute ago must not be treated as aged out")
	}
}

// TestJWTWithoutExpReachesReauthAge is the conservative policy the issue asks
// for: after a deliberately long bound, the plugin prefers to re-authorize
// rather than keep presenting a credential the upstream may have revoked.
func TestJWTWithoutExpReachesReauthAge(t *testing.T) {
	issued := time.Now()
	token := makeJWTWithClaims(t, map[string]any{"sub": "user-1", "iat": issued.Add(-jwtReauthAfter - time.Hour).Unix()})
	material := oauthMaterial{ReceivedAt: issued.Add(-jwtReauthAfter - time.Hour).UTC().Format(time.RFC3339)}
	if !jwtPastReauth(token, material, issued) {
		t.Fatal("an exp-less JWT past the bound must ask for re-authorization")
	}
	// One second short of the bound it is still used, so no working session is
	// cut short by a boundary.
	fresh := makeJWTWithClaims(t, map[string]any{"sub": "user-1", "iat": issued.Add(-jwtReauthAfter + time.Second).Unix()})
	if jwtPastReauth(fresh, oauthMaterial{}, issued) {
		t.Fatal("a JWT just inside the bound must still be used")
	}
}

// TestJWTWithExpDefersToTheClaim keeps the plugin out of the expiry business
// when the credential states its own lifetime: its own claim is authoritative,
// and a bound invented on top of it could only be wrong.
func TestJWTWithExpDefersToTheClaim(t *testing.T) {
	now := time.Now()
	// Issued long ago but valid for another year: an age-based rule would have
	// retired it; the claim must win.
	token := makeJWTWithClaims(t, map[string]any{
		"sub": "user-1",
		"iat": now.Add(-90 * 24 * time.Hour).Unix(),
		"exp": now.Add(365 * 24 * time.Hour).Unix(),
	})
	if jwtPastReauth(token, oauthMaterial{}, now) {
		t.Fatal("a JWT with a live exp claim must not be retired on age alone")
	}
}

// TestJWTAgeFallsBackToRecordedReceipt covers a credential whose claims could
// not be read at all: the login still recorded when it arrived, which is better
// than no age signal.
func TestJWTAgeFallsBackToRecordedReceipt(t *testing.T) {
	now := time.Now()
	material := oauthMaterial{ReceivedAt: now.Add(-jwtReauthAfter - time.Hour).UTC().Format(time.RFC3339)}
	if !jwtPastReauth("not-a-jwt", material, now) {
		t.Fatal("an unreadable JWT must still age out via its recorded receipt time")
	}
}

// TestJWTWithUnknownAgeIsNotStranded is the conservative direction: with no
// claim and no receipt time, the plugin must keep using the credential rather
// than guess an issue time and cut a live one short.
func TestJWTWithUnknownAgeIsNotStranded(t *testing.T) {
	if jwtPastReauth("not-a-jwt", oauthMaterial{}, time.Now()) {
		t.Fatal("a credential of unknown age must stay usable")
	}
}

// TestNumericClaimAcceptsIssuerSpellings covers the JSON shapes a numeric
// claim arrives in, so an age is never missed because of encoding.
func TestNumericClaimAcceptsIssuerSpellings(t *testing.T) {
	claims := map[string]any{
		"number":       float64(1700000000),
		"string":       "1700000000",
		"padded":       "  1700000000 ",
		"jsonNumber":   json.Number("1700000000"),
		"notANumber":   "later",
		"wrongType":    true,
		"zeroLifetime": float64(0),
	}
	got, ok := numericClaim(claims, "number")
	if !ok || got != 1700000000 {
		t.Errorf("number claim = %d ok=%v", got, ok)
	}
	if got, ok := numericClaim(claims, "string"); !ok || got != 1700000000 {
		t.Errorf("string claim = %d ok=%v", got, ok)
	}
	if got, ok := numericClaim(claims, "padded"); !ok || got != 1700000000 {
		t.Errorf("padded claim = %d ok=%v", got, ok)
	}
	if got, ok := numericClaim(claims, "jsonNumber"); !ok || got != 1700000000 {
		t.Errorf("json.Number claim = %d ok=%v", got, ok)
	}
	if _, ok := numericClaim(claims, "notANumber"); ok {
		t.Error("a non-numeric claim must not read as a time")
	}
	if _, ok := numericClaim(claims, "wrongType"); ok {
		t.Error("a boolean claim must not read as a time")
	}
	// A zero claim reads as "present but meaningless"; the expiry callers
	// treat it as the absence of an expiry, which is why they check the value
	// rather than only the presence.
	if got, ok := numericClaim(claims, "zeroLifetime"); !ok || got != 0 {
		t.Errorf("zero claim = %d ok=%v, want a present zero", got, ok)
	}
	if _, ok := numericClaim(claims, "absent"); ok {
		t.Error("an absent claim must not read as a time")
	}
}

// TestAgedJWTStillGetsItsTurnWithAFallback pins the actual behaviour the issue
// asks for on P5/P6: an aged JWT is still attempted first, because the upstream
// may still accept it, but the fallback is guaranteed a turn behind it.
func TestAgedJWTStillGetsItsTurnWithAFallback(t *testing.T) {
	now := time.Now()
	old := makeJWTWithClaims(t, map[string]any{"sub": "user-1", "iat": now.Add(-jwtReauthAfter - time.Hour).Unix()})
	doc := buildPlanDoc(t, old, "key-material-1")
	plan := executionPlan(doc, normalizeConfig(testConfig()), "GLM-5.2", nil, "", now)
	if plan.Failure != nil {
		t.Fatalf("plan failed: %+v", plan.Failure)
	}
	if len(plan.Attempts) != 2 {
		t.Fatalf("attempts = %d, want the aged primary and the fallback", len(plan.Attempts))
	}
	if plan.Attempts[0].CredentialKind != CredentialJWT {
		t.Errorf("first attempt = %q, want the jwt to still be tried", plan.Attempts[0].CredentialKind)
	}
	if plan.Attempts[1].CredentialKind != CredentialAPIKey {
		t.Errorf("second attempt = %q, want the fallback", plan.Attempts[1].CredentialKind)
	}
	// Nothing was recorded as invalid: age is a scheduling preference, never a
	// validity verdict.
	if plan.SkipBlockStatus != "" {
		t.Errorf("skip block = %q, want none for an aged-but-valid jwt", plan.SkipBlockStatus)
	}
}

// TestFreshJWTIsNotAgedOut keeps the normal path unchanged: a healthy primary
// is judged on its recorded state alone, with no age rule applied to it.
func TestFreshJWTIsNotAgedOut(t *testing.T) {
	now := time.Now()
	fresh := makeJWTWithClaims(t, map[string]any{"sub": "user-1", "iat": now.Unix()})
	if jwtPastReauth(fresh, oauthMaterial{}, now) {
		t.Error("a JWT issued now must not need re-authorization")
	}
	doc := buildPlanDoc(t, fresh, "key-material-1")
	plan := executionPlan(doc, normalizeConfig(testConfig()), "GLM-5.2", nil, "", now)
	if plan.Failure != nil {
		t.Fatalf("plan failed: %+v", plan.Failure)
	}
	if plan.Attempts[0].CredentialKind != CredentialJWT {
		t.Errorf("first attempt = %q, want the jwt", plan.Attempts[0].CredentialKind)
	}
	if plan.SkipBlockStatus != "" {
		t.Errorf("skip block = %q, want none", plan.SkipBlockStatus)
	}
}

// buildPlanDoc renders an auth document with both credentials of one identity.
func buildPlanDoc(t *testing.T, jwt, keyMaterial string) []byte {
	t.Helper()
	doc := map[string]any{"zcode": map[string]any{
		"identity_id": "zcode-user-1",
		"jwt":         map[string]any{"token": jwt, "status": "active"},
		"api_key":     map[string]any{"status": "active", "key_material": keyMaterial},
	}}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestCurrentAuthDocumentPrefersTheStore covers the P6 requirement: a request
// plans against the record as it is now, not as it was when the host scheduled
// the request.
func TestCurrentAuthDocumentPrefersTheStore(t *testing.T) {
	store := &fakeAuthStore{docs: map[string]json.RawMessage{}}
	live := []byte(`{"zcode":{"identity_id":"zcode-live","jwt":{"token":"fresh-jwt"}}}`)
	store.docs["auth-1"] = live
	original := authStoreProvider
	authStoreProvider = func() AuthStore { return store }
	t.Cleanup(func() { authStoreProvider = original })

	stale := []byte(`{"zcode":{"identity_id":"zcode-stale","jwt":{"token":"stale-jwt"}}}`)
	got := currentAuthDocument("auth-1", stale)
	if !strings.Contains(string(got), "fresh-jwt") {
		t.Fatalf("document = %s, want the store's current copy", got)
	}
}

// TestCurrentAuthDocumentFallsBackToTheSuppliedCopy keeps a request working
// when the store cannot answer: a slow or broken store must not fail requests
// the plugin could still serve.
func TestCurrentAuthDocumentFallsBackToTheSuppliedCopy(t *testing.T) {
	store := &fakeAuthStore{docs: map[string]json.RawMessage{}}
	original := authStoreProvider
	authStoreProvider = func() AuthStore { return store }
	t.Cleanup(func() { authStoreProvider = original })

	supplied := []byte(`{"zcode":{"jwt":{"token":"supplied"}}}`)
	if got := currentAuthDocument("auth-missing", supplied); string(got) != string(supplied) {
		t.Fatalf("document = %s, want the supplied copy", got)
	}
	// No auth index at all means there is nothing to re-read.
	if got := currentAuthDocument("", supplied); string(got) != string(supplied) {
		t.Fatalf("document = %s, want the supplied copy", got)
	}
}
