package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// A site profile is the only thing that knows where a site's login starts, which
// JSON key carries its access token, and which business API its managed key is
// exchanged against. These tests pin that each of the two sites resolves to the
// contract the capture proved, and that an unknown site is refused rather than
// guessed: guessing would silently send a user's authorization at the wrong site
// and store a credential labelled as the other one.

func TestSiteProfileOAuthContracts(t *testing.T) {
	cases := []struct {
		site         string
		wantProvider string
		wantTokenKey string
	}{
		{site: siteZai, wantProvider: "zai", wantTokenKey: "zai"},
		{site: siteBigmodel, wantProvider: "bigmodel", wantTokenKey: "bigmodel"},
	}
	for _, tc := range cases {
		profile, ok := siteProfileFor(tc.site)
		if !ok {
			t.Fatalf("site %q has no profile", tc.site)
		}
		if profile.OAuthProvider != tc.wantProvider {
			t.Errorf("site %q init provider = %q, want %q", tc.site, profile.OAuthProvider, tc.wantProvider)
		}
		if profile.AccessTokenKey != tc.wantTokenKey {
			t.Errorf("site %q ready access-token key = %q, want %q", tc.site, profile.AccessTokenKey, tc.wantTokenKey)
		}
	}
}

// The two sites' business APIs are different origins running the same paths, so
// the profile — not a hardcoded constant — is what decides which one a managed
// key exchange talks to.
func TestSiteProfileBusinessAPIBases(t *testing.T) {
	zai, _ := siteProfileFor(siteZai)
	bigmodel, _ := siteProfileFor(siteBigmodel)
	if zai.BusinessAPIBase() != zaiAPIBase {
		t.Errorf("zai profile base = %q, want %q", zai.BusinessAPIBase(), zaiAPIBase)
	}
	if bigmodel.BusinessAPIBase() != bigmodelAPIBase {
		t.Errorf("bigmodel profile base = %q, want %q", bigmodel.BusinessAPIBase(), bigmodelAPIBase)
	}
	if zai.BusinessAPIBase() == bigmodel.BusinessAPIBase() {
		t.Error("the two sites must not share a business API base; that would cross a site's credentials")
	}
}

// The base is read live rather than captured at init, because the variable is a
// test seam: a copy taken at package init would send exchange traffic to the real
// origin while the assertions watched the fake server.
func TestSiteProfileBusinessAPIBaseFollowsTheSeam(t *testing.T) {
	profile, _ := siteProfileFor(siteZai)
	original := zaiAPIBase
	t.Cleanup(func() { zaiAPIBase = original })
	zaiAPIBase = "http://127.0.0.1:1/fake"
	if got := profile.BusinessAPIBase(); got != zaiAPIBase {
		t.Errorf("base = %q, want the reassigned %q", got, zaiAPIBase)
	}
}

// bigmodel needs no second exchange: the capture shows the business endpoints
// accepting the OAuth access token itself, which is the single behavioural
// difference between the two sites' credential chains.
func TestSiteProfileBusinessTokenAcquisition(t *testing.T) {
	zai, _ := siteProfileFor(siteZai)
	bigmodel, _ := siteProfileFor(siteBigmodel)
	if !zai.ExchangesBusinessToken {
		t.Error("zai must exchange its access token; that is how its business token is obtained")
	}
	if bigmodel.ExchangesBusinessToken {
		t.Error("bigmodel access token is already the business token; an extra exchange would fail upstream")
	}
}

// Every known site must be reachable by its canonical name, and nothing else.
func TestSiteProfileResolutionRejectsUnknown(t *testing.T) {
	for _, known := range knownSites {
		if _, ok := siteProfileFor(known); !ok {
			t.Errorf("known site %q does not resolve", known)
		}
	}
	for _, unknown := range []string{"", "  ", "ZAI", "big-model", "bigmodel.cn", "openai", "zai2"} {
		if _, ok := siteProfileFor(unknown); ok {
			t.Errorf("unknown site %q resolved to a profile; an unknown site must be refused", unknown)
		}
	}
}

// A stored record's site decides which business API its refresh reads. A document
// with no site predates the dual-site split, and every such credential was
// created through the international login, so it reads as zai rather than as
// an unknown record that has to be discarded.
func TestReadCredentialSnapshotSite(t *testing.T) {
	doc := func(site string) []byte {
		section := `"jwt":{"token":"t"}`
		if site != "" {
			section += `,"site":"` + site + `"`
		}
		return []byte(`{"zcode":{"identity_id":"zcode-1",` + section + `}}`)
	}
	cases := []struct {
		name string
		doc  []byte
		want string
	}{
		{name: "absent site is the international site", doc: doc(""), want: siteZai},
		{name: "explicit zai", doc: doc(siteZai), want: siteZai},
		{name: "explicit bigmodel", doc: doc(siteBigmodel), want: siteBigmodel},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snap, err := readCredentialSnapshot(tc.doc)
			if err != nil {
				t.Fatalf("readCredentialSnapshot: %v", err)
			}
			if snap.Site != tc.want {
				t.Errorf("site = %q, want %q", snap.Site, tc.want)
			}
		})
	}
}

// A record whose site was written as something this build does not know must
// still parse as a credential: it was logged into successfully by an older or
// newer plugin, and refusing to read it would take a working credential out of
// service over a label rather than over its material.
func TestReadCredentialSnapshotUnknownSiteStillParses(t *testing.T) {
	doc := []byte(`{"zcode":{"identity_id":"zcode-1","jwt":{"token":"t"},"site":"future-site"}}`)
	snap, err := readCredentialSnapshot(doc)
	if err != nil {
		t.Fatalf("readCredentialSnapshot: %v", err)
	}
	if _, ok := siteProfileFor(snap.Site); ok {
		t.Errorf("unknown site %q must not resolve to a profile", snap.Site)
	}
	if snap.JWTToken != "t" {
		t.Errorf("jwt token = %q, want it preserved", snap.JWTToken)
	}
}

// The site is stored once, at the top level of the plugin's namespace, and every
// later write of that document must leave it alone: it is the account's fixed
// site, not a per-refresh observation.
func TestBuildZcodeStoragePinsSite(t *testing.T) {
	previous := []byte(`{"zcode":{"identity_id":"zcode-1","site":"bigmodel","jwt":{"token":"old"},"extra":"kept"}}`)
	doc, err := buildZcodeStorage(previous, "zcode-1", "fresh", "", siteBigmodel, time.Now())
	if err != nil {
		t.Fatalf("buildZcodeStorage: %v", err)
	}
	snap, err := readCredentialSnapshot(doc)
	if err != nil {
		t.Fatalf("readCredentialSnapshot: %v", err)
	}
	if snap.Site != siteBigmodel {
		t.Errorf("site = %q, want %q", snap.Site, siteBigmodel)
	}
	if snap.JWTToken != "fresh" {
		t.Errorf("jwt token = %q, want the fresh token", snap.JWTToken)
	}
	var root struct {
		Zcode struct {
			Extra string `json:"extra"`
		} `json:"zcode"`
	}
	if err := json.Unmarshal(doc, &root); err != nil {
		t.Fatalf("decode storage: %v", err)
	}
	if root.Zcode.Extra != "kept" {
		t.Errorf("unknown field was lost: %q", root.Zcode.Extra)
	}
}

// Every write path that touches a credential document goes through
// patchZcodeNamespace, so re-pinning the site is one call that all of them share.
func TestPinCredentialSiteRoundTrip(t *testing.T) {
	doc := []byte(`{"zcode":{"identity_id":"zcode-1","jwt":{"token":"t"}}}`)
	pinned, err := pinCredentialSite(doc, siteBigmodel)
	if err != nil {
		t.Fatalf("pinCredentialSite: %v", err)
	}
	snap, err := readCredentialSnapshot(pinned)
	if err != nil {
		t.Fatalf("readCredentialSnapshot: %v", err)
	}
	if snap.Site != siteBigmodel {
		t.Errorf("site = %q, want %q", snap.Site, siteBigmodel)
	}
	// Pinning again is idempotent, so a refresh that runs on every request cannot
	// churn the document.
	again, err := pinCredentialSite(pinned, siteBigmodel)
	if err != nil {
		t.Fatalf("pinCredentialSite second pass: %v", err)
	}
	if string(again) != string(pinned) {
		t.Error("pinning an already-pinned site rewrote the document")
	}
}

// A caller that resolved no site has nothing to pin, and writing the empty value
// would clear a site an earlier write already fixed. The empty call is therefore
// a no-op even against a pinned document.
func TestPinCredentialSiteRefusesEmptySite(t *testing.T) {
	doc := []byte(`{"zcode":{"identity_id":"zcode-1","jwt":{"token":"t"},"site":"bigmodel"}}`)
	pinned, err := pinCredentialSite(doc, "")
	if err != nil {
		t.Fatalf("pinCredentialSite: %v", err)
	}
	snap, err := readCredentialSnapshot(pinned)
	if err != nil {
		t.Fatalf("readCredentialSnapshot: %v", err)
	}
	if snap.Site != siteBigmodel {
		t.Errorf("site = %q, want the recorded %q to survive an empty pin", snap.Site, siteBigmodel)
	}
	if string(pinned) != string(doc) {
		t.Error("an empty pin rewrote the document")
	}
}

// The ready payload carries the site's access token under a key named after the
// provider. Reading the wrong key yields an empty token, which would silently
// drop the managed key exchange rather than fail the login, so the parse has to
// be pinned per site.
func TestParsePollAccessTokenPerSite(t *testing.T) {
	body := func(site string) []byte {
		return []byte(`{"data":{"status":"ready","token":"jwt","user":{"user_id":"u"},` +
			`"zai":{"access_token":"zai-token"},"bigmodel":{"access_token":"bigmodel-token"}}}`)
	}
	zai, _ := siteProfileFor(siteZai)
	bigmodel, _ := siteProfileFor(siteBigmodel)
	if got := parsePollAccessToken(body(siteZai), zai); got != "zai-token" {
		t.Errorf("zai access token = %q, want %q", got, "zai-token")
	}
	if got := parsePollAccessToken(body(siteBigmodel), bigmodel); got != "bigmodel-token" {
		t.Errorf("bigmodel access token = %q, want %q", got, "bigmodel-token")
	}
}

// A payload that carries the other site's key, or none at all, must not borrow
// the other site's token: using zai's material for a bigmodel login is exactly
// the cross-site mix the issue forbids.
func TestParsePollAccessTokenNeverBorrowsAnotherSite(t *testing.T) {
	zai, _ := siteProfileFor(siteZai)
	bigmodel, _ := siteProfileFor(siteBigmodel)
	onlyZai := []byte(`{"data":{"zai":{"access_token":"zai-token"}}}`)
	if got := parsePollAccessToken(onlyZai, bigmodel); got != "" {
		t.Errorf("bigmodel login read zai's token %q; sites must not share material", got)
	}
	onlyBigmodel := []byte(`{"data":{"bigmodel":{"access_token":"bm-token"}}}`)
	if got := parsePollAccessToken(onlyBigmodel, zai); got != "" {
		t.Errorf("zai login read bigmodel's token %q; sites must not share material", got)
	}
	if got := parsePollAccessToken([]byte(`{"data":{}}`), zai); got != "" {
		t.Errorf("empty payload produced token %q", got)
	}
}

// The camelCase spelling the upstream uses in some responses must read the same
// as the snake_case one, or a bigmodel login would find no exchange material.
func TestParsePollAccessTokenAcceptsBothSpellings(t *testing.T) {
	bigmodel, _ := siteProfileFor(siteBigmodel)
	camel := []byte(`{"data":{"bigmodel":{"accessToken":"camel-token"}}}`)
	if got := parsePollAccessToken(camel, bigmodel); got != "camel-token" {
		t.Errorf("camelCase access token = %q, want it accepted", got)
	}
}

// The auth label is what the host's account list shows, so two accounts of the
// same plugin must be distinguishable there without opening either document.
func TestAuthLabelNamesItsSite(t *testing.T) {
	if got := authLabelFor(siteZai); !strings.Contains(got, "Z.AI") {
		t.Errorf("zai label = %q, want it to name Z.AI", got)
	}
	if got := authLabelFor(siteBigmodel); !strings.Contains(got, "BigModel") {
		t.Errorf("bigmodel label = %q, want it to name BigModel", got)
	}
	if authLabelFor(siteZai) == authLabelFor(siteBigmodel) {
		t.Error("both sites share one label; the account list cannot tell them apart")
	}
}

// A label for a site this build does not know falls back to the international
// label rather than inventing a third one: the credential is still usable, and
// an unreadable label must not hide the account.
func TestAuthLabelUnknownSiteFallsBack(t *testing.T) {
	if got := authLabelFor("future-site"); got != authLabelFor(siteZai) {
		t.Errorf("unknown-site label = %q, want the zai label %q", got, authLabelFor(siteZai))
	}
}

// Reading a stored credential falls back rather than refusing. Two callers of
// the resolver need opposite answers — a login must refuse an unknown site, a
// stored record must stay readable — so each has to be able to get its own.
func TestSiteProfileOrDefaultReadsUnknownWithoutGuessing(t *testing.T) {
	for _, site := range knownSites {
		if got := siteProfileOrDefault(site); got.Site != site {
			t.Errorf("site %q resolved to %q", site, got.Site)
		}
	}
	// A record predating the site field, and a record written by a build that
	// knew a site this one does not, both still hold a usable credential.
	for _, site := range []string{"", "future-site", "bigmodel.cn"} {
		if got := siteProfileOrDefault(site); got.Site != siteZai {
			t.Errorf("site %q resolved to %q, want the international profile so the record stays readable",
				site, got.Site)
		}
	}
}
