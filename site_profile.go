package main

import (
	"encoding/json"
	"strings"
)

// One person may hold accounts on both ZCode sites, and the two are separate
// upstreams: separate logins, separate access tokens, separate business APIs,
// and separate Start Plan entitlements. The official CLI protocol serves both
// from one endpoint pair and distinguishes them only by a provider selector, so
// every site difference is a single field in one authorization body — which is
// exactly the kind of difference that gets hardcoded into one constant and
// silently sends the wrong account's credentials upstream.
//
// siteProfile is that difference, collected. Nothing outside this file may name a
// site's provider, its access-token key, or its business origin: a new caller
// that needs one of those asks a profile, so a site cannot be half-supported.

// Site identifiers. These are the plugin's own persisted vocabulary and match the
// upstream provider selectors exactly, because the value is compared against an
// upstream field rather than translated into one.
const (
	siteZai       = "zai"
	siteBigmodel  = "bigmodel"
	siteFieldName = "site"
)

// knownSites is every site this build can log into. It is closed on purpose: a
// value outside it is a configuration or request error, and falling back to the
// first entry would authorize the user at a site they did not ask for.
var knownSites = []string{siteZai, siteBigmodel}

// siteProfile is everything one site's credentials need that the other site's do
// not. Fields are read-only after construction; the two instances below are
// package-level values shared by every request.
type siteProfile struct {
	// Site is this profile's identifier, as persisted on the credential.
	Site string
	// OAuthProvider is the provider selector the CLI init body carries. It also
	// names the ready payload's access-token key, which is why the parse never
	// guesses it from the payload's shape.
	OAuthProvider string
	// AccessTokenKey is the key under data.{provider}.access_token in the ready
	// payload, read as both access_token and accessToken.
	AccessTokenKey string
	// ExchangesBusinessToken reports whether the OAuth access token must be
	// traded for a second, differently-scoped token before any business call.
	//
	// It is true only for the international site, whose business endpoints answer
	// an access token with 401 "token expired or incorrect" moments after a
	// successful login. The domestic site's endpoints accept the access token
	// itself (capture session 20261004-085036_a4f2e8: every getCustomerInfo and
	// api_keys call carries the OAuth access token directly and returns 200), so
	// exchanging there would spend a call to obtain a token the site never issued.
	ExchangesBusinessToken bool
	// AuthLabel is the host-side account label, which is where a user with two
	// accounts sees which site each one belongs to.
	AuthLabel string
}

// BusinessAPIBase returns the origin serving the site's customer and API-key
// endpoints.
//
// It reads the live package variable rather than holding a copy taken at init.
// The variable is a seam — the whole plugin can be pointed at one local server —
// and a profile that copied its value at init would keep addressing the real
// origin no matter what the seam was set to.
func (p siteProfile) BusinessAPIBase() string {
	if p.Site == siteBigmodel {
		return bigmodelAPIBase
	}
	return zaiAPIBase
}

// zaiAPIBase and bigmodelAPIBase are the two business API origins. They are
// variables so integration tests can point the plugin at a local httptest server;
// public configuration deliberately exposes no base-URL override.
//
// The two run the same paths — /api/biz/customer/getCustomerInfo and the
// organization/project api_keys chain — on different hosts, so the paths are
// shared and only the origin differs.
var (
	zaiAPIBase      = "https://api.z.ai"
	bigmodelAPIBase = "https://bigmodel.cn"
)

var (
	// zaiSiteProfile is the international site: its Start Plan provider, its own
	// API origin, and a business token that must be exchanged for.
	zaiSiteProfile = siteProfile{
		Site:                   siteZai,
		OAuthProvider:          siteZai,
		AccessTokenKey:         siteZai,
		ExchangesBusinessToken: true,
		AuthLabel:              "ZCode (Z.AI)",
	}

	// bigmodelSiteProfile is the domestic site: the same CLI OAuth protocol under a
	// different provider selector, a different business origin, and no second
	// exchange.
	bigmodelSiteProfile = siteProfile{
		Site:                   siteBigmodel,
		OAuthProvider:          siteBigmodel,
		AccessTokenKey:         siteBigmodel,
		ExchangesBusinessToken: false,
		AuthLabel:              "ZCode (BigModel)",
	}
)

// siteProfileFor resolves one site identifier to its profile. ok is false for
// anything not in the known set, and the callers that must not guess check it.
//
// An unrecognized value is resolved here rather than in each caller because
// there are two defensible answers to it and they disagree: a caller that must
// not guess (a login, a re-authorization) reads ok and refuses, while a caller
// that only needs to read an existing credential falls back to the international
// profile, since that is what a record predating the site field can only be.
// Having each caller decide for itself is how one of them ends up authorizing at
// a site the operator did not ask for.
func siteProfileFor(site string) (siteProfile, bool) {
	switch site {
	case siteZai:
		return zaiSiteProfile, true
	case siteBigmodel:
		return bigmodelSiteProfile, true
	default:
		return siteProfile{}, false
	}
}

// siteProfileOrDefault resolves one site identifier, falling back to the
// international profile. It is for reading a stored credential and rendering a
// label — never for deciding where a login goes. A record whose site this build
// does not recognize still holds real credentials; refusing to read it would take
// a working account out of service over a label.
func siteProfileOrDefault(site string) siteProfile {
	if profile, ok := siteProfileFor(site); ok {
		return profile
	}
	return zaiSiteProfile
}

// authLabelFor renders the host-side account label for a stored site. An unknown
// value falls back to the international label: the credential is still usable,
// and refusing to name it would hide a working account over a label.
func authLabelFor(site string) string {
	return siteProfileOrDefault(site).AuthLabel
}

// parsePollAccessToken reads one ready payload's access token for the site the
// login was started for.
//
// The key is the site's own, so a payload carrying only another site's token
// yields empty rather than borrowing it: the two tokens authenticate against
// different origins, and presenting one to the other is refused upstream as an
// invalid credential with nothing to say which site was wrong.
func parsePollAccessToken(body []byte, profile siteProfile) string {
	key := strings.TrimSpace(profile.AccessTokenKey)
	if key == "" {
		return ""
	}
	var root struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &root); err != nil {
		return ""
	}
	// The top level is accepted defensively, mirroring the init and poll
	// envelopes' own tolerant reading.
	read := func(source map[string]json.RawMessage) string {
		raw, ok := source[key]
		if !ok {
			return ""
		}
		var provider struct {
			AccessToken      string `json:"access_token"`
			AccessTokenCamel string `json:"accessToken"`
		}
		if err := json.Unmarshal(raw, &provider); err != nil {
			return ""
		}
		if token := strings.TrimSpace(provider.AccessToken); token != "" {
			return token
		}
		return strings.TrimSpace(provider.AccessTokenCamel)
	}
	if token := read(root.Data); token != "" {
		return token
	}
	var flat map[string]json.RawMessage
	if err := json.Unmarshal(body, &flat); err != nil {
		return ""
	}
	return read(flat)
}

// pinCredentialSite records a credential's site on its document.
//
// It is a separate call rather than a field of every write because the site is
// fixed once, at login, while the quota and state writers run on every refresh:
// pinning inside each of them would make the site an observation that a stale
// document could reset.
//
// The comparison is against the stored value rather than the one the document
// reads as. A record predating the site field already reads as the international
// site, so comparing the two would call the pin a no-op and the field would never
// be written — which is the migration this function exists to perform. Writing
// the value a document already carries is still a no-op, so a steady stream of
// requests does not churn the host auth file.
func pinCredentialSite(doc []byte, site string) ([]byte, error) {
	site = strings.TrimSpace(site)
	stored := rawCredentialSite(doc)
	// Nothing recorded and nothing to record: the document has no site and the
	// caller had none to carry, so there is no migration to perform. A document
	// whose site is absent but whose caller resolved one is the legacy case this
	// exists for, and it is deliberately not this branch.
	if site == "" && stored == "" {
		return doc, nil
	}
	if stored == site {
		return doc, nil
	}
	return patchZcodeNamespace(doc, func(zcode map[string]any) error {
		zcode[siteFieldName] = site
		return nil
	})
}

// readCredentialSite reads the site a credential's document resolves to. A
// document with no site predates the dual-site split, and every credential
// written before it came from the international login, so it reads as that site
// rather than as an unreadable record.
func readCredentialSite(doc []byte) string {
	return recordedSite(rawCredentialSite(doc))
}

// rawCredentialSite reads the site field exactly as stored, without the
// international-site default. A caller deciding whether to write the field needs
// the stored value: the default is a reading of the document, not a fact the
// document records, and treating the two as the same makes the write never happen.
func rawCredentialSite(doc []byte) string {
	var root struct {
		Zcode struct {
			Site string `json:"site"`
		} `json:"zcode"`
	}
	if err := json.Unmarshal(doc, &root); err != nil {
		return ""
	}
	return strings.TrimSpace(root.Zcode.Site)
}

// recordedSite normalizes a stored site value. An absent value means the
// international site; an unrecognized one is kept verbatim, because the
// credential behind it is still real and the label is the only thing that cannot
// be rendered — silently rewriting it to a known site would misfile the account.
func recordedSite(site string) string {
	if trimmed := strings.TrimSpace(site); trimmed != "" {
		return trimmed
	}
	return siteZai
}
