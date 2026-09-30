package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// keyExchangeFixture serves the Z.AI business API endpoints of the managed
// key exchange against a local httptest server and records every request.
type keyExchangeFixture struct {
	t   *testing.T
	srv *httptest.Server

	mu           sync.Mutex
	loginBodies  []string
	loginAuth    []string
	infoAuth     []string
	createBodies []string
	createAuth   []string
	copyPaths    []string
	copyAuth     []string

	loginStatus  int
	infoStatus   int
	createStatus int
	copyStatus   int
	infoBody     string
	createBody   string
	copyBody     string
	loginDelay   time.Duration

	createStarted chan struct{}
	blockCreate   chan struct{}
}

// newKeyExchangeFixture redirects zaiAPIBase at a local test double for the
// duration of the test. The default upstream behaves like a healthy account
// with exactly one organization and one project.
func newKeyExchangeFixture(t *testing.T) *keyExchangeFixture {
	t.Helper()
	fixture := &keyExchangeFixture{t: t}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/z/login", fixture.serveLogin)
	mux.HandleFunc("/api/biz/customer/getCustomerInfo", fixture.serveCustomerInfo)
	mux.HandleFunc("/api/biz/v1/organization/", fixture.serveKeys)
	fixture.srv = httptest.NewServer(mux)
	t.Cleanup(fixture.srv.Close)

	originalBase := zaiAPIBase
	zaiAPIBase = fixture.srv.URL
	t.Cleanup(func() { zaiAPIBase = originalBase })
	return fixture
}

func (f *keyExchangeFixture) respond(w http.ResponseWriter, status int, body string) {
	if status == 0 {
		status = http.StatusOK
	}
	if body == "" {
		body = `{"data":{}}`
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func (f *keyExchangeFixture) serveLogin(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	f.mu.Lock()
	f.loginBodies = append(f.loginBodies, string(body))
	f.loginAuth = append(f.loginAuth, r.Header.Get("Authorization"))
	delay := f.loginDelay
	f.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	f.mu.Lock()
	status := f.loginStatus
	f.mu.Unlock()
	if status != 0 && status != http.StatusOK {
		f.respond(w, status, "")
		return
	}
	f.respond(w, status, `{"data":{"access_token":"biz-token-1"}}`)
}

func (f *keyExchangeFixture) serveCustomerInfo(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.infoAuth = append(f.infoAuth, r.Header.Get("Authorization"))
	status, body := f.infoStatus, f.infoBody
	f.mu.Unlock()
	if status != 0 && status != http.StatusOK {
		f.respond(w, status, "")
		return
	}
	if body == "" {
		body = `{"data":{"organizations":[{"organizationId":"org-1","organizationName":"Org One",` +
			`"projects":[{"projectId":"proj-1","projectName":"Project One"}]}]}}`
	}
	f.respond(w, status, body)
}

func (f *keyExchangeFixture) serveKeys(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.URL.Path, "/api_keys/copy/") {
		f.mu.Lock()
		f.copyPaths = append(f.copyPaths, r.URL.Path)
		f.copyAuth = append(f.copyAuth, r.Header.Get("Authorization"))
		status, body := f.copyStatus, f.copyBody
		f.mu.Unlock()
		if status != 0 && status != http.StatusOK {
			f.respond(w, status, "")
			return
		}
		if body == "" {
			body = `{"data":{"secretKey":"secret-1"}}`
		}
		f.respond(w, status, body)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	f.mu.Lock()
	f.createBodies = append(f.createBodies, string(body))
	f.createAuth = append(f.createAuth, r.Header.Get("Authorization"))
	started, block := f.createStarted, f.blockCreate
	f.mu.Unlock()
	if started != nil {
		started <- struct{}{}
	}
	if block != nil {
		<-block
	}
	f.mu.Lock()
	status, override := f.createStatus, f.createBody
	f.mu.Unlock()
	if status != 0 && status != http.StatusOK {
		f.respond(w, status, "")
		return
	}
	if override == "" {
		override = `{"data":{"apiKey":"key-1","name":"created-name"}}`
	}
	f.respond(w, status, override)
}

func (f *keyExchangeFixture) counts() (login, info, create, copy int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.loginBodies), len(f.infoAuth), len(f.createBodies), len(f.copyPaths)
}

// withOAuthConfig stores a normalized config snapshot for the test and
// restores the previous snapshot afterwards.
func withOAuthConfig(t *testing.T, mutate func(*Config)) {
	t.Helper()
	original := currentConfig()
	cfg := defaultConfig()
	if mutate != nil {
		mutate(&cfg)
	}
	activeConfig.Store(normalizeConfig(cfg))
	t.Cleanup(func() { activeConfig.Store(original) })
}

// freshLoginDoc builds a storage document that carries only the JWT namespace,
// as it looks right after a successful login before the api_key section.
func freshLoginDoc(t *testing.T, previous []byte) []byte {
	t.Helper()
	doc, err := buildZcodeStorage(previous, "zcode-user-x", "jwt-token-x", "", time.Now())
	if err != nil {
		t.Fatalf("build storage: %v", err)
	}
	return doc
}

// apiKeySectionOf extracts the api_key section of a storage document.
func apiKeySectionOf(t *testing.T, doc []byte) map[string]any {
	t.Helper()
	section, ok := readAPIKeySection(doc)
	if !ok {
		t.Fatalf("api_key section missing in: %s", doc)
	}
	return section
}

// jwtSectionOf extracts the jwt section of a storage document.
func jwtSectionOf(t *testing.T, doc []byte) map[string]any {
	t.Helper()
	var root struct {
		Zcode struct {
			JWT map[string]any `json:"jwt"`
		} `json:"zcode"`
	}
	if err := json.Unmarshal(doc, &root); err != nil {
		t.Fatalf("decode storage: %v", err)
	}
	if root.Zcode.JWT == nil {
		t.Fatalf("jwt section missing in: %s", doc)
	}
	return root.Zcode.JWT
}

func sectionString(t *testing.T, section map[string]any, field string) string {
	t.Helper()
	value, _ := section[field].(string)
	return value
}

func lastErrorStage(t *testing.T, doc []byte) (string, string) {
	t.Helper()
	section := apiKeySectionOf(t, doc)
	raw, err := json.Marshal(section["last_error"])
	if err != nil || section["last_error"] == nil {
		t.Fatalf("last_error missing in: %s", doc)
	}
	var failure keyOpError
	if err := json.Unmarshal(raw, &failure); err != nil {
		t.Fatalf("decode last_error: %v", err)
	}
	return failure.Stage, failure.Message
}

func mustAttach(t *testing.T, doc []byte, accessToken string) []byte {
	t.Helper()
	return attachManagedAPIKey(doc, accessToken, time.Now())
}

func TestBuildManagedKeyNameUsesConfiguredPrefixAndRandomSuffix(t *testing.T) {
	name, err := buildManagedKeyName("  team-zed  ")
	if err != nil {
		t.Fatalf("buildManagedKeyName: %v", err)
	}
	if !regexp.MustCompile(`^team-zed-[0-9a-f]{8}$`).MatchString(name) {
		t.Fatalf("name = %q, want configurable prefix plus 8 hex chars", name)
	}
	other, err := buildManagedKeyName("team-zed")
	if err != nil {
		t.Fatalf("buildManagedKeyName: %v", err)
	}
	if other == name {
		t.Fatalf("two generated names collided: %q", name)
	}
	empty, err := buildManagedKeyName("")
	if err != nil {
		t.Fatalf("buildManagedKeyName: %v", err)
	}
	if !strings.HasPrefix(empty, defaultManagedKeyNamePrefix+"-") {
		t.Fatalf("empty prefix must fall back to the default, got %q", empty)
	}
	long := strings.Repeat("p", maxManagedKeyNamePrefixLength+10)
	capped, err := buildManagedKeyName(long)
	if err != nil {
		t.Fatalf("buildManagedKeyName: %v", err)
	}
	if len(capped) != maxManagedKeyNamePrefixLength+1+2*managedKeyNameSuffixBytes {
		t.Fatalf("capped name length = %d (%q)", len(capped), capped)
	}
	// A multi-byte prefix is truncated on rune boundaries, never mid-rune.
	utf8Prefix := strings.Repeat("机构", maxManagedKeyNamePrefixLength)
	multibyte, err := buildManagedKeyName(utf8Prefix)
	if err != nil {
		t.Fatalf("buildManagedKeyName: %v", err)
	}
	prefixPart := multibyte[:strings.LastIndex(multibyte, "-")]
	suffix := multibyte[len(prefixPart)+1:]
	if !utf8.ValidString(prefixPart) {
		t.Fatalf("truncated prefix split a rune: %q", prefixPart)
	}
	if !strings.HasPrefix(utf8Prefix, prefixPart) || len(prefixPart) > maxManagedKeyNamePrefixLength {
		t.Fatalf("prefix %q is not a rune-boundary truncation within the byte cap", prefixPart)
	}
	if len(suffix) != 2*managedKeyNameSuffixBytes {
		t.Fatalf("multibyte name suffix = %q", suffix)
	}
}

func TestKnownAPIKeyFieldsCoversStructTags(t *testing.T) {
	typ := reflect.TypeOf(managedAPIKeyState{})
	tags := map[string]bool{}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		tag := strings.Split(field.Tag.Get("json"), ",")[0]
		if tag == "" || tag == "-" {
			t.Fatalf("managedAPIKeyState field %s has no usable json tag", field.Name)
		}
		tags[tag] = true
	}
	known := map[string]bool{}
	for _, name := range knownAPIKeyFields {
		known[name] = true
	}
	for tag := range tags {
		if !known[tag] {
			t.Fatalf("json tag %q of managedAPIKeyState is missing from knownAPIKeyFields; stale values would survive rewrites", tag)
		}
	}
	for name := range known {
		if !tags[name] {
			t.Fatalf("knownAPIKeyFields lists %q which no longer exists on managedAPIKeyState", name)
		}
	}
}

func TestExchangeCreatesAndRecordsOwnedKey(t *testing.T) {
	fixture := newKeyExchangeFixture(t)
	doc := freshLoginDoc(t, nil)

	out := mustAttach(t, doc, "zai-access-token-1")

	login, info, create, copy := fixture.counts()
	if login != 1 || info != 1 || create != 1 || copy != 1 {
		t.Fatalf("upstream calls = login %d info %d create %d copy %d, want 1 each", login, info, create, copy)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if strings.Contains(fixture.loginBodies[0], "Bearer") || fixture.loginAuth[0] != "" {
		t.Fatalf("key login must carry the token in the body, got body %q auth %q", fixture.loginBodies[0], fixture.loginAuth[0])
	}
	if !strings.Contains(fixture.loginBodies[0], "zai-access-token-1") {
		t.Fatalf("key login must carry the OAuth access token, got %q", fixture.loginBodies[0])
	}
	for _, auth := range [][]string{fixture.infoAuth, fixture.createAuth, fixture.copyAuth} {
		if len(auth) != 1 || auth[0] != "Bearer biz-token-1" {
			t.Fatalf("business calls must use the business token, got %q", auth)
		}
	}
	var createRequest struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(fixture.createBodies[0]), &createRequest); err != nil {
		t.Fatalf("decode create body: %v", err)
	}
	if !strings.HasPrefix(createRequest.Name, defaultManagedKeyNamePrefix+"-") {
		t.Fatalf("created key name %q lacks the configured prefix", createRequest.Name)
	}

	section := apiKeySectionOf(t, out)
	if sectionString(t, section, "status") != apiKeyStatusActive {
		t.Fatalf("status = %v, want active", section["status"])
	}
	if section["managed"] != true {
		t.Fatalf("managed ownership flag missing: %v", section["managed"])
	}
	if sectionString(t, section, "key_id") != "key-1" {
		t.Fatalf("key_id = %v, want the upstream resource identifier", section["key_id"])
	}
	if sectionString(t, section, "key_material") != "key-1.secret-1" {
		t.Fatalf("key_material = %v", section["key_material"])
	}
	if sectionString(t, section, "organization_id") != "org-1" || sectionString(t, section, "project_id") != "proj-1" {
		t.Fatalf("organization/project not recorded: %v", section)
	}
	if sectionString(t, section, "name") != createRequest.Name {
		t.Fatalf("recorded name %v must match the created name %q", section["name"], createRequest.Name)
	}
	if sectionString(t, section, "created_at") == "" || sectionString(t, section, "updated_at") == "" {
		t.Fatalf("timestamps missing: %v", section)
	}
	// The JWT outcome is untouched by the successful exchange.
	jwt := jwtSectionOf(t, out)
	if jwt["token"] != "jwt-token-x" {
		t.Fatalf("jwt namespace damaged: %v", jwt)
	}
}

func TestAttachReusesRecordedActiveKeyWithoutUpstreamTraffic(t *testing.T) {
	fixture := newKeyExchangeFixture(t)
	previous := []byte(`{"zcode":{"identity_id":"zcode-user-x","api_key":{` +
		`"status":"active","managed":true,"name":"cpa-zcode-previous","key_id":"key-9",` +
		`"key_material":"key-9.secret-9","organization_id":"org-1","project_id":"proj-1",` +
		`"created_at":"2026-01-01T00:00:00Z","legacy_note":"keep"}}}`)
	doc := freshLoginDoc(t, previous)

	out := mustAttach(t, doc, "zai-access-token-fresh")

	if string(out) != string(doc) {
		t.Fatalf("a recorded active key must be reused untouched, got diff:\nold %s\nnew %s", doc, out)
	}
	if login, info, create, copy := fixture.counts(); login+info+create+copy != 0 {
		t.Fatalf("reuse must not touch upstream, got login %d info %d create %d copy %d", login, info, create, copy)
	}
}

func TestAttachRefetchesMaterialByRecordedKeyIDOnly(t *testing.T) {
	fixture := newKeyExchangeFixture(t)
	previous := []byte(`{"zcode":{"identity_id":"zcode-user-x","api_key":{` +
		`"status":"failed","managed":true,"name":"cpa-zcode-old","key_id":"key-7",` +
		`"organization_id":"org-1","project_id":"proj-1","created_at":"2026-01-01T00:00:00Z"}}}`)
	doc := freshLoginDoc(t, previous)

	out := mustAttach(t, doc, "zai-access-token-1")

	login, info, create, copy := fixture.counts()
	if login != 1 || info != 0 || create != 0 || copy != 1 {
		t.Fatalf("refetch must only log in and read material, got login %d info %d create %d copy %d", login, info, create, copy)
	}
	section := apiKeySectionOf(t, out)
	if sectionString(t, section, "status") != apiKeyStatusActive {
		t.Fatalf("status = %v, want active", section["status"])
	}
	if sectionString(t, section, "key_id") != "key-7" || sectionString(t, section, "key_material") != "key-7.secret-1" {
		t.Fatalf("refetched key not recorded: %v", section)
	}
	if sectionString(t, section, "name") != "cpa-zcode-old" || sectionString(t, section, "created_at") != "2026-01-01T00:00:00Z" {
		t.Fatalf("recorded ownership fields must survive the refetch: %v", section)
	}
}

func TestAttachAmbiguousOrganizationsWaitForExplicitSelection(t *testing.T) {
	fixture := newKeyExchangeFixture(t)
	fixture.mu.Lock()
	fixture.infoBody = `{"data":{"organizations":[` +
		`{"organizationId":"org-a","organizationName":"默认机构A","projects":[{"projectId":"proj-a","projectName":"默认项目A"}]},` +
		`{"organizationId":"org-b","organizationName":"默认机构B","projects":[{"projectId":"proj-b","projectName":"默认项目B"}]}]}}`
	fixture.mu.Unlock()
	doc := freshLoginDoc(t, nil)

	out := mustAttach(t, doc, "zai-access-token-1")

	if _, _, create, _ := fixture.counts(); create != 0 {
		t.Fatalf("no key may be created while the organization choice is ambiguous")
	}
	section := apiKeySectionOf(t, out)
	if sectionString(t, section, "status") != apiKeyStatusNeedsSelection {
		t.Fatalf("status = %v, want needs_selection instead of guessing a localized name", section["status"])
	}
	if sectionString(t, section, "key_id") != "" {
		t.Fatalf("no key id may be recorded before creation: %v", section["key_id"])
	}
	raw, err := json.Marshal(section["candidates"])
	if err != nil || section["candidates"] == nil {
		t.Fatalf("candidates missing: %v", section)
	}
	var candidates keyCandidates
	if err := json.Unmarshal(raw, &candidates); err != nil {
		t.Fatalf("decode candidates: %v", err)
	}
	if len(candidates.Organizations) != 2 || candidates.Organizations[0].ID != "org-a" || candidates.Organizations[1].ID != "org-b" {
		t.Fatalf("candidate organizations incomplete: %+v", candidates)
	}
}

func TestAttachAmbiguousProjectsWaitForExplicitSelection(t *testing.T) {
	fixture := newKeyExchangeFixture(t)
	fixture.mu.Lock()
	fixture.infoBody = `{"data":{"organizations":[{"organizationId":"org-1","organizationName":"Org One",` +
		`"projects":[{"projectId":"proj-a","projectName":"默认项目A"},{"projectId":"proj-b","projectName":"默认项目B"}]}]}}`
	fixture.mu.Unlock()
	doc := freshLoginDoc(t, nil)

	out := mustAttach(t, doc, "zai-access-token-1")

	if _, _, create, _ := fixture.counts(); create != 0 {
		t.Fatalf("no key may be created while the project choice is ambiguous")
	}
	section := apiKeySectionOf(t, out)
	if sectionString(t, section, "status") != apiKeyStatusNeedsSelection {
		t.Fatalf("status = %v, want needs_selection", section["status"])
	}
	raw, err := json.Marshal(section["candidates"])
	if err != nil || section["candidates"] == nil {
		t.Fatalf("candidates missing: %v", section)
	}
	var candidates keyCandidates
	if err := json.Unmarshal(raw, &candidates); err != nil {
		t.Fatalf("decode candidates: %v", err)
	}
	if len(candidates.Projects) != 2 || len(candidates.Organizations) != 0 {
		t.Fatalf("candidates must list the ambiguous projects only: %+v", candidates)
	}
}

func TestAttachPinnedOrganizationAndProjectAreUsed(t *testing.T) {
	fixture := newKeyExchangeFixture(t)
	withOAuthConfig(t, func(cfg *Config) {
		cfg.OAuth.OrganizationID = "org-2"
		cfg.OAuth.ProjectID = "proj-2"
	})
	fixture.mu.Lock()
	fixture.infoBody = `{"data":{"organizations":[` +
		`{"organizationId":"org-1","organizationName":"Org One","projects":[{"projectId":"proj-1","projectName":"P1"}]},` +
		`{"organizationId":"org-2","organizationName":"Org Two","projects":[{"projectId":"proj-2","projectName":"P2"}]}]}}`
	fixture.mu.Unlock()
	doc := freshLoginDoc(t, nil)

	out := mustAttach(t, doc, "zai-access-token-1")

	section := apiKeySectionOf(t, out)
	if sectionString(t, section, "status") != apiKeyStatusActive {
		t.Fatalf("status = %v (%v), want active with the pinned ids", section["status"], section["last_error"])
	}
	if sectionString(t, section, "organization_id") != "org-2" || sectionString(t, section, "project_id") != "proj-2" {
		t.Fatalf("pinned ids not used: %v", section)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if len(fixture.copyPaths) != 1 || !strings.Contains(fixture.copyPaths[0], "/organization/org-2/projects/proj-2/api_keys/copy/key-1") {
		t.Fatalf("copy path = %v, want the pinned organization/project", fixture.copyPaths)
	}
}

func TestAttachPinnedOrganizationWithAmbiguousProjectWaitsForSelection(t *testing.T) {
	fixture := newKeyExchangeFixture(t)
	withOAuthConfig(t, func(cfg *Config) {
		cfg.OAuth.OrganizationID = "org-2"
	})
	fixture.mu.Lock()
	fixture.infoBody = `{"data":{"organizations":[` +
		`{"organizationId":"org-1","organizationName":"Org One","projects":[{"projectId":"proj-1","projectName":"P1"}]},` +
		`{"organizationId":"org-2","organizationName":"Org Two","projects":[` +
		`{"projectId":"proj-a","projectName":"默认项目A"},{"projectId":"proj-b","projectName":"默认项目B"}]}]}}`
	fixture.mu.Unlock()
	doc := freshLoginDoc(t, nil)

	out := mustAttach(t, doc, "zai-access-token-1")

	if _, _, create, _ := fixture.counts(); create != 0 {
		t.Fatalf("no key may be created while the project choice is ambiguous")
	}
	section := apiKeySectionOf(t, out)
	if sectionString(t, section, "status") != apiKeyStatusNeedsSelection {
		t.Fatalf("status = %v, want needs_selection", section["status"])
	}
	raw, err := json.Marshal(section["candidates"])
	if err != nil || section["candidates"] == nil {
		t.Fatalf("candidates missing: %v", section)
	}
	var candidates keyCandidates
	if err := json.Unmarshal(raw, &candidates); err != nil {
		t.Fatalf("decode candidates: %v", err)
	}
	if len(candidates.Projects) != 2 || candidates.Projects[0].ID != "proj-a" {
		t.Fatalf("candidate projects incomplete: %+v", candidates)
	}
	if sectionString(t, section, "message") == "" {
		t.Fatalf("needs_selection must explain how to resolve the state: %v", section)
	}
}

func TestAttachConfiguredOrganizationMissingFailsAtSelection(t *testing.T) {
	fixture := newKeyExchangeFixture(t)
	withOAuthConfig(t, func(cfg *Config) {
		cfg.OAuth.OrganizationID = "missing-org"
	})
	doc := freshLoginDoc(t, nil)

	out := mustAttach(t, doc, "zai-access-token-1")

	if _, _, create, _ := fixture.counts(); create != 0 {
		t.Fatalf("no key may be created when the configured organization does not exist")
	}
	section := apiKeySectionOf(t, out)
	if sectionString(t, section, "status") != apiKeyStatusFailed {
		t.Fatalf("status = %v, want failed", section["status"])
	}
	stage, message := lastErrorStage(t, out)
	if stage != apiKeyStageSelection {
		t.Fatalf("failure stage = %q, want selection", stage)
	}
	if !strings.Contains(message, "organization") {
		t.Fatalf("failure message = %q, should mention the organization mismatch", message)
	}
}

func TestAttachExchangeFailureKeepsJWTAndRecordsDiagnosableStage(t *testing.T) {
	fixture := newKeyExchangeFixture(t)
	fixture.mu.Lock()
	fixture.loginStatus = http.StatusInternalServerError
	fixture.mu.Unlock()
	doc := freshLoginDoc(t, nil)

	out := mustAttach(t, doc, "zai-access-token-1")

	section := apiKeySectionOf(t, out)
	if sectionString(t, section, "status") != apiKeyStatusFailed {
		t.Fatalf("status = %v, want failed", section["status"])
	}
	stage, message := lastErrorStage(t, out)
	if stage != apiKeyStageLogin {
		t.Fatalf("failure stage = %q, want login", stage)
	}
	if message == "" {
		t.Fatal("failure message must be diagnosable")
	}
	// The JWT outcome must never be rolled back by an exchange failure.
	jwt := jwtSectionOf(t, out)
	if jwt["token"] != "jwt-token-x" || jwt["status"] != "active" {
		t.Fatalf("jwt namespace must survive the exchange failure: %v", jwt)
	}
	for _, secret := range []string{"zai-access-token-1", "biz-token-1", "secret-1"} {
		if strings.Contains(message, secret) {
			t.Fatalf("failure message leaked a secret: %q", message)
		}
	}
}

func TestAttachCreateWithoutKeyIdentifierFailsAtCreate(t *testing.T) {
	fixture := newKeyExchangeFixture(t)
	fixture.mu.Lock()
	fixture.createBody = `{"data":{"name":"created-name"}}`
	fixture.mu.Unlock()
	doc := freshLoginDoc(t, nil)

	out := mustAttach(t, doc, "zai-access-token-1")

	stage, _ := lastErrorStage(t, out)
	if stage != apiKeyStageCreate {
		t.Fatalf("failure stage = %q, want create", stage)
	}
}

func TestAttachMaterialFailureKeepsCreatedKeyForRefetch(t *testing.T) {
	fixture := newKeyExchangeFixture(t)
	fixture.mu.Lock()
	fixture.copyStatus = http.StatusInternalServerError
	fixture.mu.Unlock()
	doc := freshLoginDoc(t, nil)

	out := mustAttach(t, doc, "zai-access-token-1")

	section := apiKeySectionOf(t, out)
	if sectionString(t, section, "status") != apiKeyStatusFailed {
		t.Fatalf("status = %v, want failed", section["status"])
	}
	stage, _ := lastErrorStage(t, out)
	if stage != apiKeyStageMaterial {
		t.Fatalf("failure stage = %q, want material", stage)
	}
	// The created key exists upstream; its identity must be recorded so the
	// retry refetches material instead of creating a duplicate key.
	if sectionString(t, section, "key_id") != "key-1" {
		t.Fatalf("created key id lost on material failure: %v", section)
	}
	if sectionString(t, section, "organization_id") != "org-1" || sectionString(t, section, "project_id") != "proj-1" {
		t.Fatalf("created key location lost on material failure: %v", section)
	}
	if sectionString(t, section, "created_at") == "" {
		t.Fatalf("created timestamp lost on material failure: %v", section)
	}
}

func TestAttachUnknownSectionFieldsSurviveRewrite(t *testing.T) {
	fixture := newKeyExchangeFixture(t)
	fixture.mu.Lock()
	fixture.loginStatus = http.StatusInternalServerError
	fixture.mu.Unlock()
	previous := []byte(`{"zcode":{"identity_id":"zcode-user-x","api_key":{` +
		`"status":"needs_selection","credential":"old-note","key_id":"key-5",` +
		`"organization_id":"org-1","project_id":"proj-1"}}}`)
	doc := freshLoginDoc(t, previous)

	out := mustAttach(t, doc, "zai-access-token-1")

	section := apiKeySectionOf(t, out)
	if sectionString(t, section, "credential") != "old-note" {
		t.Fatalf("unknown section field lost: %v", section)
	}
	// The recorded key id means the retry must refetch, not re-create.
	if sectionString(t, section, "key_id") != "key-5" {
		t.Fatalf("recorded key id lost: %v", section)
	}
	if login, _, create, _ := fixture.counts(); create != 0 {
		t.Fatalf("a recorded key id must never trigger creation (login %d, create %d)", login, create)
	}
}

func TestAttachWithoutExchangeToken(t *testing.T) {
	t.Run("fresh account is unavailable", func(t *testing.T) {
		newKeyExchangeFixture(t)
		doc := freshLoginDoc(t, nil)
		out := mustAttach(t, doc, "")
		section := apiKeySectionOf(t, out)
		if sectionString(t, section, "status") != apiKeyStatusUnavailable {
			t.Fatalf("status = %v, want unavailable", section["status"])
		}
		if _, message := lastErrorStage(t, out); message == "" {
			t.Fatalf("unavailable state must stay diagnosable")
		}
	})
	t.Run("recorded key is retained", func(t *testing.T) {
		newKeyExchangeFixture(t)
		previous := []byte(`{"zcode":{"identity_id":"zcode-user-x","api_key":{` +
			`"status":"failed","key_id":"key-7","organization_id":"org-1","project_id":"proj-1"}}}`)
		doc := freshLoginDoc(t, previous)
		out := mustAttach(t, doc, "")
		section := apiKeySectionOf(t, out)
		if sectionString(t, section, "key_id") != "key-7" {
			t.Fatalf("recorded key id lost: %v", section)
		}
		stage, _ := lastErrorStage(t, out)
		if stage != apiKeyStageExchange {
			t.Fatalf("failure stage = %q, want exchange", stage)
		}
	})
}

func TestAttachExchangeTimeoutIsDiagnosable(t *testing.T) {
	fixture := newKeyExchangeFixture(t)
	fixture.mu.Lock()
	fixture.loginDelay = 300 * time.Millisecond
	fixture.mu.Unlock()
	originalTimeout := managedKeyExchangeTimeout
	managedKeyExchangeTimeout = 50 * time.Millisecond
	t.Cleanup(func() { managedKeyExchangeTimeout = originalTimeout })

	out := mustAttach(t, freshLoginDoc(t, nil), "zai-access-token-1")

	section := apiKeySectionOf(t, out)
	if sectionString(t, section, "status") != apiKeyStatusFailed {
		t.Fatalf("status = %v, want failed", section["status"])
	}
	_, message := lastErrorStage(t, out)
	if !strings.Contains(message, "did not complete in time") {
		t.Fatalf("timeout message = %q, want an explicit timeout diagnosis", message)
	}
	if _, _, create, _ := fixture.counts(); create != 0 {
		t.Fatalf("a timed out login must not reach key creation")
	}
}

func TestNeedsSelectionStateCarriesNoStaleFailure(t *testing.T) {
	fixture := newKeyExchangeFixture(t)
	fixture.mu.Lock()
	fixture.infoBody = `{"data":{"organizations":[` +
		`{"organizationId":"org-a","organizationName":"A","projects":[{"projectId":"proj-a","projectName":"PA"}]},` +
		`{"organizationId":"org-b","organizationName":"B","projects":[{"projectId":"proj-b","projectName":"PB"}]}]}}`
	fixture.mu.Unlock()
	previous := []byte(`{"zcode":{"identity_id":"zcode-user-x","api_key":{` +
		`"status":"failed","last_error":{"stage":"login","message":"old failure","at":"2026-01-01T00:00:00Z"}}}}`)
	doc := freshLoginDoc(t, previous)

	out := mustAttach(t, doc, "zai-access-token-1")

	section := apiKeySectionOf(t, out)
	if sectionString(t, section, "status") != apiKeyStatusNeedsSelection {
		t.Fatalf("status = %v, want needs_selection", section["status"])
	}
	if _, ok := section["last_error"]; ok {
		t.Fatalf("needs_selection is not a failure and must clear the stale error: %v", section["last_error"])
	}
	if section["managed"] != true {
		t.Fatalf("managed flag missing: %v", section)
	}
}

func TestExchangeUpstreamRejectionIsRedacted(t *testing.T) {
	fixture := newKeyExchangeFixture(t)
	fixture.mu.Lock()
	fixture.infoStatus = http.StatusForbidden
	fixture.mu.Unlock()

	out := mustAttach(t, freshLoginDoc(t, nil), "zai-access-token-1")

	_, message := lastErrorStage(t, out)
	if strings.Contains(message, "zai-access-token-1") || strings.Contains(message, "biz-token-1") {
		t.Fatalf("rejection message leaked a secret: %q", message)
	}
	if !strings.Contains(message, fmt.Sprint(http.StatusForbidden)) {
		t.Fatalf("rejection message = %q, want the http status for diagnosis", message)
	}
}
