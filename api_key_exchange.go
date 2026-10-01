package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

// zaiAPIBase is the Z.AI business API root used to exchange the OAuth access
// token for the managed fallback API key. It is a variable so integration
// tests can point the plugin at a local httptest server.
var zaiAPIBase = "https://api.z.ai"

// managedKeyExchangeTimeout bounds the whole managed key exchange (business
// login, organization/project resolution, key creation, and material read).
// The bound keeps the final OAuth poll responsive: a slower exchange fails
// into a diagnosable state instead of stretching the login out, and the JWT
// outcome is never affected by it.
var managedKeyExchangeTimeout = 30 * time.Second

// maxManagedKeyBodyBytes bounds each business API response body; the exchange
// payloads are small JSON documents.
const maxManagedKeyBodyBytes int64 = 1 << 20

// managedKeyNameSuffixBytes is the crypto-random length of the generated key
// name suffix, rendered as hex.
const managedKeyNameSuffixBytes = 4

// maxManagedKeyNamePrefixLength caps the configured prefix so generated names
// stay within a sane upstream length even with a long custom prefix.
const maxManagedKeyNamePrefixLength = 40

// Managed key section statuses recorded in the zcode namespace. active means
// the recorded material is the fallback credential; needs_selection means the
// upstream organization/project choice is ambiguous and waits for an explicit
// selection; failed and unavailable carry the reason in last_error.
const (
	apiKeyStatusActive         = "active"
	apiKeyStatusNeedsSelection = "needs_selection"
	apiKeyStatusFailed         = "failed"
	apiKeyStatusUnavailable    = "unavailable"
)

// Managed key operation stages recorded with failures for diagnosis. exchange
// marks a problem that stopped the exchange before its first upstream call.
const (
	apiKeyStageExchange  = "exchange"
	apiKeyStageLogin     = "login"
	apiKeyStageDiscovery = "discovery"
	apiKeyStageSelection = "selection"
	apiKeyStageCreate    = "create"
	apiKeyStageMaterial  = "material"
)

// managedAPIKeyState is the typed view of the plugin-owned api_key section in
// the zcode namespace. It records the fallback credential of the upstream
// identity: the upstream resource identifiers, the callable material, and the
// current availability conclusion. Its state is independent of the JWT state.
type managedAPIKeyState struct {
	Status         string         `json:"status"`
	Managed        bool           `json:"managed"`
	Message        string         `json:"message,omitempty"`
	Name           string         `json:"name,omitempty"`
	KeyID          string         `json:"key_id,omitempty"`
	KeyMaterial    string         `json:"key_material,omitempty"`
	OrganizationID string         `json:"organization_id,omitempty"`
	ProjectID      string         `json:"project_id,omitempty"`
	Candidates     *keyCandidates `json:"candidates,omitempty"`
	LastError      *keyOpError    `json:"last_error,omitempty"`
	CreatedAt      string         `json:"created_at,omitempty"`
	UpdatedAt      string         `json:"updated_at,omitempty"`
}

// keyCandidates lists the ambiguous organization/project choices for an
// explicit selection. Display names are shown for humans only; they are never
// matched or guessed by the plugin.
type keyCandidates struct {
	Organizations []keyCandidate `json:"organizations,omitempty"`
	Projects      []keyCandidate `json:"projects,omitempty"`
}

type keyCandidate struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// keyOpError records one diagnosable failure: which stage failed and a
// redacted reason. It never carries tokens or key material.
type keyOpError struct {
	Stage   string `json:"stage"`
	Message string `json:"message"`
	At      string `json:"at"`
}

// keyStageError tags an exchange failure with the stage that produced it.
type keyStageError struct {
	Stage string
	Err   error
}

func (e *keyStageError) Error() string { return e.Err.Error() }
func (e *keyStageError) Unwrap() error { return e.Err }

// keySelectionError is a selection-policy failure: the explicit configuration
// does not match upstream, or nothing is available to choose.
type keySelectionError struct{ msg string }

func (e *keySelectionError) Error() string { return e.msg }

// keySelectionNeededError reports an ambiguous organization/project choice.
// It is an outcome, not a failure: the exchange stops before creating any key
// and the candidate list waits for an explicit selection.
type keySelectionNeededError struct{ candidates *keyCandidates }

func (e *keySelectionNeededError) Error() string {
	return "organization or project selection is required before creating the managed key"
}

// keyAmbiguousError is the internal signal of chooseCandidate carrying the
// undecided level's items; the caller renders it as a selection-needed error.
type keyAmbiguousError struct{ items []keyCandidate }

func (e *keyAmbiguousError) Error() string { return "multiple candidates need an explicit selection" }

// Observed upstream response envelopes. The data wrapper is the only trusted
// location; unknown fields are ignored.

type zaiBizLoginResponse struct {
	Data struct {
		AccessToken      string `json:"access_token"`
		AccessTokenCamel string `json:"accessToken"`
	} `json:"data"`
}

type zaiCustomerInfoResponse struct {
	Data struct {
		Organizations []zaiOrganization `json:"organizations"`
	} `json:"data"`
}

type zaiOrganization struct {
	ID       string       `json:"organizationId"`
	Name     string       `json:"organizationName"`
	Projects []zaiProject `json:"projects"`
}

type zaiProject struct {
	ID   string `json:"projectId"`
	Name string `json:"projectName"`
}

type zaiCreateKeyResponse struct {
	Data struct {
		KeyID string `json:"apiKey"`
		Name  string `json:"name"`
	} `json:"data"`
}

type zaiSecretKeyResponse struct {
	Data struct {
		SecretKey string `json:"secretKey"`
	} `json:"data"`
}

// attachManagedAPIKey resolves the managed fallback key for a fresh login and
// patches the outcome into the auth document's zcode namespace. It never
// fails the login and never touches the JWT namespace: every exchange problem
// is recorded as diagnosable state inside the api_key section instead.
//
// The decision order implements the ownership rules:
//  1. A recorded active key is reused as-is; no upstream key operation runs
//     and no existing upstream key is searched, adopted, or modified.
//  2. A recorded key id without material is refetched by that recorded id.
//  3. Otherwise a new key is created under the configured prefix, but only
//     after the organization/project choice is unambiguous: explicit config
//     ids first, then a single candidate. Anything else records a
//     needs_selection state with the candidate list; localized display names
//     are never used to guess.
func attachManagedAPIKey(doc []byte, identityID, accessToken string, now time.Time) []byte {
	prevSection, hasPrev := readAPIKeySection(doc)
	prev := typedAPIKeyState(prevSection)
	timestamp := now.UTC().Format(time.RFC3339)

	if hasPrev && prev.Status == apiKeyStatusActive && strings.TrimSpace(prev.KeyMaterial) != "" {
		// Reuse: the recorded key stays untouched, including any unknown
		// fields older plugin versions wrote into the section. The managed
		// flag is not consulted because the whole zcode.api_key section is
		// plugin-owned: only this plugin ever writes it.
		return doc
	}

	if strings.TrimSpace(accessToken) == "" {
		// Without exchange material no key operation is possible. A recorded
		// key id is retained so a later login can refetch its material.
		state := prev
		state.Managed = true
		state.UpdatedAt = timestamp
		state.Candidates = nil
		state.Status = apiKeyStatusFailed
		if strings.TrimSpace(state.KeyID) == "" {
			state.Status = apiKeyStatusUnavailable
		}
		state.LastError = &keyOpError{
			Stage:   apiKeyStageExchange,
			Message: "the upstream login did not provide an API key exchange token",
			At:      timestamp,
		}
		return writeAPIKeySection(doc, prevSection, state)
	}

	cfg := currentConfig()
	ctx, cancel := context.WithTimeout(context.Background(), managedKeyExchangeTimeout)
	defer cancel()
	client := newSessionHTTPClient(cfg)
	defer client.CloseIdleConnections()

	state, err := runManagedKeyExchange(ctx, client, cfg, prev, identityID, accessToken, timestamp)
	if err != nil {
		if ctx.Err() != nil {
			err = errors.New("the managed key exchange did not complete in time")
		}
		stage := apiKeyStageLogin
		var staged *keyStageError
		if errors.As(err, &staged) {
			stage = staged.Stage
		}
		failed := state
		failed.Status = apiKeyStatusFailed
		failed.Candidates = nil
		failed.LastError = &keyOpError{Stage: stage, Message: err.Error(), At: timestamp}
		failed.UpdatedAt = timestamp
		return writeAPIKeySection(doc, prevSection, failed)
	}
	state.UpdatedAt = timestamp
	return writeAPIKeySection(doc, prevSection, state)
}

// runManagedKeyExchange performs the upstream exchange and returns the new
// section state. Errors carry their stage; the returned state preserves any
// recorded key identity so failures stay recoverable without creating a
// second key.
func runManagedKeyExchange(ctx context.Context, client *http.Client, cfg Config, prev managedAPIKeyState, identityID, accessToken, timestamp string) (managedAPIKeyState, error) {
	exchanged, err := exchangeBusinessTokenWithExpiry(ctx, client, accessToken)
	if err != nil {
		return prev, &keyStageError{Stage: apiKeyStageLogin, Err: err}
	}
	// The exchange it just performed is the business credential the account's
	// own billing calls need, so it is cached for them rather than paid for
	// again. A caller that never reaches the key stage still benefits.
	activeBusinessTokens.put(identityID, accessToken, exchanged)
	bizToken := exchanged.Token

	orgID, projID := strings.TrimSpace(prev.OrganizationID), strings.TrimSpace(prev.ProjectID)
	if orgID == "" || projID == "" {
		resolvedOrg, resolvedProj, selErr := selectOrganizationProject(ctx, client, cfg, bizToken)
		if selErr != nil {
			var needed *keySelectionNeededError
			if errors.As(selErr, &needed) {
				state := prev
				state.Status = apiKeyStatusNeedsSelection
				state.Managed = true
				state.Message = "the upstream organization/project choice is ambiguous; set oauth.organization_id and oauth.project_id, or reduce the account to one candidate, then log in again"
				state.Candidates = needed.candidates
				state.LastError = nil
				return state, nil
			}
			stage := apiKeyStageDiscovery
			var selection *keySelectionError
			if errors.As(selErr, &selection) {
				stage = apiKeyStageSelection
			}
			return prev, &keyStageError{Stage: stage, Err: selErr}
		}
		orgID, projID = resolvedOrg, resolvedProj
	}

	keyID, name, createdAt := strings.TrimSpace(prev.KeyID), prev.Name, prev.CreatedAt
	if keyID == "" {
		// No recorded key exists, so this is the one creation this identity
		// ever gets; every later run refetches by the recorded id.
		name, err = buildManagedKeyName(cfg.OAuth.ManagedKeyNamePrefix)
		if err != nil {
			return prev, &keyStageError{Stage: apiKeyStageCreate, Err: err}
		}
		keyID, err = createManagedKey(ctx, client, bizToken, orgID, projID, name)
		if err != nil {
			return prev, &keyStageError{Stage: apiKeyStageCreate, Err: err}
		}
		createdAt = timestamp
	}

	material, err := fetchManagedKeyMaterial(ctx, client, bizToken, orgID, projID, keyID)
	if err != nil {
		// The key exists upstream even though its material did not arrive.
		// Recording the key identity keeps the retry on the refetch path
		// instead of creating a duplicate key.
		failed := prev
		failed.KeyID = keyID
		failed.Name = name
		failed.OrganizationID = orgID
		failed.ProjectID = projID
		failed.CreatedAt = createdAt
		return failed, &keyStageError{Stage: apiKeyStageMaterial, Err: err}
	}

	return managedAPIKeyState{
		Status:         apiKeyStatusActive,
		Managed:        true,
		Name:           name,
		KeyID:          keyID,
		KeyMaterial:    material,
		OrganizationID: orgID,
		ProjectID:      projID,
		CreatedAt:      createdAt,
	}, nil
}

// selectOrganizationProject resolves the organization and project for a new
// managed key. Upstream read failures surface as discovery errors; policy
// failures surface as keySelectionError; an ambiguous choice surfaces as
// keySelectionNeededError with the candidate list.
func selectOrganizationProject(ctx context.Context, client *http.Client, cfg Config, bizToken string) (string, string, error) {
	orgs, err := fetchCustomerOrganizations(ctx, client, bizToken)
	if err != nil {
		return "", "", err
	}
	orgCandidates := make([]keyCandidate, 0, len(orgs))
	orgProjects := map[string][]keyCandidate{}
	for _, org := range orgs {
		id := strings.TrimSpace(org.ID)
		if id == "" {
			continue
		}
		orgCandidates = append(orgCandidates, keyCandidate{ID: id, Name: strings.TrimSpace(org.Name)})
		projCandidates := make([]keyCandidate, 0, len(org.Projects))
		for _, project := range org.Projects {
			projectID := strings.TrimSpace(project.ID)
			if projectID == "" {
				continue
			}
			projCandidates = append(projCandidates, keyCandidate{ID: projectID, Name: strings.TrimSpace(project.Name)})
		}
		orgProjects[id] = projCandidates
	}

	org, err := chooseCandidate("organization", orgCandidates, strings.TrimSpace(cfg.OAuth.OrganizationID))
	if err != nil {
		var ambiguous *keyAmbiguousError
		if errors.As(err, &ambiguous) {
			return "", "", &keySelectionNeededError{candidates: &keyCandidates{Organizations: ambiguous.items}}
		}
		return "", "", err
	}
	proj, err := chooseCandidate("project", orgProjects[org.ID], strings.TrimSpace(cfg.OAuth.ProjectID))
	if err != nil {
		var ambiguous *keyAmbiguousError
		if errors.As(err, &ambiguous) {
			// The organization is resolved; only the project is ambiguous.
			return "", "", &keySelectionNeededError{candidates: &keyCandidates{Projects: ambiguous.items}}
		}
		return "", "", err
	}
	return org.ID, proj.ID, nil
}

// chooseCandidate applies the selection policy to one hierarchy level: an
// explicit configured id wins and must exist upstream, a single candidate is
// used as is, and an ambiguous level stops the exchange with the candidate
// list instead of guessing from display names.
func chooseCandidate(level string, items []keyCandidate, configuredID string) (keyCandidate, error) {
	if configuredID != "" {
		for _, item := range items {
			if item.ID == configuredID {
				return item, nil
			}
		}
		return keyCandidate{}, &keySelectionError{fmt.Sprintf("the configured %s id does not exist upstream", level)}
	}
	switch len(items) {
	case 0:
		return keyCandidate{}, &keySelectionError{fmt.Sprintf("the upstream account has no %s to choose", level)}
	case 1:
		return items[0], nil
	default:
		return keyCandidate{}, &keyAmbiguousError{items: items}
	}
}

// buildManagedKeyName renders the managed key name: the configured prefix
// followed by a short crypto-random suffix, e.g. "cpa-zcode-a1b2c3d4". The
// suffix keeps concurrent plugin instances from colliding and makes the key
// recognizably plugin-created without ever serving as a lookup key.
func buildManagedKeyName(prefix string) (string, error) {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		prefix = defaultManagedKeyNamePrefix
	}
	prefix = truncateRunes(prefix, maxManagedKeyNamePrefixLength)
	suffix, err := randomHexToken(managedKeyNameSuffixBytes)
	if err != nil {
		return "", err
	}
	return prefix + "-" + suffix, nil
}

// truncateRunes caps a string at maxBytes without splitting a multi-byte
// rune in half.
func truncateRunes(value string, maxBytes int) string {
	if len(value) <= maxBytes {
		return value
	}
	cut := 0
	for index, r := range value {
		size := utf8.RuneLen(r)
		if index+size > maxBytes {
			break
		}
		cut = index + size
	}
	return value[:cut]
}

// fetchCustomerOrganizations lists the upstream organizations and their
// projects of the logged-in customer.
func fetchCustomerOrganizations(ctx context.Context, client *http.Client, bizToken string) ([]zaiOrganization, error) {
	body, err := managedKeyRequest(ctx, client, http.MethodGet, zaiCustomerInfoURL(), nil, bizToken)
	if err != nil {
		return nil, err
	}
	var parsed zaiCustomerInfoResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, errors.New("the upstream organization response is not valid JSON")
	}
	return parsed.Data.Organizations, nil
}

// createManagedKey creates one plugin-owned key under the given name and
// returns its upstream key identifier.
func createManagedKey(ctx context.Context, client *http.Client, bizToken, orgID, projID, name string) (string, error) {
	payload, err := json.Marshal(map[string]string{"name": name})
	if err != nil {
		return "", fmt.Errorf("encode key creation request: %w", err)
	}
	body, err := managedKeyRequest(ctx, client, http.MethodPost, zaiKeysURL(orgID, projID), payload, bizToken)
	if err != nil {
		return "", err
	}
	var parsed zaiCreateKeyResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", errors.New("the upstream key creation response is not valid JSON")
	}
	keyID := strings.TrimSpace(parsed.Data.KeyID)
	if keyID == "" {
		// The upstream answered but without a usable identifier, so whether
		// a key now exists upstream is unknown; the retry must know that
		// re-running the creation may leave a second key behind.
		return "", errors.New("the upstream key creation response did not include a key identifier; the key may or may not have been created")
	}
	return keyID, nil
}

// fetchManagedKeyMaterial reads the callable secret of the recorded key and
// renders the key material the upstream API expects.
func fetchManagedKeyMaterial(ctx context.Context, client *http.Client, bizToken, orgID, projID, keyID string) (string, error) {
	body, err := managedKeyRequest(ctx, client, http.MethodGet, zaiKeyMaterialURL(orgID, projID, keyID), nil, bizToken)
	if err != nil {
		return "", err
	}
	var parsed zaiSecretKeyResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", errors.New("the upstream key material response is not valid JSON")
	}
	secret := strings.TrimSpace(parsed.Data.SecretKey)
	if secret == "" {
		return "", errors.New("the upstream key material response did not include the key secret")
	}
	return keyID + "." + secret, nil
}

// managedKeyRequest performs one business API call with the common guards and
// returns the raw body. Errors are redacted: they carry no token, body, or
// URL query material.
func managedKeyRequest(ctx context.Context, client *http.Client, method, target string, payload []byte, bearer string) ([]byte, error) {
	var reader io.Reader
	if payload != nil {
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, fmt.Errorf("build key exchange request: %w", err)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("the key exchange upstream is unreachable")
	}
	defer drainAndClose(resp.Body)
	body, err := readLimited(resp.Body, maxManagedKeyBodyBytes)
	if err != nil {
		return nil, fmt.Errorf("read key exchange response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("the upstream key exchange rejected the request (http %d)", resp.StatusCode)
	}
	return body, nil
}

// zaiURL joins the business API base with one observed endpoint path.
func zaiURL(path string) string {
	return strings.TrimRight(zaiAPIBase, "/") + path
}

func zaiBizLoginURL() string { return zaiURL("/api/auth/z/login") }

func zaiCustomerInfoURL() string {
	return zaiURL("/api/biz/customer/getCustomerInfo")
}

func zaiKeysURL(orgID, projID string) string {
	return zaiURL("/api/biz/v1/organization/" +
		url.PathEscape(orgID) + "/projects/" + url.PathEscape(projID) + "/api_keys")
}

func zaiKeyMaterialURL(orgID, projID, keyID string) string {
	return zaiKeysURL(orgID, projID) + "/copy/" + url.PathEscape(keyID)
}

// readAPIKeySection extracts the current api_key section of the document's
// zcode namespace as a generic map, so unknown fields recorded by other
// plugin versions survive a rewrite.
func readAPIKeySection(doc []byte) (map[string]any, bool) {
	var root struct {
		Zcode struct {
			APIKey json.RawMessage `json:"api_key"`
		} `json:"zcode"`
	}
	if err := json.Unmarshal(doc, &root); err != nil {
		return nil, false
	}
	if len(root.Zcode.APIKey) == 0 {
		return nil, false
	}
	var section map[string]any
	if err := json.Unmarshal(root.Zcode.APIKey, &section); err != nil || section == nil {
		return nil, false
	}
	return section, true
}

// typedAPIKeyState renders the known fields of a section map. Unknown fields
// are ignored here but preserved by the merge on write.
func typedAPIKeyState(section map[string]any) managedAPIKeyState {
	if section == nil {
		return managedAPIKeyState{}
	}
	raw, err := json.Marshal(section)
	if err != nil {
		return managedAPIKeyState{}
	}
	var state managedAPIKeyState
	if err := json.Unmarshal(raw, &state); err != nil {
		return managedAPIKeyState{}
	}
	return state
}

// knownAPIKeyFields lists every field this plugin writes into the api_key
// section. The merge drops exactly these before applying the new state, so
// anything unknown survives untouched. TestKnownAPIKeyFieldsCoversStructTags
// keeps this list in lockstep with managedAPIKeyState's json tags.
var knownAPIKeyFields = []string{
	"status", "managed", "message", "name", "key_id", "key_material",
	"organization_id", "project_id", "candidates", "last_error",
	"created_at", "updated_at",
}

// writeAPIKeySection merges the new state into the document's api_key
// section. A merge or patch failure never fails the login: the document
// stays as the JWT-only outcome instead.
func writeAPIKeySection(doc []byte, prevSection map[string]any, state managedAPIKeyState) []byte {
	merged, err := mergeAPIKeySection(prevSection, state)
	if err != nil {
		return doc
	}
	patched, err := patchZcodeNamespace(doc, func(zcode map[string]any) error {
		zcode["api_key"] = merged
		return nil
	})
	if err != nil {
		return doc
	}
	return patched
}

func mergeAPIKeySection(prevSection map[string]any, state managedAPIKeyState) (map[string]any, error) {
	merged := map[string]any{}
	for key, value := range prevSection {
		merged[key] = value
	}
	for _, key := range knownAPIKeyFields {
		delete(merged, key)
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return nil, fmt.Errorf("encode api key state: %w", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("decode api key state: %w", err)
	}
	for key, value := range fields {
		merged[key] = value
	}
	return merged, nil
}
