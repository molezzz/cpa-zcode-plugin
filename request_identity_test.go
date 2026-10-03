package main

import (
	"encoding/json"
	"net/http"
	"regexp"
	"testing"
	"time"
)

// The official client writes a request-body identity into every Anthropic
// request (docs/ZCode adapters/src/model/anthropic-request-metadata.ts):
// metadata.user_id holding a JSON string of the device id, an empty
// account_uuid, and the session id. These tests pin the plugin's version of
// that identity and the three rules that keep it honest: the device id is the
// same persisted identity the X-Device-Mid header carries, nothing is
// fabricated when the plugin cannot resolve a value, and the session id is
// derived from the caller's stable context rather than re-rolled per request.

// parseUpstreamPayload decodes a prepared payload for inspection.
func parseUpstreamPayload(t *testing.T, payload []byte) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatalf("prepared payload is not valid JSON: %v", err)
	}
	return body
}

// metadataUserIDOf extracts the stringified user_id of a prepared payload.
func metadataUserIDOf(t *testing.T, body map[string]any) (map[string]any, bool) {
	t.Helper()
	metadata, ok := body["metadata"].(map[string]any)
	if !ok {
		return nil, false
	}
	raw, ok := metadata["user_id"].(string)
	if !ok {
		t.Fatalf("metadata.user_id = %T, want the official stringified JSON form", metadata["user_id"])
	}
	var userID map[string]any
	if err := json.Unmarshal([]byte(raw), &userID); err != nil {
		t.Fatalf("metadata.user_id is not valid JSON: %v", err)
	}
	return userID, true
}

func TestUpstreamPayloadCarriesTheRequestBodyIdentity(t *testing.T) {
	const deviceID = "11111111-2222-4333-8444-555555555555"
	identity := requestIdentity{
		DeviceID:  deviceID,
		SessionID: requestSessionID("auth-1"),
	}
	payload, _, envErr := prepareUpstreamPayload(testRequestPayload(), "GLM-5.2", nil, identity, true)
	if envErr != nil {
		t.Fatalf("prepareUpstreamPayload rejected the request: %s", envErr)
	}

	userID, ok := metadataUserIDOf(t, parseUpstreamPayload(t, payload))
	if !ok {
		t.Fatal("payload carries no metadata.user_id, want the official request-body identity")
	}
	if got := userID["device_id"]; got != deviceID {
		t.Errorf("metadata.user_id device_id = %v, want the credential's own %q", got, deviceID)
	}
	if got, want := userID["account_uuid"], ""; got != want {
		t.Errorf("metadata.user_id account_uuid = %v, want the official empty string %q", got, want)
	}
	if got := userID["session_id"]; got != identity.SessionID {
		t.Errorf("metadata.user_id session_id = %v, want the derived %q", got, identity.SessionID)
	}
}

func TestRequestBodyIdentitySharesOneDeviceIdentityWithTheHeader(t *testing.T) {
	// The body metadata and the X-Device-Mid header of the same request must
	// describe one installation: both consume the same resolved identity, so a
	// request can never present two devices to the upstream.
	const deviceID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	doc := []byte(`{"zcode":{"identity_id":"zcode-user-1","jwt":{"token":"t","status":"active"},"device_mid":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"}}`)
	identity := requestIdentityFor("auth-index-1", doc)

	payload, _, envErr := prepareUpstreamPayload(testRequestPayload(), "GLM-5.2", nil, identity, true)
	if envErr != nil {
		t.Fatalf("prepareUpstreamPayload rejected the request: %s", envErr)
	}
	userID, ok := metadataUserIDOf(t, parseUpstreamPayload(t, payload))
	if !ok {
		t.Fatal("payload carries no metadata.user_id")
	}

	plan := executionPlan(doc, normalizeConfig(defaultConfig()), "GLM-5.2", nil, identity, time.Now(), nil)
	if len(plan.Attempts) == 0 {
		t.Fatal("no credential attempt was planned")
	}
	for _, profile := range plan.Attempts {
		if got := profile.Headers.Get(deviceMidHeader); got != userID["device_id"] {
			t.Errorf("%s presents header device %q but body device %v; they must be one identity",
				profile.CredentialKind, got, userID["device_id"])
		}
	}
}

func TestRequestBodyIdentityIsStablePerSessionAndDistinctAcrossSessions(t *testing.T) {
	const deviceID = "11111111-2222-4333-8444-555555555555"
	first, _, envErr := prepareUpstreamPayload(testRequestPayload(), "GLM-5.2", nil,
		requestIdentity{DeviceID: deviceID, SessionID: requestSessionID("auth-1")}, true)
	if envErr != nil {
		t.Fatalf("prepareUpstreamPayload rejected the request: %s", envErr)
	}
	second, _, _ := prepareUpstreamPayload(testRequestPayload(), "GLM-5.2", nil,
		requestIdentity{DeviceID: deviceID, SessionID: requestSessionID("auth-1")}, true)
	other, _, _ := prepareUpstreamPayload(testRequestPayload(), "GLM-5.2", nil,
		requestIdentity{DeviceID: deviceID, SessionID: requestSessionID("auth-2")}, true)

	firstID, _ := metadataUserIDOf(t, parseUpstreamPayload(t, first))
	secondID, _ := metadataUserIDOf(t, parseUpstreamPayload(t, second))
	otherID, _ := metadataUserIDOf(t, parseUpstreamPayload(t, other))

	if firstID["session_id"] != secondID["session_id"] {
		t.Errorf("session_id drifted across requests of one session: %v then %v",
			firstID["session_id"], secondID["session_id"])
	}
	if firstID["session_id"] == otherID["session_id"] {
		t.Errorf("session_id = %v for two different sessions", firstID["session_id"])
	}
	if firstID["device_id"] != deviceID || otherID["device_id"] != deviceID {
		t.Errorf("device_id must not drift with the session: %v / %v", firstID["device_id"], otherID["device_id"])
	}
}

func TestRequestBodyIdentityIsOmittedWithoutADeviceIdentity(t *testing.T) {
	// With no device id there is nothing honest to present: the whole field is
	// omitted rather than sending an empty or guessed identity.
	payload, _, envErr := prepareUpstreamPayload(testRequestPayload(), "GLM-5.2", nil, requestIdentity{}, true)
	if envErr != nil {
		t.Fatalf("prepareUpstreamPayload rejected the request: %s", envErr)
	}
	if _, ok := metadataUserIDOf(t, parseUpstreamPayload(t, payload)); ok {
		t.Error("payload carries metadata.user_id without a device identity, want the field omitted")
	}
}

func TestSessionIDIsOmittedWithoutSessionContext(t *testing.T) {
	payload, _, envErr := prepareUpstreamPayload(testRequestPayload(), "GLM-5.2", nil,
		requestIdentity{DeviceID: "11111111-2222-4333-8444-555555555555"}, true)
	if envErr != nil {
		t.Fatalf("prepareUpstreamPayload rejected the request: %s", envErr)
	}
	userID, ok := metadataUserIDOf(t, parseUpstreamPayload(t, payload))
	if !ok {
		t.Fatal("payload carries no metadata.user_id")
	}
	if _, present := userID["session_id"]; present {
		t.Errorf("session_id = %v, want the key omitted when there is no session context", userID["session_id"])
	}
	if got := userID["account_uuid"]; got != "" {
		t.Errorf("account_uuid = %v, want the official empty string", got)
	}
}

func TestCallerRequestBodyIdentityIsReplacedByThePluginDeclaredOne(t *testing.T) {
	// The plugin is the client the upstream sees. A caller's metadata.user_id
	// describes some other client's identity and is replaced; unrelated caller
	// metadata keys are preserved.
	payload, _, envErr := prepareUpstreamPayload(
		[]byte(`{"model":"glm-5.2","max_tokens":64,"messages":[{"role":"user","content":"hi"}],"metadata":{"user_id":"user_caller_identity","conversation":"c-1"}}`),
		"GLM-5.2", nil,
		requestIdentity{DeviceID: "11111111-2222-4333-8444-555555555555", SessionID: "session-derived"}, true)
	if envErr != nil {
		t.Fatalf("prepareUpstreamPayload rejected the request: %s", envErr)
	}
	body := parseUpstreamPayload(t, payload)
	metadata := body["metadata"].(map[string]any)
	if metadata["user_id"] == "user_caller_identity" {
		t.Error("caller metadata.user_id reached the upstream, want the plugin-declared identity")
	}
	if got := metadata["conversation"]; got != "c-1" {
		t.Errorf("metadata.conversation = %v, want the caller's unrelated key preserved", got)
	}
}

func TestMalformedCallerMetadataIsReplacedByThePluginIdentity(t *testing.T) {
	// The Anthropic protocol spells metadata as an object; a caller that sends
	// anything else sends a malformed field, which the plugin's own identity
	// replaces rather than being forwarded or crashing the request.
	payload, _, envErr := prepareUpstreamPayload(
		[]byte(`{"model":"glm-5.2","max_tokens":64,"messages":[{"role":"user","content":"hi"}],"metadata":"garbage"}`),
		"GLM-5.2", nil,
		requestIdentity{DeviceID: "11111111-2222-4333-8444-555555555555"}, true)
	if envErr != nil {
		t.Fatalf("prepareUpstreamPayload rejected the request: %s", envErr)
	}
	if _, ok := metadataUserIDOf(t, parseUpstreamPayload(t, payload)); !ok {
		t.Error("payload carries no metadata.user_id after a malformed caller metadata, want the plugin identity")
	}
}

func TestRequestSessionIDIsStableWellFormedAndOpaque(t *testing.T) {
	uuidForm := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	first := requestSessionID("auth-1")
	if !uuidForm.MatchString(first) {
		t.Errorf("requestSessionID = %q, want a well-formed UUID", first)
	}
	if again := requestSessionID("auth-1"); again != first {
		t.Errorf("requestSessionID drifted: %q then %q, want one stable id per caller session", again, first)
	}
	if other := requestSessionID("auth-2"); other == first {
		t.Errorf("two auth records derived the same session id %q", first)
	}
	// The derivation must not carry the host's own record id upstream.
	if got := requestSessionID("zcode-2558a883d3f6c843"); got == "zcode-2558a883d3f6c843" || regexp.MustCompile(`2558a883`).MatchString(got) {
		t.Errorf("session id %q exposes the host record id", got)
	}
	if got := requestSessionID("  "); got != "" {
		t.Errorf("requestSessionID(whitespace) = %q, want no session context", got)
	}
}

func TestAttributionIDsCorrelateWithinARequestAndStabilizeTheSession(t *testing.T) {
	// The official headers let request/trace/query be the same value or
	// derived; what they must express is that one upstream request is one
	// correlated event, and that the session spans the caller's turns.
	session := requestSessionID("auth-1")
	headers := http.Header{}
	applyRequestAttribution(headers, session)

	if got := headers.Get(requestIDHeader); got == "" || got != headers.Get(traceIDHeader) || got != headers.Get(queryIDHeader) {
		t.Errorf("request/trace/query ids do not correlate: %q / %q / %q",
			headers.Get(requestIDHeader), headers.Get(traceIDHeader), headers.Get(queryIDHeader))
	}
	if got := headers.Get(sessionIDHeader); got != session {
		t.Errorf("%s = %q, want the stable session id", sessionIDHeader, got)
	}
	if got := headers.Get(sessionTypeHeader); got != mainSessionType {
		t.Errorf("%s = %q, want %q", sessionTypeHeader, got, mainSessionType)
	}

	again := http.Header{}
	applyRequestAttribution(again, session)
	if got := again.Get(sessionIDHeader); got != session {
		t.Errorf("session id drifted across requests: %q then %q", headers.Get(sessionIDHeader), got)
	}
	if again.Get(requestIDHeader) == headers.Get(requestIDHeader) {
		t.Error("request attribution id was reused across requests, want a fresh one per request")
	}
}

func TestAttributionSessionHeaderIsOmittedWithoutSessionContext(t *testing.T) {
	// The official client omits the session header when it has no session
	// value; a blank or invented one would describe a session that does not
	// exist.
	headers := http.Header{}
	applyRequestAttribution(headers, "")
	if got := headers.Get(sessionIDHeader); got != "" {
		t.Errorf("%s = %q, want it omitted", sessionIDHeader, got)
	}
	for _, name := range []string{requestIDHeader, traceIDHeader, queryIDHeader, sessionTypeHeader} {
		if headers.Get(name) == "" {
			t.Errorf("%s = empty, want the attribution to survive without session context", name)
		}
	}
}
