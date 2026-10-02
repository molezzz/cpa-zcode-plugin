package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// The official client presents two identity fields to the upstream on every
// Anthropic request beyond the static fingerprint headers: a request-body
// identity, metadata.user_id, holding stringified JSON of the device id, an
// empty account_uuid and the session id (docs/ZCode
// adapters/src/model/anthropic-request-metadata.ts), and the attribution
// header family whose session id is stable across the requests of one caller
// session (runner-attribution.ts, runner-status.ts). The body field is the
// Anthropic protocol's standard per-request identity; the headers are
// observability fields only — no entitlement decision reads them.
//
// This file resolves both from the plugin's own honest context. The device id
// is the credential's persisted identity, the same value the X-Device-Mid
// header and the billing requests already use, so body and headers describe
// one installation. The session id is derived from the auth record id — the
// one stable per-caller key the host protocol gives the executor — as a
// name-based UUID, so it is stable across requests and restarts without
// exposing the host's own identifier upstream. Where a value cannot be
// resolved it is omitted, never guessed: no device id drops the whole body
// field, and no session context drops the session fields.

// requestIdentity is the caller-facing identity one upstream request
// presents. The payload metadata and the attribution headers of one request
// consume the same resolved value, so a request can never describe two
// devices or two sessions.
type requestIdentity struct {
	// DeviceID is the credential's persisted device identity
	// (zcode.device_mid), shared with the X-Device-Mid header.
	DeviceID string
	// SessionID is the caller session's stable id. Empty means the request
	// has no session context, which omits the session fields.
	SessionID string
}

// requestIdentityFor resolves one request's identity from the auth record it
// runs on. The document is the same fresh read the credential plan uses, so
// the identity cannot drift from the credential the request actually runs on.
func requestIdentityFor(authIndex string, doc []byte) requestIdentity {
	return requestIdentity{
		DeviceID:  deviceIdentity(authIndex, doc),
		SessionID: requestSessionID(authIndex),
	}
}

// sessionIDNamespace is this plugin's RFC 4122 name-based UUID namespace,
// minted once for this derivation. Deriving under it never reproduces a UUID
// minted for any other purpose.
var sessionIDNamespace = mustNamespaceUUID("ffd3ea62-b297-49fa-910a-5a542aa570f3")

// mustNamespaceUUID parses a canonical namespace UUID at startup. It is only
// ever called on compile-time constants, so a failure here is a build bug that
// should stop the process, not misbehave per request.
func mustNamespaceUUID(hexUUID string) [16]byte {
	raw, err := hex.DecodeString(strings.ReplaceAll(hexUUID, "-", ""))
	if err != nil || len(raw) != 16 {
		panic("zcode: session id namespace is not a 16-byte UUID: " + hexUUID)
	}
	var ns [16]byte
	copy(ns[:], raw)
	return ns
}

// requestSessionID derives the stable session id of one caller session.
//
// The host protocol gives the executor no per-conversation session key, so the
// derivation uses the auth record id: every request of one credential presents
// as one session, which is consistent with the device id and credential it
// already shares. The id is a version-5 (name-based) UUID under the plugin's
// namespace, so it survives plugin restarts while never exposing the host's
// record id upstream. An empty record id carries no session context and yields
// "" — the session fields are omitted rather than guessed. When the host
// protocol grows a real per-conversation key, this derivation should absorb it.
func requestSessionID(authIndex string) string {
	authIndex = strings.TrimSpace(authIndex)
	if authIndex == "" {
		return ""
	}
	return derivedUUIDv5(sessionIDNamespace, authIndex)
}

// derivedUUIDv5 returns the RFC 4122 version-5 (SHA-1, name-based) UUID of
// name under the namespace. The recipe is the RFC's own; SHA-1 here is
// name-based derivation, not a security claim — the id only needs to be
// stable, well-formed, and opaque.
func derivedUUIDv5(namespace [16]byte, name string) string {
	h := sha1.New()
	h.Write(namespace[:])
	h.Write([]byte(name))
	var raw [16]byte
	copy(raw[:], h.Sum(nil))
	raw[6] = raw[6]&0x0f | 0x50
	raw[8] = raw[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16])
}

// applyRequestMetadata injects the request-body identity into one upstream
// payload. The official client always presents its own identity, so a
// caller-supplied metadata.user_id — which would describe some other client —
// is replaced, while unrelated caller metadata keys are preserved.
func applyRequestMetadata(body map[string]any, identity requestIdentity) {
	raw, ok := metadataUserID(identity)
	if !ok {
		return
	}
	metadata, _ := body["metadata"].(map[string]any)
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["user_id"] = raw
	body["metadata"] = metadata
}

// metadataUserID renders the request-body identity in its official wire form:
// a JSON string, not a nested object. The device id is shared with the
// X-Device-Mid header; account_uuid stays the official client's own empty
// string, never a fabricated value; session_id is omitted when the request has
// no session context. With no device id there is nothing honest to present
// and the whole field is omitted — the same rule the X-Device-Mid header
// follows on a host without a resolvable identity.
func metadataUserID(identity requestIdentity) (string, bool) {
	deviceID := strings.TrimSpace(identity.DeviceID)
	if deviceID == "" {
		return "", false
	}
	wire, err := json.Marshal(metadataUserIDBody{
		DeviceID:    deviceID,
		AccountUUID: "",
		SessionID:   strings.TrimSpace(identity.SessionID),
	})
	if err != nil {
		// Marshal of a three-string struct cannot fail; the guard keeps the
		// seam honest all the same.
		return "", false
	}
	return string(wire), true
}

// metadataUserIDBody is the official user_id JSON, in the official client's
// own field order.
type metadataUserIDBody struct {
	DeviceID    string `json:"device_id"`
	AccountUUID string `json:"account_uuid"`
	SessionID   string `json:"session_id,omitempty"`
}
