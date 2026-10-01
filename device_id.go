package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// The billing endpoint gates on a device identity. A balance request that
// carries none is answered 400 {"code":3001,"msg":"parameter error"} — the
// same rejection a malformed query would produce, which is why the missing
// header reads as a parameter problem. The official client sends the id in the
// X-Device-Mid header, and its own source records that the endpoint "因缺
// X-Device-Mid 被服务端拒绝为 parameter error".
//
// The upstream does not resolve the id against anything: any well-formed UUID
// is accepted and returns the account's real plan and balances, while a
// non-UUID value is rejected with the same 3001. So the id is a client-side
// identity token, not a registered device, and one generated here is as good
// as the desktop client's. It is persisted so a credential keeps reporting the
// same identity across restarts instead of drifting.

// deviceMidHeader is the header the upstream reads the device identity from.
const deviceMidHeader = "X-Device-Mid"

// deviceIDField is the auth-document field holding the device identity, stored
// in the zcode namespace beside the plugin's other owned state.
const deviceIDField = "device_mid"

// deviceIDFallback is used when a credential document cannot be written. The
// id is a client-side token, so a refresh still succeeds with an in-memory
// value; only the across-restart continuity is lost.
const deviceIDFallback = "00000000-0000-4000-8000-000000000000"

var (
	deviceIDMu    sync.Mutex
	deviceIDCache = map[string]string{}
)

// deviceIdentity returns the device id to present to the billing endpoint.
//
// The read path never writes: a quota refresh observes a credential and must
// leave it exactly as it found it, so an id that is not already recorded is
// generated into memory only. It stays stable for the life of the process, and
// recordDeviceID persists it at a point where the credential is legitimately
// being written.
func deviceIdentity(authIndex string, document []byte) string {
	authIndex = strings.TrimSpace(authIndex)
	if existing := recordedDeviceID(document); existing != "" {
		deviceIDMu.Lock()
		deviceIDCache[authIndex] = existing
		deviceIDMu.Unlock()
		return existing
	}

	deviceIDMu.Lock()
	defer deviceIDMu.Unlock()
	if cached, ok := deviceIDCache[authIndex]; ok {
		return cached
	}
	deviceID, err := newUUID()
	if err != nil {
		return deviceIDFallback
	}
	deviceIDCache[authIndex] = deviceID
	return deviceID
}

// deviceIdentityForNewRecord returns the id to stamp into a freshly built
// credential document, preferring one the identity already had.
func deviceIdentityForNewRecord(previousDoc []byte) string {
	if existing := recordedDeviceID(previousDoc); existing != "" {
		return existing
	}
	return deviceIdentity("", nil)
}

// recordDeviceID stores the identity in the credential's auth document so the
// next process reports the same device. A failure is not fatal: the caller
// keeps using the in-memory id.
func recordDeviceID(authIndex string, deviceID string, store AuthStore) error {
	authIndex = strings.TrimSpace(authIndex)
	if authIndex == "" || store == nil {
		return nil
	}
	document, err := store.Get(context.Background(), authIndex)
	if err != nil {
		return err
	}
	if recorded := recordedDeviceID(document); recorded == deviceID {
		return nil
	}
	patched, err := patchZcodeNamespace(document, func(zcode map[string]any) error {
		zcode[deviceIDField] = deviceID
		return nil
	})
	if err != nil {
		return err
	}
	return store.Save(context.Background(), authIndex, patched)
}

// recordedDeviceID reads a device id already present in an auth document.
func recordedDeviceID(document []byte) string {
	var root struct {
		Zcode struct {
			DeviceID string `json:"device_mid"`
		} `json:"zcode"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(document), &root); err != nil {
		return ""
	}
	return strings.TrimSpace(root.Zcode.DeviceID)
}

// newUUID returns a random RFC 4122 version 4 UUID. crypto/rand is used
// directly rather than pulling in a dependency: the id needs to be
// unguessable-shaped and unique per install, which is all crypto/rand gives.
func newUUID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("read crypto/rand: %w", err)
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 0, 36)
	for i, b := range raw {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out = append(out, '-')
		}
		out = append(out, hexDigits[b>>4], hexDigits[b&0x0f])
	}
	return string(out), nil
}
