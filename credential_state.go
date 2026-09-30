package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// credentialRecorder persists the availability conclusions of one upstream
// attempt. The primary JWT and the managed API key are recorded
// independently, so a failure of one never overwrites the other credential's
// state or recovery path.
type credentialRecorder interface {
	record(ctx context.Context, ref credentialRef, updates ...recordedState) error
}

// credentialRef identifies the host auth record whose document carries the two
// credential states. AuthIndex is the runtime index, Document is the request's
// own snapshot of the plugin-owned namespace, and IdentityID is the upstream
// identity whose transitions are serialized against each other.
type credentialRef struct {
	AuthIndex  string
	IdentityID string
	Document   []byte
}

// recordedState is one credential's post-attempt conclusion. RetryAfter marks
// the states that heal on their own once the window has passed: the
// verification block and the temporary cooldown carry it, while the permanent
// conclusions (invalid, exhausted) never do and are recovered by a credential
// or quota refresh instead.
type recordedState struct {
	Kind       CredentialKind
	Status     string
	RetryAfter time.Time
	// Code is the bounded upstream classification kept for diagnosis. It is
	// never a URL, a token, or upstream prose.
	Code string
	// OnlyIfStatus, when set, restricts the conclusion to a record whose
	// persisted status still reads exactly that value. A quota recovery uses
	// it so an exhausted credential flips to active only when the persisted
	// state is still exhausted — the check runs inside the identity lock, so
	// a state that changed between the quota call and the write cannot be
	// overwritten by a stale recovery.
	OnlyIfStatus string
	// NotIfStatus is the mirror guard: the conclusion applies only while the
	// persisted status is NOT this value. A credential refresh's successful
	// probe uses it so a valid authentication never clears exhausted — a
	// models endpoint 200 proves the credential authenticates, which is not
	// evidence about quota, and exhausted recovers through a quota refresh.
	NotIfStatus string
}

// errAuthFileNameUnknown reports that the host auth store could not name the
// file a state write would replace, so the write was declined rather than
// risking a second auth file for a record the host already stores.
var errAuthFileNameUnknown = errors.New("the host auth store did not name the record, so its credential state was not written")

// errCredentialMaterialLost reports a patch that would have removed every
// credential from a record that had at least one. The write is refused rather
// than committed, because a record with no JWT and no managed key is an account
// the plugin can never serve again.
var errCredentialMaterialLost = errors.New("refusing to persist a record without any credential")

// stateStore is the part of the host auth store the state machine needs.
type stateStore interface {
	Get(ctx context.Context, authIndex string) (json.RawMessage, error)
	GetRuntime(ctx context.Context, authIndex string) (pluginapi.HostAuthFileEntry, error)
	Save(ctx context.Context, name string, document json.RawMessage) error
}

// credentialStateStoreTimeout bounds one host auth store round trip during a
// state write, so a slow store cannot hold a request hostage.
const credentialStateStoreTimeout = 5 * time.Second

// identityLocks is the plugin-wide registry of per-upstream-identity mutexes.
// Every serialized-per-identity consumer — the credential state recorder and
// the management actions — shares one instance, so a management refresh and a
// request-side state write for the same account can never interleave.
type identityLocks struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

func newIdentityLocks() *identityLocks {
	return &identityLocks{locks: map[string]*sync.Mutex{}}
}

// identityLockKey collapses the identifiers that may name the same account
// onto one lock: the upstream identity wins, the auth index is the fallback,
// and an unattributed write still gets its own serialization key.
func identityLockKey(identityID, authIndex string) string {
	if key := strings.TrimSpace(identityID); key != "" {
		return key
	}
	if key := strings.TrimSpace(authIndex); key != "" {
		return key
	}
	return "zcode-unattributed"
}

// lock returns the unlock func for one identity's critical section.
func (l *identityLocks) lock(key string) func() {
	mu := l.mutexFor(key)
	mu.Lock()
	return mu.Unlock
}

// tryLock returns the unlock func and true, or false when the identity is
// already locked by someone else. Management actions use it to refuse, not
// queue, when another operation for the same account is in flight.
func (l *identityLocks) tryLock(key string) (func(), bool) {
	mu := l.mutexFor(key)
	if !mu.TryLock() {
		return nil, false
	}
	return mu.Unlock, true
}

func (l *identityLocks) mutexFor(key string) *sync.Mutex {
	l.mu.Lock()
	defer l.mu.Unlock()
	lock, ok := l.locks[key]
	if !ok {
		lock = &sync.Mutex{}
		l.locks[key] = lock
	}
	return lock
}

// identityLockRegistry is the shared instance. It exists at package level so
// recorders built through forStore and management services built per request
// serialize against the same mutexes.
var identityLockRegistry = newIdentityLocks()

// credentialStateRecorder writes credential state transitions back to the
// host auth store. Transitions are serialized per upstream identity, and one
// request's conclusions land as exactly one lossless save, so concurrent
// requests for the same identity can neither interleave nor lose the other
// credential's state.
type credentialStateRecorder struct {
	store stateStore
	// now is a test seam for the retry windows.
	now func() time.Time

	locks *identityLocks
}

// credentialStates is the plugin-wide recorder. The store is resolved when an
// execution scope is built rather than at package init, so a reconfigured host
// is always called through the current seam.
var credentialStates = newCredentialStateRecorder()

func newCredentialStateRecorder() *credentialStateRecorder {
	return newCredentialStateRecorderOver(authStoreProvider())
}

func newCredentialStateRecorderOver(store stateStore) *credentialStateRecorder {
	return &credentialStateRecorder{
		store: store,
		now:   time.Now,
		locks: identityLockRegistry,
	}
}

// record applies every transition of one request in a single save. The
// document is re-read inside the identity lock, so the write never depends on
// the caller's snapshot and a concurrent management action that rewrote the
// record between the attempt's start and its conclusion is not lost. A save
// failure is reported to the caller, which keeps it out of the caller's
// response; it never invalidates an otherwise successful upstream result.
func (r *credentialStateRecorder) record(ctx context.Context, ref credentialRef, updates ...recordedState) error {
	conclusions := stateConclusions(updates)
	if len(conclusions) == 0 {
		return nil
	}
	unlock := r.lockIdentity(ref)
	defer unlock()

	document, name, hostNamed, err := r.currentDocument(ctx, ref)
	if err != nil {
		return err
	}
	patched, changed, err := applyCredentialState(document, conclusions, r.now())
	if err != nil {
		return err
	}
	if !changed {
		// The conclusion is already the persisted one, so the record stays
		// byte-identical instead of churning the host auth file.
		return nil
	}
	if !hostNamed {
		// The host never told the plugin which file this record lives in, and
		// the identity-derived name is only what login would use: saving under
		// it could mint a second auth file for a record the host already
		// stores elsewhere. Losing this transition is the lesser harm, and the
		// next request — whose runtime lookup is expected to succeed — records
		// the state again.
		return errAuthFileNameUnknown
	}
	return r.save(ctx, ref, name, patched)
}

// stateConclusions drops the transitions that conclude nothing. An attempt
// that said nothing about a credential's availability — a skipped attempt, or
// a failure the upstream classification does not attribute to a credential —
// records no state at all, so it must not even reach the host store.
func stateConclusions(updates []recordedState) []recordedState {
	out := make([]recordedState, 0, len(updates))
	for _, update := range updates {
		if strings.TrimSpace(update.Status) == "" {
			continue
		}
		out = append(out, update)
	}
	return out
}

// forStore routes state writes to the given auth store while keeping the
// plugin-wide per-identity locks, so requests on one identity stay serialized
// even when the resolved store changes.
func (r *credentialStateRecorder) forStore(store stateStore) *credentialStateRecorder {
	return &credentialStateRecorder{store: store, now: r.now, locks: r.locks}
}

// currentDocument reads the record as the host currently holds it, together
// with the file name to save it under and whether that name came from the host.
// The runtime lookup is the authority on both; when the store cannot be read
// the attempt's own snapshot is used instead, because a lost transition strands
// a credential the caller has already seen fail. Both branches run inside the
// identity lock, so the fallback cannot race a concurrent save for the same
// identity.
func (r *credentialStateRecorder) currentDocument(ctx context.Context, ref credentialRef) ([]byte, string, bool, error) {
	derived := authFileNameFor(ref.IdentityID)
	if strings.TrimSpace(ref.AuthIndex) == "" {
		document, err := r.snapshotDocument(ref)
		return document, derived, false, err
	}
	readCtx, cancel := context.WithTimeout(ctx, credentialStateStoreTimeout)
	defer cancel()
	entry, err := r.store.GetRuntime(readCtx, ref.AuthIndex)
	if err != nil {
		document, snapshotErr := r.snapshotDocument(ref)
		return document, derived, false, snapshotErr
	}
	name := strings.TrimSpace(entry.Name)
	hostNamed := name != ""
	if !hostNamed {
		name = derived
	}
	document, err := r.store.Get(readCtx, ref.AuthIndex)
	if err != nil || !documentIsPluginRecord(document, ref.IdentityID) {
		// A document that is not one of this plugin's records is never written
		// into: the store's own answer may legitimately be a record this
		// provider does not own, and patching it would claim an account the
		// plugin never created. The attempt's own snapshot is the only
		// known-good input.
		document, snapshotErr := r.snapshotDocument(ref)
		return document, name, hostNamed, snapshotErr
	}
	return document, name, hostNamed, nil
}

// documentIsPluginRecord reports whether a stored document is the credential
// record this request is about. Ownership is the identity the record claims
// rather than whether it currently holds a credential: a record that
// legitimately has none yet is still this plugin's to record state on, while a
// document belonging to a different identity or to another provider must never
// be patched.
func documentIsPluginRecord(doc []byte, identityID string) bool {
	var root struct {
		Zcode struct {
			IdentityID string `json:"identity_id"`
		} `json:"zcode"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(doc), &root); err != nil {
		return false
	}
	owner := strings.TrimSpace(root.Zcode.IdentityID)
	requested := strings.TrimSpace(identityID)
	return owner != "" && requested != "" && owner == requested
}

// snapshotDocument is the fallback read: the document the request already
// carries, under whatever file name the caller resolved for it.
func (r *credentialStateRecorder) snapshotDocument(ref credentialRef) ([]byte, error) {
	if len(bytes.TrimSpace(ref.Document)) == 0 {
		return nil, errNoCredential
	}
	return ref.Document, nil
}

// save persists the patched document. The host's own auth file name wins over
// the name derived from the identity id, which is only a fallback for records
// the runtime lookup could not name.
func (r *credentialStateRecorder) save(ctx context.Context, ref credentialRef, name string, document []byte) error {
	writeCtx, cancel := context.WithTimeout(ctx, credentialStateStoreTimeout)
	defer cancel()
	return r.store.Save(writeCtx, name, json.RawMessage(document))
}

// lockIdentity returns the unlock func for one identity's state writes. An
// attempt with no identifiable identity still gets a lock, so writes stay
// serialized against each other.
func (r *credentialStateRecorder) lockIdentity(ref credentialRef) func() {
	return r.locks.lock(identityLockKey(ref.IdentityID, ref.AuthIndex))
}

// applyCredentialState renders one attempt's conclusions into the document and
// reports whether anything changed. Every section is written from the same
// read of the document, so one attempt can never interleave a stale JWT write
// with a fresh API key write.
func applyCredentialState(doc []byte, conclusions []recordedState, now time.Time) ([]byte, bool, error) {
	var before, after []byte
	patched, err := patchZcodeNamespace(doc, func(zcode map[string]any) error {
		before = renderNamespace(zcode)
		for _, conclusion := range conclusions {
			applyStateSection(zcode, conclusion, now)
		}
		after = renderNamespace(zcode)
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	if snap, err := readCredentialSnapshot(doc); err == nil && (snap.JWTToken != "" || snap.APIKeyToken != "") {
		if patchedSnap, err := readCredentialSnapshot(patched); err != nil ||
			(patchedSnap.JWTToken == "" && patchedSnap.APIKeyToken == "") {
			// A patch must never be the event that empties a record of its
			// credentials. The merge only ever rewrites a credential's own
			// state fields, so reaching this means the patch itself lost one.
			return nil, false, errCredentialMaterialLost
		}
	}
	return patched, !bytes.Equal(before, after), nil
}

// applyStateSection merges one credential's conclusion into the zcode
// namespace, leaving the fields the conclusion does not speak about — the
// JWT token, the managed key identity and material, the exchange candidates —
// exactly as they were. A conclusion that matches what is already recorded
// changes nothing at all, so a steady stream of successful requests does not
// rewrite the host auth file once per request.
func applyStateSection(zcode map[string]any, conclusion recordedState, now time.Time) {
	name := credentialSectionName(conclusion.Kind)
	existing, _ := zcode[name].(map[string]any)
	if conclusion.OnlyIfStatus != "" && normalizeStatus(stringField(existing, "status")) != conclusion.OnlyIfStatus {
		// The persisted state moved on since the evidence was gathered; the
		// guarded conclusion no longer applies to it.
		return
	}
	if conclusion.NotIfStatus != "" && normalizeStatus(stringField(existing, "status")) == conclusion.NotIfStatus {
		return
	}
	if stateAlreadyRecorded(existing, conclusion) {
		return
	}
	merged := map[string]any{}
	for key, value := range existing {
		merged[key] = value
	}
	merged["status"] = conclusion.Status
	setOrDrop(merged, "retry_after", formatRetryAfter(conclusion.RetryAfter))
	// A conclusion with no code — the skip block re-asserting a state the
	// record already holds — leaves the persisted reason untouched: the
	// reason belongs to the failure that produced the state, not to the
	// request that re-asserted it.
	if conclusion.Code != "" {
		merged["last_error_code"] = conclusion.Code
	}
	merged[credentialCheckedAtField(conclusion.Kind)] = now.UTC().Format(time.RFC3339)

	// A recorded window is only ever kept while it still says something true.
	// A windowed conclusion that has elapsed heals in place — that is what
	// lets a verification block recover on its own after five minutes — and a
	// conclusion that carries no window is permanent, so any window left over
	// from an earlier, temporary state is dropped rather than stranding the
	// credential behind a stale deadline.
	if isSelfHealingStatus(conclusion.Status) {
		if retryAfter, ok := merged["retry_after"].(string); ok && !retryWindowPending(retryAfter, now) {
			delete(merged, "retry_after")
		}
	} else {
		delete(merged, "retry_after")
	}
	zcode[name] = merged
}

// stateAlreadyRecorded reports whether the persisted section already expresses
// this conclusion, so a repeat of the same outcome is not rewritten. The
// checked-at stamp is deliberately ignored: it only records that a conclusion
// was reached, not that anything about the credential changed. A conclusion
// with no code asserts no reason, so the recorded one is not compared either.
func stateAlreadyRecorded(existing map[string]any, conclusion recordedState) bool {
	if existing == nil {
		return false
	}
	if normalizeStatus(stringField(existing, "status")) != conclusion.Status {
		return false
	}
	if conclusion.Code != "" && stringField(existing, "last_error_code") != conclusion.Code {
		return false
	}
	// A conclusion with no window must find no window recorded, and one with
	// a window must find exactly that window: a different deadline means the
	// recorded state says something this conclusion does not.
	return stringField(existing, "retry_after") == formatRetryAfter(conclusion.RetryAfter)
}

// stringField reads a string field, tolerating a section that holds another
// JSON type for it.
func stringField(section map[string]any, key string) string {
	value, _ := section[key].(string)
	return value
}

// setOrDrop writes a value, removing the key instead of persisting an empty
// one so the record never shows a blank reason or a zero timestamp.
func setOrDrop(section map[string]any, key, value string) {
	if strings.TrimSpace(value) == "" {
		delete(section, key)
		return
	}
	section[key] = value
}

// formatRetryAfter renders a retry window, or nothing when there is none.
func formatRetryAfter(retryAfter time.Time) string {
	if retryAfter.IsZero() {
		return ""
	}
	return retryAfter.UTC().Format(time.RFC3339)
}

// credentialCheckedAtField is the per-credential field carrying the moment its
// availability was last concluded. The JWT section already uses it from
// login, so the two sections stay distinguishable by their own schema.
func credentialCheckedAtField(kind CredentialKind) string {
	if kind == CredentialAPIKey {
		return "updated_at"
	}
	return "last_checked_at"
}

// renderNamespace serializes the namespace for change detection. Its values
// are ordinary JSON documents decoded by patchZcodeNamespace, so marshalling
// cannot fail.
func renderNamespace(zcode map[string]any) []byte {
	raw, err := json.Marshal(zcode)
	if err != nil {
		return nil
	}
	return raw
}

// credentialSectionName maps a credential kind onto its zcode namespace key. An
// unrecognized kind is a programming error, not a value to guess at: silently
// writing such a state into the JWT section would move a credential's
// availability onto the wrong credential.
func credentialSectionName(kind CredentialKind) string {
	switch kind {
	case CredentialJWT:
		return "jwt"
	case CredentialAPIKey:
		return "api_key"
	default:
		panic("unknown credential kind: " + string(kind))
	}
}

// isSelfHealingStatus reports whether a conclusion clears itself once its
// retry window has passed. Only the windowed states heal; invalid and
// exhausted are recovered by a credential refresh and a quota refresh
// respectively.
func isSelfHealingStatus(status string) bool {
	switch status {
	case jwtStatusVerificationBlocked, jwtStatusCooldown:
		return true
	default:
		return false
	}
}

// retryWindowPending reports whether a recorded retry window still holds a
// credential out of use. A missing or unparsable window holds nothing out: the
// upstream re-verifies on every request, so an unknown deadline must never
// strand a possibly-usable credential.
func retryWindowPending(retryAfter string, now time.Time) bool {
	deadline, err := time.Parse(time.RFC3339, strings.TrimSpace(retryAfter))
	if err != nil {
		return false
	}
	return now.Before(deadline)
}
