package main

import (
	"context"
	"strings"
	"time"
)

// A completed OAuth answer carries one Start Plan JWT. What that JWT is worth —
// which plans it holds, how many of them are in force, how much of each model's
// allowance is left — is only knowable by asking the upstream, and the plugin
// used to persist the credential without ever asking. The consequence was
// invisible until a request failed: an account the user believed they had
// authorized was in fact a different one, or a valid plan whose current bucket
// happened to be empty, and neither looked different from the other from the
// outside.
//
// So the balance read happens before the credential reaches the host store. It is
// a read, not a gate on the upstream's own verdict — the plugin does not decide
// what a plan is worth — but it does decide whether the credential is one this
// deployment is willing to store, and it records what the credential turned out
// to be so the management page can show it.
//
// What this file deliberately does not do:
//
//   - It never writes a second credential from a second plan. A Start Plan JWT
//     covering three plans is one JWT, stored once; the plans are the upstream's
//     business and are shown as its data.
//   - It never selects a bucket. The Messages request carries the JWT and the
//     model and nothing else, because the upstream has no client-side plan
//     routing parameter.
//   - It never treats an empty bucket as a reason to refuse. A Start Plan whose
//     current window is spent is a valid plan that will refill; refusing it would
//     make the plugin unable to store the very credentials it most needs to see.

// loginPreflight is what one candidate credential turned out to be.
type loginPreflight struct {
	// Snapshot is the live entitlement and per-model reading. It is stored on
	// the credential as diagnostic data and is not a source of truth: the next
	// quota refresh replaces it.
	Snapshot StartPlanSnapshot
	// UserID is the account identity the upstream stated for this login, or empty
	// when it stated none.
	UserID string
}

// preflightCandidate reads the candidate credential's entitlement and decides
// whether this deployment is willing to store it.
//
// The returned error is a refusal, and a refusal never leaves a credential
// behind: the caller reports it as a failed login, which leaves any existing
// record exactly as it was. That ordering is the reason this runs before the
// write rather than as a check after it — a credential that would clobber a good
// one must never get as far as the clobber.
func preflightCandidate(ctx context.Context, token, userID string, cfg Config) (loginPreflight, error) {
	preflight := loginPreflight{UserID: strings.TrimSpace(userID)}
	// The billing endpoint gates on a device identity and rejects a request
	// without one as a parameter error, which would read as a malformed query
	// rather than as a missing header. The candidate has no record yet, so this
	// is the one place a fresh id is created rather than read.
	deviceID := deviceIdentity("", nil)

	readCtx, cancel := context.WithTimeout(ctx, quotaRequestTimeout)
	defer cancel()
	evidence := fetchQuotaEvidence(readCtx, token, cfg.Product.AppVersion, deviceID, time.Now())
	snapshot := snapshotFor(evidence, time.Now())
	preflight.Snapshot = snapshot

	diagf("oauth_preflight identity=%s readable=%v verdict=%s plans=[%s] models=[%s]",
		preflightIdentityDiag(userID), snapshot.Readable, evidence.Verdict,
		strings.Join(snapshot.startPlanIDs(), " "), diagModelAllowance(snapshot))

	// A billing endpoint that could not be read is not evidence about the plan,
	// so it cannot support a refusal and cannot support a confirmation either.
	// Storing an unverified credential would reintroduce exactly the invisible
	// wrong-account this preflight exists to catch, so the login fails and says
	// the check was inconclusive rather than claiming the credential is fine.
	if !snapshot.Readable {
		return preflight, &preflightError{
			message: "the Start Plan entitlement could not be read before the credential was stored; nothing was saved. Complete the login again, or use the management page to refresh the quota of an existing credential.",
			code:    "start_plan_preflight_unreadable",
		}
	}
	if failure := evidence.AuthFailure; failure != nil {
		// The upstream rejected the candidate. That is a definite answer, and it
		// is the one case where storing the credential would be wrong on the
		// upstream's own terms rather than on this deployment's.
		return preflight, &preflightError{
			message: "the Start Plan billing endpoint rejected this credential, so nothing was saved; complete the ZCode login again.",
			code:    "start_plan_preflight_rejected",
		}
	}
	if !snapshot.hasStartPlan() {
		// The account authorized but holds no Start Plan in force. This is the
		// case the plugin used to store silently, producing an account that could
		// never serve a request. The message names the distinction the operator
		// needs, because "no plan" and "wrong plan" have different fixes.
		return preflight, &preflightError{
			message: "this login has no active Start Plan, so no credential was saved. If you expected a Start Plan, confirm in the browser which account you authorized.",
			code:    "start_plan_preflight_no_plan",
		}
	}
	if ids := planIDsOutsideAllowList(snapshot, cfg.AllowedStartPlanIDs); len(ids) > 0 {
		// An operator who configured an allow-list wants a specific plan, so a
		// login to any other one is refused rather than quietly stored. The
		// message names what the login actually got: telling the user only that
		// it was rejected would leave them re-authorizing the same wrong account.
		return preflight, &preflightError{
			message: "logged in to " + strings.Join(ids, ", ") + ", which is not in allowed_start_plan_ids, so no credential was saved",
			code:    "start_plan_preflight_not_allowed",
		}
	}
	return preflight, nil
}

// preflightError is a refusal to store a candidate credential. It carries a
// bounded code and a message composed only of plan ids the operator configured
// or the upstream itself published — never a token, a user id, or a body.
type preflightError struct {
	message string
	code    string
}

func (e *preflightError) Error() string { return e.message }

// planIDsOutsideAllowList reports the candidate's active Start Plan products that
// an allow-list does not cover. An empty allow-list returns nothing, because it
// is the default and it accepts every plan: a plan this build has never heard of
// is a legitimate plan, and requiring an operator to update a list before every
// new product would make the plugin unable to store valid credentials.
func planIDsOutsideAllowList(snapshot StartPlanSnapshot, allowed []string) []string {
	allow := normalizePlanIDs(allowed)
	if len(allow) == 0 {
		return nil
	}
	var outside []string
	for _, id := range snapshot.startPlanIDs() {
		covered := false
		for _, candidate := range allow {
			if id == candidate {
				covered = true
				break
			}
		}
		if !covered {
			outside = append(outside, id)
		}
	}
	return outside
}

// preflightIdentityDiag renders the account identity for one diagnostic line. It
// is the digest, never the raw user id: the id is the upstream account's own
// identifier, and a debug line is written to the host process log where it would
// outlive the login it describes.
func preflightIdentityDiag(userID string) string {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return "(none)"
	}
	return identityDigestOf(preflightDigestDomain, userID)
}

// preflightDigestDomain domain-separates the login-identity digest from the other
// digests the plugin derives, so the same value hashed for two different purposes
// never produces the same string.
const preflightDigestDomain = "cpa-zcode-plugin/login-identity/v1"

// attachPreflight records the preflight's reading on a freshly built credential
// document, alongside the account identity the upstream stated.
//
// The snapshot is not credential material and is not executable: it exists so the
// management page can show which plan a record actually holds before anyone has
// to run a request. A write failure is not fatal to the login — the credential
// itself is intact and every quota refresh will re-derive this — so it is
// reported through diagnostics rather than by failing the session.
func attachPreflight(doc []byte, preflight loginPreflight, identityID string, cfg Config, now time.Time) []byte {
	if preflight.Snapshot.Readable {
		if patched, err := writePlanSnapshotSection(doc, renderPlanSnapshot(preflight.Snapshot, cfg)); err != nil {
			diagf("oauth_preflight identity=%s snapshot_error=%q", preflightIdentityDiag(preflight.UserID), err.Error())
		} else {
			doc = patched
		}
	}
	if userID := strings.TrimSpace(preflight.UserID); userID != "" {
		// The identity is stored as a digest of the upstream account id. The id
		// itself is never persisted: it is the account's own identifier, and this
		// document lives in a directory the operator syncs and backs up.
		if patched, err := patchZcodeNamespace(doc, func(zcode map[string]any) error {
			login := map[string]any{"user_id_hash": preflightIdentityDiag(userID)}
			if identityID != "" {
				login["identity_id"] = identityID
			}
			login["checked_at"] = now.UTC().Format(time.RFC3339)
			zcode["login"] = login
			return nil
		}); err != nil {
			diagf("oauth_preflight identity=%s login_record_error=%q", preflightIdentityDiag(userID), err.Error())
		} else {
			doc = patched
		}
	}
	return doc
}

// loginPreflightTimeout bounds the whole preflight so a slow billing endpoint
// cannot hold the host's login poll open past its cadence.
const loginPreflightTimeout = quotaRequestTimeout
