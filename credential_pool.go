package main

import (
	"context"
	"sort"
	"strings"
	"time"
)

// One upstream account may end up holding several auth records, each with its own
// Start Plan JWT. Before this file the host chose exactly one of them per request
// and the plugin served that record or failed: an account whose first record had
// spent its Flash bucket would return an error even though its second record
// still had allowance, and an operator had no way to express a preference.
//
// The pool orders those records instead of choosing blindly. It is an
// explicitly authorized cross-account scheduling policy, so two things about it
// are non-negotiable: the order must be reproducible (a schedule that depended on
// the host's file enumeration order would send the same account's traffic to
// different plans run to run, which is how a plan gets drained at random), and it
// must be visible and switchable (start_plan_credential_pool.enabled=false
// restores the previous behaviour exactly).
//
// What the pool is NOT is plan routing within one credential. Each record keeps
// its own JWT and sends only that JWT and the model; which of the record's buckets
// the upstream spends is the upstream's decision and is never asked about. The
// pool only decides which record to present.

// poolCandidate is one auth record's standing for one model.
type poolCandidate struct {
	// AuthIndex is the host's handle for the record; every state conclusion this
	// record reaches is written against it.
	AuthIndex string
	// IdentityID is the record's own account identity. It is also the ordering's
	// last tiebreaker, which is what makes the order reproducible: it is derived
	// from the credential rather than from how the store happened to enumerate.
	IdentityID string
	// JWTToken is the record's own Start Plan JWT. It never leaves this plugin and
	// is never mixed with another record's; the pool presents one credential at a
	// time, exactly as a single-record request would.
	JWTToken string
	// Document is the record as the store currently holds it, so an attempt
	// planned from this candidate reads the same record the state conclusions will
	// be written to.
	Document []byte
	// Snapshot is the record's last entitlement reading.
	Snapshot StartPlanSnapshot
}

// poolOrdering is the pool's policy groups. Lower sorts first. There is no
// "host selected" group: the host's pick is a tiebreak inside a group, applied by
// poolRank.less, so it can never outrank the scheduling policy.
type poolOrdering int

const (
	// orderPreferred is a candidate on a plan the configuration does not reserve
	// for last resort.
	orderPreferred poolOrdering = iota
	// orderLastPriority is a candidate on a plan configured to be spent only when
	// nothing else can serve the request.
	orderLastPriority
)

// poolRank orders one candidate for one model.
//
// The ordering is by policy group first and by allowance second, and the two are
// deliberately not interchangeable. Spending the account's non-reserved allowance
// before its reserved one is the whole point of the pool, so it may not depend on
// which record happens to have more units left right now: a plan configured as
// last resort stays last even on the day it has the most to give, and even when
// the host happened to select that record for this request.
//
// The host's own pick breaks ties only within one group. It is the operator's
// expressed choice and nothing here overrides it while another candidate in the
// same group can serve the request — but it does not outrank the scheduling
// policy, because the policy is exactly the answer to "which record should serve
// this", and a host pick on a reserved plan is not a policy exemption.
func (r *poolRank) less(other *poolRank) bool {
	if r.group != other.group {
		return r.group < other.group
	}
	if r.remaining != other.remaining {
		return r.remaining > other.remaining
	}
	if r.hostPicked != other.hostPicked {
		return r.hostPicked
	}
	return r.identity < other.identity
}

// poolRank is one candidate's sort key.
type poolRank struct {
	group poolOrdering
	// remaining is the model's funded units on this candidate, used only to
	// prefer the candidate that can serve the most of the request. It is never a
	// reason to schedule a last-priority plan earlier: the group comparison runs
	// first, which is what pins the reserved plan to the end.
	remaining  float64
	hostPicked bool
	identity   string
}

// buildCredentialPool assembles the ordered candidate list for one model.
//
// It reads the host's auth records rather than trusting its choice of one, and it
// refuses records the plugin cannot read as its own: a document without this
// plugin's identity is another provider's or a partially written file, and
// scheduling a credential out of it would claim an account the plugin never
// created.
//
// Every candidate's snapshot must actually evidence a Start Plan. A record whose
// snapshot is unreadable is kept rather than dropped, for the opposite reason:
// it may well hold a funded plan the last refresh simply could not read, and
// dropping it would silently remove a working credential from service.
func buildCredentialPool(ctx context.Context, store AuthStore, hostAuthIndex, model string, cfg Config, now time.Time) ([]poolCandidate, error) {
	entries, err := store.List(ctx)
	if err != nil {
		return nil, err
	}
	candidates := make([]poolCandidate, 0, len(entries))
	for _, entry := range entries {
		if entry.Provider != pluginID && entry.Type != pluginID {
			continue
		}
		authIndex := strings.TrimSpace(entry.AuthIndex)
		if authIndex == "" {
			continue
		}
		document, err := store.Get(ctx, authIndex)
		if err != nil {
			continue
		}
		snap, err := readCredentialSnapshot(document)
		if err != nil || strings.TrimSpace(snap.IdentityID) == "" {
			// Not one of this plugin's records, or unreadable: never scheduled.
			continue
		}
		if snap.JWTToken == "" {
			// A record with no Start Plan JWT is not a pool member: it has no
			// entitlement to schedule, and its managed key is that record's own
			// business rather than another record's.
			continue
		}
		candidates = append(candidates, poolCandidate{
			AuthIndex:  authIndex,
			IdentityID: snap.IdentityID,
			JWTToken:   snap.JWTToken,
			Document:   document,
			Snapshot:   snapshotFromSection(readPlanSnapshotSection(document)),
		})
	}
	sortPool(candidates, model, hostAuthIndex, cfg)
	return candidates, nil
}

// snapshotFromSection rebuilds the schedulable view of a persisted snapshot.
//
// Only what a stored section carries survives: which plans it holds, and each
// model's allowance and refill time. A record whose section is absent yields a
// snapshot that knows nothing, and every eligibility question about it answers
// "unknown" — which keeps the record schedulable, exactly as it was before this
// feature existed.
func snapshotFromSection(section planSnapshotSection) StartPlanSnapshot {
	snapshot := StartPlanSnapshot{
		Readable:  section.Readable,
		PlanIDs:   section.PlanIDs,
		LastTried: section.LastTried,
	}
	if checked, err := time.Parse(time.RFC3339, strings.TrimSpace(section.CheckedAt)); err == nil {
		snapshot.CheckedAt = checked
	}
	if !section.Readable {
		return snapshot
	}
	for model, line := range section.Models {
		allowance := modelAllowanceFromName(line.Allowance)
		if allowance == allowanceUnknown {
			continue
		}
		remaining := 0.0
		if allowance == allowanceFunded {
			// The stored reading said this model has allowance without saying how
			// much, and the exact number only refines the order among candidates
			// that are already in the same group.
			remaining = 1
		}
		snapshot.Buckets = append(snapshot.Buckets, startPlanBucket{
			Models:    []string{model},
			Remaining: &remaining,
			ExpiresAt: line.ResetAt,
			PlanID:    firstPlanID(section.PlanIDs),
		})
	}
	return snapshot
}

func firstPlanID(ids []string) string {
	for _, id := range ids {
		if trimmed := strings.TrimSpace(id); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func modelAllowanceFromName(name string) modelAllowance {
	switch normalizeStatus(name) {
	case allowanceFunded.String():
		return allowanceFunded
	case allowanceEmpty.String():
		return allowanceEmpty
	default:
		return allowanceUnknown
	}
}

// sortPool orders the candidates for one model.
func sortPool(candidates []poolCandidate, model, hostAuthIndex string, cfg Config) {
	ranks := make(map[string]poolRank, len(candidates))
	for _, candidate := range candidates {
		group := orderPreferred
		if candidate.Snapshot.isLastPriority(cfg) {
			group = orderLastPriority
		}
		ranks[candidate.AuthIndex] = poolRank{
			group:      group,
			remaining:  modelRemainingUnits(candidate.Snapshot, model),
			hostPicked: candidate.AuthIndex == strings.TrimSpace(hostAuthIndex),
			identity:   candidate.IdentityID,
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		left := ranks[candidates[i].AuthIndex]
		right := ranks[candidates[j].AuthIndex]
		return left.less(&right)
	})
}

// modelRemainingUnits reports the units one model has across a snapshot's funded
// buckets. It only refines the order inside a policy group.
func modelRemainingUnits(snapshot StartPlanSnapshot, model string) float64 {
	target := normalizeRequestModel(model, nil)
	total := 0.0
	for _, bucket := range snapshot.Buckets {
		if !bucket.coversModel(target) || bucket.Malformed || bucket.Remaining == nil {
			continue
		}
		if *bucket.Remaining > 0 {
			total += *bucket.Remaining
		}
	}
	return total
}

// eligibleForModel reports whether a candidate may attempt one model now, and
// why not when it may not.
//
// Eligibility is deliberately three questions rather than one, because they have
// different recoveries: a credential the upstream rejected recovers through a
// refresh or a re-login, an empty allowance recovers when the bucket window
// closes, and a plan that has no bucket for the model at all never recovers on its
// own. Collapsing them into one boolean would hide which of the three is true from
// the caller and from the management page.
type poolEligibility struct {
	Eligible bool
	// Reason names why a candidate is not eligible, for diagnostics. It is a
	// bounded class, never upstream prose.
	Reason string
}

// candidateEligibility decides one candidate's standing for one model.
func candidateEligibility(candidate poolCandidate, model string) poolEligibility {
	allowance := candidate.Snapshot.modelAllowance(model)
	switch allowance {
	case allowanceFunded:
		return poolEligibility{Eligible: true}
	case allowanceEmpty:
		return poolEligibility{Reason: "model_allowance_empty"}
	default:
		// The snapshot knows nothing about this model. That is not evidence the
		// candidate cannot serve it — the upstream verifies every request — so the
		// candidate stays eligible and the request settles the question.
		return poolEligibility{Eligible: true}
	}
}
