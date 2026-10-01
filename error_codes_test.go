package main

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// zaiBody renders the Z.AI business verdict envelope.
func zaiBody(code string, msg string) []byte {
	return []byte(`{"code":` + code + `,"msg":"` + msg + `"}`)
}

// TestClassifyUpstreamFailureBusinessCodeMatrix pins the whole Z.AI code table
// the issue's acceptance criteria name. Each row asserts the credential-level
// conclusion and the status the caller sees, because the two are independent:
// a rejection may say something about the credential without being worth
// retrying, or vice versa.
func TestClassifyUpstreamFailureBusinessCodeMatrix(t *testing.T) {
	cases := []struct {
		name           string
		status         int
		body           []byte
		wantClass      failureClass
		wantClient     int
		wantMovesState bool
	}{
		// 3012 is the risk-control block this plugin actually hit, delivered on
		// HTTP 405. It is a request-level refusal: it must not mark the JWT
		// invalid or exhausted, and 405 must not reach the caller.
		{"risk control on 405", http.StatusMethodNotAllowed,
			[]byte(`{"code":3012,"msg":"request has been blocked due to unusual activity.","logid":"abc"}`),
			failureRejected, http.StatusBadRequest, false},

		{"insufficient balance", http.StatusTooManyRequests,
			[]byte(`{"code":1113,"msg":"Insufficient balance or no resource package. Please recharge."}`),
			failureExhausted, http.StatusPaymentRequired, true},

		{"quota 1304", http.StatusBadRequest, zaiBody("1304", "quota"),
			failureExhausted, http.StatusPaymentRequired, true},
		{"quota 1308", http.StatusBadRequest, zaiBody("1308", "quota"),
			failureExhausted, http.StatusPaymentRequired, true},
		{"quota 1310", http.StatusBadRequest, zaiBody("1310", "quota"),
			failureExhausted, http.StatusPaymentRequired, true},
		{"quota 1313", http.StatusBadRequest, zaiBody("1313", "quota"),
			failureExhausted, http.StatusPaymentRequired, true},
		{"quota 1321", http.StatusBadRequest, zaiBody("1321", "quota"),
			failureExhausted, http.StatusPaymentRequired, true},

		// 1309 is an elapsed subscription, not an exhausted quota: it keeps its
		// own class so renewing the plan is not confused with a quota refresh.
		{"plan expired", http.StatusBadRequest, zaiBody("1309", "plan expired"),
			failurePlanExpired, http.StatusPaymentRequired, true},
		{"plan access denied", http.StatusForbidden, zaiBody("1311", "not entitled"),
			failureRejected, http.StatusForbidden, false},
		{"provider overloaded", http.StatusServiceUnavailable, zaiBody("1312", "busy"),
			failureCooldown, http.StatusBadGateway, true},

		{"auth failed", http.StatusBadRequest, zaiBody("3007", "token invalid"),
			failureInvalid, http.StatusUnauthorized, true},

		{"rate limited 3002", http.StatusBadRequest, zaiBody("3002", "slow down"),
			failureCooldown, http.StatusTooManyRequests, true},
		{"rate limited 3008", http.StatusBadRequest, zaiBody("3008", "slow down"),
			failureCooldown, http.StatusTooManyRequests, true},
		{"rate limited 3009", http.StatusBadRequest, zaiBody("3009", "slow down"),
			failureCooldown, http.StatusTooManyRequests, true},
		{"rate limited 3010", http.StatusBadRequest, zaiBody("3010", "slow down"),
			failureCooldown, http.StatusTooManyRequests, true},
		{"rate limited 1302", http.StatusBadRequest, zaiBody("1302", "slow down"),
			failureCooldown, http.StatusTooManyRequests, true},
		{"rate limited 1303", http.StatusBadRequest, zaiBody("1303", "slow down"),
			failureCooldown, http.StatusTooManyRequests, true},
		{"rate limited 1305", http.StatusBadRequest, zaiBody("1305", "slow down"),
			failureCooldown, http.StatusTooManyRequests, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			failure := classifyUpstreamFailure(tc.status, tc.body)
			if failure.Class != tc.wantClass {
				t.Errorf("class = %q, want %q", failure.Class, tc.wantClass)
			}
			if failure.ClientStatus != tc.wantClient {
				t.Errorf("client status = %d, want %d", failure.ClientStatus, tc.wantClient)
			}
			if failure.UpstreamStatus != tc.status {
				t.Errorf("upstream status = %d, want the observed %d", failure.UpstreamStatus, tc.status)
			}
			// Whether a credential's recorded state moves is what the state
			// machine keys on, so it is asserted directly rather than inferred
			// from the class name.
			if moved := statusForClass(CredentialJWT, failure.Class) != ""; moved != tc.wantMovesState {
				t.Errorf("jwt state moves = %v, want %v", moved, tc.wantMovesState)
			}
		})
	}
}

// TestClassifyUpstreamFailureNeverForwards405 guards the specific harm the
// issue reports: 405 is how this upstream carries business verdicts, so
// forwarding it tells the caller the request method was wrong.
func TestClassifyUpstreamFailureNeverForwards405(t *testing.T) {
	for _, code := range []string{"3012", "1304", "3007", "3002", "1311", "3001", "1113"} {
		failure := classifyUpstreamFailure(http.StatusMethodNotAllowed, zaiBody(code, "upstream said no"))
		if failure.ClientStatus == http.StatusMethodNotAllowed {
			t.Errorf("code %s forwarded 405 to the caller", code)
		}
		if failure.ClientStatus < 400 || failure.ClientStatus >= 500 {
			t.Errorf("code %s client status = %d, want a 4xx/5xx the caller can act on", code, failure.ClientStatus)
		}
	}
}

// TestClassifyUpstreamFailureRiskControlStillTriesFallback is the consequence
// the issue calls out as the first harm: a verification-blocked JWT must not
// strand an account that holds a working fallback key.
func TestClassifyUpstreamFailureRiskControlStillTriesFallback(t *testing.T) {
	failure := classifyUpstreamFailure(http.StatusMethodNotAllowed,
		[]byte(`{"code":3012,"msg":"request has been blocked due to unusual activity."}`))
	if !failure.RetryableBeforeOutput {
		t.Fatal("a request-level block must remain retryable on the fallback credential")
	}
	// The block says nothing about the credential, so no JWT state may move:
	// marking it invalid would strand a JWT the upstream still accepts.
	if status := statusForClass(CredentialJWT, failure.Class); status != "" {
		t.Fatalf("jwt status = %q, want no conclusion from a request-level block", status)
	}
	if failure.Code != "upstream_rejected_invalid_request" {
		t.Errorf("code = %q", failure.Code)
	}
}

// TestClassifyUpstreamFailureKeepsMessageOfZaiEnvelope pins the third harm the
// issue reports: the upstream explains itself in "msg", and dropping it left the
// operator reading only a status.
func TestClassifyUpstreamFailureKeepsMessageOfZaiEnvelope(t *testing.T) {
	failure := classifyUpstreamFailure(http.StatusMethodNotAllowed,
		[]byte(`{"code":3012,"msg":"request has been blocked due to unusual activity.","logid":"log-1"}`))
	if !strings.Contains(failure.Message, "unusual activity") {
		t.Errorf("message = %q, want the upstream explanation", failure.Message)
	}
	if !strings.Contains(failure.Message, "3012") {
		t.Errorf("message = %q, want the business code", failure.Message)
	}
	// The message must stay bounded and single-line even when the upstream's
	// prose is neither.
	long := strings.Repeat("x", 4000)
	failure = classifyUpstreamFailure(http.StatusBadRequest, zaiBody("3001", long))
	if len(failure.Message) > maxSanitizedExcerpt+120 {
		t.Errorf("message length = %d, want a bounded excerpt", len(failure.Message))
	}
	if strings.Contains(failure.Message, "\n") {
		t.Error("message must be reduced to one line")
	}
}

// TestZaiBusinessSemanticsFallBackToHTTPStatus keeps the business-code path
// conservative: an answer with no code, or with a code the plugin has no
// verified meaning for, must fall back to HTTP semantics rather than to a
// guess.
func TestZaiBusinessSemanticsFallBackToHTTPStatus(t *testing.T) {
	bodies := []struct {
		name string
		body []byte
	}{
		{"success envelope", []byte(`{"code":0,"success":true}`)},
		{"code 200", []byte(`{"code":200,"data":{}}`)},
		{"unknown code", []byte(`{"code":9999,"msg":"something new"}`)},
		{"no code at all", []byte(`{"error":{"message":"plain upstream failure"}}`)},
		{"not json", []byte(`upstream is on fire`)},
		{"code is null", []byte(`{"code":null}`)},
	}
	for _, tc := range bodies {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, ok := zaiBusinessSemanticsFor(tc.body); ok {
				t.Fatal("an unclassified answer must not produce a business verdict")
			}
		})
	}
}

// TestZaiBusinessCodePolymorphism covers the two spellings the upstream uses
// for the same code.
func TestZaiBusinessCodePolymorphism(t *testing.T) {
	for _, body := range [][]byte{
		[]byte(`{"code":3012,"msg":"blocked"}`),
		[]byte(`{"code":"3012","msg":"blocked"}`),
		[]byte(`{"data":{"code":3012,"msg":"blocked"}}`),
		[]byte(`{"error":{"code":"3012","message":"blocked"}}`),
	} {
		semantics, code, ok := zaiBusinessSemanticsFor(body)
		if !ok {
			t.Fatalf("body %s was not classified", body)
		}
		if semantics != zaiSemRequestRejected {
			t.Errorf("body %s semantics = %q", body, semantics)
		}
		if normalizeZaiBusinessCode(string(code)) != "3012" {
			t.Errorf("body %s code = %q", body, code)
		}
	}
}

// TestQuotaAndJWTStatesStayIndependent asserts the acceptance requirement that
// a rejection against one credential never moves the other's state. The 1113
// balance error in particular is observed on the fallback key, and marking the
// JWT exhausted from it would take a healthy primary offline.
func TestQuotaAndJWTStatesStayIndependent(t *testing.T) {
	failure := classifyUpstreamFailure(http.StatusTooManyRequests,
		[]byte(`{"type":"error","error":{"type":"rate_limit_error","code":"1113","message":"[1113][Insufficient balance or no resource package. Please recharge.][...]"}}`))
	if failure.Class != failureExhausted {
		t.Fatalf("class = %q, want the exhausted conclusion", failure.Class)
	}
	// Recorded against the API key, it moves the key's state...
	if status := statusForClass(CredentialAPIKey, failure.Class); status != apiKeyStatusExhausted {
		t.Errorf("api key status = %q, want exhausted", status)
	}
	// ...and the same conclusion read against the JWT vocabulary is the JWT's
	// own vocabulary, so recording one can never be mistaken for the other.
	if status := statusForClass(CredentialJWT, failure.Class); status != jwtStatusExhausted {
		t.Errorf("jwt status = %q", status)
	}
	if statusForClass(CredentialAPIKey, failureRejected) == jwtStatusVerificationBlocked {
		t.Error("a request-level rejection must never be recorded as a verification block")
	}
}

// TestZaiBusinessSuccessRejects200WithBusinessFailure covers the Z.AI habit of
// answering 200 with a failure in the body: trusting the status alone would let
// an empty plan list read as "no subscription".
func TestZaiBusinessSuccessRejects200WithBusinessFailure(t *testing.T) {
	if zaiBusinessSuccess([]byte(`{"code":0,"success":true,"data":{"plans":[]}}`)) != true {
		t.Error("an explicit success must be trusted")
	}
	if zaiBusinessSuccess([]byte(`{"code":3001,"msg":"parameter error"}`)) {
		t.Error("a business failure carried on a 200 must not read as success")
	}
	if zaiBusinessSuccess([]byte(`{"code":0,"success":false}`)) {
		t.Error("an explicit success:false must not read as success")
	}
	if zaiBusinessSuccess([]byte(`not json`)) {
		t.Error("an unparsable body must not read as success")
	}
}

// TestRateLimitStatusAloneDoesNotMeanRateLimit pins the issue's requirement
// that a 429 not be classified from its status when the body names a quota
// verdict.
func TestRateLimitStatusAloneDoesNotMeanRateLimit(t *testing.T) {
	quota := classifyUpstreamFailure(http.StatusTooManyRequests, zaiBody("1113", "Insufficient balance"))
	if quota.Class == failureCooldown {
		t.Fatal("a 429 carrying an insufficient-balance verdict is a quota conclusion, not a rate limit")
	}
	rateLimited := classifyUpstreamFailure(http.StatusTooManyRequests, zaiBody("3002", "rate limited"))
	if rateLimited.Class != failureCooldown {
		t.Fatalf("a 429 carrying a rate-limit verdict = %q", rateLimited.Class)
	}
	// A bare 429 with no business code still means what it says.
	bare := classifyUpstreamFailure(http.StatusTooManyRequests, []byte(`too many requests`))
	if bare.Class != failureCooldown {
		t.Fatalf("a bare 429 = %q, want the cooldown class", bare.Class)
	}
}

// TestBusinessVerdictsRecoverThroughTheRightAction checks that each mapped
// state is one the state machine can actually recover, so a business verdict
// never lands the account somewhere with no path back.
func TestBusinessVerdictsRecoverThroughTheRightAction(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cases := []struct {
		code          string
		wantClass     failureClass
		wantRecovered bool
	}{
		{"3012", failureRejected, false},
		{"1304", failureExhausted, true},
		{"3007", failureInvalid, false},
		{"3002", failureCooldown, true},
		{"1312", failureCooldown, true},
	}
	for _, tc := range cases {
		failure := classifyUpstreamFailure(http.StatusBadRequest, zaiBody(tc.code, "x"))
		if failure.Class != tc.wantClass {
			t.Fatalf("code %s class = %q", tc.code, failure.Class)
		}
		conclusion := conclusionFor(CredentialJWT, failure, now)
		recoverable := retryWindowFor(conclusion.Status, now).After(now) ||
			conclusion.Status == jwtStatusExhausted
		if recoverable != tc.wantRecovered {
			t.Errorf("code %s status %q windowed = %v, want %v", tc.code, conclusion.Status, recoverable, tc.wantRecovered)
		}
	}
}

// TestCaptchaTakesPrecedenceOverBusinessCode pins the one conclusion that may
// not be re-read: the upstream signals verification from the body, and a
// business code arriving alongside it must not convert a five-minute automatic
// retry into a permanent "this credential is invalid".
func TestCaptchaTakesPrecedenceOverBusinessCode(t *testing.T) {
	for _, code := range []string{"3012", "3007", "1304", "3002"} {
		body := []byte(`{"code":` + code + `,"msg":"captcha required"}`)
		failure := classifyUpstreamFailure(http.StatusForbidden, body)
		if failure.Class != failureVerificationBlocked {
			t.Errorf("code %s class = %q, want the verification block to win", code, failure.Class)
		}
		// The same precedence holds on the billing surface.
		if quota := quotaAuthFailure(http.StatusForbidden, body); quota == nil ||
			quota.Class != failureVerificationBlocked {
			t.Errorf("code %s quota class = %v, want the verification block to win", code, quota)
		}
	}
	// A 403 that merely mentions an unrelated "check" is not a verification
	// requirement, and stays a credential rejection.
	plain := classifyUpstreamFailure(http.StatusForbidden,
		[]byte(`{"code":3007,"msg":"please check your configuration"}`))
	if plain.Class == failureVerificationBlocked {
		t.Error("an unrelated mention of checking must not read as a verification block")
	}
}

// TestPlanExpiredIsNotRecordedAsExhausted keeps the two recoverable conditions
// apart: an elapsed subscription is renewed, while exhausted quota is cleared by
// a balance reading, and conflating them sends the operator to the wrong fix.
func TestPlanExpiredIsNotRecordedAsExhausted(t *testing.T) {
	failure := classifyUpstreamFailure(http.StatusBadRequest, zaiBody("1309", "plan expired"))
	if status := statusForClass(CredentialJWT, failure.Class); status != jwtStatusPlanExpired {
		t.Fatalf("jwt status = %q, want the elapsed-term state", status)
	}
	if failure.Class == failureExhausted {
		t.Fatal("an elapsed plan must not share the exhausted class")
	}
	// The managed key is not held against a plan term, so the same verdict says
	// only that the upstream is temporarily refusing it.
	if status := statusForClass(CredentialAPIKey, failure.Class); status != apiKeyStatusCooldown {
		t.Errorf("api key status = %q, want a temporary condition", status)
	}
	now := time.Now()
	conclusion := conclusionFor(CredentialJWT, failure, now)
	if !conclusion.RetryAfter.IsZero() {
		t.Error("an elapsed term must not carry a retry window; it is renewed, not waited out")
	}
}

// TestBusinessCodeLookupIgnoresPadding keeps a padded code spelling resolving
// to the same verdict, so a formatting difference cannot silently fall through
// to HTTP classification and mislabel the rejection.
func TestBusinessCodeLookupIgnoresPadding(t *testing.T) {
	for _, code := range []string{"03012", " 3012 ", "3012"} {
		body := []byte(`{"code":"` + strings.TrimSpace(code) + `","msg":"blocked"}`)
		if _, _, ok := zaiBusinessSemanticsFor(body); !ok {
			t.Errorf("code %q did not resolve", code)
		}
	}
}
