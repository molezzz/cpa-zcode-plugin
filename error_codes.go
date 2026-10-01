package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// Z.AI does not answer with HTTP semantics alone. Its status codes are reused
// as transport carriers for business outcomes: a risk-control rejection is
// delivered as HTTP 405, a stale token as HTTP 401 on an endpoint that has no
// 401 semantics at all. Classifying on the status alone therefore mislabels
// every such answer — most visibly, forwarding 405 to the caller tells the
// caller "method not allowed" about a request whose method was always correct.
//
// The plugin therefore classifies on the Z.AI business code carried in the
// body, and only falls back to HTTP status for answers that carry no code.

// zaiBusinessEnvelope is the shape Z.AI uses to report a business outcome. The
// code and message live at the top level, next to an optional data payload;
// the code is polymorphic in the wild (number or string) and some endpoints
// wrap it under data, so both spellings are read.
type zaiBusinessEnvelope struct {
	Code    zaiBusinessCode    `json:"code"`
	Msg     string             `json:"msg"`
	Message string             `json:"message"`
	Success *bool              `json:"success"`
	Data    *zaiBusinessDetail `json:"data"`
	// Error carries the OpenAI-shaped error object the Messages endpoints use.
	// Its code is a string ("1113"), so it is read as a code too rather than
	// being treated as message text only.
	Error *zaiBusinessDetail `json:"error"`
}

type zaiBusinessDetail struct {
	Code    zaiBusinessCode `json:"code"`
	Msg     string          `json:"msg"`
	Message string          `json:"message"`
	Success *bool           `json:"success"`
}

// zaiBusinessCode reads a Z.AI business code, which arrives as a JSON number,
// a decimal string, or not at all. The three states are distinct and all three
// matter: absent means the answer carries no business verdict and the HTTP
// status is all there is.
type zaiBusinessCode string

func (c *zaiBusinessCode) UnmarshalJSON(raw []byte) error {
	trimmed := bytes.TrimSpace(raw)
	// A JSON null or an empty value is the absence of a code, not a code of
	// zero: only an explicit numeric 0 means "success".
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil
	}
	if trimmed[0] == '"' {
		var text string
		if err := json.Unmarshal(trimmed, &text); err != nil {
			return nil
		}
		*c = zaiBusinessCode(strings.TrimSpace(text))
		return nil
	}
	var number json.Number
	if err := json.Unmarshal(trimmed, &number); err != nil {
		return nil
	}
	*c = zaiBusinessCode(number.String())
	return nil
}

// present reports whether the envelope carried a code at all, and whether it
// carried a successful one.
func (c zaiBusinessCode) present() bool { return strings.TrimSpace(string(c)) != "" }

// succeeded reports the upstream's own verdict of success. Z.AI spells
// success as code 0 or 200, and some endpoints also set success:true with no
// code. A code outside that set is a failure regardless of the flag.
func (c zaiBusinessCode) succeeded() bool {
	switch strings.TrimSpace(string(c)) {
	case "", "0", "200":
		return true
	default:
		return false
	}
}

// parseZaiBusinessEnvelope decodes the Z.AI business verdict of one response
// body. ok is false only when the body is not a JSON object at all; a JSON
// object without a code is a successful envelope carrying no code.
func parseZaiBusinessEnvelope(body []byte) (zaiBusinessEnvelope, bool) {
	var parsed zaiBusinessEnvelope
	if err := json.Unmarshal(bytes.TrimSpace(body), &parsed); err != nil {
		return zaiBusinessEnvelope{}, false
	}
	// A code nested under data or error is the same verdict one level in;
	// prefer it only when the top level carried none.
	if !parsed.Code.present() {
		for _, nested := range []*zaiBusinessDetail{parsed.Data, parsed.Error} {
			if nested != nil && nested.Code.present() {
				parsed.Code = nested.Code
				break
			}
		}
	}
	if parsed.Msg == "" {
		for _, nested := range []*zaiBusinessDetail{parsed.Data, parsed.Error} {
			if nested != nil && strings.TrimSpace(nested.Msg) != "" {
				parsed.Msg = nested.Msg
				break
			}
		}
	}
	if parsed.Success == nil {
		for _, nested := range []*zaiBusinessDetail{parsed.Data, parsed.Error} {
			if nested != nil && nested.Success != nil {
				parsed.Success = nested.Success
				break
			}
		}
	}
	return parsed, true
}

// zaiBusinessSemantics is what one Z.AI business code means. The vocabulary is
// the upstream's own low-cardinality attribution table
// (packages/ui/src/lib/chatErrorAttributionEvidence.ts in the official
// client), so the plugin classifies a rejection the same way the client the
// user is running classifies it.
type zaiBusinessSemantics string

const (
	// zaiSemQuotaExhausted is a plan whose remaining units are gone. It
	// recovers when quota is refreshed or replenished, never by retrying.
	zaiSemQuotaExhausted zaiBusinessSemantics = "quota_exhausted"
	// zaiSemAuthFailed is a credential the upstream will not accept.
	zaiSemAuthFailed zaiBusinessSemantics = "auth_failed"
	// zaiSemRateLimited is a temporary request-rate rejection.
	zaiSemRateLimited zaiBusinessSemantics = "rate_limited"
	// zaiSemPlanExpired is a plan whose term has ended.
	zaiSemPlanExpired zaiBusinessSemantics = "plan_expired"
	// zaiSemPlanAccessDenied is a live plan the request is not entitled to
	// use: neither exhausted nor invalid.
	zaiSemPlanAccessDenied zaiBusinessSemantics = "plan_access_denied"
	// zaiSemProviderOverloaded is upstream capacity pressure.
	zaiSemProviderOverloaded zaiBusinessSemantics = "provider_overloaded"
	// zaiSemRequestRejected is a request-level refusal — a malformed request,
	// an unknown model, or a risk-control block. It says nothing about the
	// credential, which is why 3012 lands here and never marks a credential
	// invalid or exhausted.
	zaiSemRequestRejected zaiBusinessSemantics = "invalid_request"
	// zaiSemUpstreamError is an upstream-side fault.
	zaiSemUpstreamError zaiBusinessSemantics = "server_error"
)

// zaiBusinessCodeSemantics is the upstream's code → meaning table. It is an
// allowlist: a code that is not listed concludes nothing about the credential
// and falls through to HTTP-status classification, which is the conservative
// reading. Two additions sit outside the upstream table because the plugin
// observes them directly: 1113, the managed-key insufficient-balance answer,
// which upstream expresses in words rather than in this table.
var zaiBusinessCodeSemantics = map[zaiBusinessCode]zaiBusinessSemantics{
	"1005": zaiSemQuotaExhausted,
	"1006": zaiSemAuthFailed,
	"1113": zaiSemQuotaExhausted,
	"1120": zaiSemUpstreamError,
	"1210": zaiSemRequestRejected,
	"1213": zaiSemRequestRejected,
	"1214": zaiSemRequestRejected,
	"1230": zaiSemUpstreamError,
	"1261": zaiSemRequestRejected,
	"1301": zaiSemRequestRejected,
	"1302": zaiSemRateLimited,
	"1303": zaiSemRateLimited,
	"1304": zaiSemQuotaExhausted,
	"1305": zaiSemRateLimited,
	"1308": zaiSemQuotaExhausted,
	"1309": zaiSemPlanExpired,
	"1310": zaiSemQuotaExhausted,
	"1311": zaiSemPlanAccessDenied,
	"1312": zaiSemProviderOverloaded,
	"1313": zaiSemQuotaExhausted,
	"1314": zaiSemQuotaExhausted,
	"1315": zaiSemQuotaExhausted,
	"1316": zaiSemQuotaExhausted,
	"1317": zaiSemQuotaExhausted,
	"1318": zaiSemQuotaExhausted,
	"1319": zaiSemQuotaExhausted,
	"1320": zaiSemQuotaExhausted,
	"1321": zaiSemQuotaExhausted,
	"2007": zaiSemUpstreamError,
	"3001": zaiSemRequestRejected,
	"3002": zaiSemRateLimited,
	"3006": zaiSemRequestRejected,
	"3007": zaiSemAuthFailed,
	"3008": zaiSemRateLimited,
	"3009": zaiSemRateLimited,
	"3010": zaiSemRateLimited,
	"3012": zaiSemRequestRejected,
}

// zaiBusinessSemanticsFor reads the meaning of one Z.AI answer. ok is false
// when the body carries no code, or a code the plugin has no verified meaning
// for: an unclassified answer is the caller's cue to fall back to HTTP
// semantics rather than to a guess.
func zaiBusinessSemanticsFor(body []byte) (zaiBusinessSemantics, zaiBusinessCode, bool) {
	envelope, ok := parseZaiBusinessEnvelope(body)
	if !ok || !envelope.Code.present() || envelope.Code.succeeded() {
		return "", "", false
	}
	semantics, known := zaiBusinessCodeSemantics[zaiBusinessCode(normalizeZaiBusinessCode(string(envelope.Code)))]
	return semantics, envelope.Code, known
}

// clientStatusForSemantics maps a business meaning onto the status the caller
// should see. The upstream's own status is not reused when it would state
// something the rejection does not: 405 is the canonical case, since it tells
// the caller the request method was wrong when it was not.
func clientStatusForSemantics(semantics zaiBusinessSemantics, upstreamStatus int) int {
	switch semantics {
	case zaiSemQuotaExhausted, zaiSemPlanExpired:
		return http.StatusPaymentRequired
	case zaiSemAuthFailed:
		return http.StatusUnauthorized
	case zaiSemRateLimited:
		return http.StatusTooManyRequests
	case zaiSemProviderOverloaded, zaiSemUpstreamError:
		return http.StatusBadGateway
	default:
		// A request-level rejection keeps the upstream's own 4xx when it is a
		// real 4xx, but never a 405: 405 is the carrier this upstream chose for
		// a business verdict, and forwarding it as a method error misleads the
		// caller about something it cannot act on.
		if upstreamStatus == http.StatusMethodNotAllowed {
			return http.StatusBadRequest
		}
		if upstreamStatus >= 400 && upstreamStatus < 500 {
			return upstreamStatus
		}
		return http.StatusBadRequest
	}
}

// failureClassForSemantics maps a business meaning onto the plugin's failure
// class. The mapping is what makes the classification reach the credential
// state machine: only the meanings that are statements about the credential
// move a credential's state.
func failureClassForSemantics(semantics zaiBusinessSemantics) (failureClass, bool) {
	switch semantics {
	case zaiSemQuotaExhausted:
		return failureExhausted, true
	case zaiSemPlanExpired:
		// An expired plan is not an exhausted one: the remaining units may be
		// untouched, and the account recovers by renewing the plan rather than by
		// a quota refresh. It gets its own class so the two never share a recorded
		// state or a recovery path.
		return failurePlanExpired, true
	case zaiSemAuthFailed:
		return failureInvalid, true
	case zaiSemRateLimited, zaiSemProviderOverloaded, zaiSemUpstreamError:
		return failureCooldown, true
	default:
		// plan_access_denied and invalid_request are statements about the
		// request's entitlement to run, not about the credential's validity:
		// the same credential may serve a different request. They conclude
		// nothing, so a plan the user is not entitled to cannot strand the
		// credential, and a risk-control block cannot mark it invalid.
		return "", false
	}
}

// zaiBusinessMessage extracts the upstream's own explanation for a rejection.
// The message is what distinguishes two rejections that share a status: a 429
// carrying "insufficient balance" is a quota verdict, while the same status
// carrying a rate-limit phrase is not.
func zaiBusinessMessage(body []byte) string {
	envelope, ok := parseZaiBusinessEnvelope(body)
	if !ok {
		return ""
	}
	for _, candidate := range []string{envelope.Msg, envelope.Message} {
		if trimmed := strings.TrimSpace(singleLine(candidate)); trimmed != "" {
			return truncateRunes(trimmed, maxSanitizedExcerpt)
		}
	}
	for _, nested := range []*zaiBusinessDetail{envelope.Data, envelope.Error} {
		if nested == nil {
			continue
		}
		for _, candidate := range []string{nested.Msg, nested.Message} {
			if trimmed := strings.TrimSpace(singleLine(candidate)); trimmed != "" {
				return truncateRunes(trimmed, maxSanitizedExcerpt)
			}
		}
	}
	return ""
}

// zaiBusinessSuccess reports whether a 2xx Z.AI answer actually succeeded. Some
// Z.AI endpoints return HTTP 200 with a business failure in the body, so the
// status alone is not enough to trust a response as usable evidence.
func zaiBusinessSuccess(body []byte) bool {
	envelope, ok := parseZaiBusinessEnvelope(body)
	if !ok {
		return false
	}
	if envelope.Success != nil && !*envelope.Success {
		return false
	}
	return envelope.Code.succeeded()
}

// normalizeZaiBusinessCode renders a code for comparison and logging without
// leading zeros or surrounding whitespace, so "03012" and "3012" are one code.
func normalizeZaiBusinessCode(code string) string {
	trimmed := strings.TrimSpace(code)
	if number, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
		return strconv.FormatInt(number, 10)
	}
	return trimmed
}
