// Package predicate defines RFC-grounded test conditions grouped into
// five categories: headers, methods, cross-origin, cache, state.
package predicate

import (
	"net/http"
	"strings"
)

// Result captures the outcome of a single predicate check.
type Result struct {
	Group  string `json:"group"`
	Name   string `json:"name"`
	Status string `json:"status"` // pass, fail, warn, skip
	Detail string `json:"detail,omitempty"`
}

// Predicate is a function that checks a response against an axiom.
type Predicate func(resp *http.Response) Result

// Group is a named collection of related predicates.
type Group struct {
	Name       string      `json:"name"`
	Predicates []NamedPred `json:"predicates"`
}

// NamedPred pairs a predicate function with its name.
type NamedPred struct {
	Name string
	Fn   Predicate
}

// AllGroups returns every predicate group.
func AllGroups() []Group {
	return []Group{
		HeaderGroup(),
		MethodGroup(),
		CrossOriginGroup(),
		CacheGroup(),
		StateGroup(),
	}
}

// GroupNames returns the list of group names.
func GroupNames() []string {
	return []string{"headers", "methods", "cross-origin", "cache", "state"}
}

// ByName returns a group by name.
func ByName(name string) (Group, bool) {
	for _, g := range AllGroups() {
		if g.Name == name {
			return g, true
		}
	}
	return Group{}, false
}

// ---------------------------------------------------------------------------
// Header predicates: CSP, HSTS, SameSite, CORP, X-Frame-Options
// ---------------------------------------------------------------------------

func HeaderGroup() Group {
	return Group{
		Name: "headers",
		Predicates: []NamedPred{
			{"csp", checkCSP},
			{"hsts", checkHSTS},
			{"samesite", checkSameSite},
			{"corp", checkCORP},
			{"x-frame-options", checkXFrameOptions},
		},
	}
}

func checkCSP(resp *http.Response) Result {
	val := resp.Header.Get("Content-Security-Policy")
	if val == "" {
		return Result{"headers", "csp", "fail", "Content-Security-Policy header missing"}
	}
	return Result{"headers", "csp", "pass", val}
}

func checkHSTS(resp *http.Response) Result {
	val := resp.Header.Get("Strict-Transport-Security")
	if val == "" {
		return Result{"headers", "hsts", "fail", "Strict-Transport-Security header missing"}
	}
	if !strings.Contains(val, "max-age=") {
		return Result{"headers", "hsts", "warn", "HSTS missing max-age directive"}
	}
	return Result{"headers", "hsts", "pass", val}
}

func checkSameSite(resp *http.Response) Result {
	cookies := resp.Header.Values("Set-Cookie")
	if len(cookies) == 0 {
		return Result{"headers", "samesite", "skip", "no cookies set"}
	}
	for _, c := range cookies {
		if !strings.Contains(strings.ToLower(c), "samesite") {
			return Result{"headers", "samesite", "warn", "cookie missing SameSite attribute"}
		}
	}
	return Result{"headers", "samesite", "pass", "all cookies have SameSite"}
}

func checkCORP(resp *http.Response) Result {
	val := resp.Header.Get("Cross-Origin-Resource-Policy")
	if val == "" {
		return Result{"headers", "corp", "fail", "Cross-Origin-Resource-Policy header missing"}
	}
	return Result{"headers", "corp", "pass", val}
}

func checkXFrameOptions(resp *http.Response) Result {
	val := resp.Header.Get("X-Frame-Options")
	if val == "" {
		// Fall back: check CSP frame-ancestors directive.
		csp := resp.Header.Get("Content-Security-Policy")
		if csp != "" && strings.Contains(strings.ToLower(csp), "frame-ancestors") {
			return Result{"headers", "x-frame-options", "pass", "frame-ancestors present in CSP: " + csp}
		}
		return Result{"headers", "x-frame-options", "fail", "X-Frame-Options header missing and no CSP frame-ancestors directive"}
	}
	upper := strings.ToUpper(val)
	switch upper {
	case "DENY", "SAMEORIGIN":
		return Result{"headers", "x-frame-options", "pass", val}
	case "ALLOWALL":
		return Result{"headers", "x-frame-options", "warn", "X-Frame-Options set to ALLOWALL (no protection): " + val}
	default:
		return Result{"headers", "x-frame-options", "warn", "unrecognized X-Frame-Options value: " + val}
	}
}

// ---------------------------------------------------------------------------
// Method predicates: idempotency, safety, retries
// ---------------------------------------------------------------------------

func MethodGroup() Group {
	return Group{
		Name: "methods",
		Predicates: []NamedPred{
			{"idempotency", checkIdempotency},
			{"safety", checkSafety},
			{"retries", checkRetries},
		},
	}
}

func checkIdempotency(_ *http.Response) Result {
	// Stub: requires sending the same request twice and comparing.
	return Result{"methods", "idempotency", "skip", "requires multi-request test"}
}

func checkSafety(_ *http.Response) Result {
	return Result{"methods", "safety", "skip", "requires multi-request test"}
}

func checkRetries(_ *http.Response) Result {
	return Result{"methods", "retries", "skip", "requires multi-request test"}
}

// ---------------------------------------------------------------------------
// Cross-origin predicates: CSRF, CORS, JSONP, redirect
// ---------------------------------------------------------------------------

func CrossOriginGroup() Group {
	return Group{
		Name: "cross-origin",
		Predicates: []NamedPred{
			{"csrf", checkCSRF},
			{"cors", checkCORS},
			{"jsonp", checkJSONP},
			{"redirect", checkRedirect},
		},
	}
}

func checkCSRF(_ *http.Response) Result {
	return Result{"cross-origin", "csrf", "skip", "requires stateful test"}
}

func checkCORS(resp *http.Response) Result {
	acao := resp.Header.Get("Access-Control-Allow-Origin")
	if acao == "*" {
		return Result{"cross-origin", "cors", "warn", "wildcard CORS origin"}
	}
	if acao != "" {
		return Result{"cross-origin", "cors", "pass", acao}
	}
	return Result{"cross-origin", "cors", "skip", "no CORS headers present"}
}

func checkJSONP(_ *http.Response) Result {
	return Result{"cross-origin", "jsonp", "skip", "requires callback parameter test"}
}

func checkRedirect(resp *http.Response) Result {
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := resp.Header.Get("Location")
		if strings.HasPrefix(loc, "http://") {
			return Result{"cross-origin", "redirect", "warn", "redirect to insecure HTTP: " + loc}
		}
		return Result{"cross-origin", "redirect", "pass", "redirect to: " + loc}
	}
	return Result{"cross-origin", "redirect", "skip", "no redirect"}
}

// ---------------------------------------------------------------------------
// Cache predicates: ETag, no-store, Vary, 304
// ---------------------------------------------------------------------------

func CacheGroup() Group {
	return Group{
		Name: "cache",
		Predicates: []NamedPred{
			{"etag", checkETag},
			{"no-store", checkNoStore},
			{"vary", checkVary},
			{"304", check304},
		},
	}
}

func checkETag(resp *http.Response) Result {
	val := resp.Header.Get("ETag")
	if val != "" {
		return Result{"cache", "etag", "pass", val}
	}
	return Result{"cache", "etag", "skip", "no ETag header"}
}

func checkNoStore(resp *http.Response) Result {
	cc := resp.Header.Get("Cache-Control")
	if strings.Contains(cc, "no-store") {
		return Result{"cache", "no-store", "pass", cc}
	}
	if cc == "" {
		return Result{"cache", "no-store", "warn", "no Cache-Control header"}
	}
	return Result{"cache", "no-store", "skip", cc}
}

func checkVary(resp *http.Response) Result {
	val := resp.Header.Get("Vary")
	if val != "" {
		return Result{"cache", "vary", "pass", val}
	}
	return Result{"cache", "vary", "skip", "no Vary header"}
}

func check304(_ *http.Response) Result {
	return Result{"cache", "304", "skip", "requires conditional request test"}
}

// ---------------------------------------------------------------------------
// State predicates: workflow skip, TOCTOU, replay
// ---------------------------------------------------------------------------

func StateGroup() Group {
	return Group{
		Name: "state",
		Predicates: []NamedPred{
			{"workflow-skip", checkWorkflowSkip},
			{"toctou", checkTOCTOU},
			{"replay", checkReplay},
		},
	}
}

func checkWorkflowSkip(_ *http.Response) Result {
	return Result{"state", "workflow-skip", "skip", "requires stateful multi-step test"}
}

func checkTOCTOU(_ *http.Response) Result {
	return Result{"state", "toctou", "skip", "requires concurrent test"}
}

func checkReplay(_ *http.Response) Result {
	return Result{"state", "replay", "skip", "requires replay test"}
}

// Run executes all predicates in a group against a response.
func Run(group Group, resp *http.Response) []Result {
	results := make([]Result, 0, len(group.Predicates))
	for _, p := range group.Predicates {
		results = append(results, p.Fn(resp))
	}
	return results
}
