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

// RequestResponsePredicate checks a response in context of the request that produced it.
// Used for: CORS origin reflection, JSONP callback detection.
type RequestResponsePredicate func(req *http.Request, resp *http.Response) Result

// MultiPredicate performs its own HTTP requests to test multi-step properties.
// Used for: idempotency, safety, retries, CSRF, 304, replay, TOCTOU, workflow-skip.
type MultiPredicate func(client *http.Client, target string) Result

// Group is a named collection of related predicates.
type Group struct {
	Name       string      `json:"name"`
	Predicates []NamedPred `json:"predicates"`
}

// NamedPred pairs a predicate function with its name.
type NamedPred struct {
	Name    string
	Fn      Predicate                // single-response (existing)
	ReqFn   RequestResponsePredicate // request+response (new, nil if unused)
	MultiFn MultiPredicate           // multi-request (new, nil if unused)
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
// Header predicates: CSP, HSTS, SameSite, CORP
// ---------------------------------------------------------------------------

func HeaderGroup() Group {
	return Group{
		Name: "headers",
		Predicates: []NamedPred{
			{Name: "csp", Fn: checkCSP},
			{Name: "hsts", Fn: checkHSTS},
			{Name: "samesite", Fn: checkSameSite},
			{Name: "corp", Fn: checkCORP},
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

// ---------------------------------------------------------------------------
// Method predicates: idempotency, safety, retries
// ---------------------------------------------------------------------------

func MethodGroup() Group {
	return Group{
		Name: "methods",
		Predicates: []NamedPred{
			{Name: "idempotency", Fn: checkIdempotency},
			{Name: "safety", Fn: checkSafety},
			{Name: "retries", Fn: checkRetries},
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
			{Name: "csrf", Fn: checkCSRF},
			{Name: "cors", Fn: checkCORS},
			{Name: "jsonp", Fn: checkJSONP},
			{Name: "redirect", Fn: checkRedirect},
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
			{Name: "etag", Fn: checkETag},
			{Name: "no-store", Fn: checkNoStore},
			{Name: "vary", Fn: checkVary},
			{Name: "304", Fn: check304},
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
			{Name: "workflow-skip", Fn: checkWorkflowSkip},
			{Name: "toctou", Fn: checkTOCTOU},
			{Name: "replay", Fn: checkReplay},
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

// Run executes single-response predicates in a group against a response.
// Predicates that require request context (ReqFn) or multiple requests (MultiFn)
// are skipped — use RunWithRequest or RunMulti for those.
func Run(group Group, resp *http.Response) []Result {
	results := make([]Result, 0, len(group.Predicates))
	for _, p := range group.Predicates {
		if p.MultiFn != nil && p.Fn == nil {
			continue
		}
		if p.ReqFn != nil && p.Fn == nil {
			continue
		}
		if p.Fn != nil {
			results = append(results, p.Fn(resp))
		}
	}
	return results
}

// RunWithRequest executes request+response predicates in a group.
// Only predicates with ReqFn set are executed.
func RunWithRequest(group Group, req *http.Request, resp *http.Response) []Result {
	results := make([]Result, 0, len(group.Predicates))
	for _, p := range group.Predicates {
		if p.ReqFn != nil {
			results = append(results, p.ReqFn(req, resp))
		}
	}
	return results
}

// RunMulti executes multi-request predicates in a group.
// Only predicates with MultiFn set are executed.
func RunMulti(group Group, client *http.Client, target string) []Result {
	results := make([]Result, 0, len(group.Predicates))
	for _, p := range group.Predicates {
		if p.MultiFn != nil {
			results = append(results, p.MultiFn(client, target))
		}
	}
	return results
}

// NeedsMulti reports whether any predicate in the group requires multi-request testing.
func NeedsMulti(group Group) bool {
	for _, p := range group.Predicates {
		if p.MultiFn != nil {
			return true
		}
	}
	return false
}

// NeedsRequest reports whether any predicate in the group requires request context.
func NeedsRequest(group Group) bool {
	for _, p := range group.Predicates {
		if p.ReqFn != nil {
			return true
		}
	}
	return false
}
