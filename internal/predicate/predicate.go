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
// Header predicates: CSP, HSTS, SameSite, CORP, X-Frame-Options
// ---------------------------------------------------------------------------

func HeaderGroup() Group {
	return Group{
		Name: "headers",
		Predicates: []NamedPred{
			{Name: "csp", Fn: checkCSP},
			{Name: "hsts", Fn: checkHSTS},
			{Name: "samesite", Fn: checkSameSite},
			{Name: "corp", Fn: checkCORP},
			{Name: "x-frame-options", Fn: checkXFrameOptions},
			{Name: "x-content-type-options", Fn: checkXContentTypeOptions},
			{Name: "permissions-policy", Fn: checkPermissionsPolicy},
		},
	}
}

// parseCSPDirectives splits a CSP policy string on ";" into directives,
// then splits each directive on whitespace into name → sources.
// Example: "default-src 'self'; script-src 'self' cdn.example.com"
// returns {"default-src": ["'self'"], "script-src": ["'self'", "cdn.example.com"]}.
func parseCSPDirectives(policy string) map[string][]string {
	directives := make(map[string][]string)
	for _, raw := range strings.Split(policy, ";") {
		tokens := strings.Fields(strings.TrimSpace(raw))
		if len(tokens) == 0 {
			continue
		}
		name := strings.ToLower(tokens[0])
		directives[name] = tokens[1:]
	}
	return directives
}

// checkCSP validates that a Content-Security-Policy header is present and
// that its directives do not nullify XSS protection.
//
// This predicate validates a security invariant: "CSP must not contain sources
// that nullify its protective property." The implementation follows a
// property-based testing pattern: first decompose the policy into structured
// directives (parseCSPDirectives), then assert properties over that structure.
// This separates parsing from judgement, making each independently testable
// and composable — the same decomposition principle used in PBT generators.
func checkCSP(resp *http.Response) Result {
	val := resp.Header.Get("Content-Security-Policy")
	if val == "" {
		return Result{"headers", "csp", "fail", "Content-Security-Policy header missing"}
	}

	directives := parseCSPDirectives(val)

	// Determine which sources govern script execution:
	// script-src takes precedence; default-src is the fallback.
	sources, directiveName := directives["script-src"], "script-src"
	if _, hasScriptSrc := directives["script-src"]; !hasScriptSrc {
		sources = directives["default-src"]
		directiveName = "default-src"
	}

	// Build a set of lowercase sources for easy lookup.
	srcSet := make(map[string]bool, len(sources))
	for _, s := range sources {
		srcSet[strings.ToLower(s)] = true
	}

	// FAIL: both unsafe-inline and unsafe-eval completely disable XSS protection.
	if srcSet["'unsafe-inline'"] && srcSet["'unsafe-eval'"] {
		return Result{"headers", "csp", "fail",
			"unsafe-inline + unsafe-eval in " + directiveName}
	}

	// WARN: unsafe-inline alone weakens CSP significantly.
	if srcSet["'unsafe-inline'"] {
		return Result{"headers", "csp", "warn",
			"unsafe-inline in " + directiveName}
	}

	// WARN: wildcard or overly broad sources.
	broadSources := []string{"*", "data:", "blob:", "https:"}
	for _, broad := range broadSources {
		if srcSet[broad] {
			return Result{"headers", "csp", "warn",
				"wildcard source (" + broad + ") in " + directiveName}
		}
	}

	// WARN: no default-src means the policy has coverage gaps.
	if _, hasDefault := directives["default-src"]; !hasDefault {
		return Result{"headers", "csp", "warn",
			"no default-src directive (policy has gaps)"}
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

// parseCookieAttrs extracts the cookie name, SameSite value, and presence of
// Secure and HttpOnly flags from a raw Set-Cookie header string.
func parseCookieAttrs(raw string) (name, sameSiteVal string, hasSecure, hasHttpOnly, hasSameSite bool) {
	parts := strings.Split(raw, ";")
	// First part is the name=value pair.
	if len(parts) > 0 {
		nv := strings.TrimSpace(parts[0])
		if eq := strings.IndexByte(nv, '='); eq > 0 {
			name = nv[:eq]
		} else {
			name = nv
		}
	}
	for _, part := range parts[1:] {
		attr := strings.TrimSpace(part)
		attrLower := strings.ToLower(attr)
		if attrLower == "secure" {
			hasSecure = true
		} else if attrLower == "httponly" {
			hasHttpOnly = true
		} else if strings.HasPrefix(attrLower, "samesite") {
			hasSameSite = true
			if eq := strings.IndexByte(attr, '='); eq >= 0 {
				sameSiteVal = strings.TrimSpace(attr[eq+1:])
			}
		}
	}
	return
}

func checkSameSite(resp *http.Response) Result {
	cookies := resp.Header.Values("Set-Cookie")
	if len(cookies) == 0 {
		return Result{"headers", "samesite", "skip", "no cookies set"}
	}

	var details []string
	worstStatus := "pass" // pass < warn < fail

	for _, raw := range cookies {
		name, sameSiteVal, hasSecure, hasHttpOnly, hasSameSite := parseCookieAttrs(raw)

		if !hasSameSite {
			if worstStatus == "pass" {
				worstStatus = "warn"
			}
			details = append(details, name+": SameSite attribute absent")
			continue
		}

		valLower := strings.ToLower(sameSiteVal)
		switch valLower {
		case "none":
			if !hasSecure {
				worstStatus = "fail"
				details = append(details, name+": SameSite=None without Secure flag (browsers will reject)")
			} else {
				detail := name + ": SameSite=None; Secure"
				if !hasHttpOnly {
					detail += " (HttpOnly recommended)"
				} else {
					detail += "; HttpOnly"
				}
				details = append(details, detail)
			}
		case "strict":
			detail := name + ": SameSite=Strict"
			if hasSecure {
				detail += "; Secure"
			}
			if hasHttpOnly {
				detail += "; HttpOnly"
			}
			details = append(details, detail)
		case "lax":
			detail := name + ": SameSite=Lax"
			if hasSecure {
				detail += "; Secure"
			}
			if hasHttpOnly {
				detail += "; HttpOnly"
			}
			details = append(details, detail)
		default:
			if worstStatus == "pass" {
				worstStatus = "warn"
			}
			details = append(details, name+": SameSite="+sameSiteVal+" (unrecognized value)")
		}
	}

	return Result{"headers", "samesite", worstStatus, strings.Join(details, "; ")}
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

func checkXContentTypeOptions(resp *http.Response) Result {
	val := resp.Header.Get("X-Content-Type-Options")
	if val == "" {
		return Result{"headers", "x-content-type-options", "fail", "X-Content-Type-Options header missing"}
	}
	if strings.ToLower(val) != "nosniff" {
		return Result{"headers", "x-content-type-options", "warn", "X-Content-Type-Options is not nosniff: " + val}
	}
	return Result{"headers", "x-content-type-options", "pass", val}
}

func checkPermissionsPolicy(resp *http.Response) Result {
	val := resp.Header.Get("Permissions-Policy")
	if val == "" {
		// Check legacy Feature-Policy header.
		val = resp.Header.Get("Feature-Policy")
		if val != "" {
			return Result{"headers", "permissions-policy", "pass", "Feature-Policy (legacy): " + val}
		}
		return Result{"headers", "permissions-policy", "warn", "Permissions-Policy header missing"}
	}
	return Result{"headers", "permissions-policy", "pass", val}
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
