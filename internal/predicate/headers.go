package predicate

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// HeaderGroup returns the header security predicate group.
func HeaderGroup() Group {
	return Group{
		Name: GroupHeaders,
		Predicates: []NamedPred{
			{Name: "csp", Fn: checkCSP, Type: TypeUniversal},
			{Name: "hsts", Fn: checkHSTS, Type: TypeUniversal},
			{Name: "samesite", Fn: checkSameSite, Type: TypeUniversal},
			{Name: "corp", Fn: checkCORP, Type: TypeUniversal},
			{Name: "x-frame-options", Fn: checkXFrameOptions, Type: TypeUniversal},
			{Name: "x-content-type-options", Fn: checkXContentTypeOptions, Type: TypeUniversal},
			{Name: "permissions-policy", Fn: checkPermissionsPolicy, Type: TypeUniversal},
			{Name: "referrer-policy", Fn: checkReferrerPolicy, Type: TypeUniversal},
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
		return Result{GroupHeaders, "csp", "fail", "Content-Security-Policy header missing"}
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
		return Result{GroupHeaders, "csp", "fail",
			"unsafe-inline + unsafe-eval in " + directiveName}
	}

	// WARN: unsafe-inline alone weakens CSP significantly.
	if srcSet["'unsafe-inline'"] {
		return Result{GroupHeaders, "csp", "warn",
			"unsafe-inline in " + directiveName}
	}

	// WARN: wildcard or overly broad sources.
	broadSources := []string{"*", "data:", "blob:", "https:"}
	for _, broad := range broadSources {
		if srcSet[broad] {
			return Result{GroupHeaders, "csp", "warn",
				"wildcard source (" + broad + ") in " + directiveName}
		}
	}

	// WARN: no default-src means the policy has coverage gaps.
	if _, hasDefault := directives["default-src"]; !hasDefault {
		return Result{GroupHeaders, "csp", "warn",
			"no default-src directive (policy has gaps)"}
	}

	return Result{GroupHeaders, "csp", "pass", val}
}

// parseHSTSMaxAge extracts the numeric max-age value from an HSTS header.
// It handles edge cases: quoted values ("31536000"), spaces around '=',
// and case-insensitive matching. Returns the parsed value and true on success,
// or (0, false) if max-age is not present or not a valid integer.
var hstsMaxAgeRe = regexp.MustCompile(`(?i)max-age\s*=\s*"?(\d+)"?`)

func parseHSTSMaxAge(val string) (int64, bool) {
	m := hstsMaxAgeRe.FindStringSubmatch(val)
	if m == nil {
		return 0, false
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// checkHSTS validates the Strict-Transport-Security header per:
//   - RFC 6797 §6.1.1: max-age semantics — a value of 0 instructs the UA to
//     remove the HSTS entry, effectively disabling protection.
//   - RFC 6797 §6.1.2: includeSubDomains — without this directive, subdomain
//     takeover can bypass HSTS for the apex domain.
//
// This predicate asserts: "HSTS max-age must be positive and sufficiently long
// to prevent TLS downgrade between visits."
func checkHSTS(resp *http.Response) Result {
	val := resp.Header.Get("Strict-Transport-Security")
	if val == "" {
		return Result{GroupHeaders, "hsts", "fail", "Strict-Transport-Security header missing"}
	}

	maxAge, ok := parseHSTSMaxAge(val)
	if !ok {
		return Result{GroupHeaders, "hsts", "warn", "HSTS missing max-age directive"}
	}

	// RFC 6797 §6.1.1: max-age=0 tells the browser to delete the HSTS entry.
	if maxAge == 0 {
		return Result{GroupHeaders, "hsts", "fail", "max-age=0 disables HSTS (RFC 6797 §6.1.1)"}
	}

	const minMaxAge int64 = 31536000 // 1 year in seconds

	// Warn if max-age is too short — allows downgrade in the gap.
	if maxAge < minMaxAge {
		return Result{GroupHeaders, "hsts", "warn", fmt.Sprintf("max-age=%d is too short (< %d)", maxAge, minMaxAge)}
	}

	// RFC 6797 §6.1.2: includeSubDomains prevents subdomain takeover bypass.
	if !strings.Contains(strings.ToLower(val), "includesubdomains") {
		return Result{GroupHeaders, "hsts", "warn", "missing includeSubDomains"}
	}

	return Result{GroupHeaders, "hsts", "pass", val}
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
		return Result{GroupHeaders, "samesite", "skip", "no cookies set"}
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

	return Result{GroupHeaders, "samesite", worstStatus, strings.Join(details, "; ")}
}

func checkCORP(resp *http.Response) Result {
	val := resp.Header.Get("Cross-Origin-Resource-Policy")
	if val == "" {
		return Result{GroupHeaders, "corp", "fail", "Cross-Origin-Resource-Policy header missing"}
	}
	return Result{GroupHeaders, "corp", "pass", val}
}

func checkXFrameOptions(resp *http.Response) Result {
	val := resp.Header.Get("X-Frame-Options")
	if val == "" {
		// Fall back: check CSP frame-ancestors directive.
		csp := resp.Header.Get("Content-Security-Policy")
		if csp != "" && strings.Contains(strings.ToLower(csp), "frame-ancestors") {
			return Result{GroupHeaders, "x-frame-options", "pass", "frame-ancestors present in CSP: " + csp}
		}
		return Result{GroupHeaders, "x-frame-options", "fail", "X-Frame-Options header missing and no CSP frame-ancestors directive"}
	}
	upper := strings.ToUpper(val)
	switch upper {
	case "DENY", "SAMEORIGIN":
		return Result{GroupHeaders, "x-frame-options", "pass", val}
	case "ALLOWALL":
		return Result{GroupHeaders, "x-frame-options", "warn", "X-Frame-Options set to ALLOWALL (no protection): " + val}
	default:
		return Result{GroupHeaders, "x-frame-options", "warn", "unrecognized X-Frame-Options value: " + val}
	}
}

func checkXContentTypeOptions(resp *http.Response) Result {
	val := resp.Header.Get("X-Content-Type-Options")
	if val == "" {
		return Result{GroupHeaders, "x-content-type-options", "fail", "X-Content-Type-Options header missing"}
	}
	if strings.ToLower(val) != "nosniff" {
		return Result{GroupHeaders, "x-content-type-options", "warn", "X-Content-Type-Options is not nosniff: " + val}
	}
	return Result{GroupHeaders, "x-content-type-options", "pass", val}
}

func checkPermissionsPolicy(resp *http.Response) Result {
	val := resp.Header.Get("Permissions-Policy")
	if val == "" {
		// Check legacy Feature-Policy header.
		val = resp.Header.Get("Feature-Policy")
		if val != "" {
			return Result{GroupHeaders, "permissions-policy", "pass", "Feature-Policy (legacy): " + val}
		}
		return Result{GroupHeaders, "permissions-policy", "warn", "Permissions-Policy header missing"}
	}
	return Result{GroupHeaders, "permissions-policy", "pass", val}
}

func checkReferrerPolicy(resp *http.Response) Result {
	val := resp.Header.Get("Referrer-Policy")
	if val == "" {
		return Result{GroupHeaders, "referrer-policy", "fail", "Referrer-Policy header missing"}
	}
	safe := map[string]bool{
		"no-referrer":                   true,
		"strict-origin":                 true,
		"strict-origin-when-cross-origin": true,
		"same-origin":                   true,
		"origin":                        true,
		"origin-when-cross-origin":      true,
	}
	lower := strings.ToLower(strings.TrimSpace(val))
	if safe[lower] {
		return Result{GroupHeaders, "referrer-policy", "pass", val}
	}
	if lower == "unsafe-url" {
		return Result{GroupHeaders, "referrer-policy", "warn", "Referrer-Policy unsafe-url leaks full URL to all origins"}
	}
	if lower == "no-referrer-when-downgrade" {
		return Result{GroupHeaders, "referrer-policy", "warn", "Referrer-Policy no-referrer-when-downgrade leaks to HTTPS targets"}
	}
	return Result{GroupHeaders, "referrer-policy", "warn", "unrecognized Referrer-Policy: " + val}
}
