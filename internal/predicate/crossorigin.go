package predicate

import (
	"net/http"
	"strings"
)

// CrossOriginGroup returns the cross-origin security predicate group.
func CrossOriginGroup() Group {
	return Group{
		Name: GroupCrossOrigin,
		Predicates: []NamedPred{
			{Name: "csrf", Fn: checkCSRF, Type: TypeSequential},
			{Name: "cors", Fn: checkCORS, Type: TypeUniversal},
			{Name: "cors-reflection", ReqFn: checkCORSReflection, Type: TypeRelational},
			{Name: "jsonp", Fn: checkJSONP, Type: TypeSequential},
			{Name: "redirect", Fn: checkRedirect, Type: TypeUniversal},
		},
	}
}

func checkCSRF(_ *http.Response) Result {
	return Result{GroupCrossOrigin, "csrf", "skip", "requires stateful test"}
}

func checkCORS(resp *http.Response) Result {
	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := strings.ToLower(resp.Header.Get("Access-Control-Allow-Credentials"))

	// "null" origin allows sandboxed iframe access — always a misconfiguration.
	if acao == "null" {
		return Result{GroupCrossOrigin, "cors", "fail", "CORS allows null origin (sandboxed iframe bypass)"}
	}

	if acao == "*" {
		// Browsers reject wildcard + credentials, but the server's intent
		// to allow credentialed cross-origin access is still dangerous.
		if acac == "true" {
			return Result{GroupCrossOrigin, "cors", "fail",
				"wildcard CORS origin with Access-Control-Allow-Credentials: true (misconfigured — browsers reject, but intent is dangerous)"}
		}
		return Result{GroupCrossOrigin, "cors", "warn", "wildcard CORS origin"}
	}

	if acao != "" {
		return Result{GroupCrossOrigin, "cors", "pass", acao}
	}
	return Result{GroupCrossOrigin, "cors", "skip", "no CORS headers present"}
}

// checkCORSReflection is a RequestResponsePredicate that detects the most
// dangerous CORS misconfiguration: reflecting the request Origin verbatim
// into Access-Control-Allow-Origin. When the mutation operator
// "origin-cross-site" sets Origin: https://evil.example.com and the server
// echoes it back, any site can read the response — with credentials if
// Access-Control-Allow-Credentials: true is also set.
//
// Security invariant: "The server must not echo an attacker-controlled Origin
// into Access-Control-Allow-Origin."
func checkCORSReflection(req *http.Request, resp *http.Response) Result {
	sentOrigin := req.Header.Get("Origin")
	if sentOrigin == "" {
		return Result{GroupCrossOrigin, "cors-reflection", "skip", "no Origin header in request"}
	}

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	if acao == "" {
		return Result{GroupCrossOrigin, "cors-reflection", "pass", "no ACAO header in response"}
	}

	if acao != sentOrigin {
		return Result{GroupCrossOrigin, "cors-reflection", "pass",
			"ACAO does not reflect sent Origin"}
	}

	// Origin was reflected. Check for credentialed reflection (critical).
	acac := strings.ToLower(resp.Header.Get("Access-Control-Allow-Credentials"))
	if acac == "true" {
		return Result{GroupCrossOrigin, "cors-reflection", "fail",
			"origin reflection with credentials: sent " + sentOrigin + ", reflected in ACAO with Access-Control-Allow-Credentials: true (critical — any site can read credentialed responses)"}
	}

	return Result{GroupCrossOrigin, "cors-reflection", "fail",
		"origin reflection: sent " + sentOrigin + ", reflected verbatim in Access-Control-Allow-Origin (any site can read response)"}
}

func checkJSONP(_ *http.Response) Result {
	return Result{GroupCrossOrigin, "jsonp", "skip", "requires callback parameter test"}
}

func checkRedirect(resp *http.Response) Result {
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := resp.Header.Get("Location")
		if strings.HasPrefix(loc, "http://") {
			return Result{GroupCrossOrigin, "redirect", "warn", "redirect to insecure HTTP: " + loc}
		}
		return Result{GroupCrossOrigin, "redirect", "pass", "redirect to: " + loc}
	}
	return Result{GroupCrossOrigin, "redirect", "skip", "no redirect"}
}
