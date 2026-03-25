package predicate

import "net/http"

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
