package predicate

import "net/http"

// Run executes TypeUniversal predicates in a group against a response.
// Predicates with Type != TypeUniversal are skipped — use RunWithRequest
// or RunMulti for those.
func Run(group Group, resp *http.Response) []Result {
	results := make([]Result, 0, len(group.Predicates))
	for _, p := range group.Predicates {
		if p.Type != TypeUniversal {
			continue
		}
		if p.Fn != nil {
			results = append(results, p.Fn(resp))
		}
	}
	return results
}

// RunWithRequest executes TypeRelational predicates in a group.
// Only predicates with Type == TypeRelational are executed.
func RunWithRequest(group Group, req *http.Request, resp *http.Response) []Result {
	results := make([]Result, 0, len(group.Predicates))
	for _, p := range group.Predicates {
		if p.Type != TypeRelational {
			continue
		}
		if p.ReqFn != nil {
			results = append(results, p.ReqFn(req, resp))
		}
	}
	return results
}

// RunMulti executes TypeSequential predicates in a group.
// Only predicates with Type == TypeSequential are executed.
func RunMulti(group Group, client *http.Client, target string) []Result {
	results := make([]Result, 0, len(group.Predicates))
	for _, p := range group.Predicates {
		if p.Type != TypeSequential {
			continue
		}
		if p.MultiFn != nil {
			results = append(results, p.MultiFn(client, target))
		}
	}
	return results
}

// NeedsMulti reports whether any predicate in the group is TypeSequential.
func NeedsMulti(group Group) bool {
	for _, p := range group.Predicates {
		if p.Type == TypeSequential {
			return true
		}
	}
	return false
}

// NeedsRequest reports whether any predicate in the group is TypeRelational.
func NeedsRequest(group Group) bool {
	for _, p := range group.Predicates {
		if p.Type == TypeRelational {
			return true
		}
	}
	return false
}
