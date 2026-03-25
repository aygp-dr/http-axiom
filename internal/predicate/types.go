// Package predicate defines RFC-grounded test conditions grouped into
// five categories: headers, methods, cross-origin, cache, state.
package predicate

import "net/http"

// Predicate type constants classify each named predicate by the shape
// of the function required to evaluate it.
const (
	TypeUniversal  = 1 // func(resp) Result
	TypeRelational = 2 // func(req, resp) Result
	TypeSequential = 3 // func(client, target) Result
)

// Group name constants.
const (
	GroupHeaders     = "headers"
	GroupMethods     = "methods"
	GroupCrossOrigin = "cross-origin"
	GroupCache       = "cache"
	GroupState       = "state"
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
	Type    int                      // TypeUniversal, TypeRelational, or TypeSequential
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
	return []string{GroupHeaders, GroupMethods, GroupCrossOrigin, GroupCache, GroupState}
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
