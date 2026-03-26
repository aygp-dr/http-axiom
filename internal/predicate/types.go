// Package predicate defines RFC-grounded test conditions grouped into
// five categories: headers, methods, cross-origin, cache, state.
package predicate

import (
	"fmt"
	"net/http"
)

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

// Validate checks the NamedPred invariant: exactly one function field
// is set, and it must match the Type tag.
//
//	TypeUniversal  -> Fn set, ReqFn and MultiFn nil
//	TypeRelational -> ReqFn set, Fn and MultiFn nil
//	TypeSequential -> MultiFn set, Fn and ReqFn nil
func (p NamedPred) Validate() error {
	switch p.Type {
	case TypeUniversal:
		if p.Fn == nil {
			return fmt.Errorf("predicate %q: Type=Universal but Fn is nil", p.Name)
		}
		if p.ReqFn != nil {
			return fmt.Errorf("predicate %q: Type=Universal but ReqFn is set (must be nil)", p.Name)
		}
		if p.MultiFn != nil {
			return fmt.Errorf("predicate %q: Type=Universal but MultiFn is set (must be nil)", p.Name)
		}
	case TypeRelational:
		if p.ReqFn == nil {
			return fmt.Errorf("predicate %q: Type=Relational but ReqFn is nil", p.Name)
		}
		if p.Fn != nil {
			return fmt.Errorf("predicate %q: Type=Relational but Fn is set (must be nil)", p.Name)
		}
		if p.MultiFn != nil {
			return fmt.Errorf("predicate %q: Type=Relational but MultiFn is set (must be nil)", p.Name)
		}
	case TypeSequential:
		if p.MultiFn == nil {
			return fmt.Errorf("predicate %q: Type=Sequential but MultiFn is nil", p.Name)
		}
		if p.Fn != nil {
			return fmt.Errorf("predicate %q: Type=Sequential but Fn is set (must be nil)", p.Name)
		}
		if p.ReqFn != nil {
			return fmt.Errorf("predicate %q: Type=Sequential but ReqFn is set (must be nil)", p.Name)
		}
	default:
		return fmt.Errorf("predicate %q: unknown Type=%d", p.Name, p.Type)
	}
	return nil
}

// ValidateAll checks every predicate in every group returned by AllGroups().
// Returns the first validation error found, or nil if all predicates are valid.
func ValidateAll() error {
	for _, group := range AllGroups() {
		for _, pred := range group.Predicates {
			if err := pred.Validate(); err != nil {
				return fmt.Errorf("group %q: %w", group.Name, err)
			}
		}
	}
	return nil
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
