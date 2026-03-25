// Package relevance maps mutation operators to the predicate groups they
// exercise, forming the routing matrix that drives hax run.
package relevance

import (
	"github.com/aygp-dr/http-axiom/internal/mutation"
)

// None is the pseudo-mutation for predicates that need no request mutation
// (single-response header checks).
const None = "none"

// TestCase binds a mutation operator to the predicate groups it exercises,
// with constraints on which HTTP methods and request properties are meaningful.
type TestCase struct {
	Mutation    string   // mutation operator name (from mutation constants)
	Groups      []string // predicate group names this mutation targets
	Methods     []string // HTTP methods relevant to this combination
	NeedsAuth   bool     // whether auth variants matter
	NeedsRepeat int      // 0=single, >0=multi-request with this count
}

// matrix is the static relevance matrix built from the architecture analysis.
var matrix = []TestCase{
	{
		Mutation:    mutation.MethodRotate,
		Groups:      []string{"methods", "cross-origin"},
		Methods:     []string{"GET", "POST", "PUT", "DELETE", "PATCH"},
		NeedsAuth:   false,
		NeedsRepeat: 0,
	},
	{
		Mutation:    mutation.HeaderOmit,
		Groups:      []string{"headers"},
		Methods:     []string{"GET"},
		NeedsAuth:   false,
		NeedsRepeat: 0,
	},
	{
		Mutation:    mutation.HeaderCorrupt,
		Groups:      []string{"headers"},
		Methods:     []string{"GET"},
		NeedsAuth:   false,
		NeedsRepeat: 0,
	},
	{
		Mutation:    mutation.HeaderForge,
		Groups:      []string{"cross-origin", "headers"},
		Methods:     []string{"GET", "POST"},
		NeedsAuth:   false,
		NeedsRepeat: 0,
	},
	{
		Mutation:    mutation.OriginCrossSite,
		Groups:      []string{"cross-origin", "headers"},
		Methods:     []string{"POST", "PUT", "DELETE"},
		NeedsAuth:   false,
		NeedsRepeat: 0,
	},
	{
		Mutation:    mutation.OriginSameSite,
		Groups:      []string{"cross-origin"},
		Methods:     []string{"POST"},
		NeedsAuth:   false,
		NeedsRepeat: 0,
	},
	{
		Mutation:    mutation.RepeatN,
		Groups:      []string{"methods", "state", "cache"},
		Methods:     []string{"GET", "PUT", "DELETE"},
		NeedsAuth:   false,
		NeedsRepeat: 3,
	},
	{
		Mutation:    mutation.RepeatConcurrent,
		Groups:      []string{"state", "methods"},
		Methods:     []string{"POST"},
		NeedsAuth:   false,
		NeedsRepeat: 5,
	},
	{
		Mutation:    None,
		Groups:      []string{"headers", "cache"},
		Methods:     []string{"GET", "HEAD"},
		NeedsAuth:   false,
		NeedsRepeat: 0,
	},
}

// Matrix returns the complete relevance matrix.
// The returned slice is a copy; callers may modify it freely.
func Matrix() []TestCase {
	out := make([]TestCase, len(matrix))
	copy(out, matrix)
	return out
}

// ForGroup returns all TestCases that target a specific predicate group.
func ForGroup(group string) []TestCase {
	var out []TestCase
	for _, tc := range matrix {
		for _, g := range tc.Groups {
			if g == group {
				out = append(out, tc)
				break
			}
		}
	}
	return out
}

// ForMutation returns all TestCases for a specific mutation operator.
func ForMutation(mut string) []TestCase {
	var out []TestCase
	for _, tc := range matrix {
		if tc.Mutation == mut {
			out = append(out, tc)
		}
	}
	return out
}
