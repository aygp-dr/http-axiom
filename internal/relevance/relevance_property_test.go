package relevance

import (
	"testing"

	"github.com/aygp-dr/http-axiom/internal/mutation"
	"github.com/aygp-dr/http-axiom/internal/predicate"
	"pgregory.net/rapid"
)

// TestProperty_AllMutationOperatorsCovered verifies that every mutation
// name in mutation.AllOperators() appears in at least one Matrix() entry.
func TestProperty_AllMutationOperatorsCovered(t *testing.T) {
	rapid.Check(t, func(_ *rapid.T) {
		matrixMutations := make(map[string]bool)
		for _, tc := range Matrix() {
			matrixMutations[tc.Mutation] = true
		}

		for _, op := range mutation.AllOperators() {
			if !matrixMutations[op] {
				t.Errorf("mutation operator %q not found in relevance matrix", op)
			}
		}
	})
}

// TestProperty_AllPredicateGroupsCovered verifies that every group name
// in predicate.GroupNames() appears as a target in at least one Matrix() entry.
func TestProperty_AllPredicateGroupsCovered(t *testing.T) {
	rapid.Check(t, func(_ *rapid.T) {
		matrixGroups := make(map[string]bool)
		for _, tc := range Matrix() {
			for _, g := range tc.Groups {
				matrixGroups[g] = true
			}
		}

		for _, groupName := range predicate.GroupNames() {
			if !matrixGroups[groupName] {
				t.Errorf("predicate group %q not targeted by any matrix entry", groupName)
			}
		}
	})
}

// TestProperty_NoneMutationPresent verifies that the "none" pseudo-mutation
// appears in the matrix. This is the entry for predicates that need no
// request mutation (single-response header checks).
func TestProperty_NoneMutationPresent(t *testing.T) {
	rapid.Check(t, func(_ *rapid.T) {
		found := false
		for _, tc := range Matrix() {
			if tc.Mutation == None {
				found = true
				break
			}
		}
		if !found {
			t.Error("pseudo-mutation 'none' not found in relevance matrix")
		}
	})
}

// TestProperty_MatrixEntriesHaveNonEmptyGroups verifies that every matrix
// entry targets at least one predicate group.
func TestProperty_MatrixEntriesHaveNonEmptyGroups(t *testing.T) {
	rapid.Check(t, func(_ *rapid.T) {
		for _, tc := range Matrix() {
			if len(tc.Groups) == 0 {
				t.Errorf("matrix entry for mutation %q has no target groups", tc.Mutation)
			}
		}
	})
}

// TestProperty_MatrixEntriesHaveNonEmptyMethods verifies that every matrix
// entry specifies at least one HTTP method.
func TestProperty_MatrixEntriesHaveNonEmptyMethods(t *testing.T) {
	rapid.Check(t, func(_ *rapid.T) {
		for _, tc := range Matrix() {
			if len(tc.Methods) == 0 {
				t.Errorf("matrix entry for mutation %q has no methods", tc.Mutation)
			}
		}
	})
}
