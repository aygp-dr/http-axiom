package predicate

import (
	"testing"

	"pgregory.net/rapid"
)

// knownTypeConsistencyExceptions lists predicates where Type tag does
// not match the populated function field. Empty after fixing stubs to
// declare TypeUniversal while they use Fn (not MultiFn).
var knownTypeConsistencyExceptions = map[string]bool{}

// TestProperty_ExactlyOneFunctionFieldSet verifies the structural invariant:
// for every predicate across all groups, exactly one of Fn/ReqFn/MultiFn
// is non-nil.
func TestProperty_ExactlyOneFunctionFieldSet(t *testing.T) {
	// Use rapid.Check as the harness for consistency with the other property
	// tests, even though this is an exhaustive check (no randomness needed).
	rapid.Check(t, func(_ *rapid.T) {
		for _, group := range AllGroups() {
			for _, pred := range group.Predicates {
				nonNilCount := 0
				if pred.Fn != nil {
					nonNilCount++
				}
				if pred.ReqFn != nil {
					nonNilCount++
				}
				if pred.MultiFn != nil {
					nonNilCount++
				}

				if nonNilCount != 1 {
					t.Errorf("%s/%s: expected exactly 1 non-nil function field, got %d (Fn=%v ReqFn=%v MultiFn=%v)",
						group.Name, pred.Name, nonNilCount,
						pred.Fn != nil, pred.ReqFn != nil, pred.MultiFn != nil)
				}
			}
		}
	})
}

// TestProperty_TypeMatchesPopulatedField verifies the type consistency
// invariant: the populated function field must match the Type tag.
//
// TypeUniversal  (1) -> Fn
// TypeRelational (2) -> ReqFn
// TypeSequential (3) -> MultiFn
//
// KNOWN ISSUE: 7 predicates are declared TypeSequential but have Fn set
// (they are stubs returning "skip"). These are listed in
// knownTypeConsistencyExceptions and excluded from the strict check.
// When each stub is promoted to a real MultiFn implementation, remove
// it from the exception list and this test will enforce consistency.
func TestProperty_TypeMatchesPopulatedField(t *testing.T) {
	rapid.Check(t, func(_ *rapid.T) {
		for _, group := range AllGroups() {
			for _, pred := range group.Predicates {
				key := group.Name + "/" + pred.Name

				// Check if this is a known exception.
				if knownTypeConsistencyExceptions[key] {
					// Verify the exception is still an exception
					// (so we notice when stubs get promoted).
					if pred.Type == TypeSequential && pred.Fn != nil && pred.MultiFn == nil {
						// Still a stub -- expected.
						continue
					}
					// The stub was promoted or changed; the exception
					// is stale and should be removed.
					t.Errorf("%s: listed as type consistency exception but no longer matches stub pattern (Type=%d, Fn=%v, MultiFn=%v) -- remove from exceptions",
						key, pred.Type, pred.Fn != nil, pred.MultiFn != nil)
					continue
				}

				// Strict type consistency check.
				switch pred.Type {
				case TypeUniversal:
					if pred.Fn == nil {
						t.Errorf("%s: Type=Universal but Fn is nil", key)
					}
				case TypeRelational:
					if pred.ReqFn == nil {
						t.Errorf("%s: Type=Relational but ReqFn is nil", key)
					}
				case TypeSequential:
					if pred.MultiFn == nil {
						t.Errorf("%s: Type=Sequential but MultiFn is nil", key)
					}
				default:
					t.Errorf("%s: unknown Type=%d", key, pred.Type)
				}
			}
		}
	})
}

// TestProperty_AllGroupsNonEmpty verifies that every group returned by
// AllGroups() has at least one predicate.
func TestProperty_AllGroupsNonEmpty(t *testing.T) {
	rapid.Check(t, func(_ *rapid.T) {
		groups := AllGroups()
		if len(groups) == 0 {
			t.Fatal("AllGroups() returned empty slice")
		}
		for _, group := range groups {
			if len(group.Predicates) == 0 {
				t.Errorf("group %q has no predicates", group.Name)
			}
		}
	})
}

// TestProperty_GroupNamesMatchAllGroups verifies that GroupNames() returns
// exactly the names from AllGroups(), in the same order.
func TestProperty_GroupNamesMatchAllGroups(t *testing.T) {
	rapid.Check(t, func(_ *rapid.T) {
		names := GroupNames()
		groups := AllGroups()

		if len(names) != len(groups) {
			t.Fatalf("GroupNames() returned %d names, AllGroups() returned %d groups",
				len(names), len(groups))
		}

		for i, group := range groups {
			if names[i] != group.Name {
				t.Errorf("GroupNames()[%d]=%q != AllGroups()[%d].Name=%q",
					i, names[i], i, group.Name)
			}
		}
	})
}
