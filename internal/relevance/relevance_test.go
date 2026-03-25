package relevance

import (
	"testing"

	"github.com/aygp-dr/http-axiom/internal/mutation"
)

func TestMatrixCount(t *testing.T) {
	m := Matrix()
	// 8 mutation operators + 1 "none" entry = 9
	if got := len(m); got != 9 {
		t.Errorf("Matrix() returned %d entries, want 9", got)
	}
}

func TestMatrixIsCopy(t *testing.T) {
	a := Matrix()
	b := Matrix()
	a[0].Mutation = "tampered"
	if b[0].Mutation == "tampered" {
		t.Error("Matrix() should return a copy, not a shared slice")
	}
}

func TestForGroupHeaders(t *testing.T) {
	cases := ForGroup("headers")
	want := map[string]bool{
		mutation.HeaderOmit:      true,
		mutation.HeaderCorrupt:   true,
		mutation.HeaderForge:     true,
		mutation.OriginCrossSite: true,
		None:                     true,
	}
	got := make(map[string]bool)
	for _, tc := range cases {
		got[tc.Mutation] = true
	}
	for m := range want {
		if !got[m] {
			t.Errorf("ForGroup(\"headers\") missing mutation %q", m)
		}
	}
}

func TestForGroupState(t *testing.T) {
	cases := ForGroup("state")
	want := map[string]bool{
		mutation.RepeatN:          true,
		mutation.RepeatConcurrent: true,
	}
	got := make(map[string]bool)
	for _, tc := range cases {
		got[tc.Mutation] = true
	}
	for m := range want {
		if !got[m] {
			t.Errorf("ForGroup(\"state\") missing mutation %q", m)
		}
	}
	if len(cases) != len(want) {
		t.Errorf("ForGroup(\"state\") returned %d entries, want %d", len(cases), len(want))
	}
}

func TestForMutationMethodRotate(t *testing.T) {
	cases := ForMutation(mutation.MethodRotate)
	if len(cases) != 1 {
		t.Fatalf("ForMutation(%q) returned %d entries, want 1", mutation.MethodRotate, len(cases))
	}
	tc := cases[0]
	wantGroups := []string{"methods", "cross-origin"}
	if len(tc.Groups) != len(wantGroups) {
		t.Fatalf("groups length %d, want %d", len(tc.Groups), len(wantGroups))
	}
	for i, g := range wantGroups {
		if tc.Groups[i] != g {
			t.Errorf("groups[%d] = %q, want %q", i, tc.Groups[i], g)
		}
	}
}

func TestForMutationUnknown(t *testing.T) {
	cases := ForMutation("nonexistent-operator")
	if len(cases) != 0 {
		t.Errorf("ForMutation(\"nonexistent-operator\") returned %d entries, want 0", len(cases))
	}
}

func TestForGroupUnknown(t *testing.T) {
	cases := ForGroup("nonexistent-group")
	if len(cases) != 0 {
		t.Errorf("ForGroup(\"nonexistent-group\") returned %d entries, want 0", len(cases))
	}
}

func TestNoEmptyGroups(t *testing.T) {
	for _, tc := range Matrix() {
		if len(tc.Groups) == 0 {
			t.Errorf("TestCase for mutation %q has empty Groups slice", tc.Mutation)
		}
	}
}

func TestNoEmptyMethods(t *testing.T) {
	for _, tc := range Matrix() {
		if len(tc.Methods) == 0 {
			t.Errorf("TestCase for mutation %q has empty Methods slice", tc.Mutation)
		}
	}
}
