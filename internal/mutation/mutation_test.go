package mutation

import (
	"net/http"
	"testing"

	"github.com/aygp-dr/http-axiom/internal/generator"
)

func baseRequest() generator.Request {
	return generator.Request{
		Method: http.MethodGet,
		Path:   "/test",
		Headers: map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Bearer token123",
		},
		Auth:   "bearer",
		Origin: "omitted",
	}
}

func TestMethodRotateMutator(t *testing.T) {
	methods := []string{
		http.MethodGet, http.MethodPost, http.MethodPut,
		http.MethodDelete, http.MethodPatch, http.MethodHead,
		http.MethodOptions,
	}

	for i, m := range methods {
		r := baseRequest()
		r.Method = m
		got := methodRotateMutator(r)
		want := methods[(i+1)%len(methods)]
		if got.Method != want {
			t.Errorf("methodRotateMutator(%q) = %q, want %q", m, got.Method, want)
		}
	}
}

func TestMethodRotateMutator_UnknownMethod(t *testing.T) {
	r := baseRequest()
	r.Method = "FOOBAR"
	got := methodRotateMutator(r)
	if got.Method != http.MethodGet {
		t.Errorf("methodRotateMutator(FOOBAR) = %q, want %q", got.Method, http.MethodGet)
	}
}

func TestHeaderOmitMutator(t *testing.T) {
	r := baseRequest()
	got := headerOmitMutator(r)
	if len(got.Headers) != 0 {
		t.Errorf("headerOmitMutator: headers not empty, got %d entries", len(got.Headers))
	}
}

func TestHeaderCorruptMutator(t *testing.T) {
	r := baseRequest()
	original := r.Headers["Content-Type"]
	got := headerCorruptMutator(r)
	corrupted := got.Headers["Content-Type"]
	if corrupted == original {
		t.Error("headerCorruptMutator: value unchanged")
	}
	// The corrupted value should start with \x00\xff
	if corrupted[:2] != "\x00\xff" {
		t.Error("headerCorruptMutator: corrupted value does not start with expected bytes")
	}
}

func TestHeaderForgeMutator(t *testing.T) {
	r := baseRequest()
	got := headerForgeMutator(r)

	expected := map[string]string{
		"X-Forwarded-For": "127.0.0.1",
		"X-Real-IP":       "127.0.0.1",
		"X-Original-URL":  "/admin",
	}
	for k, want := range expected {
		if v, ok := got.Headers[k]; !ok {
			t.Errorf("headerForgeMutator: missing header %q", k)
		} else if v != want {
			t.Errorf("headerForgeMutator: header %q = %q, want %q", k, v, want)
		}
	}
}

func TestOriginCrossSiteMutator(t *testing.T) {
	r := baseRequest()
	got := originCrossSiteMutator(r)
	if got.Origin != "cross-site" {
		t.Errorf("originCrossSiteMutator: Origin = %q, want %q", got.Origin, "cross-site")
	}
	if got.Headers["Origin"] != "https://evil.example.com" {
		t.Errorf("originCrossSiteMutator: Origin header = %q, want %q", got.Headers["Origin"], "https://evil.example.com")
	}
}

func TestOriginSameSiteMutator(t *testing.T) {
	r := baseRequest()
	got := originSameSiteMutator(r)
	if got.Origin != "same-site" {
		t.Errorf("originSameSiteMutator: Origin = %q, want %q", got.Origin, "same-site")
	}
}

func TestGet_ImplementedMutators(t *testing.T) {
	implemented := []string{
		MethodRotate, HeaderOmit, HeaderCorrupt,
		HeaderForge, OriginCrossSite, OriginSameSite,
	}
	for _, name := range implemented {
		fn, ok := Get(name)
		if !ok {
			t.Errorf("Get(%q) returned false, want true", name)
		}
		if fn == nil {
			t.Errorf("Get(%q) returned nil function", name)
		}
	}
}

func TestGet_RepeatN_Implemented(t *testing.T) {
	fn, ok := Get(RepeatN)
	if !ok {
		t.Error("Get(repeat-N) returned false, want true")
	}
	if fn == nil {
		t.Error("Get(repeat-N) returned nil function")
	}
}

func TestGet_RepeatConcurrent_Implemented(t *testing.T) {
	fn, ok := Get(RepeatConcurrent)
	if !ok {
		t.Error("Get(repeat-concurrent) returned false, want true")
	}
	if fn == nil {
		t.Error("Get(repeat-concurrent) returned nil function")
	}
}

func TestRepeatNMutator(t *testing.T) {
	// When Repeat < 2, should be set to 3.
	r := baseRequest()
	r.Repeat = 0
	got := repeatNMutator(r)
	if got.Repeat != 3 {
		t.Errorf("repeatNMutator(Repeat=0) = %d, want 3", got.Repeat)
	}

	// When Repeat == 1, should be set to 3.
	r.Repeat = 1
	got = repeatNMutator(r)
	if got.Repeat != 3 {
		t.Errorf("repeatNMutator(Repeat=1) = %d, want 3", got.Repeat)
	}

	// When Repeat >= 2, should be unchanged.
	r.Repeat = 5
	got = repeatNMutator(r)
	if got.Repeat != 5 {
		t.Errorf("repeatNMutator(Repeat=5) = %d, want 5", got.Repeat)
	}
}

func TestRepeatConcurrentMutator(t *testing.T) {
	// When Repeat < 2, should be set to 5.
	r := baseRequest()
	r.Repeat = 0
	got := repeatConcurrentMutator(r)
	if got.Repeat != 5 {
		t.Errorf("repeatConcurrentMutator(Repeat=0) = %d, want 5", got.Repeat)
	}

	// Should set X-Hax-Concurrent header.
	if got.Headers["X-Hax-Concurrent"] != "true" {
		t.Error("repeatConcurrentMutator: X-Hax-Concurrent header not set")
	}

	// When Repeat >= 2, Repeat should be unchanged.
	r.Repeat = 10
	got = repeatConcurrentMutator(r)
	if got.Repeat != 10 {
		t.Errorf("repeatConcurrentMutator(Repeat=10) = %d, want 10", got.Repeat)
	}
	// Still should set concurrent header.
	if got.Headers["X-Hax-Concurrent"] != "true" {
		t.Error("repeatConcurrentMutator: X-Hax-Concurrent header not set when Repeat >= 2")
	}
}

func TestGet_UnknownOperator(t *testing.T) {
	_, ok := Get("nonexistent")
	if ok {
		t.Error("Get(nonexistent) returned true, want false")
	}
}

func TestApply_ChainsMultipleOperators(t *testing.T) {
	r := baseRequest()
	operators := []string{HeaderForge, OriginCrossSite}
	got := Apply(r, operators)

	// HeaderForge should have added forged headers
	if got.Headers["X-Forwarded-For"] != "127.0.0.1" {
		t.Error("Apply: HeaderForge not applied")
	}
	// OriginCrossSite should have set cross-site origin
	if got.Origin != "cross-site" {
		t.Error("Apply: OriginCrossSite not applied")
	}
	if got.Headers["Origin"] != "https://evil.example.com" {
		t.Error("Apply: OriginCrossSite Origin header not set")
	}
}

func TestApply_SkipsUnknownOperators(t *testing.T) {
	r := baseRequest()
	original := r.Method
	got := Apply(r, []string{"nonexistent", RepeatN})
	if got.Method != original {
		t.Errorf("Apply with unknown operators changed method from %q to %q", original, got.Method)
	}
}

func TestApply_EmptyOperators(t *testing.T) {
	r := baseRequest()
	got := Apply(r, nil)
	if got.Method != r.Method || got.Path != r.Path {
		t.Error("Apply with nil operators changed the request")
	}
}

func TestAllOperators_Returns8Items(t *testing.T) {
	ops := AllOperators()
	if len(ops) != 8 {
		t.Errorf("AllOperators() returned %d items, want 8", len(ops))
	}

	expected := map[string]bool{
		MethodRotate:     true,
		HeaderOmit:       true,
		HeaderCorrupt:    true,
		HeaderForge:      true,
		OriginCrossSite:  true,
		OriginSameSite:   true,
		RepeatN:          true,
		RepeatConcurrent: true,
	}
	for _, op := range ops {
		if !expected[op] {
			t.Errorf("AllOperators() contains unexpected operator %q", op)
		}
	}
}

// TestMutatorDoesNotModifyOriginal verifies that mutators deep-copy
// the Headers map so the caller's original request is never modified.
func TestMutatorDoesNotModifyOriginal(t *testing.T) {
	original := generator.Request{
		Method:  "GET",
		Path:    "/",
		Headers: map[string]string{"Accept": "text/html"},
	}
	// Save a copy of original headers
	originalAccept := original.Headers["Accept"]

	// Apply header-forge mutation
	Apply(original, []string{"header-forge"})

	// Original must be unchanged
	if original.Headers["Accept"] != originalAccept {
		t.Error("mutation modified original request headers")
	}
	if _, exists := original.Headers["X-Forwarded-For"]; exists {
		t.Error("mutation leaked X-Forwarded-For into original")
	}
}

// TestHeaderCorruptDoesNotModifyOriginal verifies header-corrupt
// does not corrupt the caller's original headers map.
func TestHeaderCorruptDoesNotModifyOriginal(t *testing.T) {
	original := generator.Request{
		Method:  "GET",
		Path:    "/",
		Headers: map[string]string{"Accept": "text/html"},
	}
	originalAccept := original.Headers["Accept"]

	Apply(original, []string{"header-corrupt"})

	if original.Headers["Accept"] != originalAccept {
		t.Error("header-corrupt modified original request headers")
	}
}

// TestOriginCrossSiteDoesNotModifyOriginal verifies origin-cross-site
// does not leak an Origin header into the caller's original map.
func TestOriginCrossSiteDoesNotModifyOriginal(t *testing.T) {
	original := generator.Request{
		Method:  "GET",
		Path:    "/",
		Headers: map[string]string{"Accept": "text/html"},
	}

	Apply(original, []string{"origin-cross-site"})

	if _, exists := original.Headers["Origin"]; exists {
		t.Error("origin-cross-site leaked Origin header into original")
	}
}

// TestRepeatConcurrentDoesNotModifyOriginal verifies repeat-concurrent
// does not leak X-Hax-Concurrent into the caller's original map.
func TestRepeatConcurrentDoesNotModifyOriginal(t *testing.T) {
	original := generator.Request{
		Method:  "GET",
		Path:    "/",
		Headers: map[string]string{"Accept": "text/html"},
	}

	Apply(original, []string{"repeat-concurrent"})

	if _, exists := original.Headers["X-Hax-Concurrent"]; exists {
		t.Error("repeat-concurrent leaked X-Hax-Concurrent into original")
	}
}
