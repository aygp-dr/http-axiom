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
		got := MethodRotateMutator(r)
		want := methods[(i+1)%len(methods)]
		if got.Method != want {
			t.Errorf("MethodRotateMutator(%q) = %q, want %q", m, got.Method, want)
		}
	}
}

func TestMethodRotateMutator_UnknownMethod(t *testing.T) {
	r := baseRequest()
	r.Method = "FOOBAR"
	got := MethodRotateMutator(r)
	if got.Method != http.MethodGet {
		t.Errorf("MethodRotateMutator(FOOBAR) = %q, want %q", got.Method, http.MethodGet)
	}
}

func TestHeaderOmitMutator(t *testing.T) {
	r := baseRequest()
	got := HeaderOmitMutator(r)
	if len(got.Headers) != 0 {
		t.Errorf("HeaderOmitMutator: headers not empty, got %d entries", len(got.Headers))
	}
}

func TestHeaderCorruptMutator(t *testing.T) {
	r := baseRequest()
	original := r.Headers["Content-Type"]
	got := HeaderCorruptMutator(r)
	corrupted := got.Headers["Content-Type"]
	if corrupted == original {
		t.Error("HeaderCorruptMutator: value unchanged")
	}
	// The corrupted value should start with \x00\xff
	if corrupted[:2] != "\x00\xff" {
		t.Error("HeaderCorruptMutator: corrupted value does not start with expected bytes")
	}
}

func TestHeaderForgeMutator(t *testing.T) {
	r := baseRequest()
	got := HeaderForgeMutator(r)

	expected := map[string]string{
		"X-Forwarded-For": "127.0.0.1",
		"X-Real-IP":       "127.0.0.1",
		"X-Original-URL":  "/admin",
	}
	for k, want := range expected {
		if v, ok := got.Headers[k]; !ok {
			t.Errorf("HeaderForgeMutator: missing header %q", k)
		} else if v != want {
			t.Errorf("HeaderForgeMutator: header %q = %q, want %q", k, v, want)
		}
	}
}

func TestOriginCrossSiteMutator(t *testing.T) {
	r := baseRequest()
	got := OriginCrossSiteMutator(r)
	if got.Origin != "cross-site" {
		t.Errorf("OriginCrossSiteMutator: Origin = %q, want %q", got.Origin, "cross-site")
	}
	if got.Headers["Origin"] != "https://evil.example.com" {
		t.Errorf("OriginCrossSiteMutator: Origin header = %q, want %q", got.Headers["Origin"], "https://evil.example.com")
	}
}

func TestOriginSameSiteMutator(t *testing.T) {
	r := baseRequest()
	got := OriginSameSiteMutator(r)
	if got.Origin != "same-site" {
		t.Errorf("OriginSameSiteMutator: Origin = %q, want %q", got.Origin, "same-site")
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

func TestGet_RepeatN_NotImplemented(t *testing.T) {
	_, ok := Get(RepeatN)
	if ok {
		t.Error("Get(repeat-N) returned true, want false (not yet implemented)")
	}
}

func TestGet_RepeatConcurrent_NotImplemented(t *testing.T) {
	_, ok := Get(RepeatConcurrent)
	if ok {
		t.Error("Get(repeat-concurrent) returned true, want false (not yet implemented)")
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
