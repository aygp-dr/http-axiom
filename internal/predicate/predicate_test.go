package predicate

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckXFrameOptions_Deny(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	result := checkXFrameOptions(resp)
	if result.Status != "pass" {
		t.Errorf("expected pass, got %s: %s", result.Status, result.Detail)
	}
	if result.Detail != "DENY" {
		t.Errorf("expected detail 'DENY', got %q", result.Detail)
	}
}

func TestCheckXFrameOptions_SameOrigin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	result := checkXFrameOptions(resp)
	if result.Status != "pass" {
		t.Errorf("expected pass, got %s: %s", result.Status, result.Detail)
	}
	if result.Detail != "SAMEORIGIN" {
		t.Errorf("expected detail 'SAMEORIGIN', got %q", result.Detail)
	}
}

func TestCheckXFrameOptions_Missing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	result := checkXFrameOptions(resp)
	if result.Status != "fail" {
		t.Errorf("expected fail, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckXFrameOptions_CSPFrameAncestors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'self'")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	result := checkXFrameOptions(resp)
	if result.Status != "pass" {
		t.Errorf("expected pass, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckXFrameOptions_AllowAll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "ALLOWALL")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	result := checkXFrameOptions(resp)
	if result.Status != "warn" {
		t.Errorf("expected warn, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckXFrameOptions_Unrecognized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "ALLOW-FROM https://example.com")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	result := checkXFrameOptions(resp)
	if result.Status != "warn" {
		t.Errorf("expected warn, got %s: %s", result.Status, result.Detail)
	}
}

// ---------------------------------------------------------------------------
// CSP predicate tests (hax-d6k)
// ---------------------------------------------------------------------------

func TestCheckCSP_Missing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	result := checkCSP(resp)
	if result.Status != "fail" {
		t.Errorf("expected fail, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckCSP_StrongPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	result := checkCSP(resp)
	if result.Status != "pass" {
		t.Errorf("expected pass, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckCSP_WeakPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval'")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	result := checkCSP(resp)
	if result.Status != "fail" {
		t.Errorf("expected fail, got %s: %s", result.Status, result.Detail)
	}
	if result.Detail != "unsafe-inline + unsafe-eval in default-src" {
		t.Errorf("unexpected detail: %s", result.Detail)
	}
}

func TestCheckCSP_UnsafeInlineOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "script-src 'self' 'unsafe-inline'")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	result := checkCSP(resp)
	if result.Status != "warn" {
		t.Errorf("expected warn, got %s: %s", result.Status, result.Detail)
	}
	if result.Detail != "unsafe-inline in script-src" {
		t.Errorf("unexpected detail: %s", result.Detail)
	}
}

func TestCheckCSP_WildcardSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src https: 'self'")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	result := checkCSP(resp)
	if result.Status != "warn" {
		t.Errorf("expected warn, got %s: %s", result.Status, result.Detail)
	}
	if result.Detail != "wildcard source (https:) in default-src" {
		t.Errorf("unexpected detail: %s", result.Detail)
	}
}

func TestCheckCSP_NoDefaultSrc(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "script-src 'self'; style-src 'self'")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	result := checkCSP(resp)
	if result.Status != "warn" {
		t.Errorf("expected warn, got %s: %s", result.Status, result.Detail)
	}
	if result.Detail != "no default-src directive (policy has gaps)" {
		t.Errorf("unexpected detail: %s", result.Detail)
	}
}

func TestCheckCSP_GranularStrong(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	result := checkCSP(resp)
	if result.Status != "pass" {
		t.Errorf("expected pass, got %s: %s", result.Status, result.Detail)
	}
}
