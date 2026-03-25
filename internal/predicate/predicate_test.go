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
// HSTS predicate tests (hax-uuv)
// ---------------------------------------------------------------------------

func TestCheckHSTS_Missing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	result := checkHSTS(resp)
	if result.Status != "fail" {
		t.Errorf("expected fail, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckHSTS_MaxAgeZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=0")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	result := checkHSTS(resp)
	if result.Status != "fail" {
		t.Errorf("expected fail, got %s: %s", result.Status, result.Detail)
	}
	if result.Detail != "max-age=0 disables HSTS (RFC 6797 §6.1.1)" {
		t.Errorf("unexpected detail: %s", result.Detail)
	}
}

func TestCheckHSTS_MaxAgeShort(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=3600")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	result := checkHSTS(resp)
	if result.Status != "warn" {
		t.Errorf("expected warn, got %s: %s", result.Status, result.Detail)
	}
	if result.Detail != "max-age=3600 is too short (< 31536000)" {
		t.Errorf("unexpected detail: %s", result.Detail)
	}
}

func TestCheckHSTS_NoIncludeSubDomains(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	result := checkHSTS(resp)
	if result.Status != "warn" {
		t.Errorf("expected warn, got %s: %s", result.Status, result.Detail)
	}
	if result.Detail != "missing includeSubDomains" {
		t.Errorf("unexpected detail: %s", result.Detail)
	}
}

func TestCheckHSTS_Full(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	result := checkHSTS(resp)
	if result.Status != "pass" {
		t.Errorf("expected pass, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckHSTS_WithPreload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	result := checkHSTS(resp)
	if result.Status != "pass" {
		t.Errorf("expected pass, got %s: %s", result.Status, result.Detail)
	}
}

func TestParseHSTSMaxAge(t *testing.T) {
	tests := []struct {
		input   string
		wantVal int64
		wantOK  bool
	}{
		{"max-age=31536000", 31536000, true},
		{"max-age=0", 0, true},
		{`max-age="31536000"`, 31536000, true},
		{"max-age = 0", 0, true},
		{"Max-Age=63072000; includeSubDomains; preload", 63072000, true},
		{"includeSubDomains", 0, false},
		{"", 0, false},
	}
	for _, tt := range tests {
		gotVal, gotOK := parseHSTSMaxAge(tt.input)
		if gotVal != tt.wantVal || gotOK != tt.wantOK {
			t.Errorf("parseHSTSMaxAge(%q) = (%d, %v), want (%d, %v)",
				tt.input, gotVal, gotOK, tt.wantVal, tt.wantOK)
		}
	}
}
