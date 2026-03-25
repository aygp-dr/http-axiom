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
// CORS predicate tests
// ---------------------------------------------------------------------------

func TestCheckCORS_NullOrigin(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"Access-Control-Allow-Origin": []string{"null"},
		},
	}
	result := checkCORS(resp)
	if result.Status != "fail" {
		t.Errorf("expected fail for null origin, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckCORS_WildcardWithCredentials(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"Access-Control-Allow-Origin":      []string{"*"},
			"Access-Control-Allow-Credentials": []string{"true"},
		},
	}
	result := checkCORS(resp)
	if result.Status != "fail" {
		t.Errorf("expected fail for wildcard+credentials, got %s: %s", result.Status, result.Detail)
	}
}

// ---------------------------------------------------------------------------
// CORS reflection predicate tests (RequestResponsePredicate)
// ---------------------------------------------------------------------------

func TestCheckCORSReflection_Reflected(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://target.example.com/api", nil)
	req.Header.Set("Origin", "https://evil.example.com")

	resp := &http.Response{
		Header: http.Header{
			"Access-Control-Allow-Origin": []string{"https://evil.example.com"},
		},
	}

	result := checkCORSReflection(req, resp)
	if result.Status != "fail" {
		t.Errorf("expected fail for reflected origin, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckCORSReflection_ReflectedWithCredentials(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://target.example.com/api", nil)
	req.Header.Set("Origin", "https://evil.example.com")

	resp := &http.Response{
		Header: http.Header{
			"Access-Control-Allow-Origin":      []string{"https://evil.example.com"},
			"Access-Control-Allow-Credentials": []string{"true"},
		},
	}

	result := checkCORSReflection(req, resp)
	if result.Status != "fail" {
		t.Errorf("expected fail for reflected origin with credentials, got %s: %s", result.Status, result.Detail)
	}
	if result.Detail == "" || !contains(result.Detail, "credentials") {
		t.Errorf("expected detail to mention credentials, got %q", result.Detail)
	}
}

func TestCheckCORSReflection_NotReflected(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://target.example.com/api", nil)
	req.Header.Set("Origin", "https://evil.example.com")

	resp := &http.Response{
		Header: http.Header{
			"Access-Control-Allow-Origin": []string{"https://trusted.example.com"},
		},
	}

	result := checkCORSReflection(req, resp)
	if result.Status != "pass" {
		t.Errorf("expected pass for non-reflected origin, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckCORSReflection_NoOriginSent(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://target.example.com/api", nil)
	// No Origin header set

	resp := &http.Response{
		Header: http.Header{
			"Access-Control-Allow-Origin": []string{"*"},
		},
	}

	result := checkCORSReflection(req, resp)
	if result.Status != "skip" {
		t.Errorf("expected skip when no Origin sent, got %s: %s", result.Status, result.Detail)
	}
}

// contains is a test helper for substring matching.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Referrer-Policy predicate tests
// ---------------------------------------------------------------------------

func TestCheckReferrerPolicy_Missing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	result := checkReferrerPolicy(resp)
	if result.Status != "fail" {
		t.Errorf("expected fail, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckReferrerPolicy_StrictOrigin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Referrer-Policy", "strict-origin")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	result := checkReferrerPolicy(resp)
	if result.Status != "pass" {
		t.Errorf("expected pass, got %s: %s", result.Status, result.Detail)
	}
	if result.Detail != "strict-origin" {
		t.Errorf("expected detail 'strict-origin', got %q", result.Detail)
	}
}

func TestCheckReferrerPolicy_UnsafeURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Referrer-Policy", "unsafe-url")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	result := checkReferrerPolicy(resp)
	if result.Status != "warn" {
		t.Errorf("expected warn, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckReferrerPolicy_NoReferrer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	result := checkReferrerPolicy(resp)
	if result.Status != "pass" {
		t.Errorf("expected pass, got %s: %s", result.Status, result.Detail)
	}
	if result.Detail != "no-referrer" {
		t.Errorf("expected detail 'no-referrer', got %q", result.Detail)
	}
}

func TestCheckReferrerPolicy_NoReferrerWhenDowngrade(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Referrer-Policy", "no-referrer-when-downgrade")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	result := checkReferrerPolicy(resp)
	if result.Status != "warn" {
		t.Errorf("expected warn, got %s: %s", result.Status, result.Detail)
	}
}
