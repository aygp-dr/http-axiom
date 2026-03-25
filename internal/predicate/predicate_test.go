package predicate

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckSameSite_NoCookies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	result := checkSameSite(resp)
	if result.Status != "skip" {
		t.Errorf("expected skip, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckSameSite_MissingAttribute(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "session=abc123; Path=/; HttpOnly")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	result := checkSameSite(resp)
	if result.Status != "warn" {
		t.Errorf("expected warn for missing SameSite, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckSameSite_NoneWithoutSecure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "session=abc123; Path=/; SameSite=None")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	result := checkSameSite(resp)
	if result.Status != "fail" {
		t.Errorf("expected fail for SameSite=None without Secure, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckSameSite_NoneWithSecure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "session=abc123; Path=/; SameSite=None; Secure; HttpOnly")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	result := checkSameSite(resp)
	if result.Status != "pass" {
		t.Errorf("expected pass for SameSite=None with Secure, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckSameSite_Strict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "session=abc123; Path=/; SameSite=Strict; Secure; HttpOnly")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	result := checkSameSite(resp)
	if result.Status != "pass" {
		t.Errorf("expected pass for SameSite=Strict, got %s: %s", result.Status, result.Detail)
	}
	if result.Detail != "session: SameSite=Strict; Secure; HttpOnly" {
		t.Errorf("unexpected detail: %s", result.Detail)
	}
}

func TestCheckSameSite_Lax(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "token=xyz; Path=/; SameSite=Lax")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	result := checkSameSite(resp)
	if result.Status != "pass" {
		t.Errorf("expected pass for SameSite=Lax, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckSameSite_MultipleCookies_MixedFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Good cookie
		w.Header().Add("Set-Cookie", "ok=1; Path=/; SameSite=Strict; Secure; HttpOnly")
		// Bad cookie: SameSite=None without Secure
		w.Header().Add("Set-Cookie", "bad=2; Path=/; SameSite=None")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	result := checkSameSite(resp)
	if result.Status != "fail" {
		t.Errorf("expected fail when any cookie has SameSite=None without Secure, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckSameSite_MultipleCookies_AllGood(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "a=1; SameSite=Strict; Secure; HttpOnly")
		w.Header().Add("Set-Cookie", "b=2; SameSite=Lax; Secure")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	result := checkSameSite(resp)
	if result.Status != "pass" {
		t.Errorf("expected pass for all good cookies, got %s: %s", result.Status, result.Detail)
	}
}

func TestCheckSameSite_NoneWithSecureNoHttpOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "token=abc; SameSite=None; Secure")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	result := checkSameSite(resp)
	if result.Status != "pass" {
		t.Errorf("expected pass for SameSite=None with Secure, got %s: %s", result.Status, result.Detail)
	}
	expected := "token: SameSite=None; Secure (HttpOnly recommended)"
	if result.Detail != expected {
		t.Errorf("expected detail %q, got %q", expected, result.Detail)
	}
}

func TestCheckSameSite_UnrecognizedValue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "sess=1; SameSite=InvalidValue")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	result := checkSameSite(resp)
	if result.Status != "warn" {
		t.Errorf("expected warn for unrecognized SameSite value, got %s: %s", result.Status, result.Detail)
	}
}

// TestParseCookieAttrs is a unit test for the helper function.
func TestParseCookieAttrs(t *testing.T) {
	tests := []struct {
		raw          string
		wantName     string
		wantSS       string
		wantSecure   bool
		wantHTTPOnly bool
		wantHasSS    bool
	}{
		{
			raw:      "session=abc; SameSite=Strict; Secure; HttpOnly",
			wantName: "session", wantSS: "Strict",
			wantSecure: true, wantHTTPOnly: true, wantHasSS: true,
		},
		{
			raw:      "token=xyz; Path=/; SameSite=None",
			wantName: "token", wantSS: "None",
			wantSecure: false, wantHTTPOnly: false, wantHasSS: true,
		},
		{
			raw:      "id=1; Path=/",
			wantName: "id", wantSS: "",
			wantSecure: false, wantHTTPOnly: false, wantHasSS: false,
		},
		{
			raw:      "x=2; samesite=lax; secure; httponly",
			wantName: "x", wantSS: "lax",
			wantSecure: true, wantHTTPOnly: true, wantHasSS: true,
		},
	}

	for _, tc := range tests {
		name, ssVal, secure, httpOnly, hasSS := parseCookieAttrs(tc.raw)
		if name != tc.wantName {
			t.Errorf("parseCookieAttrs(%q): name=%q, want %q", tc.raw, name, tc.wantName)
		}
		if ssVal != tc.wantSS {
			t.Errorf("parseCookieAttrs(%q): sameSiteVal=%q, want %q", tc.raw, ssVal, tc.wantSS)
		}
		if secure != tc.wantSecure {
			t.Errorf("parseCookieAttrs(%q): secure=%v, want %v", tc.raw, secure, tc.wantSecure)
		}
		if httpOnly != tc.wantHTTPOnly {
			t.Errorf("parseCookieAttrs(%q): httpOnly=%v, want %v", tc.raw, httpOnly, tc.wantHTTPOnly)
		}
		if hasSS != tc.wantHasSS {
			t.Errorf("parseCookieAttrs(%q): hasSameSite=%v, want %v", tc.raw, hasSS, tc.wantHasSS)
		}
	}
}
