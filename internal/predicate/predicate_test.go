package predicate

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// helper creates a test server that responds with the given headers.
func newTestServer(headers map[string]string, statusCode int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(statusCode)
	}))
}

// helper fetches a response from a test server.
func getResponse(t *testing.T, ts *httptest.Server) *http.Response {
	t.Helper()
	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("failed to GET %s: %v", ts.URL, err)
	}
	return resp
}

// --- CSP tests ---

func TestCheckCSP_WithHeader(t *testing.T) {
	ts := newTestServer(map[string]string{
		"Content-Security-Policy": "default-src 'self'",
	}, 200)
	defer ts.Close()

	resp := getResponse(t, ts)
	defer resp.Body.Close()
	result := checkCSP(resp)

	if result.Status != "pass" {
		t.Errorf("checkCSP with header: status = %q, want %q", result.Status, "pass")
	}
	if result.Group != "headers" {
		t.Errorf("checkCSP: group = %q, want %q", result.Group, "headers")
	}
}

func TestCheckCSP_WithoutHeader(t *testing.T) {
	ts := newTestServer(nil, 200)
	defer ts.Close()

	resp := getResponse(t, ts)
	defer resp.Body.Close()
	result := checkCSP(resp)

	if result.Status != "fail" {
		t.Errorf("checkCSP without header: status = %q, want %q", result.Status, "fail")
	}
}

// --- HSTS tests ---

func TestCheckHSTS_WithValidHeader(t *testing.T) {
	ts := newTestServer(map[string]string{
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
	}, 200)
	defer ts.Close()

	resp := getResponse(t, ts)
	defer resp.Body.Close()
	result := checkHSTS(resp)

	if result.Status != "pass" {
		t.Errorf("checkHSTS with valid header: status = %q, want %q", result.Status, "pass")
	}
}

func TestCheckHSTS_MissingMaxAge(t *testing.T) {
	ts := newTestServer(map[string]string{
		"Strict-Transport-Security": "includeSubDomains",
	}, 200)
	defer ts.Close()

	resp := getResponse(t, ts)
	defer resp.Body.Close()
	result := checkHSTS(resp)

	if result.Status != "warn" {
		t.Errorf("checkHSTS missing max-age: status = %q, want %q", result.Status, "warn")
	}
}

func TestCheckHSTS_WithoutHeader(t *testing.T) {
	ts := newTestServer(nil, 200)
	defer ts.Close()

	resp := getResponse(t, ts)
	defer resp.Body.Close()
	result := checkHSTS(resp)

	if result.Status != "fail" {
		t.Errorf("checkHSTS without header: status = %q, want %q", result.Status, "fail")
	}
}

// --- CORP tests ---

func TestCheckCORP_WithHeader(t *testing.T) {
	ts := newTestServer(map[string]string{
		"Cross-Origin-Resource-Policy": "same-origin",
	}, 200)
	defer ts.Close()

	resp := getResponse(t, ts)
	defer resp.Body.Close()
	result := checkCORP(resp)

	if result.Status != "pass" {
		t.Errorf("checkCORP with header: status = %q, want %q", result.Status, "pass")
	}
}

func TestCheckCORP_WithoutHeader(t *testing.T) {
	ts := newTestServer(nil, 200)
	defer ts.Close()

	resp := getResponse(t, ts)
	defer resp.Body.Close()
	result := checkCORP(resp)

	if result.Status != "fail" {
		t.Errorf("checkCORP without header: status = %q, want %q", result.Status, "fail")
	}
}

// --- CORS tests ---

func TestCheckCORS_Wildcard(t *testing.T) {
	ts := newTestServer(map[string]string{
		"Access-Control-Allow-Origin": "*",
	}, 200)
	defer ts.Close()

	resp := getResponse(t, ts)
	defer resp.Body.Close()
	result := checkCORS(resp)

	if result.Status != "warn" {
		t.Errorf("checkCORS wildcard: status = %q, want %q", result.Status, "warn")
	}
}

func TestCheckCORS_SpecificOrigin(t *testing.T) {
	ts := newTestServer(map[string]string{
		"Access-Control-Allow-Origin": "https://example.com",
	}, 200)
	defer ts.Close()

	resp := getResponse(t, ts)
	defer resp.Body.Close()
	result := checkCORS(resp)

	if result.Status != "pass" {
		t.Errorf("checkCORS specific origin: status = %q, want %q", result.Status, "pass")
	}
	if result.Detail != "https://example.com" {
		t.Errorf("checkCORS specific origin: detail = %q, want %q", result.Detail, "https://example.com")
	}
}

func TestCheckCORS_NoCORSHeaders(t *testing.T) {
	ts := newTestServer(nil, 200)
	defer ts.Close()

	resp := getResponse(t, ts)
	defer resp.Body.Close()
	result := checkCORS(resp)

	if result.Status != "skip" {
		t.Errorf("checkCORS no headers: status = %q, want %q", result.Status, "skip")
	}
}

// --- AllGroups tests ---

func TestAllGroups_Returns5Groups(t *testing.T) {
	groups := AllGroups()
	if len(groups) != 5 {
		t.Errorf("AllGroups() returned %d groups, want 5", len(groups))
	}

	expected := map[string]bool{
		"headers":      true,
		"methods":      true,
		"cross-origin": true,
		"cache":        true,
		"state":        true,
	}
	for _, g := range groups {
		if !expected[g.Name] {
			t.Errorf("AllGroups() contains unexpected group %q", g.Name)
		}
		delete(expected, g.Name)
	}
	for name := range expected {
		t.Errorf("AllGroups() missing group %q", name)
	}
}

// --- ByName tests ---

func TestByName_ValidNames(t *testing.T) {
	for _, name := range GroupNames() {
		g, ok := ByName(name)
		if !ok {
			t.Errorf("ByName(%q) returned false", name)
		}
		if g.Name != name {
			t.Errorf("ByName(%q).Name = %q", name, g.Name)
		}
		if len(g.Predicates) == 0 {
			t.Errorf("ByName(%q) returned group with no predicates", name)
		}
	}
}

func TestByName_InvalidName(t *testing.T) {
	_, ok := ByName("nonexistent")
	if ok {
		t.Error("ByName(nonexistent) returned true, want false")
	}
}

// --- Run tests ---

func TestRun_HeaderGroup(t *testing.T) {
	ts := newTestServer(map[string]string{
		"Content-Security-Policy":      "default-src 'self'",
		"Strict-Transport-Security":    "max-age=31536000",
		"Cross-Origin-Resource-Policy": "same-origin",
	}, 200)
	defer ts.Close()

	resp := getResponse(t, ts)
	defer resp.Body.Close()

	results := Run(HeaderGroup(), resp)
	if len(results) != 4 {
		t.Fatalf("Run(HeaderGroup) returned %d results, want 4", len(results))
	}

	// CSP, HSTS, CORP should pass; SameSite should skip (no cookies)
	statusMap := map[string]string{}
	for _, r := range results {
		statusMap[r.Name] = r.Status
	}
	if statusMap["csp"] != "pass" {
		t.Errorf("csp: %q, want pass", statusMap["csp"])
	}
	if statusMap["hsts"] != "pass" {
		t.Errorf("hsts: %q, want pass", statusMap["hsts"])
	}
	if statusMap["corp"] != "pass" {
		t.Errorf("corp: %q, want pass", statusMap["corp"])
	}
	if statusMap["samesite"] != "skip" {
		t.Errorf("samesite: %q, want skip", statusMap["samesite"])
	}
}

// --- GroupNames tests ---

func TestGroupNames(t *testing.T) {
	names := GroupNames()
	if len(names) != 5 {
		t.Errorf("GroupNames() returned %d names, want 5", len(names))
	}
}
