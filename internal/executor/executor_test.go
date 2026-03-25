package executor

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aygp-dr/http-axiom/internal/request"
)

// echoHandler writes back the method, path, and headers as JSON.
func echoHandler(w http.ResponseWriter, r *http.Request) {
	type echo struct {
		Method  string      `json:"method"`
		Path    string      `json:"path"`
		Headers http.Header `json:"headers"`
	}
	resp := echo{
		Method:  r.Method,
		Path:    r.URL.Path,
		Headers: r.Header,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func newTestServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(echoHandler))
}

func TestExecuteSingleGET(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.BaseURL = srv.URL

	req := request.Request{
		Method:  http.MethodGet,
		Path:    "/test",
		Headers: map[string]string{},
	}

	result := Execute(cfg, req)
	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	if result.Response == nil {
		t.Fatal("expected non-nil response")
	}
	if result.Response.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", result.Response.StatusCode)
	}
	if result.Duration <= 0 {
		t.Error("expected positive duration")
	}
	if len(result.Responses) != 1 {
		t.Errorf("expected 1 response, got %d", len(result.Responses))
	}

	// Verify the echo body.
	defer result.Response.Body.Close()
	body, err := io.ReadAll(result.Response.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}
	var echoed struct {
		Method string `json:"method"`
		Path   string `json:"path"`
	}
	if err := json.Unmarshal(body, &echoed); err != nil {
		t.Fatalf("failed to unmarshal echo: %v", err)
	}
	if echoed.Method != "GET" {
		t.Errorf("echoed method = %q, want GET", echoed.Method)
	}
	if echoed.Path != "/test" {
		t.Errorf("echoed path = %q, want /test", echoed.Path)
	}
}

func TestExecutePOSTWithHeaders(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.BaseURL = srv.URL

	req := request.Request{
		Method: http.MethodPost,
		Path:   "/submit",
		Headers: map[string]string{
			"X-Custom":     "hello",
			"Content-Type": "application/json",
		},
	}

	result := Execute(cfg, req)
	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	if result.Response.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", result.Response.StatusCode)
	}

	// Verify headers were sent.
	defer result.Response.Body.Close()
	body, err := io.ReadAll(result.Response.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}
	var echoed struct {
		Method  string      `json:"method"`
		Path    string      `json:"path"`
		Headers http.Header `json:"headers"`
	}
	if err := json.Unmarshal(body, &echoed); err != nil {
		t.Fatalf("failed to unmarshal echo: %v", err)
	}
	if echoed.Method != "POST" {
		t.Errorf("echoed method = %q, want POST", echoed.Method)
	}
	if echoed.Path != "/submit" {
		t.Errorf("echoed path = %q, want /submit", echoed.Path)
	}
	if got := echoed.Headers.Get("X-Custom"); got != "hello" {
		t.Errorf("X-Custom header = %q, want hello", got)
	}
}

func TestExecuteRepeat(t *testing.T) {
	var count int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.BaseURL = srv.URL

	req := request.Request{
		Method:  http.MethodGet,
		Path:    "/repeat",
		Headers: map[string]string{},
		Repeat:  3,
	}

	result := Execute(cfg, req)
	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	if len(result.Responses) != 3 {
		t.Errorf("expected 3 responses, got %d", len(result.Responses))
	}
	if count != 3 {
		t.Errorf("server received %d requests, want 3", count)
	}
	if result.Response == nil {
		t.Fatal("expected non-nil primary response")
	}
}

func TestExecuteTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.BaseURL = srv.URL
	cfg.Timeout = 100 * time.Millisecond

	req := request.Request{
		Method:  http.MethodGet,
		Path:    "/slow",
		Headers: map[string]string{},
	}

	result := Execute(cfg, req)
	if result.Err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

func TestExecuteAuth(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.BaseURL = srv.URL

	tests := []struct {
		name   string
		auth   string
		header string
		prefix string
	}{
		{"bearer", "bearer", "Authorization", "Bearer "},
		{"basic", "basic", "Authorization", "Basic "},
		{"cookie", "cookie", "Cookie", "session="},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := request.Request{
				Method:  http.MethodGet,
				Path:    "/auth",
				Headers: map[string]string{},
				Auth:    tt.auth,
			}

			result := Execute(cfg, req)
			if result.Err != nil {
				t.Fatalf("unexpected error: %v", result.Err)
			}

			defer result.Response.Body.Close()
			body, err := io.ReadAll(result.Response.Body)
			if err != nil {
				t.Fatalf("failed to read body: %v", err)
			}
			var echoed struct {
				Headers http.Header `json:"headers"`
			}
			if err := json.Unmarshal(body, &echoed); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}
			got := echoed.Headers.Get(tt.header)
			if got == "" {
				t.Errorf("expected %s header to be set", tt.header)
			}
		})
	}
}

func TestExecuteOrigin(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.BaseURL = srv.URL

	t.Run("cross-site", func(t *testing.T) {
		req := request.Request{
			Method:  http.MethodGet,
			Path:    "/origin",
			Headers: map[string]string{},
			Origin:  "cross-site",
		}
		result := Execute(cfg, req)
		if result.Err != nil {
			t.Fatalf("unexpected error: %v", result.Err)
		}
		defer result.Response.Body.Close()
		body, _ := io.ReadAll(result.Response.Body)
		var echoed struct {
			Headers http.Header `json:"headers"`
		}
		json.Unmarshal(body, &echoed)
		if got := echoed.Headers.Get("Origin"); got != "https://evil.example.com" {
			t.Errorf("Origin = %q, want https://evil.example.com", got)
		}
	})

	t.Run("same-site", func(t *testing.T) {
		req := request.Request{
			Method:  http.MethodGet,
			Path:    "/origin",
			Headers: map[string]string{},
			Origin:  "same-site",
		}
		result := Execute(cfg, req)
		if result.Err != nil {
			t.Fatalf("unexpected error: %v", result.Err)
		}
		defer result.Response.Body.Close()
		body, _ := io.ReadAll(result.Response.Body)
		var echoed struct {
			Headers http.Header `json:"headers"`
		}
		json.Unmarshal(body, &echoed)
		got := echoed.Headers.Get("Origin")
		if got == "" {
			t.Error("expected Origin header to be set for same-site")
		}
	})
}

func TestExecuteBatch(t *testing.T) {
	srv := newTestServer()
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.BaseURL = srv.URL

	reqs := []request.Request{
		{Method: http.MethodGet, Path: "/a", Headers: map[string]string{}},
		{Method: http.MethodPost, Path: "/b", Headers: map[string]string{}},
		{Method: http.MethodPut, Path: "/c", Headers: map[string]string{}},
	}

	results := ExecuteBatch(cfg, reqs)
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	for i, r := range results {
		if r.Err != nil {
			t.Errorf("result[%d]: unexpected error: %v", i, r.Err)
		}
		if r.Response == nil {
			t.Errorf("result[%d]: expected non-nil response", i)
		}
	}
}
