package executor

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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

func TestExecuteBatchSharesClient(t *testing.T) {
	var requestCount int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.BaseURL = srv.URL

	// Build 10 requests to send in a batch.
	reqs := make([]request.Request, 10)
	for i := range reqs {
		reqs[i] = request.Request{
			Method:  http.MethodGet,
			Path:    "/shared",
			Headers: map[string]string{},
		}
	}

	// After ExecuteBatch, cfg.Client should have been set internally.
	// We verify the batch completes and all 10 requests hit the server.
	results := ExecuteBatch(cfg, reqs)
	if len(results) != 10 {
		t.Fatalf("expected 10 results, got %d", len(results))
	}
	for i, r := range results {
		if r.Err != nil {
			t.Errorf("result[%d]: unexpected error: %v", i, r.Err)
		}
	}
	got := atomic.LoadInt64(&requestCount)
	if got != 10 {
		t.Errorf("server received %d requests, want 10", got)
	}

	// Verify that a second batch with different config also works.
	// (Client field was removed; the executor always creates its own client.)
	cfg2 := DefaultConfig()
	cfg2.BaseURL = srv.URL
	cfg2.Timeout = 5 * time.Second

	results2 := ExecuteBatch(cfg2, reqs[:2])
	for i, r := range results2 {
		if r.Err != nil {
			t.Errorf("second batch result[%d]: unexpected error: %v", i, r.Err)
		}
	}
}

func TestExecuteBatchConcurrent(t *testing.T) {
	var requestCount int64
	// Track max concurrent requests seen by the server.
	var inflight int64
	var maxInflight int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur := atomic.AddInt64(&inflight, 1)
		// Update max inflight (best-effort, not perfectly atomic but fine for testing).
		for {
			old := atomic.LoadInt64(&maxInflight)
			if cur <= old {
				break
			}
			if atomic.CompareAndSwapInt64(&maxInflight, old, cur) {
				break
			}
		}
		// Small sleep to keep requests overlapping.
		time.Sleep(50 * time.Millisecond)
		atomic.AddInt64(&inflight, -1)
		atomic.AddInt64(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.BaseURL = srv.URL
	cfg.Concurrency = 3

	reqs := make([]request.Request, 9)
	for i := range reqs {
		reqs[i] = request.Request{
			Method:  http.MethodGet,
			Path:    "/concurrent",
			Headers: map[string]string{},
		}
	}

	results := ExecuteBatch(cfg, reqs)
	if len(results) != 9 {
		t.Fatalf("expected 9 results, got %d", len(results))
	}
	for i, r := range results {
		if r.Err != nil {
			t.Errorf("result[%d]: unexpected error: %v", i, r.Err)
		}
		if r.Response == nil {
			t.Errorf("result[%d]: expected non-nil response", i)
		}
	}

	got := atomic.LoadInt64(&requestCount)
	if got != 9 {
		t.Errorf("server received %d requests, want 9", got)
	}

	// With concurrency=3 and 50ms sleep, we expect >1 concurrent request.
	peak := atomic.LoadInt64(&maxInflight)
	if peak < 2 {
		t.Errorf("expected at least 2 concurrent requests, peak was %d", peak)
	}
	if peak > 3 {
		t.Errorf("expected at most 3 concurrent requests (semaphore), peak was %d", peak)
	}
}

// ---------------------------------------------------------------------------
// Body limit tests (P0-2)
// ---------------------------------------------------------------------------

// mockReadCloser records whether Close was called.
type mockReadCloser struct {
	data   *strings.Reader
	closed bool
}

func (m *mockReadCloser) Read(p []byte) (int, error) {
	return m.data.Read(p)
}

func (m *mockReadCloser) Close() error {
	m.closed = true
	return nil
}

func TestLimitedBody_CloseCallsOriginal(t *testing.T) {
	original := &mockReadCloser{data: strings.NewReader("hello world")}
	lb := &limitedBody{
		Reader:   io.LimitReader(original, 5),
		original: original,
	}

	// Read limited bytes.
	buf := make([]byte, 20)
	n, _ := lb.Read(buf)
	if n != 5 {
		t.Errorf("expected to read 5 bytes, got %d", n)
	}

	// Close must delegate to original.
	if err := lb.Close(); err != nil {
		t.Fatalf("unexpected error from Close: %v", err)
	}
	if !original.closed {
		t.Error("Close() did not call original.Close()")
	}
}

func TestExecute_LargeResponseBodyLimited(t *testing.T) {
	// Server returns 8KB of data.
	payload := strings.Repeat("A", 8*1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(payload))
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.BaseURL = srv.URL
	cfg.MaxBodySize = 1024 // limit to 1KB

	req := request.Request{
		Method:  http.MethodGet,
		Path:    "/big",
		Headers: map[string]string{},
	}

	result := Execute(cfg, req)
	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	defer result.CloseResponses()

	body, err := io.ReadAll(result.Response.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}
	if len(body) != 1024 {
		t.Errorf("expected body length 1024, got %d", len(body))
	}
}

func TestExecute_MaxBodySizeZeroNoLimit(t *testing.T) {
	// Server returns 4KB of data.
	payload := strings.Repeat("B", 4*1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(payload))
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.BaseURL = srv.URL
	cfg.MaxBodySize = 0 // unlimited

	req := request.Request{
		Method:  http.MethodGet,
		Path:    "/unlimited",
		Headers: map[string]string{},
	}

	result := Execute(cfg, req)
	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	defer result.CloseResponses()

	body, err := io.ReadAll(result.Response.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}
	if len(body) != 4*1024 {
		t.Errorf("expected body length %d, got %d", 4*1024, len(body))
	}
}

func TestDefaultConfig_MaxBodySize(t *testing.T) {
	cfg := DefaultConfig()
	expectedMaxBodySize := int64(10 * 1024 * 1024)
	if cfg.MaxBodySize != expectedMaxBodySize {
		t.Errorf("DefaultConfig().MaxBodySize = %d, want %d", cfg.MaxBodySize, expectedMaxBodySize)
	}
}

// ---------------------------------------------------------------------------
// Redirect policy tests (P0-3)
// ---------------------------------------------------------------------------

// TestExecute_MaxRedirects0_FollowsZero verifies that MaxRedirects=0
// means zero redirects are followed: a 302 response is returned as-is.
func TestExecute_MaxRedirects0_FollowsZero(t *testing.T) {
	var requestCount int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requestCount, 1)
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/end", http.StatusFound)
		case "/end":
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.BaseURL = srv.URL
	cfg.MaxRedirects = 0

	req := request.Request{
		Method:  http.MethodGet,
		Path:    "/start",
		Headers: map[string]string{},
	}

	result := Execute(cfg, req)
	defer result.CloseResponses()
	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}

	// With MaxRedirects=0, only the initial request should be made.
	got := atomic.LoadInt64(&requestCount)
	if got != 1 {
		t.Errorf("server received %d requests, want 1 (no redirects followed)", got)
	}

	// The response should be the 302, not the final 200.
	if result.Response.StatusCode != http.StatusFound {
		t.Errorf("expected status 302, got %d", result.Response.StatusCode)
	}
}

// TestExecute_MaxRedirects1_FollowsExactlyOne verifies that
// MaxRedirects=1 follows exactly one redirect. Given a chain
// /a -> 302 /b -> 302 /c, we should see 2 requests and get
// /b's 302 response (the redirect from /b to /c is not followed).
func TestExecute_MaxRedirects1_FollowsExactlyOne(t *testing.T) {
	var requestCount int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requestCount, 1)
		switch r.URL.Path {
		case "/a":
			http.Redirect(w, r, "/b", http.StatusFound)
		case "/b":
			http.Redirect(w, r, "/c", http.StatusFound)
		case "/c":
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.BaseURL = srv.URL
	cfg.MaxRedirects = 1

	req := request.Request{
		Method:  http.MethodGet,
		Path:    "/a",
		Headers: map[string]string{},
	}

	result := Execute(cfg, req)
	defer result.CloseResponses()
	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}

	// /a -> /b is followed (1 redirect), /b -> /c is NOT followed.
	got := atomic.LoadInt64(&requestCount)
	if got != 2 {
		t.Errorf("server received %d requests, want 2 (follow exactly 1 redirect)", got)
	}

	// We should get /b's 302 response (the limit was hit before /c).
	if result.Response.StatusCode != http.StatusFound {
		t.Errorf("expected status 302 (from /b), got %d", result.Response.StatusCode)
	}
}

// TestExecute_MaxRedirects0_And_1_Different is a regression test
// proving that MaxRedirects=0 and MaxRedirects=1 produce different
// request counts, catching the off-by-one bug where >= was used
// instead of >.
func TestExecute_MaxRedirects0_And_1_Different(t *testing.T) {
	var requestCount0 int64
	var requestCount1 int64

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/middle", http.StatusFound)
		case "/middle":
			http.Redirect(w, r, "/end", http.StatusFound)
		case "/end":
			w.WriteHeader(http.StatusOK)
		}
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requestCount0, 1)
		handler.ServeHTTP(w, r)
	}))
	defer srv.Close()

	// MaxRedirects=0: only 1 request.
	cfg0 := DefaultConfig()
	cfg0.BaseURL = srv.URL
	cfg0.MaxRedirects = 0

	req := request.Request{
		Method:  http.MethodGet,
		Path:    "/start",
		Headers: map[string]string{},
	}

	result0 := Execute(cfg0, req)
	result0.CloseResponses()

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requestCount1, 1)
		handler.ServeHTTP(w, r)
	}))
	defer srv2.Close()

	// MaxRedirects=1: 2 requests (follows one redirect).
	cfg1 := DefaultConfig()
	cfg1.BaseURL = srv2.URL
	cfg1.MaxRedirects = 1

	result1 := Execute(cfg1, req)
	result1.CloseResponses()

	count0 := atomic.LoadInt64(&requestCount0)
	count1 := atomic.LoadInt64(&requestCount1)

	if count0 == count1 {
		t.Errorf("MaxRedirects=0 and MaxRedirects=1 produced the same request count (%d); off-by-one bug", count0)
	}
	if count0 != 1 {
		t.Errorf("MaxRedirects=0: expected 1 request, got %d", count0)
	}
	if count1 != 2 {
		t.Errorf("MaxRedirects=1: expected 2 requests, got %d", count1)
	}
}

// TestExecute_CrossHostRedirect_StripsAuth verifies that Authorization
// and Cookie headers are stripped when following a redirect to a
// different host.
func TestExecute_CrossHostRedirect_StripsAuth(t *testing.T) {
	// Target server: records headers it receives.
	var receivedAuth string
	var receivedCookie string
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		receivedCookie = r.Header.Get("Cookie")
		w.WriteHeader(http.StatusOK)
	}))
	defer targetSrv.Close()

	// Origin server: redirects to the target server (cross-host).
	originSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetSrv.URL+"/landed", http.StatusFound)
	}))
	defer originSrv.Close()

	cfg := DefaultConfig()
	cfg.BaseURL = originSrv.URL
	cfg.MaxRedirects = 5

	req := request.Request{
		Method: http.MethodGet,
		Path:   "/redirect-me",
		Headers: map[string]string{
			"Authorization": "Bearer secret-token",
			"Cookie":        "session=abc123",
		},
	}

	result := Execute(cfg, req)
	defer result.CloseResponses()
	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}

	if receivedAuth != "" {
		t.Errorf("Authorization header leaked to cross-host redirect: %q", receivedAuth)
	}
	if receivedCookie != "" {
		t.Errorf("Cookie header leaked to cross-host redirect: %q", receivedCookie)
	}
}

// TestExecute_SameHostRedirect_PreservesAuth verifies that
// Authorization and Cookie headers are preserved when following a
// redirect to the same host.
func TestExecute_SameHostRedirect_PreservesAuth(t *testing.T) {
	var receivedAuth string
	var receivedCookie string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/end", http.StatusFound)
		case "/end":
			receivedAuth = r.Header.Get("Authorization")
			receivedCookie = r.Header.Get("Cookie")
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.BaseURL = srv.URL
	cfg.MaxRedirects = 5

	req := request.Request{
		Method: http.MethodGet,
		Path:   "/start",
		Headers: map[string]string{
			"Authorization": "Bearer secret-token",
			"Cookie":        "session=abc123",
		},
	}

	result := Execute(cfg, req)
	defer result.CloseResponses()
	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}

	if receivedAuth != "Bearer secret-token" {
		t.Errorf("Authorization header not preserved on same-host redirect: got %q", receivedAuth)
	}
	if receivedCookie != "session=abc123" {
		t.Errorf("Cookie header not preserved on same-host redirect: got %q", receivedCookie)
	}
}
