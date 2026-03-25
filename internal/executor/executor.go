// Package executor converts request.Request values into real HTTP
// requests, sends them, and collects results including timing data.
package executor

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aygp-dr/http-axiom/internal/request"
)

// Config controls how requests are executed.
type Config struct {
	BaseURL     string        // e.g., "http://localhost:9999"
	Timeout     time.Duration // per-request timeout (default 10s)
	Concurrency int           // for repeat-concurrent (default 1)
}

// Result captures the outcome of executing a single request.Request.
type Result struct {
	Request   request.Request // the original request
	Response  *http.Response    // primary response (first for repeats)
	Responses []*http.Response  // all responses for repeat-N/concurrent
	Duration  time.Duration     // total execution time
	Err       error             // nil on success
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		BaseURL:     "http://localhost:9999",
		Timeout:     10 * time.Second,
		Concurrency: 1,
	}
}

// Execute sends a single request and returns the result.
func Execute(cfg Config, req request.Request) Result {
	result := Result{Request: req}

	client := &http.Client{
		Timeout: cfg.Timeout,
	}

	count := req.Repeat
	if count < 1 {
		count = 1
	}

	start := time.Now()

	for i := 0; i < count; i++ {
		resp, err := doRequest(client, cfg, req)
		if err != nil {
			result.Err = err
			result.Duration = time.Since(start)
			return result
		}
		result.Responses = append(result.Responses, resp)
	}

	result.Duration = time.Since(start)
	if len(result.Responses) > 0 {
		result.Response = result.Responses[0]
	}

	return result
}

// ExecuteBatch sends multiple requests sequentially.
func ExecuteBatch(cfg Config, reqs []request.Request) []Result {
	results := make([]Result, 0, len(reqs))
	for _, req := range reqs {
		results = append(results, Execute(cfg, req))
	}
	return results
}

// doRequest builds and sends a single HTTP request.
func doRequest(client *http.Client, cfg Config, req request.Request) (*http.Response, error) {
	fullURL := strings.TrimRight(cfg.BaseURL, "/") + req.Path

	httpReq, err := http.NewRequest(req.Method, fullURL, nil)
	if err != nil {
		return nil, err
	}

	// Set custom headers.
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	// Handle auth.
	applyAuth(httpReq, req.Auth)

	// Handle origin.
	applyOrigin(httpReq, cfg.BaseURL, req.Origin)

	return client.Do(httpReq)
}

// applyAuth sets authentication headers based on the auth mode.
func applyAuth(httpReq *http.Request, auth string) {
	switch auth {
	case "bearer":
		httpReq.Header.Set("Authorization", "Bearer test-token")
	case "basic":
		creds := base64.StdEncoding.EncodeToString([]byte("user:pass"))
		httpReq.Header.Set("Authorization", "Basic "+creds)
	case "cookie":
		httpReq.Header.Set("Cookie", "session=test-session-id")
	}
	// "none" or empty: no auth header
}

// applyOrigin sets the Origin header based on the origin mode.
func applyOrigin(httpReq *http.Request, baseURL, origin string) {
	switch origin {
	case "cross-site":
		httpReq.Header.Set("Origin", "https://evil.example.com")
	case "same-site":
		parsed, err := url.Parse(baseURL)
		if err == nil {
			httpReq.Header.Set("Origin", parsed.Scheme+"://"+parsed.Host)
		}
	}
	// "omitted" or empty: no Origin header
}
