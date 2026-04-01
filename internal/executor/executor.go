// Package executor converts request.Request values into real HTTP
// requests, sends them, and collects results including timing data.
package executor

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aygp-dr/http-axiom/internal/request"
)

// Config controls how requests are executed.
type Config struct {
	BaseURL      string        // e.g., "http://localhost:9999"
	Timeout      time.Duration // per-request timeout (default 10s)
	Concurrency  int           // for repeat-concurrent (default 1)
	MaxBodySize  int64         // limit response body reads (0 = unlimited)
	MaxRedirects int           // maximum redirects to follow (default 10)
}

// Result captures the outcome of executing a single request.Request.
type Result struct {
	Request   request.Request  // the original request
	Response  *http.Response   // primary response (first for repeats)
	Responses []*http.Response // all responses for repeat-N/concurrent
	Duration  time.Duration    // total execution time
	Err       error            // nil on success
}

// CloseResponses drains and closes ALL response bodies in Responses.
// This satisfies the contract: "Caller MUST close ALL response bodies
// in executor.Result.Responses (not just [0])".
func (r *Result) CloseResponses() {
	for _, resp := range r.Responses {
		if resp != nil && resp.Body != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}
}

// limitedBody wraps an io.LimitReader while preserving the original
// body's Close method. This avoids the io.NopCloser TCP leak: the
// underlying connection is properly returned to the pool on Close.
type limitedBody struct {
	io.Reader
	original io.ReadCloser
}

func (lb *limitedBody) Close() error {
	return lb.original.Close()
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		BaseURL:      "http://localhost:9999",
		Timeout:      10 * time.Second,
		Concurrency:  1,
		MaxBodySize:  10 * 1024 * 1024, // 10 MB
		MaxRedirects: 10,
	}
}

// makeCheckRedirect returns a CheckRedirect function that enforces
// the redirect limit and strips sensitive headers on cross-host
// redirects. Uses len(via) > maxRedirects (not >=) so that
// MaxRedirects=0 means follow zero redirects, MaxRedirects=1 means
// follow exactly one, etc.
//
// On cross-host redirect, Authorization and Cookie headers are
// stripped from the redirected request. Note: custom auth headers
// (e.g. X-Api-Key) are NOT stripped -- this is a known L1 limitation.
func makeCheckRedirect(maxRedirects int) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) > maxRedirects {
			return http.ErrUseLastResponse
		}
		// Strip Authorization and Cookie on cross-host redirect.
		if len(via) > 0 {
			previousHost := via[len(via)-1].URL.Host
			if req.URL.Host != previousHost {
				req.Header.Del("Authorization")
				req.Header.Del("Cookie")
			}
		}
		return nil
	}
}

// NewClient creates an *http.Client from this Config, wiring Timeout
// and the redirect policy. All request execution -- inside the
// executor and in main.go command handlers -- should flow through
// this method so that redirect-limit and timeout policies are never
// accidentally omitted.
func (cfg Config) NewClient() *http.Client {
	return &http.Client{
		Timeout:       cfg.Timeout,
		CheckRedirect: makeCheckRedirect(cfg.MaxRedirects),
	}
}

// Execute sends a single request and returns the result.
func Execute(cfg Config, req request.Request) Result {
	return executeSingle(cfg.NewClient(), cfg, req)
}

// ExecuteBatch sends multiple requests, sharing a single http.Client
// across the batch for connection reuse. When Concurrency > 1,
// requests are executed concurrently with a semaphore limiting
// the number of in-flight goroutines.
func ExecuteBatch(cfg Config, reqs []request.Request) []Result {
	// Share a single client across the batch for connection reuse.
	// The client is created via NewClient so the redirect policy is
	// always enforced; there is no way to bypass it with a pre-built client.
	client := cfg.NewClient()

	results := make([]Result, len(reqs))

	if cfg.Concurrency > 1 {
		sem := make(chan struct{}, cfg.Concurrency)
		var wg sync.WaitGroup
		for i, req := range reqs {
			wg.Add(1)
			sem <- struct{}{}
			go func(idx int, r request.Request) {
				defer wg.Done()
				defer func() { <-sem }()
				results[idx] = executeSingle(client, cfg, r)
			}(i, req)
		}
		wg.Wait()
	} else {
		for i, req := range reqs {
			results[i] = executeSingle(client, cfg, req)
		}
	}

	return results
}

// executeSingle is the internal implementation of Execute that accepts
// a pre-built client. This allows ExecuteBatch to share a single client.
func executeSingle(client *http.Client, cfg Config, req request.Request) Result {
	result := Result{Request: req}

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

// doRequest builds and sends a single HTTP request.
func doRequest(client *http.Client, cfg Config, req request.Request) (*http.Response, error) {
	fullURL := strings.TrimRight(cfg.BaseURL, "/") + req.Path

	var body io.Reader
	if req.Body != "" {
		body = strings.NewReader(req.Body)
	}

	httpReq, err := http.NewRequest(req.Method, fullURL, body)
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

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}

	if cfg.MaxBodySize > 0 && resp.Body != nil {
		resp.Body = &limitedBody{
			Reader:   io.LimitReader(resp.Body, cfg.MaxBodySize),
			original: resp.Body,
		}
	}

	return resp, nil
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
