package predicate

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// testServer returns an httptest.Server whose state is a counter:
//   - POST increments the counter (not idempotent, not safe)
//   - PUT sets the counter to a fixed value (idempotent)
//   - GET returns the counter (safe — no mutation)
func testServer() *httptest.Server {
	var mu sync.Mutex
	counter := 0

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		switch r.Method {
		case "GET":
			// Safe: read only
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"counter":%d}`, counter)
		case "PUT":
			// Idempotent: always sets counter to 42 regardless of how many times called
			body, _ := io.ReadAll(r.Body)
			_ = body
			counter = 42
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"counter":%d}`, counter)
		case "POST":
			// NOT idempotent: increments each time
			counter++
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"counter":%d}`, counter)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
}

func TestCheckIdempotencyMulti_Pass(t *testing.T) {
	srv := testServer()
	defer srv.Close()

	result := checkIdempotencyMulti(srv.Client(), srv.URL)
	if result.Status != "pass" {
		t.Errorf("expected pass, got %s: %s", result.Status, result.Detail)
	}
	if result.Group != GroupMethods {
		t.Errorf("expected group %q, got %q", GroupMethods, result.Group)
	}
}

func TestCheckSafetyMulti_Pass(t *testing.T) {
	srv := testServer()
	defer srv.Close()

	result := checkSafetyMulti(srv.Client(), srv.URL)
	if result.Status != "pass" {
		t.Errorf("expected pass, got %s: %s", result.Status, result.Detail)
	}
	if result.Group != GroupMethods {
		t.Errorf("expected group %q, got %q", GroupMethods, result.Group)
	}
}

// nonIdempotentServer increments a counter on every PUT, violating idempotency.
func nonIdempotentServer() *httptest.Server {
	var mu sync.Mutex
	counter := 0

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		switch r.Method {
		case "GET":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"counter":%d}`, counter)
		case "PUT":
			// BUG: not idempotent — increments on every call
			counter++
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"counter":%d}`, counter)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
}

func TestCheckIdempotencyMulti_Fail(t *testing.T) {
	srv := nonIdempotentServer()
	defer srv.Close()

	result := checkIdempotencyMulti(srv.Client(), srv.URL)
	if result.Status != "fail" {
		t.Errorf("expected fail for non-idempotent PUT, got %s: %s", result.Status, result.Detail)
	}
}

// unsafeGetServer increments a counter on every GET, violating safety.
func unsafeGetServer() *httptest.Server {
	var mu sync.Mutex
	counter := 0

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		// BUG: GET has side effects — increments counter
		counter++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"counter":%d}`, counter)
	}))
}

func TestCheckSafetyMulti_Fail(t *testing.T) {
	srv := unsafeGetServer()
	defer srv.Close()

	result := checkSafetyMulti(srv.Client(), srv.URL)
	if result.Status != "fail" {
		t.Errorf("expected fail for unsafe GET, got %s: %s", result.Status, result.Detail)
	}
}

// TestRunMulti_MethodGroup verifies that RunMulti dispatches MultiFn predicates.
func TestRunMulti_MethodGroup(t *testing.T) {
	srv := testServer()
	defer srv.Close()

	group := MethodGroup()
	results := RunMulti(group, srv.Client(), srv.URL)

	if len(results) != 2 {
		t.Fatalf("expected 2 multi results (idempotency + safety), got %d", len(results))
	}

	names := map[string]string{}
	for _, r := range results {
		names[r.Name] = r.Status
	}

	if s, ok := names["idempotency"]; !ok || s != "pass" {
		t.Errorf("expected idempotency=pass, got %q", names["idempotency"])
	}
	if s, ok := names["safety"]; !ok || s != "pass" {
		t.Errorf("expected safety=pass, got %q", names["safety"])
	}
}
