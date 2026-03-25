// haxgoat is a deliberately vulnerable HTTP server for testing hax.
//
// Every predicate group in hax has at least one endpoint that should
// trigger a finding. Run it, then point hax at it:
//
//	go run ./cmd/haxgoat &
//	./hax audit http://localhost:9999
//	./hax audit http://localhost:9999/api/transfer
//	./hax --json audit http://localhost:9999
//
// Vulnerabilities are tagged with the predicate they exercise.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

func main() {
	addr := ":9999"
	if p := os.Getenv("PORT"); p != "" {
		addr = ":" + p
	}

	mux := http.NewServeMux()

	// ---------------------------------------------------------------
	// Root: missing all security headers (headers group)
	// Triggers: csp=FAIL, hsts=FAIL, corp=FAIL
	// ---------------------------------------------------------------
	mux.HandleFunc("/", handleRoot)

	// ---------------------------------------------------------------
	// /secure: properly configured endpoint (headers group)
	// Should pass all header predicates.
	// ---------------------------------------------------------------
	mux.HandleFunc("/secure", handleSecure)

	// ---------------------------------------------------------------
	// /api/user: wildcard CORS (cross-origin group)
	// Triggers: cors=WARN (wildcard origin)
	// ---------------------------------------------------------------
	mux.HandleFunc("/api/user", handleAPIUser)

	// ---------------------------------------------------------------
	// /api/transfer: state-changing endpoint with no CSRF protection
	// Triggers: cors=WARN, csrf-relevant, samesite=WARN
	// Accepts any Origin, sets cookie without SameSite.
	// ---------------------------------------------------------------
	mux.HandleFunc("/api/transfer", handleTransfer)

	// ---------------------------------------------------------------
	// /api/data: non-idempotent GET (methods group)
	// Triggers: safety (GET has side effects — increments counter)
	// ---------------------------------------------------------------
	mux.HandleFunc("/api/data", handleData)

	// ---------------------------------------------------------------
	// /api/delete: DELETE is not idempotent (methods group)
	// Triggers: idempotency (returns different results on repeat)
	// ---------------------------------------------------------------
	mux.HandleFunc("/api/delete", handleDelete)

	// ---------------------------------------------------------------
	// /redirect-http: redirects to HTTP (cross-origin group)
	// Triggers: redirect=WARN (downgrade to insecure)
	// ---------------------------------------------------------------
	mux.HandleFunc("/redirect-http", handleRedirectHTTP)

	// ---------------------------------------------------------------
	// /redirect-ok: redirects to HTTPS (should pass)
	// ---------------------------------------------------------------
	mux.HandleFunc("/redirect-ok", handleRedirectOK)

	// ---------------------------------------------------------------
	// /cached: no cache headers at all (cache group)
	// Triggers: cache-control=WARN, etag=SKIP
	// ---------------------------------------------------------------
	mux.HandleFunc("/cached", handleCached)

	// ---------------------------------------------------------------
	// /cached-ok: proper cache headers (cache group)
	// Should pass: ETag, Cache-Control, Vary
	// ---------------------------------------------------------------
	mux.HandleFunc("/cached-ok", handleCachedOK)

	// ---------------------------------------------------------------
	// /api/replay: accepts replayed requests (state group)
	// No nonce/token checking — same request accepted twice.
	// ---------------------------------------------------------------
	mux.HandleFunc("/api/replay", handleReplay)

	// ---------------------------------------------------------------
	// /api/workflow: multi-step workflow (state group)
	// Steps can be skipped — no sequence enforcement.
	// ---------------------------------------------------------------
	mux.HandleFunc("/api/workflow/step1", handleWorkflowStep1)
	mux.HandleFunc("/api/workflow/step2", handleWorkflowStep2)
	mux.HandleFunc("/api/workflow/step3", handleWorkflowStep3)

	// ---------------------------------------------------------------
	// /api/race: TOCTOU-vulnerable endpoint (state group)
	// Check-then-act with no locking.
	// ---------------------------------------------------------------
	mux.HandleFunc("/api/race", handleRace)

	// ---------------------------------------------------------------
	// /headers: reflects request headers (mutation testing)
	// Useful for testing header-forge, header-corrupt mutations.
	// ---------------------------------------------------------------
	mux.HandleFunc("/headers", handleHeaderEcho)

	// ---------------------------------------------------------------
	// /health: health check
	// ---------------------------------------------------------------
	mux.HandleFunc("/health", handleHealth)

	// ---------------------------------------------------------------
	// /manifest: lists all endpoints and their intended vulns
	// ---------------------------------------------------------------
	mux.HandleFunc("/manifest", handleManifest)

	fmt.Printf("haxgoat listening on %s\n", addr)
	fmt.Println("Deliberately vulnerable — DO NOT expose to the internet.")
	fmt.Println()
	fmt.Println("Endpoints:")
	fmt.Println("  /                     Missing all security headers")
	fmt.Println("  /secure               Properly configured")
	fmt.Println("  /api/user             Wildcard CORS")
	fmt.Println("  /api/transfer         No CSRF, cookie without SameSite")
	fmt.Println("  /api/data             GET with side effects")
	fmt.Println("  /api/delete           Non-idempotent DELETE")
	fmt.Println("  /redirect-http        Redirect to HTTP (downgrade)")
	fmt.Println("  /redirect-ok          Redirect to HTTPS (safe)")
	fmt.Println("  /cached               No cache headers")
	fmt.Println("  /cached-ok            Proper cache headers")
	fmt.Println("  /api/replay           Accepts replayed requests")
	fmt.Println("  /api/workflow/step*   Skippable workflow steps")
	fmt.Println("  /api/race             TOCTOU-vulnerable")
	fmt.Println("  /headers              Reflects request headers")
	fmt.Println("  /health               Health check")
	fmt.Println("  /manifest             JSON endpoint manifest")
	log.Fatal(http.ListenAndServe(addr, mux))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// handleRoot: no security headers at all.
func handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `<!DOCTYPE html>
<html><head><title>haxgoat</title></head>
<body>
<h1>haxgoat</h1>
<p>Deliberately vulnerable HTTP server for testing
<a href="https://github.com/aygp-dr/http-axiom">hax</a>.</p>
<p>See <a href="/manifest">/manifest</a> for all endpoints.</p>
</body></html>`)
}

// handleSecure: all security headers set correctly.
func handleSecure(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "secure-token",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
		"note":   "This endpoint has all security headers configured correctly.",
	})
}

// handleAPIUser: wildcard CORS — allows any origin.
// Vuln: cors predicate should WARN.
func handleAPIUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	json.NewEncoder(w).Encode(map[string]any{
		"id":    42,
		"name":  "Alice",
		"email": "alice@example.com",
		"role":  "admin",
	})
}

// handleTransfer: state-changing endpoint with no CSRF protection.
// Vuln: accepts POST from any origin, cookie has no SameSite.
func handleTransfer(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	// Set cookie WITHOUT SameSite attribute.
	http.SetCookie(w, &http.Cookie{
		Name:  "session",
		Value: "weak-token-" + strconv.Itoa(rand.Intn(9999)),
		Path:  "/",
	})

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(map[string]string{
			"balance": "$10,000",
		})
	case http.MethodPost:
		// Accepts transfer without any CSRF token check.
		to := r.FormValue("to")
		amount := r.FormValue("amount")
		if to == "" {
			to = "unknown"
		}
		if amount == "" {
			amount = "0"
		}
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "transferred",
			"to":      to,
			"amount":  amount,
			"warning": "No CSRF protection — this is deliberately vulnerable",
		})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
	}
}

// handleData: GET has side effects (increments counter).
// Vuln: safety predicate — GET should be safe (no side effects).
var dataCounter int
var dataMu sync.Mutex

func handleData(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	dataMu.Lock()
	dataCounter++ // Side effect on every request including GET!
	count := dataCounter
	dataMu.Unlock()

	json.NewEncoder(w).Encode(map[string]any{
		"count":   count,
		"method":  r.Method,
		"warning": "GET has side effects — counter incremented",
	})
}

// handleDelete: non-idempotent DELETE.
// Vuln: idempotency predicate — same DELETE returns different results.
var items = map[string]bool{"item-1": true, "item-2": true, "item-3": true}
var itemsMu sync.Mutex

func handleDelete(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := r.URL.Query().Get("id")
	if id == "" {
		id = "item-1"
	}

	if r.Method != http.MethodDelete {
		json.NewEncoder(w).Encode(map[string]any{"items": items})
		return
	}

	itemsMu.Lock()
	existed := items[id]
	delete(items, id)
	itemsMu.Unlock()

	if existed {
		// First DELETE: 200 with body
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "deleted",
			"id":      id,
			"warning": "Non-idempotent: second DELETE returns 404",
		})
	} else {
		// Second DELETE: 404 — violates idempotency
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "not found",
			"id":    id,
		})
	}
}

// handleRedirectHTTP: redirects to insecure HTTP.
// Vuln: redirect predicate — downgrade to HTTP.
func handleRedirectHTTP(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "http://example.com/insecure", http.StatusFound)
}

// handleRedirectOK: redirects to HTTPS (safe).
func handleRedirectOK(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://example.com/secure", http.StatusFound)
}

// handleCached: no cache headers at all.
// Vuln: cache-control=WARN, etag=SKIP.
func handleCached(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"data":    "sensitive financial report",
		"warning": "No Cache-Control, no ETag, no Vary — may be cached by intermediaries",
	})
}

// handleCachedOK: correct cache headers.
func handleCachedOK(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("ETag", `"abc123"`)
	w.Header().Set("Vary", "Accept, Authorization")

	// Support conditional GET.
	if r.Header.Get("If-None-Match") == `"abc123"` {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"data": "properly cached content",
	})
}

// handleReplay: accepts identical requests without nonce/token.
// Vuln: replay predicate — no protection against replay attacks.
func handleReplay(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodPost {
		// Accepts the same request body repeatedly with no idempotency key.
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "processed",
			"time":    time.Now().Format(time.RFC3339),
			"warning": "No idempotency key or nonce — replay accepted",
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"endpoint": "/api/replay",
		"method":   "POST to submit",
	})
}

// Workflow: steps can be executed out of order.
// Vuln: workflow-skip predicate.

func handleWorkflowStep1(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"step": "1", "status": "completed", "next": "/api/workflow/step2",
	})
}

func handleWorkflowStep2(w http.ResponseWriter, r *http.Request) {
	// Does NOT check that step1 was completed first.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"step": "2", "status": "completed", "next": "/api/workflow/step3",
		"warning": "No check that step1 was completed — workflow skip possible",
	})
}

func handleWorkflowStep3(w http.ResponseWriter, r *http.Request) {
	// Does NOT check that step1 and step2 were completed.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"step": "3", "status": "completed", "result": "payment processed",
		"warning": "No check that step1/step2 were completed — workflow skip possible",
	})
}

// handleRace: TOCTOU-vulnerable check-then-act.
// Vuln: toctou predicate — concurrent requests can race.
var balance = 1000
var balanceMu sync.Mutex

func handleRace(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodPost {
		amountStr := r.FormValue("amount")
		amount := 100
		if amountStr != "" {
			fmt.Sscanf(amountStr, "%d", &amount)
		}

		// TOCTOU: read balance, sleep (simulate work), then deduct.
		// Concurrent requests can both read the same balance.
		balanceMu.Lock()
		current := balance
		balanceMu.Unlock()

		if current < amount {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "insufficient funds",
				"balance": strconv.Itoa(current),
			})
			return
		}

		// Simulate work between check and act.
		time.Sleep(50 * time.Millisecond)

		balanceMu.Lock()
		balance -= amount
		result := balance
		balanceMu.Unlock()

		json.NewEncoder(w).Encode(map[string]any{
			"status":  "withdrawn",
			"amount":  amount,
			"balance": result,
			"warning": "TOCTOU: check-then-act with no atomic operation",
		})
		return
	}

	balanceMu.Lock()
	current := balance
	balanceMu.Unlock()

	json.NewEncoder(w).Encode(map[string]any{
		"balance": current,
		"note":    "POST with amount= to withdraw",
	})
}

// handleHeaderEcho: reflects all request headers in response.
// Useful for testing header-forge and header-corrupt mutations.
func handleHeaderEcho(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	headers := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}
	json.NewEncoder(w).Encode(map[string]any{
		"method":  r.Method,
		"path":    r.URL.Path,
		"headers": headers,
	})
}

// handleHealth: simple health check.
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleManifest: machine-readable list of endpoints and vulns.
func handleManifest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	type endpoint struct {
		Path       string   `json:"path"`
		Methods    []string `json:"methods"`
		Group      string   `json:"predicate_group"`
		Predicates []string `json:"predicates"`
		Expected   string   `json:"expected_result"`
		Note       string   `json:"note"`
	}

	manifest := []endpoint{
		{"/", []string{"GET"}, "headers", []string{"csp", "hsts", "corp"}, "fail", "No security headers"},
		{"/secure", []string{"GET"}, "headers", []string{"csp", "hsts", "corp", "samesite"}, "pass", "All headers configured"},
		{"/api/user", []string{"GET", "OPTIONS"}, "cross-origin", []string{"cors"}, "warn", "Wildcard CORS origin"},
		{"/api/transfer", []string{"GET", "POST"}, "cross-origin", []string{"cors", "samesite"}, "warn/fail", "No CSRF, no SameSite cookie"},
		{"/api/data", []string{"GET"}, "methods", []string{"safety"}, "fail", "GET has side effects"},
		{"/api/delete", []string{"DELETE"}, "methods", []string{"idempotency"}, "fail", "DELETE returns different results on repeat"},
		{"/redirect-http", []string{"GET"}, "cross-origin", []string{"redirect"}, "warn", "Redirect to insecure HTTP"},
		{"/redirect-ok", []string{"GET"}, "cross-origin", []string{"redirect"}, "pass", "Redirect to HTTPS"},
		{"/cached", []string{"GET"}, "cache", []string{"cache-control", "etag", "vary"}, "warn", "No cache headers"},
		{"/cached-ok", []string{"GET"}, "cache", []string{"cache-control", "etag", "vary", "304"}, "pass", "Proper cache headers"},
		{"/api/replay", []string{"POST"}, "state", []string{"replay"}, "fail", "No idempotency key or nonce"},
		{"/api/workflow/step1", []string{"GET"}, "state", []string{"workflow-skip"}, "n/a", "Workflow start"},
		{"/api/workflow/step3", []string{"GET"}, "state", []string{"workflow-skip"}, "fail", "Step3 without step1/step2"},
		{"/api/race", []string{"POST"}, "state", []string{"toctou"}, "fail", "Check-then-act with sleep"},
		{"/headers", []string{"GET"}, "mutation", []string{"header-forge", "header-corrupt"}, "n/a", "Reflects request headers"},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(manifest)
}
