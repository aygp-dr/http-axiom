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
	// /weak-csp: weak Content-Security-Policy (headers group)
	// Triggers: csp=FAIL (permissive policy that current check misses)
	// CPRR C-001
	// ---------------------------------------------------------------
	mux.HandleFunc("/weak-csp", handleWeakCSP)

	// ---------------------------------------------------------------
	// /hsts-zero: HSTS with max-age=0 (headers group)
	// Triggers: hsts=FAIL (disables HSTS, current check may pass)
	// CPRR C-002
	// ---------------------------------------------------------------
	mux.HandleFunc("/hsts-zero", handleHSTSZero)

	// ---------------------------------------------------------------
	// /cors-reflect: reflects Origin into ACAO (cross-origin group)
	// Triggers: cors=FAIL (most dangerous CORS misconfig)
	// CPRR C-003
	// ---------------------------------------------------------------
	mux.HandleFunc("/cors-reflect", handleCORSReflect)

	// ---------------------------------------------------------------
	// /cors-null: ACAO set to null (cross-origin group)
	// Triggers: cors=FAIL (allows sandboxed iframe access)
	// ---------------------------------------------------------------
	mux.HandleFunc("/cors-null", handleCORSNull)

	// ---------------------------------------------------------------
	// /samesite-none-insecure: SameSite=None without Secure flag
	// Triggers: samesite=FAIL (browsers reject silently)
	// CPRR C-007
	// ---------------------------------------------------------------
	mux.HandleFunc("/samesite-none-insecure", handleSameSiteNoneInsecure)

	// ---------------------------------------------------------------
	// /samesite-none-secure: SameSite=None with Secure flag (correct)
	// Should pass samesite predicate.
	// ---------------------------------------------------------------
	mux.HandleFunc("/samesite-none-secure", handleSameSiteNoneSecure)

	// ---------------------------------------------------------------
	// /open-redirect: redirects to unvalidated URL parameter
	// Triggers: redirect=FAIL (open redirect vulnerability)
	// ---------------------------------------------------------------
	mux.HandleFunc("/open-redirect", handleOpenRedirect)

	// ---------------------------------------------------------------
	// /weak-headers: missing secondary security headers
	// Triggers: x-content-type-options=FAIL, x-frame-options=FAIL,
	//   referrer-policy=FAIL, permissions-policy=FAIL
	// Has CSP and HSTS to isolate the gap to secondary headers.
	// ---------------------------------------------------------------
	mux.HandleFunc("/weak-headers", handleWeakHeaders)

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
	fmt.Println("  /weak-csp             Weak CSP (C-001)")
	fmt.Println("  /hsts-zero            HSTS max-age=0 (C-002)")
	fmt.Println("  /cors-reflect         CORS origin reflection (C-003)")
	fmt.Println("  /cors-null            CORS Access-Control-Allow-Origin: null")
	fmt.Println("  /samesite-none-insecure SameSite=None without Secure (C-007)")
	fmt.Println("  /samesite-none-secure SameSite=None with Secure (correct)")
	fmt.Println("  /open-redirect?url=   Open redirect (no validation)")
	fmt.Println("  /weak-headers         Missing secondary security headers")
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

// handleWeakCSP: returns a permissive CSP that should fail but may pass naive checks.
// Vuln: CSP allows everything — default-src * with unsafe-inline and unsafe-eval.
// CPRR C-001: presence check passes, but the policy is effectively useless.
func handleWeakCSP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval'")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"warning": "CSP is present but permissive — allows all sources, inline scripts, and eval",
		"cprr":    "C-001",
	})
}

// handleHSTSZero: returns HSTS with max-age=0, which disables HSTS protection.
// Vuln: max-age=0 instructs browsers to remove the HSTS entry.
// CPRR C-002: header presence check passes, but the value disables protection.
func handleHSTSZero(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Strict-Transport-Security", "max-age=0")
	w.Header().Set("Content-Security-Policy", "default-src 'self'")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"warning": "HSTS max-age=0 tells browsers to remove HSTS entry",
		"cprr":    "C-002",
	})
}

// handleCORSReflect: reflects the request Origin header into Access-Control-Allow-Origin.
// Vuln: most dangerous CORS misconfiguration — trusts any origin.
// CPRR C-003: wildcard check passes (not *), but any origin is trusted.
func handleCORSReflect(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = "*"
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"origin":  origin,
		"warning": "Origin reflected verbatim into ACAO with credentials — trusts any origin",
		"cprr":    "C-003",
	})
}

// handleCORSNull: returns Access-Control-Allow-Origin: null.
// Vuln: allows access from sandboxed iframes (origin is "null" as a string).
func handleCORSNull(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "null")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"warning": "ACAO: null allows sandboxed iframe access with credentials",
	})
}

// handleSameSiteNoneInsecure: sets cookie with SameSite=None but no Secure flag.
// Vuln: browsers silently reject SameSite=None cookies without Secure.
// CPRR C-007: cookie appears set but is silently dropped by modern browsers.
func handleSameSiteNoneInsecure(w http.ResponseWriter, r *http.Request) {
	// Go's http.Cookie doesn't let us set SameSite=None without Secure easily
	// in a way that's intentionally broken, so we set the header manually.
	w.Header().Add("Set-Cookie", "session=insecure-token; Path=/; HttpOnly; SameSite=None")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"warning": "SameSite=None without Secure flag — browsers silently reject this cookie",
		"cprr":    "C-007",
	})
}

// handleSameSiteNoneSecure: sets cookie with SameSite=None and Secure flag (correct).
// This is the proper way to set a cross-site cookie.
func handleSameSiteNoneSecure(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "secure-cross-site-token",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
		Path:     "/",
	})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
		"note":   "SameSite=None with Secure flag — correct cross-site cookie configuration",
	})
}

// handleOpenRedirect: redirects to unvalidated URL parameter.
// Vuln: open redirect — attacker can craft URL to redirect victims anywhere.
func handleOpenRedirect(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	if target == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "missing url parameter",
			"usage": "/open-redirect?url=https://evil.com",
		})
		return
	}
	// No validation — redirects to any URL provided.
	http.Redirect(w, r, target, http.StatusFound)
}

// handleWeakHeaders: missing secondary security headers.
// Has CSP and HSTS (to isolate the test), but missing:
//   - X-Content-Type-Options
//   - X-Frame-Options
//   - Referrer-Policy
//   - Permissions-Policy
func handleWeakHeaders(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	// Deliberately NOT setting:
	// - X-Content-Type-Options
	// - X-Frame-Options
	// - Referrer-Policy
	// - Permissions-Policy
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"warning": "Has CSP+HSTS but missing X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy",
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
		{"/weak-csp", []string{"GET"}, "headers", []string{"csp"}, "fail", "Weak CSP: default-src * unsafe-inline unsafe-eval (CPRR C-001)"},
		{"/hsts-zero", []string{"GET"}, "headers", []string{"hsts"}, "fail", "HSTS max-age=0 disables protection (CPRR C-002)"},
		{"/cors-reflect", []string{"GET", "OPTIONS"}, "cross-origin", []string{"cors"}, "fail", "Reflects Origin into ACAO (CPRR C-003)"},
		{"/cors-null", []string{"GET", "OPTIONS"}, "cross-origin", []string{"cors"}, "fail", "ACAO: null allows sandboxed iframe access"},
		{"/samesite-none-insecure", []string{"GET"}, "headers", []string{"samesite"}, "fail", "SameSite=None without Secure flag (CPRR C-007)"},
		{"/samesite-none-secure", []string{"GET"}, "headers", []string{"samesite"}, "pass", "SameSite=None with Secure flag (correct)"},
		{"/open-redirect", []string{"GET"}, "cross-origin", []string{"redirect"}, "fail", "Open redirect — no URL validation"},
		{"/weak-headers", []string{"GET"}, "headers", []string{"x-content-type-options", "x-frame-options", "referrer-policy", "permissions-policy"}, "fail", "Missing secondary security headers (has CSP+HSTS)"},
		{"/headers", []string{"GET"}, "mutation", []string{"header-forge", "header-corrupt"}, "n/a", "Reflects request headers"},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(manifest)
}
