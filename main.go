package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aygp-dr/http-axiom/internal/generator"
)

// Build-time variables (set via ldflags).
var (
	Version   = "dev"
	GitCommit = "none"
	BuildDate = "unknown"
)

// Global flags.
var (
	jsonOutput  bool
	verboseMode bool
	targetURL   string
)

func main() {
	// Pre-parse global flags.
	args := preParseFlags(os.Args[1:])

	if len(args) == 0 {
		usage()
		os.Exit(0)
	}

	cmd := args[0]
	cmdArgs := args[1:]

	if isHelpFlag(cmd) {
		usage()
		os.Exit(0)
	}

	switch cmd {
	case "generate", "gen":
		cmdGenerate(cmdArgs)
	case "mutate", "mut":
		cmdMutate(cmdArgs)
	case "check":
		cmdCheck(cmdArgs)
	case "run":
		cmdRun(cmdArgs)
	case "list", "ls":
		cmdList(cmdArgs)
	case "audit":
		cmdAudit(cmdArgs)
	case "shrink":
		cmdShrink(cmdArgs)
	case "doctor":
		cmdDoctor(cmdArgs)
	case "quickstart", "prime":
		cmdQuickstart(cmdArgs)
	case "version":
		versionInfo()
	case "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "error: unknown command '%s'\n", cmd)
		if suggestion := suggestCommand(cmd); suggestion != "" {
			fmt.Fprintf(os.Stderr, "\nDid you mean: hax %s?\n", suggestion)
		}
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------
// Global flag parsing
// ---------------------------------------------------------------------------

func preParseFlags(args []string) []string {
	var remaining []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") {
			remaining = append(remaining, args[i:]...)
			break
		}
		switch arg {
		case "--json":
			jsonOutput = true
		case "-V", "--verbose":
			verboseMode = true
		case "-v", "--version":
			versionInfo()
			os.Exit(0)
		case "-h", "--help":
			usage()
			os.Exit(0)
		case "-t", "--target":
			if i+1 < len(args) {
				targetURL = args[i+1]
				i++
			}
		default:
			remaining = append(remaining, arg)
		}
	}
	return remaining
}

func isHelpFlag(s string) bool {
	return s == "-h" || s == "--help" || s == "help"
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

// cmdGenerate produces HTTP request variants from the request space.
//
// Axes: method × path × headers × auth × origin × repeat
func cmdGenerate(args []string) {
	if len(args) > 0 && isHelpFlag(args[0]) {
		fmt.Print(`Usage: hax generate [flags]

Generate HTTP request variants from the request space.

Axes: method × path × headers × auth × origin × repeat

Flags:
  -t, --target URL    Target URL (or use global --target)
  -m, --methods LIST  HTTP methods to include (default: GET,POST,PUT,DELETE,PATCH,HEAD,OPTIONS)
  -p, --paths LIST    Paths to test (default: /)
  -n, --count N       Number of variants to generate (default: 10)
  --seed N            Random seed for reproducibility
  --json              Output as JSON
  -h, --help          Show this help
`)
		return
	}

	methods := "GET,POST,PUT,DELETE,PATCH,HEAD,OPTIONS"
	paths := "/"
	count := 10
	seed := int64(0)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-m", "--methods":
			if i+1 < len(args) {
				methods = args[i+1]
				i++
			}
		case "-p", "--paths":
			if i+1 < len(args) {
				paths = args[i+1]
				i++
			}
		case "-n", "--count":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &count)
				i++
			}
		case "--seed":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &seed)
				i++
			}
		case "-t", "--target":
			if i+1 < len(args) {
				targetURL = args[i+1]
				i++
			}
		}
	}

	verbose("generating %d request variants (seed=%d)", count, seed)
	verbose("methods: %s", methods)
	verbose("paths: %s", paths)

	// Parse comma-separated values into slices.
	methodList := strings.Split(methods, ",")
	pathList := strings.Split(paths, ",")

	// Build config from defaults, then override with parsed flags.
	cfg := generator.DefaultConfig()
	cfg.Methods = methodList
	cfg.Paths = pathList
	cfg.Count = count
	cfg.Seed = seed

	// Generate request variants.
	requests := generator.Generate(cfg)

	// If --target is set, store it as BaseURL on each request.
	if targetURL != "" {
		for i := range requests {
			requests[i].BaseURL = targetURL
		}
	}

	// Output.
	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(requests)
		return
	}

	// Compact table: METHOD  PATH  AUTH  ORIGIN
	fmt.Printf("%-10s %-30s %-10s %s\n", "METHOD", "PATH", "AUTH", "ORIGIN")
	for _, r := range requests {
		path := r.Path
		if r.BaseURL != "" {
			path = r.BaseURL + r.Path
		}
		fmt.Printf("%-10s %-30s %-10s %s\n", r.Method, path, r.Auth, r.Origin)
	}
}

// cmdMutate applies mutation operators to HTTP requests.
//
// Vocabulary: method-rotation, header-omit, header-corrupt, header-forge,
// origin-cross-site, origin-same-site, repeat-N, repeat-concurrent
func cmdMutate(args []string) {
	if len(args) > 0 && isHelpFlag(args[0]) {
		fmt.Print(`Usage: hax mutate [flags]

Apply mutation operators to HTTP requests.

Vocabulary:
  method-rotate        Cycle through HTTP methods
  header-omit          Remove required headers
  header-corrupt       Malform header values
  header-forge         Inject forged headers
  origin-cross-site    Set cross-origin Origin header
  origin-same-site     Set same-site Origin header
  repeat-N             Replay request N times
  repeat-concurrent    Replay request concurrently

Flags:
  -o, --operators LIST  Mutation operators to apply (default: all)
  -i, --input FILE      Input requests (JSON, from generate)
  --stdin               Read requests from stdin
  -h, --help            Show this help
`)
		return
	}

	fmt.Fprintf(os.Stderr, "hax mutate: not yet implemented\n")
	os.Exit(1)
}

// cmdCheck runs predicate checks against a target.
//
// Groups: headers, methods, cross-origin, cache, state-sequence
func cmdCheck(args []string) {
	if len(args) > 0 && isHelpFlag(args[0]) {
		fmt.Print(`Usage: hax check <group> [flags]

Run predicate checks against a target.

Groups:
  headers       CSP, HSTS, SameSite, CORP
  methods       Idempotency, safety, retries
  cross-origin  CSRF, CORS, JSONP, redirect
  cache         ETag, no-store, Vary, 304
  state         Workflow skip, TOCTOU, replay

Flags:
  -t, --target URL    Target URL (required)
  -g, --group NAME    Predicate group (or positional)
  --all               Run all predicate groups
  -n, --dry-run       Show what would be checked
  -h, --help          Show this help
`)
		return
	}

	fmt.Fprintf(os.Stderr, "hax check: not yet implemented\n")
	os.Exit(1)
}

// cmdRun executes the full pipeline: generate → mutate → check → oracle.
func cmdRun(args []string) {
	if len(args) > 0 && isHelpFlag(args[0]) {
		fmt.Print(`Usage: hax run [flags]

Execute the full test pipeline:
  generate → mutate → check → oracle

Flags:
  -t, --target URL       Target URL (required)
  -n, --count N          Number of test cases (default: 100)
  --seed N               Random seed
  --shrink               Enable shrinking on failure (default: true)
  --max-shrinks N        Maximum shrink attempts (default: 50)
  --timeout DURATION     Per-request timeout (default: 10s)
  --concurrency N        Parallel requests (default: 1)
  -g, --groups LIST      Predicate groups to check (default: all)
  -o, --operators LIST   Mutation operators (default: all)
  --fail-fast            Stop on first failure
  -h, --help             Show this help
`)
		return
	}

	fmt.Fprintf(os.Stderr, "hax run: not yet implemented\n")
	os.Exit(1)
}

// cmdList enumerates available predicates, mutations, or groups.
func cmdList(args []string) {
	if len(args) > 0 && isHelpFlag(args[0]) {
		fmt.Print(`Usage: hax list <what>

List available components.

What:
  predicates    All predicate checks
  mutations     All mutation operators
  groups        Predicate groups
  methods       HTTP methods in scope

Flags:
  -h, --help    Show this help
`)
		return
	}

	what := "groups"
	if len(args) > 0 {
		what = args[0]
	}

	switch what {
	case "groups":
		groups := []struct {
			Name       string   `json:"name"`
			Predicates []string `json:"predicates"`
		}{
			{"headers", []string{"csp", "hsts", "samesite", "corp"}},
			{"methods", []string{"idempotency", "safety", "retries"}},
			{"cross-origin", []string{"csrf", "cors", "jsonp", "redirect"}},
			{"cache", []string{"etag", "no-store", "vary", "304"}},
			{"state", []string{"workflow-skip", "toctou", "replay"}},
		}
		if jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.Encode(groups)
			return
		}
		for _, g := range groups {
			fmt.Printf("%-14s %s\n", g.Name, strings.Join(g.Predicates, ", "))
		}

	case "predicates":
		predicates := []string{
			"csp", "hsts", "samesite", "corp",
			"idempotency", "safety", "retries",
			"csrf", "cors", "jsonp", "redirect",
			"etag", "no-store", "vary", "304",
			"workflow-skip", "toctou", "replay",
		}
		if jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.Encode(predicates)
			return
		}
		for _, p := range predicates {
			fmt.Println(p)
		}

	case "mutations":
		mutations := []string{
			"method-rotate",
			"header-omit", "header-corrupt", "header-forge",
			"origin-cross-site", "origin-same-site",
			"repeat-N", "repeat-concurrent",
		}
		if jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.Encode(mutations)
			return
		}
		for _, m := range mutations {
			fmt.Println(m)
		}

	case "methods":
		methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
		if jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.Encode(methods)
			return
		}
		for _, m := range methods {
			fmt.Println(m)
		}

	default:
		fmt.Fprintf(os.Stderr, "error: unknown list target '%s'\n", what)
		fmt.Fprintf(os.Stderr, "Try: hax list groups|predicates|mutations|methods\n")
		os.Exit(1)
	}
}

// cmdAudit runs a quick compliance audit against a target URL.
func cmdAudit(args []string) {
	if len(args) > 0 && isHelpFlag(args[0]) {
		fmt.Print(`Usage: hax audit <url> [flags]

Quick compliance audit of an HTTP endpoint.

Checks security headers, method semantics, CORS policy,
cache behaviour, and common state-management issues.

Flags:
  -t, --target URL    Target URL (or positional)
  -g, --groups LIST   Predicate groups (default: all)
  --timeout DURATION  Per-request timeout (default: 10s)
  -h, --help          Show this help
`)
		return
	}

	url := targetURL
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		url = args[0]
	}
	if url == "" {
		fmt.Fprintf(os.Stderr, "error: target URL required\n")
		fmt.Fprintf(os.Stderr, "Usage: hax audit <url>\n")
		os.Exit(1)
	}

	verbose("auditing %s", url)

	// Quick probe: can we reach the target?
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Head(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot reach %s: %v\n", url, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	type finding struct {
		Group  string `json:"group"`
		Check  string `json:"check"`
		Status string `json:"status"` // "pass", "fail", "warn", "skip"
		Detail string `json:"detail,omitempty"`
	}

	var findings []finding

	// Header predicates.
	headerChecks := map[string]string{
		"csp":  "Content-Security-Policy",
		"hsts": "Strict-Transport-Security",
		"corp": "Cross-Origin-Resource-Policy",
	}
	for check, header := range headerChecks {
		val := resp.Header.Get(header)
		if val == "" {
			findings = append(findings, finding{"headers", check, "fail", header + " header missing"})
		} else {
			findings = append(findings, finding{"headers", check, "pass", val})
		}
	}

	// SameSite check on Set-Cookie.
	cookies := resp.Header.Values("Set-Cookie")
	if len(cookies) == 0 {
		findings = append(findings, finding{"headers", "samesite", "skip", "no cookies set"})
	} else {
		for _, c := range cookies {
			if strings.Contains(strings.ToLower(c), "samesite") {
				findings = append(findings, finding{"headers", "samesite", "pass", "SameSite attribute present"})
			} else {
				findings = append(findings, finding{"headers", "samesite", "warn", "cookie missing SameSite attribute"})
			}
		}
	}

	// CORS check.
	corsHeader := resp.Header.Get("Access-Control-Allow-Origin")
	if corsHeader == "*" {
		findings = append(findings, finding{"cross-origin", "cors", "warn", "wildcard CORS origin"})
	} else if corsHeader != "" {
		findings = append(findings, finding{"cross-origin", "cors", "pass", corsHeader})
	} else {
		findings = append(findings, finding{"cross-origin", "cors", "skip", "no CORS headers"})
	}

	// Cache headers.
	cacheControl := resp.Header.Get("Cache-Control")
	etag := resp.Header.Get("ETag")
	if cacheControl != "" {
		findings = append(findings, finding{"cache", "cache-control", "pass", cacheControl})
	} else {
		findings = append(findings, finding{"cache", "cache-control", "warn", "no Cache-Control header"})
	}
	if etag != "" {
		findings = append(findings, finding{"cache", "etag", "pass", etag})
	} else {
		findings = append(findings, finding{"cache", "etag", "skip", "no ETag header"})
	}

	// Output.
	if jsonOutput {
		out := struct {
			Target   string    `json:"target"`
			Status   string    `json:"status"`
			Findings []finding `json:"findings"`
		}{
			Target:   url,
			Findings: findings,
		}
		// Determine overall status.
		out.Status = "pass"
		for _, f := range findings {
			if f.Status == "fail" {
				out.Status = "fail"
				break
			}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(out)
		return
	}

	// Table output.
	fmt.Printf("Audit: %s\n\n", url)
	passCount, failCount, warnCount, skipCount := 0, 0, 0, 0
	for _, f := range findings {
		marker := "?"
		switch f.Status {
		case "pass":
			marker = "OK"
			passCount++
		case "fail":
			marker = "FAIL"
			failCount++
		case "warn":
			marker = "WARN"
			warnCount++
		case "skip":
			marker = "SKIP"
			skipCount++
		}
		fmt.Printf("  [%-4s] %-14s %-12s %s\n", marker, f.Group, f.Check, f.Detail)
	}
	fmt.Printf("\nSummary: %d pass, %d fail, %d warn, %d skip\n", passCount, failCount, warnCount, skipCount)
	if failCount > 0 {
		os.Exit(1)
	}
}

// cmdShrink minimizes a failing test case using the oracle.
func cmdShrink(args []string) {
	if len(args) > 0 && isHelpFlag(args[0]) {
		fmt.Print(`Usage: hax shrink [flags]

Minimize a failing test case.

Uses Hegel-based shrinking to find the smallest request
that still triggers the failure.

Flags:
  -i, --input FILE      Failing test case (JSON)
  --stdin               Read from stdin
  --max-shrinks N       Maximum shrink attempts (default: 50)
  -h, --help            Show this help
`)
		return
	}

	fmt.Fprintf(os.Stderr, "hax shrink: not yet implemented\n")
	os.Exit(1)
}

// cmdDoctor runs health checks.
func cmdDoctor(args []string) {
	if len(args) > 0 && isHelpFlag(args[0]) {
		fmt.Print(`Usage: hax doctor

Run diagnostic health checks.

Checks:
  - Go version compatibility
  - Network connectivity
  - Configuration validity
  - Dependency availability
`)
		return
	}

	fmt.Println("hax doctor")
	fmt.Println()

	checks := 0
	passed := 0

	// Check: binary built properly.
	checks++
	if Version != "dev" {
		fmt.Println("  [OK]   version: built with ldflags")
		passed++
	} else {
		fmt.Println("  [WARN] version: dev build (no ldflags)")
	}

	// Check: can resolve DNS.
	checks++
	client := &http.Client{Timeout: 5 * time.Second}
	_, err := client.Head("https://httpbin.org/get")
	if err != nil {
		fmt.Printf("  [WARN] network: cannot reach httpbin.org: %v\n", err)
	} else {
		fmt.Println("  [OK]   network: httpbin.org reachable")
		passed++
	}

	fmt.Printf("\n%d/%d checks passed\n", passed, checks)
}

// cmdQuickstart prints onboarding context for agents.
func cmdQuickstart(args []string) {
	fmt.Print(`hax — property-based HTTP axiom tester

hax generates HTTP request variants, applies mutations, and checks
RFC-grounded predicates to find violations in web services.

Architecture:
  Request Generator → Mutation Vocabulary → Predicate Groups → Oracle

Quick start:
  hax audit https://example.com          # Quick compliance audit
  hax list groups                         # See predicate groups
  hax list mutations                      # See mutation operators
  hax run -t https://example.com          # Full property-based test run
  hax generate -t https://example.com     # Generate request variants
  hax check headers -t https://example.com # Check header predicates

Predicate groups:
  headers       CSP · HSTS · SameSite · CORP
  methods       idempotency · safety · retries
  cross-origin  CSRF · CORS · JSONP · redirect
  cache         ETag · no-store · Vary · 304
  state         workflow skip · TOCTOU · replay

Mutation vocabulary:
  method-rotate · header-omit · header-corrupt · header-forge
  origin-cross-site · origin-same-site · repeat-N · repeat-concurrent
`)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func usage() {
	fmt.Print(`Usage: hax <command> [flags]

Property-based HTTP axiom tester.

Commands:
  generate (gen)     Generate HTTP request variants
  mutate (mut)       Apply mutation operators to requests
  check              Run predicate checks against a target
  run                Full pipeline: generate → mutate → check → oracle
  list (ls)          List predicates, mutations, groups, methods
  audit              Quick compliance audit of an endpoint
  shrink             Minimize a failing test case

Utility:
  doctor             Run diagnostic health checks
  quickstart (prime) Onboarding context for agents
  version            Print version info
  help               Show this help

Global flags:
  -t, --target URL   Target URL
  -V, --verbose      Verbose output
  --json             JSON output
  -v, --version      Print version
  -h, --help         Show help

Examples:
  hax audit https://example.com
  hax run -t https://example.com --count 50
  hax list groups --json
  hax check headers -t https://example.com
`)
}

func versionInfo() {
	if jsonOutput {
		out := struct {
			Version   string `json:"version"`
			GitCommit string `json:"git_commit"`
			BuildDate string `json:"build_date"`
		}{Version, GitCommit, BuildDate}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(out)
		return
	}
	fmt.Printf("hax %s (commit: %s, built: %s)\n", Version, GitCommit, BuildDate)
}

func verbose(format string, a ...any) {
	if verboseMode {
		fmt.Fprintf(os.Stderr, "[verbose] "+format+"\n", a...)
	}
}

// suggestCommand returns a similar command name for typo correction.
func suggestCommand(input string) string {
	commands := []string{
		"generate", "gen", "mutate", "mut", "check", "run",
		"list", "ls", "audit", "shrink", "doctor", "quickstart",
		"prime", "version", "help",
	}
	best := ""
	bestDist := 3 // max edit distance
	for _, cmd := range commands {
		d := levenshtein(input, cmd)
		if d < bestDist {
			bestDist = d
			best = cmd
		}
	}
	return best
}

func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min(curr[j-1]+1, min(prev[j]+1, prev[j-1]+cost))
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}
