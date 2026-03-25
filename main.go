package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aygp-dr/http-axiom/internal/generator"
	"github.com/aygp-dr/http-axiom/internal/mutation"
	"github.com/aygp-dr/http-axiom/internal/oracle"
	"github.com/aygp-dr/http-axiom/internal/predicate"
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

	// Parse flags.
	operatorList := ""
	inputFile := ""
	useStdin := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-o", "--operators":
			if i+1 < len(args) {
				operatorList = args[i+1]
				i++
			}
		case "-i", "--input":
			if i+1 < len(args) {
				inputFile = args[i+1]
				i++
			}
		case "--stdin":
			useStdin = true
		}
	}

	// Determine operators to apply.
	var operators []string
	if operatorList != "" {
		operators = strings.Split(operatorList, ",")
	} else {
		operators = mutation.AllOperators()
	}

	// Validate operator names.
	for _, op := range operators {
		if _, ok := mutation.Get(op); !ok {
			fmt.Fprintf(os.Stderr, "error: unknown mutation operator %q\n", op)
			fmt.Fprintf(os.Stderr, "Available: %s\n", strings.Join(mutation.AllOperators(), ", "))
			os.Exit(1)
		}
	}

	// Determine input source.
	var reader io.Reader
	if inputFile != "" {
		f, err := os.Open(inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot open input file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		reader = f
	} else {
		// Default to stdin (explicit --stdin or implicit).
		_ = useStdin
		reader = os.Stdin
	}

	// Read and parse JSON input.
	var requests []generator.Request
	dec := json.NewDecoder(reader)
	if err := dec.Decode(&requests); err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid JSON input: %v\n", err)
		os.Exit(1)
	}

	if len(requests) == 0 {
		fmt.Fprintf(os.Stderr, "error: no requests in input\n")
		os.Exit(1)
	}

	verbose("mutating %d requests with operators: %s", len(requests), strings.Join(operators, ", "))

	// Apply mutations to each request, producing one mutated request per operator per input.
	var mutated []generator.Request
	for _, req := range requests {
		for _, op := range operators {
			m := mutation.Apply(req, []string{op})
			mutated = append(mutated, m)
		}
	}

	// Output.
	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(mutated)
		return
	}

	// Table output: OPERATOR  METHOD  PATH  HEADERS  ORIGIN
	fmt.Printf("%-20s %-10s %-30s %-8s %s\n", "OPERATOR", "METHOD", "PATH", "HEADERS", "ORIGIN")
	opIdx := 0
	for range requests {
		for _, op := range operators {
			r := mutated[opIdx]
			opIdx++
			path := r.Path
			if r.BaseURL != "" {
				path = r.BaseURL + r.Path
			}
			hdrCount := fmt.Sprintf("%d", len(r.Headers))
			fmt.Printf("%-20s %-10s %-30s %-8s %s\n", op, r.Method, path, hdrCount, r.Origin)
		}
	}
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
		// Derive group listing from predicate.AllGroups() so that adding a
		// predicate in internal/predicate automatically updates `hax list`.
		type groupView struct {
			Name       string   `json:"name"`
			Predicates []string `json:"predicates"`
		}
		var groups []groupView
		for _, g := range predicate.AllGroups() {
			names := make([]string, len(g.Predicates))
			for i, p := range g.Predicates {
				names[i] = p.Name
			}
			groups = append(groups, groupView{Name: g.Name, Predicates: names})
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
		// Derive predicate listing from predicate.AllGroups().
		var predicates []string
		for _, g := range predicate.AllGroups() {
			for _, p := range g.Predicates {
				predicates = append(predicates, p.Name)
			}
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
		// Derive mutation listing from mutation.AllOperators().
		mutations := mutation.AllOperators()
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

	// Use GET instead of HEAD — HEAD responses often omit headers like
	// Set-Cookie, which breaks SameSite checks on endpoints that do set cookies.
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot reach %s: %v\n", url, err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	// Discard the body so the connection can be reused.
	io.Copy(io.Discard, resp.Body)

	// Run all predicate groups against the response.
	var results []predicate.Result
	for _, group := range predicate.AllGroups() {
		results = append(results, predicate.Run(group, resp)...)
	}

	// Let the oracle judge the results.
	verdict := oracle.Judge(url, results)

	// Output.
	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(verdict)
		return
	}

	// Table output.
	fmt.Printf("Audit: %s\n\n", url)
	for _, r := range verdict.Results {
		marker := "?"
		switch r.Status {
		case "pass":
			marker = "OK"
		case "fail":
			marker = "FAIL"
		case "warn":
			marker = "WARN"
		case "skip":
			marker = "SKIP"
		}
		fmt.Printf("  [%-4s] %-14s %-24s %s\n", marker, r.Group, r.Name, r.Detail)
	}
	fmt.Printf("\nSummary: %d pass, %d fail, %d warn, %d skip\n",
		verdict.Passed, verdict.Failed, verdict.Warned, verdict.Skipped)
	if verdict.Status == "fail" {
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

Predicate groups (run 'hax list groups' for live data):
`)
	// Derive predicate groups from the package so quickstart stays in sync.
	for _, g := range predicate.AllGroups() {
		names := make([]string, len(g.Predicates))
		for i, p := range g.Predicates {
			names[i] = p.Name
		}
		fmt.Printf("  %-14s %s\n", g.Name, strings.Join(names, " · "))
	}

	fmt.Println()
	fmt.Println("Mutation vocabulary (run 'hax list mutations' for live data):")
	fmt.Printf("  %s\n", strings.Join(mutation.AllOperators(), " · "))
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
