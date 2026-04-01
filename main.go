package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"time"

	"github.com/aygp-dr/http-axiom/internal/executor"
	"github.com/aygp-dr/http-axiom/internal/generator"
	"github.com/aygp-dr/http-axiom/internal/mutation"
	"github.com/aygp-dr/http-axiom/internal/oracle"
	"github.com/aygp-dr/http-axiom/internal/output"
	"github.com/aygp-dr/http-axiom/internal/predicate"
	"github.com/aygp-dr/http-axiom/internal/relevance"
	"github.com/aygp-dr/http-axiom/internal/request"
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

// stripGlobalFlags removes --json and -V/--verbose from args, setting the
// global flags. Returns remaining args. This allows global flags to appear
// anywhere in the command line.
func stripGlobalFlags(args []string) []string {
	var remaining []string
	for _, arg := range args {
		switch arg {
		case "--json":
			jsonOutput = true
		case "-V", "--verbose":
			verboseMode = true
		default:
			remaining = append(remaining, arg)
		}
	}
	return remaining
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

	args = stripGlobalFlags(args)

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
		output.JSON(requests)
		return
	}

	// Compact table: METHOD  PATH  AUTH  ORIGIN
	headers := []string{"METHOD", "PATH", "AUTH", "ORIGIN"}
	var rows [][]string
	for _, r := range requests {
		path := r.Path
		if r.BaseURL != "" {
			path = r.BaseURL + r.Path
		}
		rows = append(rows, []string{r.Method, path, r.Auth, r.Origin})
	}
	output.Table(headers, rows)
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

	args = stripGlobalFlags(args)

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
	var requests []request.Request
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
	var mutated []request.Request
	for _, req := range requests {
		for _, op := range operators {
			m := mutation.Apply(req, []string{op})
			mutated = append(mutated, m)
		}
	}

	// Output.
	if jsonOutput {
		output.JSON(mutated)
		return
	}

	// Table output: OPERATOR  METHOD  PATH  HEADERS  ORIGIN
	headers := []string{"OPERATOR", "METHOD", "PATH", "HEADERS", "ORIGIN"}
	var rows [][]string
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
			rows = append(rows, []string{op, r.Method, path, hdrCount, r.Origin})
		}
	}
	output.Table(headers, rows)
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

	args = stripGlobalFlags(args)

	// Parse flags.
	url := targetURL
	groupName := ""
	runAll := false
	dryRun := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-t", "--target":
			if i+1 < len(args) {
				url = args[i+1]
				i++
			}
		case "-g", "--group":
			if i+1 < len(args) {
				groupName = args[i+1]
				i++
			}
		case "--all":
			runAll = true
		case "-n", "--dry-run":
			dryRun = true
		default:
			// Positional argument: treat as group name if not a flag.
			if !strings.HasPrefix(args[i], "-") && groupName == "" {
				groupName = args[i]
			}
		}
	}

	if url == "" {
		fmt.Fprintf(os.Stderr, "error: target URL required\n")
		fmt.Fprintf(os.Stderr, "Usage: hax check <group> -t <url>\n")
		os.Exit(1)
	}

	// Resolve which groups to check.
	var groups []predicate.Group
	if runAll {
		groups = predicate.AllGroups()
	} else if groupName != "" {
		g, ok := predicate.ByName(groupName)
		if !ok {
			fmt.Fprintf(os.Stderr, "error: unknown predicate group %q\n", groupName)
			fmt.Fprintf(os.Stderr, "Available: %s\n", strings.Join(predicate.GroupNames(), ", "))
			os.Exit(1)
		}
		groups = []predicate.Group{g}
	} else {
		fmt.Fprintf(os.Stderr, "error: specify a group name or --all\n")
		fmt.Fprintf(os.Stderr, "Usage: hax check <group> -t <url>\n")
		fmt.Fprintf(os.Stderr, "       hax check --all -t <url>\n")
		os.Exit(1)
	}

	// Dry-run: list what would be checked without executing.
	if dryRun {
		if jsonOutput {
			type dryPred struct {
				Group string `json:"group"`
				Name  string `json:"name"`
				Type  string `json:"type"`
			}
			var out []dryPred
			for _, g := range groups {
				for _, p := range g.Predicates {
					typeName := "universal"
					switch p.Type {
					case predicate.TypeRelational:
						typeName = "relational"
					case predicate.TypeSequential:
						typeName = "sequential"
					}
					out = append(out, dryPred{Group: g.Name, Name: p.Name, Type: typeName})
				}
			}
			output.JSON(out)
			return
		}
		fmt.Printf("Dry run: %s\n\n", url)
		for _, g := range groups {
			for _, p := range g.Predicates {
				typeName := "universal"
				switch p.Type {
				case predicate.TypeRelational:
					typeName = "relational"
				case predicate.TypeSequential:
					typeName = "sequential"
				}
				fmt.Printf("  %-14s %-24s [%s]\n", g.Name, p.Name, typeName)
			}
		}
		return
	}

	verbose("checking %d group(s) against %s", len(groups), url)

	// Set up executor config. The executor creates its own http.Client
	// with redirect policy enforcement via newClient().
	execCfg := executor.DefaultConfig()
	execCfg.BaseURL = url
	client := &http.Client{Timeout: execCfg.Timeout}

	var allResults []predicate.Result

	for _, group := range groups {
		verbose("running group: %s (%d predicates)", group.Name, len(group.Predicates))

		// Determine which predicate types this group contains.
		hasUniversal := false
		hasRelational := false
		hasSequential := false
		for _, p := range group.Predicates {
			switch p.Type {
			case predicate.TypeUniversal:
				hasUniversal = true
			case predicate.TypeRelational:
				hasRelational = true
			case predicate.TypeSequential:
				hasSequential = true
			}
		}

		// Type 1 (Universal): send a GET, run single-response predicates.
		if hasUniversal {
			req := request.Request{
				Method: "GET",
				Path:   "/",
			}
			result := executor.Execute(execCfg, req)
			if result.Err != nil {
				fmt.Fprintf(os.Stderr, "error: request to %s failed: %v\n", url, result.Err)
				os.Exit(1)
			}
			groupResults := predicate.Run(group, result.Response)
			result.CloseResponses()
			allResults = append(allResults, groupResults...)
		}

		// Type 2 (Relational): send a GET with mutation-injected headers.
		if hasRelational {
			httpReq, err := http.NewRequest("GET", url, nil)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: cannot build request for %s: %v\n", url, err)
				os.Exit(1)
			}
			httpReq.Header.Set("Origin", "https://evil.example.com")
			httpResp, err := client.Do(httpReq)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: relational request to %s failed: %v\n", url, err)
				os.Exit(1)
			}
			groupResults := predicate.RunWithRequest(group, httpReq, httpResp)
			io.Copy(io.Discard, httpResp.Body)
			httpResp.Body.Close()
			allResults = append(allResults, groupResults...)
		}

		// Type 3 (Sequential): predicates send their own requests.
		if hasSequential {
			allResults = append(allResults, predicate.RunMulti(group, client, url)...)
		}
	}

	// Let the oracle judge the results.
	verdict := oracle.Judge(url, allResults)

	// Output.
	if jsonOutput {
		output.JSON(verdict)
		return
	}

	// Table output.
	fmt.Printf("Check: %s\n\n", url)
	for _, r := range verdict.Results {
		output.Result(r)
	}
	fmt.Printf("\nSummary: %d pass, %d fail, %d warn, %d skip\n",
		verdict.Passed, verdict.Failed, verdict.Warned, verdict.Skipped)
	if verdict.Status == "fail" {
		os.Exit(1)
	}
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
  --max-redirects N      Maximum redirects to follow (default: 10)
  -g, --groups LIST      Predicate groups to check (default: all)
  -o, --operators LIST   Mutation operators (default: all)
  --max-body-size BYTES  Max response body to read (default: 10485760)
  --fail-fast            Stop on first failure
  -h, --help             Show this help
`)
		return
	}

	args = stripGlobalFlags(args)

	// ---------------------------------------------------------------
	// 1. Parse flags
	// ---------------------------------------------------------------
	url := targetURL
	count := 100
	seed := int64(0)
	timeout := 10 * time.Second
	concurrency := 1
	maxRedirects := 10
	maxBodySize := int64(10 * 1024 * 1024)
	groupList := ""
	operatorList := ""
	failFast := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-t", "--target":
			if i+1 < len(args) {
				url = args[i+1]
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
		case "--timeout":
			if i+1 < len(args) {
				d, err := time.ParseDuration(args[i+1])
				if err != nil {
					fmt.Fprintf(os.Stderr, "error: invalid timeout %q: %v\n", args[i+1], err)
					os.Exit(1)
				}
				timeout = d
				i++
			}
		case "--concurrency":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &concurrency)
				i++
			}
		case "--max-redirects":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &maxRedirects)
				i++
			}
		case "--max-body-size":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &maxBodySize)
				i++
			}
		case "-g", "--groups":
			if i+1 < len(args) {
				groupList = args[i+1]
				i++
			}
		case "-o", "--operators":
			if i+1 < len(args) {
				operatorList = args[i+1]
				i++
			}
		case "--fail-fast":
			failFast = true
		case "--json":
			jsonOutput = true
		case "-V", "--verbose":
			verboseMode = true
		}
	}

	if url == "" {
		fmt.Fprintf(os.Stderr, "error: target URL required\n")
		fmt.Fprintf(os.Stderr, "Usage: hax run -t <url>\n")
		os.Exit(1)
	}

	// Resolve predicate groups.
	var groups []predicate.Group
	if groupList != "" {
		for _, name := range strings.Split(groupList, ",") {
			name = strings.TrimSpace(name)
			g, ok := predicate.ByName(name)
			if !ok {
				fmt.Fprintf(os.Stderr, "error: unknown predicate group %q\n", name)
				fmt.Fprintf(os.Stderr, "Available: %s\n", strings.Join(predicate.GroupNames(), ", "))
				os.Exit(1)
			}
			groups = append(groups, g)
		}
	} else {
		groups = predicate.AllGroups()
	}

	// Resolve mutation operators.
	var operators []string
	if operatorList != "" {
		for _, op := range strings.Split(operatorList, ",") {
			op = strings.TrimSpace(op)
			if _, ok := mutation.Get(op); !ok {
				fmt.Fprintf(os.Stderr, "error: unknown mutation operator %q\n", op)
				fmt.Fprintf(os.Stderr, "Available: %s\n", strings.Join(mutation.AllOperators(), ", "))
				os.Exit(1)
			}
			operators = append(operators, op)
		}
	} else {
		operators = mutation.AllOperators()
	}

	verbose("pipeline: generate(%d, seed=%d) -> mutate(%d ops) -> check(%d groups) -> oracle",
		count, seed, len(operators), len(groups))
	verbose("target: %s, timeout: %s, concurrency: %d, fail-fast: %v",
		url, timeout, concurrency, failFast)

	// ---------------------------------------------------------------
	// 2. Generate
	// ---------------------------------------------------------------
	cfg := generator.DefaultConfig()
	cfg.Count = count
	cfg.Seed = seed
	requests := generator.Generate(cfg)

	verbose("generated %d base requests", len(requests))

	// ---------------------------------------------------------------
	// 3. Mutate
	// ---------------------------------------------------------------
	type taggedRequest struct {
		Req      request.Request
		Operator string // which mutation operator was applied
	}
	var mutated []taggedRequest
	for _, req := range requests {
		for _, op := range operators {
			m := mutation.Apply(req, []string{op})
			mutated = append(mutated, taggedRequest{Req: m, Operator: op})
		}
	}

	verbose("mutated into %d request variants", len(mutated))

	// ---------------------------------------------------------------
	// 4. Execute + Check
	// ---------------------------------------------------------------
	execCfg := executor.DefaultConfig()
	execCfg.BaseURL = url
	execCfg.Timeout = timeout
	execCfg.Concurrency = concurrency
	execCfg.MaxRedirects = maxRedirects
	execCfg.MaxBodySize = maxBodySize
	client := &http.Client{Timeout: timeout}

	var allResults []predicate.Result
	total := len(mutated)
	stopped := false

	for idx, tagged := range mutated {
		if stopped {
			break
		}

		// Closure ensures defer fires per-iteration, closing response
		// bodies on ALL paths — including error returns from Execute
		// that may leave partial results with open bodies.
		iterResults, iterStopped := func() ([]predicate.Result, bool) {
			req := tagged.Req

			// Execute the request.
			result := executor.Execute(execCfg, req)
			defer result.CloseResponses()

			if result.Err != nil {
				verbose("[%d/%d] %s %s -> ERROR: %v", idx+1, total, req.Method, req.Path, result.Err)
				// Record as skip — network errors should not halt the run.
				return []predicate.Result{{
					Group:  "executor",
					Name:   "request",
					Status: "skip",
					Detail: fmt.Sprintf("%s %s: %v", req.Method, req.Path, result.Err),
				}}, false
			}

			// Use the relevance matrix to select only groups relevant to this
			// mutation operator, instead of running every group (C-005 fix).
			relevantGroups := resolveRelevantGroups(tagged.Operator, groups)

			var iterResults []predicate.Result

			// Run each relevant predicate group against the response.
			for _, group := range relevantGroups {
				var groupResults []predicate.Result

				// Classify which predicate types this group contains.
				hasUniversal := false
				hasRelational := false
				hasSequential := false
				for _, p := range group.Predicates {
					switch p.Type {
					case predicate.TypeUniversal:
						hasUniversal = true
					case predicate.TypeRelational:
						hasRelational = true
					case predicate.TypeSequential:
						hasSequential = true
					}
				}

				// Universal predicates: run against the response we already have.
				if hasUniversal && result.Response != nil {
					groupResults = append(groupResults, predicate.Run(group, result.Response)...)
				}

				// Relational predicates: construct a request with evil Origin and execute.
				if hasRelational {
					httpReq, err := http.NewRequest("GET", url, nil)
					if err == nil {
						httpReq.Header.Set("Origin", "https://evil.example.com")
						httpResp, err := client.Do(httpReq)
						if err == nil {
							// Design note: relational predicates inspect headers, not body.
							// Draining httpResp.Body before RunWithRequest is intentional —
							// it returns the connection to the pool. If a future predicate
							// needs body content, restructure to read before drain.
							io.Copy(io.Discard, httpResp.Body)
							httpResp.Body.Close()
							groupResults = append(groupResults, predicate.RunWithRequest(group, httpReq, httpResp)...)
						}
					}
				}

				// Sequential predicates: they manage their own requests.
				if hasSequential {
					groupResults = append(groupResults, predicate.RunMulti(group, client, url)...)
				}

				// Verbose progress output.
				for _, r := range groupResults {
					if verboseMode {
						fmt.Fprintf(os.Stderr, "[%d/%d] %s %s [%s] -> %s: %s=%s (%s)\n",
							idx+1, total, req.Method, req.Path, tagged.Operator,
							r.Group, r.Name, r.Status, result.Duration)
					}
				}

				iterResults = append(iterResults, groupResults...)

				// Fail-fast: stop on first failure.
				if failFast {
					for _, r := range groupResults {
						if r.Status == "fail" {
							return iterResults, true
						}
					}
				}
			}

			return iterResults, false
		}()

		allResults = append(allResults, iterResults...)
		if iterStopped {
			stopped = true
		}
	}

	// ---------------------------------------------------------------
	// 5. Oracle
	// ---------------------------------------------------------------
	verdict := oracle.Judge(url, allResults)

	// ---------------------------------------------------------------
	// 6. Output
	// ---------------------------------------------------------------
	if jsonOutput {
		output.JSON(verdict)
		if verdict.Status == "fail" {
			os.Exit(1)
		}
		return
	}

	// Normal / verbose mode: print the verdict summary.
	fmt.Printf("Run: %s\n\n", url)
	for _, r := range verdict.Results {
		output.Result(r)
	}
	fmt.Printf("\nSummary: %d pass, %d fail, %d warn, %d skip\n",
		verdict.Passed, verdict.Failed, verdict.Warned, verdict.Skipped)

	if stopped {
		fmt.Println("(stopped early: --fail-fast)")
	}

	if verdict.Status == "fail" {
		os.Exit(1)
	}
}

// resolveRelevantGroups returns only the predicate groups that are relevant
// for the given mutation operator, filtered against the user-selected groups.
// This uses the relevance matrix to avoid running every group for every mutation.
func resolveRelevantGroups(operator string, selectedGroups []predicate.Group) []predicate.Group {
	cases := relevance.ForMutation(operator)
	if len(cases) == 0 {
		// Unknown operator (shouldn't happen) — fall back to all selected groups.
		return selectedGroups
	}

	// Collect the set of relevant group names from the matrix.
	relevant := make(map[string]bool)
	for _, tc := range cases {
		for _, g := range tc.Groups {
			relevant[g] = true
		}
	}

	// Filter selectedGroups to only those in the relevant set.
	var out []predicate.Group
	for _, g := range selectedGroups {
		if relevant[g.Name] {
			out = append(out, g)
		}
	}
	return out
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

	args = stripGlobalFlags(args)

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
			output.JSON(groups)
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
			output.JSON(predicates)
			return
		}
		for _, p := range predicates {
			fmt.Println(p)
		}

	case "mutations":
		// Derive mutation listing from mutation.AllOperators().
		mutations := mutation.AllOperators()
		if jsonOutput {
			output.JSON(mutations)
			return
		}
		for _, m := range mutations {
			fmt.Println(m)
		}

	case "methods":
		methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
		if jsonOutput {
			output.JSON(methods)
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
  -t, --target URL         Target URL (or positional)
  -g, --groups LIST        Predicate groups (default: all)
  --timeout DURATION       Per-request timeout (default: 10s)
  --max-body-size BYTES    Max response body to read (default: 10485760)
  --max-redirects N        Maximum redirects to follow (default: 10)
  -h, --help               Show this help
`)
		return
	}

	args = stripGlobalFlags(args)

	url := targetURL
	auditTimeout := 10 * time.Second
	maxBodySize := int64(10 * 1024 * 1024)
	maxRedirects := 10

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-t", "--target":
			if i+1 < len(args) {
				url = args[i+1]
				i++
			}
		case "--timeout":
			if i+1 < len(args) {
				d, err := time.ParseDuration(args[i+1])
				if err != nil {
					fmt.Fprintf(os.Stderr, "error: invalid timeout %q: %v\n", args[i+1], err)
					os.Exit(1)
				}
				auditTimeout = d
				i++
			}
		case "--max-body-size":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &maxBodySize)
				i++
			}
		case "--max-redirects":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &maxRedirects)
				i++
			}
		default:
			if !strings.HasPrefix(args[i], "-") && url == "" {
				url = args[i]
			}
		}
	}

	if url == "" {
		fmt.Fprintf(os.Stderr, "error: target URL required\n")
		fmt.Fprintf(os.Stderr, "Usage: hax audit <url>\n")
		os.Exit(1)
	}

	verbose("auditing %s", url)

	// Parse the target URL to extract base URL and path for executor.
	parsed, err := neturl.Parse(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid URL %s: %v\n", url, err)
		os.Exit(1)
	}

	baseURL := parsed.Scheme + "://" + parsed.Host
	path := parsed.RequestURI()

	// Build a request.Request and executor.Config, then execute via the
	// shared executor which handles auth, origin, repeat, and pooling.
	req := request.Request{
		Method: "GET",
		Path:   path,
	}
	cfg := executor.DefaultConfig()
	cfg.BaseURL = baseURL
	cfg.Timeout = auditTimeout
	cfg.MaxBodySize = maxBodySize
	cfg.MaxRedirects = maxRedirects

	result := executor.Execute(cfg, req)
	if result.Err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot reach %s: %v\n", url, result.Err)
		os.Exit(1)
	}

	resp := result.Response
	// Close ALL response bodies (not just [0]) so connections can be reused.
	defer result.CloseResponses()

	// Run all predicate groups against the response.
	client := &http.Client{Timeout: auditTimeout}
	var results []predicate.Result
	for _, group := range predicate.AllGroups() {
		// Type 1 (Universal): single-response predicates.
		results = append(results, predicate.Run(group, resp)...)

		// Type 2 (Relational): predicates that compare request+response.
		if predicate.NeedsRequest(group) {
			httpReq, _ := http.NewRequest("GET", url, nil)
			httpReq.Header.Set("Origin", "https://evil.example.com")
			httpResp, err := client.Do(httpReq)
			if err == nil {
				results = append(results, predicate.RunWithRequest(group, httpReq, httpResp)...)
				io.Copy(io.Discard, httpResp.Body)
				httpResp.Body.Close()
			}
		}

		// Type 3 (Sequential): predicates that send their own requests.
		if predicate.NeedsMulti(group) {
			results = append(results, predicate.RunMulti(group, client, url)...)
		}
	}

	// Let the oracle judge the results.
	verdict := oracle.Judge(url, results)

	// Output.
	if jsonOutput {
		output.JSON(verdict)
		return
	}

	output.Verdict(verdict)
	if verdict.Status == "fail" {
		os.Exit(1)
	}
}

// cmdShrink minimizes a failing test case using the oracle.
func cmdShrink(args []string) {
	if len(args) > 0 && isHelpFlag(args[0]) {
		fmt.Print(`Usage: hax shrink [flags]

Minimize a failing test case using lattice-based shrinking.

Progressively simplifies a failing request to find the minimal
reproduction: remove headers, simplify auth/origin, reduce method
and repeat count.

Flags:
  -i, --input FILE      Failing test case (JSON request)
  --stdin               Read from stdin (default if no --input)
  --max-shrinks N       Maximum shrink attempts (default: 50)
  -t, --target URL      Target URL (required)
  --predicate NAME      Predicate name to check
  --group NAME          Predicate group to check
  --json                Output as JSON
  -h, --help            Show this help

Examples:
  echo '{"method":"POST","path":"/","headers":{"X-A":"1","X-B":"2"}}' | hax shrink -t http://localhost:9999 --group headers
  hax shrink -i failing-request.json -t http://localhost:9999 --predicate csp
`)
		return
	}

	args = stripGlobalFlags(args)

	// Parse flags.
	url := targetURL
	inputFile := ""
	useStdin := false
	maxShrinks := 50
	predicateName := ""
	groupName := ""

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-i", "--input":
			if i+1 < len(args) {
				inputFile = args[i+1]
				i++
			}
		case "--stdin":
			useStdin = true
		case "--max-shrinks":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &maxShrinks)
				i++
			}
		case "-t", "--target":
			if i+1 < len(args) {
				url = args[i+1]
				i++
			}
		case "--predicate":
			if i+1 < len(args) {
				predicateName = args[i+1]
				i++
			}
		case "--group":
			if i+1 < len(args) {
				groupName = args[i+1]
				i++
			}
		}
	}

	if url == "" {
		fmt.Fprintf(os.Stderr, "error: target URL required (-t <url>)\n")
		os.Exit(1)
	}

	// Read the failing request from stdin or file.
	var inputData []byte
	var readErr error

	if inputFile != "" {
		inputData, readErr = os.ReadFile(inputFile)
	} else {
		// Default to stdin.
		useStdin = true
		_ = useStdin
		inputData, readErr = io.ReadAll(os.Stdin)
	}
	if readErr != nil {
		fmt.Fprintf(os.Stderr, "error reading input: %v\n", readErr)
		os.Exit(1)
	}

	var req request.Request
	if err := json.Unmarshal(inputData, &req); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing request JSON: %v\n", err)
		os.Exit(1)
	}

	// Resolve which predicates to use.
	var groups []predicate.Group
	if groupName != "" {
		g, ok := predicate.ByName(groupName)
		if !ok {
			fmt.Fprintf(os.Stderr, "error: unknown predicate group %q\n", groupName)
			fmt.Fprintf(os.Stderr, "Available: %s\n", strings.Join(predicate.GroupNames(), ", "))
			os.Exit(1)
		}
		groups = []predicate.Group{g}
	} else if predicateName != "" {
		// Find the predicate by name across all groups.
		for _, g := range predicate.AllGroups() {
			for _, p := range g.Predicates {
				if p.Name == predicateName {
					groups = []predicate.Group{{Name: g.Name, Predicates: []predicate.NamedPred{p}}}
					break
				}
			}
			if len(groups) > 0 {
				break
			}
		}
		if len(groups) == 0 {
			fmt.Fprintf(os.Stderr, "error: unknown predicate %q\n", predicateName)
			os.Exit(1)
		}
	} else {
		// Default: run all groups.
		groups = predicate.AllGroups()
	}

	// Set up executor config. The executor creates its own http.Client
	// with redirect policy enforcement -- no external client injection.
	execCfg := executor.DefaultConfig()
	execCfg.BaseURL = url
	// A standalone client for Type 3 (Sequential) predicates that
	// manage their own requests outside the executor.
	seqClient := &http.Client{Timeout: execCfg.Timeout}

	// Build the CheckFunc: execute the request and run predicates.
	checkFn := func(r request.Request) (predicate.Result, error) {
		r.BaseURL = url
		result := executor.Execute(execCfg, r)
		defer result.CloseResponses()
		if result.Err != nil {
			return predicate.Result{}, result.Err
		}
		if result.Response == nil {
			return predicate.Result{}, fmt.Errorf("no response")
		}

		// Run predicates and return the first failure.
		for _, group := range groups {
			for _, p := range group.Predicates {
				var pr predicate.Result
				switch p.Type {
				case predicate.TypeUniversal:
					if p.Fn != nil {
						pr = p.Fn(result.Response)
					}
				case predicate.TypeRelational:
					if p.ReqFn != nil {
						fullURL := strings.TrimRight(url, "/") + r.Path
						httpReq, reqErr := http.NewRequest(r.Method, fullURL, nil)
						if reqErr == nil {
							for k, v := range r.Headers {
								httpReq.Header.Set(k, v)
							}
							pr = p.ReqFn(httpReq, result.Response)
						}
					}
				case predicate.TypeSequential:
					if p.MultiFn != nil {
						pr = p.MultiFn(seqClient, url)
					}
				}
				if pr.Status == "fail" {
					return pr, nil
				}
			}
		}
		// No failure found.
		return predicate.Result{Status: "pass"}, nil
	}

	// Run the shrink.
	shrinkCfg := oracle.ShrinkConfig{
		MaxAttempts: maxShrinks,
		Enabled:     true,
	}

	verbose("shrinking request against %s (max %d attempts)", url, maxShrinks)
	shrinkResult := oracle.Shrink(shrinkCfg, req, checkFn)
	verbose("shrink complete: %d steps", shrinkResult.Steps)

	// Output.
	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(shrinkResult)
	} else {
		fmt.Printf("Shrink result (%d steps):\n\n", shrinkResult.Steps)
		if shrinkResult.Predicate != "" {
			fmt.Printf("  Failing predicate: %s (group: %s)\n\n", shrinkResult.Predicate, shrinkResult.Group)
		}
		fmt.Println("  Original:")
		printRequestSummary("    ", shrinkResult.Original)
		fmt.Println()
		fmt.Println("  Shrunk:")
		printRequestSummary("    ", shrinkResult.Shrunk)
		fmt.Println()
		if shrinkResult.Steps == 0 {
			fmt.Println("  (request is already minimal or does not fail)")
		}
	}
}

// printRequestSummary prints a human-readable summary of a request.
func printRequestSummary(indent string, r request.Request) {
	method := r.Method
	if method == "" {
		method = "GET"
	}
	fmt.Printf("%sMethod:  %s\n", indent, method)
	fmt.Printf("%sPath:    %s\n", indent, r.Path)
	if r.Auth != "" {
		fmt.Printf("%sAuth:    %s\n", indent, r.Auth)
	}
	if r.Origin != "" {
		fmt.Printf("%sOrigin:  %s\n", indent, r.Origin)
	}
	if r.Repeat > 1 {
		fmt.Printf("%sRepeat:  %d\n", indent, r.Repeat)
	}
	if len(r.Headers) > 0 {
		fmt.Printf("%sHeaders: (%d)\n", indent, len(r.Headers))
		for k, v := range r.Headers {
			fmt.Printf("%s  %s: %s\n", indent, k, v)
		}
	}
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

	args = stripGlobalFlags(args)
	_ = args

	type doctorCheck struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Detail string `json:"detail"`
	}

	var results []doctorCheck
	checks := 0
	passed := 0

	// Check: binary built properly.
	checks++
	if Version != "dev" {
		results = append(results, doctorCheck{"version", "ok", "built with ldflags"})
		passed++
	} else {
		results = append(results, doctorCheck{"version", "warn", "dev build (no ldflags)"})
	}

	// Check: can resolve DNS.
	checks++
	client := &http.Client{Timeout: 5 * time.Second}
	_, err := client.Head("https://httpbin.org/get")
	if err != nil {
		results = append(results, doctorCheck{"network", "warn", fmt.Sprintf("cannot reach httpbin.org: %v", err)})
	} else {
		results = append(results, doctorCheck{"network", "ok", "httpbin.org reachable"})
		passed++
	}

	// JSON output mode.
	if jsonOutput {
		status := "pass"
		if passed < checks {
			status = "fail"
		}
		out := struct {
			Status  string        `json:"status"`
			Checks  int           `json:"checks"`
			Passed  int           `json:"passed"`
			Results []doctorCheck `json:"results"`
		}{status, checks, passed, results}
		output.JSON(out)
		if passed < checks {
			os.Exit(1)
		}
		return
	}

	// Human-readable output.
	fmt.Println("hax doctor")
	fmt.Println()
	for _, r := range results {
		marker := "WARN"
		if r.Status == "ok" {
			marker = "OK"
		}
		fmt.Printf("  [%-4s] %s: %s\n", marker, r.Name, r.Detail)
	}
	fmt.Printf("\n%d/%d checks passed\n", passed, checks)

	if passed < checks {
		os.Exit(1)
	}
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
		output.JSON(out)
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
