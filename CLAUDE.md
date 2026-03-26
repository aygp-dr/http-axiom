## Your Role

You are a coding agent working on http-axiom (hax), a property-based
HTTP axiom tester. You write Go code, run tests, and fix failures.

## Foundational Axiom

HTTP compliance is a property-testing problem: generate request
variants, apply mutations, check RFC-grounded predicates, and shrink
failures to minimal reproductions. Existing tools check headers
statically; hax checks behaviour dynamically.

Do not optimize for static analysis or one-shot scanning at any layer.

## Confirmation Gate

Before writing any code, output a summary of what you will change,
which files are affected, and which predicate group or mutation
operator is involved. Wait for confirmation.

## What You Are Building

- A zero-dependency Go CLI (`hax`) for property-based HTTP testing
- Five RFC-grounded predicate groups (headers, methods, cross-origin, cache, state)
- Eight mutation operators against the HTTP request space
- An oracle with Hegel-based shrinking for failure minimization

## Explicit Anti-Goals

- **Not a scanner** (like nuclei/nikto) — no signature database, no CVE matching
- **Not a fuzzer** (like ffuf) — mutations are structured, not random bytes
- **Not a proxy** (like burp/mitmproxy) — no interception, no GUI
- **Not a load tester** (like k6/vegeta) — concurrency is for correctness, not throughput

## Key Design Decisions

- Single-binary, zero external dependencies (stdlib only)
- Hand-written flag parsing (no cobra, no urfave/cli) — follows sb/cprr pattern
- `--json` global flag for machine-readable output
- `internal/` packages for domain logic (generator, mutation, predicate, oracle)
- Makefile with ldflags for version injection

## Build Order

1. `hax list` and `hax version` — enumerate components (done)
2. `hax audit <url>` — single-request header/CORS/cache checks (done, basic)
3. `hax generate` — request variant generation from cartesian product
4. `hax mutate` — apply mutation operators to generated requests
5. `hax check` — run predicate groups against live target
6. `hax run` — full pipeline: generate → mutate → check → oracle
7. `hax shrink` — minimize failing test cases

If an acceptance test fails, stop. Document what failed, what you
tried, and what the blocker is. Do not proceed to the next step.
Surface the failure as a CPRR refutation candidate.

## Property Types

Every predicate is one of three types (see docs/formal-model.org):

- **Type 1 (Universal)**: `func(resp) Result` — single response, no request context.
  CSP, HSTS, SameSite, CORP, X-Frame-Options, X-Content-Type-Options, Permissions-Policy.
- **Type 2 (Relational)**: `func(req, resp) Result` — checks response against sent request.
  CORS reflection, JSONP callback. Uses `RequestResponsePredicate`.
- **Type 3 (Sequential)**: `func(client, target) Result` — sends its own requests.
  Idempotency, safety, CSRF, 304, replay, TOCTOU, workflow-skip. Uses `MultiPredicate`.

When adding a predicate, choose the minimal type that can verify the property.

## Relevance Matrix

Mutations route to specific predicate groups (not uniform fan-out):
- `header-*` → headers
- `method-rotate` → methods, cross-origin
- `origin-*` → cross-origin, headers
- `repeat-N` → methods, cache, state
- `repeat-concurrent` → state, methods

See `internal/relevance/relevance.go` for the matrix data structure.

## Project Layout

```
main.go                      CLI entry point (hand-written arg routing)
go.mod                       Module (zero deps)
Makefile                     Build, test, lint, install
cmd/haxgoat/                 Deliberately vulnerable test server (23 endpoints)
internal/generator/          Request variant generation
internal/mutation/           Mutation operators (8)
internal/predicate/          RFC-grounded predicate checks (21 across 5 groups)
internal/oracle/             Verdict + shrinking
internal/executor/           HTTP request execution (single, repeat, concurrent)
internal/relevance/          Mutation → predicate group routing matrix
docs/formal-model.org        Property type theory and stack position
```

## Multi-Agent Workflow

The outer loop (human + coordinator agent) merges; worktree agents grind in isolation.

- **Outer loop**: coordinates, reviews, merges branches, runs smoke tests
- **Worktree agents**: each gets a bead (bd issue), works in `sb`-managed worktree, commits to a branch
- **aq**: gossip layer — agents announce files they're editing, check for conflicts before starting
- **bd**: dependency-chained issue tracking — `bd ready` shows unblocked work
- **cprr**: conjecture tracking — each hypothesis tied to a bead with falsification criteria
- **sb**: worktree management — one worktree per agent, `sb audit` verifies placement

Git hooks are active (`.githooks/` via `core.hooksPath`):
- `pre-commit`: auto-announces staged files to aq broadcast channel
- `post-commit`: announces completion with commit message

Every agent MUST:
1. `aq announce -c <bead-id> -f "<files>"` before starting
2. `aq check -f "<file>"` before editing a shared file — if conflict, coordinate
3. `aq status` to see what other agents are doing (read the gossip!)
4. Commit to a branch named `<bead-id>-<slug>`
4. `go build ./...` and `go test ./...` before committing

## Contracts (from audit)

- `request.Request` is a value type — deep-copy `Headers` map before mutation
- `NamedPred.Type` determines which function field is set (exactly one of Fn/ReqFn/MultiFn)
- Caller MUST close ALL response bodies in `executor.Result.Responses` (not just `[0]`)
- `--json` must work in any flag position (via `stripGlobalFlags` or `flag.FlagSet`)
- Commands that detect issues must exit non-zero

## Conjecture Workflow

Conjectures (`.cprr/conjectures.json`) drive all changes. The workflow:

1. **Observe** — run hax against targets, read output, find gaps
2. **Document** — create a conjecture with hypothesis, falsification
   criteria, and acceptance criteria
3. **Assign** — every conjecture gets an `assigned_agent` and a
   `review_gate` (a design/scope question the agent must answer first)
4. **Gate** — the assigned agent evaluates the review gate BEFORE any
   implementation. The gate checks whether the conjecture fits hax's
   design intent, anti-goals, and L1 scope
5. **Implement** — only after the gate passes, in an isolated worktree

No conjecture becomes code without passing the review gate. The
coordinator agent (outer loop) observes and documents but does NOT
implement or decide scope fitness — that is the assigned agent's job.

### Review gate examples

- "Is TRACE detection a property check or a scan?" → if scan, violates
  anti-goal (not a scanner), conjecture is deferred
- "Does open redirect detection require app-specific knowledge?" → if
  yes, it's L2 not L1, out of scope for hax
- "Does rapid as test-only dep violate zero-dep?" → test deps don't
  ship in the binary, so no

### Agent assignments by domain

| Agent | Domain |
|-------|--------|
| `lambda` | Formal methods (TLA+, Alloy, Dafny, Lean4) |
| `sec-research` | RFC coverage, security predicates, L1 boundary |
| `staff-engineer` | Architecture, signatures, executor, relevance |
| `observer` | Methodology, naming, documentation |
| `code-reviewer` | Test infrastructure, code quality |
| `researcher` | Future integrations (Hegel, external tools) |

## Example Applications

`examples/` contains deliberately evolving web applications that serve
as long-lived hax targets. They are test beds, not products.

| App | Stack | Security surface |
|-----|-------|-----------------|
| `petstore-rails` | Rails + ViewComponent + Turbo | Server-rendered, CSRF tokens, cache headers |
| `todo-clj` | Clojure Ring + Reagent SPA | Cross-origin, JWT cookies, anti-CSRF header |

Each app defines **epochs** (numbered security postures). Epoch 0 is
deliberately insecure; each subsequent epoch introduces a fix. hax
scenarios are tagged with the epoch at which their expected results
become valid, making hax a regression gate across time.

See `examples/*/spec.org` for full specifications.

## Stack

- Go 1.23+ (stdlib only, flag.FlagSet for rebuild CLI layer)
- Make for build orchestration (file-based targets, idempotent)
- L1 in the testing stack (see docs/formal-model.org)
- Rebuild option: Cobra/pflag if flag complexity warrants it
