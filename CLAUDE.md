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

## Tracking

- `bd` (beads) for issue tracking — `bd ready` shows unblocked work
- `cprr` for conjectures — each hypothesis tied to a bead
- `aq` for inter-agent coordination

## Stack

- Go 1.23+ (stdlib only)
- Make for build orchestration
- No external dependencies
- L1 in the testing stack (see docs/formal-model.org)
