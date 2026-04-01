# Forge — Builder / Adversary / Validator / Meta Pipeline

Four-agent pipeline for implementing changes with built-in adversarial
review. Named after the process: heat (build), strike (attack), quench
(validate), temper (document).

## Usage

```
/forge <description of change>
```

## Arguments

$ARGUMENTS — description of the change to implement. Can reference a
conjecture ID (e.g., "C-042"), a P0 finding, or a plain description.

## Pipeline

### Phase 1: Builder (worktree isolation)

Launch a `builder` agent in an isolated worktree with:
- What to change and why
- Files affected
- Tests to write
- Wiring verification (every Config field → CLI flag → command handler)
- Constraint: `go build ./...` and `go test ./...` must pass

### Phase 2: Adversary

Launch a `security-expert` agent against the builder's worktree:
- Verify claimed fixes are actually fixed
- Try to break the implementation (edge cases, bypasses, zero-values)
- Check policy is reachable from CLI entry point (the "dead code" check)
- Check no scatter-pattern bypasses exist (grep for bare constructions)
- Output: CONFIRMED / REFUTED / FRAGILE per finding

### Phase 3: Validator

Launch a `code-reviewer` agent against the same worktree:
- Confirm or refute each adversary finding by reading actual code
- Independent verification of the builder's claims
- Check tests actually test what they claim
- Output: summary table of findings with verdicts

### Phase 4: Meta (boundary invariants)

Launch an `observer` agent:
- Document boundary invariants using connascence vocabulary
- Track EMC phase (expand / migrate / contract)
- Identify fitness functions for architecture-governance.org
- Assess process quality vs previous rounds

## Rules

1. Builder runs in a worktree (`isolation: "worktree"`)
2. Adversary, validator, and meta run in parallel after builder completes
3. If adversary finds CONFIRMED bugs, report them — do NOT auto-rebuild
4. Every new Config field must have a CLI flag (the wiring contract)
5. `grep '&http.Client{' main.go` must return 0 (transport policy uniformity)
6. `grep 'executor.Config{' main.go` must return 0 (DefaultConfig contract)
7. No `io.NopCloser` on network response bodies (the NopCloser antipattern)

## Fitness Functions (checked by each phase)

| Function | Check | Phase |
|----------|-------|-------|
| Build | `go build ./...` | Builder |
| Test | `go test ./...` | Builder |
| gofmt | `gofmt -l .` empty | Builder |
| No bare Config | `grep 'executor.Config{' main.go` == 0 | Adversary |
| No bare Client | `grep '&http.Client{' main.go` == 0 | Adversary |
| No NopCloser | `grep 'NopCloser' internal/executor/` == 0 (except comments) | Adversary |
| Wiring | every Config field reachable from CLI | Validator |
| EMC phase | documented in commit message | Meta |

## Example

```
/forge C-042: export NewClient to eliminate scatter-client bypass
```

Launches builder with C-042 spec → adversary attacks → validator confirms → meta documents boundary invariants.
