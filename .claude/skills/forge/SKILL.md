---
name: forge
description: Four-agent pipeline (builder/adversary/validator/meta) for implementing changes with adversarial review. Use when making structural changes, fixing bugs, or implementing conjectures.
argument-hint: "<conjecture or change description>"
allowed-tools: Agent, Bash, Read, Write, Edit, Grep, Glob
effort: max
---

# Forge — Builder / Adversary / Validator / Meta Pipeline

Four-agent pipeline for implementing changes with built-in adversarial
review. Heat (build), strike (attack), quench (validate), temper (document).

## Input

$ARGUMENTS — the change to implement. Can reference a conjecture ID
(e.g., "C-042"), a P0 finding, or a plain description.

## Pipeline

### Phase 1: Builder (worktree isolation)

Launch a `builder` agent with `isolation: "worktree"`:
- What to change and why
- Files affected
- Tests to write
- Wiring verification (every Config field has a CLI flag path)
- Must pass: `go build ./...`, `go test ./...`, `gofmt -l .` clean

### Phase 2: Adversary (parallel with Phase 3-4)

Launch a `security-expert` agent against the builder's worktree:
- Verify claimed fixes are actually fixed
- Try to break it (edge cases, bypasses, zero-values)
- Check policy reachable from CLI entry point ("dead code" check)
- Check no scatter-pattern bypasses (grep for bare constructions)
- Output: CONFIRMED / REFUTED / FRAGILE per finding

### Phase 3: Validator (parallel with Phase 2, 4)

Launch a `code-reviewer` agent against the same worktree:
- Confirm or refute each adversary finding by reading actual code
- Independent verification of builder's claims
- Check tests actually test what they claim
- Output: summary table of findings with verdicts

### Phase 4: Meta — boundary invariants (parallel with Phase 2-3)

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
7. No `io.NopCloser` on network response bodies

## Fitness Functions

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

## After pipeline completes

- If all phases pass: copy worktree files to main, commit, push
- If adversary found CONFIRMED issues: present findings, ask user whether to re-forge or accept
- Update conjecture status in `.cprr/conjectures.json` if applicable
