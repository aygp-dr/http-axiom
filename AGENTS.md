## Agent Development Rules

### Core Principles

1. **No frameworks** — stdlib only. Reject cobra, urfave/cli, kong.
2. **Minimize flags** — use positional args where possible.
3. **Non-interactive** — agents cannot answer prompts. Use `--force`.
4. **Exit codes matter** — `audit` and `check` return non-zero on failures.
5. **`quickstart` is structured for agents** — LLM-consumable bootstrap text.

### Adding a New Command

1. Add the case to `main()` switch in `main.go`
2. Write `cmdFoo(args []string)` with help text and flag parsing
3. Add to `suggestCommand` command list for typo correction
4. Add to `usage()` help text
5. Update `quickstart` if user-facing

### Adding a New Predicate

1. Add to the appropriate group in `internal/predicate/predicate.go`
2. Create a `checkFoo(resp *http.Response) Result` function
3. Register in the group's `Predicates` slice
4. Update `list groups` output in `main.go` if group changes

### Adding a New Mutation Operator

1. Add constant to `internal/mutation/mutation.go`
2. Implement `FooMutator(r generator.Request) generator.Request`
3. Register in `Get()` switch and `AllOperators()` slice
4. Update `list mutations` output in `main.go`

### Flag Parsing Pattern

Follow the hand-written loop pattern from sb/cprr:

```go
func cmdFoo(args []string) {
    if len(args) > 0 && isHelpFlag(args[0]) {
        fmt.Print(`Usage: hax foo ...`)
        return
    }

    var myFlag string
    var positional []string

    for i := 0; i < len(args); i++ {
        switch args[i] {
        case "-f", "--flag":
            if i+1 < len(args) {
                myFlag = args[i+1]
                i++
            }
        default:
            positional = append(positional, args[i])
        }
    }
    // ...
}
```

### Testing

- `make test` for unit tests
- `make test-race` with race detector
- Tests should not depend on external services
- Use `httptest.NewServer` for predicate/audit tests

### Commit Messages

- Imperative mood: "Add cors predicate" not "Added cors predicate"
- Reference predicate group or mutation operator when relevant

<!-- BEGIN BEADS INTEGRATION -->
## Issue Tracking with bd (beads)

**IMPORTANT**: This project uses **bd (beads)** for ALL issue tracking. Do NOT use markdown TODOs, task lists, or other tracking methods.

### Why bd?

- Dependency-aware: Track blockers and relationships between issues
- Git-friendly: Dolt-powered version control with native sync
- Agent-optimized: JSON output, ready work detection, discovered-from links
- Prevents duplicate tracking systems and confusion

### Quick Start

**Check for ready work:**

```bash
bd ready --json
```

**Create new issues:**

```bash
bd create "Issue title" --description="Detailed context" -t bug|feature|task -p 0-4 --json
bd create "Issue title" --description="What this issue is about" -p 1 --deps discovered-from:bd-123 --json
```

**Claim and update:**

```bash
bd update <id> --claim --json
bd update bd-42 --priority 1 --json
```

**Complete work:**

```bash
bd close bd-42 --reason "Completed" --json
```

### Issue Types

- `bug` - Something broken
- `feature` - New functionality
- `task` - Work item (tests, docs, refactoring)
- `epic` - Large feature with subtasks
- `chore` - Maintenance (dependencies, tooling)

### Priorities

- `0` - Critical (security, data loss, broken builds)
- `1` - High (major features, important bugs)
- `2` - Medium (default, nice-to-have)
- `3` - Low (polish, optimization)
- `4` - Backlog (future ideas)

### Workflow for AI Agents

1. **Check ready work**: `bd ready` shows unblocked issues
2. **Claim your task atomically**: `bd update <id> --claim`
3. **Work on it**: Implement, test, document
4. **Discover new work?** Create linked issue:
   - `bd create "Found bug" --description="Details about what was found" -p 1 --deps discovered-from:<parent-id>`
5. **Complete**: `bd close <id> --reason "Done"`

### Auto-Sync

bd automatically syncs via Dolt:

- Each write auto-commits to Dolt history
- Use `bd dolt push`/`bd dolt pull` for remote sync
- No manual export/import needed!

### Important Rules

- ✅ Use bd for ALL task tracking
- ✅ Always use `--json` flag for programmatic use
- ✅ Link discovered work with `discovered-from` dependencies
- ✅ Check `bd ready` before asking "what should I work on?"
- ❌ Do NOT create markdown TODO lists
- ❌ Do NOT use external issue trackers
- ❌ Do NOT duplicate tracking systems

For more details, see README.md and docs/QUICKSTART.md.

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd sync
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds

<!-- END BEADS INTEGRATION -->
