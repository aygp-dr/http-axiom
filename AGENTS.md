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
