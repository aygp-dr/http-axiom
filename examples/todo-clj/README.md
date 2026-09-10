# todo-clj (hax target)

A deliberately insecure Clojure Ring + reitit + next.jdbc (SQLite) todo API
with a static SPA shell. It's a long-lived target for hax. See
[spec.org](spec.org) for the epochs and scenarios. This is epoch 0: no
security headers, no auth, no CORS.

## Run

```bash
make dev      # or: bb serve   (clojure -M:run, Jetty on http://localhost:8080)
make clean    # remove todos.db
```

## Development

This directory is a standalone Clojure project that follows the aygp-dr
Clojure standard. `deps.edn` is the manifest and `bb.edn` holds the tasks.
CI runs `bb check` from the repo root workflow.

| Task                    | What it does                       |
|-------------------------|------------------------------------|
| `bb test`               | test suite (`clojure -M:test`)     |
| `bb lint`               | clj-kondo (fails on errors)        |
| `bb fmt` / `bb fmt:fix` | cljfmt check / fix                 |
| `bb check`              | lint + fmt + test (CI runs this)   |
| `bb serve`              | run the app (`clojure -M:run`)     |

The tests need no server and no network. They call `todo.routes/app` and the
handlers with plain Ring request maps, and `todo.test-db/with-temp-db` points
`todo.db` at a throwaway SQLite file, so `todos.db` is never touched.

### Specs

Data specs for the todo entity, request bodies, Ring requests and responses
live in `src/todo/specs.clj`. Every fn in `todo.db`, `todo.routes`,
`todo.middleware` and `todo.main` has an `s/fdef` right after its `defn`
(see the [clojure.spec guide](https://clojure.org/guides/spec)).

- `test/todo/specs_test.clj` runs `stest/check` over the pure fns.
- `test/todo/db_test.clj` checks the `todo.db` fdefs against the temp database.
- The route and db tests run with instrumentation on, and `clj -M:dev`
  instruments at the REPL.

When a later epoch changes behaviour, such as adding headers in
`todo.middleware`, update the matching fdef and the epoch-0 header test in
`test/todo/routes_test.clj`.
