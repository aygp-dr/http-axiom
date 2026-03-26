# Petstore Rails (hax target)

Deliberately insecure Rails 8 API app for demonstrating hax over the lifecycle of a project.

## Setup

```bash
gmake setup    # creates db, runs migration, seeds 5 pets
gmake server   # starts on port 3033
```

## Endpoints

| Method | Path         | Description          |
|--------|-------------|----------------------|
| GET    | /health     | Health check + version |
| GET    | /pets       | List pets (filter: ?status=available) |
| GET    | /pets/:id   | Show pet              |
| POST   | /pets       | Create pet            |
| PUT    | /pets/:id   | Update pet            |
| DELETE | /pets/:id   | Delete pet            |

## hax audit (v0.0.1 baseline)

```
3 FAIL:  csp, hsts, corp
3 WARN:  permissions-policy, coep, coop
7 PASS:  x-frame-options, x-content-type-options, referrer-policy,
         cors-reflection, etag, idempotency, safety
12 SKIP: stateful/multi-request checks not yet available
```

## Version history

| Version | hax result | Change |
|---------|-----------|--------|
| 0.0.1   | 7/25 pass, 3 fail, 3 warn | Baseline: no security headers configured |
