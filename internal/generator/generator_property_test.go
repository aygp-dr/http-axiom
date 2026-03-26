package generator

import (
	"testing"

	"pgregory.net/rapid"
)

// nonEmptyStringSlice generates a non-empty slice of strings sampled from a pool.
func nonEmptyStringSlice(pool []string) *rapid.Generator[[]string] {
	return rapid.Custom[[]string](func(t *rapid.T) []string {
		return rapid.SliceOfN(
			rapid.SampledFrom(pool),
			1, len(pool),
		).Draw(t, "slice")
	})
}

// configGen generates arbitrary Config values with non-empty axes.
func configGen() *rapid.Generator[Config] {
	return rapid.Custom[Config](func(t *rapid.T) Config {
		methods := nonEmptyStringSlice([]string{
			"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
		}).Draw(t, "methods")

		paths := nonEmptyStringSlice([]string{
			"/", "/api", "/login", "/admin", "/users", "/health", "/api/v2",
		}).Draw(t, "paths")

		auth := nonEmptyStringSlice([]string{
			"none", "bearer", "basic", "cookie",
		}).Draw(t, "auth")

		origins := nonEmptyStringSlice([]string{
			"omitted", "same-site", "cross-site",
		}).Draw(t, "origins")

		count := rapid.IntRange(1, 100).Draw(t, "count")
		seed := rapid.Int64().Draw(t, "seed")

		return Config{
			Methods: methods,
			Paths:   paths,
			Auth:    auth,
			Origins: origins,
			Count:   count,
			Seed:    seed,
		}
	})
}

// contains checks whether a string is in a slice.
func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// TestProperty_GeneratedRequestsInConfigSpace verifies that every generated
// request has Method, Path, Auth, and Origin drawn from the Config's axes.
func TestProperty_GeneratedRequestsInConfigSpace(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		cfg := configGen().Draw(t, "config")
		requests := Generate(cfg)

		if len(requests) != cfg.Count {
			t.Fatalf("Generate returned %d requests, want %d", len(requests), cfg.Count)
		}

		for i, req := range requests {
			if !contains(cfg.Methods, req.Method) {
				t.Fatalf("request[%d].Method=%q not in Config.Methods %v", i, req.Method, cfg.Methods)
			}
			if !contains(cfg.Paths, req.Path) {
				t.Fatalf("request[%d].Path=%q not in Config.Paths %v", i, req.Path, cfg.Paths)
			}
			if !contains(cfg.Auth, req.Auth) {
				t.Fatalf("request[%d].Auth=%q not in Config.Auth %v", i, req.Auth, cfg.Auth)
			}
			if !contains(cfg.Origins, req.Origin) {
				t.Fatalf("request[%d].Origin=%q not in Config.Origins %v", i, req.Origin, cfg.Origins)
			}
			if req.Headers == nil {
				t.Fatalf("request[%d].Headers is nil, want initialized map", i)
			}
		}
	})
}

// TestProperty_SingleElementAxes verifies that generation works correctly
// when each axis has exactly one element.
func TestProperty_SingleElementAxes(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		method := rapid.SampledFrom([]string{
			"GET", "POST", "PUT", "DELETE",
		}).Draw(t, "method")
		path := rapid.SampledFrom([]string{
			"/", "/api", "/test",
		}).Draw(t, "path")
		auth := rapid.SampledFrom([]string{
			"none", "bearer", "basic",
		}).Draw(t, "auth")
		origin := rapid.SampledFrom([]string{
			"omitted", "same-site", "cross-site",
		}).Draw(t, "origin")
		count := rapid.IntRange(1, 50).Draw(t, "count")
		seed := rapid.Int64().Draw(t, "seed")

		cfg := Config{
			Methods: []string{method},
			Paths:   []string{path},
			Auth:    []string{auth},
			Origins: []string{origin},
			Count:   count,
			Seed:    seed,
		}

		requests := Generate(cfg)

		if len(requests) != count {
			t.Fatalf("Generate returned %d requests, want %d", len(requests), count)
		}

		for i, req := range requests {
			if req.Method != method {
				t.Fatalf("request[%d].Method=%q, want %q", i, req.Method, method)
			}
			if req.Path != path {
				t.Fatalf("request[%d].Path=%q, want %q", i, req.Path, path)
			}
			if req.Auth != auth {
				t.Fatalf("request[%d].Auth=%q, want %q", i, req.Auth, auth)
			}
			if req.Origin != origin {
				t.Fatalf("request[%d].Origin=%q, want %q", i, req.Origin, origin)
			}
		}
	})
}
