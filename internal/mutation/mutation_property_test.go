package mutation

import (
	"testing"

	"github.com/aygp-dr/http-axiom/internal/request"
	"pgregory.net/rapid"
)

// headerKeyGen generates realistic HTTP header keys matching X-Something pattern.
var headerKeyGen = rapid.StringMatching(`X-[A-Z][a-z]{2,10}`)

// headerValueGen generates plausible header values.
var headerValueGen = rapid.StringMatching(`[a-zA-Z0-9 /;=\-]{1,50}`)

// requestGen generates arbitrary request.Request values for property testing.
func requestGen() *rapid.Generator[request.Request] {
	return rapid.Custom[request.Request](func(t *rapid.T) request.Request {
		method := rapid.SampledFrom([]string{
			"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
		}).Draw(t, "method")

		path := rapid.SampledFrom([]string{
			"/", "/api", "/login", "/admin", "/users", "/health",
		}).Draw(t, "path")

		headerCount := rapid.IntRange(0, 10).Draw(t, "headerCount")
		headers := make(map[string]string, headerCount)
		for i := 0; i < headerCount; i++ {
			key := headerKeyGen.Draw(t, "headerKey")
			value := headerValueGen.Draw(t, "headerValue")
			headers[key] = value
		}

		auth := rapid.SampledFrom([]string{
			"", "bearer", "basic", "cookie",
		}).Draw(t, "auth")

		origin := rapid.SampledFrom([]string{
			"", "omitted", "same-site", "cross-site",
		}).Draw(t, "origin")

		repeat := rapid.IntRange(0, 10).Draw(t, "repeat")

		return request.Request{
			Method:  method,
			Path:    path,
			Headers: headers,
			Auth:    auth,
			Origin:  origin,
			Repeat:  repeat,
		}
	})
}

// deepCopyHeaders returns an independent copy of a headers map.
func deepCopyHeaders(h map[string]string) map[string]string {
	cp := make(map[string]string, len(h))
	for k, v := range h {
		cp[k] = v
	}
	return cp
}

// TestProperty_MutatorDoesNotModifyOriginal verifies that for ALL mutators
// in AllOperators(), applying the mutator to an arbitrary Request does not
// modify the original request's fields.
func TestProperty_MutatorDoesNotModifyOriginal(t *testing.T) {
	for _, opName := range AllOperators() {
		opName := opName // capture
		t.Run(opName, func(t *testing.T) {
			rapid.Check(t, func(t *rapid.T) {
				original := requestGen().Draw(t, "request")

				// Snapshot all fields before mutation.
				snapshotMethod := original.Method
				snapshotPath := original.Path
				snapshotAuth := original.Auth
				snapshotOrigin := original.Origin
				snapshotRepeat := original.Repeat
				snapshotHeaders := deepCopyHeaders(original.Headers)

				fn, ok := Get(opName)
				if !ok {
					t.Fatalf("Get(%q) returned false", opName)
				}

				// Apply the mutator. The returned value is the mutated
				// request; the original must remain untouched.
				_ = fn(original)

				// Verify scalar fields unchanged.
				if original.Method != snapshotMethod {
					t.Fatalf("Method mutated: %q -> %q", snapshotMethod, original.Method)
				}
				if original.Path != snapshotPath {
					t.Fatalf("Path mutated: %q -> %q", snapshotPath, original.Path)
				}
				if original.Auth != snapshotAuth {
					t.Fatalf("Auth mutated: %q -> %q", snapshotAuth, original.Auth)
				}
				if original.Origin != snapshotOrigin {
					t.Fatalf("Origin mutated: %q -> %q", snapshotOrigin, original.Origin)
				}
				if original.Repeat != snapshotRepeat {
					t.Fatalf("Repeat mutated: %d -> %d", snapshotRepeat, original.Repeat)
				}

				// Verify headers map unchanged.
				if len(original.Headers) != len(snapshotHeaders) {
					t.Fatalf("Headers length changed: %d -> %d", len(snapshotHeaders), len(original.Headers))
				}
				for k, v := range snapshotHeaders {
					if original.Headers[k] != v {
						t.Fatalf("Header %q changed: %q -> %q", k, v, original.Headers[k])
					}
				}
			})
		})
	}
}
