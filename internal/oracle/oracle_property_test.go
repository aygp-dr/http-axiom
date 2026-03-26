package oracle

import (
	"testing"

	"github.com/aygp-dr/http-axiom/internal/predicate"
	"github.com/aygp-dr/http-axiom/internal/request"
	"pgregory.net/rapid"
)

// resultGen generates an arbitrary predicate.Result with a valid status.
func resultGen() *rapid.Generator[predicate.Result] {
	return rapid.Custom[predicate.Result](func(t *rapid.T) predicate.Result {
		status := rapid.SampledFrom([]string{
			"pass", "fail", "warn", "skip",
		}).Draw(t, "status")
		group := rapid.SampledFrom([]string{
			"headers", "methods", "cross-origin", "cache", "state",
		}).Draw(t, "group")
		name := rapid.StringMatching(`[a-z\-]{3,20}`).Draw(t, "name")
		return predicate.Result{
			Group:  group,
			Name:   name,
			Status: status,
		}
	})
}

// TestProperty_JudgeArithmetic verifies that for arbitrary result slices,
// Total == Passed + Failed + Warned + Skipped.
func TestProperty_JudgeArithmetic(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		results := rapid.SliceOfN(resultGen(), 0, 50).Draw(t, "results")
		verdict := Judge("https://example.com", results)

		sum := verdict.Passed + verdict.Failed + verdict.Warned + verdict.Skipped
		if verdict.Total != sum {
			t.Fatalf("Total(%d) != Passed(%d) + Failed(%d) + Warned(%d) + Skipped(%d) = %d",
				verdict.Total, verdict.Passed, verdict.Failed, verdict.Warned, verdict.Skipped, sum)
		}

		if verdict.Total != len(results) {
			t.Fatalf("Total(%d) != len(results)(%d)", verdict.Total, len(results))
		}
	})
}

// headerKeyGen generates header keys for request generation.
var headerKeyGen = rapid.StringMatching(`X-[A-Z][a-z]{2,8}`)

// requestForShrinkGen generates requests with 0-15 headers for shrink testing.
func requestForShrinkGen() *rapid.Generator[request.Request] {
	return rapid.Custom[request.Request](func(t *rapid.T) request.Request {
		headerCount := rapid.IntRange(0, 15).Draw(t, "headerCount")
		headers := make(map[string]string, headerCount)
		for i := 0; i < headerCount; i++ {
			key := headerKeyGen.Draw(t, "headerKey")
			headers[key] = "value"
		}
		method := rapid.SampledFrom([]string{
			"GET", "POST", "PUT", "DELETE",
		}).Draw(t, "method")
		auth := rapid.SampledFrom([]string{
			"", "bearer", "basic", "cookie",
		}).Draw(t, "auth")
		origin := rapid.SampledFrom([]string{
			"", "same-site", "cross-site",
		}).Draw(t, "origin")
		repeat := rapid.IntRange(0, 5).Draw(t, "repeat")

		return request.Request{
			Method:  method,
			Path:    "/test",
			Headers: headers,
			Auth:    auth,
			Origin:  origin,
			Repeat:  repeat,
		}
	})
}

// TestProperty_ShrinkTerminatesAndPreservesFailure verifies that Shrink:
// 1. Returns (does not hang)
// 2. The shrunk request still produces a failure
// 3. The shrunk request has <= headers than the original (monotonic reduction)
func TestProperty_ShrinkTerminatesAndPreservesFailure(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		original := requestForShrinkGen().Draw(t, "request")

		// Threshold: fail when header count > threshold.
		// Use threshold in [0, len(headers)-1] so the original always fails.
		// If headers is empty, skip -- nothing to shrink.
		if len(original.Headers) == 0 {
			return
		}
		threshold := rapid.IntRange(0, len(original.Headers)-1).Draw(t, "threshold")

		checkFunc := func(req request.Request) (predicate.Result, error) {
			if len(req.Headers) > threshold {
				return predicate.Result{
					Group:  "headers",
					Name:   "header-count",
					Status: "fail",
					Detail: "too many headers",
				}, nil
			}
			return predicate.Result{Status: "pass"}, nil
		}

		cfg := ShrinkConfig{MaxAttempts: 100, Enabled: true}
		result := Shrink(cfg, original, checkFunc)

		// Property 1: Shrink returned (implicit -- we got here).

		// Property 2: Shrunk request still fails.
		checkResult, err := checkFunc(result.Shrunk)
		if err != nil {
			t.Fatalf("checkFunc returned error on shrunk request: %v", err)
		}
		if checkResult.Status != "fail" {
			t.Fatalf("shrunk request does not fail: status=%q, headers=%d, threshold=%d",
				checkResult.Status, len(result.Shrunk.Headers), threshold)
		}

		// Property 3: Monotonic reduction in header count.
		if len(result.Shrunk.Headers) > len(original.Headers) {
			t.Fatalf("shrunk headers(%d) > original headers(%d)",
				len(result.Shrunk.Headers), len(original.Headers))
		}
	})
}
