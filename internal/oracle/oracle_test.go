package oracle

import (
	"testing"

	"github.com/aygp-dr/http-axiom/internal/predicate"
	"github.com/aygp-dr/http-axiom/internal/request"
)

func TestJudge_CountsCorrectly(t *testing.T) {
	results := []predicate.Result{
		{Group: "headers", Name: "csp", Status: "pass", Detail: "ok"},
		{Group: "headers", Name: "hsts", Status: "fail", Detail: "missing"},
		{Group: "headers", Name: "samesite", Status: "warn", Detail: "no attr"},
		{Group: "headers", Name: "corp", Status: "skip", Detail: "skipped"},
		{Group: "cache", Name: "etag", Status: "pass", Detail: "ok"},
	}

	v := Judge("https://example.com", results)

	if v.Total != 5 {
		t.Errorf("Total = %d, want 5", v.Total)
	}
	if v.Passed != 2 {
		t.Errorf("Passed = %d, want 2", v.Passed)
	}
	if v.Failed != 1 {
		t.Errorf("Failed = %d, want 1", v.Failed)
	}
	if v.Warned != 1 {
		t.Errorf("Warned = %d, want 1", v.Warned)
	}
	if v.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1", v.Skipped)
	}
}

func TestJudge_FailStatusWhenAnyFailures(t *testing.T) {
	results := []predicate.Result{
		{Group: "headers", Name: "csp", Status: "pass"},
		{Group: "headers", Name: "hsts", Status: "fail"},
		{Group: "headers", Name: "corp", Status: "pass"},
	}

	v := Judge("https://example.com", results)

	if v.Status != "fail" {
		t.Errorf("Status = %q, want %q", v.Status, "fail")
	}
}

func TestJudge_PassStatusWhenNoFailures(t *testing.T) {
	results := []predicate.Result{
		{Group: "headers", Name: "csp", Status: "pass"},
		{Group: "headers", Name: "hsts", Status: "pass"},
		{Group: "headers", Name: "samesite", Status: "warn"},
		{Group: "headers", Name: "corp", Status: "skip"},
	}

	v := Judge("https://example.com", results)

	if v.Status != "pass" {
		t.Errorf("Status = %q, want %q", v.Status, "pass")
	}
}

func TestJudge_PassStatusWithEmptyResults(t *testing.T) {
	v := Judge("https://example.com", nil)

	if v.Status != "pass" {
		t.Errorf("Status = %q, want %q with no results", v.Status, "pass")
	}
	if v.Total != 0 {
		t.Errorf("Total = %d, want 0", v.Total)
	}
}

func TestJudge_AllFailing(t *testing.T) {
	results := []predicate.Result{
		{Group: "headers", Name: "csp", Status: "fail"},
		{Group: "headers", Name: "hsts", Status: "fail"},
		{Group: "headers", Name: "corp", Status: "fail"},
	}

	v := Judge("https://example.com", results)

	if v.Status != "fail" {
		t.Errorf("Status = %q, want %q", v.Status, "fail")
	}
	if v.Failed != 3 {
		t.Errorf("Failed = %d, want 3", v.Failed)
	}
	if v.Passed != 0 {
		t.Errorf("Passed = %d, want 0", v.Passed)
	}
}

func TestJudge_Target(t *testing.T) {
	v := Judge("https://test.example.com", nil)
	if v.Target != "https://test.example.com" {
		t.Errorf("Target = %q, want %q", v.Target, "https://test.example.com")
	}
}

func TestJudge_ResultsPreserved(t *testing.T) {
	results := []predicate.Result{
		{Group: "headers", Name: "csp", Status: "pass", Detail: "default-src 'self'"},
	}

	v := Judge("https://example.com", results)

	if len(v.Results) != 1 {
		t.Fatalf("Results length = %d, want 1", len(v.Results))
	}
	if v.Results[0].Detail != "default-src 'self'" {
		t.Errorf("Results[0].Detail = %q, want %q", v.Results[0].Detail, "default-src 'self'")
	}
}

func TestDefaultShrinkConfig(t *testing.T) {
	cfg := DefaultShrinkConfig()

	if !cfg.Enabled {
		t.Error("DefaultShrinkConfig().Enabled = false, want true")
	}
	if cfg.MaxAttempts <= 0 {
		t.Errorf("DefaultShrinkConfig().MaxAttempts = %d, want positive value", cfg.MaxAttempts)
	}
	if cfg.MaxAttempts != 50 {
		t.Errorf("DefaultShrinkConfig().MaxAttempts = %d, want 50", cfg.MaxAttempts)
	}
}

// ---------------------------------------------------------------------------
// Shrink tests
// ---------------------------------------------------------------------------

// TestShrink_RemovesHeadersToMinimum verifies that Shrink removes headers
// down to the minimum set that still causes a failure.
// The mock check function fails when the request has >2 headers.
func TestShrink_RemovesHeadersToMinimum(t *testing.T) {
	original := request.Request{
		Method: "GET",
		Path:   "/",
		Headers: map[string]string{
			"X-A": "1",
			"X-B": "2",
			"X-C": "3",
			"X-D": "4",
			"X-E": "5",
		},
	}

	// Fails when header count > 2.
	check := func(req request.Request) (predicate.Result, error) {
		if len(req.Headers) > 2 {
			return predicate.Result{
				Group:  "headers",
				Name:   "too-many-headers",
				Status: "fail",
				Detail: "more than 2 headers",
			}, nil
		}
		return predicate.Result{Status: "pass"}, nil
	}

	cfg := DefaultShrinkConfig()
	result := Shrink(cfg, original, check)

	if len(result.Shrunk.Headers) != 3 {
		t.Errorf("Shrunk headers count = %d, want 3 (minimum that still fails)", len(result.Shrunk.Headers))
	}
	if result.Steps == 0 {
		t.Error("Steps = 0, expected at least one shrink step")
	}
	if result.Steps != 2 {
		t.Errorf("Steps = %d, want 2 (removed 2 headers from 5 to 3)", result.Steps)
	}
	if result.Predicate != "too-many-headers" {
		t.Errorf("Predicate = %q, want %q", result.Predicate, "too-many-headers")
	}
	if result.Group != "headers" {
		t.Errorf("Group = %q, want %q", result.Group, "headers")
	}
}

// TestShrink_TerminatesWhenNothingToRemove verifies that Shrink stops
// when the request is already minimal and no simplification preserves failure.
func TestShrink_TerminatesWhenNothingToRemove(t *testing.T) {
	original := request.Request{
		Method: "GET",
		Path:   "/",
		Headers: map[string]string{
			"X-Required": "yes",
		},
	}

	// Fails only when X-Required header is present.
	check := func(req request.Request) (predicate.Result, error) {
		if _, ok := req.Headers["X-Required"]; ok {
			return predicate.Result{
				Group:  "headers",
				Name:   "required-header",
				Status: "fail",
			}, nil
		}
		return predicate.Result{Status: "pass"}, nil
	}

	cfg := DefaultShrinkConfig()
	result := Shrink(cfg, original, check)

	// The header can't be removed (failure goes away), and there's nothing
	// else to simplify, so steps should be 0.
	if result.Steps != 0 {
		t.Errorf("Steps = %d, want 0 (already minimal)", result.Steps)
	}
	if len(result.Shrunk.Headers) != 1 {
		t.Errorf("Shrunk headers count = %d, want 1", len(result.Shrunk.Headers))
	}
	if result.Shrunk.Headers["X-Required"] != "yes" {
		t.Error("X-Required header should be preserved")
	}
}

// TestShrink_MaxAttemptsLimitsIterations verifies that MaxAttempts bounds
// the number of outer loop iterations.
func TestShrink_MaxAttemptsLimitsIterations(t *testing.T) {
	original := request.Request{
		Method: "POST",
		Path:   "/",
		Headers: map[string]string{
			"X-A": "1",
			"X-B": "2",
			"X-C": "3",
			"X-D": "4",
			"X-E": "5",
			"X-F": "6",
			"X-G": "7",
			"X-H": "8",
		},
		Auth:   "bearer",
		Origin: "cross-site",
		Repeat: 5,
	}

	// Always fails, so every simplification will be accepted.
	check := func(req request.Request) (predicate.Result, error) {
		return predicate.Result{
			Group:  "headers",
			Name:   "always-fails",
			Status: "fail",
		}, nil
	}

	cfg := ShrinkConfig{MaxAttempts: 3, Enabled: true}
	result := Shrink(cfg, original, check)

	// With MaxAttempts=3, only 3 outer iterations run. Each iteration
	// makes one change (removes a header in this case), so steps <= 3.
	if result.Steps > 3 {
		t.Errorf("Steps = %d, want <= 3 with MaxAttempts=3", result.Steps)
	}
	if result.Steps == 0 {
		t.Error("Steps = 0, expected some shrink steps")
	}
}

// TestShrink_SimplifiesAuth verifies auth simplification down the ladder.
func TestShrink_SimplifiesAuth(t *testing.T) {
	original := request.Request{
		Method:  "GET",
		Path:    "/",
		Headers: map[string]string{},
		Auth:    "bearer",
	}

	// Fails regardless of auth.
	check := func(req request.Request) (predicate.Result, error) {
		return predicate.Result{
			Group:  "headers",
			Name:   "auth-test",
			Status: "fail",
		}, nil
	}

	cfg := DefaultShrinkConfig()
	result := Shrink(cfg, original, check)

	// Auth should be simplified from bearer -> basic -> cookie -> none (empty).
	if result.Shrunk.Auth != "" {
		t.Errorf("Shrunk.Auth = %q, want empty (fully simplified)", result.Shrunk.Auth)
	}
	if result.Steps < 1 {
		t.Errorf("Steps = %d, want >= 1", result.Steps)
	}
}

// TestShrink_SimplifiesOrigin verifies origin simplification.
func TestShrink_SimplifiesOrigin(t *testing.T) {
	original := request.Request{
		Method:  "GET",
		Path:    "/",
		Headers: map[string]string{},
		Origin:  "cross-site",
	}

	// Fails regardless of origin.
	check := func(req request.Request) (predicate.Result, error) {
		return predicate.Result{
			Group:  "cross-origin",
			Name:   "origin-test",
			Status: "fail",
		}, nil
	}

	cfg := DefaultShrinkConfig()
	result := Shrink(cfg, original, check)

	if result.Shrunk.Origin != "" {
		t.Errorf("Shrunk.Origin = %q, want empty (fully simplified)", result.Shrunk.Origin)
	}
}

// TestShrink_SimplifiesMethod verifies method simplification to GET.
func TestShrink_SimplifiesMethod(t *testing.T) {
	original := request.Request{
		Method:  "DELETE",
		Path:    "/",
		Headers: map[string]string{},
	}

	// Fails regardless of method.
	check := func(req request.Request) (predicate.Result, error) {
		return predicate.Result{
			Group:  "methods",
			Name:   "method-test",
			Status: "fail",
		}, nil
	}

	cfg := DefaultShrinkConfig()
	result := Shrink(cfg, original, check)

	if result.Shrunk.Method != "GET" {
		t.Errorf("Shrunk.Method = %q, want GET", result.Shrunk.Method)
	}
}

// TestShrink_ReducesRepeat verifies repeat count reduction.
func TestShrink_ReducesRepeat(t *testing.T) {
	original := request.Request{
		Method:  "GET",
		Path:    "/",
		Headers: map[string]string{},
		Repeat:  5,
	}

	// Fails when repeat >= 2.
	check := func(req request.Request) (predicate.Result, error) {
		if req.Repeat >= 2 {
			return predicate.Result{
				Group:  "state",
				Name:   "repeat-test",
				Status: "fail",
			}, nil
		}
		return predicate.Result{Status: "pass"}, nil
	}

	cfg := DefaultShrinkConfig()
	result := Shrink(cfg, original, check)

	if result.Shrunk.Repeat != 2 {
		t.Errorf("Shrunk.Repeat = %d, want 2 (minimum that still fails)", result.Shrunk.Repeat)
	}
}

// TestShrink_OriginalDoesNotFail verifies that if the original request
// does not fail, Shrink returns it unchanged with 0 steps.
func TestShrink_OriginalDoesNotFail(t *testing.T) {
	original := request.Request{
		Method:  "GET",
		Path:    "/",
		Headers: map[string]string{"X-A": "1"},
	}

	check := func(req request.Request) (predicate.Result, error) {
		return predicate.Result{Status: "pass"}, nil
	}

	cfg := DefaultShrinkConfig()
	result := Shrink(cfg, original, check)

	if result.Steps != 0 {
		t.Errorf("Steps = %d, want 0 (original doesn't fail)", result.Steps)
	}
	if len(result.Shrunk.Headers) != 1 {
		t.Errorf("Shrunk headers should be unchanged")
	}
}

// TestShrink_FullSimplification verifies combined simplification across
// all dimensions when everything can be stripped.
func TestShrink_FullSimplification(t *testing.T) {
	original := request.Request{
		Method: "POST",
		Path:   "/api/test",
		Headers: map[string]string{
			"X-A": "1",
			"X-B": "2",
		},
		Auth:   "bearer",
		Origin: "cross-site",
		Repeat: 3,
	}

	// Always fails: everything can be simplified.
	check := func(req request.Request) (predicate.Result, error) {
		return predicate.Result{
			Group:  "headers",
			Name:   "always-fails",
			Status: "fail",
		}, nil
	}

	cfg := DefaultShrinkConfig()
	result := Shrink(cfg, original, check)

	if len(result.Shrunk.Headers) != 0 {
		t.Errorf("Shrunk headers = %d, want 0 (all removable)", len(result.Shrunk.Headers))
	}
	if result.Shrunk.Auth != "" {
		t.Errorf("Shrunk.Auth = %q, want empty", result.Shrunk.Auth)
	}
	if result.Shrunk.Origin != "" {
		t.Errorf("Shrunk.Origin = %q, want empty", result.Shrunk.Origin)
	}
	if result.Shrunk.Method != "GET" {
		t.Errorf("Shrunk.Method = %q, want GET", result.Shrunk.Method)
	}
	if result.Shrunk.Repeat > 1 {
		t.Errorf("Shrunk.Repeat = %d, want <= 1 (fully simplified)", result.Shrunk.Repeat)
	}
	if result.Steps < 1 {
		t.Errorf("Steps = %d, want >= 1", result.Steps)
	}
}

// TestShrink_LocalMinimum_GreedyMisses2D demonstrates the greedy shrinker's
// known limitation: it cannot find the global minimum when the failure
// surface requires simultaneous changes across two dimensions.
//
// The CheckFunc defines a failure region shaped like two disconnected islands:
//
//	Island 1: headers >= 2 AND auth == "bearer"  (complex)
//	Island 2: headers == 0 AND auth == ""         (simple, global minimum)
//
// Starting from (headers=3, auth="bearer"), the greedy shrinker:
//   - Can remove headers: (2, bearer) still fails → accepted
//   - Cannot remove another header: (1, bearer) passes → rejected
//   - Cannot simplify auth: (2, basic) passes → rejected
//   - Gets stuck at (2, bearer) — a local minimum
//
// The global minimum (0, "") is reachable only by simultaneously removing
// all headers AND simplifying auth, which the single-axis strategy never tries.
//
// This test documents the limitation identified by TLA+ spec
// formal/ShrinkTermination.tla (C-013 local-minimum witness).
func TestShrink_LocalMinimum_GreedyMisses2D(t *testing.T) {
	original := request.Request{
		Method: "GET",
		Path:   "/",
		Headers: map[string]string{
			"X-A": "1",
			"X-B": "2",
			"X-C": "3",
		},
		Auth: "bearer",
	}

	// Two failure islands: (headers>=2, auth=bearer) OR (headers=0, auth="")
	check := func(req request.Request) (predicate.Result, error) {
		h := len(req.Headers)
		a := req.Auth

		// Island 1: complex (the starting point)
		if h >= 2 && a == "bearer" {
			return predicate.Result{
				Group: "test", Name: "2d-minimum", Status: "fail",
				Detail: "island1",
			}, nil
		}
		// Island 2: simple (the global minimum)
		if h == 0 && a == "" {
			return predicate.Result{
				Group: "test", Name: "2d-minimum", Status: "fail",
				Detail: "island2",
			}, nil
		}
		// Valley between islands: passes
		return predicate.Result{Status: "pass"}, nil
	}

	cfg := DefaultShrinkConfig()
	result := Shrink(cfg, original, check)

	// The greedy shrinker CANNOT reach Island 2.
	// It will be stuck at the local minimum on Island 1.
	if len(result.Shrunk.Headers) == 0 && result.Shrunk.Auth == "" {
		t.Fatal("Greedy shrinker reached global minimum — " +
			"the local minimum limitation is not demonstrated")
	}

	// Verify it IS stuck at the local minimum: headers=2, auth=bearer
	if len(result.Shrunk.Headers) != 2 {
		t.Errorf("Expected local minimum with 2 headers, got %d", len(result.Shrunk.Headers))
	}
	if result.Shrunk.Auth != "bearer" {
		t.Errorf("Expected local minimum with auth=bearer, got %q", result.Shrunk.Auth)
	}

	// Verify the global minimum EXISTS and is simpler
	globalMin := request.Request{Method: "GET", Path: "/", Headers: map[string]string{}}
	globalResult, _ := check(globalMin)
	if globalResult.Status != "fail" {
		t.Fatal("Global minimum (headers=0, auth='') should fail but doesn't")
	}

	t.Logf("Local minimum: headers=%d auth=%q", len(result.Shrunk.Headers), result.Shrunk.Auth)
	t.Logf("Global minimum: headers=0 auth='' (unreachable by greedy shrinker)")
	t.Logf("Greedy shrinker stuck at local minimum after %d steps", result.Steps)
}

// TestCopyRequest verifies deep copy of request headers.
func TestCopyRequest(t *testing.T) {
	original := request.Request{
		Method: "GET",
		Path:   "/",
		Headers: map[string]string{
			"X-A": "1",
			"X-B": "2",
		},
		Auth:   "bearer",
		Origin: "cross-site",
	}

	cp := copyRequest(original)

	// Modify the copy's headers.
	cp.Headers["X-C"] = "3"
	delete(cp.Headers, "X-A")

	// Original should be unchanged.
	if _, ok := original.Headers["X-A"]; !ok {
		t.Error("Modifying copy affected original: X-A deleted")
	}
	if _, ok := original.Headers["X-C"]; ok {
		t.Error("Modifying copy affected original: X-C appeared")
	}
	if len(original.Headers) != 2 {
		t.Errorf("Original headers = %d, want 2", len(original.Headers))
	}
}
