package oracle

import (
	"testing"

	"github.com/aygp-dr/http-axiom/internal/predicate"
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
