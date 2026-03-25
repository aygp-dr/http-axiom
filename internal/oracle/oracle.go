// Package oracle reports pass/fail verdicts and minimizes failing
// test cases using shrinking.
package oracle

import (
	"github.com/aygp-dr/http-axiom/internal/predicate"
)

// Verdict summarises the outcome of a test run.
type Verdict struct {
	Target      string             `json:"target"`
	Status      string             `json:"status"` // pass, fail
	Total       int                `json:"total"`
	Passed      int                `json:"passed"`
	Failed      int                `json:"failed"`
	Warned      int                `json:"warned"`
	Skipped     int                `json:"skipped"`
	Results     []predicate.Result `json:"results"`
	Shrunk      bool               `json:"shrunk,omitempty"`
	ShrinkSteps int                `json:"shrink_steps,omitempty"`
}

// Judge evaluates a set of predicate results into a verdict.
func Judge(target string, results []predicate.Result) Verdict {
	v := Verdict{
		Target:  target,
		Results: results,
		Total:   len(results),
	}

	for _, r := range results {
		switch r.Status {
		case "pass":
			v.Passed++
		case "fail":
			v.Failed++
		case "warn":
			v.Warned++
		case "skip":
			v.Skipped++
		}
	}

	if v.Failed > 0 {
		v.Status = "fail"
	} else {
		v.Status = "pass"
	}

	return v
}

// ShrinkConfig controls the shrinking process.
type ShrinkConfig struct {
	MaxAttempts int
	Enabled     bool
}

// DefaultShrinkConfig returns the default shrink configuration.
func DefaultShrinkConfig() ShrinkConfig {
	return ShrinkConfig{
		MaxAttempts: 50,
		Enabled:     true,
	}
}
