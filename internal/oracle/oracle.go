// Package oracle reports pass/fail verdicts and minimizes failing
// test cases using shrinking.
package oracle

import (
	"github.com/aygp-dr/http-axiom/internal/predicate"
	"github.com/aygp-dr/http-axiom/internal/request"
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

// ShrinkResult captures the outcome of minimizing a failing request.
type ShrinkResult struct {
	Original  request.Request `json:"original"`
	Shrunk    request.Request `json:"shrunk"`
	Steps     int             `json:"steps"`
	Predicate string          `json:"predicate"`
	Group     string          `json:"group"`
}

// CheckFunc tests whether a request still triggers a failure.
// It should return a predicate.Result with Status "fail" if the failure
// is still reproducible.
type CheckFunc func(req request.Request) (predicate.Result, error)

// Shrink minimizes a failing request by progressively simplifying it.
// Each step removes one attribute; if the failure persists, the simplification
// is kept. Returns the minimal request that still fails.
//
// Shrink operations form a lattice over request complexity:
//  1. Remove headers one at a time
//  2. Simplify auth: bearer -> basic -> cookie -> none
//  3. Simplify origin: cross-site -> same-site -> omitted
//  4. Simplify method: current -> GET
//  5. Reduce repeat count: N -> N-1 -> ... -> 1
func Shrink(cfg ShrinkConfig, original request.Request, check CheckFunc) ShrinkResult {
	current := original
	steps := 0
	var lastResult predicate.Result

	// Verify the original actually fails before shrinking.
	initResult, err := check(original)
	if err != nil || initResult.Status != "fail" {
		return ShrinkResult{
			Original:  original,
			Shrunk:    original,
			Steps:     0,
			Predicate: initResult.Name,
			Group:     initResult.Group,
		}
	}
	lastResult = initResult

	for attempt := 0; attempt < cfg.MaxAttempts; attempt++ {
		changed := false

		// 1. Try removing each header one at a time.
		// Collect keys for deterministic iteration order.
		headerKeys := sortedKeys(current.Headers)
		for _, key := range headerKeys {
			candidate := copyRequest(current)
			delete(candidate.Headers, key)
			result, cerr := check(candidate)
			if cerr == nil && result.Status == "fail" {
				current = candidate
				lastResult = result
				steps++
				changed = true
				break // restart outer loop with simplified request
			}
		}
		if changed {
			continue
		}

		// 2. Try simplifying auth down the ladder.
		authSimplified := shrinkAuth(current, check)
		if authSimplified != nil {
			current = authSimplified.req
			lastResult = authSimplified.result
			steps++
			continue
		}

		// 3. Try simplifying origin down the ladder.
		originSimplified := shrinkOrigin(current, check)
		if originSimplified != nil {
			current = originSimplified.req
			lastResult = originSimplified.result
			steps++
			continue
		}

		// 4. Try simplifying method to GET.
		if current.Method != "" && current.Method != "GET" {
			candidate := copyRequest(current)
			candidate.Method = "GET"
			result, cerr := check(candidate)
			if cerr == nil && result.Status == "fail" {
				current = candidate
				lastResult = result
				steps++
				continue
			}
		}

		// 5. Try reducing repeat count.
		if current.Repeat > 1 {
			candidate := copyRequest(current)
			candidate.Repeat--
			result, cerr := check(candidate)
			if cerr == nil && result.Status == "fail" {
				current = candidate
				lastResult = result
				steps++
				continue
			}
		}

		// Nothing more to shrink; we are at the minimal failing request.
		break
	}

	return ShrinkResult{
		Original:  original,
		Shrunk:    current,
		Steps:     steps,
		Predicate: lastResult.Name,
		Group:     lastResult.Group,
	}
}

// shrinkStep is an internal type for returning a successful shrink step.
type shrinkStep struct {
	req    request.Request
	result predicate.Result
}

// shrinkAuth tries to simplify the auth field down the lattice:
// bearer -> basic -> cookie -> none (empty string).
func shrinkAuth(current request.Request, check CheckFunc) *shrinkStep {
	authLadder := []string{"bearer", "basic", "cookie", ""}
	currentIdx := -1
	for i, a := range authLadder {
		if current.Auth == a {
			currentIdx = i
			break
		}
	}
	// If current auth is not in ladder or already at simplest, nothing to do.
	if currentIdx < 0 {
		// Unknown auth value; try simplifying to empty.
		candidate := copyRequest(current)
		candidate.Auth = ""
		result, err := check(candidate)
		if err == nil && result.Status == "fail" {
			return &shrinkStep{req: candidate, result: result}
		}
		return nil
	}

	// Try each simpler level.
	for i := currentIdx + 1; i < len(authLadder); i++ {
		candidate := copyRequest(current)
		candidate.Auth = authLadder[i]
		result, err := check(candidate)
		if err == nil && result.Status == "fail" {
			return &shrinkStep{req: candidate, result: result}
		}
	}
	return nil
}

// shrinkOrigin tries to simplify the origin field down the lattice:
// cross-site -> same-site -> omitted (empty string).
func shrinkOrigin(current request.Request, check CheckFunc) *shrinkStep {
	originLadder := []string{"cross-site", "same-site", ""}
	currentIdx := -1
	for i, o := range originLadder {
		if current.Origin == o {
			currentIdx = i
			break
		}
	}
	if currentIdx < 0 {
		candidate := copyRequest(current)
		candidate.Origin = ""
		result, err := check(candidate)
		if err == nil && result.Status == "fail" {
			return &shrinkStep{req: candidate, result: result}
		}
		return nil
	}

	for i := currentIdx + 1; i < len(originLadder); i++ {
		candidate := copyRequest(current)
		candidate.Origin = originLadder[i]
		result, err := check(candidate)
		if err == nil && result.Status == "fail" {
			return &shrinkStep{req: candidate, result: result}
		}
	}
	return nil
}

// copyRequest returns a deep copy of a request, duplicating the Headers map.
func copyRequest(r request.Request) request.Request {
	cp := r
	cp.Headers = make(map[string]string, len(r.Headers))
	for k, v := range r.Headers {
		cp.Headers[k] = v
	}
	return cp
}

// sortedKeys returns the keys of a map in sorted order for deterministic iteration.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Simple insertion sort (no sort import needed for stdlib-only constraint).
	for i := 1; i < len(keys); i++ {
		j := i
		for j > 0 && keys[j-1] > keys[j] {
			keys[j-1], keys[j] = keys[j], keys[j-1]
			j--
		}
	}
	return keys
}
