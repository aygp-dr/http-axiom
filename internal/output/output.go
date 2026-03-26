// Package output provides presentation helpers for CLI output.
// It consolidates repeated JSON-encoding, verdict-table, and
// tabular-output patterns from the top-level command handlers.
package output

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/aygp-dr/http-axiom/internal/oracle"
	"github.com/aygp-dr/http-axiom/internal/predicate"
)

// JSON writes any value as indented JSON to stdout.
func JSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

// Verdict renders an oracle.Verdict as a table to stdout.
func Verdict(v oracle.Verdict) {
	fmt.Printf("Audit: %s\n\n", v.Target)
	for _, r := range v.Results {
		Result(r)
	}
	fmt.Printf("\nSummary: %d pass, %d fail, %d warn, %d skip\n",
		v.Passed, v.Failed, v.Warned, v.Skipped)
}

// Result renders a single predicate.Result as a table row.
func Result(r predicate.Result) {
	marker := "?"
	switch r.Status {
	case "pass":
		marker = "OK"
	case "fail":
		marker = "FAIL"
	case "warn":
		marker = "WARN"
	case "skip":
		marker = "SKIP"
	}
	fmt.Printf("  [%-4s] %-14s %-24s %s\n", marker, r.Group, r.Name, r.Detail)
}

// Table renders a simple table with headers and rows.
func Table(headers []string, rows [][]string) {
	// Calculate column widths.
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}
	// Print header.
	for i, h := range headers {
		fmt.Printf("%-*s  ", widths[i], h)
	}
	fmt.Println()
	// Print rows.
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) {
				fmt.Printf("%-*s  ", widths[i], cell)
			}
		}
		fmt.Println()
	}
}
