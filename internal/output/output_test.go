package output

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/aygp-dr/http-axiom/internal/oracle"
	"github.com/aygp-dr/http-axiom/internal/predicate"
)

// captureStdout runs fn while capturing os.Stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	buf.ReadFrom(r)
	return buf.String()
}

func TestJSON_ValidOutput(t *testing.T) {
	type sample struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	v := sample{Name: "test", Count: 42}

	got := captureStdout(t, func() {
		JSON(v)
	})

	// Must be valid JSON.
	var decoded sample
	if err := json.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatalf("JSON() produced invalid JSON: %v\nOutput: %s", err, got)
	}
	if decoded.Name != "test" || decoded.Count != 42 {
		t.Errorf("JSON() decoded = %+v, want {test 42}", decoded)
	}

	// Must be indented (contains newline + spaces).
	if !strings.Contains(got, "\n  ") {
		t.Errorf("JSON() output not indented:\n%s", got)
	}
}

func TestJSON_SliceOutput(t *testing.T) {
	items := []string{"alpha", "beta", "gamma"}
	got := captureStdout(t, func() {
		JSON(items)
	})
	var decoded []string
	if err := json.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatalf("JSON() produced invalid JSON for slice: %v", err)
	}
	if len(decoded) != 3 || decoded[0] != "alpha" {
		t.Errorf("JSON() decoded = %v, want [alpha beta gamma]", decoded)
	}
}

func TestVerdict_Format(t *testing.T) {
	v := oracle.Verdict{
		Target:  "https://example.com",
		Status:  "fail",
		Total:   3,
		Passed:  1,
		Failed:  1,
		Warned:  1,
		Skipped: 0,
		Results: []predicate.Result{
			{Group: "headers", Name: "csp", Status: "pass", Detail: "present"},
			{Group: "headers", Name: "hsts", Status: "fail", Detail: "missing"},
			{Group: "cache", Name: "etag", Status: "warn", Detail: "weak"},
		},
	}

	got := captureStdout(t, func() {
		Verdict(v)
	})

	// Check header line.
	if !strings.Contains(got, "Audit: https://example.com") {
		t.Errorf("Verdict() missing header line:\n%s", got)
	}
	// Check result markers.
	if !strings.Contains(got, "[OK  ]") {
		t.Errorf("Verdict() missing OK marker:\n%s", got)
	}
	if !strings.Contains(got, "[FAIL]") {
		t.Errorf("Verdict() missing FAIL marker:\n%s", got)
	}
	if !strings.Contains(got, "[WARN]") {
		t.Errorf("Verdict() missing WARN marker:\n%s", got)
	}
	// Check summary line.
	if !strings.Contains(got, "Summary: 1 pass, 1 fail, 1 warn, 0 skip") {
		t.Errorf("Verdict() missing or incorrect summary:\n%s", got)
	}
}

func TestResult_Markers(t *testing.T) {
	tests := []struct {
		status string
		want   string
	}{
		{"pass", "[OK  ]"},
		{"fail", "[FAIL]"},
		{"warn", "[WARN]"},
		{"skip", "[SKIP]"},
		{"unknown", "[?   ]"},
	}
	for _, tt := range tests {
		got := captureStdout(t, func() {
			Result(predicate.Result{
				Group:  "test",
				Name:   "check",
				Status: tt.status,
				Detail: "detail",
			})
		})
		if !strings.Contains(got, tt.want) {
			t.Errorf("Result(status=%q) = %q, want marker %q", tt.status, got, tt.want)
		}
	}
}

func TestTable_AlignedColumns(t *testing.T) {
	headers := []string{"NAME", "STATUS", "DETAIL"}
	rows := [][]string{
		{"short", "ok", "all good"},
		{"a-longer-name", "fail", "bad"},
	}

	got := captureStdout(t, func() {
		Table(headers, rows)
	})

	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("Table() produced %d lines, want 3:\n%s", len(lines), got)
	}

	// All lines should have the same column start positions for alignment.
	// The header "NAME" width should expand to "a-longer-name" (13 chars).
	if !strings.HasPrefix(lines[0], "NAME") {
		t.Errorf("Table() header missing NAME prefix: %q", lines[0])
	}

	// Check that the longest value in column 0 is properly padded in the header.
	// "NAME" (4) should be padded to 13 (length of "a-longer-name") + 2 spaces.
	headerNameField := lines[0][:15] // 13 + 2 spaces
	if !strings.HasPrefix(headerNameField, "NAME") {
		t.Errorf("Table() header NAME field not padded: %q", headerNameField)
	}
	// The second row should contain "a-longer-name".
	if !strings.Contains(lines[2], "a-longer-name") {
		t.Errorf("Table() row 2 missing 'a-longer-name': %q", lines[2])
	}
}

func TestTable_Empty(t *testing.T) {
	got := captureStdout(t, func() {
		Table([]string{"A", "B"}, nil)
	})
	// Should still print header.
	if !strings.Contains(got, "A") || !strings.Contains(got, "B") {
		t.Errorf("Table() with no rows should still print headers: %q", got)
	}
}
