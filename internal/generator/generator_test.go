package generator

import (
	"net/http"
	"testing"
)

func TestGenerate_ReturnsConfigCount(t *testing.T) {
	for _, count := range []int{0, 1, 5, 20, 100} {
		cfg := DefaultConfig()
		cfg.Count = count
		got := Generate(cfg)
		if len(got) != count {
			t.Errorf("Generate(count=%d) returned %d items, want %d", count, len(got), count)
		}
	}
}

func TestGenerate_SeedDeterminism(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Seed = 42
	cfg.Count = 50

	first := Generate(cfg)
	second := Generate(cfg)

	if len(first) != len(second) {
		t.Fatalf("different lengths: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].Method != second[i].Method {
			t.Errorf("index %d: method %q != %q", i, first[i].Method, second[i].Method)
		}
		if first[i].Path != second[i].Path {
			t.Errorf("index %d: path %q != %q", i, first[i].Path, second[i].Path)
		}
		if first[i].Auth != second[i].Auth {
			t.Errorf("index %d: auth %q != %q", i, first[i].Auth, second[i].Auth)
		}
		if first[i].Origin != second[i].Origin {
			t.Errorf("index %d: origin %q != %q", i, first[i].Origin, second[i].Origin)
		}
	}
}

func TestGenerate_DifferentSeedsProduceDifferentOutput(t *testing.T) {
	cfg1 := DefaultConfig()
	cfg1.Seed = 1
	cfg1.Count = 20

	cfg2 := DefaultConfig()
	cfg2.Seed = 2
	cfg2.Count = 20

	first := Generate(cfg1)
	second := Generate(cfg2)

	allSame := true
	for i := range first {
		if first[i].Method != second[i].Method {
			allSame = false
			break
		}
	}
	if allSame {
		t.Error("different seeds produced identical output")
	}
}

func TestGenerate_MethodsDrawnFromConfig(t *testing.T) {
	cfg := Config{
		Methods: []string{http.MethodGet, http.MethodPost},
		Paths:   []string{"/a"},
		Auth:    []string{"none"},
		Origins: []string{"omitted"},
		Count:   100,
		Seed:    99,
	}

	allowed := map[string]bool{http.MethodGet: true, http.MethodPost: true}

	for _, r := range Generate(cfg) {
		if !allowed[r.Method] {
			t.Errorf("unexpected method %q", r.Method)
		}
	}
}

func TestGenerate_PathsDrawnFromConfig(t *testing.T) {
	cfg := Config{
		Methods: []string{http.MethodGet},
		Paths:   []string{"/foo", "/bar", "/baz"},
		Auth:    []string{"none"},
		Origins: []string{"omitted"},
		Count:   100,
		Seed:    7,
	}

	allowed := map[string]bool{"/foo": true, "/bar": true, "/baz": true}
	seen := map[string]bool{}

	for _, r := range Generate(cfg) {
		if !allowed[r.Path] {
			t.Errorf("unexpected path %q", r.Path)
		}
		seen[r.Path] = true
	}

	// With 100 samples across 3 paths, we should see all of them.
	for p := range allowed {
		if !seen[p] {
			t.Errorf("path %q never generated in 100 samples", p)
		}
	}
}

func TestGenerate_HeadersInitialized(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Count = 5
	for _, r := range Generate(cfg) {
		if r.Headers == nil {
			t.Error("Headers map is nil, expected initialized empty map")
		}
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Count != 10 {
		t.Errorf("default Count = %d, want 10", cfg.Count)
	}
	if len(cfg.Methods) != 7 {
		t.Errorf("default Methods has %d items, want 7", len(cfg.Methods))
	}
	if cfg.Seed != 0 {
		t.Errorf("default Seed = %d, want 0", cfg.Seed)
	}
}
