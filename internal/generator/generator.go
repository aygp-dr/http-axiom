// Package generator produces HTTP request variants from a cartesian
// product of axes: method × path × headers × auth × origin × repeat.
package generator

import (
	"math/rand"
	"net/http"

	"github.com/aygp-dr/http-axiom/internal/request"
)

// Config controls request generation.
type Config struct {
	Methods []string
	Paths   []string
	Auth    []string
	Origins []string
	Count   int
	Seed    int64
}

// DefaultConfig returns a sensible starting configuration.
func DefaultConfig() Config {
	return Config{
		Methods: []string{
			http.MethodGet, http.MethodPost, http.MethodPut,
			http.MethodDelete, http.MethodPatch, http.MethodHead,
			http.MethodOptions,
		},
		Paths:   []string{"/"},
		Auth:    []string{"none"},
		Origins: []string{"omitted"},
		Count:   10,
		Seed:    0,
	}
}

// Generate produces request variants by sampling from the config space.
func Generate(cfg Config) []request.Request {
	rng := rand.New(rand.NewSource(cfg.Seed))
	requests := make([]request.Request, 0, cfg.Count)

	for i := 0; i < cfg.Count; i++ {
		r := request.Request{
			Method:  cfg.Methods[rng.Intn(len(cfg.Methods))],
			Path:    cfg.Paths[rng.Intn(len(cfg.Paths))],
			Auth:    cfg.Auth[rng.Intn(len(cfg.Auth))],
			Origin:  cfg.Origins[rng.Intn(len(cfg.Origins))],
			Headers: make(map[string]string),
		}
		requests = append(requests, r)
	}

	return requests
}
