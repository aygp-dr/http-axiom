// Package mutation applies mutation operators to HTTP requests.
//
// Vocabulary:
//   - method-rotate:      cycle through HTTP methods
//   - header-omit:        remove required headers
//   - header-corrupt:     malform header values
//   - header-forge:       inject forged headers
//   - origin-cross-site:  set cross-origin Origin header
//   - origin-same-site:   set same-site Origin header
//   - repeat-N:           replay request N times
//   - repeat-concurrent:  replay request concurrently
package mutation

import (
	"net/http"

	"github.com/aygp-dr/http-axiom/internal/generator"
)

// Operator names.
const (
	MethodRotate     = "method-rotate"
	HeaderOmit       = "header-omit"
	HeaderCorrupt    = "header-corrupt"
	HeaderForge      = "header-forge"
	OriginCrossSite  = "origin-cross-site"
	OriginSameSite   = "origin-same-site"
	RepeatN          = "repeat-N"
	RepeatConcurrent = "repeat-concurrent"
)

// AllOperators returns every available mutation operator name.
func AllOperators() []string {
	return []string{
		MethodRotate,
		HeaderOmit, HeaderCorrupt, HeaderForge,
		OriginCrossSite, OriginSameSite,
		RepeatN, RepeatConcurrent,
	}
}

// Mutator is a function that transforms a request.
type Mutator func(generator.Request) generator.Request

// MethodRotateMutator cycles the method to the next in the standard list.
func MethodRotateMutator(r generator.Request) generator.Request {
	methods := []string{
		http.MethodGet, http.MethodPost, http.MethodPut,
		http.MethodDelete, http.MethodPatch, http.MethodHead,
		http.MethodOptions,
	}
	for i, m := range methods {
		if m == r.Method {
			r.Method = methods[(i+1)%len(methods)]
			return r
		}
	}
	r.Method = http.MethodGet
	return r
}

// HeaderOmitMutator removes all custom headers from the request.
func HeaderOmitMutator(r generator.Request) generator.Request {
	r.Headers = make(map[string]string)
	return r
}

// HeaderCorruptMutator corrupts header values with invalid bytes.
func HeaderCorruptMutator(r generator.Request) generator.Request {
	for k := range r.Headers {
		r.Headers[k] = "\x00\xff" + r.Headers[k]
	}
	return r
}

// HeaderForgeMutator injects common forged headers.
func HeaderForgeMutator(r generator.Request) generator.Request {
	r.Headers["X-Forwarded-For"] = "127.0.0.1"
	r.Headers["X-Real-IP"] = "127.0.0.1"
	r.Headers["X-Original-URL"] = "/admin"
	return r
}

// OriginCrossSiteMutator sets a cross-origin Origin header.
func OriginCrossSiteMutator(r generator.Request) generator.Request {
	r.Origin = "cross-site"
	r.Headers["Origin"] = "https://evil.example.com"
	return r
}

// OriginSameSiteMutator sets a same-site Origin header.
func OriginSameSiteMutator(r generator.Request) generator.Request {
	r.Origin = "same-site"
	return r
}

// RepeatNMutator sets the request to be replayed N times.
func RepeatNMutator(r generator.Request) generator.Request {
	if r.Repeat < 2 {
		r.Repeat = 3
	}
	return r
}

// RepeatConcurrentMutator sets the request to be replayed concurrently.
func RepeatConcurrentMutator(r generator.Request) generator.Request {
	if r.Repeat < 2 {
		r.Repeat = 5
	}
	// Mark as concurrent via header marker.
	if r.Headers == nil {
		r.Headers = make(map[string]string)
	}
	r.Headers["X-Hax-Concurrent"] = "true"
	return r
}

// Get returns the Mutator for a named operator.
func Get(name string) (Mutator, bool) {
	switch name {
	case MethodRotate:
		return MethodRotateMutator, true
	case HeaderOmit:
		return HeaderOmitMutator, true
	case HeaderCorrupt:
		return HeaderCorruptMutator, true
	case HeaderForge:
		return HeaderForgeMutator, true
	case OriginCrossSite:
		return OriginCrossSiteMutator, true
	case OriginSameSite:
		return OriginSameSiteMutator, true
	case RepeatN:
		return RepeatNMutator, true
	case RepeatConcurrent:
		return RepeatConcurrentMutator, true
	default:
		return nil, false
	}
}

// Apply runs a sequence of named mutators on a request.
func Apply(r generator.Request, operators []string) generator.Request {
	for _, name := range operators {
		if fn, ok := Get(name); ok {
			r = fn(r)
		}
	}
	return r
}
