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

	"github.com/aygp-dr/http-axiom/internal/request"
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
type Mutator func(request.Request) request.Request

// copyHeaders returns a shallow copy of the headers map.
func copyHeaders(h map[string]string) map[string]string {
	cp := make(map[string]string, len(h))
	for k, v := range h {
		cp[k] = v
	}
	return cp
}

// methodRotateMutator cycles the method to the next in the standard list.
func methodRotateMutator(r request.Request) request.Request {
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

// headerOmitMutator removes all custom headers from the request.
func headerOmitMutator(r request.Request) request.Request {
	// Deep copy before clearing — the caller's map must not be affected.
	r.Headers = make(map[string]string)
	return r
}

// headerCorruptMutator corrupts header values with invalid bytes.
func headerCorruptMutator(r request.Request) request.Request {
	r.Headers = copyHeaders(r.Headers)
	for k := range r.Headers {
		r.Headers[k] = "\x00\xff" + r.Headers[k]
	}
	return r
}

// headerForgeMutator injects common forged headers.
func headerForgeMutator(r request.Request) request.Request {
	r.Headers = copyHeaders(r.Headers)
	r.Headers["X-Forwarded-For"] = "127.0.0.1"
	r.Headers["X-Real-IP"] = "127.0.0.1"
	r.Headers["X-Original-URL"] = "/admin"
	return r
}

// originCrossSiteMutator sets a cross-origin Origin header.
func originCrossSiteMutator(r request.Request) request.Request {
	r.Headers = copyHeaders(r.Headers)
	r.Origin = "cross-site"
	r.Headers["Origin"] = "https://evil.example.com"
	return r
}

// originSameSiteMutator sets a same-site Origin header.
func originSameSiteMutator(r request.Request) request.Request {
	r.Headers = copyHeaders(r.Headers)
	r.Origin = "same-site"
	return r
}

// repeatNMutator sets the request to be replayed N times.
func repeatNMutator(r request.Request) request.Request {
	if r.Repeat < 2 {
		r.Repeat = 3
	}
	return r
}

// repeatConcurrentMutator sets the request to be replayed concurrently.
func repeatConcurrentMutator(r request.Request) request.Request {
	if r.Repeat < 2 {
		r.Repeat = 5
	}
	// Mark as concurrent via header marker.
	r.Headers = copyHeaders(r.Headers)
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
		return methodRotateMutator, true
	case HeaderOmit:
		return headerOmitMutator, true
	case HeaderCorrupt:
		return headerCorruptMutator, true
	case HeaderForge:
		return headerForgeMutator, true
	case OriginCrossSite:
		return originCrossSiteMutator, true
	case OriginSameSite:
		return originSameSiteMutator, true
	case RepeatN:
		return repeatNMutator, true
	case RepeatConcurrent:
		return repeatConcurrentMutator, true
	default:
		return nil, false
	}
}

// Apply runs a sequence of named mutators on a request.
func Apply(r request.Request, operators []string) request.Request {
	for _, name := range operators {
		if fn, ok := Get(name); ok {
			r = fn(r)
		}
	}
	return r
}
