package predicate

import (
	"net/http"
	"strings"
)

// CacheGroup returns the HTTP caching predicate group.
func CacheGroup() Group {
	return Group{
		Name: GroupCache,
		Predicates: []NamedPred{
			{Name: "etag", Fn: checkETag, Type: TypeUniversal},
			{Name: "no-store", Fn: checkNoStore, Type: TypeUniversal},
			{Name: "vary", Fn: checkVary, Type: TypeUniversal},
			{Name: "304", Fn: check304, Type: TypeSequential},
		},
	}
}

func checkETag(resp *http.Response) Result {
	val := resp.Header.Get("ETag")
	if val != "" {
		return Result{GroupCache, "etag", "pass", val}
	}
	return Result{GroupCache, "etag", "skip", "no ETag header"}
}

func checkNoStore(resp *http.Response) Result {
	cc := resp.Header.Get("Cache-Control")
	if strings.Contains(cc, "no-store") {
		return Result{GroupCache, "no-store", "pass", cc}
	}
	if cc == "" {
		return Result{GroupCache, "no-store", "warn", "no Cache-Control header"}
	}
	return Result{GroupCache, "no-store", "skip", cc}
}

func checkVary(resp *http.Response) Result {
	val := resp.Header.Get("Vary")
	if val != "" {
		return Result{GroupCache, "vary", "pass", val}
	}
	return Result{GroupCache, "vary", "skip", "no Vary header"}
}

func check304(_ *http.Response) Result {
	return Result{GroupCache, "304", "skip", "requires conditional request test"}
}
