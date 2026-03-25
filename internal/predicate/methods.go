package predicate

import "net/http"

// MethodGroup returns the HTTP method semantics predicate group.
func MethodGroup() Group {
	return Group{
		Name: GroupMethods,
		Predicates: []NamedPred{
			{Name: "idempotency", Fn: checkIdempotency, Type: TypeSequential},
			{Name: "safety", Fn: checkSafety, Type: TypeSequential},
			{Name: "retries", Fn: checkRetries, Type: TypeSequential},
		},
	}
}

func checkIdempotency(_ *http.Response) Result {
	// Stub: requires sending the same request twice and comparing.
	return Result{GroupMethods, "idempotency", "skip", "requires multi-request test"}
}

func checkSafety(_ *http.Response) Result {
	return Result{GroupMethods, "safety", "skip", "requires multi-request test"}
}

func checkRetries(_ *http.Response) Result {
	return Result{GroupMethods, "retries", "skip", "requires multi-request test"}
}
