package predicate

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

// MethodGroup returns the HTTP method semantics predicate group.
func MethodGroup() Group {
	return Group{
		Name: GroupMethods,
		Predicates: []NamedPred{
			{Name: "idempotency", MultiFn: checkIdempotencyMulti, Type: TypeSequential},
			{Name: "safety", MultiFn: checkSafetyMulti, Type: TypeSequential},
			{Name: "retries", Fn: checkRetries, Type: TypeSequential},
		},
	}
}

// checkIdempotencyMulti verifies that PUT is idempotent per RFC 9110 §9.2.2.
// It compares server state (via GET) after two identical PUTs, not response
// status codes — a server may legitimately return different codes while the
// resource effect remains the same.
func checkIdempotencyMulti(client *http.Client, target string) Result {
	// Send PUT with a test body
	body := strings.NewReader(`{"test":"idempotency"}`)
	req1, _ := http.NewRequest("PUT", target, body)
	req1.Header.Set("Content-Type", "application/json")
	resp1, err := client.Do(req1)
	if err != nil {
		return Result{GroupMethods, "idempotency", "skip", "request failed: " + err.Error()}
	}
	resp1.Body.Close()

	// Read state after first PUT
	state1, err := client.Get(target)
	if err != nil {
		return Result{GroupMethods, "idempotency", "skip", "state read failed: " + err.Error()}
	}
	body1, _ := io.ReadAll(state1.Body)
	state1.Body.Close()

	// Send identical PUT again
	body = strings.NewReader(`{"test":"idempotency"}`)
	req2, _ := http.NewRequest("PUT", target, body)
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := client.Do(req2)
	if err != nil {
		return Result{GroupMethods, "idempotency", "skip", "second request failed: " + err.Error()}
	}
	resp2.Body.Close()

	// Read state after second PUT
	state2, err := client.Get(target)
	if err != nil {
		return Result{GroupMethods, "idempotency", "skip", "second state read failed: " + err.Error()}
	}
	body2, _ := io.ReadAll(state2.Body)
	state2.Body.Close()

	// Compare state, not response codes
	if string(body1) != string(body2) {
		return Result{GroupMethods, "idempotency", "fail",
			fmt.Sprintf("state differs after repeated PUT (RFC 9110 §9.2.2)")}
	}
	return Result{GroupMethods, "idempotency", "pass", "PUT is idempotent: state unchanged after repeat"}
}

// checkSafetyMulti verifies that GET is safe per RFC 9110 §9.2.1.
// A safe method must not change server state. We compare state before and
// after issuing the method under test.
func checkSafetyMulti(client *http.Client, target string) Result {
	// Read state before GET
	before, err := client.Get(target)
	if err != nil {
		return Result{GroupMethods, "safety", "skip", "initial state read failed: " + err.Error()}
	}
	bodyBefore, _ := io.ReadAll(before.Body)
	before.Body.Close()

	// Send GET (should not change state)
	mid, err := client.Get(target)
	if err != nil {
		return Result{GroupMethods, "safety", "skip", "GET request failed: " + err.Error()}
	}
	mid.Body.Close()

	// Read state after GET
	after, err := client.Get(target)
	if err != nil {
		return Result{GroupMethods, "safety", "skip", "post-GET state read failed: " + err.Error()}
	}
	bodyAfter, _ := io.ReadAll(after.Body)
	after.Body.Close()

	if string(bodyBefore) != string(bodyAfter) {
		return Result{GroupMethods, "safety", "fail",
			"GET changed server state (RFC 9110 §9.2.1)"}
	}
	return Result{GroupMethods, "safety", "pass", "GET is safe: no state change"}
}

func checkRetries(_ *http.Response) Result {
	return Result{GroupMethods, "retries", "skip", "requires multi-request test"}
}
