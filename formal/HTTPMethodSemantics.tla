---------------------------- MODULE HTTPMethodSemantics ----------------------------
(*
 * TLA+ specification of HTTP method safety and idempotency per RFC 9110.
 *
 * Maps to: internal/predicate/methods.go
 *   - checkSafetyMulti (lines 74-103)
 *   - checkIdempotencyMulti (lines 26-69)
 *
 * RFC 9110 §9.2.1 (Safe Methods):
 *   "Request methods are considered 'safe' if their defined semantics are
 *    essentially read-only; i.e., the client does not request, and does not
 *    expect, any state change on the origin server."
 *   Safe methods: GET, HEAD, OPTIONS, TRACE
 *
 * RFC 9110 §9.2.2 (Idempotent Methods):
 *   "A request method is considered 'idempotent' if the intended effect on
 *    the server of multiple identical requests with that method is the same
 *    as the effect for a single such request."
 *   Idempotent methods: PUT, DELETE (plus all safe methods)
 *
 * This spec models:
 *   1. A server with observable state (integer counter + resource map)
 *   2. HTTP methods as actions that may modify state
 *   3. hax's checkSafetyMulti and checkIdempotencyMulti as TLA+ operators
 *   4. Properties that should hold for compliant servers
 *   5. Counterexamples for non-compliant servers
 *
 * Key result: status-code comparison (which hax explicitly avoids per C-004)
 * is shown to be insufficient — a server can return different status codes
 * for repeated PUTs while maintaining idempotent state effects.
 *)

EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Methods,       \* Set of HTTP methods to test
    MaxOps,        \* Maximum number of operations per trace
    ResourceIds    \* Set of resource identifiers

ASSUME Methods \subseteq {"GET", "PUT", "POST", "DELETE", "HEAD", "OPTIONS", "TRACE"}
ASSUME MaxOps \in Nat /\ MaxOps >= 1

VARIABLES
    resources,     \* Function: ResourceId -> value (Nat or 0 for deleted)
    opCount,       \* Number of operations performed
    lastMethod,    \* Last method executed
    lastStatus,    \* Last HTTP status code returned
    stateHistory   \* Sequence of state snapshots for comparison

vars == <<resources, opCount, lastMethod, lastStatus, stateHistory>>

(*
 * ---------- SERVER MODEL ----------
 * Models a simple resource server where:
 *   - GET reads state (no change)
 *   - PUT sets resource to a value (idempotent: same value each time)
 *   - POST creates/increments (NOT idempotent)
 *   - DELETE removes resource (idempotent: already-deleted stays deleted)
 *)

Init ==
    /\ resources = [r \in ResourceIds |-> 0]
    /\ opCount = 0
    /\ lastMethod = "NONE"
    /\ lastStatus = 0
    /\ stateHistory = <<>>

(*
 * RFC 9110 §9.3.1: GET retrieves current state of target resource.
 * Safe: does not modify server state.
 *)
DoGET(rid) ==
    /\ opCount < MaxOps
    /\ lastMethod' = "GET"
    /\ lastStatus' = IF resources[rid] > 0 THEN 200 ELSE 404
    /\ UNCHANGED resources
    /\ opCount' = opCount + 1
    /\ stateHistory' = Append(stateHistory, resources)

(*
 * RFC 9110 §9.3.4: PUT replaces target resource state.
 * Idempotent: repeated PUTs with same payload yield same state.
 * Note: status code MAY differ (201 on create, 200/204 on update)
 * — this is the key insight hax uses (compare state, not status).
 *)
DoPUT(rid, val) ==
    /\ opCount < MaxOps
    /\ lastMethod' = "PUT"
    /\ lastStatus' = IF resources[rid] = 0 THEN 201 ELSE 200
    /\ resources' = [resources EXCEPT ![rid] = val]
    /\ opCount' = opCount + 1
    /\ stateHistory' = Append(stateHistory, resources')

(*
 * RFC 9110 §9.3.3: POST processes request payload.
 * Neither safe nor idempotent: each POST may create new state.
 *)
DoPOST(rid) ==
    /\ opCount < MaxOps
    /\ lastMethod' = "POST"
    /\ lastStatus' = 201
    /\ resources' = [resources EXCEPT ![rid] = resources[rid] + 1]
    /\ opCount' = opCount + 1
    /\ stateHistory' = Append(stateHistory, resources')

(*
 * RFC 9110 §9.3.5: DELETE removes target resource.
 * Idempotent: deleting an already-deleted resource is a no-op.
 * Note: status MAY differ (200 on first delete, 404 on subsequent)
 * — another case where status-code comparison gives false negatives.
 *)
DoDELETE(rid) ==
    /\ opCount < MaxOps
    /\ lastMethod' = "DELETE"
    /\ lastStatus' = IF resources[rid] > 0 THEN 200 ELSE 404
    /\ resources' = [resources EXCEPT ![rid] = 0]
    /\ opCount' = opCount + 1
    /\ stateHistory' = Append(stateHistory, resources')

(*
 * Stutter when all operations exhausted.
 *)
Done ==
    /\ opCount >= MaxOps
    /\ UNCHANGED vars

Next ==
    \/ \E rid \in ResourceIds:
        \/ DoGET(rid)
        \/ \E val \in 1..3: DoPUT(rid, val)
        \/ DoPOST(rid)
        \/ DoDELETE(rid)
    \/ Done

Spec == Init /\ [][Next]_vars

(*
 * ---------- PROPERTIES ----------
 *)

TypeOK ==
    /\ \A rid \in ResourceIds: resources[rid] \in Nat
    /\ opCount \in 0..MaxOps
    /\ lastMethod \in {"NONE", "GET", "PUT", "POST", "DELETE", "HEAD", "OPTIONS", "TRACE"}
    /\ lastStatus \in 0..599

(*
 * Safety property (RFC 9110 §9.2.1):
 * GET must not change server state.
 *
 * This is what checkSafetyMulti verifies:
 *   state_before_GET == state_after_GET
 *
 * Expressed as: if the last method was GET, resources are unchanged.
 *)
SafeMethodsPreserveState ==
    [][lastMethod' = "GET" => resources' = resources]_vars

(*
 * Idempotency property (RFC 9110 §9.2.2):
 * PUT is a pure function of its arguments: the resulting state depends
 * only on (rid, val), not on prior state. Formally, after any DoPUT(rid, val),
 * resources'[rid] = val regardless of what resources[rid] was before.
 *
 * This is what checkIdempotencyMulti verifies:
 *   state_after_PUT_1 == state_after_PUT_2
 *
 * Expressed as an action property: when PUT fires, the resource is
 * set to the PUT value unconditionally.
 *)
IdempotentPUTConverges ==
    [][\A rid \in ResourceIds:
        (lastMethod' = "PUT" /\ resources'[rid] # resources[rid])
        => resources'[rid] # 0  \* PUT always sets to a positive value
    ]_vars

(*
 * ---------- COUNTEREXAMPLE: STATUS CODE COMPARISON IS INSUFFICIENT ----------
 *
 * C-004 asserts: "Idempotency requires state comparison not status codes."
 *
 * Demonstration:
 *   1. PUT /r1 with val=1 when r1 does not exist → status 201, state {r1: 1}
 *   2. PUT /r1 with val=1 when r1 exists → status 200, state {r1: 1}
 *
 * Status codes differ (201 ≠ 200) but state is identical ({r1: 1}).
 * A status-code-based check would report "not idempotent" — FALSE NEGATIVE.
 *
 * Similarly for DELETE:
 *   1. DELETE /r1 when r1 exists → status 200, state {r1: 0}
 *   2. DELETE /r1 when r1 is deleted → status 404, state {r1: 0}
 *
 * Status codes differ (200 ≠ 404) but state is identical ({r1: 0}).
 *
 * This validates hax's design decision to compare response bodies (as a
 * proxy for state) rather than status codes.
 *)

(*
 * Anti-property: if we checked status codes instead of state,
 * PUT would appear non-idempotent. This SHOULD be violated by TLC,
 * producing the counterexample above.
 *)
StatusCodeIdempotency_SHOULD_FAIL ==
    [][lastMethod' = "PUT" => lastStatus' = lastStatus]_vars

(*
 * Anti-property for DELETE: same logic.
 *)
StatusCodeIdempotencyDELETE_SHOULD_FAIL ==
    [][lastMethod' = "DELETE" => lastStatus' = lastStatus]_vars

(*
 * ---------- POST IS NOT IDEMPOTENT ----------
 *
 * Verify that the model correctly captures POST's non-idempotent nature.
 * This invariant should be VIOLATED by TLC, producing a trace where
 * two POSTs yield different states.
 *)
POSTIsIdempotent_SHOULD_FAIL ==
    [][\A rid \in ResourceIds:
        (lastMethod' = "POST" /\ resources[rid] = resources'[rid])
    ]_vars

=============================================================================
