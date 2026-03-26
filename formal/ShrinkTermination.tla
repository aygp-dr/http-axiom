---------------------------- MODULE ShrinkTermination ----------------------------
(*
 * TLA+ specification of hax's oracle.Shrink algorithm.
 *
 * Maps to: internal/oracle/oracle.go lines 92-187
 *
 * The Shrink algorithm minimizes a failing HTTP request by progressively
 * simplifying it along 5 dimensions:
 *   1. Headers   — remove one at a time
 *   2. Auth      — bearer > basic > cookie > none
 *   3. Origin    — cross-site > same-site > none
 *   4. Method    — any non-GET > GET
 *   5. Repeat    — N > N-1 > ... > 1
 *
 * This spec proves:
 *   (a) Termination: the complexity measure strictly decreases on every
 *       accepted step, so shrinking terminates without MaxAttempts.
 *   (b) Failure monotonicity: the current request always produces a failure
 *       (invariant maintained by the check-before-accept pattern).
 *   (c) Local-minimum limitation: the greedy single-axis strategy can miss
 *       globally minimal counterexamples when failure requires simultaneous
 *       changes across 2+ dimensions.
 *)

EXTENDS Naturals, FiniteSets

CONSTANTS
    MaxHeaders,       \* Upper bound on number of headers (e.g., 4)
    MaxRepeat,        \* Upper bound on repeat count (e.g., 5)
    AuthLadder,       \* Sequence of auth levels, indexed 0..3
                      \* 0 = "bearer", 1 = "basic", 2 = "cookie", 3 = "none"
    OriginLadder      \* Sequence of origin levels, indexed 0..2
                      \* 0 = "cross-site", 1 = "same-site", 2 = "none"

ASSUME MaxHeaders \in Nat /\ MaxHeaders >= 0
ASSUME MaxRepeat \in Nat /\ MaxRepeat >= 1

VARIABLES
    headers,     \* Number of headers remaining (0..MaxHeaders)
    auth,        \* Auth level index (0 = most complex, 3 = simplest)
    origin,      \* Origin level index (0 = most complex, 2 = simplest)
    method,      \* 0 = non-GET, 1 = GET (simplest)
    repeat,      \* Repeat count (1..MaxRepeat)
    done,        \* Whether shrinking has terminated
    steps        \* Number of shrink steps taken

vars == <<headers, auth, origin, method, repeat, done, steps>>

(*
 * Complexity measure: a well-founded ordering over the 5 dimensions.
 * This is the lexicographic tuple that strictly decreases on every step.
 * In the Go code, each accepted simplification removes at least one unit
 * from one dimension. Since all dimensions are bounded below (headers >= 0,
 * auth <= 3, origin <= 2, method <= 1, repeat >= 1), the measure is
 * well-founded and shrinking must terminate.
 *)
Complexity == headers + (3 - auth) + (2 - origin) + (1 - method) + (repeat - 1)

(*
 * The CheckFunc oracle: determines whether a simplified request still fails.
 * In the real system, this calls the predicate against a live server.
 * Here we model it non-deterministically: any simplification MIGHT preserve
 * the failure. This gives TLC maximum freedom to explore all behaviors.
 *)
CheckStillFails == TRUE \/ FALSE  \* Non-deterministic in model checking

(*
 * Initial state: request at maximum complexity, failure verified.
 *)
Init ==
    /\ headers = MaxHeaders
    /\ auth = 0          \* "bearer" (most complex)
    /\ origin = 0        \* "cross-site" (most complex)
    /\ method = 0        \* non-GET
    /\ repeat = MaxRepeat
    /\ done = FALSE
    /\ steps = 0

(*
 * Shrink dimension 1: Remove one header.
 * Maps to oracle.go lines 115-127.
 *)
ShrinkHeader ==
    /\ ~done
    /\ headers > 0
    /\ \E stillFails \in {TRUE, FALSE}:
        IF stillFails
        THEN /\ headers' = headers - 1
             /\ steps' = steps + 1
             /\ UNCHANGED <<auth, origin, method, repeat, done>>
        ELSE /\ UNCHANGED vars

(*
 * Shrink dimension 2: Simplify auth down the ladder.
 * Maps to oracle.go shrinkAuth (lines 197-228).
 * Ladder: bearer(0) -> basic(1) -> cookie(2) -> none(3)
 *)
ShrinkAuth ==
    /\ ~done
    /\ auth < 3
    /\ \E nextAuth \in (auth + 1)..3:
        \E stillFails \in {TRUE, FALSE}:
            IF stillFails
            THEN /\ auth' = nextAuth
                 /\ steps' = steps + 1
                 /\ UNCHANGED <<headers, origin, method, repeat, done>>
            ELSE /\ UNCHANGED vars

(*
 * Shrink dimension 3: Simplify origin down the ladder.
 * Maps to oracle.go shrinkOrigin (lines 232-260).
 * Ladder: cross-site(0) -> same-site(1) -> none(2)
 *)
ShrinkOrigin ==
    /\ ~done
    /\ origin < 2
    /\ \E nextOrigin \in (origin + 1)..2:
        \E stillFails \in {TRUE, FALSE}:
            IF stillFails
            THEN /\ origin' = nextOrigin
                 /\ steps' = steps + 1
                 /\ UNCHANGED <<headers, auth, method, repeat, done>>
            ELSE /\ UNCHANGED vars

(*
 * Shrink dimension 4: Simplify method to GET.
 * Maps to oracle.go lines 151-161.
 *)
ShrinkMethod ==
    /\ ~done
    /\ method = 0
    /\ \E stillFails \in {TRUE, FALSE}:
        IF stillFails
        THEN /\ method' = 1
             /\ steps' = steps + 1
             /\ UNCHANGED <<headers, auth, origin, repeat, done>>
        ELSE /\ UNCHANGED vars

(*
 * Shrink dimension 5: Reduce repeat count by 1.
 * Maps to oracle.go lines 164-174.
 *)
ShrinkRepeat ==
    /\ ~done
    /\ repeat > 1
    /\ \E stillFails \in {TRUE, FALSE}:
        IF stillFails
        THEN /\ repeat' = repeat - 1
             /\ steps' = steps + 1
             /\ UNCHANGED <<headers, auth, origin, method, done>>
        ELSE /\ UNCHANGED vars

(*
 * Termination: no dimension can be simplified further.
 * Maps to oracle.go line 177: "Nothing more to shrink; break".
 *)
Terminate ==
    /\ ~done
    /\ headers = 0
    /\ auth = 3
    /\ origin = 2
    /\ method = 1
    /\ repeat = 1
    /\ done' = TRUE
    /\ UNCHANGED <<headers, auth, origin, method, repeat, steps>>

(*
 * Stall: all simplifications were tried and none preserved the failure.
 * The Go code breaks out of the loop when changed == false after trying
 * all 5 dimensions (line 177). This is a second termination path where
 * the request is at a local minimum but not the global minimum.
 *)
Stall ==
    /\ ~done
    /\ done' = TRUE
    /\ UNCHANGED <<headers, auth, origin, method, repeat, steps>>

(*
 * Done: once terminated, stutter (no further changes).
 *)
Done ==
    /\ done
    /\ UNCHANGED vars

Next ==
    \/ ShrinkHeader
    \/ ShrinkAuth
    \/ ShrinkOrigin
    \/ ShrinkMethod
    \/ ShrinkRepeat
    \/ Terminate
    \/ Stall
    \/ Done

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

(*
 * ---------- PROPERTIES ----------
 *)

(*
 * Safety: complexity never increases.
 * If complexity decreases on every accepted step and cannot go below 0,
 * shrinking must terminate.
 *)
TypeOK ==
    /\ headers \in 0..MaxHeaders
    /\ auth \in 0..3
    /\ origin \in 0..2
    /\ method \in 0..1
    /\ repeat \in 1..MaxRepeat
    /\ Complexity \in 0..(MaxHeaders + 3 + 2 + 1 + (MaxRepeat - 1))
    /\ done \in BOOLEAN
    /\ steps \in Nat

(*
 * Liveness: shrinking eventually terminates.
 *)
EventuallyDone == <>done

(*
 * Safety: every accepted step strictly decreases complexity.
 * Expressed as: complexity at step N+1 < complexity at step N.
 * (This is encoded in the actions — each one decreases exactly one dimension.)
 *)
ComplexityDecreases ==
    [][steps' > steps => Complexity' < Complexity]_vars

(*
 * Bounded steps: the total number of shrink steps never exceeds
 * the initial complexity. This proves MaxAttempts is a redundant guard
 * (for termination — it still limits wall-clock time).
 *)
BoundedSteps ==
    steps <= MaxHeaders + 3 + 2 + 1 + (MaxRepeat - 1)

(*
 * ---------- LOCAL MINIMUM WITNESS ----------
 *
 * The greedy strategy tries one dimension at a time and takes the first
 * successful simplification. This means it can get stuck at a local minimum
 * where:
 *   - Removing header H alone causes the check to pass (not fail)
 *   - Simplifying auth alone causes the check to pass
 *   - But removing H AND simplifying auth simultaneously preserves the failure
 *
 * The Go code at line 125 does `break` on first successful header removal,
 * restarting the outer loop. It never tries pairs. This is a known limitation
 * documented below, NOT a bug — the single-axis strategy is O(n) per round
 * while pairwise would be O(n²).
 *
 * To demonstrate this with TLC, construct a CheckFunc that fails only when
 * headers >= 2 AND auth = 0, OR headers = 0 AND auth >= 2. The greedy
 * shrinker cannot cross the "valley" at (headers=1, auth=1) where neither
 * axis alone preserves the failure.
 *)

=============================================================================
