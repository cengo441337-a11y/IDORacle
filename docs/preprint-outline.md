# A model-conditional soundness test for black-box write-authorization witnesses (outline v2)

Status: workshop-scale. NOT a new detection capability over BACScan, NOT new statistical
machinery. The narrow contribution is (i) a negative + sibling control suite that makes a
BACScan-style entropy-token oracle FALSE-POSITIVE-sound *within a declared content-only
model M*, and (ii) a matching characterization of when such soundness is achievable.
Rewritten after an adversarial review that found four soundness gaps in v1; they are fixed
below. Soundness is MODEL-CONDITIONAL (you cannot certify a black box leaked nothing via a
side channel), never "sound oracle" simpliciter.

## 1. Problem
Automated IDOR/BOLA testing infers a bug from HTTP responses, which are unsound oracles
(200 on a silent no-op = false positive; 403 while persisting = false negative). BACScan
(below) replaces this with entropy-token injection + view search, a high-PRECISION
heuristic. We ask: under what stated conditions is that heuristic actually FALSE-POSITIVE
sound, and can the conditions be self-tested black-box?

## 2. Observation model M (define it precisely - the soundness is relative to M)
M's observable alphabet is the response-BODY bytes of qualifying views only. Explicitly
EXCLUDED: status codes, latency, response size, ordering, quota/rate deltas, error strings.
Every claim below is "sound within M"; a timing/quota/ordering side channel can witness with
no content view, so neither soundness nor the characterization is claimed outside M.

## 3. Qualifying view (defined INDEPENDENTLY of the witness, so the iff is not tautological)
A view v is qualifying for (object o, mutated field f) iff:
- O1 authorized: the tester may read v.
- O2' commit-gated, LATE-PATH: v is a function of o's durably committed state of f. Tested by
  a negative control that induces a same-(o,f), same-handler, POST-VALIDATION non-commit
  (transaction rollback / persistence-boundary constraint abort), NOT an early auth/400
  reject. The early-reject path is distinct and proves nothing about attempt/audit-log
  contamination; only a late-path non-commit whose token does NOT appear excludes the
  audit-log false positive (which is the core claim).
- O3 entropy-preserving: a CSPRNG token survives verbatim into v (positive control).
- O4' unique-causal-path, BOTH sides: (write side) sibling tokens injected via every other
  reachable write path must NOT appear in v; (observe side) the token locus in v is provably
  bound to f and NOT writable by the attacker through any authorized path - else the attacker
  plants the token into the observation surface directly and fakes a witness.
- O5 durability: the token survives a session/cache/TTL teardown - re-read v from a FRESH
  independent session after the settle window, excluding request-scoped cache reflections,
  same-response echoes, and writes a background job later reverts.

## 4. Construction + the proposition
Construction: inject a fresh CSPRNG token tau INTO field f via the tested (attacker) write;
after the settle, re-read a qualifying view from a fresh session; tau present => durable
unauthorized mutation of f, FP <= 2^-128 (on top of O4' causal uniqueness). Absence is
INCONCLUSIVE, never no-write.
Proposition (relative to M): a content-only-sound witness for the unauthorized mutation of
f exists IFF the tester holds a view qualifying for (o,f) under O1-O5. (<=) the construction;
(=>) two indistinguishable-transcript worlds (commit vs late non-commit) parameterized by
"tester lacks a qualifying view for (o,f)". The impossibility kills COMPLETENESS only, not
the soundness claim; pure black-box completeness is therefore impossible.

## 5. Policy-aware verdict
A witnessed write is a bug only relative to intended policy, which is unobservable black-box.
Two tiers: CONSTRUCTION-UNCONDITIONAL on the cell the HARNESS INVARIANT controls (the tester
created o private, never shared it, re-read the ACL, and excluded ambient super-roles during
the window - so B writing it violates any sane policy BY SETUP, not by inspecting the target);
CONDITIONAL elsewhere (sound only if tester-declared == intended policy). It is NOT an
inspection of target policy; rename from "construction-sound" to "construction-unconditional".

## 6. Honest two-denominator coverage
An anytime-valid one-sided ABSOLUTE (never relative-error) upper bound on the residual mass
of untested authorization-equivalence classes, via a betting test-martingale (Ville). The
sub-stream MUST be a separate UNIFORMLY-RANDOM class sampler INDEPENDENT of the stateful
crawl (a crawler's class discovery is non-i.i.d. and under-samples rare high-privilege
classes in a way correlated with risk); report the sub-stream sampling rate. Caveat: a small
residual-MASS bound is RISK-BLIND - near-zero mass is compatible with a catastrophic
admin-only endpoint being wholly untested. Reported beside the provably-blind non-plantable
classes.

## 7. Prior art (pinned; cite up front)
- Mechanism (the headline overlap): **BACScan**, Liu et al., CCS 2025 (Fudan + CUHK,
  Distinguished Paper, doi 10.1145/3719027.3744825) - injects unique high-entropy tokens
  (6-char pseudo-random strings) into attacker-replayed modification requests and confirms
  the commit via a feedback-driven oracle that re-fetches the victim's operationally-dependent
  STATUS pages identified by an Inter-page Data Dependency Graph (presence for INSERT/UPDATE,
  absence for DELETE). Our new ingredient is the negative/sibling control suite, NOT the
  token-and-search, which is theirs.
- Planted-marker primitive: honeytokens - concept popularized by Spitzner, "Honeytokens: The
  Other Honeypot" (SecurityFocus, 2003); term coined by Augusto Paes de Barros (2003);
  Canarytokens (Thinkst, canarytokens.org, accessed 2026). Our novelty is the soundness
  argument, not the marker.
- Betting confidence sequence: Waudby-Smith & Ramdas, "Estimating means of bounded random
  variables by betting", JRSS-B 86(1):1-27, 2024.
- Relative-error missing-mass impossibility (invoked ONLY for the relative-error claim;
  does not preclude additive/Good-Turing): Mossel & Ohannessian, "On the Impossibility of
  Learning the Missing Mass", Entropy 2019, 21(1):28, doi 10.3390/e21010028.
- source->sink (STATIC white-box; we borrow the concept, not the technique): Dahse & Holz,
  "Static Detection of Second-Order Vulnerabilities in Web Applications", USENIX Sec 2014.
- White-box policy-structure coverage of a KNOWN policy (contrast with our black-box,
  unknown-policy setting; NOT equivalent): Bertolino, Daoudagh, Lonetti, "On-line tracing of
  XACML-based policy coverage criteria", IET Software 2018, doi 10.1049/iet-sen.2017.0351.

## 8. Evaluation
- The self-test on heterogeneous channels: committed-state search, grey-box DB replica, OOB
  webhook all qualify; an attempt-derived audit log fails O2'; an attacker-writable feed fails
  O4'.
- External-validity pilot: the witness tool validates a REAL third-party write-IDOR (OWASP
  Juice Shop "edit another user's review" BOLA) end-to-end, emitting a signed verdict; against
  a differently-shaped target it HOLDs on its defaults and witnesses only with a discovered
  profile. (The full O2'/O4'/O5 self-test on a live target requires constructing a late-path
  non-commit control, which is target-specific - stated honestly as future work.)
- Certificate validity: over 500 i.i.d. sub-streams the true uncovered mass exceeds the
  certified absolute bound at rate <= alpha.

## 9. Honest framing (say this, do not deny it)
No new detection capability over BACScan and no new statistical machinery. The contribution
is the model-conditional soundness self-test and the matching (completeness-)impossibility.
Soundness is conditional on the content-only model M (uncertifiable black-box) and the
qualifying-view assumption. The practical value is a sound validation oracle an LLM red-team
agent can call, plus an honest coverage report that names where it is blind.
