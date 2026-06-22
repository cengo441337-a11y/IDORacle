# Proof, Not Guesses: Sound Validation of Authorization Bugs (and Why the Same Idea Gates AI Agents)

*By Deniz Ceylan. June 2026.*

## The lie at the heart of automated security testing

Almost every automated tool that hunts for access control bugs makes the same quiet mistake: it trusts the response. It fires a cross user request, reads the HTTP status, and decides. A `200 OK` becomes "vulnerability found." A `403 Forbidden` becomes "all good."

But a server's response is an unsound oracle. Two cases break it completely:

1. **The silent no op.** The server returns `200 OK` to the attacker, but never persists the change. A status reading scanner reports a broken access control that does not exist. This is a false positive.
2. **The denied but committed write.** The server returns `403 Forbidden`, yet the write lands anyway (an authorization check on the wrong layer, an asynchronous worker that re applies the payload, an eventually consistent index that accepts what the primary rejected). The scanner reports "secure." This is a false negative, and it is the dangerous one.

The result is the daily reality of API security: kilometre long lists of unverified findings that a human has to re triage by hand, and a quiet residue of real bugs the tool never saw.

This article describes IDORacle, an open source tool that takes a different stance. It does not read the response. It reads committed state, and it proves what it claims.

## The canary witness

The core idea is simple enough to state in three steps. Suppose principal B (the attacker) tries to write an object that belongs to principal A.

1. As A, plant the object with a fresh 128 bit cryptographically random token (a canary) in a tester controlled field, and record it.
2. As B, perform the suspected unauthorized write.
3. As A, re read the object through an authorized path. If the canary changed (or the object is gone), an unauthorized write provably happened.

The verdict depends only on A's re read of committed state. It never looks at the status code B received. So the silent no op cannot fire it, and the denied but committed write cannot hide from it. The false positive probability is bounded by the collision probability of a 128 bit token, roughly `2^-128`.

When A cannot plant the object, or no committed state view reflects it, IDORacle does not guess. It returns `provably_blind` and asserts nothing. That honesty is not a weakness. It is the point.

## The part that actually makes it sound: the qualifying view self test

A token search is only a heuristic until you prove the place you searched reflects committed state rather than mere attempts. This is the trap that catches naive implementations. Imagine the observation channel is an audit log that records every attempted write, including rejected ones. Your canary would appear there even when the write was denied, and you would report a bug that never happened.

IDORacle qualifies every observation channel before it trusts it, using an executable self test:

- **O1, authorized.** The tester can read the view.
- **O2, commit gated.** A token from a genuine non commit (a real path write that is accepted then rolled back, not an early reject) must not appear. This negative control is what excludes the attempt log false positive. It is the single most important check, and the part most tools skip.
- **O3, entropy preserving.** A token from a real commit appears verbatim (a positive control).
- **O4, unique causal path.** A token injected through any other write path must not appear, and the view itself must not be attacker writable. Otherwise the attacker plants the marker into the observation surface directly and fakes a witness.
- **O5, durability.** The token survives a fresh session past the settle window, ruling out request scoped cache reflections and writes a background job later reverts.

A committed state search, a read only database replica, and an out of band webhook callback all pass this test. An attempt derived audit log fails O2. An attacker writable feed fails O4. The same engine grades every channel, and a channel that does not pass is declared `provably_blind`, never green.

## Honest coverage instead of a green checkmark

Finding bugs is half the job. The other half is the question every report dodges: how much did you actually test? IDORacle answers it with a two denominator report rather than a reassuring "0 findings."

It partitions the object space into authorization equivalence classes (object references that share the same access decision for the principal pair and the same typed shape) and, over a decoupled, independently sampled verification sub stream, computes an anytime valid upper bound on the residual mass of untested classes using a betting test martingale. The output reads like this:

> 1 confirmed, 2 clean, 1 held; coverage at least 95 percent over 2 of 2 plantable classes; 4 of 6 declared classes are `provably_blind` by construction (pre existing objects, owner not observable).

A tool that tells you exactly where it is blind is worth more than a dashboard that proudly blinks zero.

## Signed receipts you do not have to trust

Every verdict is a content addressed, HMAC signed receipt whose verdict can be re derived offline from the facts alone. A validly signed receipt whose verdict contradicts its facts is rejected. This matters in automation: a downstream system, or another agent, can consume the verdict without trusting the issuer, only the math.

## It works on real, third party software

This is not a toy demonstration. IDORacle was run live against deliberately vulnerable training applications that the author did not write:

- **OWASP Juice Shop.** A real write IDOR (editing another user's review). The canary landed in A's review, observed in committed state. Verdict: a signed `witness`.
- **OWASP crAPI.** A cross user write that returns `HTTP 200` but commits nothing to the victim's object. Verdict: a sound `no bug`, exactly where a status code scanner produces a false positive.

Both directions of soundness, on real code: it catches the real bug, and it refuses the one that is not there.

## From discovery to proof: the ARES combination

Finding candidates and proving them are different jobs, and they want different tools. ARES (Adaptive Red-Team Execution System) is an authorization gated, multi agent red team orchestrator: it explores an application, reasons about which endpoints, principal pairs, and object references are worth attacking, and proposes candidate findings. That part is broad, creative, and heuristic, and like any language model driven system, it guesses.

IDORacle is the deterministic validation oracle bolted to the other end. ARES hands each candidate to IDORacle as a small JSON recipe (how to authenticate, what to plant, where to write, where to observe). IDORacle runs the canary witness and returns a signed verdict: a proven bug, a sound clean, or an honest hold. The red team agent never has to be believed. Its findings arrive already validated, or already refuted, each with a receipt a human or a downstream agent can re check offline.

The effect is a red team that does not drown you in maybes. ARES discovers at machine scale; IDORacle makes every claim sound or marks it `provably_blind`. The validator ships as a standalone, dependency free tool inside the ARES tools directory, and it keeps the same honesty about its own boundary as the rest of the system: a live run against a real external target is offensive work that requires a named, authorized scope.

## The bigger idea: a sound committed effect witness

Strip away the IDOR skin and what remains is general. IDORacle is a way to prove that an action really changed state, without trusting the system's success response, and to declare honestly what you cannot observe. That pattern reaches far past access control.

The sharpest application is AI agents. Autonomous agents now write into production systems, and their most common failure is the confident silent no op: "I created the ticket, updated the row, sent the mail," when nothing committed. Today's agent evaluation harnesses capture the tool's return value and, at best, ask a language model to judge it. In other words, they trust the response. IDORacle's `agent_gate` applies the same primitive at the action seam: before an agent is allowed to say DONE, it plants a token in the write it is already making, re reads the target through a separate committed state path, and releases only on a durable observation. The tool's exit code and the agent's narration are the untrusted response, so the silent no op does not pass. The verdict is a portable signed receipt the next agent re derives without a language model in the loop.

The same shape fits other problems wherever a plantable marker and a true committed state read both exist: proving cross tenant isolation (tenant B provably cannot write tenant A's data) as continuous, signed evidence; proving a webhook was not merely delivered but actually processed; tracing GDPR erasure across every reachable view and catching a backup restore that silently resurrects deleted data; and gating a CI/CD promotion on proof that a config or policy change really took effect on every live instance. Where those preconditions do not hold, the honest verdict is `provably_blind`, not green.

## Honest scope and prior art

Intellectual honesty is part of the contribution, so here it is plainly. The mechanism of injecting a high entropy token and searching dependent views is **prior art**: BACScan (Liu et al., CCS 2025, a Distinguished Paper) injects unique tokens and confirms a committed modification through the victim's operationally dependent status pages. IDORacle claims no new detection capability over it.

The narrow, defensible contribution is twofold. First, the executable negative and sibling control suite that converts such a token search from a high precision heuristic into a false positive sound witness within a declared, content only observation model. Second, the matching characterization: a sound content only witness for the unauthorized mutation of a field exists if and only if the tester holds a qualifying view of it. Soundness is model conditional, because a black box can leak through timing or other side channels you cannot certify away, and pure black box completeness is information theoretically impossible. IDORacle says so rather than pretending otherwise.

Lineage worth crediting: honeytokens (Spitzner, "Honeytokens: The Other Honeypot," 2003), second order injection from source to sink (Dahse and Holz, USENIX Security 2014), and betting confidence sequences (Waudby-Smith and Ramdas, JRSS-B 86(1):1-27, 2024).

## Conclusion

The security industry automates on hope and regular expressions: it reads a response and believes it. The shift IDORacle argues for is small to state and large in consequence. Stop trusting the response. Plant a marker, read committed state, and when you cannot, say so. The same discipline that turns an IDOR scanner from a false positive factory into a sound witness is exactly what the agent economy needs at the seam where autonomous software writes into the real world.

IDORacle is open source under the MIT license: https://github.com/cengo441337-a11y/IDORacle
