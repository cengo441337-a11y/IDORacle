<div align="center">

<img src="assets/idoracle-banner.jpg" alt="IDORacle: a sound, target-agnostic security oracle for detecting write-BOLA / IDOR vulnerabilities" width="860">

# IDORacle

### Proof, not guesses, for access control bugs.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-stdlib%20only-3776AB.svg)](#)
[![Tests](https://img.shields.io/badge/tests-57%20passing-brightgreen.svg)](#)
[![Soundness](https://img.shields.io/badge/verdict-canary--witnessed-8A2BE2.svg)](#)

A sound, target agnostic oracle that **proves** a write IDOR / BOLA is real, instead of guessing from HTTP status codes. It plants a unique high entropy canary, lets the attacker account write it, and confirms the change actually landed in committed state. It witnesses real bugs, and it refuses the false positives that wreck every status code scanner. When it cannot observe an object soundly, it says so, on the record, signed.

</div>

---

## The problem

Servers lie. A `200 OK` can be a silent no op. A `403 Forbidden` can hide a write that persisted. Almost every automated IDOR/BOLA scanner reads those responses and produces kilometre long false positive lists a human has to re triage.

## What IDORacle does instead

It does not read the response. It reads **committed state**.

1. As principal A, plant an object carrying a fresh 128 bit canary token.
2. As principal B (the attacker), write that object.
3. As principal A, re read it. If the canary changed, an unauthorized write **provably** happened, regardless of what status B received. False positive probability `<= 2^-128`.

If A cannot plant the object, or no committed state view reflects it, IDORacle returns `provably_blind` and asserts nothing. Honest blindness beats a confident wrong answer.

## Proven on real, third party apps

Not a toy demo. Run live against software nobody on this project wrote:

| Target | Finding | IDORacle verdict | A status code scanner would have |
|---|---|---|---|
| **OWASP Juice Shop** v20 | real write IDOR (edit another user's review) | `witness` -> signed `fail` | also flagged it (true positive) |
| **OWASP crAPI** latest | cross user `PUT` returns **HTTP 200** but writes nothing | `no-bug` (sound) | screamed "BOLA!" (**false positive**) |

Both directions of soundness, on real code: it catches the real bug, and it does not invent the one that is not there.

## Quickstart

```bash
git clone https://github.com/cengo441337-a11y/IDORacle && cd IDORacle
python -m unittest discover -s idoracle/tests -p "test_*.py"   # 57 tests, stdlib only

python idoracle/demo.py        # the canary soundness table
python idoracle/obs_demo.py    # which observation views are SOUND to witness on
```

Validate one finding from a JSON recipe (the ARES native tool):

```bash
python idoracle/witness_tool.py --recipe recipes/juiceshop-review-bola.json
# -> signed verdict JSON: witness / no-bug / hold, content addressed + HMAC
```

## How it stays sound: the qualifying view self test

A token search is only a heuristic until you prove the view you searched reflects committed state. IDORacle qualifies every observation channel before it trusts it:

- **O1** authorized: the tester can read the view.
- **O2** commit gated: a token from a real path **non commit** must NOT appear (the negative control that excludes attempt and audit log false positives).
- **O3** entropy preserving: a committed token survives verbatim (positive control).
- **O4** unique causal path: a token injected through any other write path must NOT appear, and the view is not attacker writable.
- **O5** durability: the token survives a fresh session past the settle window.

A committed state search, a grey box DB replica, and an OOB webhook all qualify. An attempt derived audit log fails O2. An attacker writable feed fails O4. The same engine grades all of them.

## Honest by design

- **Signed receipts.** Every verdict is a content addressed, HMAC signed receipt whose verdict is re derivable offline. A validly signed receipt with a wrong verdict is rejected.
- **Two denominator coverage.** An anytime valid certificate reports residual mass of untested authorization classes beside the classes that are `provably_blind` by construction. Example output: `1 confirmed, 2 clean, 1 held; coverage >= 95% over 2/2 plantable classes; 4/6 declared classes provably_blind`.
- **Policy aware.** A legitimately shared object that B may write fires the raw witness but is correctly **not** a bug.

## ARES native

IDORacle is the deterministic validation oracle for [ARES](https://github.com/cengo441337-a11y/ares), the adaptive red team execution system. ARES discovers candidates, IDORacle turns each into a sound verdict plus a signed receipt and a coverage report. `idoracle/witness_tool.py` is a standalone, stdlib only ARES tool driven by a JSON recipe.

## Beyond IDOR: the same primitive, generalized

Under the IDOR skin, IDORacle is a **sound committed effect witness**: prove an action
really changed state, without trusting the system's success response, and declare honestly
what you cannot observe. That generalizes far past access control. `idoracle/agent_gate.py`
applies it to AI agents: before an agent is allowed to say DONE, it plants a token in the
write it is already making, re reads the target through a separate committed state path, and
releases only on a durable observation. The tool's `200` / `exit 0` and the agent's "I did
it" are the untrusted response, so the **silent no op**, the agent economy's most common
failure, does not pass. The verdict is a portable signed receipt a downstream agent
re derives LLM free (the A2A handoff).

```bash
python idoracle/agent_gate_demo.py
# really commits        -> pass
# returns ok, commits nothing -> fail   (the silent no-op, caught)
# no committed-state view     -> hold   (provably_blind)
```

The same shape fits cross tenant isolation proofs, webhook and eventual consistency
convergence, GDPR erasure tracing, and CI/CD config and policy propagation gates. It only
fits where a plantable marker and a true committed state read both exist; everywhere else it
says `provably_blind` rather than green.

## Honest scope and prior art

The token injection plus view search **mechanism is prior art**: BACScan (Liu et al., CCS 2025, Distinguished Paper) injects high entropy tokens and confirms via dependent status pages. IDORacle claims **no new detection capability** over it. The contribution is narrow and stated plainly: the executable negative and sibling control suite that makes such an oracle false positive sound within a declared content only model, plus honest blind spot reporting and signed receipts. Soundness is model conditional (a black box can leak via timing or other side channels you cannot certify away). Pure black box completeness is information theoretically impossible, and IDORacle says so.

Lineage: honeytokens (Spitzner, "Honeytokens: The Other Honeypot", 2003), second order injection source to sink (Dahse and Holz, USENIX Security 2014), betting confidence sequences (Waudby-Smith and Ramdas, JRSS-B 86(1):1-27, 2024).

## Layout

```
idoracle/
  oracle.py        canary write witness + signed receipt + verify_witness
  views.py         the O1-O5 qualifying view self test
  schema.py        authorization equivalence class DSL
  coverage.py      classifier + policy aware verdict + ENVELOPE_NOTES
  certificate.py   anytime valid coverage certificate (betting test martingale)
  pipeline.py      one audit bundle: validate + certify + honest report
  witness_tool.py  ARES native, recipe driven CLI
  target_app.py / obs_target.py / ext_target.py   deterministic lab targets
  tests/           57 tests, stdlib unittest
recipes/           validation recipes (e.g. juiceshop-review-bola.json)
docs/              the model conditional soundness write up
```

## License

MIT. Authorized testing only.
