# Preprint Outline v2 - Red-Team Fixed (Honest Framing)

**IDORacle: A Sound, Model-Conditional Authorization Oracle for Write-BOLA Validation via Canary Witnessing**

## Abstract
Sound by construction oracle using canary values observed through qualifying views. Target-agnostic (auth callable + field discovery). Honest audit bundles with coverage certificates and explicit blind-spot reporting. Proven on real third-party deliberately-vulnerable apps (Juice Shop, crAPI).

Cites BACScan (Liu et al. CCS 2025) for baseline. Contribution is disciplined validation and honesty, not new detection power.

## Red-Team Fixes Applied
- Late-path negative control (post-validation rollback)
- O5 Durability-Reread
- Observe-side writability explicitly excluded
- Unconditional cell = harness-invariant
- Overclaims removed: model-conditional soundness, Proposition not Theorem

## Structure
1. Motivation (false-positive factory in status-code tools)
2. Related Work (BACScan, WSR JRSS-B 86(1) 2024, Spitzner 2003, Bertolino 2018)
3. Definitions (observable view, canary witness, plantable classes)
4. Target-Agnostic Design
5. Soundness (model-conditional)
6. Implementation & ARES Fusion
7. External Pilots
8. Honest Pipeline
9. Limitations
10. Conclusion

Pinned citations and full text in repo.
