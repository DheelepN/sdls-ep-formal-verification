# Project B — Proof-of-Concept Attack Traces

Project B is a **formal verification** effort, so its proofs of concept are **machine-checked Tamarin traces**, not runnable exploit binaries. Each walkthrough below states the exact rule-firing sequence of the attack, the command to reproduce it, and the prover's verdict. Reviewers re-run the model and Tamarin regenerates the trace.

Why not CVE-style runnable exploits? The targets are **published protocol proposals and a draft**, not deployed software (see `REPORT.md §6`). There is no shipped implementation to exploit; the contribution is design-level analysis delivered to the CCSDS Security Working Group and the proposal authors. Where a finding is machine-confirmed, the exported trace is the artifact of record.

## Walkthroughs

| PoC | Finding | Verdict | Reproducible artifact |
|---|---|---|---|
| [POC_FB01_rekey_desync.md](POC_FB01_rekey_desync.md) | **FB-01** — non-recoverable rekey desynchronization in Triple-KEM under a closing pass window (no crypto compromise) | ✅ confirmed | `traces/fb01_desync.dot` / `.json` |
| [POC_FA02_dual_kem.md](POC_FA02_dual_kem.md) | **FA-02** — Dual-KEM loses responder authentication and post-compromise security once the psk leaks | ✅ confirmed (2 traces) | `traces/fa02_respauth.dot`, `traces/fa02_pcs.dot` |
| [POC_FC01_e2eqss_hybrid.md](POC_FC01_e2eqss_hybrid.md) | **FC-01** — E2EQSS hybrid does not protect confidentiality when ML-KEM breaks (auth rides only on the KEM challenge) | ✅ confirmed | `traces/fc01_attack.dot` (isolated model) |

## Rendering a trace

```bash
dot -Tpng traces/fb01_desync.dot -o fb01_desync.png     # requires graphviz
# or open the .json in the Tamarin interactive GUI
```

## What is NOT claimed

- No claim of a vulnerability in any deployed/released product.
- FA-01 (Triple-KEM secure) and the verified E2EQSS lemmas are positive proofs, not attacks; they have no PoC by nature.
- Any finding marked "conjecture" in a walkthrough is exactly that until its trace is machine-confirmed.
