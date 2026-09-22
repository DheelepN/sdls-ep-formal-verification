# Mechanized Analysis of Post-Quantum Key-Update Proposals for CCSDS SDLS-EP

Symbolic (Dolev–Yao) verification, in the Tamarin prover, of two proposed
post-quantum extensions to the CCSDS Space Data Link Security Extended
Procedures — delivered as input to the CCSDS Security Working Group and to the
proposal authors **during** the standardization window, rather than after it.

## Why now

SDLS-EP today manages keys with symmetric cryptography and pre-shared keys only.
A compromised key cannot be replaced, so compromise is permanent for the mission
and there is no post-compromise security. This is architectural rather than
accidental: CCSDS 354.0-M-1 §1.2 puts asymmetric and public-key cryptosystems
explicitly out of scope for CCSDS key management.

Two proposals address it. **Triple-KEM / Dual-KEM** (Hülsing, Lange and Weber,
CANS 2025) has, per its authors, begun standardization as a CCSDS Blue Book, on
the strength of a hand-written computational proof in a modified
Bellare–Rogaway model. **E2EQSS** (Wildfeuer et al., ESA 3S 2025) is a hybrid
ML-KEM + ECDH handshake with ML-DSA certificates.

Neither had a mechanized proof. A protocol entering a Blue Book is a protocol
that will fly for decades on spacecraft that cannot easily be patched.

## Findings

| # | Result | Nature |
|---|---|---|
| FA-01 | Triple-KEM satisfies key secrecy, forward secrecy, post-compromise security, injective mutual authentication and key agreement, under an adversary that may reveal any long-term key and the pre-shared key | Positive — corroborates the BR′ proof, mechanized |
| FA-02 | Dual-KEM loses responder authentication, and once the pre-shared key is compromised loses post-compromise security entirely | Boundary made precise, with attack traces |
| **FB-01** | **Triple-KEM permits a non-recoverable rekey desynchronization under space channel constraints: one lost key confirmation across a closing pass window leaves ground on the new key and the spacecraft on the old one, with no automatic recovery** | **New finding — availability** |
| FC-01 | E2EQSS is hybrid for confidentiality but **not** for authentication: its certificates sign only static keys, so a broken ML-KEM lets an adversary replay a certificate with its own ephemerals | Finding, confirmed constructively |

**FB-01 is the one with operational consequences.** It requires no cryptographic
compromise — the witness trace contains no key reveal of any kind — and it is
structurally invisible to a proof that establishes secrecy and authentication,
because both-sided completion is neither of those properties.

*Mitigation:* mission control must not activate the new SDLS master key until it
has positive evidence the spacecraft activated it — an acknowledgement, or
deferred activation with a defined fallback. That makes the rekey atomic across
pass boundaries. It is a small change now and an expensive one after adoption.

## Layout

```
models/      Tamarin theories (.spthy) and the E2EQSS proof oracle
traces/      Captured prover output, and exported attack traces (.dot/.png)
poc/         Walkthroughs of the three attack findings
paper/       Write-up
references/  Source papers and standards (not redistributed; see .gitignore)
REPORT.md    Verification report, the disclosure-facing document
PROGRESS.md  Phase-by-phase log with modelling decisions
```

## Reproducing

Requires Tamarin 1.12.0 and Maude 3.1.

```bash
./reproduce.sh
```

Or individually:

```bash
tamarin-prover --prove models/triple_kem.spthy
tamarin-prover --prove models/dual_kem.spthy
tamarin-prover --prove models/triple_kem_space.spthy     # FB-01
tamarin-prover --prove models/e2eqss.spthy               # needs the oracle
tamarin-prover --prove models/e2eqss_fc01.spthy          # FC-01 attack
```

The E2EQSS model's `mutual_authentication_MC` requires the custom proof oracle
(`models/oracle_e2eqss.py`, applied per-lemma with `[heuristic=O]`) to converge;
it takes 327 steps.

## Notes for a reader checking this work

- **The proofs of concept are formal-methods artifacts, not runnable exploits.**
  The targets are protocol proposals, not deployed software, so no CVE applies.
- **`hybrid_secure_if_dh_survives` does not terminate in the full E2EQSS model**
  under any heuristic tried, including the custom oracle. FC-01 is instead
  confirmed constructively in an isolated model with the relevant reveal rules
  removed, so any trace found necessarily has the ECDH leg intact. This is
  stated rather than papered over, and closing it in the full model would
  strengthen the result.
- **Both legs of the E2EQSS hybrid are abstracted as idealized secret
  delivery**, including the ECDH leg. This is faithful for the hybrid property
  under test and removes the Diffie–Hellman AC-unification that otherwise makes
  the lemmas non-terminating. The reasoning is in `REPORT.md` §5.1.
- **`references/eprint_2024_230.pdf` is not a source for this work.** It is
  "Analysis of Layered ROLLO-I", a code-based KEM cryptanalysis paper, pulled by
  mistake while searching for the TU/e key-update paper (Tanja Lange is a
  co-author of both). It is cited nowhere and should be deleted.

## Status

Phases 0–4 complete. The verification report is drafted. Remaining steps are
outward-facing and deliberately left for a human: courtesy notice to the
proposal authors, then the CCSDS Security Working Group; a Zenodo DOI for the
models and captured proofs; and a venue decision (see `paper/paper.md` §9.3 —
Project C targets the same workshop).

## Licence

MIT for the models, code and write-ups. Third-party papers and standards in
`references/` are not ours to redistribute and are excluded from version
control.
