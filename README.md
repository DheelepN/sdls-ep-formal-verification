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
| FA-01 | Triple-KEM satisfies key secrecy, forward secrecy, post-compromise security (after psk compromise), injective mutual authentication in both directions, and key agreement, under a network adversary who may reveal the pre-shared key at any time and any long-term key after the session | Positive — corroborates the BR′ proof, mechanized |
| FA-02 | Dual-KEM loses responder authentication, and once the pre-shared key is compromised loses post-compromise security entirely | Boundary made precise, with attack traces |
| **FB-01** | **Triple-KEM permits a rekey desynchronization under space channel constraints: one lost key confirmation across a closing pass window leaves ground on the new key and the spacecraft on the old one, and the proposal defines no recovery step** | **Availability — confirmed by the proposal authors** |
| FB-01 fix | A four-message variant — the spacecraft acknowledges activation, ground activates only on the acknowledgement, the spacecraft keeps the old key until the first frame under the new one — closes FB-01. The fourth message alone does not: a lost acknowledgement leaves the spacecraft ahead of ground | Mitigation, mechanized |
| FC-01 | E2EQSS is hybrid for confidentiality but **not** for authentication: its certificates sign only static keys, so a broken ML-KEM lets an adversary replay a certificate with its own ephemerals | Finding, confirmed constructively |

**FB-01 is the one with operational consequences.** It requires no cryptographic
compromise — the witness trace is one undelivered message, with no key reveal
of any kind — and it is structurally invisible to a proof that establishes
secrecy and authentication, because both-sided completion is neither of those
properties.

*Mitigation:* mission control must not activate the new SDLS master key until it
has positive evidence the spacecraft activated it — an acknowledgement (a fourth
message). That alone is not enough: no number of messages makes the switch
atomic over a lossy link (the two generals problem), and a lost acknowledgement
leaves the spacecraft on the new key and ground on the old one. The fix is safe
when the spacecraft also **keeps the old key** until it sees traffic under the
new one. `models/triple_kem_space_4pass.spthy` verifies exactly that: ground
activates only after the spacecraft, and the spacecraft retires the old key only
after ground activated, so the two always share a key whichever message is lost.
It is a small change now and an expensive one after adoption.

## Layout

```
models/      Tamarin theories (.spthy) and the E2EQSS proof oracle
traces/      Captured prover output, and exported attack traces (.dot/.png)
poc/         Walkthroughs of the three attack findings
REPORT.md    Verification report, the disclosure-facing document
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
tamarin-prover --prove models/triple_kem_space.spthy       # FB-01
tamarin-prover --prove models/triple_kem_space_4pass.spthy # FB-01 fix
tamarin-prover --prove models/e2eqss.spthy                 # uses the oracle
tamarin-prover --prove models/e2eqss_fc01.spthy            # FC-01 attack
```

`reproduce.sh` runs all six and checks every verdict and step count against
the captured output in `traces/`; it exits non-zero on any difference.

The E2EQSS model's `mutual_authentication_MC` requires the custom proof oracle
`models/oracle_e2eqss.py` to converge (327 steps). The lemma names it itself —
`[heuristic=O "oracle_e2eqss.py"]`, resolved relative to the theory file — so
no command-line flag is needed; the oracle must be executable.

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
- **What FB-01 is and is not.** Tamarin shows the desynchronized state is
  reachable; the counterexample is simply the last message not arriving.
  "No recovery" is a property of the proposal, which defines no recovery step,
  not something the prover derives. The finding is that the specification
  needs one.
- **E2EQSS authentication is checked in mission control's view only**
  (`mutual_authentication_MC`); the spacecraft's view is not stated as a lemma.

## Changes since v1.0

- **Dual-KEM `initiator_auth_holds` was vacuous in v1.0.** It required
  `Running(SAT, MC, …)` — the spacecraft's own earlier step — so it held
  trivially (4 steps). Mission control now emits a `Running` event and the lemma
  requires it; it verifies (11 steps), now without the psk-intact escape clause.
  A mutation check (removing `ss_mc` from the key) falsifies it, as it should.
- **Triple-KEM mutual authentication is now checked in both directions.**
  v1.0 checked only mission control's view; `mutual_authentication_SAT` adds the
  spacecraft's (injective, 25 steps).
- **New model `triple_kem_space_4pass.spthy`** for the FB-01 fix (above).
- **FC-01 prover output is now captured in full.** In v1.0
  `traces/e2eqss_fc01_proof.txt` stopped before the result.
- **Reproducibility.** v1.0's `reproduce.sh` pointed at the oracle by a path
  Tamarin did not resolve, and neither the script nor the oracle was committed
  as executable, so the E2EQSS proof failed from a fresh clone; the script also
  hid failures. Fixed, with a single oracle file, and the script now checks
  verdicts. The E2EQSS wellformedness warning in v1.0 was a derivation-check
  timeout; re-run, all wellformedness checks succeed.
- Wording: "atomic" rekey corrected (see the mitigation above); "no recovery"
  explained as a property of the proposal rather than a prover result; the
  post-compromise lemma is described as what it is, a special case of key
  secrecy.

All other verdicts and step counts are unchanged from v1.0.

## Status

Phases 0–4 complete. The verification report is drafted. Courtesy notice sent
to the Triple-KEM/Dual-KEM authors (Hülsing, Lange) and to the E2EQSS author
(Wildfeuer) — both replied; the proposal authors confirmed FB-01. CCSDS
Security Working Group notice in progress. Remaining: a venue decision.

## Cite this work

If you use these models or results, please cite the archived release (the
Tamarin theory files are as much the contribution as the report — they are
what lets a revised protocol be re-verified rather than re-argued):

```bibtex
@software{gupthaa_sdls_ep_2026,
  author       = {Gupthaa, N. Dheelep Sai},
  title        = {{Mechanized Analysis of Post-Quantum Key-Update
                   Proposals for CCSDS SDLS-EP}},
  year         = {2026},
  publisher    = {Zenodo},
  doi          = {10.5281/zenodo.22907127},
  url          = {https://doi.org/10.5281/zenodo.22907127}
}
```

DOI `10.5281/zenodo.22907127` always resolves to the latest release; see
[`CITATION.cff`](CITATION.cff) for a machine-readable version.

## Licence

MIT for the models, code and write-ups. Third-party papers and standards in
`references/` are not ours to redistribute and are excluded from version
control.
