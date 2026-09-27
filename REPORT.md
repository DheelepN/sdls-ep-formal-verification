# Formal Verification of Proposed Post-Quantum Key-Update Mechanisms for CCSDS SDLS-EP

**Author:** N. Dheelep Sai Gupthaa
**Status:** Draft verification report (Project B)
**Scope:** Symbolic (Dolev–Yao) analysis in the Tamarin Prover of two proposed extensions to the CCSDS Space Data Link Security Extended Procedures (SDLS-EP), delivered as input to the CCSDS Security Working Group and to the proposal authors during the ongoing standardization window.

---

## 1. Summary

SDLS-EP today uses symmetric cryptography with pre-shared keys only: a compromised key cannot be replaced, so key compromise is permanent for the mission, and there is no post-compromise security. Two proposals aim to fix this:

1. **Triple-KEM / Dual-KEM** — Hülsing, Lange & Weber, *A Key-Update Mechanism for the Space Data Link Security Protocol*, CANS 2025. A standalone, KEM-based, post-quantum key-establishment protocol. ESA has led CCSDS to begin standardizing the Triple-KEM proposal as a Blue Book.
2. **E2EQSS** — Wildfeuer et al., *End-to-End Quantum-Safe Security for Satellite Data Links*, ESA 3S 2025. A hybrid ML-KEM + ECDH handshake with ML-DSA certificate authentication, layered onto the CCSDS/SDLS stack.

The authors of proposal 1 provide a hand-written computational proof (a modified Bellare–Rogaway model, "BR'"). No mechanized or symbolic proof of either protocol existed prior to this work. The authors of proposal 2 report a Tamarin analysis limited to replay and man-in-the-middle, unpublished and self-described as "still ongoing"; they do not address forward secrecy, post-compromise security, or the hybrid guarantee.

This report contributes independent Tamarin models and machine-checked results. Headline outcomes:

| # | Result | Nature |
|---|--------|--------|
| FA-01 | Triple-KEM satisfies key secrecy, forward secrecy, post-compromise security (after psk compromise), injective mutual authentication in both directions, and key agreement under a full Dolev–Yao adversary that may compromise the pre-shared key at any time and any long-term key after the session. | Positive — corroborates the BR' proof, mechanized. |
| FA-02 | Dual-KEM loses responder authentication (as the authors state) and, once the pre-shared key is compromised, loses post-compromise security entirely — the adversary impersonates the satellite by encapsulating to public keys it can read. | Boundary made precise, with attack traces. |
| **FB-01** | **Triple-KEM permits a rekey desynchronization under space channel constraints (pass window + no abort-and-retry): a single lost key-confirmation leaves mission control on the new key and the spacecraft on the old one, and the proposal defines no recovery step. Requires no cryptographic compromise, and is invisible to the BR' proof.** | **Availability — confirmed by the proposal authors.** |
| FB-01 fix | A four-message variant (spacecraft acknowledges; mission control activates only on the acknowledgement; spacecraft keeps the old key until the first frame under the new one) closes FB-01. The fourth message alone does not: a lost acknowledgement leaves the spacecraft ahead of mission control (two generals), which is safe only because the old key is kept. | Mitigation, mechanized (§4.5). |
| FC-01 | E2EQSS achieves authenticated key secrecy, replay resistance, and hybrid security in the ML-KEM-surviving direction (all machine-verified). The ECDH-surviving direction (ML-KEM broken) does **not** hold — **machine-confirmed** by an isolated attack trace: certificates authenticate only static keys, so per-session authentication rides entirely on the KEM challenge, and a broken ML-KEM lets an adversary replay an honest certificate with its own ephemeral keys and recover the master secret. | Finding — E2EQSS is hybrid for confidentiality but not authentication. |

FB-01 is the finding with the most operational significance and is described in full in §4.

---

## 2. Method

All models are in [`models/`](models/); captured prover output is in [`traces/`](traces/). Reproduce with `tamarin-prover --prove <model>.spthy` (Tamarin 1.12.0, Maude 3.1).

**KEM abstraction.** An IND-CCA KEM is modeled as public-key encryption of a fresh shared secret: `Encap(pk) = aenc(~ss, pk)`, `Decap(sk, c) = adec(c, sk)`. This is the standard sound Dolev–Yao abstraction; it captures that only the private-key holder recovers the shared secret, and that any party can encapsulate to a public key (the property that drives FA-02).

**Pre-shared key is revealable.** The psk that authenticated-encrypts the flights can be revealed by the adversary (`Reveal_psk`). Consequently security cannot rest on the psk and must be provided by the KEMs — which is exactly what makes the post-compromise claim non-trivial to check, and matches the paper's intent that the psk is only a defense-in-depth measure (and may be all-zero).

**Adversary.** Full Dolev–Yao network control, plus compromise of any long-term key (`Reveal_ltk`) and any psk. `Honest`/`LtkReveal` action facts scope the reveal exceptions inside each lemma so that "secure unless a relevant key was compromised" is stated precisely.

---

## 3. Triple-KEM and Dual-KEM (Phase 1)

Model files: [`models/triple_kem.spthy`](models/triple_kem.spthy), [`models/dual_kem.spthy`](models/dual_kem.spthy).

### 3.1 Protocol as modeled

Roles: initiator = Mission Control (MC), responder = Satellite (SAT). Long-term KEM keypairs for MC and SAT; ephemeral KEM keypair generated by MC.

```
M1  MC -> SAT :  AEAD_psk( c_sat , pk_e )
M2  SAT-> MC  :  AEAD_psk( c_e , c_mc , confirm_sat )
M3  MC -> SAT :  confirm_mc

c_sat = Encap(pk_sat)   -- challenges SAT's long-term key (authenticates SAT)
c_e   = Encap(pk_e)     -- ephemeral encapsulation (forward secrecy)
c_mc  = Encap(pk_mc)    -- challenges MC's long-term key (authenticates MC)
th    = H(c_sat, pk_e, c_e, c_mc)
k     = KDF(psk, ss_sat, ss_e, ss_mc, th)
```

Key confirmation is bidirectional (SAT confirms in M2, MC confirms in M3), matching the paper's insistence on key confirmation. Dual-KEM is Triple-KEM with `c_sat` (and the optional `pk_sat_new`) removed, so `k = KDF(psk, ss_e, ss_mc, th)` has no `ss_sat` term.

### 3.2 Results — Triple-KEM (all verified, no wellformedness warnings)

| Lemma | Result |
|-------|--------|
| `executable` | verified |
| `key_secrecy` | verified — secret unless an honest long-term key was revealed; psk compromise alone does not break it |
| `forward_secrecy` | verified — revealing a long-term key *after* a session does not expose the earlier key |
| `post_compromise_security` | verified — key stays secret even with the psk revealed, given intact long-term/ephemeral keys |
| `mutual_authentication_MC` | verified — injective agreement, MC's view (SAT authenticated to MC) |
| `mutual_authentication_SAT` | verified — injective agreement, SAT's view (MC authenticated to SAT) |
| `key_agreement` | verified |

`post_compromise_security` is a special case of `key_secrecy`, which already lets the adversary reveal the psk; it is listed separately to make the psk-compromise scenario explicit, not as an independent result. Healing after *long-term* key compromise is not modelled. Likewise `key_secrecy` excuses the reveal of either party's long-term key, so key-compromise impersonation resistance is not claimed.

The symbolic analysis independently corroborates the authors' BR' proof and supplies the mechanized artifact the proposal currently lacks.

### 3.3 Results — Dual-KEM

| Lemma | Result |
|-------|--------|
| `executable` | verified |
| `initiator_auth_holds` | verified — MC remains authenticated to SAT via `c_mc`, even with the psk revealed (corrected in v1.1: the v1.0 lemma was vacuous, see README) |
| `responder_auth_expected_fail` | **falsified (attack trace)** — MC cannot authenticate SAT |
| `key_secrecy_psk_intact` | verified — safe while the psk is secret |
| `post_compromise_security_expected_fail` | **falsified (attack trace)** — no post-compromise security once the psk leaks |

**FA-02.** Dual-KEM's dropped responder challenge means that, once the psk is compromised (precisely the scenario post-compromise security is meant to address), the Dolev–Yao adversary encapsulates to the public keys itself, impersonates the satellite, and derives the same key MC does. The paper's qualitative caution — use Dual-KEM only where responder authenticity is guaranteed out of band — is thereby sharpened into a precise property statement: **absent that out-of-band authentication, Dual-KEM provides confidentiality only while the psk is secret, and no post-compromise security.** The Triple-vs-Dual contrast (Triple binds `ss_sat`, recoverable only by the real SAT; Dual removes it) also serves as evidence that the models are faithful — they distinguish the two designs exactly where theory predicts.

---

## 4. Space-specific adversary — FB-01 (Phase 3)

Model file: [`models/triple_kem_space.spthy`](models/triple_kem_space.spthy). Prover output: [`traces/triple_kem_space_proof.txt`](traces/triple_kem_space_proof.txt).

### 4.1 What the BR' proof does not cover

The computational proof establishes confidentiality and authenticity of the derived key against a network adversary. It does not model the space channel. The paper concedes this directly (Sec. 3): on packet loss or reordering the protocol "needs to assume an attack and drop the connection," and reordering/re-request is deferred to a lower layer. Two further space facts compound it: a spacecraft is reachable only during a pass (a one-way window), and a failed handshake may not be retryable at will.

### 4.2 Model

A contact/pass window is a linear `!Contact` token, minted when SAT sends M2 and consumed when SAT processes M3; rule `Pass_ends` destroys the token (the pass closes before M3 arrives), and there is no retry. Crucially, key **activation** is separated from key derivation: MC activates the new key on sending M3 (`KeyActiveMC`), but SAT activates only on receiving M3 (`KeyActiveSat`), because key confirmation must precede activation.

### 4.3 Results

| Lemma | Result |
|-------|--------|
| `executable` | verified — an honest run still completes both-sided within a pass |
| `rekey_atomicity` | **falsified (attack trace)** — MC activates while SAT never does. The counterexample is M3 not being delivered; it does not need `Pass_ends` |
| `desync_reachable` | **verified (exists-trace)** — MC activates, pass ends, SAT never activates, with **no** long-term-key or psk compromise in the trace |
| `replay_resistance_timing_independent` | verified — freshness rests on the transcript hash and fresh ephemerals, not on timers |
| `key_secrecy` | verified — confidentiality unaffected by the space model |

### 4.4 Finding and mitigation

**FB-01 (availability).** Triple-KEM as specified permits a **rekey desynchronization with no defined recovery**. Because key confirmation gates SAT-side activation, a single lost M3 across a closing pass window leaves MC on the new key and SAT on the old one, with no automatic recovery under the no-abort-and-retry constraint. Subsequent SDLS traffic under the new master key is then rejected by the spacecraft. This is a liveness/availability failure that the secrecy-and-authentication BR' proof cannot observe, and it requires no cryptographic compromise.

What the prover does and does not establish: it shows the desynchronized state is reachable, and the counterexample is simply the last message not arriving — the same trace exists in the plain `triple_kem.spthy`. What the space model adds is that the loss is final for that session. "No recovery" is a property of the proposal, which defines no recovery step, not a property Tamarin derives; the finding is that the specification needs one. The proposal authors confirmed the finding.

`replay_resistance_timing_independent` is the paired positive result: the protocol's freshness does not depend on timing, so the minutes-to-hours round trips of deep space do not weaken replay resistance. The desynchronization is therefore specifically an *activation/liveness* issue, not a freshness one.

**Recommended mitigation.** Mission control must not activate or switch the SDLS master key until it has positive evidence that the spacecraft activated it — a spacecraft→ground post-activation acknowledgement. That is necessary but not sufficient. No finite number of messages makes the switch atomic over a channel that can lose any of them (the coordinated-attack, or "two generals", problem): with an acknowledgement, a lost acknowledgement leaves the spacecraft on the new key and mission control on the old one. The rekey is safe — the two sides always share a usable key — only if the spacecraft also **keeps the previous key** after activating the new one and retires it only on evidence that mission control switched, such as the first authenticated frame under the new key. §4.5 verifies this.

### 4.5 The four-message fix

Model file: [`models/triple_kem_space_4pass.spthy`](models/triple_kem_space_4pass.spthy). Prover output: [`traces/triple_kem_space_4pass_proof.txt`](traces/triple_kem_space_4pass_proof.txt).

The model keeps §4.2's pass window and adds: MC does not activate on sending M3; SAT activates on a valid M3, keeps the old key, and sends M4 = MAC_k('ack', th); MC activates on a valid M4 and then sends traffic under k; SAT retires the old key on the first authenticated frame under k. M3 can be lost to the pass closing or the network, M4 to the network.

| Lemma | Result |
|-------|--------|
| `executable` | verified — the full rekey, including retirement of the old key, completes with no compromise |
| `mc_activation_safe` | verified — MC activates k only after SAT activated k (the property `rekey_atomicity` fails in §4.3) |
| `sat_retirement_safe` | verified — SAT retires the old key only after MC activated k |
| `sat_activation_implies_mc_activation` | **falsified (expected)** — a lost M4 leaves SAT active on k and MC not: the two-generals residue |
| `residual_asymmetry_reachable` | verified (exists-trace) — that state, with the old key still held by SAT and no compromise; exported to [`traces/fb01_fix_residual.dot`](traces/fb01_fix_residual.dot) |
| `replay_resistance_timing_independent` | verified |
| `key_secrecy` | verified |

MC only ever sends under the old key or, after activation, under k. By `mc_activation_safe` SAT already holds k by then; by `sat_retirement_safe` SAT still holds the old key for as long as MC may be using it. So SAT always holds the key MC is using, whichever message is lost. Both safety lemmas were mutation-checked: restoring the three-message activation falsifies `mc_activation_safe`, and letting SAT retire on its own M4 falsifies `sat_retirement_safe`.

Left open, and needed in a specification: how SAT discards a pending new key that MC never activated, and what happens if a second rekey starts while SAT still holds both keys.

---

## 5. E2EQSS (Phase 2)

Model file: [`models/e2eqss.spthy`](models/e2eqss.spthy). Prover output: [`traces/e2eqss_proof.txt`](traces/e2eqss_proof.txt). Proof oracle: [`models/oracle_e2eqss.py`](models/oracle_e2eqss.py).

### 5.1 Protocol as modeled

Mutual authentication via ML-DSA-65 X.509 certificates (the `signing` builtin) issued by a CA (OCSP abstracted as certificate validity). Both parties hold long-term KEM keypairs; the handshake mixes a long-term KEM challenge each way (`c_ltSAT`, `c_ltMC`), an ephemeral ML-KEM leg (`c_eph`), and a classical ECDH leg into a hybrid master secret `MS = KDF(ss_ltSAT, ss_eph, ss_dh, ss_ltMC, th)`, with bilateral MAC key confirmation.

**Modeling note.** Both key-establishment legs are modeled as idealized ephemeral secret delivery (an IND-CCA KEM is public-key encryption of a fresh secret; the ECDH leg is abstracted the same way). This is faithful for the property under test — hybrid security depends only on each leg contributing an *independent* secret that the adversary cannot obtain without the corresponding ephemeral secret, not on the algebraic `g^xy` structure. It also removes the Diffie–Hellman AC-unification that otherwise makes these lemmas non-terminating. A separate reveal rule per leg (`Reveal_kem_secret`, `Reveal_dh_secret`) lets the adversary break one leg at a time.

### 5.2 Results

| Lemma | Result |
|-------|--------|
| `executable` | verified |
| `key_secrecy` | verified — authenticated key secrecy against a network adversary |
| `mutual_authentication_MC` | verified (proof oracle required; 327 steps) — agreement on the transcript hash, MC's view; SAT's view is not stated as a lemma |
| `replay_resistance` | verified — a transcript is committed at most once |
| `hybrid_secure_if_kem_survives` | verified — key holds when the ECDH leg is fully broken |
| `hybrid_secure_if_dh_survives` | did not terminate in the full model — **confirmed as a break** in the isolated model (see 5.3) |

(The v1.0 output carried a wellformedness warning: Tamarin's derivation checks had hit their default timeout. Re-run, all wellformedness checks succeed, as recorded in `traces/e2eqss_proof.txt`; `reproduce.sh` disables the timeout so slower machines do not hit it.)

This already goes materially beyond what the E2EQSS authors report (replay and MITM only): it adds machine-checked key secrecy, injective-style agreement, and both directions of the hybrid question.

### 5.3 Finding FC-01 — the ECDH leg does not protect confidentiality when ML-KEM breaks

The remaining direction — does the ECDH leg protect the key when ML-KEM is broken? — did not terminate in the full `e2eqss.spthy` under the default heuristic, alternative built-in heuristics, or a custom proof oracle, in either its all-traces or exists-trace form. It is instead **confirmed constructively** in an isolated model, [`models/e2eqss_fc01.spthy`](models/e2eqss_fc01.spthy): the full handshake trimmed to the attack-relevant rules, with the ECDH-leg-reveal and long-term-key-reveal rules deliberately removed so that any trace found has the ECDH leg intact and no long-term key compromised.

Result: `fc01_kem_broken_dh_survives_attack (exists-trace): verified (16 steps)`, captured in [`traces/e2eqss_fc01_proof.txt`](traces/e2eqss_fc01_proof.txt) and exported to [`traces/fc01_attack.dot`](traces/fc01_attack.dot). Walkthrough: [`poc/POC_FC01_e2eqss_hybrid.md`](poc/POC_FC01_e2eqss_hybrid.md).

Why the isolated trace carries over to the full model: the trimmed model omits the SAT challenge `c_ltSAT` and MC's later steps, but neither helps the satellite. In the full model the adversary builds `c_ltSAT = Encap(pk_SAT)` itself, so it chooses `ss_ltSAT` and knows it; every other KDF input is obtained exactly as in the isolated trace. The attack is on the satellite's view, which never depends on MC completing.

The attack: the ML-DSA certificates sign only each party's *static* long-term KEM key; nobody signs the per-session ephemeral public keys or the transcript. Per-session peer authentication therefore rests on the KEM challenge (only the holder of the long-term KEM secret recovers the encapsulated secret that feeds the MAC). If ML-KEM is broken, an adversary replays an honest party's public certificate, substitutes its own ephemeral keys, completes the handshake, and — with the KEM-leg secret exposed via `KemReveal` — recovers every KDF input; the surviving ECDH leg does not restore confidentiality because its ephemeral key was never authenticated. **The construction is hybrid for confidentiality but not for authentication.**

Mitigation: authenticate the transcript, or at least the ephemeral public keys, with the ML-DSA signatures, so authentication survives the loss of either primitive.

---

## 6. Disclosure and next steps

- Triple-KEM/Dual-KEM findings (FA-01, FA-02, FB-01): these are analyses of published proposals, not of deployed operational software. Courtesy notice sent to the proposal authors, who replied and confirmed FB-01. CCSDS Security Working Group notice in progress. The four-message model (§4.5) is offered as a template for checking any revised specification.
- E2EQSS (FC-01): courtesy notice sent to the author, who replied. FC-01 rests on the E2EQSS signatures covering only static keys; that reading of the design should be confirmed with the authors before it is cited.
- Publish all models and captured proofs as a Zenodo artifact with a DOI; the Tamarin theory files are as much the contribution as the report.
- Venue: SpaceSec / CCSDS SWG technical input; the mechanized-verification-during-standardization framing is the durable contribution.
