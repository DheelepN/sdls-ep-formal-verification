# Formal Verification of Proposed Post-Quantum Key-Update Mechanisms for CCSDS SDLS-EP

**Author:** N. Dheelep Sai Gupthaa
**Status:** Draft verification report (Project B)
**Scope:** Symbolic (Dolev–Yao) analysis in the Tamarin Prover of two proposed extensions to the CCSDS Space Data Link Security Extended Procedures (SDLS-EP), delivered as input to the CCSDS Security Working Group and to the proposal authors during the ongoing standardization window.

---

## 1. Summary

SDLS-EP today uses symmetric cryptography with pre-shared keys only: a compromised key cannot be replaced, so key compromise is permanent for the mission, and there is no post-compromise security. Two proposals aim to fix this:

1. **Triple-KEM / Dual-KEM** — Hülsing, Lange & Weber, *A Key-Update Mechanism for the Space Data Link Security Protocol*, CANS 2025. A standalone, KEM-based, post-quantum key-establishment protocol. Per the paper (§1.5), CCSDS, under ESA's lead, has begun standardizing the Triple-KEM proposal as a Blue Book.
2. **E2EQSS** — Wildfeuer et al., *End-to-End Quantum-Safe Security for Satellite Data Links*, ESA 3S 2025. A hybrid ML-KEM + ECDH handshake with ML-DSA certificate authentication, layered onto the CCSDS/SDLS stack.

The authors of proposal 1 provide a hand-written computational proof (a modified Bellare–Rogaway model, "BR'"). No published mechanized or symbolic proof of either protocol existed prior to this work. The authors of proposal 2 report a Tamarin analysis limited to replay and man-in-the-middle, unpublished and self-described as "still ongoing"; they do not address forward secrecy, post-compromise security, or the hybrid guarantee.

This report contributes independent Tamarin models and machine-checked results. Every Triple-KEM and Dual-KEM result is checked on two versions of the protocol: **as published** (Fig. 1 of the CANS paper, without a long-term key update, where M2 carries only the two ciphertexts), and **with a SAT→MC key confirmation added to M2**. Up to v1.1 this report checked only the second and presented it as Fig. 1; §3.1 explains the correction. Headline outcomes:

| # | Result | Nature |
|---|--------|--------|
| FA-01 | **As published:** key secrecy, post-compromise security (after psk compromise) and SAT's authentication of MC hold. MC's authentication of SAT and key agreement do **not**, even with no key compromised: MC receives nothing from SAT that it can check, so a genuine M2 re-routed from another rekey session makes MC complete a rekey SAT never ran. Forward secrecy holds while the psk is secret and fails once it leaks. **With the SAT→MC confirmation added:** all seven properties verify. | Mechanized, both versions (§3.2). |
| FA-02 | Dual-KEM loses responder authentication (as the authors state) and, once the pre-shared key is compromised, loses post-compromise security entirely — the adversary impersonates the satellite by encapsulating to public keys it can read. Identical on both versions. | Boundary made precise, with attack traces. |
| **FB-01** | **Triple-KEM permits a rekey desynchronization under space channel constraints (pass window + no abort-and-retry): a single lost key-confirmation leaves mission control on the new key and the spacecraft on the old one, and the proposal defines no recovery step. Requires no cryptographic compromise, is invisible to the BR' proof, and holds on both versions: the SAT→MC confirmation does not remove it.** | **Availability, mechanized (§4).** |
| FB-01 fix | A four-message variant (spacecraft acknowledges; mission control activates only on the acknowledgement; spacecraft keeps the old key until the first frame under the new one) closes FB-01 on both versions, and on the published one also closes the re-routing in FA-01. The fourth message alone does not suffice: a lost acknowledgement leaves the spacecraft ahead of mission control (two generals), which is safe only because the old key is kept. | Mitigation, mechanized (§4.5). |
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

Model files: as published, [`models/triple_kem_published.spthy`](models/triple_kem_published.spthy) and [`models/dual_kem_published.spthy`](models/dual_kem_published.spthy); with the SAT→MC confirmation added, [`models/triple_kem.spthy`](models/triple_kem.spthy) and [`models/dual_kem.spthy`](models/dual_kem.spthy).

### 3.1 Protocol as modeled

Roles: initiator = Mission Control (MC), responder = Satellite (SAT). Long-term KEM keypairs for MC and SAT; ephemeral KEM keypair generated by MC.

**As published** (CANS paper, Fig. 1, "with psk", without the optional long-term key update, i.e. the bracketed `pk_mc_new` / `pk_sat_new` absent):

```
M1  MC -> SAT :  AEAD_psk( c_sat , pk_e )
M2  SAT-> MC  :  AEAD_psk( c_e , c_mc )
M3  MC -> SAT :  confirm_mc

c_sat = Encap(pk_sat)   -- challenges SAT's long-term key (authenticates SAT)
c_e   = Encap(pk_e)     -- ephemeral encapsulation (forward secrecy)
c_mc  = Encap(pk_mc)    -- challenges MC's long-term key (authenticates MC)
th    = H(c_sat, pk_e, c_e, c_mc)
k     = KDF(psk, ss_sat, ss_e, ss_mc, th)
```

**With the SAT→MC confirmation added**, M2 is `AEAD_psk( c_e , c_mc , confirm_sat )`, where `confirm_sat` is a MAC under k over the transcript hash.

*Correction in v1.2.* Earlier releases modelled only the second version and described its bidirectional confirmation as "matching the paper's insistence on key confirmation". That was wrong for the case modelled. The paper does insist on key confirmation (§1.3). In Fig. 1, MC confirms explicitly in M3 (Table 1 lists the third packet at 16 bytes, the size of one tag), while SAT's confirmation is carried by the optional updated long-term key in M2, which the figure shows protected under the handshake's shared secrets. When the long-term key is not updated — the case modelled here — that payload is absent and M2 carries no confirmation. The literal protocol is now modelled, and the earlier models are kept as the confirmed version, so the effect of that one message element is visible lemma by lemma. The case *with* a long-term key update is not modelled. The paper defers its detailed protocol descriptions and the BR' definitions to a full version (its reference [12]) that, as far as we can find, is not public; "as published" therefore means Fig. 1 and §2.1 of the CANS paper.

Dual-KEM is Triple-KEM with `c_sat` (and the optional `pk_sat_new`) removed, so `k = KDF(psk, ss_e, ss_mc, th)` has no `ss_sat` term.

### 3.2 Results — Triple-KEM

| Lemma | As published | With SAT→MC confirmation |
|-------|--------------|--------------------------|
| `executable` | verified | verified |
| `key_secrecy` | verified | verified — secret unless an honest long-term key was revealed; psk compromise alone does not break it |
| `post_compromise_security` | verified | verified — key stays secret even with the psk revealed, given intact long-term/ephemeral keys |
| `mutual_authentication_SAT` | verified | verified — injective agreement, SAT's view (MC authenticated to SAT) |
| `forward_secrecy` | **falsified** | verified — revealing a long-term key *after* a session does not expose the earlier key |
| `forward_secrecy_psk_intact` | verified | — |
| `mutual_authentication_MC` | **falsified** | verified — injective agreement, MC's view (SAT authenticated to MC) |
| `mutual_authentication_MC_psk_intact` | **falsified** | — |
| `key_agreement` | **falsified** | verified |
| `key_agreement_psk_intact` | **falsified** | — |
| `mc_completes_without_sat` (exists-trace) | verified — no key of any kind revealed | — |

No wellformedness warnings in either model.

**As published, MC's authentication of SAT is only implicit.** The key MC derives can be computed only by the intended SAT (`key_secrecy` holds), but nothing in M2 lets MC check that SAT computed it: M2 is authenticated only by the psk, which is the same for every rekey between the pair, and it carries nothing bound to MC's M1. The counterexample to `mutual_authentication_MC_psk_intact` takes a genuine M2 that SAT produced in a different rekey session and delivers it to MC. MC derives a key from a transcript SAT never saw, confirms, and completes; `mc_completes_without_sat` witnesses this with no psk, long-term key or other reveal anywhere in the trace. In the model MC proceeds regardless of whether decapsulation "succeeds"; that matches KEMs with implicit rejection, such as ML-KEM (FIPS 203), whose decapsulation of a ciphertext made for another key returns a pseudorandom value rather than an error. The consequence for availability is in §4.3.

Forward secrecy on MC's side degrades for a related reason. With the psk intact it verifies. Once the psk leaks, an active adversary can forge M2 with an ephemeral ciphertext it made itself, so MC's key no longer depends on a secret that later long-term-key compromise cannot reach.

With the SAT→MC confirmation in M2, every one of these verifies: MC commits only after checking a tag that only a party holding k could produce.

We report this as a property of the published text, not as a novel attack: adding an authenticated SAT payload to M2 is the evident repair, and the confirmed model shows it is sufficient. The CANS paper states that its BR' analysis proves "both confidentiality and authenticity of the resulting keys" (§4), with the definitions in the full version. Whether that authenticity is implicit or explicit decides whether the MC-side result is outside the theorem's scope or in tension with it. We have not seen those definitions and make no claim either way.

`post_compromise_security` is a special case of `key_secrecy`, which already lets the adversary reveal the psk; it is listed separately to make the psk-compromise scenario explicit, not as an independent result. Healing after *long-term* key compromise is not modelled. Likewise `key_secrecy` excuses the reveal of either party's long-term key, so key-compromise impersonation resistance is not claimed.

On confidentiality, both versions independently corroborate the BR' proof; on authentication, the confirmed version does. Either way this supplies the mechanized artifact the proposal currently lacks.

### 3.3 Results — Dual-KEM

Both versions give the same verdicts (`dual_kem_published.spthy` and `dual_kem.spthy`).

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

Model files: [`models/triple_kem_space_published.spthy`](models/triple_kem_space_published.spthy) (as published) and [`models/triple_kem_space.spthy`](models/triple_kem_space.spthy) (with the SAT→MC confirmation). Prover output: [`traces/triple_kem_space_published_proof.txt`](traces/triple_kem_space_published_proof.txt), [`traces/triple_kem_space_proof.txt`](traces/triple_kem_space_proof.txt).

### 4.1 What the BR' proof does not cover

The computational proof establishes confidentiality and authenticity of the derived key against a network adversary. It does not model the space channel. The paper concedes this directly (Sec. 3): on packet loss or reordering the protocol "needs to assume an attack and drop the connection," and reordering/re-request is deferred to a lower layer. Two further space facts compound it: a spacecraft is reachable only during a pass (a one-way window), and a failed handshake may not be retryable at will.

### 4.2 Model

A contact/pass window is a linear `!Contact` token, minted when SAT sends M2 and consumed when SAT processes M3; rule `Pass_ends` destroys the token (the pass closes before M3 arrives), and there is no retry. Crucially, key **activation** is separated from key derivation: MC activates the new key on sending M3 (`KeyActiveMC`), but SAT activates only on receiving M3 (`KeyActiveSat`). This follows the paper's own design rule (§1.3): "we instead derive the final keys only once everything in the handshake has been completed by the party in question". MC's part is complete when it sends M3; SAT's is complete only when it receives M3.

### 4.3 Results

| Lemma | As published | With SAT→MC confirmation |
|-------|--------------|--------------------------|
| `executable` | verified | verified — an honest run still completes both-sided within a pass |
| `rekey_atomicity` | **falsified** | **falsified (attack trace)** — MC activates while SAT never does. The counterexample is M3 not being delivered; it does not need `Pass_ends` |
| `desync_reachable` | **verified** | **verified (exists-trace)** — MC activates, pass ends, SAT never activates, with **no** long-term-key or psk compromise in the trace |
| `desync_by_splice` (exists-trace) | **verified** — MC activates a key SAT never derived; no message lost, no pass ended, no key revealed | — (excluded by `mutual_authentication_MC`, §3.2) |
| `replay_resistance_timing_independent` | verified | verified — freshness rests on the transcript hash and fresh ephemerals, not on timers |
| `key_secrecy` | verified | verified — confidentiality unaffected by the space model |

### 4.4 Finding and mitigation

**FB-01 (availability).** Triple-KEM as specified permits a **rekey desynchronization with no defined recovery**. Because key confirmation gates SAT-side activation, a single lost M3 across a closing pass window leaves MC on the new key and SAT on the old one, with no automatic recovery under the no-abort-and-retry constraint. Subsequent SDLS traffic under the new master key is then rejected by the spacecraft. This is a liveness/availability failure that the secrecy-and-authentication BR' proof cannot observe, and it requires no cryptographic compromise.

What the prover does and does not establish: it shows the desynchronized state is reachable, and the counterexample is simply the last message not arriving — the same trace exists in the plain `triple_kem.spthy`. What the space model adds is that the loss is final for that session. "No recovery" is a property of the proposal, which defines no recovery step, not a property Tamarin derives; the finding is that the specification needs one.

FB-01 is independent of the M2 question in §3.2: it holds with and without the SAT→MC confirmation, because that confirmation tells MC that SAT *derived* k, not that SAT *activated* it, and activation still waits for M3. On the published version there is a second route to the same state that needs no lost message at all: the re-routed M2 of §3.2 makes MC activate a key SAT never derived (`desync_by_splice`).

`replay_resistance_timing_independent` is the paired positive result: the protocol's freshness does not depend on timing, so the minutes-to-hours round trips of deep space do not weaken replay resistance. The desynchronization is therefore specifically an *activation/liveness* issue, not a freshness one.

**Recommended mitigation.** No finite number of messages makes the switch atomic over a channel that can lose any of them (the coordinated-attack, or "two generals", problem). What any fix must guarantee is therefore not atomicity but that the spacecraft can process mission control's traffic under **whichever key mission control is using**: in practice, the spacecraft **keeps the previous key** until it has evidence that mission control switched, such as the first authenticated frame under the new key. The mechanized realisation in §4.5 adds a spacecraft→ground acknowledgement: mission control activates only on it, and the spacecraft retains the old key until mission control's first frame under the new one. The acknowledgement alone is not sufficient: a lost acknowledgement leaves the spacecraft on the new key and mission control on the old one, which is safe only because the old key is kept. Other realisations of the same condition may need no fourth message, for example a spacecraft that holds a derived key as pending and accepts mission control's first authenticated frame under it as confirmation; those are not modelled here.

### 4.5 The four-message fix

Model files: [`models/triple_kem_space_4pass_published.spthy`](models/triple_kem_space_4pass_published.spthy) (built on the published M2) and [`models/triple_kem_space_4pass.spthy`](models/triple_kem_space_4pass.spthy) (built on M2 with the SAT→MC confirmation). Prover output: [`traces/triple_kem_space_4pass_published_proof.txt`](traces/triple_kem_space_4pass_published_proof.txt), [`traces/triple_kem_space_4pass_proof.txt`](traces/triple_kem_space_4pass_proof.txt).

The model keeps §4.2's pass window and adds: MC does not activate on sending M3; SAT activates on a valid M3, keeps the old key, and sends M4 = MAC_k('ack', th); MC activates on a valid M4 and then sends traffic under k; SAT retires the old key on the first authenticated frame under k. M3 can be lost to the pass closing or the network, M4 to the network.

| Lemma | On published M2 | On M2 with SAT→MC confirmation |
|-------|-----------------|--------------------------------|
| `executable` | verified | verified — the full rekey, including retirement of the old key, completes with no compromise |
| `mc_activation_safe` | verified | verified — MC activates k only after SAT activated k (the property `rekey_atomicity` fails in §4.3) |
| `sat_retirement_safe` | verified | verified — SAT retires the old key only after MC activated k |
| `sat_activation_implies_mc_activation` | **falsified (expected)** | **falsified (expected)** — a lost M4 leaves SAT active on k and MC not: the two-generals residue |
| `residual_asymmetry_reachable` | verified | verified (exists-trace) — that state, with the old key still held by SAT and no compromise; exported to [`traces/fb01_fix_residual.dot`](traces/fb01_fix_residual.dot) |
| `desync_by_splice` (exists-trace) | **no trace found** — the fix also closes the re-routing of §3.2 | — |
| `replay_resistance_timing_independent` | verified | verified |
| `key_secrecy` | verified | verified |

MC only ever sends under the old key or, after activation, under k. By `mc_activation_safe` SAT already holds k by then; by `sat_retirement_safe` SAT still holds the old key for as long as MC may be using it. So SAT always holds the key MC is using, whichever message is lost. Both safety lemmas were mutation-checked on the confirmed version: restoring the three-message activation falsifies `mc_activation_safe`, and letting SAT retire on its own M4 falsifies `sat_retirement_safe`.

The fix does not depend on the M2 confirmation. M4 is a MAC under k, so MC activates only on evidence that SAT holds the key MC derived, whatever M2 carried. For the same reason a re-routed M2 no longer causes a desynchronization: MC derives a key SAT does not have, no valid M4 can arrive for it, and MC stays on the old key.

Two edge cases are left open for a specification; they are set out as directives in §4.7.

### 4.6 Operational edge-case matrix

The following table enumerates the single-message-loss cases on the space channel
exhaustively. Cases 2 and 3 are established directly by the named lemmas of §4.5;
Cases 1, 4 and 5 are corollaries of the same activation ordering, or hold by
construction, as each row states. The distinction is deliberate: the model proves the
activation ordering (`mc_activation_safe`, `sat_retirement_safe`) and the reachability
of the residual state (`residual_asymmetry_reachable`); the remaining cases follow from
that ordering rather than being separately proved traces.

#### Case 1 — M3 lost (pass window closes, RF dropout, adversary drop)

MC sent M3 but SAT never received it.

- **3-message protocol (§4.3):** Fatal. MC activated the new key on sending M3; SAT is
  still on the old key. All subsequent telecommand frames are rejected, and the proposal
  defines no recovery mechanism.
- **4-message protocol (§4.5):** Safe. MC does not activate on sending M3 (rule `MC_3`
  requires a valid M4), and SAT does not activate without M3 (rule `SAT_2` requires it).
  Both sides remain on the old key; telecommand capability is preserved. This is a
  corollary of `mc_activation_safe`: with no `KeyActiveSat`, MC never reaches
  `KeyActiveMC`. Re-initiating the rekey on a later pass is an operational action outside
  the model — the model contains no retry rule; `Pass_ends` simply ends the session.

#### Case 2 — M4 lost (the two-generals residue)

SAT received M3, activated k, retained the old key, and sent M4 (ACK). M4 was dropped.

- **State:** SAT holds k (active) *and* the old key (retained). MC never received the
  ACK, so MC remains on the old key.
- **Backing:** this is the residual state shown reachable with no compromise by
  `residual_asymmetry_reachable` (verified exists-trace), and the expected falsification
  of `sat_activation_implies_mc_activation`; exported to `traces/fb01_fix_residual.dot`.
- **Why it is safe:** MC's next telecommand frame is sent under the old key. By
  `sat_retirement_safe`, SAT retires the old key only after MC has activated k, which has
  not happened here, so SAT still holds the old key and can process MC's traffic. Safety
  in this case rests on that ordering argument, as in §4.5 — the model verifies the
  retirement ordering, not old-key frame acceptance directly.

#### Case 3 — Both M3 and M4 arrive (nominal success)

- MC activates k on receiving M4 (`mc_activation_safe` verified — MC activates only after
  SAT).
- MC sends the first operational frame under k.
- SAT receives it, verifies it under k, and retires the old key (`sat_retirement_safe`
  verified — old key retired only after MC activated k).
- The `executable` lemma witnesses the full sequence (`KeyActiveSat`, `KeyActiveMC`,
  `RetireOldSat`) with no compromise. Clean, fully synchronized transition.

#### Case 4 — M1 or M2 lost

The rekey handshake never reaches key confirmation, so neither side derives or activates
k. Both remain on the old key. Safe by construction: with no `KeyActiveSat` or
`KeyActiveMC` event, the activation lemmas hold vacuously and no state transition occurs.
This is indistinguishable from "no rekey attempted."

#### Case 5 — F lost (the first frame under k)

MC received a valid M4, activated k, and sent the first frame F under k; F was dropped.

- **State:** MC is on k. SAT holds both keys — it has not retired the old key, because
  `SAT_retire` requires F.
- **Why it is safe:** both sides hold k, so MC continues under k and SAT, holding k,
  processes it; SAT simply retains the old key longer than the nominal case until an
  authenticated frame under k arrives. No dead state. This is the benign counterpart of
  Directive 1 (§4.7): an active k alongside an un-retired old key, resolved by MC's next
  frame.

### 4.7 Open specification directives

Two edge cases require normative text in a Blue Book revision. The Tamarin model in §4.5
does not address them because they concern policy timeouts and session management, not
cryptographic safety properties; both are named as out of scope in the model header.

**Directive 1 — Pending key expiry.** If M4 is lost and ground never sends traffic under
k (for example, no further passes are scheduled, or the mission enters safe mode), SAT
holds k indefinitely in a pending slot alongside the old key. The specification must
define either (a) a normative timeout after which SAT discards the uncommitted key k and
reverts to single-key state, or (b) a ground-initiated "abort pending rekey" directive
that explicitly flushes k.

**Directive 2 — Rekey session concurrency.** If a second rekey is initiated (a new M1)
while SAT still holds both the old key and an unconfirmed k from a previous session, the
specification must mandate what happens to k. The simplest safe rule is that a new M1
automatically invalidates any uncommitted pending key, preventing key-table exhaustion
on resource-constrained spacecraft memory. Without such a rule, repeated failed rekeys
could fill SAT's key storage.


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

- Triple-KEM/Dual-KEM findings (FA-01, FA-02, FB-01): these are analyses of published proposals, not of deployed operational software. Courtesy notice sent to the proposal authors ahead of any public release. CCSDS Security Working Group notice in progress. The four-message models (§4.5) are offered as a template for checking any revised specification, with or without a SAT→MC confirmation in M2.
- E2EQSS (FC-01): courtesy notice sent to the author ahead of any public release. FC-01 rests on the E2EQSS signatures covering only static keys. That is how the E2EQSS paper describes the design (Sec. VI.B): ML-DSA-65 appears only as the CA's signature on certificates binding each party's identity to its long-term ML-KEM key, and no signature by either party over the ephemeral keys or the transcript is described. The reading should still be confirmed with the authors before it is cited.
- Models and captured proofs are published as a Zenodo artifact (DOI 10.5281/zenodo.22907127); the Tamarin theory files are as much the contribution as the report.
- Venue: SpaceSec / CCSDS SWG technical input; the mechanized-verification-during-standardization framing is the durable contribution.
