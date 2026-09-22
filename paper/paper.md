# Verify Before Adoption: Mechanized Analysis of Post-Quantum Key-Update Proposals for CCSDS SDLS-EP

**Author:** N. Dheelep Sai Gupthaa, DefenseBlu Technologies
**Status:** Full draft. Port to the target venue's template; verify every citation against its primary source first.
**Venue note:** Project C is also aimed at SpaceSec. The program's own guidance cautions against consecutive submissions to the same workshop, so a venue decision is required before submission — see §9.3.

## Abstract

The CCSDS Space Data Link Security Extended Procedures (SDLS-EP) manage keys
using symmetric cryptography and pre-shared keys only. A compromised key cannot
be replaced, so compromise is permanent for the mission and there is no
post-compromise security. Two proposals address this, and one of them — the
Triple-KEM key-update mechanism of Hülsing, Lange and Weber — has begun
standardization as a CCSDS Blue Book. Its security rests on a hand-written
computational proof in a modified Bellare–Rogaway model; no mechanized proof of
either proposal existed.

We contribute independent Tamarin models and machine-checked results for both.
Triple-KEM's claimed properties hold: key secrecy, forward secrecy,
post-compromise security, injective mutual authentication and key agreement are
all verified under a Dolev–Yao adversary that may reveal any long-term key and
the pre-shared key. The Dual-KEM variant's documented weakening is made precise
with attack traces: once the pre-shared key leaks, it provides no post-compromise
security at all.

Our principal finding is not a confidentiality break but an availability one.
Modelling the space channel — a contact window that closes, and no
abort-and-retry — shows that Triple-KEM as specified permits a **non-recoverable
rekey desynchronization**: a single lost key-confirmation message leaves mission
control on the new key and the spacecraft on the old one, with no automatic
recovery and no cryptographic compromise anywhere in the trace. This failure is
structurally invisible to a proof that establishes secrecy and authentication,
because it is neither. We give a mitigation that makes the rekey atomic across
pass boundaries. Separately, we show that E2EQSS is hybrid for confidentiality
but not for authentication, since its certificates sign only static keys.

## 1. Introduction

A satellite's cryptographic keys are, today, effectively permanent. CCSDS SDLS
and its Extended Procedures provide key management built entirely on symmetric
cryptography with pre-shared keys: keys are loaded before launch or uploaded
under an existing master key, and there is no mechanism by which a spacecraft and
its ground segment can establish a *fresh* shared secret that an adversary
holding the old material cannot derive. If a key is compromised, it stays
compromised. There is no post-compromise security.

This is not an oversight either. It is architectural: CCSDS 354.0-M-1 puts
asymmetric and public-key cryptosystems explicitly out of scope for CCSDS key
management. The consequence is that the obvious fix — run a key exchange — is
outside the standard as written.

Two proposals now aim to change that, and the timing is what makes this work
worth doing now rather than later.

**Triple-KEM / Dual-KEM** (Hülsing, Lange and Weber, CANS 2025) is a standalone,
KEM-based, post-quantum key-establishment protocol designed to sit alongside
SDLS without modifying it. Its authors state that ESA has led CCSDS to begin
standardizing the Triple-KEM proposal as a Blue Book. Its security argument is a
hand-written computational proof in a modified Bellare–Rogaway model, which we
refer to as BR'.

**E2EQSS** (Wildfeuer et al., ESA 3S 2025) is a hybrid ML-KEM plus ECDH handshake
with ML-DSA certificate authentication, layered onto the CCSDS stack.

Neither had a mechanized proof. The E2EQSS authors report a Tamarin analysis of
their own, but it is unpublished, limited to replay and man-in-the-middle, and
self-described as "still ongoing"; it does not address forward secrecy,
post-compromise security, or the hybrid guarantee that is the design's entire
rationale.

A protocol being written into a Blue Book is a protocol that will be deployed for
decades on spacecraft that cannot be patched easily. Mechanized analysis
delivered *during* the standardization window is worth more than the same
analysis delivered after it, and that timing is this paper's motivation.

### 1.1 Contributions

1. **The first mechanized symbolic analysis of Triple-KEM and Dual-KEM**,
   corroborating the BR' proof and supplying the artifact the proposal lacks
   (FA-01).
2. **A precise statement of Dual-KEM's security boundary** (FA-02): the authors'
   qualitative caution becomes a checkable property, with attack traces.
3. **FB-01, a non-recoverable rekey desynchronization** under space channel
   constraints, requiring no cryptographic compromise and invisible to the BR'
   proof by construction — together with a concrete mitigation.
4. **FC-01: E2EQSS is hybrid for confidentiality but not authentication**,
   confirmed constructively by an attack trace, with a one-line mitigation.
5. **A reproducible artifact**: all Tamarin theories, captured prover output, and
   exported attack traces.

### 1.2 What this paper does not claim

- We do **not** claim an error in the BR' proof. FA-01 corroborates it. FB-01 is
  outside the properties it establishes, not a contradiction of them.
- We do **not** claim a break in any deployed system. Both targets are published
  proposals, not operational software.
- We do **not** claim cryptographic weaknesses in ML-KEM or ML-DSA. FC-01 is
  conditional: it describes what survives *if* ML-KEM is broken, which is
  precisely the question a hybrid design exists to answer.

## 2. Method

All models are in `models/`; captured prover output is in `traces/`. Reproduce
with `tamarin-prover --prove <model>.spthy` (Tamarin 1.12.0, Maude 3.1).

**KEM abstraction.** An IND-CCA KEM is modelled as public-key encryption of a
fresh shared secret: `Encap(pk) = aenc(~ss, pk)`, `Decap(sk, c) = adec(c, sk)`.
This is the standard sound Dolev–Yao abstraction. It captures both properties
that matter: only the private-key holder recovers the shared secret, and *any*
party may encapsulate to a public key. The second is what drives FA-02.

A richer alternative exists and we address it rather than ignore it. The KEMTLS
analysis of Celi et al. uses a dedicated KEM equational theory in Tamarin
(`kempk`, `kemencaps`, `kemdecaps`) instead of a plain public-key-encryption
abstraction. None of our properties depends on the distinction. We never rely on
an adversary being *unable* to re-encapsulate to a public key — FA-02 turns on
precisely the opposite, that anyone can — and FB-01 is a liveness property in
which the cryptographic layer plays no part at all. Re-running under the richer
theory would nonetheless be a reasonable robustness check, and we note it as
such.

**The pre-shared key is revealable.** The psk that authenticated-encrypts the
flights can be revealed by the adversary (`Reveal_psk`). Security therefore
cannot rest on the psk and must come from the KEMs — which is what makes the
post-compromise claim non-trivial to check, and matches the proposal's own
intent that the psk is defence in depth and may be all-zero.

**Adversary.** Full Dolev–Yao network control, plus compromise of any long-term
key (`Reveal_ltk`) and any psk. `Honest` and `LtkReveal` action facts scope the
reveal exceptions inside each lemma, so "secure unless a relevant key was
compromised" is stated precisely rather than assumed.

## 3. Triple-KEM and Dual-KEM

### 3.1 The protocol as modelled

Initiator is Mission Control (MC), responder is the Satellite (SAT). Both hold
long-term KEM keypairs; MC generates an ephemeral KEM keypair.

```
M1  MC  -> SAT :  AEAD_psk( c_sat , pk_e )
M2  SAT -> MC  :  AEAD_psk( c_e , c_mc , confirm_sat )
M3  MC  -> SAT :  confirm_mc

c_sat = Encap(pk_sat)   -- challenges SAT's long-term key (authenticates SAT)
c_e   = Encap(pk_e)     -- ephemeral encapsulation (forward secrecy)
c_mc  = Encap(pk_mc)    -- challenges MC's long-term key (authenticates MC)
th    = H(c_sat, pk_e, c_e, c_mc)
k     = KDF(psk, ss_sat, ss_e, ss_mc, th)
```

Key confirmation is bidirectional — SAT confirms in M2, MC in M3 — matching the
proposal's insistence on always confirming. Dual-KEM is Triple-KEM with `c_sat`
removed, so `k = KDF(psk, ss_e, ss_mc, th)` carries no `ss_sat` term.

### 3.2 FA-01: Triple-KEM verifies

All six lemmas verify, with no wellformedness warnings.

| Lemma | Result |
|---|---|
| `executable` | verified |
| `key_secrecy` | verified — secret unless an honest long-term key was revealed; psk compromise alone does not break it |
| `forward_secrecy` | verified — revealing a long-term key *after* a session does not expose the earlier key |
| `post_compromise_security` | verified — key stays secret with the psk revealed, given intact long-term and ephemeral keys |
| `mutual_authentication_MC` | verified — injective agreement |
| `key_agreement` | verified |

This is the expected outcome for a peer-reviewed design, and we report it as a
positive result rather than burying it. Its value is twofold: it corroborates the
BR' proof independently, in a different model with a different adversary
formalization, and it supplies the mechanized artifact the Blue Book process can
point to.

### 3.3 FA-02: Dual-KEM's boundary, made precise

| Lemma | Result |
|---|---|
| `executable` | verified |
| `initiator_auth_holds` | verified — MC remains authenticated to SAT via `c_mc` |
| `responder_auth_expected_fail` | **falsified (attack trace)** |
| `key_secrecy_psk_intact` | verified — safe while the psk is secret |
| `post_compromise_security_expected_fail` | **falsified (attack trace)** |

Dropping the responder challenge has a consequence sharper than the qualitative
caution in the paper. Once the psk is compromised — which is *precisely* the
scenario post-compromise security exists to address — the Dolev–Yao adversary
encapsulates to the public keys itself, impersonates the satellite, and derives
the same key MC does. So the precise statement is: **absent out-of-band responder
authentication, Dual-KEM provides confidentiality only while the psk is secret,
and no post-compromise security whatsoever.**

The Triple-versus-Dual contrast also serves as evidence that the models are
faithful. Triple-KEM binds `ss_sat`, recoverable only by the real satellite;
Dual-KEM removes it. The models distinguish the two designs exactly where theory
predicts they should, which is the kind of differential check that catches a
model that verifies everything because it models nothing.

## 4. FB-01: non-recoverable rekey desynchronization

### 4.1 What the BR' proof does not cover, by construction

The computational proof establishes confidentiality and authenticity of the
derived key against a network adversary. It does not model the space channel, and
the paper says so directly: on packet loss or reordering the protocol "needs to
assume an attack and drop the connection," with reordering and re-request
deferred to a lower layer.

Two further facts about spacecraft operations compound this. A spacecraft is
reachable only during a contact window, which closes on a schedule nobody
controls. And a failed handshake may not be retryable at will, because the next
opportunity may be hours away.

This is not a criticism of the proof. A proof of secrecy and authentication
cannot observe a liveness failure; the property is simply not in its scope. It is
an argument that the scope needs widening before deployment.

### 4.2 Model

A contact window is a linear `!Contact` token, minted when SAT sends M2 and
consumed when SAT processes M3. The rule `Pass_ends` destroys the token — the
pass closes before M3 arrives — and there is no retry.

The critical modelling decision is separating key **activation** from key
derivation. MC activates the new key on *sending* M3 (`KeyActiveMC`); SAT
activates only on *receiving* M3 (`KeyActiveSat`). This asymmetry is not
arbitrary: it follows from the protocol's own requirement that key confirmation
must precede activation.

### 4.3 Results

| Lemma | Result |
|---|---|
| `executable` | verified — an honest run still completes both-sided within a pass |
| `rekey_atomicity` | **falsified (attack trace)** — MC activates while SAT never does |
| `desync_reachable` | **verified (exists-trace)** — with **no** long-term-key or psk compromise anywhere in the trace |
| `replay_resistance_timing_independent` | verified |
| `key_secrecy` | verified — confidentiality unaffected by the space model |

### 4.4 The finding

**FB-01 (availability).** Triple-KEM as specified permits a non-recoverable rekey
desynchronization. Because key confirmation gates satellite-side activation, a
single lost M3 across a closing pass window leaves mission control on the new key
and the spacecraft on the old one, with no automatic recovery under the
no-abort-and-retry constraint. Subsequent SDLS traffic under the new master key
is then rejected by the spacecraft.

Two things make this worth reporting. It requires **no cryptographic
compromise** — the `desync_reachable` witness contains no key reveal of any kind,
so this is reachable through ordinary packet loss, not adversarial action. And it
is **structurally invisible** to the BR' proof, which establishes secrecy and
authentication and therefore cannot observe a both-sided-completion failure.

The paired positive result matters for diagnosis.
`replay_resistance_timing_independent` verifies: two satellite activations can
never share a key regardless of message delay, because freshness rests on the
transcript hash and fresh ephemerals rather than on timers. That is essential for
the minutes-to-hours round trips of deep space, and it localises FB-01
precisely — this is an *activation and liveness* problem, not a freshness one.

### 4.5 Mitigation

Mission control must not activate or switch the SDLS master key until it has
positive evidence that the spacecraft activated it: a spacecraft-to-ground
post-activation acknowledgement, or deferred activation with a defined fallback
to the previous key if the acknowledgement does not arrive within the pass.
Either makes the rekey an atomic, retry-safe operation across pass boundaries.

This is a small change and it is cheap to make now, while the Blue Book is being
drafted. It is expensive to make later, because the alternative is operational
procedure compensating for a protocol that cannot complete atomically.

## 5. FC-01: E2EQSS is hybrid for confidentiality, not authentication

### 5.1 The protocol as modelled

Mutual authentication via ML-DSA-65 certificates issued by a CA, with OCSP
abstracted as certificate validity. Both parties hold long-term KEM keypairs. The
handshake mixes a long-term KEM challenge each way (`c_ltSAT`, `c_ltMC`), an
ephemeral ML-KEM leg (`c_eph`) and a classical ECDH leg into a hybrid master
secret `MS = KDF(ss_ltSAT, ss_eph, ss_dh, ss_ltMC, th)`, with bilateral MAC key
confirmation.

**Modelling note, stated for the reviewer.** Both key-establishment legs are
modelled as idealized ephemeral secret delivery; the ECDH leg is abstracted the
same way as a KEM rather than with the Diffie–Hellman builtin. This is faithful
for the property under test, because hybrid security depends only on each leg
contributing an *independent* secret the adversary cannot obtain without the
corresponding ephemeral secret — not on the algebraic structure of `g^xy`. It
also removes the DH AC-unification that makes these lemmas non-terminating.
Per-leg reveal rules (`Reveal_kem_secret`, `Reveal_dh_secret`) let the adversary
break exactly one leg at a time, which is what the hybrid question requires.

### 5.2 Results

| Lemma | Result |
|---|---|
| `executable` | verified |
| `key_secrecy` | verified — authenticated key secrecy against a network adversary |
| `mutual_authentication_MC` | verified (327 steps, custom proof oracle) |
| `replay_resistance` | verified — a transcript is committed at most once |
| `hybrid_secure_if_kem_survives` | verified — the key holds when the ECDH leg is fully broken |
| `hybrid_secure_if_dh_survives` | did not terminate in the full model; confirmed as a break in an isolated model (§5.3) |

This already goes materially beyond what the E2EQSS authors report, which covers
replay and MITM only. A wellformedness precheck times out under `--auto-sources`;
this does not affect the proofs, which run against the saturated sources.

### 5.3 The finding

The remaining direction — does the ECDH leg protect the key when ML-KEM is
broken? — did not terminate in the full model under the default heuristic, the
alternative built-in heuristics, or a custom oracle, in either all-traces or
exists-trace form. Rather than report a non-result, we confirmed it
**constructively** in an isolated model, `models/e2eqss_fc01.spthy`: the full
handshake trimmed to the attack-relevant rules, with the ECDH-leg-reveal and
long-term-key-reveal rules deliberately *removed*, so that any trace found
necessarily has the ECDH leg intact and no long-term key compromised.

Result: `fc01_kem_broken_dh_survives_attack (exists-trace): verified (16 steps)`,
exported to `traces/fc01_attack.dot`.

The attack is structural. The ML-DSA certificates sign only each party's
*static* long-term KEM key. Nobody signs the per-session ephemeral public keys or
the transcript. Per-session peer authentication therefore rests entirely on the
KEM challenge, since only the holder of the long-term KEM secret recovers the
encapsulated secret feeding the MAC. If ML-KEM is broken, an adversary replays an
honest party's public certificate, substitutes its own ephemeral keys, completes
the handshake, and recovers every KDF input. The surviving ECDH leg does not save
it, because that leg's ephemeral key was never authenticated.

**E2EQSS is hybrid for confidentiality but not for authentication.**

**Mitigation.** Sign the transcript, or at minimum the ephemeral public keys,
with the ML-DSA signatures — so that authentication survives the loss of either
primitive, which is what a hybrid construction is for.

## 6. Reproducibility

| Model | Purpose |
|---|---|
| `triple_kem.spthy` | FA-01 |
| `dual_kem.spthy` | FA-02 |
| `triple_kem_space.spthy` | FB-01 |
| `e2eqss.spthy` (+ `oracle_e2eqss.py`) | FC-01 positive results |
| `e2eqss_fc01.spthy` | FC-01 attack confirmation |

Attack traces are exported to `traces/` as `.dot` files. Walkthroughs for the
three attack findings are in `poc/` (`POC_FB01_rekey_desync.md`,
`POC_FA02_dual_kem.md`, `POC_FC01_e2eqss_hybrid.md`). These are formal-methods
proofs of concept — reproducible Tamarin traces — not runnable exploits; the
targets are protocol proposals rather than deployed software, so no CVE applies.

## 7. Related work

The Triple-KEM authors provide the BR' proof. Ours is the first mechanized
analysis, and FB-01 is outside BR''s scope by construction rather than in
tension with it.

We are explicit that this is not an oversight on the authors' part. Andreas
Hülsing co-authored both the Triple-KEM proposal and the Tamarin verification of
KEMTLS, so mechanization was plainly available to them and the hand-written BR'
proof was a choice. Our contribution is to supply, during the standardization
window, the artifact the Blue Book process can point to -- and, in FB-01, a
property the chosen proof technique cannot express regardless of who applies
it.

The E2EQSS authors report an unpublished, ongoing Tamarin analysis limited to
replay and MITM. Because their model is unavailable, an independent rebuild was
necessary, and our contribution — forward secrecy, post-compromise security, and
both directions of the hybrid guarantee — is disjoint from what they describe.

Symbolic analyses of post-quantum key exchange in terrestrial settings are
numerous and do not address the space channel constraints that produce FB-01.

## 8. Limitations

Symbolic analysis does not establish computational security; it establishes the
absence of structural attacks in the Dolev–Yao model. FA-01 therefore
corroborates the BR' proof rather than replacing it.

The KEM and ECDH abstractions are standard and are justified in §2 and §5.1, but
they are abstractions; an attack depending on the algebraic structure of a real
primitive would be outside the model.

FB-01's pass-window model is deliberately minimal — one contact token, no
retry. Real mission operations have more structure, and an operator may already
compensate procedurally. The finding is that the *protocol as specified* does not
guarantee atomicity, not that any particular mission is exposed.

`hybrid_secure_if_dh_survives` remains unproven in the full E2EQSS model. The
isolated model is constructive evidence of the break, and closing it in the full
model — by interactive proof or by hand — would strengthen the result.

## 9. Disclosure, venue, and next steps

### 9.1 Disclosure

Both targets are published proposals, not deployed operational software, so no
embargo applies. The appropriate path is a courtesy notice to the proposal
authors first — Hülsing, Lange and Weber; Wildfeuer et al. — and then to the
CCSDS Security Working Group. FB-01 is specifically timely while the Triple-KEM
Blue Book is being drafted, and that timeliness decays.

### 9.2 Artifact

All models and captured proofs should be published with a Zenodo DOI. The Tamarin
theory files are as much the contribution as this report: they are what lets the
working group re-check the result, and what lets a future revision of the
protocol be re-verified rather than re-argued.

### 9.3 Venue

The mechanized-verification-during-standardization framing is the durable
contribution, and SpaceSec is the natural fit. However, Project C targets the
same workshop, and the program's guidance cautions against consecutive
submissions to one venue. A decision is required: either separate the two across
venues, or sequence them across years. This paper's CCSDS Security Working Group
technical-input path is viable independently of the academic venue, and should
proceed regardless.

## References

To be verified against primary sources before submission:

- Hülsing, Lange, Weber. *A Key-Update Mechanism for the Space Data Link Security
  Protocol.* CANS 2025.
- Wildfeuer et al. *End-to-End Quantum-Safe Security for Satellite Data Links.*
  ESA 3S Conference, 2025.
- CCSDS 355.0-B-2 — Space Data Link Security Protocol.
- CCSDS 355.1-B-1 — SDLS Extended Procedures.
- CCSDS 354.0-M-1 — CCSDS Key Management (asymmetric out of scope, §1.2).
- NIST FIPS 203 — ML-KEM. NIST FIPS 204 — ML-DSA.
- Meier, Schmidt, Cremers, Basin. *The TAMARIN Prover for the Symbolic Analysis
  of Security Protocols.* CAV 2013.
- Celi, Hülsing, Stebila, Wiggers et al. *A Tale of Two Models: Formal
  Verification of KEMTLS via Tamarin.* ESORICS 2022 (IACR ePrint 2022/1111).
- Bellare, Rogaway. *Entity Authentication and Key Distribution.* CRYPTO 1993.
