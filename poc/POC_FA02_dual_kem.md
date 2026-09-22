# FA-02 PoC Walkthrough — Dual-KEM Loses Responder Authentication and Post-Compromise Security

**Project:** Project B — SDLS-EP Key Management Verification
**Target:** Dual-KEM variant (Hülsing, Lange & Weber, CANS 2025)
**Class:** Authentication / post-compromise security (design boundary). Not a CVE — analysis of a proposed protocol variant.
**Status:** ✅ CONFIRMED by two machine-checked Tamarin attack traces

---

## What this PoC is

Two Tamarin attack traces that make precise the boundary the paper states qualitatively ("Dual-KEM does not itself guarantee any authenticity of the responder"). The traces show that, once the pre-shared key is compromised — exactly the situation post-compromise security is meant to survive — the Dolev–Yao adversary impersonates the satellite and shares the "new" key with mission control. This confirms Dual-KEM must never be used without out-of-band responder authentication.

## Files

| File | Description |
|---|---|
| [`models/dual_kem.spthy`](../models/dual_kem.spthy) | The Dual-KEM model |
| [`traces/dual_kem_proof.txt`](../traces/dual_kem_proof.txt) | Captured prover verdicts |
| [`traces/fa02_respauth.dot`](../traces/fa02_respauth.dot) / [`.json`](../traces/fa02_respauth.json) | Responder-authentication failure trace |
| [`traces/fa02_pcs.dot`](../traces/fa02_pcs.dot) / [`.json`](../traces/fa02_pcs.json) | Post-compromise-security failure trace |

## Build & Run

```bash
# from Project_B/models
tamarin-prover --prove dual_kem.spthy

tamarin-prover --prove=responder_auth_expected_fail \
  --output-dot=../traces/fa02_respauth.dot dual_kem.spthy
tamarin-prover --prove=post_compromise_security_expected_fail \
  --output-dot=../traces/fa02_pcs.dot dual_kem.spthy
```

## What the traces demonstrate

Both exported traces share the same shape, and its defining feature is what is **absent**: neither `SAT_1` nor `SAT_2` ever fires. Mission control completes a rekey while **no satellite ever ran the protocol**.

Rule-firing sequence (from `fa02_respauth.dot` / `fa02_pcs.dot`):

1. **`Register_ltk` ×2, `Register_psk`** — MC and SAT setup.
2. **`Reveal_psk`** — the adversary compromises the pre-shared key (the post-compromise scenario). In `fa02_pcs` the trace also shows the adversary constructing the key material (`c_kdf`, `c_aenc`, `isend` nodes).
3. **`MC_1`** — MC starts a rekey and sends `M1 = AEAD_psk(pk_e)` (Dual-KEM omits the `c_sat` challenge to SAT's long-term key).
4. **No `SAT_1`.** Instead, the adversary — now holding the psk — fabricates `M2` on its own: it picks `ss_e`, `ss_mc` and computes `c_e = Encap(pk_e)`, `c_mc = Encap(pk_mc)` **using only public keys** (anyone can encapsulate to a public key), derives `k = KDF(psk, ss_e, ss_mc, th)`, and forges the confirmation `senc(<'sc', th>, k)`.
5. **`MC_2`** — MC receives the forged `M2`, its checks pass (it has no way to verify a satellite was involved), and it **commits and activates `k`** (`Commit($MC, $SAT, ...)`, `AcceptMC`). The adversary knows `k`.

So MC believes it has completed an authenticated rekey with the satellite; in reality it shares the key with the adversary, and the satellite was never present.

## Confirmed output

```
executable (exists-trace): verified
initiator_auth_holds (all-traces): verified
responder_auth_expected_fail (all-traces): falsified - found trace (14 steps)
key_secrecy_psk_intact (all-traces): verified
post_compromise_security_expected_fail (all-traces): falsified - found trace (15 steps)
```

- `initiator_auth_holds` **verified**: MC is still authenticated to SAT (the `c_mc` challenge to MC's long-term key survives) — Dual-KEM only drops *responder* authentication.
- `key_secrecy_psk_intact` **verified**: while the psk is secret, the key is safe.
- `responder_auth_expected_fail` and `post_compromise_security_expected_fail` **falsified with traces**: once the psk leaks, both fail.

## Root cause

Triple-KEM authenticates the satellite by having MC encapsulate a fresh secret `ss_sat` to the satellite's long-term public key (`c_sat`); only the real satellite can recover `ss_sat`, and `ss_sat` feeds the derived key, so producing a valid confirmation proves possession of the satellite's long-term secret. **Dual-KEM removes `c_sat`.** The derived key then depends only on values (`ss_e`, `ss_mc`) that any network party can produce by encapsulating to public keys. When the psk (the only remaining shared secret) is also gone, there is nothing tying the responder side to the real satellite.

## Impact and correct usage

This is not a break of the paper — the authors state Dual-KEM requires out-of-band responder authentication (e.g. by the ground station). The traces turn that caution into a precise property: **without out-of-band responder authentication, Dual-KEM provides confidentiality only while the pre-shared key is secret, and no post-compromise security at all.** Any deployment that selects Dual-KEM to save bandwidth must therefore guarantee responder authenticity by another mechanism, and must not rely on it for recovery after key compromise.

The Triple-vs-Dual contrast also serves as evidence that the models are faithful: they distinguish the two variants exactly where the cryptographic argument says they differ.
