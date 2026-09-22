# FC-01 PoC Walkthrough — E2EQSS Hybrid Fails When ML-KEM Breaks

**Project:** Project B — SDLS-EP Key Management Verification
**Target:** E2EQSS hybrid handshake (Wildfeuer et al., ESA 3S 2025)
**Class:** Authentication / hybrid-security (design-level).
**Machine-confirmation status:** ✅ CONFIRMED. The isolated exists-trace model ([`models/e2eqss_fc01.spthy`](../models/e2eqss_fc01.spthy)) verifies the attack — `fc01_kem_broken_dh_survives_attack (exists-trace): verified (16 steps)`. Trace exported to [`traces/fc01_attack.dot`](../traces/fc01_attack.dot).

---

## Claim

E2EQSS advertises a hybrid of ML-KEM and ECDH so that the session survives the compromise of either primitive. This holds in the ML-KEM-surviving direction (`hybrid_secure_if_kem_survives`, machine-verified). It does **not** hold in the other direction: if ML-KEM is broken, the surviving ECDH leg does **not** protect confidentiality, because per-session authentication rides entirely on the KEM challenge — the ML-DSA certificates sign only static long-term keys, never the ephemeral keys or the transcript.

## Isolated model

To confirm the attack constructively, [`models/e2eqss_fc01.spthy`](../models/e2eqss_fc01.spthy) is the full E2EQSS handshake trimmed to the rules the attack needs, with **the ECDH-leg-reveal rule and the long-term-key-reveal rule deliberately removed.** Any trace found in this model therefore *structurally* has the ECDH leg intact and no long-term key compromised — so a witnessing trace proves that breaking ML-KEM alone (`KemReveal`) suffices.

```bash
# from Project_B/models
tamarin-prover --auto-sources --prove=fc01_kem_broken_dh_survives_attack \
  --output-dot=../traces/fc01_attack.dot e2eqss_fc01.spthy
```

Lemma:

```
lemma fc01_kem_broken_dh_survives_attack:
  exists-trace
  "Ex SAT MC MS #i #j #k s.
      Secret(MS) @ #i & K(MS) @ #j & KemReveal(s) @ #k
    & AcceptSat(SAT, MC, MS) @ #i"
```

## The attack, step by step

1. An **honest MC** starts a handshake (`MC_1`), which places its valid certificate `certMC` on the network. Certificates are public.
2. The **adversary** captures `certMC` and crafts its own `M1` to the satellite: the honest `certMC`, but the adversary's **own** ephemeral keys `eph_pk*`, `dh_pk*`, and its own `c_ltSAT* = Encap(pk_sat)` (it picks `ss_ltSAT*`).
3. The **satellite** verifies `certMC` — it is a genuine CA-signed certificate, so verification passes. Nothing binds `eph_pk*`/`dh_pk*` to MC. SAT proceeds (`SAT_1`), encapsulating `c_eph = Encap(eph_pk*)`, `c_dh = Encap(dh_pk*)`, and `c_ltMC = Encap(pk_mc)`, and derives `MS = KDF(ss_ltSAT*, ss_eph, ss_dh, ss_ltMC, th)`.
4. The adversary now recovers every KDF input:
   - `ss_ltSAT*` — it chose it.
   - `ss_eph` — decapsulate `c_eph` with its own `eph_sk*`.
   - `ss_dh` — decapsulate `c_dh` with its own `dh_sk*` (the ECDH leg is intact but useless: its ephemeral key was never authenticated, so the adversary simply owns it).
   - `ss_ltMC` — this one is encapsulated to the honest MC's long-term key, which the adversary does **not** hold. It obtains it via **`KemReveal`** — i.e. this is exactly where "ML-KEM is broken" is used.
   - `th` — public transcript hash.
5. The adversary computes `MS`, forges the key-confirmation `senc(<'mc', th>, MS)`, and the satellite accepts (`SAT_2`, `AcceptSat`, `Secret(MS)`). The adversary knows `MS`.

The ECDH leg was fully intact throughout and no long-term key was compromised, yet the master secret is the adversary's.

## Root cause

Authentication in E2EQSS is layered as: ML-DSA certificate (binds identity ↔ *static* long-term KEM key) + KEM challenge (`c_ltMC`/`c_ltSAT`, proves possession of the static KEM secret) + MAC confirmation. **Nothing signs the per-session ephemeral public keys or the handshake transcript.** So the only thing tying a session to the authenticated identity is the KEM challenge. Break the KEM and authentication collapses, regardless of the intact ECDH leg — the hybrid is hybrid for confidentiality but not for authentication.

## Recommended mitigation

Authenticate the transcript (or at least the ephemeral public keys `eph_pk`, `dh_pk`) with the ML-DSA signatures, so that authentication survives the loss of either primitive. Then a broken ML-KEM leaves ECDH-based confidentiality genuinely protected.

## Confirmed output

```
fc01_kem_broken_dh_survives_attack (exists-trace): verified (16 steps)
```

The exported trace (`traces/fc01_attack.dot`) contains exactly: `Register_CA`, `Register_ltk` (MC and SAT), `MC_1` (honest MC emits its certificate), `SAT_1` (satellite responds to the adversary-crafted `M1`), `Reveal_kem_secret` (the ML-KEM leg break — `KemReveal`), and `SAT_2` (`AcceptSat`, `Secret(MS)`), with the adversary deriving `K(MS)`. Because the model defines **no** ECDH-leg-reveal rule and **no** long-term-key-reveal rule, the trace proves the master secret falls with the ECDH leg intact and no long-term key compromised.

## Status

- ✅ `hybrid_secure_if_kem_survives` (ECDH-leg break tolerated) — machine-verified in `e2eqss.spthy`.
- ✅ FC-01 attack (ML-KEM-leg break defeats confidentiality despite the intact ECDH leg) — **machine-confirmed** in `e2eqss_fc01.spthy`.

Note on the full model: in the complete `e2eqss.spthy`, the equivalent all-traces lemma `hybrid_secure_if_dh_survives` did not terminate under the available heuristics/oracle within budget; the finding is instead confirmed constructively in the isolated model above, which is the standard way to settle a property the full model cannot decide in reasonable time.
