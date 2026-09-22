# FB-01 PoC Walkthrough — Non-Recoverable Rekey Desynchronization (Triple-KEM)

**Project:** Project B — SDLS-EP Key Management Verification
**Target:** Triple-KEM key-update mechanism (Hülsing, Lange & Weber, CANS 2025) — CCSDS Blue Book candidate
**Class:** Availability / liveness (design-level). Not a CVE — analysis of a proposed standard, not deployed software.
**Status:** ✅ CONFIRMED by machine-checked Tamarin trace

---

## What this PoC is

This is a formal-methods proof of concept. The "exploit" is a Tamarin attack trace: a concrete, machine-found execution of the protocol in which mission control ends up on the new key while the spacecraft is stuck on the old one, with no cryptographic compromise anywhere in the run. Anyone can re-run the model and Tamarin reproduces the trace. In symbolic verification the reproducible trace *is* the PoC, the way a runnable C exploit is the PoC for an implementation bug.

## Files

| File | Description |
|---|---|
| [`models/triple_kem_space.spthy`](../models/triple_kem_space.spthy) | The space-channel model (pass window + no-retry) |
| [`traces/triple_kem_space_proof.txt`](../traces/triple_kem_space_proof.txt) | Captured prover verdicts |
| [`traces/fb01_desync.dot`](../traces/fb01_desync.dot) | The exported attack trace (GraphViz) |
| [`traces/fb01_desync.json`](../traces/fb01_desync.json) | The same trace as JSON |

## Build & Run

```bash
# from Project_B/models  (WSL: Tamarin 1.12.0, Maude 3.1)
tamarin-prover --prove triple_kem_space.spthy

# export the desynchronization trace as a graph:
tamarin-prover --prove=desync_reachable \
  --output-dot=../traces/fb01_desync.dot \
  --output-json=../traces/fb01_desync.json \
  triple_kem_space.spthy
# render:  dot -Tpng ../traces/fb01_desync.dot -o fb01_desync.png
```

## What the trace demonstrates

The exported trace (`fb01_desync.dot`) is the following rule-firing sequence. It uses only honest protocol steps plus one channel event — **no key reveal of any kind occurs**.

1. **`Register_ltk` ×2, `Register_psk`** — mission control (MC) and satellite (SAT) get their long-term KEM keypairs and a pre-shared key. Ordinary setup.
2. **`MC_1`** — MC starts a rekey: sends `M1 = AEAD_psk(c_sat, pk_e)`.
3. **`SAT_1`** — SAT receives `M1`, derives the new key `k = KDF(psk, ss_sat, ss_e, ss_mc, th)`, sends `M2` with its key confirmation, and **opens a contact/pass window** (the linear `Contact($SAT, ~sidS)` fact). SAT has computed `k` but, per the protocol's key-confirmation discipline, has **not activated** it — it is waiting for MC's confirmation in `M3`.
4. **`MC_2`** — MC receives `M2`, checks SAT's confirmation, derives the same `k`, and **activates the new key** (`KeyActiveMC($MC, $SAT, k)` — visible in the trace node, along with `Secret(k)`). MC emits `M3` (its own confirmation).
5. **`Pass_ends`** — the pass window closes (`PassEnded($SAT, ~sidS)` fires and consumes the `Contact` token) **before `M3` is processed**. `M3` is not delivered within the window.
6. **`SAT_2` never fires.** With the contact token gone and no retry, SAT can never process `M3`. `KeyActiveSat(...)` never occurs.

End state: `KeyActiveMC(MC, SAT, k)` is in the trace; `KeyActiveSat(SAT, MC, k)` is not. MC is on the new key; SAT is still on the old key.

## Confirmed output

```
executable (exists-trace): verified (8 steps)
rekey_atomicity (all-traces): falsified - found trace (5 steps)
desync_reachable (exists-trace): verified (8 steps)
replay_resistance_timing_independent (all-traces): verified (10 steps)
key_secrecy (all-traces): verified (23 steps)
```

- `rekey_atomicity` **falsified**: it is not always true that MC activating the key implies SAT activating it.
- `desync_reachable` **verified**: the desynchronized end state is reachable, and the lemma explicitly excludes `LtkReveal` and `PskReveal` — so the trace contains **no key compromise**.
- `key_secrecy` still holds: this is purely an availability/liveness failure, not a confidentiality one.

## Root cause

Triple-KEM binds key **activation** to key **confirmation**, asymmetrically:

- MC activates on **sending** `M3` (rule `MC_2`).
- SAT activates only on **receiving** `M3` (rule `SAT_2`), because a receiver must not switch to a key it has not had confirmed.

On a terrestrial link a lost `M3` is repaired by retransmission. The space channel removes that escape hatch: the paper (Sec. 3) states that on loss/reordering the protocol "needs to assume an attack and drop the connection," and the operational reality adds one-way pass windows and no abort-and-retry. A single dropped confirmation across a closing pass window is therefore terminal for that rekey.

The original computational (BR') proof cannot see this: it proves secrecy and authentication of the derived key, not both-sided agreement on completion under message loss.

## Impact

After the desync, MC encrypts subsequent SDLS traffic under the new master key; SAT still holds only the old key and rejects it. The command/telemetry link is broken until manual, out-of-band recovery — potentially not until the next pass, or later. For a large constellation this is a per-link, per-rekey hazard.

## Recommended mitigation

MC must not activate/switch the SDLS master key until it has positive evidence that SAT activated it — e.g. a SAT→MC post-activation acknowledgement (a 4th message), or deferred activation with a defined fallback to the previous key if acknowledgement does not arrive within the pass. This makes the rekey atomic and retry-safe across pass boundaries.
