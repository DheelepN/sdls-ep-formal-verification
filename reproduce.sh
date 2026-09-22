#!/usr/bin/env bash
# Re-prove every Tamarin result in this project.
#
# Requires Tamarin 1.12.0 and Maude 3.1 on PATH. Output is written to
# traces/, alongside the captured output from the original runs, so a reader
# can diff a fresh run against what this project reported.
set -euo pipefail

cd "$(dirname "$0")"

if ! command -v tamarin-prover >/dev/null 2>&1; then
    echo "tamarin-prover not found on PATH."
    echo "Install Tamarin 1.12.0 (and Maude 3.1), or run inside WSL where it is installed."
    exit 1
fi

mkdir -p traces/rerun

run() {
    local model="$1"; shift
    local name
    name="$(basename "$model" .spthy)"
    echo
    echo "=== $name"
    tamarin-prover --prove "$@" "$model" | tee "traces/rerun/${name}_proof.txt" \
        | grep -E "verified|falsified|steps" || true
}

# FA-01: Triple-KEM. All six lemmas should verify.
run models/triple_kem.spthy

# FA-02: Dual-KEM. Two lemmas are EXPECTED to falsify -- that is the finding,
# not a failure. See README.
run models/dual_kem.spthy

# FB-01: the space-channel model. rekey_atomicity is expected to falsify and
# desync_reachable to verify as an exists-trace, with no key reveal in the trace.
run models/triple_kem_space.spthy

# FC-01 positives. mutual_authentication_MC needs the custom oracle, which the
# model applies per-lemma via [heuristic=O].
run models/e2eqss.spthy --heuristic=O --oraclename=oracle_e2eqss.py

# FC-01 attack confirmation, in the isolated model.
run models/e2eqss_fc01.spthy

echo
echo "Done. Fresh output in traces/rerun/ ; original captured output in traces/."
echo "Expected falsifications: dual_kem (responder auth, PCS), triple_kem_space (rekey_atomicity)."
