#!/usr/bin/env bash
# Re-prove every Tamarin result in this project and check it against the
# captured output in traces/.
#
# Requires Tamarin 1.12.0 and Maude 3.1 on PATH. Fresh output is written to
# traces/rerun/. For each model the per-lemma verdicts (verified / falsified
# and step counts) are compared with the captured *_proof.txt; the script
# exits non-zero if any model fails to run or any verdict differs.
set -uo pipefail

cd "$(dirname "$0")"

if ! command -v tamarin-prover >/dev/null 2>&1; then
    echo "tamarin-prover not found on PATH."
    echo "Install Tamarin 1.12.0 (and Maude 3.1), or run inside WSL where it is installed."
    exit 1
fi

# Tamarin prints Unicode (e.g. the quantifier symbols) and aborts on a
# non-UTF-8 locale.
if [ "$(locale charmap 2>/dev/null)" != "UTF-8" ]; then
    export LANG=C.UTF-8 LC_ALL=C.UTF-8
fi

mkdir -p traces/rerun
failed=0

# tr strips CR, so captured traces checked out with CRLF (Windows,
# core.autocrlf=true) still compare equal to fresh LF output.
verdicts() {
    tr -d '\r' < "$1" | sed -n '/summary of summaries/,$p' | grep -E '\((all-traces|exists-trace)\)' | sort -u
}

run() {
    local model="$1"; shift
    local name out ref
    name="$(basename "$model" .spthy)"
    out="traces/rerun/${name}_proof.txt"
    ref="traces/${name}_proof.txt"
    echo
    echo "=== $name"
    # --derivcheck-timeout=0: let the wellformedness derivation checks finish
    # on slow machines instead of timing out with a warning.
    if ! tamarin-prover --prove --derivcheck-timeout=0 "$@" "$model" > "$out" 2>&1; then
        echo "FAILED to run -- see $out"
        tail -n 5 "$out"
        failed=1
        return
    fi
    verdicts "$out"
    if [ -f "$ref" ] && ! diff <(verdicts "$ref") <(verdicts "$out") >/dev/null; then
        echo "MISMATCH against $ref:"
        diff <(verdicts "$ref") <(verdicts "$out")
        failed=1
    fi
}

# Each Triple-KEM / Dual-KEM model comes in two versions. The *_published
# models give M2 exactly as in Fig. 1 of the CANS paper (no SAT -> MC
# confirmation, the case without a long-term key update). The unsuffixed
# models add that confirmation to M2.

# FA-01, as published. mutual_authentication_MC(_psk_intact), key_agreement
# (_psk_intact) and forward_secrecy are EXPECTED to falsify; the rest verify.
run models/triple_kem_published.spthy

# FA-01, with a SAT -> MC confirmation in M2. All seven lemmas verify.
run models/triple_kem.spthy

# FA-02: Dual-KEM, both versions. Two lemmas are EXPECTED to falsify in each --
# that is the finding, not a failure. See README.
run models/dual_kem_published.spthy
run models/dual_kem.spthy

# FB-01, both versions. rekey_atomicity is expected to falsify and
# desync_reachable to verify, with no key reveal in the trace. The published
# version also verifies desync_by_splice (no message lost, no key revealed).
run models/triple_kem_space_published.spthy
run models/triple_kem_space.spthy

# FB-01 fix, both versions. mc_activation_safe and sat_retirement_safe verify;
# sat_activation_implies_mc_activation is EXPECTED to falsify (a lost fourth
# message -- the two-generals residue). In the published version
# desync_by_splice is EXPECTED to find no trace: the fix closes the splice.
run models/triple_kem_space_4pass_published.spthy
run models/triple_kem_space_4pass.spthy

# FC-01 positives. mutual_authentication_MC uses the custom proof oracle
# models/oracle_e2eqss.py, named in the lemma's [heuristic=O "..."] attribute
# and resolved relative to the theory file.
run models/e2eqss.spthy

# FC-01 attack confirmation, in the isolated model.
run models/e2eqss_fc01.spthy

echo
if [ "$failed" -ne 0 ]; then
    echo "FAILED: at least one model did not run or did not match traces/."
    exit 1
fi
echo "All verdicts match the captured output in traces/. Fresh output in traces/rerun/."
echo "Expected falsifications: triple_kem_published (MC-side authentication, key"
echo "agreement, forward secrecy once the psk leaks), dual_kem and dual_kem_published"
echo "(responder auth, PCS), triple_kem_space and triple_kem_space_published"
echo "(rekey_atomicity), both 4pass models (sat_activation_implies_mc_activation),"
echo "and triple_kem_space_4pass_published (desync_by_splice: no trace)."
