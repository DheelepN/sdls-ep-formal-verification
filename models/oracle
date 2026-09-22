#!/usr/bin/env python3
# Proof oracle for e2eqss.spthy.
#
# Tamarin calls this with the lemma name as argv[1] and the current open goals
# on stdin, one per line, each prefixed with an integer index. The oracle prints
# the indices in the order Tamarin should try them (a prefix is enough; any
# omitted indices keep their relative order afterwards).
#
# Strategy for the secrecy/agreement lemmas that do not converge under the
# default heuristic: both reduce to "the adversary cannot obtain the surviving
# leg secret (ss_dh) or the SAT-challenge secret (ss_ltSAT), hence cannot build
# the KDF, hence cannot forge the MAC/derive MS." We therefore:
#   * drive adversary-knowledge goals for the PROTECTED fresh secrets first
#     (they lead straight to a contradiction),
#   * then KDF / senc(...MS) knowledge goals,
#   * resolve protocol state and setup facts next,
#   * and strongly deprioritise reconstruction of the deliberately-leaked
#     secrets (ss_eph, ss_ltMC) and generic message-deduction goals, which are
#     what blow the search up.

import sys, re

lemma = sys.argv[1] if len(sys.argv) > 1 else ""

goals = []
for line in sys.stdin:
    m = re.match(r'\s*(\d+):\s*(.*)', line)
    if m:
        goals.append((int(m.group(1)), m.group(2)))

PROTECTED = ('~ss_dh', '~ss_ltSAT')
LEAKED    = ('~ss_eph', '~ss_ltMC')

# Attack-finding mode (exists-trace): drive the trace that breaks the DH-only
# direction -- reveal the ML-KEM leg, advance protocol state, let the adversary
# build the KDF -- rather than steering away from it.
def rank_attack(text):
    t = text
    if 'Reveal' in t:
        return 0                      # fire the leg-break / reveal rules
    if any(f in t for f in ('St_MC_', 'St_SAT_')):
        return 1                      # advance honest sessions (leak the cert)
    if '!KU(' in t and 'kdf(' in t:
        return 2                      # adversary assembling the master secret
    if '!KU(' in t and any(l in t for l in LEAKED + PROTECTED):
        return 3                      # adversary obtaining the KDF inputs
    if any(f in t for f in ('!Cert(', '!Ltk(', '!Pk(', '!CA(')):
        return 4
    return 5

def rank(text):
    t = text
    ku = '!KU(' in t
    if ku and any(p in t for p in PROTECTED):
        return 0                      # protected secret -> fast contradiction
    # the surviving-leg ciphertext / ephemeral: drive its chain to the dead end
    if any(s in t for s in ('c_dh', 'dh_pk', '!DhSecret(')):
        return 1
    if ku and 'kdf(' in t:
        return 2                      # adversary building the master secret
    if ku and 'senc(' in t and 'mc' in t:
        return 3                      # forging a key-confirmation MAC
    if any(f in t for f in ('St_MC_', 'St_SAT_')):
        return 4                      # advance protocol state
    if any(f in t for f in ('!Cert(', '!Ltk(', '!Pk(', '!CA(')):
        return 5                      # setup facts
    # deliberately-leaked secrets and the reveal machinery blow up the search
    if 'Reveal' in t or (ku and any(l in t for l in LEAKED)):
        return 9
    if ku:
        return 7                      # generic message deduction: late
    return 6

rk = rank_attack if 'attack' in lemma else rank
order = sorted(range(len(goals)), key=lambda i: (rk(goals[i][1]), goals[i][0]))
for i in order:
    print(goals[i][0])
