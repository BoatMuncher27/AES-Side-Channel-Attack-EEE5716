"""
Leakage models for a last-round CPA attack on the DPA contest v2 traces.

Target: the 16 bytes of the AES-128 round-10 (last round) key, k10.
For output byte position i, AES computes

    ciphertext[i] = SBOX[state9[src(i)]] XOR k10[i]

where state9 is the state after round 9 and src(i) is the ShiftRows source
index, using the SAME convention as aes_tools.encrypt:

    src(i) = (i + 4 * (i % 4)) % 16

Guessing k10[i] and knowing ciphertext[i] lets us compute the hypothesised
intermediate value

    v(i, k) = InvSBox(ciphertext[i] XOR k)   == state9[src(i)]

This is independent per byte (no need to guess two bytes jointly), which is
what makes a per-byte CPA attack with 256 hypotheses practical.

Two leakage models are provided:

    'hw'  Hamming weight of v itself. This is the safe, unambiguous model:
          v is a value that actually exists in the hardware (the SBOX
          output register that round 10 reads from the previous state),
          so HW(v) is a legitimate guess at its leakage regardless of how
          the implementation's registers are wired.

    'hd'  Hamming distance between two DIFFERENT register snapshots, for a
          hardware that keeps one 16-byte state register and overwrites it
          in place once per round (the usual SASEBO-GII AES core behavior,
          and the model commonly reported to work well on DPA contest v2).

          Register j's content after round 9 is state9[j] (no permutation
          -- state9 is just "the state as it physically sits" after round
          9 finishes). During round 10, SubBytes+ShiftRows+AddRoundKey
          combinationally compute ciphertext[j] = SBOX[state9[src(j)]] XOR
          k10[j], and that overwrites register j, so the transition at
          register j is

              HW( state9[j]  XOR  ciphertext[j] )

          We can only compute state9[j] from a KEY GUESS at a possibly
          DIFFERENT position: from the defining equation above (written
          for position m), state9[src(m)] = InvSBox(ciphertext[m] XOR
          k10[m]). Setting j = src(m) (i.e. attacking key byte k10[m]),
          this says the register whose transition depends on k10[m] is
          register src(m), not register m:

              HW( InvSBox(ciphertext[m] XOR k10[m])  XOR  ciphertext[src(m)] )

          So leakage_hd needs the ciphertext byte at position src(m) as
          the "new value" partner, NOT the ciphertext byte at position m
          itself. Using the same index for both (the natural-looking but
          wrong shortcut) only happens to work for row 0 (m in {0,4,8,12}),
          where src(m) == m -- ShiftRows doesn't move row 0. If your
          results only recover row-0 bytes under 'hd', this is almost
          certainly the symptom: see cpa_attack.attack_full_key, which
          passes ct[:, shiftrows_src(m)] as the partner column.

          Whether this HD model is the right one *at all* for your
          hardware (vs. 'hw', or vs. HD against some other pair of
          registers) is still something to verify empirically on a known
          key before freezing it for every key you attack.

Both models are vectorised: given an array of ciphertext bytes for many
traces, they return a (256, n_traces) array of hypothesised leakage values,
one row per key-byte hypothesis.
"""
import numpy as np

from aes_tools import INV_SBOX, HW


def shiftrows_src(i):
    return (i + 4 * (i % 4)) % 16


def hyp_intermediate(ct_byte, all_guesses=True):
    """v(i,k) for one ciphertext byte position across all traces.

    ct_byte : (n_traces,) uint8 array, ciphertext[:, i]
    Returns (256, n_traces) uint8 array: row k is InvSBox(ct_byte XOR k).
    """
    ct_byte = ct_byte.astype(np.uint8)
    guesses = np.arange(256, dtype=np.uint8)
    # XOR every guess against every ciphertext byte: (256, n_traces)
    x = guesses[:, None] ^ ct_byte[None, :]
    
    return INV_SBOX[x]


def leakage_hw(ct_byte):
    """Hamming-weight model. Returns (256, n_traces) leakage hypotheses."""
    v = hyp_intermediate(ct_byte)
    
    return HW[v].astype(np.float64)


def leakage_hd(ct_byte, ct_partner_byte):
    """Hamming-distance model.

    ct_byte         : ciphertext[:, m] -- used, with each key guess, to form
                       the hypothesis v = InvSBox(ct_byte XOR guess) = state9[src(m)]
    ct_partner_byte : ciphertext[:, src(m)] -- the "new" register content
                       that overwrote state9[src(m)] in register src(m).
                       MUST be the ciphertext column at src(m), not at m
                       (see the module docstring) -- cpa_attack.py supplies
                       this correctly via shiftrows_src(m).
    """
    v = hyp_intermediate(ct_byte)
    ct_partner_byte = ct_partner_byte.astype(np.uint8)
    
    return HW[v ^ ct_partner_byte[None, :]].astype(np.float64)


MODELS = {"hw": leakage_hw, "hd": leakage_hd}


def leakage_hypotheses(ct_byte, model="hd", ct_partner_byte=None):
    """Dispatch to the chosen model. model in {'hw', 'hd'}.

    ct_partner_byte is required (and used) only for 'hd'; see leakage_hd.
    """
    if model == "hw":
        return leakage_hw(ct_byte)
    if model == "hd":
        if ct_partner_byte is None:
            raise ValueError("model='hd' requires ct_partner_byte = ct[:, shiftrows_src(m)]")
        return leakage_hd(ct_byte, ct_partner_byte)
    raise ValueError(f"unknown model {model!r}, expected one of {list(MODELS)}")
