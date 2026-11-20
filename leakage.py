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

    'hd'  Hamming distance between v and ciphertext[i], i.e. HW(v XOR C_i).
          This assumes the physical register at position i is overwritten
          in place: old content ~ v, new content = ciphertext[i]. This is
          the model commonly reported to work well on the SASEBO-GII AES
          core used for DPA contest v2, but whether register i's *previous*
          content lines up with v(i,k) at the *same* index i (rather than
          the ShiftRows-permuted index) is an assumption about the specific
          hardware wiring -- the project instructions flag this explicitly
          ("working out which ciphertext byte lands in which register
          position is part of your job"). Don't take it on faith: run both
          models on one of the four known keys first (known key used only
          to pick the model/settings, never inside the attack on unknown
          keys) and keep whichever gives the cleaner, higher correlation
          peak. Then freeze that choice for every other key you attack.

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


def leakage_hd(ct_byte):
    """Hamming-distance (HD with ciphertext byte, same index) model."""
    v = hyp_intermediate(ct_byte)
    ct_byte = ct_byte.astype(np.uint8)
    return HW[v ^ ct_byte[None, :]].astype(np.float64)


MODELS = {"hw": leakage_hw, "hd": leakage_hd}


def leakage_hypotheses(ct_byte, model="hd"):
    """Dispatch to the chosen model. model in {'hw', 'hd'}."""
    if model not in MODELS:
        raise ValueError(f"unknown model {model!r}, expected one of {list(MODELS)}")
    return MODELS[model](ct_byte)
