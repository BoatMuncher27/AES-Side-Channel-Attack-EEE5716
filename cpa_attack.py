"""
Correlation Power Analysis (CPA) on one key folder's traces.

Usage:
    python cpa_attack.py <key_folder> [--model hw|hd] [--n-traces N] [--out results/foo]

Recovers all 16 bytes of the round-10 key, inverts the key schedule to get
the master key, and (for reporting only) compares against the known key in
key.txt.
"""
import argparse
import os
import time

import numpy as np

from aes_tools import master_from_round10
from leakage import leakage_hypotheses, shiftrows_src
from utils import load_key_folder, true_round10_key


def pearson_corr_matrix(H, T):
    """Pearson correlation between every row of H and every column of T.

    H : (n_hyp, n_traces) hypothesis matrix
    T : (n_traces, n_samples) trace matrix
    Returns (n_hyp, n_samples) correlation matrix.

    Uses the standard single-pass CPA formula so all 256 hypotheses and all
    sample points are scored with a handful of matrix multiplications,
    instead of looping over (hypothesis, sample) pairs in Python.
    """
    n = T.shape[0]
    H = H.astype(np.float64)
    T = T.astype(np.float64)

    sumH = H.sum(axis=1)                      # (n_hyp,)
    sumH2 = (H * H).sum(axis=1)                # (n_hyp,)
    sumT = T.sum(axis=0)                       # (n_samples,)
    sumT2 = (T * T).sum(axis=0)                # (n_samples,)

    sumHT = H @ T                              # (n_hyp, n_samples)

    numer = n * sumHT - sumH[:, None] * sumT[None, :]
    denomH = n * sumH2 - sumH ** 2             # (n_hyp,)
    denomT = n * sumT2 - sumT ** 2             # (n_samples,)
    denom = np.sqrt(np.maximum(denomH[:, None] * denomT[None, :], 1e-12))
    return numer / denom


def attack_byte(traces, ct_byte, model="hd", ct_partner_byte=None):
    """CPA on a single key byte position.

    ct_partner_byte: required for model='hd' -- must be ct[:, shiftrows_src(m)]
    where m is the key-byte position ct_byte came from (ct[:, m]). See
    leakage.py's module docstring for why this is a different column than
    ct_byte itself for every row except row 0.

    Returns:
        best_guess   : int, argmax key byte 0..255
        peak_corr    : (256,) max |correlation| over all sample points, per guess
        corr_matrix  : (256, n_samples) full correlation matrix (for plotting)
    """
    H = leakage_hypotheses(ct_byte, model=model, ct_partner_byte=ct_partner_byte)
    corr = pearson_corr_matrix(H, traces)
    peak_corr = np.max(np.abs(corr), axis=1)
    best_guess = int(np.argmax(peak_corr))
    return best_guess, peak_corr, corr


def attack_full_key(traces, ct, model="hd", verbose=True):
    """Recover all 16 round-10 key bytes. Returns (recovered_key_bytes, peak_corrs, corr_matrices)."""
    recovered = np.zeros(16, dtype=np.uint8)
    peak_corrs = np.zeros((16, 256), dtype=np.float64)
    corr_matrices = [None] * 16
    for i in range(16):
        partner = ct[:, shiftrows_src(i)] if model == "hd" else None
        best, peaks, corr = attack_byte(traces, ct[:, i], model=model, ct_partner_byte=partner)
        recovered[i] = best
        peak_corrs[i] = peaks
        corr_matrices[i] = corr
        if verbose:
            # Sort so we can report the gap between best and 2nd-best guess,
            # a quick signal of how confident this byte's recovery is.
            order = np.argsort(peaks)[::-1]
            print(f"  byte {i:2d}: best=0x{best:02x} (corr={peaks[best]:.3f}), "
                  f"runner-up=0x{order[1]:02x} (corr={peaks[order[1]]:.3f})")
    return recovered, peak_corrs, corr_matrices


def run(folder, model="hd", n_traces=None, out_dir=None, verbose=True):
    traces, pt, ct, key_hex = load_key_folder(folder, n_traces=n_traces)
    n = traces.shape[0]
    traces = np.asarray(traces, dtype=np.float32)
    if verbose:
        print(f"Attacking {folder} with {n} traces, model={model}")
    t0 = time.time()
    recovered, peak_corrs, corr_matrices = attack_full_key(traces, ct, model=model, verbose=verbose)
    dt = time.time() - t0

    true_k10 = true_round10_key(key_hex)
    byte_correct = recovered == true_k10
    n_correct = int(byte_correct.sum())

    recovered_master = master_from_round10(bytes(recovered)).hex()

    if verbose:
        print
        print(f"True key:              {key_hex}")
        print(f"Recovered round10 key: {recovered.tobytes().hex()}")
        print(f"True round10 key:      {bytes(true_k10).hex()}")
        print(f"Recovered master key:  {recovered_master}")
        print(f"Bytes correct: {n_correct}/16")
        print(f"Full key match: {recovered_master == key_hex}")
        print(f"Elapsed: {dt:.1f}s")

    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        np.save(os.path.join(out_dir, "recovered_round10.npy"), recovered)
        np.save(os.path.join(out_dir, "peak_corrs.npy"), peak_corrs)
        with open(os.path.join(out_dir, "summary.txt"), "w") as f:
            f.write(f"folder={folder}\nmodel={model}\nn_traces={n}\n")
            f.write(f"true_key={key_hex}\nrecovered_master_key={recovered_master}\n")
            f.write(f"bytes_correct={n_correct}/16\nfull_key_match={recovered_master == key_hex}\n")

    return {
        "recovered_round10": recovered,
        "recovered_master": recovered_master,
        "true_key": key_hex,
        "byte_correct": byte_correct,
        "n_correct": n_correct,
        "peak_corrs": peak_corrs,
        "corr_matrices": corr_matrices,
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("folder", help="path to a converted key folder (e.g. data/082efa98...)")
    ap.add_argument("--model", choices=["hw", "hd"], default="hd")
    ap.add_argument("--n-traces", type=int, default=None, help="use only the first N traces")
    ap.add_argument("--out", default=None, help="directory to save results into")
    args = ap.parse_args()
    run(args.folder, model=args.model, n_traces=args.n_traces, out_dir=args.out)
