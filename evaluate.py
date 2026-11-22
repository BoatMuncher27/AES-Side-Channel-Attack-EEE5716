"""
Success rate and guessing entropy of the CPA attack as a function of the
number of traces used, averaged over several random subsets (as required:
"at least 10 random subsets of traces for each number of traces").

Usage:
    python evaluate.py <key_folder> --n-list 50 100 200 500 1000 2000 5000 \
        --repeats 10 --model hd --out results/eval_<key>.csv

For each N in --n-list, draws --repeats random subsets of N traces (without
replacement, no fixed time offset -- "random" here means which traces are
chosen, not which chronological order), runs the CPA attack on each subset,
and records, per byte:
    rank      = position of the true key byte in the correlation ranking
                (0 = recovered correctly, 255 = worst possible)
    success   = 1 if rank == 0 else 0

Reports, per N:
    mean success rate (averaged over the 16 bytes and all repeats)
    mean guessing entropy (averaged over the 16 bytes and all repeats)
    full-key success rate (fraction of repeats where all 16 bytes were correct)
"""
import argparse
import csv
import os

import numpy as np

from cpa_attack import attack_byte
from leakage import shiftrows_src
from utils import load_key_folder, true_round10_key


def guessing_entropy_and_success(peak_corrs_row, true_byte):
    """Rank (0-based) of true_byte within the 256 correlation scores, descending."""
    order = np.argsort(peak_corrs_row)[::-1]
    rank = int(np.where(order == true_byte)[0][0])
    return rank, int(rank == 0)


def evaluate(folder, n_list, repeats=10, model="hd", seed=0, verbose=True):
    traces_full, pt_full, ct_full, key_hex = load_key_folder(folder, mmap=True)
    true_k10 = true_round10_key(key_hex)
    n_available = traces_full.shape[0]
    rng = np.random.default_rng(seed)

    rows = []
    for N in n_list:
        if N > n_available:
            print(f"skipping N={N}: only {n_available} traces available")
            continue
        
        ranks_all = np.zeros((repeats, 16), dtype=int)
        success_all = np.zeros((repeats, 16), dtype=int)
        
        for rep in range(repeats):
            idx = rng.choice(n_available, size=N, replace=False)
            idx.sort()  # sorted indices are much faster for memmap fancy-indexing
            traces = np.asarray(traces_full[idx], dtype=np.float32)
            ct = ct_full[idx]
            
            for i in range(16):
                partner = ct[:, shiftrows_src(i)] if model == "hd" else None
                _, peaks, _ = attack_byte(traces, ct[:, i], model=model, ct_partner_byte=partner)
                rank, succ = guessing_entropy_and_success(peaks, true_k10[i])
                ranks_all[rep, i] = rank
                success_all[rep, i] = succ
                
        mean_ge = ranks_all.mean()
        mean_sr = success_all.mean()
        full_key_sr = np.mean(np.all(success_all == 1, axis=1))
        if verbose:
            print(f"N={N:6d}  byte success rate={mean_sr:.3f}  "
                  f"guessing entropy={mean_ge:6.2f}  full-key success={full_key_sr:.3f}")
        rows.append({
            "N": N, 
            "byte_success_rate": mean_sr, 
            "guessing_entropy": mean_ge, 
            "full_key_success_rate": full_key_sr
        })
    
    return rows


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("folder")
    ap.add_argument("--n-list", type=int, nargs="+", default=[50, 100, 200, 500, 1000, 2000, 5000, 10000])
    ap.add_argument("--repeats", type=int, default=10)
    ap.add_argument("--model", choices=["hw", "hd"], default="hd")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", default=None, help="CSV output path")
    args = ap.parse_args()

    rows = evaluate(args.folder, args.n_list, repeats=args.repeats, model=args.model, seed=args.seed)

    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["N", "byte_success_rate", "guessing_entropy", "full_key_success_rate"])
            w.writeheader()
            w.writerows(rows)
        print(f"wrote {args.out}")
