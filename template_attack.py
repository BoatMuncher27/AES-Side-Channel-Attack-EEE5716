"""
Profiled (template) attack - grad-only requirement.

Builds a Hamming-weight template (per key byte position) from traces of
OTHER keys whose keys are known, then attacks a target key's traces and
compares how many traces it needs against the CPA attack in cpa_attack.py.

    "Graduate students will additionally implement a profiled attack
    (template attack or a neural network) that learns the leakage from
    keys other than the attacked one, and compare the number of traces it
    needs with their CPA."
    "In the profiled attack, do not use any trace of the attacked key for
    profiling."

Method (classic Gaussian template attack with pooled covariance):
  1. Profiling: for a chosen byte position i, pool traces from several
     *other* keys (known keys, used only to label each trace with its
     Hamming-weight class -- this is what "profiled" means, it is not
     cheating on the target key). Label each trace with
         v = InvSBox(ciphertext[i] XOR true_key_byte_i)
         class = HW(v)   in {0, ..., 8}
     Select a handful of points of interest (POIs) with the highest
     signal-to-noise ratio between classes, then fit one mean vector per
     class and a single pooled covariance matrix (shared across classes --
     the standard "pooled covariance" template attack; it needs far less
     profiling data per class than a separate covariance per class).
  2. Attack: for a trace from the target key and every key-byte guess k,
     predict the class implied by k and ciphertext[i], evaluate the
     Gaussian log-likelihood of the trace's POIs under that class's
     template, and accumulate the log-likelihood across all attack traces.
     The guess with the highest total log-likelihood wins.

Usage:
    python template_attack.py <data_root> <target_key_hex> \
        --n-pois 20 --profile-traces-per-key 3000 --max-profile-keys 8 \
        --attack-n-list 10 20 50 100 200 500 --repeats 10 \
        --compare-cpa --model hd --out results/template_vs_cpa.csv
"""
import argparse
import csv
import os

import numpy as np

from aes_tools import INV_SBOX, HW
from cpa_attack import attack_byte
from leakage import shiftrows_src
from utils import list_key_folders, load_key_folder, true_round10_key

#
# TODO: Implement template nessesary attack functions here
#

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("data_root")
    ap.add_argument("target_key_hex")
    ap.add_argument("--repeats", type=int, default=10)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--model", choices=["hw", "hd"], default="hd", help="leakage model used for the CPA side of the comparison") # All attacks should use hd
    ap.add_argument("--out", default=None)
    
    #
    # TODO: Add additional arguments here
    #
    
    args = ap.parse_args()
    
    #
    # TODO: Use template attack functions to preform template attack here
    #
    
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", newline="") as f:
            #
            # TODO: Write outputs, delete 'pass' below
            #
            pass
        print(f"wrote {args.out}")
