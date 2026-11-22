"""
Driver script that runs everything the report needs for one key:
  1. CPA attack recovering all 16 bytes (+ correlation-trace plot for byte 0)
  2. Success-rate / guessing-entropy sweep vs number of traces
  3. (if --with-template) profiled template attack + comparison vs CPA

Usage:
    python run_all.py data/082efa98ec4e6c89452821e638d01377 --tag required_key1
    python run_all.py data/<random_key> --tag random_key1 --with-template --data-root data
"""
import argparse
import os
import csv as csvmod

import numpy as np

import cpa_attack
import evaluate
import plot_results

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("folder", help="key folder to attack")
    ap.add_argument("--tag", required=True, help="short name used in output filenames")
    ap.add_argument("--model", choices=["hw", "hd"], default="hd") # hw does not work
    ap.add_argument("--out-dir", default="results")
    ap.add_argument("--n-list", type=int, nargs="+", default=[50, 100, 200, 500, 1000, 2000, 5000, 10000])
    ap.add_argument("--repeats", type=int, default=10)
    ap.add_argument("--with-template", action="store_true")
    ap.add_argument("--data-root", default=None, help="required if --with-template is set")
    args = ap.parse_args()

    out_dir = os.path.join(args.out_dir, args.tag)
    os.makedirs(out_dir, exist_ok=True)

    print(f"=== CPA full-key attack: {args.tag} ===")
    res = cpa_attack.run(args.folder, model=args.model, out_dir=out_dir)

    print("\n=== correlation-trace plot (byte 0) ===")
    plot_results.plot_correlation_traces(
        res["corr_matrices"][0], 
        int(res["recovered_round10"][0]), 
        0,
        os.path.join(out_dir, "corr_byte0.png")
    )

    print("\n=== success rate / guessing entropy vs N ===")
    rows = evaluate.evaluate(args.folder, args.n_list, repeats=args.repeats, model=args.model)
    csv_path = os.path.join(out_dir, "eval.csv")
    with open(csv_path, "w", newline="") as f:
        w = csvmod.DictWriter(f, fieldnames=["N", "byte_success_rate", "guessing_entropy", "full_key_success_rate"])
        w.writeheader()
        w.writerows(rows)
     
    # Plot CPA byte success rate vs N   
    plot_results.plot_metric_vs_n(
        csv_path, 
        os.path.join(out_dir, "success_rate.png"),
        ["byte_success_rate"], 
        ["CPA byte success rate"],
        ylabel="success rate"
    )
    
    # Plot CPA guessing entropy vs N   
    plot_results.plot_metric_vs_n(
        csv_path, 
        os.path.join(out_dir, "guessing_entropy.png"),
        ["guessing_entropy"], 
        ["CPA guessing entropy"],
        ylabel="guessing entropy"
    )

    # If --with-template is specified, run profiled template attack and compare with CPA
    if args.with_template:
        assert args.data_root, "--data-root is required with --with-template"
        
        import template_attack
        
        #
        # TODO: Once template_attack is implemented, call it here and save the results to out_dir
        #
        
        #
        # TODO: Plot the comparison of CPA and template attack results
        #

    print(f"\nAll outputs written to {out_dir}/")
