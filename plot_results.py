"""
Plotting helpers for the report:
  - correlation-vs-sample plots for the correct key guess vs. wrong guesses
    (required: "the correct guess should be obviously different")
  - success-rate / guessing-entropy vs. number-of-traces curves
  - CPA vs. template-attack comparison curves
"""
import csv

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


def plot_correlation_traces(corr_matrix, correct_guess, byte_index, out_path, n_wrong=15):
    """corr_matrix: (256, n_samples) from cpa_attack.attack_byte."""
    fig, ax = plt.subplots(figsize=(9, 4))
    wrong = [k for k in range(256) if k != correct_guess]
    rng = np.random.default_rng(0)
    sample_wrong = rng.choice(wrong, size=min(n_wrong, len(wrong)), replace=False)
    for k in sample_wrong:
        ax.plot(corr_matrix[k], color="lightgray", lw=0.6)
    ax.plot(corr_matrix[correct_guess], color="crimson", lw=1.5,
             label=f"correct guess 0x{correct_guess:02x}")
    ax.set_xlabel("sample index")
    ax.set_ylabel("Pearson correlation")
    ax.set_title(f"CPA correlation traces, key byte {byte_index}")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def plot_metric_vs_n(csv_path, out_path, metric_cols, labels=None, ylabel=None, logx=True):
    """Generic N -> metric line plot, reading a CSV written by evaluate.py / template_attack.py."""
    rows = list(csv.DictReader(open(csv_path)))
    Ns = [int(r["N"]) for r in rows]
    fig, ax = plt.subplots(figsize=(7, 4.5))
    for i, col in enumerate(metric_cols):
        ys = [float(r[col]) for r in rows]
        label = labels[i] if labels else col
        ax.plot(Ns, ys, marker="o", label=label)
    if logx:
        ax.set_xscale("log")
    ax.set_xlabel("number of traces")
    ax.set_ylabel(ylabel or "")
    ax.legend()
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="quick CLI for the CSV-based plots")
    ap.add_argument("csv_path")
    ap.add_argument("out_path")
    ap.add_argument("--metric", choices=["success", "entropy", "template_vs_cpa_success",
                                          "template_vs_cpa_entropy"], default="success")
    args = ap.parse_args()

    if args.metric == "success":
        plot_metric_vs_n(args.csv_path, args.out_path, ["byte_success_rate"],
                          ["CPA byte success rate"], ylabel="success rate")
    elif args.metric == "entropy":
        plot_metric_vs_n(args.csv_path, args.out_path, ["guessing_entropy"],
                          ["CPA guessing entropy"], ylabel="guessing entropy")
    elif args.metric == "template_vs_cpa_success":
        plot_metric_vs_n(args.csv_path, args.out_path,
                          ["template_success_rate", "cpa_success_rate"],
                          ["template attack", "CPA"], ylabel="success rate")
    elif args.metric == "template_vs_cpa_entropy":
        plot_metric_vs_n(args.csv_path, args.out_path,
                          ["template_guessing_entropy", "cpa_guessing_entropy"],
                          ["template attack", "CPA"], ylabel="guessing entropy")
