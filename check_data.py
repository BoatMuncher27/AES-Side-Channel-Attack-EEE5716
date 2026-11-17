"""
Sanity check of one converted DPA contest v2 key folder (Project 5).

    python check_data.py <npy folder>/<key hex>

It checks that AES(plaintext, key) = ciphertext for the first 50 traces,
prints the trace array shape and value range, and saves a plot of the mean
trace and of three single traces (mean_trace.png) so you can find the
region of the last round. It contains no attack code.
"""
import os
import sys

import numpy as np

from aes_tools import encrypt


def main():
    d = sys.argv[1].rstrip("/\\")
    key = open(os.path.join(d, "key.txt")).read().strip()
    tr = np.load(os.path.join(d, "traces.npy"), mmap_mode="r")
    pt = np.load(os.path.join(d, "pt.npy"))
    ct = np.load(os.path.join(d, "ct.npy"))
    print(f"key {key}: traces {tr.shape} {tr.dtype}, plaintexts {pt.shape}, ciphertexts {ct.shape}")
    bad = sum(encrypt(pt[i], key) != bytes(ct[i]) for i in range(50))
    print("AES check on 50 traces:", "OK" if bad == 0 else f"{bad} mismatches")
    sub = np.asarray(tr[:2000], dtype=np.float32)
    print(f"sample values: min {sub.min():.0f}, max {sub.max():.0f}")
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(2, 1, figsize=(10, 6), sharex=True)
        ax[0].plot(sub.mean(0), lw=0.7)
        ax[0].set_ylabel("mean of 2000 traces")
        for i in range(3):
            ax[1].plot(sub[i], lw=0.5)
        ax[1].set_ylabel("single traces")
        ax[1].set_xlabel("sample index (0.2 ns per sample)")
        fig.tight_layout()
        fig.savefig("mean_trace.png", dpi=120)
        print("saved mean_trace.png")
    except ImportError:
        print("matplotlib not installed, no plot")


if __name__ == "__main__":
    main()
