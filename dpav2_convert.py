"""
Convert the DPA contest v2 public base into one NumPy folder per key (Project 5).

The archive holds 640,000 CSV files (32 keys x 20,000 traces, 3253 samples per
trace). Extracting it creates about 11.5 GB of small files, which is slow on
Windows. This script reads the four .part files as a single stream, never
writes the CSV files to disk, and saves for every key:

    <out>/<key_hex>/traces.npy   int16, shape (20000, n_samples)
    <out>/<key_hex>/pt.npy       uint8, shape (20000, 16)  plaintexts
    <out>/<key_hex>/ct.npy       uint8, shape (20000, 16)  ciphertexts
    <out>/<key_hex>/key.txt      the 128-bit key in hex

and one index file <out>/index.csv (trace number, key, plaintext, ciphertext),
which replaces the old keymsg_public_base_dpacontest2 file.

Usage examples:
    # all 32 keys, all 3253 samples (about 4.2 GB of output)
    python dpav2_convert.py --parts <download folder> --out <npy folder>

    # only the keys you need (the archive is still read from start to end)
    python dpav2_convert.py --parts dl --out npy --keys 0000000000000003243f6a8885a308d3 13198a2e03707344a4093822299f31d0

    # keep only a window of samples to save disk space
    python dpav2_convert.py --parts dl --out npy --samples 2000:3253

The trace values are the raw 16-bit oscilloscope words. To convert to volts:
    volts = word * 1.41351e-05 + 4.62481e-02
(both numbers are in every CSV header). For CPA the raw words are fine.
Reading the full archive takes roughly 20 to 40 minutes on a laptop.
"""
import argparse
import glob
import io
import os
import re
import sys
import tarfile
import time

import numpy as np

N_PER_KEY = 20000
N_SAMPLES = 3253
NAME_RE = re.compile(r"n=(\d+)_k=([0-9a-f]{32})_m=([0-9a-f]{32})_c=([0-9a-f]{32})\.csv$")


class ConcatReader(io.RawIOBase):
    """Presents several files, one after another, as one readable stream."""

    def __init__(self, paths):
        self.paths = list(paths)
        self.f = open(self.paths.pop(0), "rb")

    def readable(self):
        return True

    def readinto(self, buf):
        while True:
            n = self.f.readinto(buf)
            if n:
                return n
            self.f.close()
            if not self.paths:
                return 0
            self.f = open(self.paths.pop(0), "rb")


class KeyBuffer:
    """Collects the traces of one key and writes them to disk when full."""

    def __init__(self, key, lo, hi):
        self.key = key
        self.lo, self.hi = lo, hi
        self.traces = np.zeros((N_PER_KEY, hi - lo), dtype=np.int16)
        self.pt = np.zeros((N_PER_KEY, 16), dtype=np.uint8)
        self.ct = np.zeros((N_PER_KEY, 16), dtype=np.uint8)
        self.count = 0

    def add(self, samples, m, c):
        i = self.count
        self.traces[i] = samples[self.lo:self.hi]
        self.pt[i] = np.frombuffer(bytes.fromhex(m), dtype=np.uint8)
        self.ct[i] = np.frombuffer(bytes.fromhex(c), dtype=np.uint8)
        self.count += 1

    def save(self, out_dir):
        d = os.path.join(out_dir, self.key)
        os.makedirs(d, exist_ok=True)
        n = self.count
        np.save(os.path.join(d, "traces.npy"), self.traces[:n])
        np.save(os.path.join(d, "pt.npy"), self.pt[:n])
        np.save(os.path.join(d, "ct.npy"), self.ct[:n])
        with open(os.path.join(d, "key.txt"), "w") as f:
            f.write(self.key + "\n")
        print(f"\n  saved key {self.key}: {n} traces, {self.hi - self.lo} samples")


def parse_samples(text):
    # header lines start with '#'; the remaining lines hold one integer each
    body = text[text.rfind("#"):]
    body = body[body.find("\n") + 1:]
    return np.array(body.split(), dtype=np.int16)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--parts", required=True, help="folder with the four .tar.bz2.partN files")
    ap.add_argument("--out", required=True, help="output folder")
    ap.add_argument("--keys", nargs="*", default=None, help="only save these keys (hex); default: all")
    ap.add_argument("--samples", default=f"0:{N_SAMPLES}", help="sample window lo:hi (default all)")
    args = ap.parse_args()

    parts = sorted(glob.glob(os.path.join(args.parts, "*.tar.bz2.part*")))
    if len(parts) != 4:
        sys.exit(f"expected 4 part files in {args.parts}, found {len(parts)}")
    lo, hi = (int(x) for x in args.samples.split(":"))
    wanted = set(k.lower() for k in args.keys) if args.keys else None
    os.makedirs(args.out, exist_ok=True)

    stream = io.BufferedReader(ConcatReader(parts), 1 << 22)
    tar = tarfile.open(fileobj=stream, mode="r|bz2")
    buffers = {}
    index = open(os.path.join(args.out, "index.csv"), "w")
    index.write("n,key,plaintext,ciphertext\n")
    t0 = time.time()
    total = 0
    for member in tar:
        if not member.isfile():
            continue
        m = NAME_RE.search(member.name)
        if m is None:
            continue
        n, key, pt, ct = m.groups()
        index.write(f"{n},{key},{pt},{ct}\n")
        total += 1
        if total % 5000 == 0:
            rate = total / (time.time() - t0)
            sys.stdout.write(f"\r{total:6d} traces read, {rate:5.0f} traces/s")
            sys.stdout.flush()
        if wanted is not None and key not in wanted:
            continue
        samples = parse_samples(tar.extractfile(member).read().decode("ascii"))
        if samples.size != N_SAMPLES:
            print(f"\n  warning: {member.name} has {samples.size} samples, skipped")
            continue
        buf = buffers.get(key)
        if buf is None:
            buf = buffers[key] = KeyBuffer(key, lo, hi)
        buf.add(samples, pt, ct)
        if buf.count == N_PER_KEY:
            buf.save(args.out)
            del buffers[key]
    for buf in buffers.values():  # keys with fewer than 20000 traces, if any
        buf.save(args.out)
    index.close()
    print(f"\nDone: {total} traces indexed in {(time.time() - t0) / 60:.1f} min")


if __name__ == "__main__":
    main()
