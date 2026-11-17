"""
Download the DPA contest v2 public trace database (Project 5).

The original site (www.dpacontest.org) is no longer online. The public base is
mirrored by Telecom Paris as four split parts of one .tar.bz2 archive
(about 3.7 GB in total). This script downloads the four parts and resumes a
partial download if it is interrupted.

Usage:
    python dpav2_download.py --out <folder>

After the download, run dpav2_convert.py on the same folder. You do NOT need
to extract the archive by hand (it contains 640,000 small CSV files).
"""
import argparse
import os
import sys
import urllib.request

SHARE = "https://cloud.telecom-paris.fr/s/N5qgyMdxEcqipN2/download?path=%2F&files="
ARCHIVE = "DPA_contest2_public_base_diff_vcc_a128_2009_12_23.tar.bz2"
# Expected size of each part in bytes (used to check that a download is complete)
PARTS = {
    ARCHIVE + ".part0": 1073741824,
    ARCHIVE + ".part1": 1073741824,
    ARCHIVE + ".part2": 1073741824,
    ARCHIVE + ".part3": 464242892,
}


def download(name, size, out_dir):
    path = os.path.join(out_dir, name)
    have = os.path.getsize(path) if os.path.exists(path) else 0
    if have == size:
        print(f"{name}: already complete")
        return
    if have > size:
        print(f"{name}: local file is larger than expected, deleting it")
        os.remove(path)
        have = 0
    req = urllib.request.Request(SHARE + name)
    if have:
        req.add_header("Range", f"bytes={have}-")
        print(f"{name}: resuming at {have / 2**20:.0f} MB")
    with urllib.request.urlopen(req, timeout=120) as resp, open(path, "ab" if have else "wb") as f:
        if have and resp.status != 206:
            # server ignored the Range header, start again from zero
            f.seek(0)
            f.truncate()
            have = 0
        done = have
        while True:
            chunk = resp.read(1 << 22)
            if not chunk:
                break
            f.write(chunk)
            done += len(chunk)
            sys.stdout.write(f"\r{name}: {done / 2**20:8.0f} / {size / 2**20:.0f} MB")
            sys.stdout.flush()
    print()
    if os.path.getsize(path) != size:
        sys.exit(f"{name}: size mismatch, run the script again to resume")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True, help="folder for the four archive parts")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    for name, size in PARTS.items():
        download(name, size, args.out)
    print("All four parts are complete. Next step: python dpav2_convert.py --parts", args.out, "--out <npy folder>")


if __name__ == "__main__":
    main()
