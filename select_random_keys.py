"""
Randomly select extra keys to attack, as required by part 3 of the
assignment (undergrad: 1 key, grad: 2 keys), excluding the 4 specified keys
in Table 1.

Usage:
    python select_random_keys.py <data_root> --n 2 --seed 42

Prints the chosen key folders. Re-run with the same --seed to reproduce the
same selection for your report (pick a seed once and keep it -- don't
reroll until you get keys you like, that would defeat the point of
"randomly select").
"""
import argparse
import random

from utils import list_key_folders

SPECIFIED_KEYS = {
    "082efa98ec4e6c89452821e638d01377",
    "be5466cf34e90c6cc0ac29b7c97c50dd",
    "0000000000000003243f6a8885a308d3",
    "13198a2e03707344a4093822299f31d0",
}

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("data_root", help="directory holding one subfolder per key")
    ap.add_argument("--n", type=int, default=2, help="2 for grad students")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    folders = list_key_folders(args.data_root)
    candidates = [k for k in folders if k not in SPECIFIED_KEYS]
    print(f"{len(folders)} key folders found, {len(candidates)} available for random selection")

    rng = random.Random(args.seed)
    chosen = rng.sample(candidates, args.n)
    print(f"\nChosen keys (seed={args.seed}):")
    for k in chosen:
        print(f"  {k}  ->  {folders[k]}")
