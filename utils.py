"""
Shared data-loading helpers for Project 5.

A converted key folder (as produced by dpav2_convert.py) looks like:
    <folder>/traces.npy   (n_traces x n_samples, int16 or similar)
    <folder>/pt.npy       (n_traces x 16, uint8)
    <folder>/ct.npy       (n_traces x 16, uint8)
    <folder>/key.txt      (32 hex chars)
"""
import os

import numpy as np

from aes_tools import encrypt


def load_key_folder(folder, n_traces=None, mmap=True):
    """Load one converted key folder.

    Parameters
    ----------
    folder : str
        Path to the folder holding traces.npy, pt.npy, ct.npy, key.txt.
    n_traces : int or None
        If given, only load/return the first n_traces traces (randomized
        subset selection should be done by the caller, not here).
    mmap : bool
        If True, traces.npy is memory-mapped instead of loaded fully into
        RAM (useful since the file is ~130 MB per key).

    Returns
    -------
    traces : np.ndarray (float32) shape (n, n_samples)
    pt     : np.ndarray (uint8) shape (n, 16)
    ct     : np.ndarray (uint8) shape (n, 16)
    key_hex: str, the known key for this folder (ground truth, evaluation only)
    """
    folder = folder.rstrip("/\\")
    key_hex = open(os.path.join(folder, "key.txt")).read().strip()
    mode = "r" if mmap else None
    tr = np.load(os.path.join(folder, "traces.npy"), mmap_mode=mode)
    pt = np.load(os.path.join(folder, "pt.npy"))
    ct = np.load(os.path.join(folder, "ct.npy"))
    if n_traces is not None:
        tr = tr[:n_traces]
        pt = pt[:n_traces]
        ct = ct[:n_traces]
    return tr, pt, ct, key_hex


def key_hex_to_bytes(key_hex):
    return np.frombuffer(bytes.fromhex(key_hex), dtype=np.uint8)


def true_round10_key(key_hex):
    """Ground truth last-round key bytes, for evaluation only."""
    from aes_tools import expand_key
    return np.array(expand_key(key_hex)[10], dtype=np.uint8)


def verify_folder(folder, n_check=50):
    """Sanity check: AES(pt, key) == ct for n_check traces. Raises on mismatch."""
    tr, pt, ct, key_hex = load_key_folder(folder, n_traces=n_check)
    for i in range(n_check):
        if encrypt(bytes(pt[i]), key_hex) != bytes(ct[i]):
            raise ValueError(f"AES check failed on trace {i} of {folder}")
    return True


def list_key_folders(data_root):
    """Return {key_hex: folder_path} for every converted key folder under data_root."""
    out = {}
    for name in sorted(os.listdir(data_root)):
        full = os.path.join(data_root, name)
        if os.path.isdir(full) and os.path.exists(os.path.join(full, "key.txt")):
            key_hex = open(os.path.join(full, "key.txt")).read().strip()
            out[key_hex] = full
    return out
