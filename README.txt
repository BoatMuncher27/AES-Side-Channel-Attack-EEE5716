Project 5: Side-channel attacks on AES (DPA contest v2 traces)
Read Section 5 of Project_Descriptions_F26.pdf first.

Contents
  dpav2_download.py       downloads the DPA contest v2 public base (4 parts, about 3.7 GB) from the
                          Telecom Paris mirror; run it again to resume an interrupted download
  dpav2_convert.py        streams the archive into one NumPy folder per key (no extraction needed)
  aes_tools.py            S-box, inverse S-box, Hamming weights, key schedule and its inversion,
                          reference AES encryption (no attack code)
  check_data.py           checks one converted key folder and plots the mean trace

New Contents
  utils.py                load a converted key folder, ground-truth round-10 key (eval only)
  leakage.py              the two leakage models (`hw`, `hd`) and the ShiftRows byte mapping
  cpa_attack.py           the CPA attack itself — recovers all 16 round-10 key bytes
  evaluate.py             success rate / guessing entropy vs. number of traces (≥10 random subsets per N)
  select_random_keys.py   randomly pick the extra keys required by part 3 (grad: 2 keys)
  template_attack.py      profiled (template) attack + comparison vs. CPA
  plot_results.py         the plots the report needs
  run_all.py              driver: runs CPA + sweep (+ template, optionally) for one key, saves everything
  test_pipeline.py        self-test using simulated traces — run this first

Shortcut: the TAs share the already converted folders of all 32 keys (4 GB, link on Canvas).
If you download those, skip steps 1 and 2 and point check_data.py and your scripts to them.

Steps
  1. python dpav2_download.py --out dpav2_parts
  2. python dpav2_convert.py --parts dpav2_parts --out dpav2_npy --keys 082efa98ec4e6c89452821e638d01377 be5466cf34e90c6cc0ac29b7c97c50dd 0000000000000003243f6a8885a308d3 13198a2e03707344a4093822299f31d0
     (without --keys all 32 keys are converted: about 4.2 GB, 10 to 30 minutes)
     dpav2_npy/index.csv lists every trace with its key, plaintext and ciphertext, so you can
     pick your random extra keys from it and convert them later.
  3. python check_data.py dpav2_npy/13198a2e03707344a4093822299f31d0
     prints "AES check on 50 traces: OK" and saves mean_trace.png
  4. python aes_tools.py     self-test (FIPS-197 vector and key-schedule inversion)

# TODO: Add new steps

Data format per key folder
  traces.npy  int16 (20000, 3253)   raw oscilloscope words, one row per encryption
  pt.npy      uint8 (20000, 16)     plaintext bytes
  ct.npy      uint8 (20000, 16)     ciphertext bytes
  key.txt     the 128-bit key in hex
Use np.load(path, mmap_mode="r") to read traces without loading everything into memory.
You can delete the four .part files after the conversion.
