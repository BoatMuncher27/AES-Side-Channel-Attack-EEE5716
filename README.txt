Project 5: Side-channel attacks on AES (DPA contest v2 traces)
Read Section 5 of Project_Descriptions_F26.pdf first.

Contents (provided)
  dpav2_download.py       downloads the DPA contest v2 public base (4 parts, about 3.7 GB) from the
                          Telecom Paris mirror; run it again to resume an interrupted download
  dpav2_convert.py        streams the archive into one NumPy folder per key (no extraction needed)
  aes_tools.py            S-box, inverse S-box, Hamming weights, key schedule and its inversion,
                          reference AES encryption (no attack code)
  check_data.py           checks one converted key folder and plots the mean trace

Contents (added for this submission)
  utils.py                load a converted key folder, ground-truth round-10 key (eval only)
  leakage.py              the two leakage models (`hw`, `hd`) and the ShiftRows byte mapping
  cpa_attack.py           the CPA attack itself. Recovers all 16 round-10 key bytes
  evaluate.py             success rate / guessing entropy vs. number of traces (>=10 random subsets per N)
  select_random_keys.py   randomly pick the extra keys required by part 3 (grad: 2 keys)
  template_attack.py      profiled (template) attack + comparison vs. CPA (grad only)
  plot_results.py         the plots the report needs
  run_all.py              driver: runs CPA + sweep (+ template, optionally) for one key, saves everything

Generating the data
  The trace data is NOT included in this repository. Regenerate it with:

    1. python dpav2_download.py --out dpav2_parts
    2. python dpav2_convert.py --parts dpav2_parts --out dpav2_npy \
           --keys 082efa98ec4e6c89452821e638d01377 be5466cf34e90c6cc0ac29b7c97c50dd \
                  0000000000000003243f6a8885a308d3 13198a2e03707344a4093822299f31d0 \
                  <your random key 1> <your random key 2>
       (omit --keys to convert all 32 keys instead, about 4.2 GB, 10-30 minutes;
        dpav2_npy/index.csv lists every trace's key, plaintext and ciphertext, which is how you
        can look up your random keys before converting them)

    Shortcut: the TAs share the already-converted folders for all 32 keys (link on Canvas).
    If you use those, skip steps 1-2 above and just point every command below at that folder.

    3. python check_data.py dpav2_npy/13198a2e03707344a4093822299f31d0
       should print "AES check on 50 traces: OK" and save mean_trace.png
    4. python aes_tools.py
       self-test (FIPS-197 test vector and key-schedule inversion)

    You can delete the four dpav2_parts/*.part files once conversion finishes.

Running the attack

  5. Run the full attack + trace-count sweep for each of the four specified keys:
       python run_all.py dpav2_npy/082efa98ec4e6c89452821e638d01377 --tag key1 --model hd
       python run_all.py dpav2_npy/be5466cf34e90c6cc0ac29b7c97c50dd --tag key2 --model hd
       python run_all.py dpav2_npy/0000000000000003243f6a8885a308d3 --tag key3 --model hd
       python run_all.py dpav2_npy/13198a2e03707344a4093822299f31d0 --tag key4 --model hd
     Each writes the recovered key, success_rate.png, guessing_entropy.png, corr_byte0.png and
     eval.csv to results/<tag>/.

  6. Pick and run the required 2 extra random keys, excluding the four above:
       python select_random_keys.py dpav2_npy --n 2 --seed 42
     then, for each key it prints:
       python run_all.py dpav2_npy/<random_key> --tag rand1 --model hd
       python run_all.py dpav2_npy/<random_key> --tag rand2 --model hd

  7. Profiled template attack vs. CPA, on one random key:
       python run_all.py dpav2_npy/<random_key> --tag rand1_template --model hd --with-template --data-root dpav2_npy
     Profiles Gaussian templates from every OTHER key folder under dpav2_npy (never the
     attacked key, enforced in code) and writes template_vs_cpa_success.png /
     template_vs_cpa_entropy.png comparing how many traces each method needs.

Data format per key folder
  traces.npy  int16 (20000, 3253)   raw oscilloscope words, one row per encryption
  pt.npy      uint8 (20000, 16)     plaintext bytes
  ct.npy      uint8 (20000, 16)     ciphertext bytes
  key.txt     the 128-bit key in hex
Use np.load(path, mmap_mode="r") to read traces without loading everything into memory.
