# Quantum Digital Signature - Yin et al.

This repository explores a Quantum Digital Signature (QDS) construction based on Yin et al. The core implementation lives in [QDS_Yin_et_al.ipynb](QDS_Yin_et_al.ipynb), which now includes more beginner-friendly markdown so a first-time reader can follow the protocol before diving into the heavier proof sections.

## What This Repo Covers

- GF(2) arithmetic for the bit-level polynomial operations used by the protocol
- LFSR-generated Toeplitz hashing
- a software abstraction of the QKD key-distribution stage
- Alice's signing procedure
- Bob and Charlie's independent verification logic
- authenticated classical channels for non-repudiation
- attack simulations and parameter-tuning experiments

## Best Place To Start

If you are new to the topic, use this order:

1. Read the opening sections of [QDS_Yin_et_al.ipynb](QDS_Yin_et_al.ipynb).
2. On your first pass, focus on `Quick Symbol Guide`, `GF(2) Arithmetic`, `LFSR Construction and the Toeplitz Matrix`, `Key Distribution`, `Signing`, `Authenticated Channels`, and `Verification`.
3. Return later to the attack simulations, parameter optimization, and the `p_a` reuse loophole proof.

The notebook is written so you can understand the workflow first:

`key setup -> hashing -> signing -> authenticated exchange -> verification`

## Beginner Notes

- The notebook does not simulate quantum optics or quantum circuits.
- The QKD stage is abstracted as trusted correlated key generation so the implementation can focus on the signature logic.
- The most important security rule in the notebook is that the signing polynomial `p_a` must be fresh for every signature.

## Repository Layout

- [QDS_Yin_et_al.ipynb](QDS_Yin_et_al.ipynb): main notebook with the full implementation, walkthrough text, attack simulations, and plots
- [QDS_Beginner_Walkthrough.ipynb](QDS_Beginner_Walkthrough.ipynb): shorter guided notebook for first-time readers
- [BEGINNER_GUIDE.md](BEGINNER_GUIDE.md): glossary, workflow overview, and common beginner questions
- [qds_beginner.py](qds_beginner.py): simplified Python module with the core protocol logic
- [beginner_demo.py](beginner_demo.py): small terminal demo
- [attack_results.png](attack_results.png): attack simulation figure
- [performance_plots.png](performance_plots.png): parameter and performance plots
- [requirements.txt](requirements.txt): Python dependencies

## Quick Setup

Install the dependencies:

```bash
pip install -r requirements.txt
```

Open the main notebook:

```bash
jupyter notebook QDS_Yin_et_al.ipynb
```

If you want a faster first run, open the lighter walkthrough notebook instead:

```bash
jupyter notebook QDS_Beginner_Walkthrough.ipynb
```

## Optional Terminal Demo

Run the simplified demo:

```bash
python beginner_demo.py
```

Show a custom message and print the key terms:

```bash
python beginner_demo.py --document "Quantum signatures are cool" --bits 768 --show-terms
```
