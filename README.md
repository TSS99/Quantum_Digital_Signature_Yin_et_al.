# Quantum Digital Signature - Beginner-Friendly Edition

This project implements the Quantum Digital Signature (QDS) protocol based on Yin et al.

The original repository centered around a single research-style notebook. This version keeps that notebook, but also adds simpler entry points so you can understand the protocol in layers instead of all at once.

## Start Here

If you are new to the project, use this order:

1. Open `QDS_Beginner_Walkthrough.ipynb`
2. Run `python beginner_demo.py`
3. Explore `qds_beginner.py`
4. Dive into `QDS_Yin_et_al.ipynb` for the full derivations, validation checks, attack simulations, and plots

## Files

- `QDS_Beginner_Walkthrough.ipynb`: shortest guided notebook for first-time readers
- `beginner_demo.py`: simple end-to-end script you can run from the terminal
- `qds_beginner.py`: reusable Python module with the core protocol logic
- `QDS_Yin_et_al.ipynb`: original full notebook with mathematical background, proofs, tests, and simulations
- `attack_results.png`: attack simulation plot
- `performance_plots.png`: parameter and performance plots

## Requirements

Install the dependencies:

```bash
pip install -r requirements.txt
```

## Quick Run

Run the terminal demo:

```bash
python beginner_demo.py
```

Open the beginner notebook:

```bash
jupyter notebook QDS_Beginner_Walkthrough.ipynb
```

Open the full research notebook:

```bash
jupyter notebook QDS_Yin_et_al.ipynb
```

## What The Demo Covers

The beginner path focuses on the honest protocol flow:

1. Choose security parameters for a message length
2. Simulate QKD-style shared keys
3. Sign a document as Alice
4. Verify the signature independently as Bob and Charlie
5. Check whether both verifiers agree

This gives you the protocol workflow first, before you study the heavier mathematical sections.

## Notes

- The QKD stage is abstracted as trusted pre-shared key generation.
- The implementation focuses on the classical cryptographic part of the protocol.
- The original notebook is still the best place to study the full paper-level reasoning.
