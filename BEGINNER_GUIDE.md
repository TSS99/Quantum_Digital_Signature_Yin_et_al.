# Beginner Guide

This guide is the shortest explanation of the project without diving straight into the full research notebook.

## What Problem The Protocol Solves

Alice wants to sign a message in a way that:

- Bob and Charlie can verify it
- Bob cannot forge a new signature by himself
- Alice cannot make Bob accept while Charlie rejects

That last property is called non-repudiation.

## The Main Objects

These symbols appear everywhere in the project:

- `bM`: number of bits used to encode the document
- `bH`: hash length used for the signature
- `bH_prime`: authentication-tag length for the Bob/Charlie channel
- `XA`: Alice's effective secret key
- `XB`: Bob's key share
- `XC`: Charlie's key share
- `p_a`: fresh irreducible polynomial used for one signature
- `T_{p,s}`: Toeplitz matrix built from a polynomial and seed
- `h_a`: document hash output
- `Dig`: internal digest, equal to `h_a || polynomial_bits`
- `Sig`: public signature, equal to `Dig XOR OTP`
- `lS`: signature length in bits
- `lP`: total pre-shared key material used by the protocol

## The Core Relationship

The protocol relies on:

```text
XA = XB XOR XC
```

This means Bob and Charlie each hold only part of the information needed to reconstruct Alice's signing key.

## Honest Protocol Flow

The easiest way to understand the project is to follow one honest run:

1. Generate correlated keys so that `XA = XB XOR XC`.
2. Alice chooses a fresh irreducible polynomial `p_a`.
3. Alice builds a Toeplitz matrix from `p_a` and her seed bits.
4. Alice hashes the document to get `h_a`.
5. Alice combines `h_a` with the lower bits of `p_a` to form the digest.
6. Alice hides the digest with a one-time pad to create `Sig`.
7. Bob and Charlie exchange authenticated side information.
8. Bob and Charlie independently reconstruct the same key and verify the signature.
9. Both parties should agree on the result.

## Three Common Beginner Confusions

### 1. What is the difference between `p_a`, the seed, and the Toeplitz matrix?

- `p_a` defines the LFSR feedback rule.
- the seed defines the starting LFSR state.
- the Toeplitz matrix is built from the generated bit sequence.

They are connected, but they are not the same object.

### 2. Why is the signature not just the hash?

Because the digest is hidden with a one-time pad. The public signature is the masked digest, not the raw digest.

### 3. Why does `p_a` have to be fresh every time?

If Alice reuses the same polynomial with the same key material, Bob can exploit the reused hash structure and forge a signature. The full notebook includes both the proof and a demonstration of this loophole.

## Best Ways To Explore The Project

- Start with `python beginner_demo.py --show-terms`
- Then open `QDS_Beginner_Walkthrough.ipynb`
- Then read `qds_beginner.py`
- Save `QDS_Yin_et_al.ipynb` for the deeper theory and attack sections

## Good Experiments To Try

- Change the demo message and rerun it.
- Change `bM` and see how `bH` and `bH_prime` change.
- Compare `--quiet` and the verbose protocol run.
- Follow the attack sections only after the honest flow already makes sense.
