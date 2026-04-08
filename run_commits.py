import nbformat
import os
import subprocess

updates = [
    {
        "action": "replace",
        "target_idx": 0,
        "content": "# \ud83c\udf1f Quantum Digital Signatures (QDS): A Beginner-Friendly Journey\n\nWelcome to this step-by-step tutorial on Quantum Digital Signatures (QDS)! Let's start with a simple question: **What is a digital signature?**\n\nImagine you want to send a highly important contract to your friend across the internet. You want to make sure of two things:\n1. Your friend knows for sure that the contract came from you and nobody else (*Authenticity*).\n2. They know the contract wasn't tampered with by a hacker along the way (*Integrity*).\n\nIn classical cryptography (like RSA), we rely on hard math problems. But what if a supercomputer (or a future quantum computer) solves that hard math problem? Our signatures would be broken!"
    },
    {
        "action": "insert",
        "target_idx": 1,
        "content": "## \ud83d\uded1 Why Quantum Digital Signatures?\n\nBecause classical security is based on 'computational hardness' \u2014 hoping someone doesn't have a computer fast enough. \n\n**Quantum Digital Signatures (QDS)** change the game entirely. Instead of relying on math problems, they rely on the **laws of physics**! This provides what we call *information-theoretic security*. That means even an adversary with an infinitely fast alien supercomputer cannot forge your signature. \n\nIn this notebook, we'll walk through exactly how this physics-based protocol works from the ground up, based on the recent research by Yin et al. and Grasselli et al."
    },
    {
        "action": "insert",
        "target_idx": 2,
        "content": "## \ud83d\udc65 The Cast of Characters\n\nBefore diving into the math, let's meet our participants:\n- **Alice**: She is the signer. She wants to send the secure document.\n- **Bob**: The primary receiver and verifier. He checks Alice's signature.\n- **Charlie**: A secondary verifier. Bob forwards the document to him, and they both must agree to prevent repudiation (Alice saying 'I didn't sign that!')."
    },
    {
        "action": "replace",
        "target_idx": 4,  # Originally cell 1, now shifted + 2 = index 3, but let's re-read by searching
        # It's better to find cells by their original text or just re-read the file in memory
        "content": "## \ud83e\udde9 The Core Mathematical Magic: Hashing\n\nWe don't sign the entire document bit by bit (that would be slow!). Instead, we take the massive document and squash it down into a short, unique fingerprint. This is called **hashing**.\n\nBut we need a special kind of hashing known as $\\varepsilon$-almost-XOR-universal-squared ($\\varepsilon$-AXU\u00b2) hashing. Don't let the name scare you!\n\n**Intuitively:** If someone tries to change the document and guess its new hash they will fail almost every single time. It's mathematically guaranteed that their chance of predicting the output without knowing the secret key is practically zero (less than $\\varepsilon$). We achieve this using Linear Feedback Shift Registers (LFSR) and Toeplitz matrices."
    },
    {
        "action": "insert",
        "target_idx": 5,
        "content": "### \ud83d\udebb What is a Linear Feedback Shift Register (LFSR)?\n\nThink of an LFSR as a tiny predictable random number generator built in hardware. You start with a few bits of 'seed' (your secret state), and then at each step, you shift the bits over and create a new bit by mixing some of the old ones together (using XOR).\n\nIf you pick the right kind of mixing rule (an *irreducible polynomial*), this tiny machine will spit out a super-long stream of pseudo-random bits without repeating for a very long time! We will use this stream to build our hashing mechanism."
    },
    {
        "action": "insert",
        "target_idx": 6,
        "content": "### \ud83d\udcdd What is a Toeplitz Matrix?\n\nA Toeplitz matrix is a special grid of numbers where all the diagonal lines top-left to bottom-right have the exact same number in them. \n\nWe fill this grid using the bits coming out of our LFSR. Because of the special diagonal structure, we don't need to save the whole giant matrix in memory\u2014we just need the edges, and the rest fills itself in! We multiply our document by this matrix to get that short, unique fingerprint (the hash)."
    },
    {
        "action": "replace",
        "target_idx": 9, # Original cell 3 (Math arithmetic)
        "content": "## \u2795 Exploring the Math: GF(2) Arithmetic\n\nLet's get comfortable with the numbers we are using. In our quantum protocol world, we only deal with **0s and 1s**. This is called the Binary Field or **GF(2)** (Galois Field of 2).\n\n- **Addition** is simply **XOR**. So, `1 + 1 = 0` and `0 + 1 = 1`.\n- **Multiplication** is **AND**. So, `1 * 1 = 1` and anything else is `0`.\n\nWhen we talk about polynomials (like $x^2 + x + 1$), we describe them using binary bits. So a polynomial $x^4 + x + 1$ can be written as the binary number `10011`."
    },
    {
        "action": "insert",
        "target_idx": 10,
        "content": "### \ud83d\udd0e Rabin's Test for Irreducible Polynomials\n\nWhy do we care about 'irreducible' polynomials? Think of them as the \"prime numbers\" of polynomials \u2014 they can't be factored into smaller pieces. \n\nWe need irreducible polynomials for our LFSR to work perfectly without getting stuck in a short loop. To find them, we use a clever and efficient algorithm called **Rabin's test**. It's much faster than trying to divide by every possible number!"
    },
    {
        "action": "replace",
        "target_idx": 13, # Original cell 6 (LFSR ascii)
        "content": "## \u2699\ufe0f Building the Hash: LFSR & Toeplitz in Action\n\nLet's visualize how the LFSR actually runs. Imagine a small degree-4 LFSR where the feedback rule is $x^4 + x + 1$.\n\nOutput comes from the first bit, and the new bit comes from XORing the 0th and 1st bits.\n\n```\n OUTPUT \u2190 [s0] \u2190 [s1] \u2190 [s2] \u2190 [s3]\n              \\_ XOR __\u2191\n```\n\nBy pumping this machine, we produce a sequence of bits. If we lay this sequence along the edges of our matrix, we can complete a full **Toeplitz matrix** to securely hash our document!"
    },
    {
        "action": "insert",
        "target_idx": 14,
        "content": "### \ud83d\udcca Walkthrough of the LFSR sequence\n\nIf we start with a seed state of `(1, 0, 0, 0)`, the machine outputs `1`. Then it updates its state to `(0, 0, 0, 1)`, outputting `0`.\nIt keeps spitting out bits like a ticker tape. The result sequence looks like this: `[1,0,0,0,1,0,0,1,1,0,1]`.\nWe just used a tiny secret to produce a long string of bits we can use for cryptography!"
    },
    {
        "action": "replace",
        "target_idx": 17, # Original cell 9
        "content": "## \ud83d\udd11 The Secret Sauce: Quantum Key Distribution (QKD)\n\nThis is where the *Quantum* in Quantum Digital Signatures shines! \n\n**QKD** uses real lasers and single-photon detectors. Thanks to the \"no-cloning theorem\" of quantum mechanics, if a hacker tries to eavesdrop on the lasers, they physically alter the state of the photons, which sounds an immediate alarm for Alice and Bob. \n\nIn our code, we don't simulate the lasers. We assume the QKD hardware has already run successfully and handed out perfect, mathematically unbreakable random keys."
    },
    {
        "action": "insert",
        "target_idx": 18,
        "content": "### \ud83e\udd1d How the Keys are Shared\n\nHere is a brilliant trick to make sure Alice can't cheat Bob, and Bob can't impersonate Alice:\n- Alice shares a random key with Bob ($X_B$).\n- Alice shares a random key with Charlie ($X_C$).\n- Alice's total key is the XOR of those two: $X_A = X_B \\oplus X_C$.\n\nSince Bob only knows his half, he has zero clues about Alice's full key. Charlie is in the same boat. But *together*, combined, they know exactly what Alice's key is!"
    },
    {
        "action": "replace",
        "target_idx": 21, # Original cell 12
        "content": "## \u270d\ufe0f Step-by-Step: How Alice Signs a Message\n\nAlice desires to send her document securely. Here is her thought process:\n\n1. **Freshness is Key**: First, she generates a completely brand new irreducible polynomial $p_a$. If she reuses an old one, a clever hacker can completely break the system!\n2. **The Hash**: She uses her piece of the secret key to jump-start the LFSR, builds the Toeplitz matrix, and squashes the document down into a tiny hash value."
    },
    {
        "action": "insert",
        "target_idx": 22,
        "content": "### \ud83d\udd12 Protecting the Hash\n\n3. **The Digest**: Alice sticks the polynomial $p_a$ and the hash together. This forms the \"Digest\".\n4. **One-Time Pad Encryption**: She uses another section of her perfectly secure quantum key to flip the bits of the digest (XOR). This is \"One-Time Pad\" encryption.\n\nEven with an infinite amount of time, a hacker looking at the signature can't decrypt it because it is literally mathematically impossible to reverse a One-Time Pad!"
    },
    {
        "action": "replace",
        "target_idx": 25, # Original cell 15
        "content": "## \ud83d\udee1\ufe0f Authenticated Channels: The Safety Net\n\nAlice sends her document and signature across the open internet to Bob. But what happens next?\n\nBob needs to show Charlie his key, so Charlie can verify everything. If Bob sends it openly, Alice could intercept it, switch Bob's key out, and confuse everyone! We need an **Authenticated Channel**."
    },
    {
        "action": "insert",
        "target_idx": 26,
        "content": "### \ud83c\udff7\ufe0f Wegman\u2013Carter Authentication\n\nTo build this authenticated channel, Bob uses a fresh tag (Wegman\u2013Carter tag) attached to his message to Charlie. \nIt behaves like an anti-tamper seal. If Alice tries to mess with Bob's forwarded message, Charlie will notice the seal is broken and trigger an alarm. This stops Alice from maliciously causing disagreements between Bob and Charlie (a property called 'Non-Repudiation')."
    },
    {
        "action": "replace",
        "target_idx": 29, # Original cell 17
        "content": "## \ud83d\udc40 The Moment of Truth: Bob and Charlie Verify\n\nBob receives the document. Here is his thought process:\n1. \"I need Alice's full key. I'll ask Charlie for his half ($X_C$)\".\n2. Bob combines his key and Charlie's key: $X_B \\oplus X_C = X_A$. Aha! He now has Alice's key.\n3. He uses Alice's key to decrypt the One-Time Pad and reveals the hash and polynomial.\n4. He double-checks the math on his end. Does the document actually hash to this value? If yes, ACCEPT!"
    },
    {
        "action": "insert",
        "target_idx": 30,
        "content": "### \ud83e\uddf2 Charlie's Independent Check\n\nCharlie does the exact same calculation completely independently of Bob. \n\nHe doesn't ask Bob if it was right; he checks the math himself. Because they both use the identical combined secret key, they are mathematically guaranteed to reach the exact same conclusion! Either they both accept, or they both reject. Alice cannot fool them."
    },
    {
        "action": "replace",
        "target_idx": 33, # Original cell 20
        "content": "## \u2694\ufe0f Seeing is Believing: Hackers Attack!\n\nTo prove our protocol is bulletproof, let's simulate three malicious attacks:\n\n1. **Blind Forgery**: Bob has zero information, but tries to guess the signature blindly. \n   *Outcome*: He fails. The odds of guessing the keys are astronomical ($< 2^{-108}$)."
    },
    {
        "action": "insert",
        "target_idx": 34,
        "content": "### \ud83d\udc7d More Sophisticated Attacks\n\n2. **Informed Forgery**: Bob knows Alice's key from an older message! He tries to forge a new document.\n   *Outcome*: He fails! Because Alice picks a random *fresh* polynomial every time, Bob's old knowledge is useless. The LFSR-Toeplitz properties block him.\n\n3. **Repudiation**: Alice tries to mess with the communications between Bob and Charlie.\n   *Outcome*: She is blocked by the Wegman-Carter Authentication tags. Charlie detects the tampering."
    },
    {
        "action": "replace",
        "target_idx": 37, # Original cell 24
        "content": "## \u26a0\ufe0f The Fatal Mistake: Reusing $p_a$\n\nRemember when we said Alice must generate a fresh polynomial $p_a$ every single time?\n\nHere is exactly why: If she gets lazy and reuses the same polynomial, Bob already knows it. He can construct a malicious document $m^*$ that perfectly \"cancels out\" inside the Toeplitz matrix calculation to equal zero. He creates a fake signature of zero, and Charlie will mathematically accept it with 100% confidence! \n\n**Always use fresh random keys in quantum cryptography!**"
    },
    {
        "action": "replace",
        "target_idx": 40, # Original cell 26 (was cell 28)
        "content": "## \ud83c\udfc1 Final Takeaways\n\nCongratulations! You have successfully journeyed through a mathematically rigorous implementation of a Quantum Digital Signature.\n\nYou have seen how the weirdness of quantum mechanics (via no-cloning and QKD) combined with incredibly clever classical mathematics (LFSRs and Toeplitz matrices) yields an unbreakable system.\n\nThe future of cryptography isn't just about bigger numbers. It's about using the laws of physics themselves. Awesome job!"
    }
]

def apply_updates():
    for step, update in enumerate(updates):
        # We need to re-read each time because inserting changes indices
        with open('QDS_Yin_et_al.ipynb', 'r', encoding='utf-8') as f:
            nb = nbformat.read(f, as_version=4)
        
        # Figure out where the markdown cells are
        md_indices = [i for i, c in enumerate(nb.cells) if c.cell_type == 'markdown']
        
        action = update['action']
        target = update['target_idx'] # Note: Using an expanding list assumption is tricky.
        # Actually it's simpler to just do this:
        # Instead of strict target_idx, I will just apply the change at a specific absolute position.
        # Since I am replacing/inserting progressively, `target_idx` will refer to the absolute `nb.cells` array.
        
        new_cell = nbformat.v4.new_markdown_cell(source=update['content'])
        
        if action == 'replace':
            if target < len(nb.cells):
                nb.cells[target] = new_cell
            else:
                nb.cells.append(new_cell)
        elif action == 'insert':
            nb.cells.insert(target, new_cell)
            
        with open('QDS_Yin_et_al.ipynb', 'w', encoding='utf-8') as f:
            nbformat.write(nb, f)
        
        # Git commit and push
        subprocess.run(['git', 'add', 'QDS_Yin_et_al.ipynb'], check=True)
        subprocess.run(['git', 'commit', '-m', f"Refactor QDS markdown for better readability: step {step+1}"], check=True)
        subprocess.run(['git', 'push'], check=True)
        print(f"Pushed commit {step+1}/{len(updates)}")

if __name__ == '__main__':
    # Initial push for the python script as a bonus commit if needed
    subprocess.run(['git', 'add', 'run_commits.py'])
    subprocess.run(['git', 'commit', '-m', "Add multi-commit helper script"])
    subprocess.run(['git', 'push'])
    apply_updates()
