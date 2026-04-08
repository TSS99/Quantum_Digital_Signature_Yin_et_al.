"""Beginner-friendly Quantum Digital Signature helpers.

This module extracts the core protocol code from the research notebook so the
project can be explored as regular Python before diving into the full paper-style
walkthrough.
"""

# ============================================================
# Cell 3: Imports, Custom Exceptions, and Global Configuration
# ============================================================

import numpy as np
import secrets
import random
import logging
import math
import time
import json
import itertools
from collections import Counter

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.WARNING, format="%(levelname)-8s %(message)s")
logger = logging.getLogger("QDS")

# ── Custom exception hierarchy ────────────────────────────────────────────────
class QDSError(Exception):
    """Base class for all QDS protocol errors."""

class SigningError(QDSError):
    """Raised when Alice's signing procedure fails."""

class VerificationError(QDSError):
    """Raised when verification encounters an inconsistency."""

class AuthenticationFailure(QDSError):
    """Raised when a Wegman-Carter tag check fails (possible tampering)."""

class SecurityLoophole(QDSError):
    """Raised when a known security loophole (e.g., pa reuse) is detected."""

# ── Cryptographically secure RNG (backed by os.urandom) ───────────────────────
SECURE_RNG = secrets.SystemRandom()

# ── Default protocol configuration ───────────────────────────────────────────
CONFIG = {
    "bM": 10_000,
    "epsilon_target": 1e-10,
}

BEGINNER_TERMS = {
    "bM": "Document length in bits after encoding.",
    "bH": "Hash output length. Larger values reduce forgery probability.",
    "bH_prime": "Authentication-tag length used on the Bob/Charlie channel.",
    "XA": "Alice's effective secret key.",
    "XB": "Bob's key share.",
    "XC": "Charlie's key share.",
    "p_a": "Fresh irreducible polynomial chosen for one signature.",
    "T_{p,s}": "Toeplitz matrix built from the polynomial p and seed s.",
    "h_a": "Hash of the document under the Toeplitz construction.",
    "Dig": "Internal digest equal to hash bits plus polynomial bits.",
    "Sig": "Published signature, which is the digest hidden by a one-time pad.",
    "lS": "Signature length in bits.",
    "lP": "Total pre-shared key material consumed by the protocol.",
    "eps_for": "Forgery bound for a dishonest verifier.",
    "eps_rep": "Repudiation bound for a dishonest signer.",
}


def compute_security_params(bM: int, epsilon_target: float = 1e-10) -> dict:
    """Compute optimal Protocol 1 security parameters (Grasselli et al. Eqs. 29-30).

    Minimises l_P = 3*bH + 5*bH_prime subject to:
        eps_for = bM / 2^(bH-1)          <= eps_for_target
        eps_rep = (bM+2*bH) / 2^(bH'-1) <= eps_rep_target
        eps_for_target + eps_rep_target  == epsilon_target

    The optimal budget split (from Lagrange multiplier analysis) is
    eps_for_target = 0.6*eps, eps_rep_target = 0.4*eps, giving:

        bH  ~= ceil(log2(bM / (0.6*eps)) + 1),  min 4
        bH' ~= ceil(log2((bM+2*bH) / (0.4*eps)) + 1), min 4

    Args:
        bM (int): Document length in bits. Must be >= 1.
        epsilon_target (float): Total target security parameter. Must be > 0.

    Returns:
        dict: Keys bH, bH_prime, lS, lP, eps_for, eps_rep, eps_total.

    Raises:
        ValueError: If bM < 1 or epsilon_target <= 0.
    """
    if bM < 1:
        raise ValueError(f"bM must be >= 1, got {bM}")
    if epsilon_target <= 0:
        raise ValueError(f"epsilon_target must be > 0, got {epsilon_target}")

    eps_for_budget = 0.6 * epsilon_target
    eps_rep_budget = 0.4 * epsilon_target

    bH = max(4, math.ceil(math.log2(bM / eps_for_budget) + 1))
    bH_prime = max(4, math.ceil(math.log2((bM + 2 * bH) / eps_rep_budget) + 1))

    lS = 2 * bH
    lP = 3 * bH + 5 * bH_prime
    eps_for_actual = bM / (2 ** (bH - 1))
    eps_rep_actual = (bM + 2 * bH) / (2 ** (bH_prime - 1))

    return {
        "bH": bH, "bH_prime": bH_prime,
        "lS": lS, "lP": lP,
        "eps_for": eps_for_actual, "eps_rep": eps_rep_actual,
        "eps_total": eps_for_actual + eps_rep_actual,
    }

DEFAULT_PARAMS = compute_security_params(CONFIG["bM"], CONFIG["epsilon_target"])
CONFIG.update(DEFAULT_PARAMS)

# ============================================================
# Cell 5: GF(2) Polynomial Arithmetic Engine
# ============================================================


def poly_degree(poly_int: int) -> int:
    """Return the degree of a GF(2) polynomial encoded as integer.

    Bit k of poly_int = coefficient of x^k.
    Degree = position of highest set bit. Returns -1 for zero polynomial.

    Args:
        poly_int (int): Polynomial as non-negative integer.

    Returns:
        int: Degree (>= 0) or -1 if poly_int == 0.

    Examples:
        poly_degree(0b10011) == 4   # x^4 + x + 1
        poly_degree(0)       == -1  # zero polynomial
    """
    return poly_int.bit_length() - 1


def poly_to_bits(poly_int: int, degree: int) -> np.ndarray:
    """Convert a GF(2) polynomial integer to a coefficient bit array.

    Index k of the returned array = coefficient of x^k.
    Array length = degree + 1; index `degree` is always 1 for monic polynomials.

    Args:
        poly_int (int): Polynomial as non-negative integer.
        degree (int): Degree of the polynomial. Must be >= 0.

    Returns:
        np.ndarray: uint8 array of length degree+1.

    Example:
        poly_to_bits(0b10011, 4) -> [1,1,0,0,1]   # x^4+x+1
    """
    return np.array([(poly_int >> k) & 1 for k in range(degree + 1)], dtype=np.uint8)


def bits_to_int(bits: np.ndarray) -> int:
    """Convert a bit array to an integer (LSB-first encoding).

    bit k of result = bits[k]. This is the inverse of poly_to_bits.

    Args:
        bits (np.ndarray): uint8 array of 0s and 1s.

    Returns:
        int: Non-negative integer representation.

    Example:
        bits_to_int(np.array([1,1,0,0,1], dtype=np.uint8)) == 0b10011 == 19
    """
    result = 0
    for i, b in enumerate(bits):
        if b:
            result |= (1 << i)
    return result


def gf2_poly_mod(a: int, b: int) -> int:
    """Compute a(x) mod b(x) over GF(2) via bit-manipulation synthetic division.

    All coefficient arithmetic is mod 2 (XOR). The algorithm repeatedly XORs
    the dividend with a shifted divisor until the remainder has smaller degree.

    Args:
        a (int): Dividend polynomial as integer.
        b (int): Divisor polynomial as integer. Must not be 0.

    Returns:
        int: Remainder r(x) such that a(x) = q(x)*b(x) + r(x) over GF(2),
            with deg(r) < deg(b).

    Raises:
        ValueError: If b == 0.

    Example:
        gf2_poly_mod(0b11001, 0b10011) == 10  # 0b01010 = x^3 + x
    """
    if b == 0:
        raise ValueError("Divisor polynomial must not be zero.")
    deg_b = poly_degree(b)
    r = a
    while True:
        deg_r = poly_degree(r)
        if deg_r < deg_b:
            break
        r ^= b << (deg_r - deg_b)
    return r


def gf2_poly_mul(a: int, b: int) -> int:
    """Multiply two GF(2) polynomials (no modular reduction).

    Uses the shift-and-XOR algorithm: if bit k of a is set, XOR result
    with (b << k). All arithmetic is over GF(2).

    Args:
        a (int): First polynomial as integer.
        b (int): Second polynomial as integer.

    Returns:
        int: Product a(x)*b(x) over GF(2). Degree = deg(a) + deg(b).

    Example:
        gf2_poly_mul(0b101, 0b11) == 0b1111   # (x^2+1)(x+1) = x^3+x^2+x+1
    """
    result, tb = 0, b
    while a:
        if a & 1:
            result ^= tb
        a >>= 1
        tb <<= 1
    return result


def gf2_poly_pow_mod(base: int, exp: int, modulus: int) -> int:
    """Compute base(x)^exp mod modulus(x) over GF(2) via repeated squaring.

    Used in Rabin's irreducibility test to compute x^(2^k) mod p(x) efficiently.
    Handles astronomically large exponents (e.g., 2^200).

    Args:
        base (int): Base polynomial as integer.
        exp (int): Non-negative integer exponent.
        modulus (int): Modulus polynomial as integer.

    Returns:
        int: (base^exp) mod modulus over GF(2).
    """
    result = 1
    base = gf2_poly_mod(base, modulus)
    while exp > 0:
        if exp & 1:
            result = gf2_poly_mod(gf2_poly_mul(result, base), modulus)
        base = gf2_poly_mod(gf2_poly_mul(base, base), modulus)
        exp >>= 1
    return result


def gf2_gcd(a: int, b: int) -> int:
    """Euclidean GCD over GF(2)[x].

    Args:
        a (int): First polynomial as integer.
        b (int): Second polynomial as integer.

    Returns:
        int: GCD polynomial (with leading coefficient 1, as all GF(2) polys).
    """
    while b:
        a, b = b, gf2_poly_mod(a, b)
    return a


def is_irreducible_gf2(poly_int: int, degree: int) -> bool:
    """Test GF(2) polynomial irreducibility using Rabin's algorithm (1980).

    Rabin's criterion: p(x) of degree n over GF(2) is irreducible iff:
      (1) For each prime q dividing n:
              gcd(p(x), x^(2^(n/q)) XOR x) = 1  (mod p(x))
      (2) x^(2^n) = x  (mod p(x))

    Time complexity: O(n^2 log n) using repeated squaring - feasible for n ~200.

    Args:
        poly_int (int): Polynomial as integer.
        degree (int): Claimed degree. Must equal poly_degree(poly_int).

    Returns:
        bool: True iff p(x) is irreducible over GF(2).

    Raises:
        ValueError: If degree < 1.
    """
    if degree < 1:
        raise ValueError(f"Degree must be >= 1, got {degree}")
    if poly_degree(poly_int) != degree:
        return False
    # Constant term must be 1 (otherwise x | p, and p is reducible)
    if not (poly_int & 1):
        return False  # Even polynomial => x is a factor

    def prime_factors(n):
        factors, d, m = set(), 2, n
        while d * d <= m:
            while m % d == 0:
                factors.add(d); m //= d
            d += 1
        if m > 1:
            factors.add(m)
        return factors

    x = 2  # polynomial "x" = bit 1 = integer 2
    for q in prime_factors(degree):
        xpow = gf2_poly_pow_mod(x, 1 << (degree // q), poly_int)
        diff  = xpow ^ x   # x^(2^(n/q)) + x over GF(2) (addition = XOR)
        if diff == 0:
            return False   # gcd(p, 0) = p != 1
        if gf2_gcd(poly_int, diff) != 1:
            return False
    # Condition (2): x^(2^n) = x mod p
    return gf2_poly_pow_mod(x, 1 << degree, poly_int) == x


def is_irreducible_gf2_trial(poly_int: int, degree: int) -> bool:
    """Test GF(2) polynomial irreducibility via trial division (educational only).

    Tests all monic polynomials of degree 1 to degree//2 as potential factors.
    Exponential complexity O(2^(n/2)); practical only for degree <= 20.

    Args:
        poly_int (int): Polynomial as integer.
        degree (int): Degree. Must be <= 20 for reasonable runtime.

    Returns:
        bool: True iff irreducible over GF(2).

    Raises:
        ValueError: If degree > 20.
    """
    if degree > 20:
        raise ValueError(
            f"Trial division is impractical for degree={degree} > 20. "
            "Use is_irreducible_gf2() (Rabin's test) instead."
        )
    for d in range(1, degree // 2 + 1):
        for lower in range(1 << d):
            factor = (1 << d) | lower
            if gf2_poly_mod(poly_int, factor) == 0:
                return False
    return True


def generate_irreducible_poly(degree: int, rng=None) -> tuple:
    """Randomly generate an irreducible polynomial of given degree over GF(2).

    Samples random monic odd polynomials (constant term = 1, leading term = 1)
    and tests each with Rabin's algorithm until one passes.

    Expected number of trials: O(n) (irreducible polys have density ~1/(n*ln 2)).

    Args:
        degree (int): Polynomial degree. Must be >= 4.
        rng: Random number generator with a getrandbits(n) method.
            Defaults to secrets.SystemRandom().

    Returns:
        tuple: (poly_int: int, coeff_bits: np.ndarray of length degree+1).
            coeff_bits[k] = coefficient of x^k; coeff_bits[degree] = 1 (monic).

    Raises:
        ValueError: If degree < 4.
    """
    if degree < 4:
        raise ValueError(f"degree must be >= 4, got {degree}")
    if rng is None:
        rng = secrets.SystemRandom()
    while True:
        middle = rng.getrandbits(degree - 1)
        poly_int = (1 << degree) | (middle << 1) | 1   # monic and odd
        if is_irreducible_gf2(poly_int, degree):
            return poly_int, poly_to_bits(poly_int, degree)

# ============================================================
# Cell 8: LFSR Engine and Toeplitz Matrix Construction
# ============================================================


def lfsr_generate_sequence(poly_int: int, initial_state_bits: np.ndarray,
                            num_bits: int) -> np.ndarray:
    """Generate a bit sequence from a GF(2) Fibonacci LFSR.

    Implementation details:
      - State is stored as an integer (bit k = register cell k, LSB = s_0).
      - Output at each step: current LSB (s_0).
      - Feedback: new MSB = parity(state AND feedback_mask).
      - feedback_mask = poly_int XOR (1 << degree) = non-leading coefficients.

    This corresponds to the standard Fibonacci LFSR where the output sequence
    satisfies the linear recurrence defined by poly_int's coefficients.

    Args:
        poly_int (int): Irreducible connection polynomial (bit k = coeff of x^k).
        initial_state_bits (np.ndarray): uint8 array of length bH.
            Must not be all zeros (would generate degenerate all-zero sequence).
        num_bits (int): Number of output bits to generate.

    Returns:
        np.ndarray: uint8 array of length num_bits (the LFSR output sequence).

    Raises:
        ValueError: If initial state is all zeros, poly is not irreducible, or bH < 4.
    """
    degree = len(initial_state_bits)
    if degree < 4:
        raise ValueError(f"LFSR degree (bH) must be >= 4, got {degree}")
    if not np.any(initial_state_bits):
        raise ValueError(
            "LFSR initial state must not be all zeros - "
            "this produces the degenerate all-zero output sequence."
        )
    if not is_irreducible_gf2(poly_int, degree):
        raise ValueError(
            f"poly_int={poly_int:#x} is not irreducible of degree {degree}. "
            "Irreducibility is required for the AXU^2 property."
        )

    state = bits_to_int(initial_state_bits)
    # feedback_mask = non-leading coefficients of p(x) (all bits except the leading x^degree)
    feedback_mask = poly_int ^ (1 << degree)
    output = np.empty(num_bits, dtype=np.uint8)

    for k in range(num_bits):
        output[k] = state & 1       # LSB = current output bit

        # Parity of (state AND feedback_mask) via XOR-folding trick
        fb = state & feedback_mask
        fb ^= fb >> 16
        fb ^= fb >> 8
        fb ^= fb >> 4
        fb ^= fb >> 2
        fb ^= fb >> 1
        feedback_bit = fb & 1

        # Shift state right, insert feedback at MSB position
        state = (state >> 1) | (feedback_bit << (degree - 1))

    return output


def build_toeplitz_matrix(poly_int: int, initial_state_bits: np.ndarray,
                           bM: int, bH: int) -> np.ndarray:
    """Build the FAXU^2 Toeplitz hash matrix T_{p,s} of shape (bH, bM).

    Entry T[i, j] = r_{i+j} where r is the LFSR output sequence starting
    from initial state s. Requires bH + bM - 1 LFSR output bits total.

    The hash function h = T * Doc (mod 2) is from the epsilon-AXU^2 family
    with epsilon = bM / 2^(bH-1) (Krawczyk 1994, Theorem 5).

    Args:
        poly_int (int): Irreducible connection polynomial.
        initial_state_bits (np.ndarray): uint8 array of length bH (LFSR seed).
        bM (int): Number of matrix columns (document bit length).
        bH (int): Number of matrix rows (hash output length). Must be >= 4.

    Returns:
        np.ndarray: uint8 array of shape (bH, bM).

    Raises:
        ValueError: If bH < 4.
    """
    if bH < 4:
        raise ValueError(f"bH must be >= 4, got {bH}")
    seq = lfsr_generate_sequence(poly_int, initial_state_bits, bH + bM - 1)
    T = np.empty((bH, bM), dtype=np.uint8)
    for i in range(bH):
        T[i, :] = seq[i: i + bM]
    return T


def hash_document(toeplitz_matrix: np.ndarray, doc_bits: np.ndarray) -> np.ndarray:
    """Compute h = T * Doc (mod 2) - GF(2) matrix-vector product.

    Each output bit h_i = XOR_{j=0}^{bM-1} T[i,j] * Doc[j] (binary dot product).
    Implemented efficiently using integer dot product followed by mod 2.

    Args:
        toeplitz_matrix (np.ndarray): uint8 array of shape (bH, bM).
        doc_bits (np.ndarray): uint8 array of length bM (the document).

    Returns:
        np.ndarray: uint8 array of length bH (the hash value h).

    Raises:
        ValueError: If toeplitz_matrix columns != len(doc_bits).
    """
    bH, bM = toeplitz_matrix.shape
    if len(doc_bits) != bM:
        raise ValueError(
            f"Document length {len(doc_bits)} != Toeplitz matrix columns {bM}"
        )
    result = toeplitz_matrix.astype(np.int32) @ doc_bits.astype(np.int32)
    return (result % 2).astype(np.uint8)

# ============================================================
# Cell 11: Key Distribution Simulation
# ============================================================


def simulate_qkd_keys(bH: int, rng=None) -> tuple:
    """Simulate QKD key distribution for Alice, Bob, and Charlie.

    Generates uniform random XB and XC independently, then sets XA = XB XOR XC.
    This satisfies the information-theoretic privacy property:
        H(XA | XB) = H(XC) = 3*bH  (bits)
        H(XA | XC) = H(XB) = 3*bH  (bits)

    Key structure (each key is 3*bH bits):
        key[0:bH]    = LFSR seed (determines Toeplitz hash matrix)
        key[bH:3*bH] = OTP key (2*bH bits for digest encryption)

    In a real deployment, XA = XAB XOR XAC where XAB and XAC are independently
    established via QKD sessions (Alice-Bob and Alice-Charlie respectively).

    Args:
        bH (int): Hash output length in bits. Must be >= 4.
        rng: Random number generator. Defaults to secrets.SystemRandom()
            (backed by os.urandom, cryptographically secure).

    Returns:
        tuple: (XA, XB, XC) - numpy uint8 arrays of length 3*bH,
            satisfying XA[i] = XB[i] XOR XC[i] for all i.

    Raises:
        ValueError: If bH < 4.
    """
    if bH < 4:
        raise ValueError(f"bH must be >= 4, got {bH}")
    if rng is None:
        rng = secrets.SystemRandom()
    key_len = 3 * bH
    XB = np.array([rng.randint(0, 1) for _ in range(key_len)], dtype=np.uint8)
    XC = np.array([rng.randint(0, 1) for _ in range(key_len)], dtype=np.uint8)
    return XB ^ XC, XB, XC   # XA, XB, XC


def partition_key(key: np.ndarray, bH: int) -> tuple:
    """Partition a 3*bH-bit key into (LFSR seed, OTP key).

    Args:
        key (np.ndarray): uint8 array of length exactly 3*bH.
        bH (int): Hash output length. Must be >= 4.

    Returns:
        tuple: (seed, otp_key)
            seed:    uint8 array of length bH (LFSR initial state).
            otp_key: uint8 array of length 2*bH (One-Time Pad for encryption).

    Raises:
        ValueError: If bH < 4 or len(key) != 3*bH.
    """
    if bH < 4:
        raise ValueError(f"bH must be >= 4, got {bH}")
    if len(key) != 3 * bH:
        raise ValueError(f"Key length {len(key)} != 3*bH={3*bH}")
    return key[:bH].copy(), key[bH:].copy()   # seed, otp_key (length 2*bH)


def verify_key_relation(XA: np.ndarray, XB: np.ndarray, XC: np.ndarray) -> None:
    """Assert that XA = XB XOR XC elementwise.

    Args:
        XA (np.ndarray): Alice's key (uint8 array).
        XB (np.ndarray): Bob's key share (uint8 array).
        XC (np.ndarray): Charlie's key share (uint8 array).

    Raises:
        ValueError: If arrays have different lengths.
        AssertionError: If XA != XB XOR XC at any position.
    """
    if not (len(XA) == len(XB) == len(XC)):
        raise ValueError(
            f"Key lengths must match: |XA|={len(XA)}, |XB|={len(XB)}, |XC|={len(XC)}"
        )
    expected = XB ^ XC
    if not np.all(XA == expected):
        bad = np.where(XA != expected)[0]
        raise AssertionError(
            f"Key relation XA = XB XOR XC violated at {len(bad)} positions "
            f"(first mismatch at index {bad[0]})."
        )
    logger.info("Key relation XA = XB XOR XC verified successfully.")

# ============================================================
# Cell 14: Document Encoding and Alice's Signing Procedure
# ============================================================


def encode_document(text_input, bM: int) -> np.ndarray:
    """Convert a string or bytes input to a fixed-length bM-bit array.

    Encoding procedure (consistent with FAXU definition, Appendix B):
        1. UTF-8 encode if input is a string.
        2. Convert bytes to bits, MSB-first within each byte.
        3. Append a single '1' terminator bit (prevents length-extension ambiguity).
        4. Zero-pad to exactly bM bits.

    The terminating 1-bit ensures that two strings of different byte lengths
    always map to distinct bM-bit vectors, satisfying the domain requirement
    of the FAXU^2 universal hash family.

    Args:
        text_input (str or bytes): The document to encode.
        bM (int): Target length in bits. Must be >= 8.

    Returns:
        np.ndarray: uint8 array of length bM.

    Raises:
        ValueError: If the encoded document + terminator exceeds bM bits.
        TypeError: If text_input is not str or bytes.
    """
    if isinstance(text_input, str):
        raw_bytes = text_input.encode("utf-8")
    elif isinstance(text_input, (bytes, bytearray)):
        raw_bytes = bytes(text_input)
    else:
        raise TypeError(f"Expected str or bytes, got {type(text_input).__name__}")

    # Convert bytes to bits (MSB first within each byte)
    bits = []
    for byte in raw_bytes:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)

    # Terminating 1-bit
    bits.append(1)

    if len(bits) > bM:
        raise ValueError(
            f"Encoded document ({len(raw_bytes)} bytes + terminator = {len(bits)} bits) "
            f"exceeds bM={bM}. Use a larger bM or shorter document."
        )

    # Zero-pad to exactly bM bits
    bits.extend([0] * (bM - len(bits)))
    return np.array(bits, dtype=np.uint8)


def alice_sign(doc_bits: np.ndarray, XA: np.ndarray, bH: int, bM: int,
               rng=None) -> tuple:
    """Alice's signing procedure for Protocol 1 (Grasselli et al. 2025).

    Steps performed:
        1. Partition XA -> (seed = XA[:bH], otp_key = XA[bH:3*bH]).
        2. Generate a fresh irreducible polynomial p_a of degree bH.
        3. Build Toeplitz matrix T = T_{p_a, seed} of shape (bH, bM).
        4. Compute hash h_a = T * doc_bits (mod 2) in GF(2).
        5. Form digest Dig = h_a || pa_lower_bits (each bH bits, total 2*bH).
        6. OTP-encrypt: Sig = Dig XOR otp_key.

    The polynomial p_a is encoded as its bH lower-order coefficients
    (the leading x^{bH} term has coefficient 1 and is reconstructed by the
    verifier by setting bit bH = 1).

    SECURITY NOTE: p_a MUST be freshly generated for each signature.
    Reusing p_a with the same XA allows the pa-reuse attack (Lemma III.3).
    This function enforces freshness by always calling generate_irreducible_poly().

    Args:
        doc_bits (np.ndarray): uint8 array of length bM (the document).
        XA (np.ndarray): Alice's key, uint8 array of length 3*bH.
        bH (int): Hash output length (= polynomial degree). Must be >= 4.
        bM (int): Document length in bits. Must match len(doc_bits).
        rng: Random number generator. Defaults to secrets.SystemRandom().

    Returns:
        tuple: (sig_bits, pa_poly_int)
            sig_bits:    uint8 array of length 2*bH (the signature).
            pa_poly_int: int, the irreducible polynomial used (for audit logging).

    Raises:
        SigningError: If any step of the signing procedure fails.
        ValueError: If bH < 4, or dimensions do not match.
    """
    if bH < 4:
        raise ValueError(f"bH must be >= 4, got {bH}")
    if len(doc_bits) != bM:
        raise ValueError(f"doc_bits length {len(doc_bits)} != bM={bM}")
    if len(XA) != 3 * bH:
        raise ValueError(f"XA length {len(XA)} != 3*bH={3*bH}")
    if rng is None:
        rng = secrets.SystemRandom()

    try:
        # Step 1: Partition key
        seed, otp_key = partition_key(XA, bH)
        if not np.any(seed):
            logger.warning("SIGN: XA seed is all-zero; using all-one fallback.")
            seed = np.ones(bH, dtype=np.uint8)
        logger.info(f"SIGN: seed[:8] = {seed[:8]}")

        # Step 2: Fresh irreducible polynomial
        pa_poly_int, pa_coeff_full = generate_irreducible_poly(bH, rng)
        # pa_coeff_full has length bH+1 (includes leading 1 at index bH)
        # We transmit only the lower bH coefficients (leading 1 is implicit)
        pa_lower = pa_coeff_full[:bH].copy()
        logger.info(f"SIGN: p_a = {pa_poly_int:#010x} (degree {bH})")

        # Step 3: Toeplitz matrix
        T = build_toeplitz_matrix(pa_poly_int, seed, bM, bH)
        logger.info(f"SIGN: Toeplitz T.shape = {T.shape}")

        # Step 4: Hash
        h_a = hash_document(T, doc_bits)
        logger.info(f"SIGN: h_a = {h_a}")

        # Step 5: Digest = h_a || pa_lower (each bH bits)
        dig = np.concatenate([h_a, pa_lower])

        # Step 6: OTP encryption
        if len(otp_key) != 2 * bH:
            raise SigningError(f"OTP key length {len(otp_key)} != 2*bH={2*bH}")
        sig_bits = dig ^ otp_key
        logger.info(f"SIGN: Sig[:8] = {sig_bits[:8]}")

        return sig_bits, pa_poly_int

    except (ValueError, QDSError) as e:
        raise SigningError(f"Signing failed: {e}") from e

# ============================================================
# Cell 17: Wegman-Carter Authenticated Channel
# ============================================================


class WegmanCarterChannel:
    """Wegman-Carter (WC) authenticated channel between two parties.

    Uses an LFSR-Toeplitz hash from the epsilon-AXU^2 family for authentication
    tags, with a fresh OTP block consumed per message. The hash key (poly, seed)
    is fixed for the lifetime of the channel; only OTP blocks are consumed.

    Key structure of shared_auth_key (length >= (2+n_messages)*bH_prime):
        [0 : bH']       = LFSR seed for authentication hash
        [bH' : 2*bH']   = Encoded lower bits of irreducible polynomial
        [2*bH' : ...]   = OTP pool: n_messages consecutive bH'-bit blocks

    Security guarantee: For each authenticated message, the probability of
    a successful tag forgery is at most bM_tag / 2^(bH'-1) (AXU^2 bound).

    Attributes:
        bH_prime (int): Authentication tag length in bits.
        message_count (int): Number of messages sent/received so far.
        max_messages (int): Maximum number of messages (OTP pool size).
    """

    def __init__(self, shared_auth_key: np.ndarray, bH_prime: int):
        """Initialise the Wegman-Carter channel.

        Args:
            shared_auth_key (np.ndarray): Shared pre-established key bits.
                uint8 array of length at least (2+n_messages)*bH_prime.
            bH_prime (int): Authentication tag length. Must be >= 4.

        Raises:
            ValueError: If bH_prime < 4 or shared_auth_key too short for 1 message.
        """
        if bH_prime < 4:
            raise ValueError(f"bH_prime must be >= 4, got {bH_prime}")
        self.bH_prime = bH_prime
        self.message_count = 0

        # Parse key: LFSR seed
        seed = shared_auth_key[:bH_prime].copy()
        if not np.any(seed):
            seed = np.ones(bH_prime, dtype=np.uint8)

        # Parse key: polynomial bits (lower bH_prime bits; leading 1 is implicit)
        poly_bits = shared_auth_key[bH_prime:2 * bH_prime].copy()
        poly_int  = bits_to_int(poly_bits) | (1 << bH_prime)

        # If reconstructed polynomial is not irreducible, use deterministic fallback
        # Both sender and receiver derive the same fallback from the shared key
        if not is_irreducible_gf2(poly_int, bH_prime):
            det_rng = random.Random(bits_to_int(poly_bits))
            poly_int, _ = generate_irreducible_poly(bH_prime, det_rng)
            logger.info(f"AUTH: key poly not irreducible; deterministic fallback {poly_int:#x}")

        self._poly = poly_int
        self._seed = seed
        self._otp_pool = shared_auth_key[2 * bH_prime:].copy()
        self.max_messages = len(self._otp_pool) // bH_prime

        if self.max_messages < 1:
            raise ValueError(
                f"shared_auth_key too short: {len(shared_auth_key)} bits "
                f"requires at least {3 * bH_prime} for 1 message."
            )
        logger.info(f"AUTH CHANNEL: bH'={bH_prime}, poly={poly_int:#010x}, "
                    f"max_messages={self.max_messages}")

    def _compute_raw_tag(self, message_bits: np.ndarray) -> np.ndarray:
        """Compute raw (pre-OTP) authentication tag: hash(message).

        Builds the Toeplitz matrix for the message length and computes
        h = T_{poly, seed} * message_bits (mod 2).

        Args:
            message_bits (np.ndarray): uint8 array (the message to authenticate).

        Returns:
            np.ndarray: uint8 array of length bH_prime.
        """
        bM_tag = len(message_bits)
        T = build_toeplitz_matrix(self._poly, self._seed, bM_tag, self.bH_prime)
        return hash_document(T, message_bits)

    def _get_otp_block(self) -> np.ndarray:
        """Get the next fresh OTP block from the pool.

        Returns:
            np.ndarray: uint8 array of length bH_prime.

        Raises:
            AuthenticationFailure: If the OTP pool is exhausted.
        """
        if self.message_count >= self.max_messages:
            raise AuthenticationFailure(
                f"OTP pool exhausted after {self.message_count} messages. "
                "The authenticated channel key must be refreshed."
            )
        start = self.message_count * self.bH_prime
        block = self._otp_pool[start:start + self.bH_prime].copy()
        self.message_count += 1
        return block

    def send(self, message_bits: np.ndarray) -> tuple:
        """Authenticate and send a message.

        Computes: tag = hash(message) XOR otp_block, where otp_block is the
        next fresh block from the OTP pool (consumed and never reused).

        Args:
            message_bits (np.ndarray): uint8 array (the message to authenticate).

        Returns:
            tuple: (message_bits_copy, tag_bits) where tag_bits is uint8 array
                of length bH_prime.
        """
        raw_tag = self._compute_raw_tag(message_bits)
        otp     = self._get_otp_block()
        tag     = raw_tag ^ otp
        logger.info(f"AUTH SEND: msg_len={len(message_bits)}, tag={tag[:4]}...")
        return message_bits.copy(), tag

    def receive(self, message_bits: np.ndarray, tag_bits: np.ndarray) -> np.ndarray:
        """Verify and receive an authenticated message.

        Recomputes the tag using the shared hash key and the next OTP block,
        then compares with the received tag. The OTP block consumed here
        corresponds to the one used in the matching send() call.

        Args:
            message_bits (np.ndarray): uint8 array (the received message).
            tag_bits (np.ndarray): uint8 array of length bH_prime (the tag).

        Returns:
            np.ndarray: message_bits if authentication succeeds.

        Raises:
            AuthenticationFailure: If the tag does not match (possible tampering).
        """
        raw_tag  = self._compute_raw_tag(message_bits)
        otp      = self._get_otp_block()
        expected = raw_tag ^ otp
        if not np.all(tag_bits == expected):
            raise AuthenticationFailure(
                f"Authentication tag mismatch! "
                f"Received: {tag_bits[:4]}..., Expected: {expected[:4]}... "
                "The message may have been tampered with."
            )
        logger.info("AUTH RECV: message authenticated successfully.")
        return message_bits.copy()


def simulate_auth_key_needed(n_messages: int, bH_prime: int) -> int:
    """Compute total pre-shared key bits for an authenticated channel.

    Formula: (2 + n_messages) * bH_prime
        2*bH_prime  = hash function key (LFSR seed + polynomial bits)
        n_messages*bH_prime = OTP pool (one bH_prime-bit block per message)

    This is the l_P contribution from authenticated channels.
    For Protocol 1 with 3 authenticated messages: 5*bH_prime.

    Args:
        n_messages (int): Number of messages to authenticate.
        bH_prime (int): Authentication tag length in bits.

    Returns:
        int: Total pre-shared key bits required.
    """
    return (2 + n_messages) * bH_prime

# ============================================================
# Cell 19: Bob and Charlie Verification Functions
# ============================================================


def _reconstruct_and_verify(doc_bits: np.ndarray, sig_bits: np.ndarray,
                              own_key: np.ndarray, other_share: np.ndarray,
                              bH: int, bM: int, party: str) -> tuple:
    """Shared verification logic for Bob and Charlie.

    Implements the verification steps common to both parties:
        1. Reconstruct XA = own_key XOR other_share.
        2. Partition reconstructed key into seed and OTP key.
        3. Decrypt digest: Dig = sig_bits XOR otp_key.
        4. Parse digest into h_received and pa_lower_bits.
        5. Reconstruct polynomial: pa = (1 << bH) | bits_to_int(pa_lower).
        6. Verify pa is irreducible (rejects if not).
        7. Rebuild Toeplitz matrix T = T_{pa, seed}.
        8. Recompute hash h_computed = T * doc_bits (mod 2).
        9. Accept iff h_received == h_computed.

    Args:
        doc_bits (np.ndarray): uint8 array of length bM (the document).
        sig_bits (np.ndarray): uint8 array of length 2*bH (the signature).
        own_key (np.ndarray): Verifier's own key share, length 3*bH.
        other_share (np.ndarray): Other party's key share, length 3*bH.
        bH (int): Hash output length. Must be >= 4.
        bM (int): Document length in bits.
        party (str): 'Bob' or 'Charlie' (for logging).

    Returns:
        tuple: (accept: bool, K_reconstructed: np.ndarray)

    Raises:
        VerificationError: On structural inconsistencies.
        ValueError: If bH < 4.
    """
    if bH < 4:
        raise ValueError(f"bH must be >= 4, got {bH}")

    # Step 1-2: Reconstruct and partition
    K      = own_key ^ other_share     # = XA
    K_seed = K[:bH].copy()
    K_otp  = K[bH:].copy()            # length 2*bH
    if not np.any(K_seed):
        logger.warning(f"VERIFY [{party}]: reconstructed seed all-zero; using all-one.")
        K_seed = np.ones(bH, dtype=np.uint8)

    # Validate dimensions
    if len(sig_bits) != 2 * bH:
        raise VerificationError(
            f"sig_bits length {len(sig_bits)} != 2*bH={2*bH}"
        )
    if len(K_otp) != 2 * bH:
        raise VerificationError(
            f"K_otp length {len(K_otp)} != 2*bH={2*bH}"
        )

    # Step 3: Decrypt digest
    dig = sig_bits ^ K_otp

    # Step 4: Parse
    h_received = dig[:bH]
    pa_lower   = dig[bH:]
    pa_int     = bits_to_int(pa_lower) | (1 << bH)   # restore leading x^{bH}

    logger.info(f"VERIFY [{party}]: h_received={h_received}, pa={pa_int:#010x}")

    # Step 5: Irreducibility check
    try:
        irred = is_irreducible_gf2(pa_int, bH)
    except Exception as e:
        logger.warning(f"VERIFY [{party}]: irreducibility check error: {e}")
        irred = False

    if not irred:
        logger.warning(f"VERIFY [{party}]: pa={pa_int:#010x} not irreducible -> REJECT")
        return False, K

    # Steps 7-9: Rebuild matrix, recompute hash, compare
    try:
        T = build_toeplitz_matrix(pa_int, K_seed, bM, bH)
        h_computed = hash_document(T, doc_bits)
    except Exception as e:
        raise VerificationError(f"Hash recomputation failed for {party}: {e}") from e

    accept = bool(np.all(h_received == h_computed))
    logger.info(f"VERIFY [{party}]: h_computed={h_computed} -> accept={accept}")
    return accept, K


def bob_verify(doc_bits: np.ndarray, sig_bits: np.ndarray,
               XB: np.ndarray, XC_from_charlie: np.ndarray,
               bH: int, bM: int) -> tuple:
    """Bob's signature verification procedure.

    Bob receives {Doc, Sig} from Alice (public channel) and XC from Charlie
    (authenticated channel). He reconstructs XA = XB XOR XC and verifies.

    Args:
        doc_bits (np.ndarray): uint8 array of length bM (the document).
        sig_bits (np.ndarray): uint8 array of length 2*bH (the signature).
        XB (np.ndarray): Bob's own key share, uint8 array of length 3*bH.
        XC_from_charlie (np.ndarray): Charlie's share received via auth channel.
        bH (int): Hash output length. Must be >= 4.
        bM (int): Document length in bits.

    Returns:
        tuple: (accept: bool, VB: int, KB: np.ndarray)
            accept: True if Bob accepts the signature.
            VB: 1 if accept, 0 if reject.
            KB: Bob's reconstructed version of XA.
    """
    accept, KB = _reconstruct_and_verify(
        doc_bits, sig_bits, XB, XC_from_charlie, bH, bM, "Bob"
    )
    return accept, int(accept), KB


def charlie_verify(doc_bits: np.ndarray, sig_bits: np.ndarray,
                   XC: np.ndarray, XB_from_bob: np.ndarray,
                   bH: int, bM: int) -> tuple:
    """Charlie's independent signature verification procedure.

    Charlie receives {Doc, Sig, XB} from Bob (authenticated channel).
    He reconstructs XA = XC XOR XB and verifies INDEPENDENTLY of Bob's report.
    This independence is essential for repudiation security.

    Args:
        doc_bits (np.ndarray): uint8 array of length bM (the document).
        sig_bits (np.ndarray): uint8 array of length 2*bH (the signature).
        XC (np.ndarray): Charlie's own key share, uint8 array of length 3*bH.
        XB_from_bob (np.ndarray): Bob's key share received via auth channel.
        bH (int): Hash output length. Must be >= 4.
        bM (int): Document length in bits.

    Returns:
        tuple: (accept: bool, KC: np.ndarray)
            accept: True if Charlie accepts the signature.
            KC: Charlie's reconstructed version of XA.
    """
    accept, KC = _reconstruct_and_verify(
        doc_bits, sig_bits, XC, XB_from_bob, bH, bM, "Charlie"
    )
    return accept, KC


def check_agreement(bob_accept: bool, charlie_accept: bool) -> bool:
    """Check whether Bob and Charlie agree on the signature's validity.

    In the honest protocol, both parties must always agree (both accept or
    both reject). A disagreement indicates either an attack or a protocol failure.

    Args:
        bob_accept (bool): Bob's verification result.
        charlie_accept (bool): Charlie's verification result.

    Returns:
        bool: True if both agree, False if they disagree.
    """
    if bob_accept == charlie_accept:
        logger.info(f"AGREEMENT: both {'accept' if bob_accept else 'reject'}. OK.")
        return True
    logger.warning(
        f"AGREEMENT FAILURE: Bob={bob_accept}, Charlie={charlie_accept}. "
        "Possible repudiation attack or authenticated channel compromise!"
    )
    return False

# ============================================================
# Cell 22: Full Protocol Runner
# ============================================================


def run_qds_protocol(document: str, bM: int, bH: int, bH_prime: int,
                     verbose: bool = True) -> dict:
    """Run the complete QDS Protocol 1 from key distribution to agreement check.

    Orchestrates all protocol phases:
        Phase 1: QKD key distribution (simulated).
        Phase 2: Alice signs the document.
        Phase 3: Setup Wegman-Carter authenticated channels Bob <-> Charlie.
        Phase 4: Bob sends {Doc || Sig || XB} to Charlie (authenticated).
        Phase 5: Charlie sends XC to Bob (authenticated).
        Phase 6: Bob verifies independently.
        Phase 7: Charlie verifies independently.
        Phase 8: Agreement check.

    Args:
        document (str): The message to sign (UTF-8 string).
        bM (int): Document encoding length in bits.
        bH (int): Hash output length (signature security parameter). Must be >= 4.
        bH_prime (int): Authentication tag length (repudiation parameter). Must be >= 4.
        verbose (bool): If True, print a short human-readable execution summary.

    Returns:
        dict: Full protocol result containing all keys, the signature, verification
            outcomes, security parameters, and a boolean 'success' flag.
            Keys: document, bM, bH, bH_prime, XA, XB, XC, doc_bits, sig_bits,
            pa_poly, bob_accept, charlie_accept, agreement, success,
            eps_for, eps_rep, lS, lP.
    """
    logging.getLogger("QDS").setLevel(logging.WARNING)
    rng = secrets.SystemRandom()

    lS = 2 * bH
    lP = 3 * bH + 5 * bH_prime
    eps_for = bM / (2 ** (bH - 1))
    eps_rep = (bM + 2 * bH) / (2 ** (bH_prime - 1))

    if verbose:
        print(f"\n{'='*60}\nQDS Protocol 1 - Full Execution\n{'='*60}")
        print(f"Document: '{document}'")
        print(f"bM={bM:,d}, bH={bH}, bH'={bH_prime}")
        print(f"eps_for={eps_for:.2e}, eps_rep={eps_rep:.2e}")
        print(f"l_S={lS} bits, l_P={lP} bits")

    # ── Phase 1: Key Distribution ─────────────────────────────────────────────
    XA, XB, XC = simulate_qkd_keys(bH, rng)
    verify_key_relation(XA, XB, XC)

    # Authenticated channel keys: (2+3)*bH_prime = 5*bH_prime bits each
    auth_len = simulate_auth_key_needed(3, bH_prime)
    auth_key_BC = np.array([rng.randint(0,1) for _ in range(auth_len)], dtype=np.uint8)
    auth_key_CB = np.array([rng.randint(0,1) for _ in range(auth_len)], dtype=np.uint8)

    # ── Phase 2: Alice Signs ──────────────────────────────────────────────────
    doc_bits = encode_document(document, bM)
    sig_bits, pa_poly = alice_sign(doc_bits, XA, bH, bM, rng)

    # ── Phase 3: Bob -> Charlie: {Doc || Sig || XB} (authenticated) ───────────
    msg_BC = np.concatenate([doc_bits, sig_bits, XB])   # total: bM + 2*bH + 3*bH bits
    chan_BC_s = WegmanCarterChannel(auth_key_BC.copy(), bH_prime)
    chan_BC_r = WegmanCarterChannel(auth_key_BC.copy(), bH_prime)
    msg_sent, tag_BC = chan_BC_s.send(msg_BC)
    try:
        msg_recv = chan_BC_r.receive(msg_sent, tag_BC)
    except AuthenticationFailure as e:
        logger.warning(f"BC channel authentication failed: {e}")
        msg_recv = msg_sent  # simulation continues despite failure

    # ── Phase 4: Charlie -> Bob: {XC} (authenticated) ────────────────────────
    chan_CB_s = WegmanCarterChannel(auth_key_CB.copy(), bH_prime)
    chan_CB_r = WegmanCarterChannel(auth_key_CB.copy(), bH_prime)
    xc_sent, tag_CB = chan_CB_s.send(XC)
    try:
        xc_recv = chan_CB_r.receive(xc_sent, tag_CB)
    except AuthenticationFailure as e:
        logger.warning(f"CB channel authentication failed: {e}")
        xc_recv = xc_sent

    # Parse the received Bob->Charlie message
    doc_recv = msg_recv[:bM]
    sig_recv = msg_recv[bM:bM + 2 * bH]
    XB_recv  = msg_recv[bM + 2 * bH:]

    # ── Phase 5-6: Verification ───────────────────────────────────────────────
    bob_accept, VB, KB   = bob_verify(doc_bits, sig_bits, XB, xc_recv, bH, bM)
    charlie_accept, KC   = charlie_verify(doc_recv, sig_recv, XC, XB_recv, bH, bM)
    agreement = check_agreement(bob_accept, charlie_accept)
    success   = bob_accept and charlie_accept and agreement

    if verbose:
        print(f"\nVerification Results:")
        print(f"  Bob accepted:     {bob_accept}")
        print(f"  Charlie accepted: {charlie_accept}")
        print(f"  Agreement:        {agreement}")
        print(f"  Protocol passed:  {success}")

    return {
        "document": document, "bM": bM, "bH": bH, "bH_prime": bH_prime,
        "XA": XA, "XB": XB, "XC": XC, "doc_bits": doc_bits, "sig_bits": sig_bits,
        "pa_poly": pa_poly, "bob_accept": bob_accept, "charlie_accept": charlie_accept,
        "agreement": agreement, "success": success,
        "eps_for": eps_for, "eps_rep": eps_rep, "lS": lS, "lP": lP,
    }


def format_result_summary(result: dict) -> str:
    """Return a compact human-readable summary of a protocol run."""
    return "\n".join(
        [
            "Summary",
            "-" * 45,
            f"Protocol success : {result['success']}",
            f"Bob accepted     : {result['bob_accept']}",
            f"Charlie accepted : {result['charlie_accept']}",
            f"Agreement        : {result['agreement']}",
            f"lS               : {result['lS']} bits",
            f"lP               : {result['lP']} bits",
            f"eps_for          : {result['eps_for']:.2e}",
            f"eps_rep          : {result['eps_rep']:.2e}",
        ]
    )


def format_beginner_terms() -> str:
    """Return a compact glossary of the most common symbols in the project."""
    lines = ["Beginner term cheat sheet", "-" * 45]
    for name, meaning in BEGINNER_TERMS.items():
        lines.append(f"{name:<10} : {meaning}")
    return "\n".join(lines)
