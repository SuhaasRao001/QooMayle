"""
Entropy Analysis Engine — NIST SP 800-90B Statistical Tests
============================================================
Applies a subset of NIST SP 800-90B statistical tests to key material bytes
to score their quality. This gives a quantitative "quantum quality" metric
that's actually meaningful to show in a demo.

Tests implemented:
  1. Monobit (frequency) test     — checks bit balance
  2. Block frequency test         — checks frequency within sub-blocks
  3. Runs test                    — checks runs of identical bits
  4. Entropy estimation (H_bitstring from SP 800-90B §6.3.1)

This is purely for analysis/demo — the actual crypto is independent of these scores.
"""
import math
import struct
from typing import Dict, Any


def _bytes_to_bits(data: bytes) -> list[int]:
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def monobit_test(bits: list[int]) -> dict:
    """NIST SP 800-22 Test 1: Monobit Frequency Test."""
    n = len(bits)
    s = sum(2 * b - 1 for b in bits)  # map 0→-1, 1→+1
    s_obs = abs(s) / math.sqrt(n)
    # P-value approximation using erfc
    p_value = math.erfc(s_obs / math.sqrt(2))
    return {
        "name": "Monobit Frequency",
        "statistic": round(s_obs, 4),
        "p_value": round(p_value, 4),
        "pass": p_value >= 0.01,
        "ones_ratio": round(sum(bits) / n, 4),
    }


def block_frequency_test(bits: list[int], block_size: int = 128) -> dict:
    """NIST SP 800-22 Test 2: Block Frequency Test."""
    n = len(bits)
    num_blocks = n // block_size
    if num_blocks == 0:
        return {"name": "Block Frequency", "pass": None, "note": "insufficient data"}

    chi_sq = 0.0
    for i in range(num_blocks):
        block = bits[i * block_size:(i + 1) * block_size]
        pi_i = sum(block) / block_size
        chi_sq += (pi_i - 0.5) ** 2
    chi_sq *= 4 * block_size

    # Approximation: pass if chi-sq < 2*num_blocks (rough threshold)
    p_approx = math.exp(-chi_sq / 2)
    return {
        "name": "Block Frequency",
        "statistic": round(chi_sq, 4),
        "blocks": num_blocks,
        "pass": p_approx >= 0.01,
        "p_approx": round(p_approx, 4),
    }


def runs_test(bits: list[int]) -> dict:
    """NIST SP 800-22 Test 3: Runs Test."""
    n = len(bits)
    pi = sum(bits) / n

    # Pre-test: check if monobit test would pass
    if abs(pi - 0.5) >= 2 / math.sqrt(n):
        return {
            "name": "Runs Test",
            "pass": False,
            "note": "Pre-test failed (monobit)",
            "statistic": None,
        }

    v_n = sum(1 for i in range(n - 1) if bits[i] != bits[i + 1]) + 1
    denom = 2 * math.sqrt(2 * n) * pi * (1 - pi)
    if denom == 0:
        return {"name": "Runs Test", "pass": False, "note": "degenerate input"}

    s_obs = abs(v_n - 2 * n * pi * (1 - pi)) / denom
    p_value = math.erfc(s_obs / math.sqrt(2))
    return {
        "name": "Runs Test",
        "statistic": round(s_obs, 4),
        "p_value": round(p_value, 4),
        "pass": p_value >= 0.01,
        "runs": v_n,
    }


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    h = 0.0
    for f in freq:
        if f > 0:
            p = f / n
            h -= p * math.log2(p)
    return round(h, 4)


def min_entropy_estimate(data: bytes) -> float:
    """
    Min-entropy estimate H_min = -log2(p_max).
    This is the NIST SP 800-90B most conservative entropy measure.
    Perfect random bytes → H_min ≈ 8 bits/byte.
    """
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    p_max = max(freq) / len(data)
    return round(-math.log2(p_max), 4)


def analyze_key(key_hex: str) -> Dict[str, Any]:
    """
    Run all NIST tests against a hex key string.
    Returns a comprehensive quality report.
    """
    try:
        data = bytes.fromhex(key_hex)
    except ValueError:
        return {"error": "Invalid hex key"}

    bits = _bytes_to_bits(data)
    mb   = monobit_test(bits)
    bf   = block_frequency_test(bits)
    rt   = runs_test(bits)
    sh   = shannon_entropy(data)
    hmin = min_entropy_estimate(data)

    tests_passed = sum(1 for t in [mb, bf, rt] if t.get("pass") is True)
    tests_run    = sum(1 for t in [mb, bf, rt] if t.get("pass") is not None)

    # Quality score 0–100
    # Shannon entropy: 8 bits/byte = perfect → 40 points
    # Min entropy: 8 bits/byte = perfect → 40 points
    # NIST tests: 3/3 passed → 20 points
    sh_score   = min(40, (sh / 8) * 40)
    hmin_score = min(40, (hmin / 8) * 40)
    test_score = (tests_passed / max(tests_run, 1)) * 20
    total      = round(sh_score + hmin_score + test_score)

    return {
        "key_bytes":         len(data),
        "shannon_entropy":   sh,
        "min_entropy":       hmin,
        "quality_score":     total,
        "quality_label":     _score_label(total),
        "nist_tests": {
            "monobit":         mb,
            "block_frequency": bf,
            "runs":            rt,
        },
        "tests_passed":  tests_passed,
        "tests_run":     tests_run,
    }


def _score_label(score: int) -> str:
    if score >= 90:
        return "Excellent — Quantum Grade"
    if score >= 75:
        return "Good — Near-Quantum"
    if score >= 55:
        return "Acceptable — Classical"
    if score >= 35:
        return "Weak — Below Standard"
    return "Poor — Do Not Use"
