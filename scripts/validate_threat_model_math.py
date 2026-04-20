#!/usr/bin/env python3
"""Validate the tables in docs/THREAT_MODEL_TRIANGULATION.md against
Python's stdlib (reference implementation). Keeps the docs honest.

Run: `python3 scripts/validate_threat_model_math.py`

Exit code 0 if every claim matches to 4 decimal places; non-zero
otherwise, printing the first mismatch.
"""

from __future__ import annotations

import sys
from itertools import combinations
from math import comb, isclose

from threat_model_priors import SUBSYSTEM_PRIORS, p_vector


def binom_ge(n: int, p: float, k: int) -> float:
    """P(X >= k) for X ~ Binomial(n, p)."""
    return sum(comb(n, i) * p**i * (1 - p) ** (n - i) for i in range(k, n + 1))


def poisson_binom_dist(ps: tuple[float, ...]) -> list[float]:
    """Return [P(X=0), P(X=1), ..., P(X=n)] for Poisson-Binomial(ps)."""
    n = len(ps)
    out = [0.0] * (n + 1)
    for r in range(n + 1):
        for S in combinations(range(n), r):
            prod = 1.0
            for i in range(n):
                prod *= ps[i] if i in S else 1 - ps[i]
            out[r] += prod
    return out


def poisson_binom_ge(ps: tuple[float, ...], k: int) -> float:
    return sum(poisson_binom_dist(ps)[k:])


def check(name: str, actual: float, expected: float, tol: float = 1e-4) -> bool:
    ok = isclose(actual, expected, abs_tol=tol)
    mark = "OK  " if ok else "FAIL"
    print(f"  [{mark}] {name}: actual={actual:.6f} expected={expected:.6f}")
    return ok


def main() -> int:
    all_ok = True

    print("§2 Uniform Binomial(5, p)")
    # (p, P>=2, P>=3, P>=4) from the doc
    table = [
        (0.05, 0.0226, 0.0012, 0.00003),
        (0.10, 0.0815, 0.0086, 0.0005),
        (0.15, 0.1648, 0.0266, 0.0022),
        (0.20, 0.2627, 0.0579, 0.0067),
        (0.30, 0.4718, 0.1631, 0.0308),
        (0.50, 0.8125, 0.5000, 0.1875),
    ]
    for p, ge2, ge3, ge4 in table:
        all_ok &= check(f"Bin(5,{p}) P>=2", binom_ge(5, p, 2), ge2)
        all_ok &= check(f"Bin(5,{p}) P>=3", binom_ge(5, p, 3), ge3)
        all_ok &= check(f"Bin(5,{p}) P>=4", binom_ge(5, p, 4), ge4)

    print("\n§3 Poisson-Binomial with realistic p_i")
    ps = p_vector()
    expected_canonical = (0.05, 0.10, 0.15, 0.20, 0.30)
    if ps != expected_canonical:
        print(
            f"  [FAIL] priors module drifted from doc canonical vector "
            f"{expected_canonical}: got {ps}. "
            f"Update docs/THREAT_MODEL_TRIANGULATION.md §3 to match the "
            f"new SUBSYSTEM_PRIORS, or revert the prior change."
        )
        all_ok = False
    print(f"  priors: {[(s.name, s.p) for s in SUBSYSTEM_PRIORS]}")
    dist = poisson_binom_dist(ps)
    all_ok &= check("PB P(X=0)", dist[0], 0.4070)
    all_ok &= check("PB P(X=1)", dist[1], 0.4146)
    all_ok &= check("PB P(X=2)", dist[2], 0.1517)
    all_ok &= check("PB P(X=3)", dist[3], 0.0249)
    all_ok &= check("PB P(X=4)", dist[4], 0.0018)
    all_ok &= check("PB P(X=5)", dist[5], 0.000045, tol=5e-6)
    all_ok &= check("PB sum=1", sum(dist), 1.0, tol=1e-9)
    all_ok &= check("PB P(X>=2)", poisson_binom_ge(ps, 2), 0.1784)
    all_ok &= check("PB P(X>=3)", poisson_binom_ge(ps, 3), 0.0267)
    all_ok &= check("PB P(X>=4)", poisson_binom_ge(ps, 4), 0.0018)

    print("\n§4 Adding 6th subsystem (realistic ps + p_6)")
    expected = {
        0.05: {2: 0.1991, 3: 0.0343, 4: 0.0031},
        0.10: {2: 0.2199, 3: 0.0419, 4: 0.0043},
        0.15: {2: 0.2406, 3: 0.0495, 4: 0.0056},
    }
    for p6, by_k in expected.items():
        for k, exp in by_k.items():
            actual = poisson_binom_ge((*ps, p6), k)
            all_ok &= check(f"PB(6) p_6={p6} k={k}", actual, exp)

    print("\n§(boundary) straddle probability (P3 sanitization doc)")
    # P_straddle = (k-1) / (L - k + 1); for k=30, L=200 KiB = 204,800
    k_pat, L = 30, 200 * 1024
    p_straddle = (k_pat - 1) / (L - k_pat + 1)
    all_ok &= check("P_straddle(k=30, L=200KiB)", p_straddle, 0.0001417, tol=5e-7)

    print()
    if all_ok:
        print("All claims in docs/THREAT_MODEL_TRIANGULATION.md and")
        print("docs/THREAT_MODEL_SANITIZATION.md verify to 4 decimal places.")
        return 0
    print("One or more mismatches — update the doc or the checker.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
