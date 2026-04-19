#!/usr/bin/env python3
"""Independent verification using SymPy's exact-rational arithmetic.

SymPy computes Binomial and Poisson-Binomial probabilities with symbolic
rationals, never going through IEEE-754 float. If SymPy agrees with the
stdlib validator in `validate_threat_model_math.py`, we have two
independent implementations confirming the same answers.

Requires SymPy. If not installed, exits cleanly with a note.
"""

from __future__ import annotations

import sys

try:
    from sympy import Rational, binomial, prod
except ImportError:
    print("SymPy not installed — skipping independent validation.")
    print("To enable: pip install sympy")
    sys.exit(0)


def bin_ge_exact(n: int, p: Rational, k: int) -> Rational:
    total = Rational(0)
    for i in range(k, n + 1):
        total += binomial(n, i) * p**i * (1 - p) ** (n - i)
    return total


def pb_ge_exact(ps: list[Rational], k: int) -> Rational:
    from itertools import combinations

    n = len(ps)
    total = Rational(0)
    for r in range(k, n + 1):
        for S in combinations(range(n), r):
            term = prod(ps[i] if i in S else 1 - ps[i] for i in range(n))
            total += term
    return total


def main() -> int:
    print("=== Exact rational verification (SymPy) ===\n")

    print("Binomial(5, p) — P(X >= 2) and P(X >= 3) as exact fractions:")
    for p_dec in (Rational(1, 20), Rational(1, 10), Rational(3, 20),
                  Rational(1, 5), Rational(3, 10), Rational(1, 2)):
        g2 = bin_ge_exact(5, p_dec, 2)
        g3 = bin_ge_exact(5, p_dec, 3)
        print(f"  p={float(p_dec):.2f}  P>=2 = {g2} ≈ {float(g2):.6f}   "
              f"P>=3 = {g3} ≈ {float(g3):.6f}")

    print("\nPoisson-Binomial with realistic p_i:")
    ps = [Rational(5, 100), Rational(10, 100), Rational(15, 100),
          Rational(20, 100), Rational(30, 100)]
    for k in (2, 3, 4):
        v = pb_ge_exact(ps, k)
        print(f"  P(X >= {k}) = {v} ≈ {float(v):.6f}")

    print("\nAdding 6th subsystem, realistic p_i + p_6:")
    for p6_num, p6_label in [(5, "0.05"), (10, "0.10"), (15, "0.15")]:
        ps6 = ps + [Rational(p6_num, 100)]
        for k in (2, 3, 4):
            v = pb_ge_exact(ps6, k)
            print(f"  p_6={p6_label}, k={k}: ≈ {float(v):.6f}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
