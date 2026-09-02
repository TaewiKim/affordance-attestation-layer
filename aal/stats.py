"""Exact statistical tests (pure Python, no dependencies).

Used to report the guard comparison rigorously rather than with a degenerate bootstrap CI:
 - a zero-failure result is reported as an exact Clopper-Pearson one-sided upper bound on the
   failure probability (not "0 with CI [0,0]");
 - AAL vs each baseline is a paired binary comparison, tested with the exact McNemar test;
 - effect sizes are risk ratios with confidence bounds.
"""
from __future__ import annotations

import math


def clopper_pearson_upper(k: int, n: int, alpha: float = 0.05) -> float:
    """One-sided (1-alpha) upper confidence bound on a binomial probability from k events / n.
    For k=0 this is the exact bound 1 - alpha**(1/n) (rule-of-three is the ~3/n approximation)."""
    if n == 0:
        return 1.0
    if k == 0:
        return 1.0 - alpha ** (1.0 / n)
    if k >= n:
        return 1.0
    # invert the Beta quantile via bisection on the regularized incomplete beta (a=k+1, b=n-k)
    a, b = k + 1, n - k
    lo, hi = 0.0, 1.0
    for _ in range(200):
        mid = (lo + hi) / 2
        # P(X <= k) = I_{1-mid}(n-k, k+1); upper bound solves P(X<=k) = alpha
        if _betainc(a, b, mid) < 1 - alpha:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def rule_of_three(n: int) -> float:
    """~95% upper bound on the rate when 0 events are observed in n trials."""
    return 3.0 / n if n else 1.0


def _betainc(a: float, b: float, x: float) -> float:
    """Regularized incomplete beta I_x(a,b) via continued fraction (Numerical Recipes)."""
    if x <= 0:
        return 0.0
    if x >= 1:
        return 1.0
    bt = math.exp(math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
                  + a * math.log(x) + b * math.log(1 - x))
    if x < (a + 1) / (a + b + 2):
        return bt * _betacf(a, b, x) / a
    return 1.0 - bt * _betacf(b, a, 1 - x) / b


def _betacf(a, b, x, itmax=200, eps=1e-12):
    qab, qap, qam = a + b, a + 1, a - 1
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < 1e-30:
        d = 1e-30
    d = 1.0 / d
    h = d
    for m in range(1, itmax):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < 1e-30:
            d = 1e-30
        c = 1.0 + aa / c
        if abs(c) < 1e-30:
            c = 1e-30
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < 1e-30:
            d = 1e-30
        c = 1.0 + aa / c
        if abs(c) < 1e-30:
            c = 1e-30
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < eps:
            break
    return h


def mcnemar_exact(b: int, c: int) -> float:
    """Exact (binomial) McNemar test p-value for discordant pair counts b, c.
    b = # cases guard-A safe & guard-B unsafe; c = # A unsafe & B safe."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    # two-sided exact binomial p at prob 0.5
    p = 0.0
    for i in range(0, k + 1):
        p += math.comb(n, i) * (0.5 ** n)
    return min(1.0, 2 * p)


def risk_ratio_ci(k1, n1, k2, n2, alpha=0.05):
    """Risk ratio (rate1/rate2) with a log-normal (Katz) CI. Returns (rr, lo, hi)."""
    if n1 == 0 or n2 == 0:
        return None, None, None
    r1, r2 = k1 / n1, k2 / n2
    if r2 == 0:
        return (0.0 if r1 == 0 else math.inf), None, None
    rr = r1 / r2
    if k1 == 0 or k2 == 0:
        return rr, None, None
    se = math.sqrt(1 / k1 - 1 / n1 + 1 / k2 - 1 / n2)
    z = 1.959963984540054
    lo = math.exp(math.log(rr) - z * se)
    hi = math.exp(math.log(rr) + z * se)
    return rr, lo, hi
