"""Two proportions, and whether the difference between them is worth a sentence.

One function, because one comparison keeps coming up: a rate measured under attack against the
same rate measured on ordinary traffic. Everything in this repository that claims an attack
"raises" or "lowers" anything is that comparison, and until now the arithmetic behind such a
claim lived wherever the claim was written.

FISHER RATHER THAN A CHI-SQUARE, because the counts are small and stay small. A sweep is a few
hundred probes and a benign corpus is fifty, and the interesting cells are routinely under ten
-- twenty-one leaks out of twenty-seven retrievals is a typical row here. The exact test is
defined at those sizes; the approximation is not, and its failure mode is a confident p-value.

NOT SHARED WITH `test_benchmark.py`, ON PURPOSE. That suite recomputes the published page's
p-values from raw rows with its own copy of this arithmetic, and the point of it is being
INDEPENDENT: if the page and its check were both derived from this module, a defect here would
move them together and the check would agree with the mistake. Two implementations of one rule
is normally the thing to delete; a verifier that shares its subject's code is worse.
"""
from math import comb


def fisher_exact(a, b, c, d):
    """Two-tailed p for the 2x2 [[a, b], [c, d]]. Rows are the two groups being compared.

    `a` of `a + b` in one group and `c` of `c + d` in the other: p is the chance of a table
    at least this lopsided if the two groups behave identically.

    Two-tailed, deliberately. A one-tailed test halves the p-value by assuming the direction of
    the effect before looking, and the direction is exactly what is in question when asking
    whether an attack adds anything -- more than one measurement here has come back pointing
    the other way.
    """
    n, r1, r2, c1 = a + b + c + d, a + b, c + d, a + c
    if not r1 or not r2 or not c1 or c1 == n:
        # A margin of zero means one of the two groups is empty, or nobody in either group had
        # the outcome. There is no comparison to make, and returning 1.0 would read as "measured
        # and found identical" rather than "not measured".
        return None
    def pr(x):
        return comb(r1, x) * comb(r2, c1 - x) / comb(n, c1)
    p0 = pr(a)
    # The 1e-12 is float slack, not a threshold: tables of exactly equal probability must be
    # counted, and two ways of reaching the same value differ in the last bit.
    return sum(pr(x) for x in range(max(0, c1 - r2), min(r1, c1) + 1) if pr(x) <= p0 + 1e-12)
