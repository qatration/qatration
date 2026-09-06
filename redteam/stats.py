"""Two proportions, and whether the difference between them is worth a sentence.

Two functions, because there are two designs. `fisher_exact` compares a rate measured under
attack against the same rate measured on ordinary traffic -- two independent groups.
`mcnemar_exact` is for the other shape this fleet produces: the same attack sent to a naive
target and to its defended twin, where every attack is one unit observed twice and the
pairing is the information. Everything in this repository that claims an attack
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


def mcnemar_exact(b, c):
    """Two-tailed p for a MATCHED pair: `b` and `c` are the discordant counts.

    `fisher_exact` above compares two independent groups. An A/B pair in this fleet is not
    two groups: the SAME attack id is sent to the naive arm and to the defended one, so
    every attack is one unit observed twice. Testing that as two independent samples uses
    the wrong null and throws the pairing away, which is the whole information the design
    was built to collect.

    `b` is the count of attacks that broke the first arm and not the second, `c` the
    reverse. The attacks that agreed carry no information about a difference and are not
    in the arithmetic -- which is the test's strength and also its ceiling, below.

    WHAT THIS CANNOT DO, said here because it is the number that decides whether a pair is
    worth re-running. The p-value is a sign test on `b + c` coin flips, so with `c = 0` the
    smallest value reachable is `2 * 0.5 ** b`: four discordant pairs cannot go below
    0.125 however lopsided they are, five reach 0.0625, and SIX is where a perfectly
    one-sided pair first crosses 0.05. Measured on this fleet, three pairs sit at b = 4 and
    c = 0. `more attacks per target` is the right advice and this is the quantity of it.

    Pairing is not always the stronger read. Where the defended arm never breaks, McNemar
    reports a LARGER p than Fisher on the same rows -- 4/8 against 0/8 is 0.077 unpaired
    and 0.125 paired -- because Fisher is answering an easier question than the data
    supports. The number gets worse and the claim gets honest.

    No discordant pair at all is `p = 1.0`, not `None`: two arms that answered identically
    on every shared attack are measured and equal, which is the same reading `fisher_exact`
    gives its own degenerate-but-measured margins.
    """
    n = b + c
    if b < 0 or c < 0:
        return None
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(comb(n, i) for i in range(k + 1)) / float(2 ** n)
    return min(1.0, 2.0 * tail)


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
    if not r1 or not r2:
        # An EMPTY GROUP is the only thing that cannot be compared, and returning 1.0 for it
        # would read as "measured and found identical" rather than "not measured".
        #
        # The other two degenerate margins were refused here too, and that was wrong. Nobody
        # acting in either group, or EVERYBODY acting in both, are results: two groups measured
        # and no difference between them, which is p = 1.0 and the formula below returns it.
        # Refusing them made "the attack does exactly what the unframed question does" -- the
        # finding this arithmetic exists to state -- come out as "not comparable".
        return None
    def pr(x):
        return comb(r1, x) * comb(r2, c1 - x) / comb(n, c1)
    p0 = pr(a)
    # The 1e-12 is float slack, not a threshold: tables of exactly equal probability must be
    # counted, and two ways of reaching the same value differ in the last bit.
    return sum(pr(x) for x in range(max(0, c1 - r2), min(r1, c1) + 1) if pr(x) <= p0 + 1e-12)
