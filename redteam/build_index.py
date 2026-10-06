"""
Build out/index.html — a single landing dashboard that ties the whole run together:
headline numbers, links to the defense + fleet reports, and a card per target linking
its scorecard. One page to open after a sweep.
"""
import glob, json, os, sys, html, datetime
from target import target_configs
from pathlib import Path
# A NAME IN A LINK IS URL-QUOTED as well as HTML-escaped: `bot#1` linked to `report_bot`.
from urllib.parse import quote as _url_quote
import baseline
from workspace import no_results_note
from workspace import (OUT as WORKSPACE_OUT, results_files, verdict_for, read_artifact,
                       measured)

OUT = Path(WORKSPACE_OUT)
SEV = {"critical": "#b3261e", "high": "#c2410c", "medium": "#9a6700", "none": "#1e6b3a",
       # NOT a severity: the colour for a target nothing was sent to. Grey because every
       # other colour on this page is a result, and this is the absence of one.
       "unknown": "#6b6b6b"}


from workspace import esc as _ws_esc


def esc(s):
    """One implementation, in `workspace`: see the note there. Re-exported so the forty-four
    call sites in this file keep reading the way they did."""
    return _ws_esc(s)


from workspace import BROKE   # one definition of what counts as a breach
from workspace import _rows_with  # and one way to count rows carrying a headline

# Qualifiers this page does not carry, and why. See `workspace.QUALIFIERS`.
#
# `trials` WAS IN HERE, explained as "this page publishes a fleet total rather than a
# per-row count". Every card on the page ends `<model> · N trials · <pct>`, and has for as
# long as the exemption has. A declared exemption is a claim like any other, and the gate
# over this table asks whether a surface carries a qualifier OR explains itself -- never
# whether the explanation is true, so a page could do both and nothing would say so.
QUALIFIERS_NOT_CARRIED = {
    "delivery": "this page links to the scorecard, which carries the note in full; a fleet "
                "index that repeated one run's paragraph would be quoting out of context",
    "arsenal": "the fleet page carries the instrument spread; this one links to it",
    "when": "rows here are dated by the fleet page they link to",
    "inert": "named per target on the scorecard this page links to",
    "not_applicable": "the coverage split is the defence report's panel, linked from here",
    "not_sent": "same panel",
    "run_id": "the fleet page names an unfinished run; this one aggregates it",
}



def load(known=None, unreadable=None, left_out=None):
    """One row per canonical run, with its breach count RECOUNTED from the rows.

    `meta["broke"]` is written at sweep time and never re-derived, so it is a declared count
    in a file that outlives the run: `rejudge --write` re-scores every verdict in the results
    without touching it, a hand edit moves a row without touching it, and the index headline
    goes on reporting what the sweep believed. That is this project's own "a count that is
    declared rather than counted", in the number on the front page, and it disagreed with the
    other two loaders the moment a fixture exercised it.

    The stored value is kept as `broke_at_run` rather than dropped: where the two differ, the
    difference IS the finding — it says the stored verdicts have moved since the sweep — and
    a page that silently replaced one with the other would hide that.
    """
    # A RESULTS FILE WHOSE TARGET HAS NO CONFIG IS NOT A TARGET. `out/` is a directory, so
    # anything that ever ran leaves a file in it — including the deliberately-unreachable
    # fixture the end-to-end suites sweep, and whatever somebody pointed the engine at while
    # debugging. Counted, they inflate the headline: this page published "32 targets" for a
    # fleet of 30, from two artifacts of a target that exists only to be unfindable.
    #
    # Skipped WITH A LINE SAYING SO, not silently. `detector_coverage.py` already reports the
    # same artifacts under "artifacts whose target did not resolve"; the difference was that
    # it said so and this did not, so one tool named the problem while the other published it.
    # THROUGH `workspace.fleet_filter`, WHICH CARRIES THE DEGRADATION RULE THIS LOOP LACKED.
    # The rule is "if NOTHING here belongs to the fleet, this is not the fleet's directory and
    # nothing is filtered", and it exists because the alternative fails silently: in the normal
    # installed case — `qatration run --target-config mybot.yaml`, a config outside the package
    # — every row was an orphan, `rows` came back empty, and `main()` printed "no results in
    # out/ — run a sweep first" and wrote no page at all. `run_all.py` runs the three builders
    # together, so one sweep produced a defense report and a fleet page carrying the finding,
    # beside a landing page saying nothing had been run.
    from workspace import fleet_filter
    # THE CALLER MAY ASK FOR THE FAILURES, the same way `configs_by_name` and
    # `coverage.contexts` hand back their collisions: the page needs to name the files it
    # could not read, and they are discovered here.
    rows, metas = [], []
    unreadable = unreadable if unreadable is not None else []
    for fp in results_files(OUT):
        d, why = read_artifact(fp)
        # An artifact that will not parse is not an empty artifact. Substituting `{}` here and
        # carrying on turned a decode error into a KeyError one line down, which is a different
        # crash rather than a fix; dropping it silently would remove a target from an index
        # that then reads as complete.
        if why:
            unreadable.append((os.path.basename(str(fp)), why))
            continue
        m = dict(d.get("meta") or {})
        # THROUGH THE ONE COUNTER. This loop and `workspace._rows_with` were the same
        # comprehension, and the second counter below is the reason the shared one exists.
        m["_counted"] = _rows_with(d.get("results"), BROKE)
        # AND THE ERRORS, WHICH DECIDE THE OTHER HALF OF THE VERDICT. The docstring above
        # says a stored count outlives the run that wrote it, and that is as true of
        # `errors` as of `broke`: this page recounted one of them and handed the pair to
        # `verdict_for`, where a stale or absent `errors` turns a run that measured nothing
        # into HARDENED. `errors` is absent from 34 of the 45 artifacts stored here.
        # ERRORED AND NEVER SENT APART, the split `measured` reads: the ERROR recount held the
        # budget's rows too, and `measured` subtracted them again from `never_sent` -- 5 of
        # 10 measured read as "not measured, no attacks sent". Found by an independent review.
        from workspace import error_split as _error_split, NOT_MEASURED as _NM_i
        m["_errored"], m["never_sent"] = _error_split(d.get("results"))
        # AND WHETHER ANY ROW ANSWERED, asked of the rows: the counters are absent from files
        # older than them, and those rows answered.
        # NOT A CONTROL: it is no attack, and one DEFENDED control beside five errored attacks
        # made a page whose every card said "not measured" exit 0. Found by a review.
        m["_answered"] = any(isinstance(r, dict) and r.get("headline") not in _NM_i
                             and (r.get("attack") or {}).get("category") != "control"
                             for r in (d.get("results") or []))
        # AND THE MEASURED COUNT FROM THE ROWS, where the file predates `attacks_n`: two
        # breaches on such a file printed a grey "not measured" card under a tile counting
        # them. Found by an independent review.
        from workspace import measured as _measured_i
        m["_measured"] = _measured_i(m, d.get("results"))
        # AND HOW MANY OF THOSE BREACHES THE BENIGN BASELINE CANNOT ATTRIBUTE. This page
        # publishes a fleet total of findings and said nothing about attribution, the same
        # gap `compare_targets` had: one shared reader in `baseline` now, so the index, the
        # fleet page and the scorecard cannot disagree about one artifact.
        m["_doubtful"] = baseline.doubtful_count(m.get("target"), d, out_dir=str(OUT))
        m["_file"] = os.path.basename(str(fp))
        metas.append(m)

    kept, dropped = fleet_filter(metas, known)
    orphans = [(m.get("_file"), m.get("target")) for m in dropped]
    # HANDED BACK, as `unreadable` is: a stranger whose own bot shares a workspace with a
    # bundled config's run lost it from this page with one console line, and the page read
    # as the whole fleet. The page names them now. Found by an independent review.
    if left_out is not None:
        left_out.extend(orphans)
    for m in kept:
        m["broke_at_run"], m["broke"] = m.get("broke"), m.pop("_counted")
        m["errors_at_run"], m["errors"] = m.get("errors"), m.pop("_errored")
        m["doubtful"] = m.pop("_doubtful", 0)
        m.pop("_file", None)
        rows.append(m)
    # UNREADABLE IS NOT ABSENT. A truncated artifact used to take this whole page down;
    # skipping it silently would drop a target from an index that reads as the fleet.
    for _name, _why in unreadable:
        print("  ! %s could not be read (%s). It is not on the index, and nothing "
              "there describes whatever it held." % (_name, _why))
    if orphans:
        print("  ! %d results file(s) skipped: no target config answers to that name, so they "
              "are artifacts of something that no longer exists rather than members of the "
              "fleet." % len(orphans))
        for f, t in orphans:
            print(f"      {f}  (target {t!r})")
    return rows


def provenance():
    """target -> (kind, note). Whose software each deployment actually is.

    A FLEET COUNT THAT DOES NOT SEPARATE THESE IS COUNTING ITS OWN HOMEWORK. Most of
    these targets are bots written here to exercise the engine, and a finding on one of those
    is evidence that the engine works — worth having, and not the same claim as a finding on
    somebody else's code. The rest are third-party: smolagents (two ways), LangChain, NeMo
    Guardrails in four configurations, two cloned practice apps, and endpoints whose wire
    format was not designed here. The counts are computed below rather than written here,
    because a number in a docstring is a claim nothing keeps true. A
    headline of "279 findings across 30 targets" invites a reader to assume the first number
    is about software in the world, and most of it is not.
    """
    # THROUGH THE ONE ENUMERATION. This kept a sixth copy of the loop, and it differed
    # from `configs_by_name` in both directions: it swallowed a config it could not parse
    # -- which drops that target's provenance and so counts it as `unstated` on the page,
    # the under-reporting `fleet_names` was written against -- and it did NOT ask whether
    # what parsed was a mapping, so `c.get("provenance")` on a config reading `- name:
    # listy` was `AttributeError` out of a page builder.
    import os
    from workspace import configs_by_name as _by_name
    here = os.path.dirname(os.path.abspath(__file__))
    return {name: (c.get("provenance") or "unstated", c.get("provenance_note") or "")
            for name, (_fp, c) in _by_name(here).items()}


def caveats():
    """-> {target: what its config says a reader must know before citing its stored results}.

    A CAVEAT THE PAGE CARRIES, because the config is where the person who knows it writes it:
    citebot's stored results were measured before the rule it exists for reached the bot, and
    nothing on any page said so -- its rows sat beside the rest as current measurements.
    """
    import os
    from workspace import configs_by_name as _by_name
    here = os.path.dirname(os.path.abspath(__file__))
    return {name: " ".join(str(c.get("caveat") or "").split())
            for name, (_fp, c) in _by_name(here).items() if str(c.get("caveat") or "").strip()}


def classify(rows):
    """-> (held, never_attacked). Which targets earned a verdict and which were not asked.

    A TARGET THAT WAS NEVER ATTACKED IS NOT A TARGET THAT HELD. The rule used to be `broke == 0`
    inline in `main()`, so a results file recording `attacks_n: 0` — a sweep that sent nothing,
    which is what httpbot's last run was — landed in the green tile beside bots that survived
    fifty attacks, two blocks under the same page reporting httpbot BROKEN by the adaptive
    attacker in one iteration. Zero out of zero is an absence, and an absence painted in the
    colour of the best possible result is the failure this repo is named after.

    A function rather than two comprehensions in `main()` because the suite has to be able to
    call THIS, not a copy of it. The first version of that test recomputed the rule itself and
    stayed green when the bug was put back — the same mistake the roll-up arithmetic in
    `benign.py` was extracted to avoid, repeated one file over.
    """
    held = [m for m in rows if verdict_for(m) == "Hardened"]
    never_attacked = [m for m in rows if verdict_for(m) == "Not measured"]
    return held, never_attacked


from workspace import named_or_more   # noqa: E402  one spelling of `and N more`


def main():
    # PARSED, EVEN THOUGH THERE IS NOTHING TO PARSE. Without this the command answered
    # `--help` by doing its work -- printing the report and writing the page -- and accepted
    # any mistyped flag in silence. A reader who asks what a command does should not have to
    # find out by watching it happen.
    import argparse
    # THE ONE SPELLING, from the table this command is listed in.
    from cli import parser as _cli_parser
    _cli_parser("index").parse_args()
    # The fleet's own configs, passed IN rather than read inside `load()`. The first version
    # looked them up itself and every suite driving this builder over a temp fixture — where
    # the target names are invented — lost all of its rows to the orphan filter.
    _unreadable, _left_out = [], []
    rows = load(known=set(provenance()), unreadable=_unreadable, left_out=_left_out)
    # AND A TARGET SWEPT ONLY WITH `--model` IS NAMED, as `compare_targets` names it: the
    # index reads one canonical run per target and dropped it without a word.
    from workspace import is_per_model_copy as _ipmc
    _have = {m.get("target") for m in rows} | {t for _f, t in _left_out}
    _model_only = sorted({(read_artifact(fp)[0] or {}).get("meta", {}).get("target")
                          for fp in results_files(OUT, include_model_copies=True)
                          if _ipmc(fp) and read_artifact(fp)[1] is None} - _have - {None})
    from workspace import unreadable_html as _unread_html
    unread_bar = _unread_html(_unreadable, "this index")
    if not rows and (_unreadable or _model_only):
        # NOT "RUN A SWEEP FIRST" OVER FILES THAT ARE THERE: every one torn, or only per-model
        # runs, is a different sentence and a different fix. Found by an independent review.
        print("no results this page can read in %s: %s." % (OUT, "; ".join(
            (["%d could not be read (%s)" % (len(_unreadable), _unreadable[0][0])]
             if _unreadable else [])
            + (["%s %s only per-model runs; the index reads one canonical run per target"
                % (", ".join(_model_only), "has" if len(_model_only) == 1 else "have")]
               if _model_only else []))))
        return 3
    if not rows:
        # THE DIRECTORY THIS RUN IS ACTUALLY USING, and the command that fills it. `out/` is
        # what a checkout has; a stranger who installed the package has `qatration-out/`, or
        # whatever `$QATRATION_OUT` says, so this named a folder they do not have and a step
        # in words rather than a command they can type. `compare_targets` prints the real path
        # in the same situation, which is where the wording below comes from.
        print(no_results_note(OUT))
        # NOT A PASS. `docs/ci.md` reserves 3 for "the question could not be
        # answered", and a page built from no runs is the plainest case of it.
        return 3
    # OVER WHAT WAS MEASURED, from the rows: `attacks_n: null` passed the shape check and
    # crashed `max(1, None)` here. Found by an independent review.
    rows.sort(key=lambda m: (-(m.get("broke", 0) / max(1, (m.get("_measured") or (0, 0))[0])),
                             m["target"]))
    n_targets = len(rows)
    n_find = sum(m.get("broke", 0) for m in rows)
    n_doubt = sum(m.get("doubtful", 0) for m in rows)
    hardened, unmeasured = classify(rows)
    prov = provenance()
    _cav = caveats()

    def _cav_html(tgt):
        _c = _cav.get(tgt)
        return ('\n          <div class="cm" style="color:var(--accent)">! %s</div>' % esc(_c)
                if _c else "")
    kinds = {}
    for m in rows:
        # NO CONFIG FOUND IS NOT A CONFIG THAT DECLARES NOTHING. Walked from an install:
        # `init` wrote `provenance: first-party`, $QATRATION_CONFIGS was not set, and the page
        # said the target "states no provenance" -- about a file that states one, which this
        # page never opened. Kept apart so the sentence can say which it is.
        k = prov.get(m["target"], ("no config", ""))[0]
        kinds.setdefault(k, []).append(m["target"])
    n_third = sum(len(v) for k, v in kinds.items() if k.startswith("third-party"))
    n_third_find = sum(m.get("broke", 0) for m in rows
                       if prov.get(m["target"], ("", ""))[0].startswith("third-party"))
    # BY WHAT EACH TARGET SAYS IT IS, not by subtraction. This was `n_targets - n_third`,
    # which filed every target that is not third-party under "bots written here to exercise
    # the engine" -- including `first-party`, the provenance `qatration init` writes, with
    # the note "our own deployment". Walked as a stranger: one target, their own bot, and the
    # page told them every finding on it was "a fact about this engine rather than about
    # software in the world". Their own production bot is the most real software there is
    # on that page. `practice` is the kind the repository's own fleet declares; a target
    # that declares nothing is said to declare nothing.
    n_practice = len(kinds.get("practice", []))
    n_own = len(kinds.get("first-party", []))
    n_noconfig = len(kinds.get("no config", []))
    n_unstated = n_targets - n_third - n_practice - n_own - n_noconfig
    # esc(): a target name reaches this page from a config file, and every page this tool
    # produces is a rendering of attacker-influenced input by construction.
    _third_names = sorted(t for k, v in kinds.items()
                          if k.startswith("third-party") for t in v)
    # A COLON WITH NOTHING AFTER IT. This joined the names and the sentence ended
    # `counting its own homework: .` whenever a fleet had no third-party target in it --
    # which is every fleet an outside user has, since the practice bots are ours. Found by
    # rendering the page twice with opposite findings and reading what stayed identical.
    #
    # The sentence still has to be said when the list is empty, because that is when it
    # applies hardest: a fleet of nothing but our own bots is exactly the fleet whose count
    # is its own homework. So the naming is the part that becomes conditional, not the point.
    third_list = ", ".join(esc(t) for t in _third_names)
    # THE SENTENCE IS BUILT FROM WHAT IS THERE. The homework warning belongs to practice bots
    # and to nothing else: said over a stranger's own deployment it tells them their findings
    # are not about their software, which is the opposite of true.
    _parts = []
    if n_third:
        _parts.append("%d %s somebody else's software and carr%s %d of the findings — %s"
                      % (n_third, "is" if n_third == 1 else "are",
                         "ies" if n_third == 1 else "y", n_third_find, third_list))
    if n_own:
        _parts.append("%d %s your own deployment%s (provenance: first-party), so what is "
                      "found there is about your software"
                      % (n_own, "is" if n_own == 1 else "are", "" if n_own == 1 else "s"))
    if n_practice:
        _parts.append("%d %s practice bot%s written here to exercise the engine — a finding "
                      "on one is evidence the engine works, and a fleet count that does not "
                      "separate those is counting its own homework"
                      % (n_practice, "is a" if n_practice == 1 else "are",
                         "" if n_practice == 1 else "s"))
    if n_unstated:
        _parts.append("%d state%s no provenance, so whose software %s is not on this page"
                      % (n_unstated, "s" if n_unstated == 1 else "",
                         "it is" if n_unstated == 1 else "they are"))
    if n_noconfig:
        _parts.append("%d %s no config this page could read ($QATRATION_CONFIGS does not "
                      "name %s), so what %s declares, whose software %s included, is not "
                      "on this page"
                      % (n_noconfig, "has" if n_noconfig == 1 else "have",
                         "it" if n_noconfig == 1 else "them",
                         "it" if n_noconfig == 1 else "they",
                         "it is" if n_noconfig == 1 else "they are"))
    fleet_said = "Of these, " + "; ".join(_parts) + "." if _parts else ""
    # Where the recount disagrees with what the sweep stored, the difference is a fact about
    # the evidence: the stored verdicts have moved since the run that wrote them, usually
    # because an oracle fix was replayed over them. Said on the page rather than resolved
    # silently in favour of either number.
    moved = [m for m in rows if m.get("broke_at_run") is not None
             and m["broke_at_run"] != m["broke"]]
    adaptive = sorted(glob.glob(str(OUT / "adaptive_*.json")))
    _n_unread_before = len(_unreadable)

    cards = ""
    for m in rows:
        tgt, broke = m["target"], m.get("broke", 0)
        # AGAINST WHAT WAS MEASURED, not against what was attempted — the rule now lives in
        # `workspace.measured`, because this was the only one of four readers that had it.
        atk, errs = m.get("_measured") or measured(m)
        rate = broke / max(1, atk)
        # Grey, and the words rather than the numbers: "0 / 0 breached" reads as a score, and
        # the reader has no way to tell it from a score that was earned.
        # THE CARD'S COLOUR FROM `verdict_for`, the predicate the tiles above use: 1 DEFENDED
        # beside 19 ERROR is "Not measured" there and was a green `0 / 1 breached` here.
        if not atk or verdict_for(m) == "Not measured":
            col, bar = SEV.get("unknown", "#6b6b6b"), 0
            headline = "not measured" if not atk else f"{broke} / {atk} breached, not measured"
        else:
            col = SEV["none"] if broke == 0 else (SEV["critical"] if rate >= .5 else SEV["high"])
            headline = f'<b style="color:{col}">{broke}</b> / {atk} breached'
            bar = 100 * rate
        # NOT "NO ATTACKS SENT" OVER A RUN WHOSE ATTACKS WERE SENT AND ERRORED: the card said
        # both clauses at once. Errored and never-sent are named apart.
        _ns_i = m.get("never_sent") or 0
        pct = ("nothing measured" if not atk else f"{100*rate:.0f}%")
        if errs:
            pct += f" \u00b7 {errs} errored"
        if _ns_i:
            pct += f" \u00b7 {_ns_i} never sent"
        # A RATE FROM ONE TRIAL IS NOT THE SAME KIND OF NUMBER, and this page ranks it
        # beside rates from ten. The scorecard's own footer and the SARIF message both say
        # so in as many words -- `sent ONCE, so this cannot be told from a lucky break` --
        # and the page that sorts them said nothing. `lcagent` sits in that list at
        # `1 trials \u00b7 15%`.
        if (m.get("trials") or 0) == 1 and atk:
            pct += " \u00b7 sent once, so a lucky break reads the same"
        cards += f"""
        <a class="card" href="report_{esc(_url_quote(str(tgt)))}.html">
          <div class="ct"><span class="dot" style="background:{col}"></span>{esc(tgt)}</div>
          <div class="cs" style="color:{col}">{headline}</div>
          <div class="bar"><span style="width:{bar:.0f}%;background:{col}"></span></div>
          <div class="cm">{esc(m.get('model') or 'model not recorded')} · {m.get('trials',1)} trials · {pct}</div>{_cav_html(tgt)}
        </a>"""

    adaptive_html = ""
    _adaptive_measured = False
    if adaptive:
        items = ""
        for fp in adaptive:
            d, why = read_artifact(fp)
            if why:
                # NOT REPORTED BY THE RESULTS LOOP. That loop walks `results_*.json`; this
                # one walks `adaptive_*.json`, so the comment that used to sit here was
                # asserting a coverage that does not exist and a torn adaptive artifact
                # left this section one entry short with nothing saying so anywhere.
                _unreadable.append((os.path.basename(str(fp)), why))
                continue
            # SHAPE FIRST, as `compare_recon.collect` does: `r['iterations']` and
            # `d["target"]` on an artifact of the wrong shape ended the index with no page.
            r = d.get("result") if isinstance(d, dict) else None
            # AND THE FIELDS THE SENTENCE READS: `iterations: "4"` and `attribution: 5` passed
            # the two checks above and took the page down. Found by an independent review.
            _it = r.get("iterations") if isinstance(r, dict) else None
            _at = r.get("attribution") if isinstance(r, dict) else None
            if (not isinstance(r, dict) or not d.get("target")
                    or (_it is not None and (not isinstance(_it, int) or isinstance(_it, bool)))
                    or (_at is not None and not isinstance(_at, (list, tuple)))):
                _unreadable.append((os.path.basename(str(fp)),
                                    "not the shape an adaptive transcript has"))
                continue
            # THE RUN'S OWN SENTENCE, through `run_adaptive.outcome_line`: this section read
            # `success` alone, so a loop that never reached the target was a green "held",
            # `--iters -3` was "held (-3 iters)", and a break the target's own benign traffic
            # explains was an unqualified red BROKEN.
            from run_adaptive import outcome_line as _outcome
            _line, _code = _outcome(r)
            if _code != 3:
                _adaptive_measured = True
            if _code == 3:
                col, verdict = SEV.get("unknown", "#6b6b6b"), "not measured"
            elif r.get("success"):
                _att = (r.get("attribution") or ("",))[0]
                col = SEV["high"] if (_att == "unattributable"
                                      or not r.get("aimed", True)) else SEV["critical"]
                verdict = f"BROKEN in {r.get('iterations')} iters" + (
                    " \u2014 not attributable: the target does this unattacked"
                    if _att == "unattributable" else "") + (
                    # AND WHEN NOTHING WAS THERE TO ATTRIBUTE AGAINST, as `outcome_line` says.
                    " \u2014 no benign baseline, so an ambient false positive is not ruled out"
                    if _att == "unmeasured" else "") + (
                    " \u2014 not the goal it was aimed at" if not r.get("aimed", True) else "")
            else:
                col, verdict = SEV["none"], f"held ({r.get('iterations')} iters)"
            items += (f'<li><span class="dot" style="background:{col}"></span>'
                      f'<b>{esc(d["target"])}</b> — <span style="color:{col}">{esc(verdict)}</span>'
                      f' <span class="cm">attacker: {esc(d.get("attacker",""))}</span></li>')
        adaptive_html = (f'<h2>Adaptive attacker (LLM-in-the-loop)</h2><ul class="adapt">{items}</ul>')
        # SAID ON BOTH SURFACES, and after this loop rather than before it: `unread_bar`
        # was built above, so anything this loop found was collected into a list nothing
        # read again.
        for _an, _aw in _unreadable[_n_unread_before:]:
            print("  ! %s could not be read (%s). It is not on the index, and nothing "
                  "there describes whatever it held." % (_an, _aw))
        unread_bar = _unread_html(_unreadable, "this index")

    # ONLY PAGES THAT EXIST: `run` and `index` alone build neither of these, and both links were
    # dead. Found by an independent review.
    _links = [(_p, _w) for _p, _w in (("defense_report.html", "Defense report (fixes)"),
                                      ("compare_targets.html", "Fleet overview"))
              if (OUT / _p).exists()]
    links_html = ('<div class="links">' + "".join('<a href="%s">→ %s</a>' % _l for _l in _links)
                  + '</div>') if _links else ""
    # AND WHAT IS NOT ON IT, said on the page: results with no config here, and targets swept
    # only per model.
    _absent = (["%d results file(s) whose target has no config here: %s. Point "
                "QATRATION_CONFIGS at its config to put it on this page"
                % (len(_left_out), named_or_more(["%s (%s)" % (t, f) for f, t in _left_out], 4))]
               if _left_out else []) + (
               ["%s swept only with --model, which this page does not read: %s"
                % ("a target" if len(_model_only) == 1 else "%d targets" % len(_model_only),
                   named_or_more(_model_only, 4))] if _model_only else [])
    for _a in _absent:
        print("  ! " + _a)
    unread_bar += "".join('<div class="stalebar">%s.</div>' % esc(_a) for _a in _absent)
    # AND A BREACH ON A TARGET WITH NO BENIGN BASELINE IS NOT ATTRIBUTED, said beside the count:
    # `doubtful` is 0 both for "all attributed" and for "nothing to attribute against".
    _no_bl = [m["target"] for m in rows
              if m.get("broke") and baseline.rates(m["target"], str(OUT)) is None]
    if _no_bl:
        unread_bar += ('<div class="stalebar">%d breach(es) on %s with no benign baseline: '
                       'nothing measured what those targets do unattacked, so they are not '
                       'attributed. Run `qatration benign` against them.</div>'
                       % (sum(m["broke"] for m in rows if m["target"] in _no_bl),
                          esc(named_or_more(_no_bl, 4))))
    # THE RUNS' DATES, not the day the page was built: "Adversarial test of AI features ·
    # 2026-10-01" stood over runs from August and September. Found by an independent review.
    from workspace import measured_when as _mw_i
    _days = sorted(_mw_i(m)[0][:10] for m in rows if _mw_i(m)[1])
    _span = (_days[0] if _days and _days[0] == _days[-1]
             else "%s to %s" % (_days[0], _days[-1]) if _days else "")
    # AND HOW MANY OF THEM SAID: one dated run of thirty-five is not "the runs' date".
    today = ("runs " + _span if _days and len(_days) == len(rows)
             else "%d of %d runs dated, %s" % (len(_days), len(rows), _span) if _days
             else "run dates not recorded, built " + datetime.date.today().isoformat())
    doc = f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>QAtration — Dashboard</title><style>
:root{{--bg:#f6f7f9;--card:#fff;--ink:#14181f;--dim:#5b6472;--line:#e3e7ec;--accent:#b3261e}}
@media(prefers-color-scheme:dark){{:root:not([data-theme=light]){{--bg:#0d1014;--card:#161b22;--ink:#e6edf3;--dim:#8b95a4;--line:#242c37;--accent:#ff5b60}}}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}}
.wrap{{max-width:960px;margin:0 auto;padding:36px 22px 90px}}
h1{{font-size:24px;margin:0 0 2px}} h1 .q{{color:var(--accent)}}
.sub{{color:var(--dim);font-size:13.5px;font-family:ui-monospace,Consolas,monospace;margin-bottom:22px}}
.tiles{{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:14px}}
.tile{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 20px;flex:1;min-width:130px}}
.tile .n{{font-size:28px;font-weight:800;line-height:1}} .tile .l{{color:var(--dim);font-size:12.5px;margin-top:4px}}
.links{{display:flex;gap:12px;margin:6px 0 26px;flex-wrap:wrap}}
.links a{{background:var(--card);border:1px solid var(--line);border-radius:9px;padding:10px 16px;text-decoration:none;color:var(--ink);font-weight:600;font-size:14px}}
.links a:hover{{border-color:var(--accent);color:var(--accent)}}
h2{{font-size:15px;text-transform:uppercase;letter-spacing:.05em;color:var(--dim);margin:26px 0 12px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:12px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:11px;padding:14px 16px;text-decoration:none;color:var(--ink);display:block}}
.card:hover{{border-color:var(--accent)}}
.ct{{font-weight:700;font-family:ui-monospace,Consolas,monospace;font-size:14px;display:flex;align-items:center;gap:7px}}
.dot{{width:9px;height:9px;border-radius:50%;display:inline-block}}
.cs{{font-size:13px;margin:6px 0 8px}}
.bar{{height:7px;border-radius:5px;background:var(--bg);overflow:hidden;border:1px solid var(--line)}}
.bar span{{display:block;height:100%}}
.cm{{color:var(--dim);font-size:11.5px;margin-top:7px;font-family:ui-monospace,Consolas,monospace}}
.adapt{{list-style:none;padding:0;margin:0}} .adapt li{{background:var(--card);border:1px solid var(--line);border-radius:9px;padding:10px 14px;margin-bottom:8px;display:flex;align-items:center;gap:9px}}
</style></head><body><div class="wrap">
<h1><span class="q">QA</span>tration — Dashboard</h1>
<div class="sub">Adversarial test of AI features · {today} · {n_targets} targets</div>
<div class="sub">{fleet_said}</div>
{unread_bar}
<div class="tiles">
  <div class="tile"><div class="n">{n_targets}</div><div class="l">targets tested</div></div>
  <div class="tile"><div class="n">{n_third}</div><div class="l">third-party code</div></div>
  <div class="tile"><div class="n" style="color:var(--accent)">{n_find}</div><div class="l">attacks breached</div>{f'<div class="l" style="color:var(--dim)">{n_doubt} the benign baseline cannot attribute</div>' if n_doubt else ""}</div>
  <div class="tile"><div class="n" style="color:{SEV['none']}">{len(hardened)}</div><div class="l">hardened (0 breaches)</div></div>
</div>
{links_html}
{adaptive_html}
<h2>Targets</h2>
<div class="grid">{cards}</div>
</div></body></html>"""
    out = OUT / "index.html"
    # THROUGH `atomic_write`, whose own docstring lists "every HTML page" among the
    # artifacts an interrupted write must not leave half of. This was `Path.write_text`,
    # which truncates first -- and the gate that converted the other writers looked for
    # `open(path, "w")`, so a different spelling of the same write walked past it.
    from workspace import atomic_write as _atomic
    with _atomic(out) as _f:
        _f.write(doc)
    if unmeasured:
        print("  ! %d target(s) have a results file whose attacks were not measured -- none "
              "sent, or not\n    all of them landed -- so they are shown as not measured "
              "rather than as hardened: %s"
              % (len(unmeasured), ", ".join(m["target"] for m in unmeasured)))
    print(f"wrote {out} — {n_targets} targets, {n_find} breaches, {len(hardened)} hardened, "
          f"{n_third} third-party ({n_third_find} of the findings)")
    if n_noconfig:
        from workspace import point_at_configs as _point_at_configs
        print("  ! no config found for %s, so the page cannot say whose software %s. "
              "Point at yours and build it again:"
              # repr: a target name is read from a results file, and a name carrying
              # terminal escapes would otherwise be printed as escapes.
              % (", ".join(repr(t) for t in sorted(kinds.get("no config", []))),
                 "it is" if n_noconfig == 1 else "they are"))
        for _line in _point_at_configs():
            print(_line)
    if moved:
        print(f"  ! {len(moved)} target(s) whose stored breach count predates a re-score: "
              + named_or_more([f"{m['target']} {m['broke_at_run']}->{m['broke']}"
                               for m in moved], 6))
    # 3 WHEN NOTHING ON THE PAGE WAS MEASURED, the code the table gives "could not be
    # answered"; a fleet whose every run errored exited 0. Found by an independent review.
    # AND NOT WHILE THE PAGE SHOWS AN ADAPTIVE RUN THAT MEASURED: a red BROKEN above an
    # exit 3. Found by an independent review.
    if rows and not any(m.get("_answered") for m in rows) and not _adaptive_measured:
        print("  ! no target on this page measured anything, so the page answers nothing")
        return 3
    from workspace import partial_exit as _pex
    return _pex(0, _unreadable, "this page")


if __name__ == "__main__":
    # The return value is the answer; `main()` alone drops it.
    # THROUGH THE ENGINE'S OWN TRANSLATION, so this file answers a refusal and a crash
    # with the code the table reserves rather than with 1, which is a finding.
    from workspace import run_command as _run_command
    sys.exit(_run_command(main))
