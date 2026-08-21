"""
Build out/index.html — a single landing dashboard that ties the whole run together:
headline numbers, links to the defense + fleet reports, and a card per target linking
its scorecard. One page to open after a sweep.
"""
import glob, json, os, html, datetime
from target import target_configs
from pathlib import Path
from workspace import OUT as WORKSPACE_OUT, results_files, verdict_for, read_artifact

OUT = Path(WORKSPACE_OUT)
SEV = {"critical": "#b3261e", "high": "#c2410c", "medium": "#9a6700", "none": "#1e6b3a",
       # NOT a severity: the colour for a target nothing was sent to. Grey because every
       # other colour on this page is a result, and this is the absence of one.
       "unknown": "#6b6b6b"}


def esc(s):
    return html.escape(str(s))


BROKE = ("EXPLOITED", "PARTIAL")


def load(known=None):
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
    known = set(known or ())
    rows, orphans, unreadable = [], [], []
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
        if known and m.get("target") not in known:
            orphans.append((os.path.basename(str(fp)), m.get("target")))
            continue
        counted = sum(1 for r in d.get("results", [])
                      if r.get("headline") in BROKE
                      and (r.get("attack") or {}).get("category") != "control")
        m["broke_at_run"], m["broke"] = m.get("broke"), counted
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
    headline of "197 findings across 30 targets" invites a reader to assume the first number
    is about software in the world, and most of it is not.
    """
    import glob, yaml, os
    here = os.path.dirname(os.path.abspath(__file__))
    out = {}
    for fp in target_configs(here):
        try:
            c = yaml.safe_load(open(fp, encoding="utf-8")) or {}
        except Exception:
            continue
        name = c.get("name") or os.path.basename(fp)[len("targets_"):-len(".yaml")]
        out.setdefault(name, (c.get("provenance") or "unstated",
                              c.get("provenance_note") or ""))
    return out


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


def main():
    # The fleet's own configs, passed IN rather than read inside `load()`. The first version
    # looked them up itself and every suite driving this builder over a temp fixture — where
    # the target names are invented — lost all of its rows to the orphan filter.
    rows = load(known=set(provenance()))
    if not rows:
        print("no results in out/ — run a sweep first"); return
    rows.sort(key=lambda m: (-(m.get("broke", 0) / max(1, m.get("attacks_n", 1))), m["target"]))
    n_targets = len(rows)
    n_find = sum(m.get("broke", 0) for m in rows)
    hardened, unmeasured = classify(rows)
    prov = provenance()
    kinds = {}
    for m in rows:
        k = prov.get(m["target"], ("unstated", ""))[0]
        kinds.setdefault(k, []).append(m["target"])
    n_third = sum(len(v) for k, v in kinds.items() if k.startswith("third-party"))
    n_third_find = sum(m.get("broke", 0) for m in rows
                       if prov.get(m["target"], ("", ""))[0].startswith("third-party"))
    n_practice = n_targets - n_third
    # esc(): a target name reaches this page from a config file, and every page this tool
    # produces is a rendering of attacker-influenced input by construction.
    third_list = ", ".join(esc(t) for t in sorted(t for k, v in kinds.items()
                                                  if k.startswith("third-party") for t in v))
    # Where the recount disagrees with what the sweep stored, the difference is a fact about
    # the evidence: the stored verdicts have moved since the run that wrote them, usually
    # because an oracle fix was replayed over them. Said on the page rather than resolved
    # silently in favour of either number.
    moved = [m for m in rows if m.get("broke_at_run") is not None
             and m["broke_at_run"] != m["broke"]]
    adaptive = sorted(glob.glob(str(OUT / "adaptive_*.json")))

    cards = ""
    for m in rows:
        tgt, atk, broke = m["target"], m.get("attacks_n", 0), m.get("broke", 0)
        rate = broke / max(1, atk)
        # Grey, and the words rather than the numbers: "0 / 0 breached" reads as a score, and
        # the reader has no way to tell it from a score that was earned.
        if not atk:
            col, headline, bar = SEV.get("unknown", "#6b6b6b"), "not measured", 0
        else:
            col = SEV["none"] if broke == 0 else (SEV["critical"] if rate >= .5 else SEV["high"])
            headline = f'<b style="color:{col}">{broke}</b> / {atk} breached'
            bar = 100 * rate
        pct = "no attacks sent" if not atk else f"{100*rate:.0f}%"
        cards += f"""
        <a class="card" href="report_{esc(tgt)}.html">
          <div class="ct"><span class="dot" style="background:{col}"></span>{esc(tgt)}</div>
          <div class="cs" style="color:{col}">{headline}</div>
          <div class="bar"><span style="width:{bar:.0f}%;background:{col}"></span></div>
          <div class="cm">{esc(m.get('model') or 'hosted')} · {m.get('trials',1)} trials · {pct}</div>
        </a>"""

    adaptive_html = ""
    if adaptive:
        items = ""
        for fp in adaptive:
            d, why = read_artifact(fp)
            if why:
                continue                       # reported by the results loop above
            r = d.get("result") or {}
            ok = r.get("success")
            col = SEV["critical"] if ok else SEV["none"]
            verdict = (f"BROKEN in {r['iterations']} iters" if ok
                       else f"held ({r['iterations']} iters)")
            items += (f'<li><span class="dot" style="background:{col}"></span>'
                      f'<b>{esc(d["target"])}</b> — <span style="color:{col}">{verdict}</span>'
                      f' <span class="cm">attacker: {esc(d.get("attacker",""))}</span></li>')
        adaptive_html = (f'<h2>Adaptive attacker (LLM-in-the-loop)</h2><ul class="adapt">{items}</ul>')

    today = datetime.date.today().isoformat()
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
<div class="sub">{n_third} of them are somebody else's software and carry {n_third_find} of the
findings; the other {n_practice} are bots written here to exercise the engine. A fleet count
that does not separate those is counting its own homework: {third_list}.</div>
<div class="tiles">
  <div class="tile"><div class="n">{n_targets}</div><div class="l">targets tested</div></div>
  <div class="tile"><div class="n">{n_third}</div><div class="l">third-party code</div></div>
  <div class="tile"><div class="n" style="color:var(--accent)">{n_find}</div><div class="l">attacks breached</div></div>
  <div class="tile"><div class="n" style="color:{SEV['none']}">{len(hardened)}</div><div class="l">hardened (0 breaches)</div></div>
</div>
<div class="links">
  <a href="defense_report.html">→ Defense report (fixes)</a>
  <a href="compare_targets.html">→ Fleet overview</a>
</div>
{adaptive_html}
<h2>Targets</h2>
<div class="grid">{cards}</div>
</div></body></html>"""
    out = OUT / "index.html"
    out.write_text(doc, encoding="utf-8")
    if unmeasured:
        print("  ! %d target(s) have a results file that sent NO attacks, so they are shown as "
              "not measured\n    rather than as hardened: %s"
              % (len(unmeasured), ", ".join(m["target"] for m in unmeasured)))
    print(f"wrote {out} — {n_targets} targets, {n_find} breaches, {len(hardened)} hardened, "
          f"{n_third} third-party ({n_third_find} of the findings)")
    if moved:
        print(f"  ! {len(moved)} target(s) whose stored breach count predates a re-score: "
              + ", ".join(f"{m['target']} {m['broke_at_run']}->{m['broke']}" for m in moved[:6]))


if __name__ == "__main__":
    main()
