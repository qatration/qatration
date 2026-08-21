"""
Cross-target overview — the discrimination story in one page: which systems are
exploitable and which are hardened, across the same arsenal. Reads every
out/results_<target>.json (skips per-model copies) -> out/compare_targets.html.
"""
import json, glob, os, html, datetime, yaml
from pathlib import Path
from workspace import (OUT as WORKSPACE_OUT, results_files, verdict_for,
                       fleet_names, fleet_filter)

OUT_DIR = Path(WORKSPACE_OUT)

SEVERITY = {  # detector -> severity, to compute a target's worst finding
    "command_injection": "critical", "ssrf_call": "critical",
    "destructive_tool_call": "critical", "canary_in_output": "critical",
    "rogue_tool_call": "high", "canary_in_context": "high", "exfil_via_url": "high",
    "sysprompt_leak": "medium",
}
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, None: 3}
SEV = {"critical": "#b3261e", "high": "#c2410c", "medium": "#9a6700", None: "#1e9d63"}
# Grey for the third verdict, because it is not a result: a run that sent no attacks
# measured nothing, and it used to be coloured as the best possible outcome.
VERDICT_C = {"Vulnerable": "#b3261e", "Hardened": "#1e9d63", "Not measured": "#6b6b6b"}


def esc(s):
    return html.escape(str(s))


def _declared_pairs():
    """Pairs a config declares with `compare_with:`, plus the `<x>-naive` convention.

    The suffix rule was never enough: it can only express "this is the unguarded twin", and
    the sharpest A/B in the fleet is not that shape at all. rangebot and rangebot-sources
    differ by whether the APPLICATION pastes raw tool output under the answer, and the
    second one is the worse of the two — so nothing about the naming said they belong
    together, and the strongest measurement here was missing from the page entirely.
    A declared relationship also carries WHAT changed, which a suffix cannot.
    """
    # `target_configs`, not a raw glob — the thirteenth call site. A temporary e2e config
    # left in this directory by a suite that is still running would enter the A/B pairing.
    from target import target_configs as _tc
    pairs = {}
    for fp in _tc(os.path.dirname(os.path.abspath(__file__))):
        cfg = yaml.safe_load(open(fp, encoding="utf-8")) or {}
        name = cfg.get("name") or os.path.basename(fp)[len("targets_"):-len(".yaml")]
        if cfg.get("compare_with"):
            pairs[name] = (cfg["compare_with"], cfg.get("compare_label")
                           or f"{name} vs {cfg['compare_with']}")
    return pairs


def pair_diffs(matrix):
    """For every declared or `-naive` pair, the attacks where the two disagree.

    A summary count across the whole arsenal is the wrong instrument for "what does the
    guard buy you", and it actively misleads: mcpagent's guarded build scored WORSE than its
    naive one (5/9 vs 4/9) while in fact defending the exact attack it exists to defend. The
    guard strips poison from tool descriptions, so the two builds differ in the context the
    model sees, and attacks with nothing to do with poisoning drift in both directions and
    swamp the one row that matters. Only the per-attack diff shows which is which.
    """
    by_name = {m["target"]: d for m, d in matrix}
    declared = _declared_pairs()
    out = []
    for name in sorted(by_name):
        if name in declared:
            base, label = declared[name]
        elif name.endswith("-naive"):
            base, label = name[:-len("-naive")], f"{name[:-len('-naive')]} — what the control buys"
        else:
            continue
        if base not in by_name:
            continue
        guarded, naive = by_name[base], by_name[name]
        diffs, unpaired = [], []
        for aid in sorted(set(guarded) | set(naive)):
            g, n = guarded.get(aid), naive.get(aid)
            if not g or not n:
                # ONE SIDE ONLY, so there is nothing to compare and the attack is not
                # evidence about the control either way. It used to `continue` here with the
                # other two conditions, which drops it out of a comparison whose entire claim
                # is "this is what the guard buys" — a subset presented as the whole. Two
                # sweeps of a pair made with different arsenals is exactly the case the
                # history diff already grew a confound machinery for, and the same silence
                # here would narrow the comparison without narrowing the sentence about it.
                unpaired.append((aid, "guarded" if g else name))
                continue
            if g[0] == n[0]:
                continue
            gb = g[0] in ("EXPLOITED", "PARTIAL")
            nb = n[0] in ("EXPLOITED", "PARTIAL")
            if gb == nb:
                continue
            diffs.append({"attack": aid, "guarded": g[0], "naive": n[0],
                          "fired": ", ".join(n[1] if nb else g[1]) or "-",
                          # the only direction that is evidence FOR the control
                          "guard_helped": nb and not gb})
        # A declared pair with no diffs is not nothing to report — it is the finding that
        # the change bought nothing, and dropping it hides exactly the result the pair was
        # declared to measure. Measured on foreign / foreign-code: once the deployment
        # logged what its tools actually RECEIVED, both builds landed on the same 8 of 12
        # and the code agent stopped looking safer than the tool-calling one. Silence here
        # would have left "the reasoning format changes nothing" invisible, which is the
        # same way the strongest measurement of the day went missing once already.
        shared = sorted(set(guarded) & set(naive))
        if diffs or name in declared:
            out.append({"base": base, "naive": name, "label": label, "diffs": diffs,
                        "identical": len(shared) if not diffs else 0,
                        "shared": len(shared), "unpaired": unpaired})
    return out


def movement():
    """target -> what changed since the run before this one.

    A matrix of current verdicts answers "what is broken". It cannot answer the question a
    matters on the second run — did anything move — and that data now exists in
    out/history and was stopping at a console. A regression is kept separate from a new
    finding because a fix that did not hold is the worse of the two, and merging them hides
    it.
    """
    try:
        from history import diff
    except Exception:
        return {}
    out = {}
    for fp in glob.glob(str(OUT_DIR / "history" / "*.jsonl")):
        t = os.path.basename(fp)[:-len(".jsonl")]
        d = diff(t)
        if "reason" not in d:
            out[t] = d
    return out


def benign_noise():
    """target -> (clean, probes) from the stored benign runs.

    "22 of 24 systems vulnerable" invites exactly one question from anyone deciding whether
    to switch this on, and the answer existed only in a JSON file and a console: how much of
    that is noise. A breach count with no noise count beside it is the half of the story
    every scanner tells.

    The corpus is clean by construction — no attacker, nothing asking a target to
    misbehave — so it is the same arsenal's oracle judging traffic that should produce
    nothing, on the same target, the same day.
    """
    out = {}
    for fp in glob.glob(str(OUT_DIR / "benign_*.json")):
        try:
            m = json.load(open(fp, encoding="utf-8"))["meta"]
            out[m["target"]] = (m.get("clean", 0), m.get("probes", 0))
        except Exception:
            continue
    return out


def main():
    # ARGPARSE FOR ONE REASON: `--help` must not touch the filesystem. Without it this command
    # ignored its arguments entirely and went straight to building a report, so `qatration
    # compare --help` crashed on a missing output directory — found by installing the package
    # into a clean venv and running every subcommand as somebody who had just found the
    # project. A program that cannot describe itself has not been run by a stranger.
    import argparse
    ap = argparse.ArgumentParser(
        description="One page across every target that has stored evidence: which systems "
                    "broke, on which attacks, and how the same arsenal fared on each.")
    ap.add_argument("--out", default=None,
                    help="where to write the page (default: the workspace artifact directory)")
    args = ap.parse_args()

    global OUT_DIR
    if args.out:
        OUT_DIR = Path(args.out)

    rows, all_attacks_order, seen = [], [], set()
    matrix = []   # (meta, {attack_id: (headline, fired)})
    # A results file whose target has no config is not a system that was tested. `out/` keeps
    # whatever ever ran, so this page counted "32 systems" for a fleet of 30. `fleet_filter`
    # identifies the directory by its contents rather than its path: where nothing resolves,
    # this is a fixture's fleet and nothing is dropped.
    _all_metas = []
    for fp in results_files(OUT_DIR):
        try:
            _all_metas.append(json.load(open(fp, encoding="utf-8"))["meta"])
        except Exception:
            pass
    if not _all_metas:
        print("no results in %s — run a sweep first, then this page has something to compare."
              % OUT_DIR)
        return 0
    _keep, _ = fleet_filter(_all_metas, fleet_names())
    _keep_names = {(m or {}).get("target") for m in _keep}
    for fp in results_files(OUT_DIR):
        d = json.load(open(fp, encoding="utf-8"))
        meta = d["meta"]
        if meta.get("target") not in _keep_names:
            continue
        by_id, worst = {}, None
        for r in d["results"]:
            aid = r["attack"]["id"]
            by_id[aid] = (r["headline"], r["fired"])
            if aid not in seen:
                seen.add(aid); all_attacks_order.append(aid)
            if r["headline"] in ("EXPLOITED", "PARTIAL") and r["attack"].get("category") != "control":
                for det in r["fired"]:
                    s = SEVERITY.get(det)
                    if s and SEV_RANK[s] < SEV_RANK[worst]:
                        worst = s
        broke = meta.get("broke", 0)
        # a matrix mixing today's numbers with last week's reads as one snapshot, which is
        # how a stale row gets cited as current. The age travels with the row.
        measured = datetime.datetime.fromtimestamp(
            os.path.getmtime(fp)).strftime("%Y-%m-%d %H:%M")
        rows.append(dict(measured=measured,
                         target=meta["target"], caps=meta.get("caps") or [],
                         model=meta.get("model", ""), attacks_n=meta.get("attacks_n", 0),
                         broke=broke, worst=worst,
                         # `verdict_for`, not `broke > 0`: this column called httpbot
                         # Hardened off a run that sent zero attacks, while the index page —
                         # fixed first — called the same run not measured. A shared judgement
                         # copied rather than called agrees until one copy moves.
                         verdict=verdict_for(meta)))
        matrix.append((meta, by_id))

    noise = benign_noise()
    moved = movement()
    for r in rows:
        r["benign"] = noise.get(r["target"])
        r["moved"] = moved.get(r["target"])
    rows.sort(key=lambda r: (-r["broke"], SEV_RANK[r["worst"]]))
    n_vuln = sum(1 for r in rows if r["verdict"] == "Vulnerable")

    def caps_label(caps):
        if not caps:
            return "black box"
        m = {"tool_visibility": "tools", "seed": "data", "chain": "multi-turn"}
        return ", ".join(m.get(c, c) for c in caps)

    tbody = ""
    for r in rows:
        vc = VERDICT_C[r["verdict"]]
        worst_html = (f'<span class="sevdot" style="background:{SEV[r["worst"]]}"></span>{r["worst"]}'
                      if r["worst"] else "<span class='dim'>—</span>")
        # Not measured is not the same as measured clean. A blank cell that reads as zero
        # is how a gap turns into a claim, so an unmeasured target says so on hover.
        if r["benign"]:
            c, n = r["benign"]
            benign_html = (f'<span style="color:var(--ok)">{c}/{n}</span>' if c == n
                           else f'<span style="color:#c2410c">{c}/{n}</span>')
        else:
            benign_html = ("<span class='dim' title='no benign run for this target'>"
                           "not measured</span>")
        # Movement, and "one run" said out loud rather than left blank — a single sweep is
        # a snapshot, and an empty cell there would read as "nothing changed".
        m = r["moved"]
        if not m:
            move_html = "<span class='dim' title='only one run recorded'>first run</span>"
        else:
            parts = []
            if m["regressed"]:
                parts.append(f"<span style='color:#b3261e;font-weight:700'>"
                             f"{len(m['regressed'])} returned</span>")
            if m["new"]:
                parts.append(f"<span style='color:var(--accent)'>+{len(m['new'])}</span>")
            if m["fixed"]:
                parts.append(f"<span style='color:var(--ok)'>-{len(m['fixed'])}</span>")
            if m["not_run"]:
                parts.append(f"<span class='dim' title='was broken, this run did not "
                             f"re-test it'>{len(m['not_run'])} untested</span>")
            move_html = " ".join(parts) or "<span class='dim'>no change</span>"
        tbody += f"""<tr>
          <td class="tname">{esc(r['target'])}<div class="dim when">{esc(r['measured'])}</div></td>
          <td class="dim">{esc(caps_label(r['caps']))}</td>
          <td class="num">{r['attacks_n']}</td>
          <td class="num" style="color:{'var(--accent)' if r['broke'] else 'var(--dim)'};font-weight:700">{r['broke']}</td>
          <td class="num">{benign_html}</td>
          <td class="num">{move_html}</td>
          <td class="worst">{worst_html}</td>
          <td><span class="verdict" style="color:{vc};border-color:{vc}">{r['verdict']}</span></td>
        </tr>"""

    # compact full matrix (scrollable), for the detail-minded
    mcols = "".join(f"<th>{esc(m['target'])}</th>" for m, _ in matrix)
    mrows = ""
    for aid in all_attacks_order:
        cells = ""
        for _, by_id in matrix:
            hit = by_id.get(aid)
            if hit is None:
                cells += '<td class="na">·</td>'
            else:
                head = hit[0]
                col = {"EXPLOITED": "var(--accent)", "PARTIAL": "#c2410c"}.get(head, "var(--ok)")
                mark = {"EXPLOITED": "●", "PARTIAL": "◐", "DEFENDED": "○", "SKIP": "·", "ERROR": "!"}.get(head, "·")
                cells += f'<td style="color:{col}" title="{head}">{mark}</td>'
        mrows += f'<tr><td class="mono aid">{esc(aid)}</td>{cells}</tr>'

    pairs = pair_diffs(matrix)
    pair_html = ""
    for p_ in pairs:
        helped = sum(1 for d in p_["diffs"] if d["guard_helped"])
        drifted = len(p_["diffs"]) - helped
        rws = "".join(
            f'<tr><td class="mono aid">{esc(d["attack"])}</td>'
            f'<td style="color:{"var(--accent)" if d["naive"] in ("EXPLOITED", "PARTIAL") else "var(--dim)"}">{esc(d["naive"])}</td>'
            f'<td style="color:{"var(--accent)" if d["guarded"] in ("EXPLOITED", "PARTIAL") else "var(--dim)"}">{esc(d["guarded"])}</td>'
            f'<td class="dim">{esc(d["fired"])}</td>'
            f'<td>{"the control held" if d["guard_helped"] else "drift, not the control"}</td></tr>'
            for d in p_["diffs"])
        pair_html += f'<h3>{esc(p_.get("label") or p_["base"])}</h3>'
        # An attack only one build was run against is not evidence about the control, and
        # dropping it silently narrows a comparison without narrowing the sentence about it.
        if p_.get("unpaired"):
            ids = ", ".join(f"{a} ({side})" for a, side in p_["unpaired"][:6])
            more = "" if len(p_["unpaired"]) <= 6 else f" … and {len(p_['unpaired']) - 6} more"
            pair_html += (
                f'<p class="dim pn"><b>Read over {p_.get("shared", 0)} shared attack(s).</b> '
                f'{len(p_["unpaired"])} attack(s) were run against one build only and are not '
                f'in this comparison — they say nothing about the control either way: '
                f'{esc(ids)}{esc(more)}. Re-run both builds with one arsenal before reading '
                f'the counts below as a before-and-after.</p>')
        if not p_["diffs"]:
            # "no difference" is a result, and it is the one this pair was declared to find
            pair_html += (
                f'<p class="dim pn">Identical on all {p_["identical"]} attacks both builds '
                f'were run against: every attack that broke one broke the other, and every '
                f'attack that held, held on both. The change bought nothing measurable.</p>')
            continue
        pair_html += (
            f'<p class="dim pn">{helped} attack(s) stopped by the control; {drifted} moved '
            f'the other way on attacks the control has nothing to do with. A summary count '
            f'adds those together and can report the guarded build as the weaker one.</p>'
            f'<table class="pair"><thead><tr><th>attack</th><th>naive</th><th>guarded</th>'
            f'<th>detectors</th><th>reading</th></tr></thead><tbody>{rws}</tbody></table>')
    if pair_html:
        pair_html = ('<h2 class="sect">What one change buys</h2>' + pair_html)

    newest = max((r["measured"] for r in rows), default="")
    older = sorted({r["measured"][:10] for r in rows if r["measured"][:10] < newest[:10]})
    staleness = ("" if not older else
                 f'<div class="stalebar">Rows on this page were measured on different '
                 f'days: newest {esc(newest[:10])}, also {esc(", ".join(older))}. '
                 f'A run older than the engine that produced the newest row was measured '
                 f'differently and should be re-run before it is compared.</div>')
    today = datetime.date.today().isoformat()
    doc = f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>QAtration — Fleet Overview</title><style>
:root{{--bg:#f6f7f9;--card:#fff;--ink:#14181f;--dim:#5b6472;--line:#e3e7ec;--accent:#b3261e;--ok:#1e9d63;--panel:#eef1f5}}
@media(prefers-color-scheme:dark){{:root:not([data-theme="light"]){{--bg:#0d1014;--card:#161b22;--ink:#e6edf3;--dim:#8b95a4;--line:#242c37;--accent:#ff5b60;--ok:#45c586;--panel:#1a2029}}}}
:root[data-theme="dark"]{{--bg:#0d1014;--card:#161b22;--ink:#e6edf3;--dim:#8b95a4;--line:#242c37;--accent:#ff5b60;--ok:#45c586;--panel:#1a2029}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.6 -apple-system,Segoe UI,Roboto,sans-serif}}
.wrap{{max-width:860px;margin:0 auto;padding:40px 22px 96px}}
.head{{border-bottom:1px solid var(--line);padding-bottom:20px;margin-bottom:24px}}
h1{{font-size:24px;margin:0 0 4px;letter-spacing:-.01em}} h1 .q{{color:var(--accent)}}
.sub{{color:var(--dim);font-size:13.5px;font-family:ui-monospace,Consolas,monospace}}
.lead{{font-size:15px;margin:0 0 24px;max-width:64ch}}
.lead b{{color:var(--accent)}}
table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden}}
th,td{{text-align:left;padding:12px 14px;border-bottom:1px solid var(--line);font-size:14px}}
th{{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--dim);font-weight:600}}
tr:last-child td{{border-bottom:none}}
.tname{{font-family:ui-monospace,Consolas,monospace;font-weight:600}}
.num{{text-align:right;font-variant-numeric:tabular-nums;width:1%;white-space:nowrap}}
.worst{{white-space:nowrap}} .sevdot{{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;vertical-align:1px}}
.verdict{{font-size:11px;font-weight:700;letter-spacing:.03em;padding:3px 10px;border:1px solid;border-radius:20px;white-space:nowrap}}
.dim{{color:var(--dim)}}
h2{{font-size:15px;margin:34px 0 12px;color:var(--dim);font-weight:600;text-transform:uppercase;letter-spacing:.05em}}
.matrix-wrap{{overflow-x:auto;border:1px solid var(--line);border-radius:12px;background:var(--card)}}
.matrix{{border:none;border-radius:0;min-width:520px}}
.matrix th,.matrix td{{text-align:center;padding:7px 9px;font-size:13px}}
.matrix .aid{{text-align:left;font-size:12px;color:var(--dim)}}
.matrix th:first-child{{text-align:left}}
.when{{font-size:10.5px;font-weight:400}}
.stalebar{{background:#fff5e0;color:#8a5a00;border-left:3px solid #8a5a00;border-radius:6px;padding:10px 13px;margin:0 0 16px;font-size:13px}}
@media(prefers-color-scheme:dark){{.stalebar{{background:rgba(138,90,0,.22);color:#e0a83a}}}}
.sect{{font-size:16px;margin:34px 0 4px}}
h3{{font-size:14px;margin:18px 0 2px}}
.pn{{font-size:13px;margin:0 0 8px}}
table.pair{{width:100%;border-collapse:collapse;margin-bottom:6px}}
table.pair th{{font-size:10.5px;text-transform:uppercase;letter-spacing:.03em;color:var(--dim);text-align:left;padding:5px 10px 5px 0}}
table.pair td{{padding:6px 10px 6px 0;border-bottom:1px solid var(--line);font-size:13px}}
.na{{color:var(--line)}}
.legend{{font-size:12.5px;color:var(--dim);margin-top:10px;font-family:ui-monospace,Consolas,monospace}}
</style></head><body><div class="wrap">
<div class="head">
  <h1><span class="q">QA</span>tration — Fleet Overview</h1>
  <div class="sub">Same arsenal · {len(rows)} systems · {today}</div>
</div>
<p class="lead">The same attack suite run against every system. <b>{n_vuln} of {len(rows)}</b> were
exploitable; the rest held. A tool that breaks the undefended and clears the hardened is measuring
real posture — not crying wolf.</p>

{staleness}
<table>
  <thead><tr><th>System</th><th>Interface</th><th>Attacks</th><th>Breached</th><th title="ordinary traffic, no attacker: how many probes the oracle left alone">Quiet on benign</th><th title="against the previous run of this target">Since last run</th><th>Worst</th><th>Verdict</th></tr></thead>
  <tbody>{tbody}</tbody>
</table>

{pair_html}
<h2>Full matrix</h2>
<div class="matrix-wrap"><table class="matrix">
  <thead><tr><th>Attack</th>{mcols}</tr></thead><tbody>{mrows}</tbody>
</table></div>
<div class="legend">● exploited · ◐ partial · ○ defended · · not applicable</div>
</div></body></html>"""
    out = OUT_DIR / "compare_targets.html"
    # The directory may not exist on a first run, and it is the caller's own workspace rather
    # than something to be precious about.
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(doc, encoding="utf-8")
    print(f"wrote {out} — {len(rows)} systems, {n_vuln} vulnerable")


if __name__ == "__main__":
    main()
