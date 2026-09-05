"""
Fleet hygiene — every target's recon profile in one table.

An operator rarely has one bot. Ten profiles read one at a time are nine separate errands;
side by side they answer the question a reader actually has, which is not "is this bot
vulnerable" but "which of my bots should I look at first, and what is wrong with them that
I could have found without an attack".

Everything here comes from benign probes. Reads out/recon_<target>.json (whatever exists)
-> out/recon_fleet.html plus a console table. Targets with warnings sort first, because a
warning means a measurement downstream cannot be trusted until it is fixed.

    qatration compare
"""
import json, glob, os, html, sys
from pathlib import Path
from workspace import OUT as WORKSPACE_OUT
from recon import memory_phrase

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

OUT_DIR = Path(WORKSPACE_OUT)

# The four channel answers are not interchangeable — see recon.py. "silent" and
# "unobservable" both mean "no call was seen", and only one of them is a problem.
CHANNEL = {
    "real": ("real", "#1e9d63"),
    "printed": ("printed only", "#b3261e"),
    "silent": ("unverified", "#9a6700"),
    "unobservable": ("not observable", "#6b6b70"),
}


from workspace import esc as _ws_esc


def esc(s):
    """One implementation, in `workspace`: see the note there. Re-exported so the forty-four
    call sites in this file keep reading the way they did."""
    return _ws_esc(s)


def _row(profile, name, when):
    # Three states, like `disclosure` two lines down. "remembers" MISSING means the
    # fingerprint never got that far — an errored probe, or a profile written before the
    # question was asked — and reading that as `stateless` reports a security-relevant
    # property the run never measured. A stateless bot cannot carry a poisoned standing rule
    # into a later turn, which is exactly the conclusion a reader would draw from the word.
    mem = memory_phrase(profile, unknown="unmeasured", no="stateless",
                        clears="remembers, reset clears", sticks="RESET DOES NOT CLEAR")
    warns = [h["text"] for h in profile.get("hints", [])
             if isinstance(h, dict) and h.get("level") == "warn"]
    lock = profile.get("token_lock") or {}
    # COUNTED OUT OF WHAT WAS ASKED, not out of what was listed. An unmeasured token used to
    # arrive here as "blocked" and inflate the column that reads as the target's defence.
    blocked = sum(1 for v in lock.values() if v == "blocked")
    unmeasured = sum(1 for v in lock.values() if v == "unmeasured")
    disc = profile.get("disclosure_open")
    return {
        "target": name,
        "when": when,
        "channel": profile.get("tool_channel", "?"),
        "tools": ", ".join(profile.get("tools_seen", [])) or "—",
        "memory": mem,
        # None is a real third state: no markers configured, so the question was not asked
        "disclosure": "leaks" if disc else ("held" if disc is False else "unscored"),
        # DENOMINATOR IS WHAT WAS ASKED. `blocked/len(lock)` counted tokens whose probe never
        # landed as part of the total, so a half-dead run read as a partial lock instead of a
        # partial measurement. The unmeasured ones are named rather than folded into either side.
        "content_lock": (f"{blocked}/{len(lock) - unmeasured}"
                         + (f" (+{unmeasured} unmeasured)" if unmeasured else "")) if lock else "—",
        "unlabelled": sum(len(v) for v in (profile.get("new_patterns") or {}).values()),
        "warnings": warns,
    }


def collect():
    rows = []
    for fp in sorted(glob.glob(str(OUT_DIR / "recon_*.json"))):
        name = os.path.basename(fp)[len("recon_"):-len(".json")]
        try:
            with open(fp, encoding="utf-8") as f:
                profile = json.load(f)
        except Exception as e:
            print(f"  ! skipping {os.path.basename(fp)}: {e}", file=sys.stderr)
            continue
        when = __import__("datetime").datetime.fromtimestamp(
            os.path.getmtime(fp)).strftime("%Y-%m-%d %H:%M")
        rows.append(_row(profile, name, when))
    # worst first: a warning invalidates measurements, so it outranks everything else
    rows.sort(key=lambda r: (-len(r["warnings"]), -r["unlabelled"], r["target"]))
    return rows


def render(rows):
    body = ""
    for r in rows:
        label, color = CHANNEL.get(r["channel"], (r["channel"], "#6b6b70"))
        warn_html = "".join(f'<div class="w">{esc(w)}</div>' for w in r["warnings"])
        body += f"""<tr>
      <td class="mono"><b>{esc(r['target'])}</b><div class="dim sm">{esc(r['when'])}</div></td>
      <td><span style="color:{color}">{esc(label)}</span><div class="dim sm">{esc(r['tools'])}</div></td>
      <td class="{'bad' if 'NOT CLEAR' in r['memory'] else ''}">{esc(r['memory'])}</td>
      <td class="{'bad' if r['disclosure'] == 'leaks' else ''}">{esc(r['disclosure'])}</td>
      <td class="mono">{esc(r['content_lock'])}</td>
      <td class="mono">{r['unlabelled'] or '—'}</td>
      <td>{warn_html or '<span class="dim">—</span>'}</td>
    </tr>"""
    n_warn = sum(1 for r in rows if r["warnings"])
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>QAtration — fleet recon</title><style>
:root{{--bg:#f7f7f8;--card:#fff;--ink:#1a1a1a;--dim:#6b6b70;--line:#e4e4e8;--accent:#b3261e}}
@media(prefers-color-scheme:dark){{:root{{--bg:#16161a;--card:#1f1f25;--ink:#eaeaec;--dim:#9a9aa2;--line:#33333c}}}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}}
.wrap{{max-width:1100px;margin:0 auto;padding:32px 20px 80px}}
h1{{font-size:22px;margin:0 0 2px}} h1 .q{{color:var(--accent)}}
.sub{{color:var(--dim);margin:0 0 20px;font-size:14px}}
table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden}}
th,td{{text-align:left;padding:10px 13px;border-bottom:1px solid var(--line);vertical-align:top;font-size:13.5px}}
th{{font-size:11px;text-transform:uppercase;letter-spacing:.03em;color:var(--dim)}}
.mono{{font-family:ui-monospace,Consolas,monospace}} .dim{{color:var(--dim)}} .sm{{font-size:11.5px}}
.bad{{color:var(--accent);font-weight:600}}
.w{{background:#fdeceb;color:#b3261e;border-left:3px solid #b3261e;border-radius:5px;padding:6px 9px;margin-bottom:5px;font-size:12.5px}}
@media(prefers-color-scheme:dark){{.w{{background:rgba(179,38,30,.16);color:#ff8a80}}}}
.note{{color:var(--dim);font-size:13px;margin-top:14px}}
</style></head><body><div class="wrap">
<h1><span class="q">QA</span>tration — fleet recon</h1>
<p class="sub">{len(rows)} targets profiled · {n_warn} with warnings · benign probes only, no attacks</p>
<table>
<thead><tr><th>Target</th><th>Tool channel</th><th>Memory</th><th>Plain disclosure ask</th>
<th>Tokens blocked</th><th>Unlabelled refusals</th><th>Warnings</th></tr></thead>
<tbody>{body}</tbody></table>
<p class="note">Everything above was established without a single attack. A <b>warning</b> means a
number measured later cannot be trusted until it is fixed — a reset() that does not reset contaminates
every trial, and a tool call that is only printed never ran. <b>Unlabelled refusals</b> are walls the
lock map would otherwise file as plain compliance. <b>Unscored</b> disclosure means no
<span class="mono">sysprompt_markers</span> are configured for that target, so the question was never
actually asked.</p>
</div></body></html>"""


def main():
    # PARSED, EVEN THOUGH THERE IS NOTHING TO PARSE. Without this the command answered
    # `--help` by doing its work -- printing the report and writing the page -- and accepted
    # any mistyped flag in silence. A reader who asks what a command does should not have to
    # find out by watching it happen.
    import argparse
    argparse.ArgumentParser(prog="qatration profiles", description='every profiled target in one table, worst first').parse_args()
    rows = collect()
    if not rows:
        # NOT `run_recon.py`. That file exists in a checkout of this repository and nowhere
        # in an installed package: `pip install qatration` puts the modules inside the package
        # and gives the reader `qatration recon`. The path was already right here; the remedy
        # was the half written for whoever wrote it.
        print(f"no recon_*.json in {OUT_DIR} — profile a target first:\n"
              f"    qatration recon --target-config <your-config>.yaml")
        # NOT A PASS, for the reason `build_index` records.
        return 3
        return
    w = max(len(r["target"]) for r in rows)
    print(f"{'target':<{w}}  {'channel':<15}{'memory':<26}{'disclosure':<12}"
          f"{'tokens':<8}{'unlabelled':<12}warnings")
    print("-" * (w + 85))
    for r in rows:
        print(f"{r['target']:<{w}}  {r['channel']:<15}{r['memory']:<26}"
              f"{r['disclosure']:<12}{r['content_lock']:<8}"
              f"{str(r['unlabelled'] or '-'):<12}{len(r['warnings']) or '-'}")
    for r in rows:
        for warn in r["warnings"]:
            print(f"  ! {r['target']}: {warn}")

    out = OUT_DIR / "recon_fleet.html"
    out.parent.mkdir(exist_ok=True)
    out.write_text(render(rows), encoding="utf-8")
    print(f"\nreport → {out}")


if __name__ == "__main__":
    # The return value is the answer; `main()` alone drops it.
    sys.exit(main() or 0)
