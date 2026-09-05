"""The deliverable must not be attackable by the system it tests — no model, no network.

Every page this tool produces is built from text the TARGET wrote. A reply, a tool argument,
a retrieved document, a refusal phrasing, an objective name, a fingerprint: all of it is
attacker-influenced by construction, because that is the whole premise of the assessment. So
the client-facing artifact is a rendering of hostile input, and a security report that
executes script when it is opened is a finding about the tool that wrote it.

Nothing here was broken when this was written, which is the reason to write it: escaping is
the kind of property that holds until one `f"...{x}..."` is added without `esc()`, at which
point it fails silently and only for the customers whose bot happened to emit markup. The
repo already has `xss_in_output` as a DETECTOR for exactly this in someone else's product,
and `test_reports` checks that `esc` escapes — which is a test of the helper, not of the
pages. This drives the real builders over a target that answers every question with a script
tag and asserts the payload never survives raw.

Deliberately hostile in every field a target can reach, not only the obvious reply: the
attack id, the planted seed and its field name, the tool name AND its argument, the
observation, an earlier turn, the refusal signal, the fired detector list, the lock-map
objective and property names, the recon self-description, style, tool names, refusal vocab
and hints, and the target's own name — a customer picks that, and a customer can be careless.

    python test_deliverable.py     # exits 1 on any failure (CI gate)
"""
import sys, os, io, json, tempfile, shutil, pathlib, contextlib
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from report_engine import build_html
import defense_report as dr
import build_index as bi
import compare_targets as ct
import compare_recon as cr

# Two shapes: one that runs if it survives raw, and one that breaks OUT of an attribute if
# the value is interpolated into a tag rather than into text.
PAYLOADS = ['<script>alert(1)</script>', '" onmouseover="alert(2)']


def hostile_run(pay):
    return {"meta": {"target": "bot" + pay, "model": pay, "caps": [pay], "trials": 1,
                     "attacks_n": 1, "broke": 1, "skipped": 0, "baseline": [pay],
                     "attribution": pay},
            "results": [{"attack": {"id": "a" + pay, "category": "exfil", "text": pay,
                                    "delivery": "indirect", "user_prompt": pay,
                                    "seed": {"field": pay, "text": pay}},
                         "headline": "EXPLOITED", "fired": [pay], "rate": "1/1",
                         "trials": [{"verdict": "EXPLOITED", "fired": [pay],
                                     "probe": {"output": pay, "tool_calls": [[pay, pay]],
                                               "observations": [pay],
                                               "turns": [{"output": pay}]},
                                     "refusal": {"class": "compliance", "signals": [pay]}}]}]}


def hostile_isolation(pay):
    sample = {"output": pay, "tool_calls": [[pay, pay]], "achieved": True}
    return {"maps": [{"objective": pay, "verdict": "PARTIAL", "coupling": [pay],
                      "keyed": [pay], "combined": {"status": "open", "sample": sample},
                      "properties": [{"name": pay, "status": "open", "hits": "1/1",
                                      "sample": sample}]}],
            "when": "2026-01-01 00:00"}


def hostile_recon(pay):
    return {"profile": {"target": pay, "style": {"tone": pay}, "self_description": pay,
                        "tool_channel": pay, "tools_seen": [pay],
                        "refusal_vocab": [{"probe": pay, "class": pay, "reply": pay}],
                        "hints": [{"level": "warn", "text": pay}]},
            "when": "2026-01-01 00:00"}


def hostile_profile(pay):
    """The recon artifact as `compare_recon` finds it: the profile at TOP level.

    `hostile_recon` above is the shape `report_engine` is handed -- {profile, when} --
    and the file on disk is not that. Passing the wrapped one produces a row of empty
    strings and a page with no payload in it, which is a gate that passes because
    nothing was rendered.
    """
    return {
        "target": pay, "tool_channel": pay, "tools_seen": [pay],
        "self_description": pay, "style": {"tone": pay},
        "refusal_vocab": [{"probe": pay, "class": pay, "reply": pay}],
        "hints": [{"level": "warn", "text": pay}],
        "token_lock": {pay: "blocked", pay + "2": "unmeasured"},
        "new_patterns": {pay: [pay]},
        "disclosure_open": True,
        "remembers": True, "reset_clears": False,
    }


def main():
    fails, checks = [], 0

    def check(label, ok, detail=""):
        nonlocal checks
        checks += 1
        print(f"{'PASS' if ok else 'FAIL'}  {label}")
        if not ok:
            fails.append(f"{label}: {detail}")

    for pay in PAYLOADS:
        short = pay[:18]

        # --- the per-target scorecard, with every side panel it can carry ---------------
        run = hostile_run(pay)
        page = build_html(run["meta"], run["results"],
                          recon=hostile_recon(pay), isolation=hostile_isolation(pay))
        check(f"the scorecard renders {short!r} inert",
              pay not in page, f"{page.count(pay)} raw occurrence(s)")

        # --- and the fleet pages, driven through their real entry points ----------------
        tmp = tempfile.mkdtemp()
        try:
            with open(os.path.join(tmp, "results_hostile.json"), "w", encoding="utf-8") as f:
                json.dump(run, f)
            # `compare_recon` reads a different file entirely, so without this it builds
            # its page from nothing and renders every payload inert by having none.
            with open(os.path.join(tmp, "recon_hostile.json"), "w", encoding="utf-8") as f:
                json.dump(hostile_profile(pay), f)
            real = (dr.OUT_DIR, bi.OUT, ct.OUT_DIR, cr.OUT_DIR)
            dr.OUT_DIR = bi.OUT = ct.OUT_DIR = cr.OUT_DIR = pathlib.Path(tmp)
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    dr.main()
                    bi.main()
                    try:
                        ct.main()
                    except SystemExit:
                        pass
                    cr.main()
            finally:
                dr.OUT_DIR, bi.OUT, ct.OUT_DIR, cr.OUT_DIR = real

            built = sorted(f for f in os.listdir(tmp) if f.endswith(".html"))
            # THE NUMBER IS THE GATE. Every check below is `payload not in html`, which a
            # builder that wrote nothing passes perfectly. `compare_recon` was the fifth
            # page this tool produces and the only one this suite never opened.
            check(f"the fleet pages were actually built for {short!r}", len(built) >= 4,
                  str(built))
            for name in built:
                html = open(os.path.join(tmp, name), encoding="utf-8").read()
                check(f"{name} renders {short!r} inert",
                      pay not in html, f"{html.count(pay)} raw occurrence(s)")

            # AND ON THE ONE PAGE BUILT ENTIRELY FROM THE PROFILE, the payload has to be
            # THERE. `pay not in html` is satisfied by a page that dropped the value, by a
            # renderer that read the wrong file, and by an empty string -- the same
            # absence-as-a-clean-result this repo keeps finding. Measured: the fleet recon
            # page carries it three times, escaped.
            fleet = os.path.join(tmp, "recon_fleet.html")
            page = open(fleet, encoding="utf-8").read() if os.path.exists(fleet) else ""
            check(f"...and recon_fleet.html still carries {short!r}, escaped",
                  cr.esc(pay) in page,
                  "the payload was dropped rather than escaped")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # A gate that passes because nothing was rendered is not a gate. The payload has to
    # reach the page in its escaped form, or the checks above are satisfied by an empty file.
    run = hostile_run(PAYLOADS[0])
    page = build_html(run["meta"], run["results"],
                      recon=hostile_recon(PAYLOADS[0]), isolation=hostile_isolation(PAYLOADS[0]))
    check("...and the evidence is still on the page, escaped rather than dropped",
          "&lt;script&gt;" in page, "the payload vanished instead of being escaped")

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — the report is not attackable by the target it describes.")


if __name__ == "__main__":
    main()
