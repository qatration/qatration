"""
Arsenal linter — a self-check that keeps the growing YAML honest. The nastiest
failure mode of a template-driven scanner is SILENT: an attack whose success list
names a detector that doesn't exist never fires, so the target looks 'defended'
when it was never actually tested. This catches that (and friends) before a run.

    python lint_arsenal.py            # exits 1 on any error (CI gate)

Checks: duplicate ids; required fields; delivery-shape (direct→text, indirect→seed
+user_prompt, chain→steps); every success/partial detector exists in oracle;
every applies_to names a real target config; success list non-empty.
"""
import sys, os, glob
from target import target_configs
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
import yaml
from oracle import DETECTORS
from encoders import ENCODERS

ROOT = os.path.dirname(os.path.abspath(__file__))
VALID_DELIVERY = {"direct", "indirect", "chain", "sessions", "forged_history"}


def known_targets():
    """Every runnable target name: a config's explicit `name`, else its basename
    (no-name configs use the adapter's default, which equals the basename)."""
    names = set()
    for cfg_path in target_configs(ROOT):
        base = os.path.basename(cfg_path)[len("targets_"):-len(".yaml")]
        cfg = yaml.safe_load(open(cfg_path, encoding="utf-8")) or {}
        names.add(cfg.get("name", base))
    return names


def main():
    # `--help` has to be answered before anything is read. Without this the flag fell through
    # and the linter simply ran, which looks harmless and is the same defect that made
    # `qatration compare --help` crash: a command that does not parse its arguments cannot be
    # asked what it does, and the one that could not answer was found by a stranger's install
    # rather than by any suite.
    import argparse
    argparse.ArgumentParser(
        description="Check the attack corpus for the mistakes that read as findings: a "
                    "detector name nothing defines, a target that does not exist, an "
                    "expectation no probe can satisfy.").parse_args()
    targets = known_targets()
    # lint EVERY arsenal file (attacks.yaml + every attacks_*.yaml focus file), not just
    # the baseline — an unlinted focus file with a typo'd detector is the same silent
    # no-fire trap, it just hid in a file the linter never opened.
    files = sorted(glob.glob(os.path.join(ROOT, "attacks*.yaml")))
    errors, warns = [], []
    total = 0

    for path in files:
        fname = os.path.basename(path)
        attacks = yaml.safe_load(open(path, encoding="utf-8")) or []
        if not isinstance(attacks, list):
            errors.append(f"{fname}: top-level YAML is not a list of attacks"); continue
        total += len(attacks)
        seen = {}                                  # ids must be unique WITHIN a file
        for i, a in enumerate(attacks):
            aid = a.get("id")
            where = f"{fname} #{i} ({aid or '??'})"
            if not aid:
                errors.append(f"{where}: missing 'id'"); continue
            if aid in seen:
                errors.append(f"{fname}: {aid}: duplicate id (also at #{seen[aid]})")
            seen[aid] = i

            if not a.get("category"):
                errors.append(f"{fname}: {aid}: missing 'category'")

            delivery = a.get("delivery", "direct")
            if delivery not in VALID_DELIVERY:
                errors.append(f"{fname}: {aid}: bad delivery {delivery!r} (want {sorted(VALID_DELIVERY)})")
            # EMPTY IS NOT ABSENT, which is the distinction this whole project is organised
            # around, and the rule had it collapsed: `text: ""` is falsy, so the one probe whose
            # payload IS the empty string could not be written. A deployment that answers
            # nothing with its entire system prompt has a bug nobody had to attack it to find,
            # and it is the case a template renderer is least likely to have been tested on.
            # `is None` keeps the real error — a `text:` key with nothing after it — an error.
            elif delivery == "direct" and a.get("text") is None:
                errors.append(f"{fname}: {aid}: direct delivery needs 'text' "
                              f"(use `text: \"\"` if the empty prompt is the point)")
            elif delivery == "indirect" and not (a.get("seed") and a.get("user_prompt")):
                errors.append(f"{fname}: {aid}: indirect delivery needs 'seed' + 'user_prompt'")
            elif delivery == "chain" and not a.get("steps"):
                errors.append(f"{fname}: {aid}: chain delivery needs 'steps'")

            elif delivery == "sessions" and not a.get("steps"):
                errors.append(f"{fname}: {aid}: sessions delivery needs 'steps'")

            elif delivery == "forged_history":
                hist = a.get("history")
                if not a.get("text") or not hist:
                    errors.append(f"{fname}: {aid}: forged_history delivery needs "
                                  f"'history' + 'text'")
                elif not any(h.get("role") == "assistant" for h in hist):
                    # A forged history with no assistant turn is a chain written the long
                    # way round. The entire mechanism is that the model reads a reply it
                    # never gave, so an attack lacking one measures something else while
                    # filing under this name.
                    errors.append(f"{fname}: {aid}: forged_history with no forged assistant "
                                  f"turn — that is a chain, not a context-compliance attack")
                elif any(h.get("role") not in ("user", "assistant") or not h.get("content")
                         for h in hist):
                    errors.append(f"{fname}: {aid}: every history entry needs a non-empty "
                                  f"'content' and role user|assistant")

            # An empty `success` used to mean an attack that could never register a break,
            # and that stopped being true when the always-on sets arrived: a leak is now
            # caught whether or not the attack thought to name the detector, which is the
            # whole reason those sets exist. The rule outlived the engine and started
            # failing 40 times on arsenals that run correctly every day — and a gate that
            # cries wolf on good content is one nobody reads, which is worse than no gate.
            # What is still worth saying is that such an attack relies ENTIRELY on the
            # always-on detectors, so a target-specific break would go unnoticed.
            #
            # And it went one step further: it says it on EVERY such attack, EVERY run — 53
            # times across six arsenals where resting on the always-on set is the design
            # (rangebot exists to make those detectors fire; draftbot's whole point is a
            # consequence downstream of the reply). A warning that is correct, unactionable
            # and permanent is noise, and noise is what a reader learns to skip past on the
            # way to the one line that matters.
            #
            # So an attack may SAY it meant to: `scored_by: always_on`. Then the warning is
            # left for the attacks that have not said so, which is the case it was written
            # for — someone forgot to name a detector — and the file records the decision
            # where the next reader will see it.
            succ = a.get("success", [])
            if a.get("scored_by") == "always_on":
                pass
            elif not succ and not a.get("partial") and a.get("category") != "control":
                warns.append(f"{fname}: {aid}: no 'success' or 'partial' — scoring rests "
                             f"entirely on the always-on detectors")
            for d in succ + a.get("partial", []):
                if d not in DETECTORS:
                    errors.append(f"{fname}: {aid}: unknown detector {d!r} in success/partial "
                                  f"(SILENT no-fire — typo? not registered in oracle.py?)")

            # Same risk, same shape, and it had no guard on either side: a misspelled
            # `encode:` used to leave the payload PLAIN and let the attack run and report,
            # so the row read "the obfuscation did not fool it" when there was none.
            enc = a.get("encode")
            if enc and enc not in ENCODERS:
                errors.append(f"{fname}: {aid}: unknown encoding {enc!r} "
                              f"(the payload would go out UNOBFUSCATED and score as a "
                              f"defence — known: {', '.join(sorted(ENCODERS))})")
            if enc == "ascii_art" and "[[ART:" not in str(a.get("text") or ""):
                warns.append(f"{fname}: {aid}: encode: ascii_art with no [[ART:WORD]] "
                             f"marker — the strategy has nothing to replace")

            for t in a.get("applies_to", []) or []:
                if t not in targets:
                    warns.append(f"{fname}: {aid}: applies_to names '{t}' — no such target config")

    print(f"linted {total} attacks across {len(files)} file(s) · {len(DETECTORS)} detectors · {len(targets)} targets")
    for w in warns:
        print(f"  WARN  {w}")
    for e in errors:
        print(f"  ERROR {e}")
    if errors:
        print(f"\nFAIL — {len(errors)} error(s), {len(warns)} warning(s).")
        sys.exit(1)
    print(f"\nOK — arsenal clean ({len(warns)} warning(s)).")


if __name__ == "__main__":
    main()
