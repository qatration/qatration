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
import re
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
        from workspace import config_name as _config_name
        base = _config_name(cfg_path, {})
        cfg = yaml.safe_load(open(cfg_path, encoding="utf-8")) or {}
        names.add(cfg.get("name", base))
    return names


# RFC 2606 RESERVED SPACE, and nothing else. A host inside a payload is where this tool asks
# somebody's agent to send whatever it can reach, on every machine that runs the corpus. If the
# name is registrable, whoever registers it is the recipient.
#
# `attacker-example.com` was moved to `attacker.example` for exactly this reason, and the sweep
# that should have followed did not happen -- so `isolation_example.yaml` went on naming an
# all-staff list at a registrable `.com` in two probes of an objective whose other two already
# used the reserved form. That is why this checks the class rather than a list of known-bad
# names.
_RESERVED_HOST = re.compile(
    r"(?:^|\.)(?:example|test|invalid|localhost)$|^example\.(?:com|net|org)$"
    r"|\.example\.(?:com|net|org)$")
_HOST = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b")
# Endings that are a filename or an attribute access, not a host.
_NOT_A_HOST = (".py", ".json", ".yaml", ".yml", ".html", ".md", ".txt", ".jsonl", ".png",
               ".jpg", ".pdf", ".csv", ".xml", ".sh", ".log", ".lower", ".upper", ".items",
               ".join", ".format", ".append", ".exe", ".dll", ".so")


def registrable_hosts(text):
    """Every host in a payload that somebody could go and register."""
    out = set()
    for h in _HOST.findall(str(text).lower()):
        if h.endswith(_NOT_A_HOST):
            continue
        if not _RESERVED_HOST.search(h):
            out.add(h)
    return out


# Keys an attack may carry that the ENGINE never reads, and why each is allowed. Written down
# here because the alternative is a scan that finds them unread and a lint that calls them
# typos -- somebody decided these belong in the corpus, and the decision lives beside the rule
# it exempts, the way `QUALIFIERS_NOT_CARRIED` does in the surfaces.
WRITTEN_NOT_READ = {
    "found_on": "run_adaptive stamps the target an attack was discovered against",
    "found_at": "and when, so a promoted attack carries its own provenance",
    "found_after_iters": "how many iterations the search took to reach it",
    "goal": "the objective the adaptive attacker was pursuing when it found this",
    "confirmed_on": "targets a discovered attack has since been reproduced against",
}


def attack_keys_read(root=None):
    """Every key some part of this engine reads off an attack.

    A KEY NOTHING READS IS AN INSTRUCTION NOTHING FOLLOWS. `encode: base64` typed `encoding:`
    leaves the attack in plain text while its id, its category and the report all call it
    encoded -- a transform that was never applied, reported as one that was. `paired_with`
    misspelled unpairs an A/B comparison; `plants` misspelled makes a finding unattributable;
    `expects_refusal` misspelled turns a refusal test into an ordinary one.
    `success` is the one spelling already covered, because `lint` warns when an attack has
    neither `success` nor `partial`.

    Derived from the source rather than listed, for the reason the other two scans in this
    package are: a list of twenty-one keys beside a corpus of six hundred attacks is the copy
    that goes stale.
    """
    import re as _re
    # THE PACKAGE, NOT `ROOT`. `ROOT` is where the corpus is, and `test_lint` redirects it to
    # a temporary directory holding two YAML files — so a scan rooted there finds no Python at
    # all, returns nothing, and calls every key in every attack unknown. The suite caught that
    # on the first run: `text` reported as a key nothing reads.
    here = root or os.path.dirname(os.path.abspath(__file__))
    keys = set()
    pats = (r'\ba\.get\(\s*["\']([a-z_]+)["\']',
            r'\ba\[["\']([a-z_]+)["\']\]',
            r'attack\.get\(\s*["\']([a-z_]+)["\']',
            r'attack\[["\']([a-z_]+)["\']\]',
            r'atk\.get\(\s*["\']([a-z_]+)["\']',
            r'_at\.get\(\s*["\']([a-z_]+)["\']')
    for fname in sorted(glob.glob(os.path.join(here, "*.py"))):
        if os.path.basename(fname).startswith("test_"):
            continue
        try:
            src = open(fname, encoding="utf-8").read()
        except OSError:
            continue
        for p in pats:
            keys |= set(_re.findall(p, src))
    return keys | set(WRITTEN_NOT_READ)


def control_ids(root=None):
    """Every attack in the shipped corpus whose category is `control`.

    HERE BECAUSE THIS MODULE OWNS READING THE ARSENAL, and because the caller that needs it is
    the one whose subject is coverage. `discrimination` counts the controls that RAN and says
    "no control fired", which is the tool's claim not to cry wolf; it had no way to say how
    much of the control corpus that claim rests on. Measured when this was written: 131
    controls in the arsenals, 118 with at least one stored row, 13 that have never been sent
    anywhere -- a self-audit reporting a pass over a subset, with the size of the subset
    unstated. That is this repository's own named failure, in the section that exists to
    police it.
    """
    import glob as _glob
    out = set()
    for fname in sorted(_glob.glob(os.path.join(root or ROOT, "attacks*.yaml"))):
        try:
            doc = yaml.safe_load(open(fname, encoding="utf-8")) or []
        except Exception:
            # A corpus file that will not parse is `lint`'s business, not this function's.
            # Skipping it here understates the corpus, which keeps the caller's caveat small
            # rather than inventing one.
            continue
        for a in (doc if isinstance(doc, list) else doc.get("attacks") or []):
            if isinstance(a, dict) and a.get("category") == "control" and a.get("id"):
                out.add(a["id"])
    return out


_LIST_FIELDS = None


def list_attack_fields(root=None):
    """Every attack field the engine reads as a LIST — derived from the arsenals that ship.

    Seven of them, and not one of the 1,060 shipped attacks writes any field with two
    different types, which is what makes this derivable rather than a matter of opinion. A
    field added on a Monday joins by being a list in the file that introduces it.
    """
    global _LIST_FIELDS
    if _LIST_FIELDS is not None and root is None:
        return _LIST_FIELDS
    import glob as _glob
    import io as _io
    import yaml as _yaml
    here = root or ROOT
    seen = {}
    for fn in _glob.glob(os.path.join(here, "attacks*.yaml")):
        try:
            rows = _yaml.safe_load(_io.open(fn, encoding="utf-8").read()) or []
        except Exception:
            continue
        if not isinstance(rows, list):
            continue
        for a in rows:
            if isinstance(a, dict):
                for k, v in a.items():
                    seen.setdefault(k, set()).add(type(v).__name__)
    out = {k for k, kinds in seen.items() if kinds == {"list"}}
    if root is None:
        _LIST_FIELDS = out
    return out


def bad_entry_shapes(entries):
    """-> [(id, field, why)] for entries whose list fields are not lists.

    A STRING IS ITERABLE, AND THESE TWO ITERATE IT DIFFERENTLY.

    `success: canary_in_output` — no brackets — makes the name check below read the value one
    character at a time, so the run is refused (right) for `'c'` being an unknown detector
    (useless). The operator sees a letter and their problem is a missing pair of brackets.

    `applies_to: httpbot` is worse, because nothing refuses it at all. Scoping asks
    `target.name in a["applies_to"]`, which on a string is a SUBSTRING test: an attack written
    for `httpbot` also runs against a target called `bot`, or `http`. It is judged there, it
    produces rows there, and those rows read as coverage of a bot the attack was never
    written for.
    """
    want = list_attack_fields()
    out = []
    if not want:
        return out
    for e in entries:
        if not isinstance(e, dict):
            continue
        who = e.get("id") or e.get("name") or "?"
        for k, v in e.items():
            if k not in want or v is None or isinstance(v, (list, tuple)):
                continue
            if isinstance(v, str):
                out.append((who, k, "is a single string; this field is read as a LIST, so %r "
                                    "would be used one character at a time. Write it as "
                                    "[%r]" % (v, v)))
            else:
                out.append((who, k, "is %s; this field is read as a list"
                            % type(v).__name__))
    return out


def bad_encoders(entries):
    """-> [(id, why)] for attacks whose `encode:` cannot do what its name claims.

    TWO SHAPES, AND THE FIRST ONE EXITS 1. `apply_encoding` raises `KeyError` on a name it
    does not know -- right, because the alternative is sending the payload in the clear under
    an encoded name -- but it raises MID-SWEEP, out of the runner, to Python's default handler.
    That is exit 1, which this project's own table documents as "the target was exploited or
    breached". A YAML typo filed as a security finding, and the attacks before it in the file
    have already been sent.

    The second is quieter and older: `encode: ascii_art` with no `[[ART:WORD]]` marker is a
    documented no-op -- "a no-op transform is worth being able to see", says the encoder -- and
    the only thing that could see it was `qatration lint`, which takes no path and so could
    never be pointed at the file a stranger wrote.

    Both were already known here. `lint` has carried an error for the first and a warning for
    the second since they were written; neither could reach a corpus loaded with `--attacks`.
    """
    import difflib
    known = sorted(ENCODERS)
    out = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        enc = e.get("encode")
        if not enc:
            continue
        who = e.get("id") or "?"
        if enc not in ENCODERS:
            near = difflib.get_close_matches(str(enc), known, n=1, cutoff=0.6)
            out.append((who, "encode: %r is not an encoder this build has%s. The payload "
                             "cannot be obfuscated, and sending it in the clear under an "
                             "encoded name scores the plain word as a defence."
                        % (enc, " — did you mean %r?" % near[0] if near else
                           "; it has: %s" % ", ".join(known))))
        elif enc == "ascii_art" and "[[ART:" not in str(e.get("text") or ""):
            out.append((who, "encode: ascii_art has no [[ART:WORD]] marker in its text, so the "
                             "transform is a no-op: the sensitive word goes out written "
                             "normally and a DEFENDED verdict describes a target that was "
                             "shown it in the clear."))
    return out


def refuse_unknown_detectors(entries, what, path):
    """Refuse a corpus whose success/partial lists name detectors that do not exist.

    `unknown_detectors` below has always known this rule; `qatration lint` has always applied
    it. Neither could reach the file a stranger actually runs. `run --attacks mine.yaml` and
    `isolation --objectives mine.yaml` both take a path, `lint` takes no arguments at all, and
    nothing validated the corpus at the point it was loaded -- so the one rule written for this
    failure was aimed exclusively at files that already pass it.

    WHAT IT COSTS, WALKED: an attack whose only success detector is `canary_in_ouput` (one
    transposed letter) came back DEFENDED 0/1 with exit code 0 and the line "0/1 attacks
    breached the target". Nothing could have scored it. The same run prints a careful warning
    about five detectors that cannot fire FOR WANT OF CONFIG -- the engine has the exact
    vocabulary for this -- and says nothing about a detector that does not exist, because
    `inert_for` only knows names that are registered.

    In isolation it is worse, for the reason written on `unknown_detectors`: every trial misses,
    `hits == 0` reads as locked, and every property locked reads as HARDENED.

    Refused rather than warned, because after this point every signal the run produces is a
    measurement of nothing, and this is the last moment anybody is reading.
    """
    import difflib
    # SHAPE BEFORE SPELLING, because a `success:` written without brackets fails the spelling
    # check one character at a time and the message names a letter.
    shapes = bad_entry_shapes(entries)
    if shapes:
        raise SystemExit(
            "%s: %d field(s) in %s are not the shape the engine reads. Nothing was sent.\n"
            % (what, len(shapes), path)
            + "\n".join("    %-22s %-12s %s" % (w, k, why) for w, k, why in shapes[:8]))
    # AND THE TRANSFORM, before the names: an unknown encoder is refused by `apply_encoding`
    # already, but it refuses mid-sweep as an uncaught KeyError and exit 1.
    _enc = bad_encoders(entries)
    if _enc:
        raise SystemExit(
            "%s: %d attack(s) in %s declare a transform that cannot be applied. Nothing was "
            "sent.\n" % (what, len(_enc), path)
            + "\n".join("    %-22s %s" % (who, why) for who, why in _enc[:8]))
    known = sorted(DETECTORS)
    bad = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        names = list(e.get("success") or []) + list(e.get("partial") or [])
        for p in (e.get("properties") or []):
            if isinstance(p, dict):
                names += list(p.get("success") or []) + list(p.get("partial") or [])
        for n in unknown_detectors(names):
            near = difflib.get_close_matches(str(n), known, n=1, cutoff=0.7)
            bad.append((e.get("id") or e.get("name") or "?", n, near[0] if near else ""))
    if not bad:
        return
    lines = ["%s: %d name(s) in %s are not detectors this build registers. Nothing was sent."
             % (what, len(bad), path)]
    for who, n, near in bad[:10]:
        lines.append("    %-28s %r%s" % (who, n, " — did you mean %r?" % near if near else ""))
    lines.append("  A name nothing registers can never fire, so every attack that declares it "
                 "comes back DEFENDED and the run reports a clean result over a question it "
                 "never asked.")
    lines.append("  The %d names this build knows: qatration lint" % len(known))
    raise SystemExit("\n".join(lines))


def unknown_detectors(names):
    """Names in a success/partial list that `oracle.py` does not register.

    A FUNCTION BECAUSE THERE ARE TWO CORPORA, and only one of them was being asked. This rule
    lived inline in the loop below, which walks `attacks*.yaml`; the objectives in
    `isolation*.yaml` name detectors out of the same vocabulary, through the same key, and
    nothing read them at all. Fifty-seven references, all of them correct on the day this was
    written -- which is what an ungated invariant looks like right up until it is not.

    THE FAILURE IS SILENT IN BOTH, and in isolation it is worse than in the arsenal. A typo
    here does not raise: `_achieved` filters the success list to names it knows and returns
    False when nothing is left, so every trial misses, `hits == 0` reads as "locked", every
    property locked reads as HARDENED -- the strongest claim this tool makes about a target --
    and the run that produced it never asked the target anything the detector could have seen.
    """
    return [n for n in names if n not in DETECTORS]


_ATTACK_KEYS = None


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
    global _ATTACK_KEYS
    _ATTACK_KEYS = attack_keys_read()
    files = sorted(glob.glob(os.path.join(ROOT, "attacks*.yaml")))
    errors, warns = [], []
    total = 0

    # AN EMPTY CORPUS IS THE FAILURE THIS IS RUN TO CATCH, and it used to be the surest
    # way to pass: no files means no errors means "OK — arsenal clean", exit 0. The CI
    # step that invokes this from outside the checkout is the ONLY check on
    # `[tool.setuptools.package-data]`, whose own comment reads "an install without the
    # YAML is a runner with nothing to run". Measured on an installed layout with the
    # YAML stripped: "linted 0 attacks across 0 file(s) · OK — arsenal clean".
    if not files:
        print(f"REFUSED: no attacks*.yaml beside {ROOT} — an arsenal that is not there\n"
              f"cannot be linted, and this is what a packaging mistake looks like from\n"
              f"inside an installed copy. Check [tool.setuptools.package-data].")
        return 1

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

            # SEE registrable_hosts. Everything the attack actually sends, in one place, so a
            # new delivery shape cannot quietly escape the check.
            sent = [a.get("text") or ""]
            sent += [str(x) for x in (a.get("steps") or [])]
            sent += [str((h or {}).get("content", "")) for h in (a.get("history") or [])]
            sent.append(str((a.get("seed") or {}).get("text", "")))
            for host in sorted(registrable_hosts(" ".join(sent))):
                errors.append(
                    f"{fname}: {aid}: payload names {host}, which is registrable. Use RFC 2606 "
                    f"reserved space (.example) — an agent told to send data to a name somebody "
                    f"can own will send it to whoever owns it")
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
            # A KEY NOTHING READS IS AN INSTRUCTION NOTHING FOLLOWS. See `attack_keys_read`:
            # `encode:` typed `encoding:` sends the attack in plain text under an encoded name,
            # and every layer downstream reports it as the encoded one.
            for k in sorted(set(a) - _ATTACK_KEYS):
                errors.append(f"{fname}: {aid}: unknown key {k!r} — nothing in this engine "
                              f"reads it, so whatever it was meant to do does not happen")

            for d in unknown_detectors(succ + a.get("partial", [])):
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

    # A LINTER THAT PASSES ON NOTHING IS THE DEFECT IT EXISTS TO CATCH. With no files, or
    # files holding no attacks, this printed "linted 0 attacks across 0 file(s)" and then
    # "OK - arsenal clean" and exited 0 -- and it is the only thing in CI that would notice a
    # packaging change dropping the YAML out of the wheel. The README's own sentence: "The
    # corpus IS the product. An install without the YAML is a runner with nothing to run."
    #
    # ZERO, never a specific count. A floor of "at least 300 attacks" would be the arsenal
    # size written a second time, and the second copy is the one that goes stale.
    # The no-FILES case is refused above, before anything is read. This is the other half:
    # files that exist and hold nothing between them, which that guard does not reach.
    if not total:
        errors.append(f"{len(files)} arsenal file(s) and not one attack between them")

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
    # `sys.exit(main())`, not a bare call. The return value was discarded, so an early refusal
    # inside `main` printed its reason and exited 0 — a gate that says REFUSED and lets the
    # build through. The deeper failures reached `sys.exit(1)` directly and worked, which is
    # what kept this invisible: one function, two ways of failing, only one of them wired up.
    sys.exit(main())
