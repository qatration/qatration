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
from workspace import arsenal_files as _arsenal_files


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


def sent_strings(a):
    """Everything an attack actually puts in front of a target, in one place.

    Written out inside `main`'s loop, where only the shipped corpus reaches it, and
    with the reason attached: so a new delivery shape cannot quietly escape the check
    that reads it. It escaped the OTHER way instead -- a second caller, in `run`,
    needed the same list and there was nothing to call.
    """
    if not isinstance(a, dict):
        return []
    out = [a.get("text") or ""]
    out += [str(x) for x in (a.get("steps") or [])]
    out += [str((h or {}).get("content", "")) for h in (a.get("history") or [])]
    out.append(str((a.get("seed") or {}).get("text", "")))
    out.append(str(a.get("user_prompt") or ""))
    return [s for s in out if s]


# WHAT DECIDES A ROW'S VERDICT, reduced to twelve characters. `history.diff` compares two
# runs attack by attack and names every input it can see that moved between them -- the
# model, the engine that judged, the detectors the config armed, the trial count, the
# size of the arsenal. THE ATTACK ITSELF WAS NOT ON THAT LIST, and it is the thing the
# comparison is quantified over: an id is a name, not a prompt.
#
# It moves in practice and it moved here. Fixing the corpus to use RFC 2606 reserved
# space rewrote five attacks across three arsenals without changing the count of any of
# them, so the one confound that could have noticed -- `arsenal N -> M attacks` -- saw
# nothing. A verdict that moved for that reason reads as the target getting better.
#
# Both halves are here because both move a verdict: what is SENT (the strings, the
# encoding applied to them, the delivery that carries them) and what SCORES it (the
# detectors named success or partial, and the scored_by rule). `applies_to` and any
# note are deliberately outside it -- they decide whether the attack runs, not what it
# does when it does, and 177 ids differ across arsenals by `applies_to` alone.
#
# THE FIRST VERSION MISSED FOUR, and the way to find them was to read what `run_attack`
# and `judged_ctx` actually take off an attack rather than to reason about the schema:
#
#   plants           `judged_ctx` merges it into `planted_markers`, which is the whole
#                    input to `marker_echoed`
#   expects_refusal  the same function turns it into `ctx["expects_refusal"]`, which
#                    decides whether a refusal is the finding or the pass
#   seed doc/field   `target.seed(attack["seed"])` is handed the WHOLE mapping, and
#                    `sent_strings` reads only its `text`: poisoning the refunds document
#                    and poisoning the returns one are two attacks under one id
#   history roles    a forged turn attributed to the assistant is a different attack from
#                    the same words attributed to the user, and only the content was here
#
# Widening it splits no group in the corpus (1,060 attacks) and none in the stored
# evidence, which is why it costs nothing -- and is exactly why it had to be measured
# rather than assumed: a digest that ignores a field is silent in the one case the
# comparisons that read it exist for.
def attack_digest(a):
    """-> 12 hex characters over what this attack sends and how it is judged."""
    import hashlib, json as _json
    if not isinstance(a, dict):
        return ""
    seed = a.get("seed") if isinstance(a.get("seed"), dict) else {}
    body = {
        "sent": sent_strings(a),
        "encode": a.get("encode"),
        "delivery": a.get("delivery"),
        "success": sorted(str(x) for x in (a.get("success") or [])),
        "partial": sorted(str(x) for x in (a.get("partial") or [])),
        "scored_by": a.get("scored_by"),
        "plants": sorted(str(x) for x in (a.get("plants") or [])),
        "expects_refusal": bool(a.get("expects_refusal")),
        "seed_at": [seed.get("doc"), seed.get("field")],
        "roles": [str((h or {}).get("role", "user")) for h in (a.get("history") or [])],
    }
    blob = _json.dumps(body, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:12]


# IN A URL, not in prose. `version 1.2.3.4 of the spec` is four numbers and a full stop,
# and refusing an arsenal over it would be the same damage as missing the real one. The
# address has to be reached FOR: preceded by a scheme's `//`, or followed by a path or a
# port, which is what an instruction to send data somewhere looks like.
_IP_LITERAL = re.compile(
    r"(?:(?<=//)((?:\d{1,3}\.){3}\d{1,3})(?![\w.])"
    r"|(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?=[:/]))")


def reachable_addresses(text):
    """Every IP literal in a payload that reaches somebody else's machine today.

    `registrable_hosts` beside this asks whether a NAME could be owned. An address
    needs no owning: `https://8.8.8.8/ingest` in an attack tells an agent to send data
    to a machine that answers now, and the host scan could not see it -- it matches
    dotted names, and 8.8.8.8 is not one.

    GLOBALLY REACHABLE ONLY, which is the whole distinction. An SSRF attack SHOULD name
    `169.254.169.254` and `10.0.0.5`: those are the target's own inside, they are the
    test, and they reach nobody else. Four attacks in this corpus do exactly that and
    none of them names a routable address, which is what makes `is_global` the right
    question rather than a guess.
    """
    import ipaddress
    out = set()
    for groups in _IP_LITERAL.findall(str(text)):
        m = next((g for g in groups if g), "")
        try:
            ip = ipaddress.ip_address(m)
        except ValueError:
            continue
        if ip.is_global:
            out.add(m)
    return out


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
    # THE PACKAGE, NOT `ROOT`. `ROOT` is where the corpus is, and `test_lint` redirects it to
    # a temporary directory holding two YAML files — so a scan rooted there finds no Python at
    # all, returns nothing, and calls every key in every attack unknown. The suite caught that
    # on the first run: `text` reported as a key nothing reads.
    here = root or os.path.dirname(os.path.abspath(__file__))
    # THROUGH `workspace.scan_source_keys`, which is the same eight lines `engine_keys`
    # below and the two config scans in `workspace` each had a copy of. The patterns are
    # what differs between them; the scan is not.
    from workspace import scan_source_keys as _scan
    pats = (r'\ba\.get\(\s*["\']([a-z_]+)["\']',
            r'\ba\[["\']([a-z_]+)["\']\]',
            r'attack\.get\(\s*["\']([a-z_]+)["\']',
            r'attack\[["\']([a-z_]+)["\']\]',
            r'atk\.get\(\s*["\']([a-z_]+)["\']',
            r'_at\.get\(\s*["\']([a-z_]+)["\']')
    return _scan(here, pats) | set(WRITTEN_NOT_READ)


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
    for fname in _arsenal_files(root or ROOT):
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
    # THE CACHE REMEMBERS THE ANSWER AND HAS TO REMEMBER THE QUESTION. It used to key on
    # nothing: the first call with `root=None` stored whatever `ROOT` pointed at, and `ROOT`
    # is a module global that both this file's own `main` and the suites reassign. Any
    # caller reached from inside a fixture directory therefore froze the answer to that
    # fixture's corpus for the life of the process, and the next honest call got it back.
    #
    # It stayed hidden while every caller was `main`, which sets `ROOT` and then asks. It
    # surfaced the moment `unusable_entries` -- reached from a fixture run -- started
    # asking too: `list_attack_fields()` returned {'success'} for the rest of the process,
    # so `applies_to` was no longer a list field and the rule about it silently did nothing.
    global _LIST_FIELDS
    here = root or ROOT
    if _LIST_FIELDS is not None and _LIST_FIELDS[0] == here:
        return _LIST_FIELDS[1]
    import glob as _glob
    import io as _io
    import yaml as _yaml
    seen = {}
    for fn in _arsenal_files(here):
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
    _LIST_FIELDS = (here, out)
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


def _unchanged(e, enc):
    """True when applying `enc` to this attack's payload gives the payload back.

    Compared after the plain-language line the strategies prepend, because that line is not
    the payload: every strategy adds one, and comparing with it attached would say every
    transform did something.
    """
    from encoders import apply_encoding
    from encoders import _plain as _body
    for s in sent_strings(e):
        if not isinstance(s, str) or not s.strip():
            continue
        try:
            out = apply_encoding(s, enc)
        except Exception:
            # An encoder that raises is the OTHER branch's finding, not this one's.
            return False
        if _body(out).strip() == s.strip():
            return True
    return False


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
    from encoders import apply_encoding, decode, ONE_WAY
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
        # AND THE SAME NO-OP UNDER ANY OTHER NAME. The rule above was written for the one
        # encoder that had been caught doing it, and `quoted_printable` was doing it in two
        # shipped arsenals at the same time: RFC 2045 escapes only non-ASCII, `=` and
        # trailing whitespace, so a plain English instruction came back byte for byte,
        # under a header announcing it was encoded. Whether a transform no-ops is a property
        # of the encoder AND the payload together, which is why it has to be asked here,
        # about this attack's own text, rather than once about the encoder.
        elif _unchanged(e, enc):
            out.append((who, "encode: %s leaves this payload byte for byte unchanged, so the attack "
                             "goes to the target in the clear under an encoded name. A "
                             "DEFENDED verdict then describes a model that was shown the "
                             "plain words -- credit for resisting a technique it was never "
                             "shown." % enc))
        else:
            # AND A MARKER THE ENCODING DESTROYS. `plants:` names a string the attack puts
            # into the target and later asks it to repeat, and `marker_echoed` is the
            # detector that decides whether it did. Encoding the text encodes the marker
            # with it: a strategy that cannot be read back cannot carry one, so the model
            # echoes something else, the detector cannot fire, and the run reports
            # DEFENDED against an attack that was never asked properly.
            #
            # Nothing in the shipped corpus does this today. It is legal in the schema and
            # silent when it happens, which is the combination worth refusing before the
            # probes are sent rather than reading in a report afterwards.
            _plants = e.get("plants")
            _marks = [str(m) for m in (_plants if isinstance(_plants, list)
                                       else [_plants] if _plants else [])]
            if _marks:
                _sent = apply_encoding(str(e.get("text") or ""), enc)
                # COMPARED THE WAY THE ORACLE COMPARES: `_markers` lower-cases both
                # sides, so a strategy that only folds case carries a marker fine and
                # refusing it would block an attack that works.
                _back = decode(_sent, enc)
                _back = _back.lower() if _back is not None else None
                if _back is None:
                    out.append((who, "encode: %s cannot be read back (%s), and this attack "
                                     "plants %s. The marker is encoded along with the text, "
                                     "so the target echoes something else and "
                                     "`marker_echoed` cannot fire: the attack scores as a "
                                     "defence."
                                % (enc, ONE_WAY.get(enc, "no inverse"),
                                   ", ".join(repr(m) for m in _marks))))
                else:
                    _lost = [m for m in _marks if m.lower() not in _back]
                    if _lost:
                        out.append((who, "encode: %s does not carry %s through intact "
                                         "(it comes back as %r). The target is asked to "
                                         "repeat a string that was never sent, so a perfect "
                                         "echo scores as a defence."
                                    % (enc, ", ".join(repr(m) for m in _lost), _back[:80])))
    return out


def unscored_properties(entries):
    """-> [(id, why)] for objectives whose combined test silently drops a property.

    `achieved_combined` requires EVERY property's own condition to hold on the combined
    payload -- that is what "combined" means -- and it builds that list as the
    properties which declare a `success:`. A property without one is not judged
    strictly; it is dropped, and `all()` over fewer conditions is EASIER to satisfy.

    Which way that fails is the point. `combined` open is what `_verdict` reads as
    EXPLOITED, so an objective with three properties and two scoring lists reports the
    combination as achieved when two thirds of it held. A manufactured finding, in the
    one direction this engine must never drift.

    The mirror is safe and stays that way: `_achieved` returns False for a property with
    no usable detector names, so a property is never demonstrated by having nothing to
    demonstrate.

    ALL-OR-NOTHING IS NOT REFUSED. An objective whose properties declare no scoring at
    all falls back to the objective's own `success:` list, which is the documented older
    shape and is judged whole. Only the MIXED one narrows the test without saying so.
    """
    out = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        props = [p for p in (e.get("properties") or []) if isinstance(p, dict)]
        scored = [p for p in props if p.get("success")]
        if not props or not scored or len(scored) == len(props):
            continue
        _blank = [str(p.get("name") or "??") for p in props if not p.get("success")]
        out.append((e.get("id") or "?",
                    "%d of %d properties declare no `success:` (%s), and the combined test requires every property that DOES. A property with none is dropped from it, so the combination is judged on the rest -- and a combined payload that satisfied only those reads as EXPLOITED."
                    % (len(_blank), len(props), ", ".join(_blank[:4]))))
    return out


def refuse_unknown_detectors(entries, what, path, nested=False):
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
    # AND A KEY THAT LOOKS LIKE ONE THIS ENGINE READS. `unusable_entries` does this for
    # an arsenal against the tighter attack vocabulary; an objective's readers are named
    # too many ways to derive a set that precisely, so it is asked against the whole
    # engine's vocabulary here. Walked, one typo at a time: `properites:` and `probe:`
    # misspelt come out as a traceback telling the customer it is a bug in this tool,
    # `combind:` silently drops the combined probe and turns EXPLOITED into PARTIAL, and
    # `applies_too:` runs an objective written for one bot against every one of them.
    # ASKED OF THE CALLER, NOT OF THE DATA. The first version of this looked for
    # entries that HAVE `properties`, which is defeated by exactly the typo that
    # matters most: misspell `properties:` and there are no objectives to check, so the
    # check that would have named it does not run. A corpus knows what it is; a corpus
    # with a typo in it does not.
    _objs = [e for e in entries if isinstance(e, dict)] if nested else []
    if _objs:
        _vocab = engine_keys()
        _typos = []
        for e in _objs:
            _typos += misspelt_keys(e, what, _vocab)
            for _p in (e.get("properties") or []):
                _typos += misspelt_keys(
                    _p, what, _vocab,
                    "property %r" % (_p.get("name") or "??") if isinstance(_p, dict)
                    else "")
        if _typos:
            raise SystemExit(
                "%s: %d key(s) in %s look like keys this engine reads and are not. Nothing was sent.\n" % (what, len(_typos), path)
                + "\n".join("    " + s for s in _typos[:8]))

    # AND A COMBINED TEST THAT DROPS HALF ITS OWN CONDITIONS. Refused here rather than
    # warned, for the reason above it: after this point every signal is a measurement
    # of something narrower than the objective says it is.
    _unscored = unscored_properties(entries)
    if _unscored:
        raise SystemExit(
            "%s: %d objective(s) in %s would be judged on fewer properties than they declare. Nothing was sent.\n" % (what, len(_unscored), path)
            + "\n".join("    %-22s %s" % (who, why) for who, why in _unscored[:8]))
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




def engine_keys(root=None):
    """Every string this package ever reads off a mapping, as one vocabulary.

    `attack_keys_read` is precise about ATTACKS because their readers are named `a`,
    `attack`, `atk`. An objective's readers are not: `objective`, `obj`, `o`, `spec`,
    `prop`, `p`, `tasks`, and `task_self` is reached as `tasks[key]` with the key held
    in a variable. A precise set for objectives would be a guess, and a guess that
    misses a real key refuses a valid file -- the wrong direction to be wrong in.

    So this is deliberately WIDE: every `x.get("k")` and `x["k"]` literal in the
    package, which over-collects on purpose. Over-collecting only ever costs a missed
    typo (`probes:` in an objective is a real key elsewhere, so it passes), and never
    refuses a key some part of this engine actually reads.
    """
    here = root or os.path.dirname(os.path.abspath(__file__))
    from workspace import scan_source_keys as _scan
    pats = (r'\b[A-Za-z_][A-Za-z_0-9]*\.get\(\s*["\']([a-z_][a-z_0-9]*)["\']',
            r'\b[A-Za-z_][A-Za-z_0-9]*\[\s*["\']([a-z_][a-z_0-9]*)["\']\s*\]')
    keys = _scan(here, pats)
    # Reached with a variable key, so no literal scan can find it. Named here rather
    # than in a comment, because a key this rule cannot see is a file it would refuse.
    return keys | {"task_self"} | set(WRITTEN_NOT_READ)


def misspelt_keys(a, fname="arsenal", known=None, where=""):
    """-> sentences for keys that look like a typo of a key this engine reads.

    A KEY NOTHING READS IS AN INSTRUCTION NOTHING FOLLOWS, and `lint.main` has said so
    since it was written -- about the shipped corpus, which is the one file that never
    has the problem. `run --attacks mine.yaml` takes any path. Walked: an arsenal with
    `encoding:`, `plnts:` and `expects_refusl:` ran, sent the attack in plain text
    under an encoded name, planted nothing, expected no refusal, and said none of it.

    A NEAR MISS, NOT AN UNKNOWN KEY, and the difference matters at this door. `main`
    refuses any key it does not read, which is right for a curated corpus and hostile
    to a customer who annotates their own file with `owner:` or `ticket:`. Measured
    over this engine's 32 keys: the typos score 0.71 to 0.97 against their intended
    key and plausible annotations score 0.44 to 0.62, so the line sits between
    `encoding` -> `encode` at 0.71 and `severity` -> `delivery` at 0.62. Both ends are
    pinned in `test_lint`, because a cutoff nobody measured is a cutoff that drifts.

    AND THE INTENDED KEY MUST BE ABSENT. An attack carrying both `encode: base64` and
    its own `encoding: utf-8` is annotating, not misspelling, and nothing here should
    have an opinion about it.
    """
    from workspace import near_miss_keys
    if not isinstance(a, dict):
        return []
    known = attack_keys_read() if known is None else known
    aid = (a.get("id") or a.get("name") or "??")
    if where:
        aid = "%s: %s" % (aid, where)
    out = []
    for k, near in near_miss_keys(a, known):
        out.append("%s: %s: %r is not a key this engine reads, and it looks like "
                   "%r. Nothing would follow it: the field is simply never looked at, "
                   "and every layer downstream describes the attack as though it had "
                   "been." % (fname, aid, k, near))
    return out


def unusable_entries(attacks, fname="arsenal"):
    """The entry faults a RUN cannot survive, as a list of sentences.

    These three lived inside `main`, which meant only the shipped corpus was checked for
    them. `run --attacks mine.yaml` takes any file, and a customer writing their own
    arsenal got: a missing `category` crashing the sweep at
    `a["category"]` AFTER the probes were sent, so their target's budget was spent and the
    answer was a traceback; and a duplicate id sent twice, landing two rows under one id in
    a results file that `history`, `verify` and `rejudge` all key by it.

    The rest of the linter stays where it is. These are the ones that make a run
    misbehave rather than make an arsenal worse, which is why they are the ones the run
    needs before it sends anything.
    """
    out, seen = [], {}
    for i, a in enumerate(attacks or []):
        if not isinstance(a, dict):
            out.append("%s #%d: entry is %s, not a mapping" % (fname, i, type(a).__name__))
            continue
        aid = a.get("id")
        if not aid:
            out.append("%s #%d (??): missing 'id'" % (fname, i))
            continue
        if aid in seen:
            out.append("%s: %s: duplicate id (also at #%d)" % (fname, aid, seen[aid]))
        seen[aid] = i
        if not a.get("category"):
            out.append("%s: %s: missing 'category'" % (fname, aid))
        out += bad_delivery(a, fname)
        out += misspelt_keys(a, fname)
    # NOT `bad_entry_shapes` HERE, and the absence is the point. It is already raised by
    # `refuse_unknown_detectors`, which both `run_redteam` and `run_isolation` call before
    # anything is sent -- shape before spelling, with the reason written there. Adding it
    # to this function too would be a second implementation of one rule at one door, which
    # is the mistake `workspace.BROKE` and `runner.attacker_side` were each collapsed out of.
    return out


def bad_delivery(a, fname="arsenal"):
    """The delivery faults a RUN cannot survive, for one entry, as sentences.

    THE RULE WAS HERE AND THE DOOR WAS NOT. `main` has checked delivery shapes since
    they were written, and `main` only ever sees the shipped corpus. `run --attacks
    mine.yaml` takes any file, and a customer who types `delivery: chian` gets one of
    two things, both bad:

      * with `steps` and no `text`, a `KeyError: 'text'` out of the runner, mid-sweep,
        after the attacks before it in the file have already been sent -- and the
        crash handler tells them this is a bug in qatration and not a problem with
        their config, which is wrong on the second clause;
      * with a `text` as well, SILENCE. The unknown name falls through to the direct
        branch, so a multi-turn attack is delivered as a single prompt, DEFENDED
        describes an attack that was never delivered the way it was written, and
        nothing anywhere says so. That is the worse one.

    The shape checks come with it, for the same reason: `chain` with no `steps` reaches
    the same `KeyError` by the other route.
    """
    from runner import DELIVERIES
    import difflib
    aid = a.get("id") or "??"
    d = a.get("delivery", "direct")
    if d not in DELIVERIES:
        near = difflib.get_close_matches(str(d), list(DELIVERIES), n=1, cutoff=0.6)
        return ["%s: %s: delivery %r is not one this build has%s. An unknown name is not refused by the runner -- it falls through to the direct branch, so a multi-turn attack is sent as a single prompt and a DEFENDED verdict describes an attack that was never delivered." % (fname, aid, d,
                                   " -- did you mean %r?" % near[0] if near else
                                   "; it has: %s" % ", ".join(sorted(DELIVERIES)))]
    # EMPTY IS NOT ABSENT. `text: ""` is falsy, and the one probe whose payload IS the
    # empty string has to be writable: a deployment that answers nothing with its whole
    # system prompt has a bug nobody had to attack it to find.
    need = {"direct": ("text",), "indirect": ("seed", "user_prompt"),
            "chain": ("steps",), "sessions": ("steps",),
            "forged_history": ("history", "text")}[d]
    missing = [k for k in need
               if (a.get(k) is None if k == "text" else not a.get(k))]
    if missing:
        return ["%s: %s: %s delivery needs %s, and the run reads it without checking -- a missing one is a KeyError mid-sweep, after the attacks before it have been sent%s" % (fname, aid, d, " + ".join("'%s'" % k for k in need),
                   " (use `text: \"\"` if the empty prompt is the point)"
                   if d == "direct" else "")]
    return []


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
    # THROUGH THE SHARED ENUMERATION. This globbed, so one leftover scratch file made
    # `qatration lint` report an error in a file nobody ships and exit 1.
    files = _arsenal_files(ROOT)
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
        # THE THREE A RUN CANNOT SURVIVE, through the function the run calls too. They
        # were written here and only here, so `run --attacks mine.yaml` never saw them.
        errors += unusable_entries(attacks, fname)
        seen = {}                                  # ids must be unique WITHIN a file
        for i, a in enumerate(attacks):
            aid = a.get("id")
            where = f"{fname} #{i} ({aid or '??'})"
            if not aid:
                continue

            # SEE registrable_hosts. Everything the attack actually sends, in one place, so a
            # new delivery shape cannot quietly escape the check -- and through the shared
            # assembly, because `run` needs the same list to warn a customer about their own.
            sent = sent_strings(a)
            for host in sorted(registrable_hosts(" ".join(sent))):
                errors.append(
                    f"{fname}: {aid}: payload names {host}, which is registrable. Use RFC 2606 "
                    f"reserved space (.example) — an agent told to send data to a name somebody "
                    f"can own will send it to whoever owns it")
            # AND AN ADDRESS NEEDS NO REGISTERING AT ALL. The scan above matches names,
            # so `https://8.8.8.8/ingest` walked past it: a machine that answers today,
            # named in an instruction handed to an agent. The SSRF attacks here are
            # untouched, because they name the target's own inside rather than a
            # routable address, and that is exactly the line `is_global` draws.
            for addr in sorted(reachable_addresses(" ".join(sent))):
                errors.append(
                    f"{fname}: {aid}: payload names {addr}, which is a globally routable "
                    f"address — an agent told to send data there sends it to whoever runs "
                    f"that machine. RFC 5737 documentation space (192.0.2.0/24) reaches "
                    f"nobody and tests the same behaviour")
            seen[aid] = i


            # THE DELIVERY SHAPE IS NOT CHECKED HERE ANY MORE. It was written out in this
            # loop, where only the shipped corpus reaches it, and it now lives in
            # `unusable_entries` -- the door a customer's `--attacks` file comes through --
            # which this function already calls for every file above. Checking again here
            # would report each fault twice.
            if a.get("delivery") == "forged_history":
                # `unusable_entries` has already refused a forged_history with no `history`
                # at all, so this asks only about the shape of one that has entries.
                hist = a.get("history") or []
                if hist and not any(h.get("role") == "assistant" for h in hist):
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
            # STRICTER HERE THAN AT THE DOOR, deliberately. This walks the corpus this
            # repository ships, where a key nothing reads is a mistake rather than an
            # annotation; `unusable_entries` refuses only the NEAR MISSES, because a
            # customer's own file may carry `owner:` or `ticket:` and that is theirs.
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
    # THROUGH THE ENGINE'S OWN TRANSLATION, so this file answers a refusal and a crash
    # with the code the table reserves rather than with 1, which is a finding.
    from workspace import run_command as _run_command
    sys.exit(_run_command(main))
