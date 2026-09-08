"""One place decides where artifacts go — no model, no network.

Thirteen modules used to answer that question and they answered it four different ways:
`Path(__file__).resolve().parents[1] / "out"`, `os.path.join(ROOT, "out")`,
`os.path.join(os.path.dirname(ROOT), "out")`, and a spelled-out double `dirname` — because
`ROOT` means the package directory in some files and the repository in others. Two more
built a RELATIVE default, `os.path.join("out", …)`, which is a working-directory dependency
by another name in a repo that had just finished removing its last one.

All of them landed on the same folder, which is the kind of agreement that holds until it
does not: one module moved a directory deeper, or one `ROOT` renamed to match its
neighbours, and a writer starts writing where no reader looks. A result nobody reads is a
gap reported as a measurement, arriving by the dullest possible route.

The checks below are in two halves. The first is arithmetic on `workspace.out_dir()`. The
second is the one that matters and the one that goes stale on its own: **every module that
names an artifact root must resolve to the same string**, asserted by importing them and
comparing, not by reading the source. A fourteenth module can be added tomorrow with its own
`parents[1] / "out"` and this is what says so.

    python test_workspace.py       # exits 1 on any failure (CI gate)
"""
import sys, os, ast, glob, importlib
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
ROOT = os.path.dirname(HERE)

import workspace

# Every module that holds an artifact root, and the name it holds it under. Listed rather
# than discovered, because a module that STOPS exposing one has to be noticed too: a missing
# name fails here instead of quietly shrinking the check.
ROOTED = {
    "baseline": "OUT_DIR", "benign": "OUT_DIR", "build_index": "OUT",
    "compare_recon": "OUT_DIR", "compare_targets": "OUT_DIR", "defense_report": "OUT_DIR",
    "detector_coverage": "OUT", "discrimination": "OUT", "history": "OUT",
    "model_matrix": "OUT", "rejudge": "OUT_DIR", "run_adaptive": "OUT_DIR",
    "run_redteam": "OUT_DIR",
}


def builds_its_own_root(src):
    """-> [(line, expression)] for every path expression that joins the literal "out".

    Parsed rather than grepped: the last gate written here failed on the docstring that
    explained the defect it guarded, and a check that fires on its own explanation is one
    nobody keeps. `workspace.py` itself is the one file allowed to do this — it is the place
    the answer is supposed to live.
    """
    found = []
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Call):
            f = node.func
            name = getattr(f, "attr", "")
            if name == "join" and any(isinstance(a, ast.Constant) and a.value == "out"
                                      for a in node.args):
                found.append((node.lineno, "os.path.join(..., 'out')"))
        # Path(...) / "out"
        if (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div)
                and isinstance(node.right, ast.Constant) and node.right.value == "out"):
            found.append((node.lineno, "Path(...) / 'out'"))
    return found


def check_every_command_refuses():
    """The rule had nowhere to live, so eight commands were missing it.

    Ten commands read a target config and every one calls `yaml.safe_load` itself: there is no
    shared loader, so the checks that stop a manufactured finding were written into `run` and
    `onboard` and were absent from the rest. `benign` is the worst of those by some distance —
    it is the command this tool TELLS an operator to run to measure their false-positive rate,
    and with `canaries: "ACME"` it would report a wall of noise the operator would read as the
    detector being broken. `verify` re-sends the findings a report claims. `isolation`
    publishes HARDENED.

    THE SET IS SCANNED, not listed, so a command added on a Monday joins by existing. A module
    that takes `--target-config` and parses YAML is one of these, and it must name the shared
    refusal; anything else is a module that reads a config and cannot tell a usable one from a
    config that manufactures breaches.
    """
    import glob as _g
    import io as _io
    import os as _os
    import workspace as _ws
    fails = []

    def check(label, got, want):
        print("%s  %s -> %r" % ("PASS" if got == want else "FAIL", label, got))
        if got != want:
            fails.append("%s: %r != %r" % (label, got, want))

    _here = _os.path.dirname(_os.path.abspath(_ws.__file__))
    _readers, _missing = [], []
    for _fp in sorted(_g.glob(_os.path.join(_here, "*.py"))):
        _name = _os.path.basename(_fp)
        if _name.startswith("test_"):
            continue
        _src = _io.open(_fp, encoding="utf-8").read()
        # THE ARGPARSE FLAG, not a mention of the word. A first attempt matched any module
        # holding "target_config" and "yaml.safe_load", which is nine modules that merely SCAN
        # every shipped config — `build_index`, `rejudge`, `detector_coverage` — and refusing
        # there would fail a report over a config the run already used. A command that
        # declares `--target-config` is one a person points at a file.
        if 'add_argument("--target-config"' not in _src:
            continue
        _readers.append(_name)
        # THE CALL, NOT THE IMPORT. A first version looked for the name in the source, and
        # deleting the call while leaving `from workspace import refuse_unusable_config`
        # passed it — an import that nothing invokes is exactly the shape of the defect.
        import ast as _ast
        _alias, _called = None, False
        try:
            _tree = _ast.parse(_src)
        except SyntaxError:
            _tree = None
        for _node in _ast.walk(_tree) if _tree else []:
            if isinstance(_node, _ast.ImportFrom) and _node.module == "workspace":
                for _a in _node.names:
                    if _a.name == "refuse_unusable_config":
                        _alias = _a.asname or _a.name
            elif (isinstance(_node, _ast.Call) and isinstance(_node.func, _ast.Name)
                  and _alias and _node.func.id == _alias):
                _called = True
        if not (_alias and _called):
            _missing.append(_name)

    check("the commands that read a target config can be found", len(_readers) >= 8, True)
    # `onboard` reports these as problems rather than raising, because refusing is the whole
    # job of the command and it has its own report to put them in; `sarif` reads a config only
    # to look up canaries for a run that already happened, and refusing there would fail an
    # export over evidence already on disk.
    _EXEMPT = {
        "onboard.py": "reports them in its own problem list rather than raising; refusing a "
                      "config IS this command, and it must say everything wrong at once",
        "sarif.py": "reads a config to look up the canaries of a run that already happened; "
                    "refusing would fail an export over evidence already recorded",
    }
    check("every exemption names a file that still reads a config",
          sorted(set(_EXEMPT) - set(_readers)), [])
    check("...and gives a reason", all(_EXEMPT.values()), True)
    check("no command reads a target config without the shared refusal",
          sorted(set(_missing) - set(_EXEMPT)), [])

    # --- AND A KEY THAT LOOKS LIKE ONE THE ENGINE READS ---------------------------------
    #
    # `test_http_adapter` has asked since it was written that no SHIPPED config declares a
    # top-level key nothing reads, and it wrote the consequence down: a config saying
    # `gaurd: false` is not refused and not applied, so the bot stays guarded and the
    # published numbers describe a different deployment from the file. Every command takes
    # `--target-config <a path somebody typed>`, and that copy never reached the rule --
    # the fifth time in this engine that a check was aimed only at files already passing it.
    import glob as _g_c, io as _io_c, os as _os_c, yaml as _y_c
    _here_ws = _os_c.path.dirname(_os_c.path.abspath(_ws.__file__))
    _CFG = {"adapter": "http", "name": "b", "url": "http://127.0.0.1:9/x",
            "request": {"message": "{prompt}"}, "response": {"reply": "reply"},
            "oracle_context": {"canaries": ["ACME-CANARY-9931"]}}

    def _cfg_refused(c):
        try:
            _ws.refuse_unusable_config(c, "run")
            return ""
        except SystemExit as e:
            return str(e)

    def _swapk(d, old, new):
        e = dict(d)
        e[new] = e.pop(old)
        return e

    for _bad, _meant in (("gaurd", "guard"), ("adaptor", "adapter"),
                         ("respons", "response"), ("histroy", "history"),
                         ("rat", "rate")):
        _c = (_swapk(_CFG, _meant, _bad) if _meant in _CFG
              else dict(_CFG, **{_bad: True}))
        check("a config key %r is refused" % _bad,
              "looks like %r" % _meant in _cfg_refused(_c), True)
    check("...and the message says the run would describe the wrong deployment",
          "rather than the way it is" in _cfg_refused(dict(_CFG, gaurd=False)), True)

    # NOT THE ANNOTATIONS, and `notes:` is the one that decides the design. Against the WIDE
    # membership set it reads as a misspelling of `note` -- a key no config has ever had,
    # swept in from readers of run records that use the same variable name -- and the
    # message would send the reader looking for it. So the suggestion is drawn from a
    # tighter set than the membership test.
    # `author` IS NOT ON THIS LIST, and that is a measured cost rather than an oversight:
    # `auth:` is a real config key, so `author:` beside no `auth:` reads as a misspelling of
    # it and is refused. Naming the collision here rather than widening the rule until it
    # catches nothing.
    for _ann in ("owner", "ticket", "notes", "severity", "tags", "comment"):
        check("a config annotation %r is not refused" % _ann,
              _cfg_refused(dict(_CFG, **{_ann: "x"})), "")
    check("a well-formed config is not refused", _cfg_refused(_CFG), "")
    # AND A KEY BESIDE THE ONE IT RESEMBLES IS AN ANNOTATION. A config carrying `guard:` and
    # its own `guards:` note is not misspelling anything, and nothing here should have an
    # opinion about it.
    check("...nor one whose near-miss sits beside the real key",
          _cfg_refused(dict(_CFG, guard=True, guards="two of them")), "")

    # AND EVERY CONFIG THIS REPOSITORY SHIPS PASSES, or the rule is one nobody could adopt.
    _refused = {}
    for _fp in _shipped_configs():
        try:
            _said = _cfg_refused(
                _y_c.safe_load(_io_c.open(_fp, encoding="utf-8")) or {})
        except Exception as _e:
            _said = "%s: %s" % (type(_e).__name__, _e)
        if _said:
            _refused[_os_c.path.basename(_fp)] = _said[:120]
    check("no config this repository ships is refused by the rule", _refused, {})

    # THE TWO SETS ARE DIFFERENT AND BOTH ARE NEEDED. A key missing from the suggestion set
    # costs nothing -- it is still known, so never a candidate -- and a key spuriously IN it
    # invents a refusal.
    _wide, _tight = _ws.config_keys_read(), _ws.config_key_suspects()
    check("the suggestion set is a subset of what counts as known",
          sorted(_tight - _wide), [])
    check("...and is genuinely tighter, or the distinction is decorative",
          len(_wide) > len(_tight), True)
    check("...with `note` out of it, which is the entry that invented a refusal",
          "note" in _wide and "note" not in _tight, True)
    check("...and every key a shipped config uses still counts as known",
          sorted({_k for _fp in _shipped_configs()
                  for _k in (_y_c.safe_load(_io_c.open(_fp, encoding="utf-8")) or {})}
                 - _wide), [])

    # AND THE REFUSAL REFUSES. A scan asserting a call exists in ten files says nothing about
    # what the call does.
    def _refused(cfg):
        try:
            _ws.refuse_unusable_config(cfg, "test")
        except SystemExit as e:
            return str(e)
        return ""

    check("a scalar canary is refused",
          "one character at a time" in _refused({"oracle_context": {"canaries": "ACME"}}), True)
    check("a broken refusal vocabulary is refused",
          "not a class this classifier names" in _refused(
              {"oracle_context": {"refusal_patterns": {"refusal_contnet": ["x"]}}}), True)
    check("...and the message names the command that stopped",
          _refused({"oracle_context": {"canaries": "A"}}).startswith("test:"), True)
    check("a usable config is not refused",
          _refused({"oracle_context": {"canaries": ["ACME-CANARY-9931"]}}), "")
    check("...nor is one with no oracle_context at all", _refused({"adapter": "http"}), "")

    # --- AND THE OTHER HALF: A PATH THAT IS NOT THERE ------------------------------------
    #
    # The rule above is about what a config CONTAINS. Whether it could be READ was a second
    # rule with the same history and it was never finished: `run` grew a `_load` closure,
    # which is a rule no sibling can call, `generate` wrote a second copy of it, and five
    # commands opened the path bare.
    #
    # WALKED. `qatration benign --target-config nope.yaml`, and the same for `verify`,
    # `recon`, `isolation` and `matrix`, each answered a mistyped filename with a Python
    # traceback under the sentence `This is a bug in qatration, not a finding about your
    # target and not a problem with your config` -- wrong on the last clause, and it asks
    # the reader to file a bug for their own typo. The exit code was 2 either way, so a
    # pipeline was never misled and only the person was.
    #
    # DRIVEN AS PROCESSES over the same scanned set, because the thing under test is what
    # a shell sees. An in-process call would exercise the function and not the command, and
    # the function was never the part that was missing.
    import subprocess as _sp
    import sys as _sys
    import tempfile as _tfp
    import cli as _cli
    _mod_to_cmd = {}
    for _cmd, (_mod, _blurb) in _cli.COMMANDS.items():
        _mod_to_cmd.setdefault(_mod + ".py", _cmd)
    # A reader with no command is reachable only as a module, so a person cannot mistype a
    # path into it. Named rather than dropped, so the two sets stay comparable.
    _drivable = [(_mod_to_cmd[_n], _n) for _n in _readers if _n in _mod_to_cmd]
    check("the readers that a person can actually type a path into are found",
          len(_drivable) >= 7, True)

    _crashed, _wrong_code = [], []
    _env = dict(_os.environ, PYTHONDONTWRITEBYTECODE="1", QATRATION_OUT=_tfp.mkdtemp())
    # `matrix` compares stored per-model runs and refuses before that without a mode, so it
    # is given the one that reaches the config read. Nothing here reaches a network: every
    # one of these must stop at the path.
    _EXTRA = {"matrix": ["--from-disk"], "sarif": ["--results", "nope.json"]}
    for _cmd, _n in sorted(_drivable):
        _p = _sp.run([_sys.executable, _os.path.join(_here, "cli.py"), _cmd,
                      "--target-config", "definitely-not-here.yaml"] + _EXTRA.get(_cmd, []),
                     capture_output=True, text=True, timeout=180, env=_env,
                     cwd=_os.path.dirname(_here))
        _out = (_p.stdout or "") + (_p.stderr or "")
        if "Traceback (most recent call last)" in _out:
            _crashed.append(_cmd)
        if _p.returncode != 2:
            _wrong_code.append("%s exited %s" % (_cmd, _p.returncode))
    check("no command answers a path that is not there with a traceback",
          sorted(_crashed), [])
    check("...and every one of them exits 2, the code for a refused invocation",
          sorted(_wrong_code), [])

    # AND THE READER ITSELF SAYS WHICH OF THE THREE THINGS WENT WRONG, because `no such
    # file`, `that is a directory` and `that is not YAML` have different remedies.
    def _read(path):
        try:
            _ws.load_yaml_or_refuse(path, "target config", "test")
        except SystemExit as e:
            return str(e)
        return ""

    check("a path that is not there is named", "no target config at" in _read("nope.yaml"),
          True)
    check("...and the command that stopped is named", _read("nope.yaml").startswith("test:"),
          True)
    check("a directory is not reported as a missing file",
          "is a directory" in _read(_here), True)
    # A NAME IS THE COMMONEST WRONG PATH, because `--target` is an unambiguous prefix of
    # `--target-config` and argparse accepts it. Said only for a bare name: a hint printed
    # on every mistyped path is one nobody reads by the third time.
    check("a bare name is diagnosed as the flag trap it usually is",
          "prefix of `--target-config`" in _read("opsbot"), True)
    check("...and a real path that is simply absent is not",
          "prefix of `--target-config`" in _read("configs/opsbot.yaml"), False)
    return fails


def check_esc():
    """One escaper, and a control set that covers what this arsenal attacks with.

    THERE WERE FIVE. `report_engine`, `build_index`, `compare_targets`, `compare_recon` and
    `defense_report` each defined their own, and only one did anything about invisible
    characters — so the same payload rendered two ways on pages built from the same artifact
    minutes apart: the per-target report showed `&lt;U+200B&gt;`, the index showed nothing.

    AND THE SET MISSED THE C0 CONTROLS, which is the half `attacks_ansi.yaml` is built from:
    every ANSI and OSC-8 sequence is ESC (0x1B) and BEL (0x07). A report quoting such a reply
    printed the escape raw, a browser dropped it, and the reader saw `click here` rather than
    the terminal hyperlink that makes it a finding — the evidence rendered as ordinary prose,
    on the page whose whole job is to show what came back.
    """
    from workspace import esc, CONTROL_CHARS
    import report_engine, build_index, compare_targets, compare_recon, defense_report
    fails = []

    def check(label, got, want):
        print("%s  %s -> %r" % ("PASS" if got == want else "FAIL", label, got))
        if got != want:
            fails.append("%s: %r != %r" % (label, got, want))

    check("html is escaped", esc("<script>x</script>"), "&lt;script&gt;x&lt;/script&gt;")
    check("a quote is escaped", esc('a"b'), "a&quot;b")

    # THE TWO FAMILIES, one of which used to render as nothing at all.
    check("a zero-width space is shown", esc("a\u200bb"), "a&lt;U+200B&gt;b")
    check("an ESC is shown", esc("a\x1bb"), "a&lt;U+001B&gt;b")
    check("a BEL is shown", esc("a\x07b"), "a&lt;U+0007&gt;b")
    check("a DEL is shown", esc("a\x7fb"), "a&lt;U+007F&gt;b")
    check("a bidi override is shown", esc("a\u202eb"), "a&lt;U+202E&gt;b")

    # AND AN OSC-8 HYPERLINK, WHOLE, because that is the shipped attack rather than a
    # character in isolation: without this the reader is shown the label and not the link.
    _osc = "\x1b]8;;http://evil.example\x07click here\x1b]8;;\x07"
    check("an OSC-8 terminal hyperlink cannot hide in a report",
          "evil.example" in esc(_osc) and "&lt;U+001B&gt;" in esc(_osc), True)

    # LAYOUT IS NOT CONCEALMENT. Rendering these as codepoints would turn every multi-line
    # payload into noise, so they pass through.
    check("a newline is layout", esc("a\nb"), "a\nb")
    check("a tab is layout", esc("a\tb"), "a\tb")
    check("a carriage return is layout", esc("a\rb"), "a\rb")

    # ONE IMPLEMENTATION, asked of the five pages rather than of the module: a copy could be
    # reintroduced in any of them and every check above would still pass.
    _payload = "x\u200b\x1by"
    for _m in (report_engine, build_index, compare_targets, compare_recon, defense_report):
        check("%s renders it the same way" % _m.__name__, _m.esc(_payload), esc(_payload))

    check("the control set is not empty", bool(CONTROL_CHARS.search("\x1b")), True)
    return fails


def check_context_shapes():
    """A string is iterable, which is the whole defect.

        canaries: "ACME-9931"      ->  'a', 'c', 'e', 'm', '1', '3', '9', '-'

    Nothing raises and nothing is empty; the loop that expected one eight-character token gets
    eight one-character ones, and `canary_in_output` fires on any reply containing the letter
    'a'. Walked against a live endpoint before this existed: a bot answering "Standard shipping
    takes 3-5 business days" came back EXPLOITED 1/1 on `canary_in_output,canary_transformed`,
    "1/1 attacks breached the target", exit 0. Two characters of YAML between that and the
    truth.

    It is the mirror of this project's usual failure -- a finding manufactured rather than a
    gap concealed -- and worse for the reader, who has no way to tell it from a real one.
    """
    from workspace import bad_context_shapes, list_context_keys
    import workspace as _ws
    fails = []

    def check(label, got, want):
        print("%s  %s -> %r" % ("PASS" if got == want else "FAIL", label, got))
        if got != want:
            fails.append("%s: %r != %r" % (label, got, want))

    _keys = list_context_keys()
    check("the list-valued keys can be derived", len(_keys) >= 20, True)
    check("...including the one that manufactures findings", "canaries" in _keys, True)
    # AND NOT A KEY THAT IS A SCALAR BY DESIGN, or every correct config would be refused.
    check("...and not a genuinely scalar one", "caller_id" in _keys, False)
    check("...nor one that is a bool", "pii_expect_phone" in _keys, False)
    # ONE FROM EACH SOURCE, or dropping either scan leaves the other's keys and every check
    # above still passes. `privileged_fields` is a list in the shipped configs and is read by
    # a line this scan's pattern does not match; `own_names` is the reverse.
    check("...a key only the shipped configs show", "privileged_fields" in _keys, True)
    check("...and a key only the source shows", "own_names" in _keys, True)

    _b = bad_context_shapes({"oracle_context": {"canaries": "ACME-9931"}})
    check("a scalar where a list belongs is reported", len(_b), 1)
    check("...naming the key", _b[0][0] if _b else "", "canaries")
    check("...and showing what it would be used as",
          "one character at a time" in (_b[0][1] if _b else ""), True)
    check("...and giving the corrected line",
          "['ACME-9931']" in (_b[0][1] if _b else ""), True)

    check("a list is accepted",
          bad_context_shapes({"oracle_context": {"canaries": ["ACME-9931"]}}), [])
    check("a scalar key that is meant to be scalar is accepted",
          bad_context_shapes({"oracle_context": {"caller_id": "2001"}}), [])
    check("a number where a list belongs is reported too",
          len(bad_context_shapes({"oracle_context": {"canaries": 5}})), 1)
    check("a null is left alone",
          bad_context_shapes({"oracle_context": {"canaries": None}}), [])
    check("no oracle_context is nothing to report", bad_context_shapes({}), [])
    check("an oracle_context that is not a mapping is itself the problem",
          len(bad_context_shapes({"oracle_context": ["oops"]})), 1)

    # A SCAN THAT FOUND NOTHING ACCUSES NOTHING HERE BY CONSTRUCTION, which is why there is
    # no guard for it in `bad_context_shapes` and no check for one: the loop skips every key
    # not in the set, so an empty set skips everything. Its neighbour `unread_context_keys`
    # asks the opposite question and does need the guard — an empty set there would accuse
    # every key in the config — and has a check that fails without it.
    _real = _ws.list_context_keys
    _ws.list_context_keys = lambda root=None: set()
    try:
        check("an empty scan is a no-op rather than an accusation",
              bad_context_shapes({"oracle_context": {"canaries": "X"}}), [])
    finally:
        _ws.list_context_keys = _real

    # AND EVERY SHIPPED CONFIG PASSES, which is what makes the refusal usable rather than a
    # wall — and what fails if a key changes shape and one of forty-three is missed.
    import glob as _g, io as _io, os as _os, yaml as _y
    _here = _os.path.dirname(_os.path.abspath(_ws.__file__))
    _n = 0
    for _fp in _shipped_configs():
        _c = _y.safe_load(_io.open(_fp, encoding="utf-8").read()) or {}
        if not isinstance(_c, dict):
            continue
        _n += 1
        check("%s has a usable context" % _os.path.basename(_fp), bad_context_shapes(_c), [])
    check("...over every config that ships", _n >= 20, True)
    return fails


def check_one_name_rule():
    """What a target name may be, decided in one place by everything that takes one.

    `safe_target_name` exists because the rule was written in `targets_http` and four
    callers then assigned the raw config value onto the target after construction -- its own
    docstring says so. It was lifted out for every adapter that is not the HTTP one, and the
    HTTP one kept its copy: the same regex, the same `.strip(".")` guard, character for
    character. A divergence there is the hardest kind to notice, because both sides refuse
    and the only question is ever which names each one refuses.
    """
    fails = []

    def check(label, ok, detail=""):
        print("%s  %s" % ("PASS" if ok else "FAIL", label))
        if not ok:
            fails.append("%s: %s" % (label, detail))

    import ast as _ast_n, io as _io_n, os as _os_n
    from workspace import safe_target_name as _safe
    from targets_http import HttpConfiguredTarget as _H

    # THE SAME ANSWER FROM BOTH DOORS, on the names that decide the rule.
    for _n in ("ok-name", "fine_1.2", "a.b-c_9"):
        _http = _H(name=_n, url="http://127.0.0.1:9/x").name
        check("both doors accept %r" % _n,
              _http == _safe(_n, "w") == _n, _http)
    for _n in ("../evil", "a/b", ".", "..", "x" * 65, "", "  ", "a b", "a\\b"):
        _a = _b = None
        try:
            _H(name=_n, url="http://127.0.0.1:9/x")
        except SystemExit as _e:
            _a = str(_e)
        try:
            _safe(_n, "w")
        except SystemExit as _e:
            _b = str(_e)
        check("both doors refuse %r" % _n, bool(_a) and bool(_b),
              "http=%r workspace=%r" % (_a, _b))

    # AND THE ADAPTER HAS NO SECOND COPY OF THE RULE, which is what keeps the two in step.
    _src = _io_n.open(_os_n.path.join(HERE, "targets_http.py"), encoding="utf-8").read()
    check("targets_http keeps no copy of the name pattern",
          "[A-Za-z0-9._-]{1,64}" not in _src, "the regex is written out again")
    _tree = _ast_n.parse(_src)
    _uses = any(isinstance(_x, _ast_n.Call) and isinstance(_x.func, _ast_n.Name)
                and _x.func.id in ("safe_target_name", "_safe_name")
                for _x in _ast_n.walk(_tree))
    check("...and calls the shared rule instead", _uses,
          "the name is validated some other way")
    return fails


def check_ctx_read_forms():
    """Every way the engine reads a context key, in one place, read by both scans.

    `workspace.context_keys_read` derives the whole set an operator may configure;
    `oracle.quieted_by` derives the suppressor keys ONE detector reads. Same question, two
    scopes -- and the second had a single pattern, `ctx.get(...)`, while this file had five.
    A detector reading its suppressor as `ctx["allowed_domains"]`, or through `_configured`
    or `_num`, was reported as having no suppressor at all, so `noisy_for` never told the
    operator it was unarmed.

    No detector does that today, and that is not the point: four of the five forms were
    added HERE one at a time, each because a read this scan could not see became a key
    `onboard` told an operator nothing reads, and none of those four lessons reached the
    copy one file over.
    """
    fails = []

    def check(label, ok, detail=""):
        print("%s  %s" % ("PASS" if ok else "FAIL", label))
        if not ok:
            fails.append("%s: %s" % (label, detail))

    from workspace import CTX_READ_FORMS, ctx_keys_in
    SRC = ('ctx.get("alpha") and ctx["beta"] and '
           '_configured("gamma", ctx) and _num(ctx, "delta", 3) and '
           'oracle_context.get("epsilon")')
    check("every documented form of a context read is found",
          sorted(ctx_keys_in(SRC))
          == ["alpha", "beta", "delta", "epsilon", "gamma"],
          str(sorted(ctx_keys_in(SRC))))
    check("...and there are five of them, so a form cannot go missing quietly",
          len(CTX_READ_FORMS) == 5, str(len(CTX_READ_FORMS)))
    check("...and a source that reads nothing yields nothing",
          ctx_keys_in("return True") == set(), str(ctx_keys_in("return True")))
    check("...and None is not a crash", ctx_keys_in(None) == set(), "")

    # AND BOTH SCANS READ IT. A shared definition two callers do not use is a third copy.
    import ast as _ast_c, io as _io_c, os as _os_c
    for _mod, _fn in (("workspace.py", "context_keys_read"),
                      ("oracle.py", "quieted_by")):
        _src = _io_c.open(_os_c.path.join(HERE, _mod), encoding="utf-8").read()
        _tree = _ast_c.parse(_src)
        _body = [n for n in _ast_c.walk(_tree)
                 if isinstance(n, _ast_c.FunctionDef) and n.name == _fn]
        check("%s uses the shared form list" % _fn,
              bool(_body) and any(
                  isinstance(n, _ast_c.Name)
                  and n.id in ("CTX_READ_FORMS", "_ctx_keys_in", "ctx_keys_in")
                  for n in _ast_c.walk(_body[0])),
              "%s has its own pattern" % _fn)
    # ...AND NEITHER KEEPS A SECOND COPY OF THE REGEX.
    for _mod in ("oracle.py",):
        _src = _io_c.open(_os_c.path.join(HERE, _mod), encoding="utf-8").read()
        check("%s has no second copy of the ctx.get pattern" % _mod,
              _src.count(chr(92) + chr(92) + ".get") == 0
              or "ctx" + chr(92) + chr(92) + ".get" not in _src, _mod)
    return fails


def check_one_breach_rule():
    """The tuple that decides what a finding IS, in one place -- and it was in fifteen.

    `workspace.BROKE` was written to end exactly this, and its own comment says so: three
    modules had spelled the tuple out, a fourth was about to, and "three copies of a rule
    agree until the day somebody decides a fourth verdict counts as a breach, and then two
    reports disagree about what a finding is".

    Fourteen copies were still there. Not in corners either: `run_redteam` counting the
    breaches it prints, `defense_report` picking the finding rows and the trial to show,
    `compare_targets` colouring the fleet table, `rejudge` rewriting `meta["broke"]`,
    `baseline` deciding what to attribute, `runner` and `refusal`. Every number a reader of
    this engine sees came off one of those literals.

    `NOT_MEASURED` -- the same rule's twin, one section up in the same file -- really was
    consolidated, and grew from `("ERROR",)` to `("SKIP", "ERROR")` afterwards. That is the
    change this gate exists for: had it happened to `BROKE`, fourteen sites would have kept
    the old answer and nothing would have said so.

    AST, not a substring: the tuple appears in prose in half these files, and a comment
    quoting the rule is not a second implementation of it.
    """
    import ast as _ast_b, glob as _glob_b, io as _io_b, os as _os_b
    fails = []

    def check(label, ok, detail=""):
        print("%s  %s" % ("PASS" if ok else "FAIL", label))
        if not ok:
            fails.append("%s: %s" % (label, detail))

    WANT = {"BROKE": {"EXPLOITED", "PARTIAL"},
            "NOT_MEASURED": {"SKIP", "ERROR"}}

    def literals(path):
        """-> [(name of the rule, line)] for every literal spelling of one in this file."""
        found = []
        try:
            tree = _ast_b.parse(_io_b.open(path, encoding="utf-8").read())
        except SyntaxError:
            return found
        for n in _ast_b.walk(tree):
            if not isinstance(n, (_ast_b.Tuple, _ast_b.List, _ast_b.Set)):
                continue
            vals = [e.value for e in n.elts
                    if isinstance(e, _ast_b.Constant) and isinstance(e.value, str)]
            if len(vals) != len(n.elts) or len(vals) < 2:
                continue
            for name, want in WANT.items():
                if set(vals) == want:
                    found.append((name, n.lineno))
        return found

    # THE SCANNER WORKS, PROVED WHERE THE RULE IS ALLOWED TO BE. A scan that finds nothing
    # because it can no longer see anything is the failure this whole suite is about, and
    # a gate over `no copies exist` is satisfied by a broken scanner.
    _home = sorted(n for n, _ in literals(_os_b.path.join(HERE, "workspace.py")))
    check("the scan finds both rules where they are DEFINED",
          _home == ["BROKE", "NOT_MEASURED"], str(_home))

    _scanned, _copies = 0, []
    for _p in sorted(_glob_b.glob(_os_b.path.join(HERE, "*.py"))):
        _b = _os_b.path.basename(_p)
        if _b.startswith("test_") or _b == "workspace.py":
            continue
        _scanned += 1
        for _name, _line in literals(_p):
            _copies.append("%s:%d spells out %s" % (_b, _line, _name))
    check("no module spells out a rule workspace already owns", not _copies,
          "; ".join(_copies[:6]))
    check("...over the whole package, not a corner of it", _scanned >= 30, str(_scanned))

    # AND THE NAME HAS TO BE THE SHARED OBJECT. Deleting a literal in favour of a local
    # constant of the same name would pass the scan above and be the fifteenth copy.
    import importlib as _il_b
    for _m in ("baseline", "compare_targets", "defense_report", "refusal", "rejudge",
               "run_redteam", "runner", "history", "discrimination", "verify"):
        try:
            _mod = _il_b.import_module(_m)
        except Exception as _e:
            check("%s imports" % _m, False, "%s: %s" % (type(_e).__name__, _e))
            continue
        check("%s reads BROKE from workspace, not a namesake of its own" % _m,
              getattr(_mod, "BROKE", None) is workspace.BROKE,
              repr(getattr(_mod, "BROKE", None)))
    return fails


def check_unread_context_keys():
    """A key nothing reads is a detector nobody armed, and TWO commands need to say so.

    `canaries` misspelled `canarys` parses, sweeps, and disarms every canary detector in the
    oracle. `onboard` has always reported it; a run reached without onboarding said only
    "canary_in_output needs canaries", which over a config that plainly declares a canary is a
    riddle -- the reader has written one, can see it in the file, and is being told there is
    none. The misspelling is the answer and it was in the config all along.

    THE RULE LIVES HERE NOW, beside the scan it consults, because `run` reaching into the
    onboarding COMMAND for it is the wrong direction and cost a silence: the import sat behind
    a bare `except Exception` and something in it raised, so the line never printed and
    nothing said why.
    """
    from workspace import unread_context_keys
    import workspace as _ws
    fails = []

    def check(label, got, want):
        print("%s  %s -> %r" % ("PASS" if got == want else "FAIL", label, got))
        if got != want:
            fails.append("%s: %r != %r" % (label, got, want))

    check("a misspelled context key is named",
          unread_context_keys({"oracle_context": {"canarys": ["X"]}}), ["canarys"])
    check("...and the correct spelling is not",
          unread_context_keys({"oracle_context": {"canaries": ["X"]}}), [])
    check("a config with no oracle_context has nothing to report",
          unread_context_keys({"adapter": "http"}), [])
    check("neither does an empty one", unread_context_keys({"oracle_context": {}}), [])
    check("nor does no config at all", unread_context_keys(None), [])
    check("several are all named, in order",
          unread_context_keys({"oracle_context": {"zzz": 1, "canarys": 2, "canaries": 3}}),
          ["canarys", "zzz"])

    # A BROKEN SCAN MUST ACCUSE NOTHING. If `context_keys_read` ever returns empty -- a
    # packaging change, a source-less install -- every key in every config looks wrong, and a
    # command that told an operator all forty-nine of their keys are unread would be worse
    # than one that said nothing.
    _real = _ws.context_keys_read
    _ws.context_keys_read = lambda root=None: set()
    try:
        check("a scan that finds nothing accuses nothing",
              unread_context_keys({"oracle_context": {"canarys": 1, "canaries": 2}}), [])
    finally:
        _ws.context_keys_read = _real

    # AND THE SCAN IS NOT EMPTY IN A REAL TREE, or every check above passes over nothing.
    check("...while the real scan knows a real key",
          "canaries" in _ws.context_keys_read(), True)
    return fails


def check_config_model():
    """Which model a config runs against, read the way the adapter reads it.

    `meta["model"]` asked for a top-level `model:` key. The practice bots have one; an
    `adapter: http` config -- the only kind an outside user writes -- keeps it at
    `request.model`, where every OpenAI-shaped body carries it and where `qatration init` has
    written it since 0.4.0. So every artifact produced outside this repository recorded no
    model at all, including the ones `--model` had just named the FILE after.
    """
    from workspace import config_model
    fails = []

    def check(label, got, want):
        print("%s  %s -> %r" % ("PASS" if got == want else "FAIL", label, got))
        if got != want:
            fails.append("%s: %r != %r" % (label, got, want))

    check("a practice bot's top-level key is the model", config_model({"model": "nemo"}), "nemo")
    check("an http target's model lives under request",
          config_model({"adapter": "http", "request": {"model": "llama3.2:3b"}}), "llama3.2:3b")
    # THE TOP LEVEL WINS, because that is the branch `--model` writes for every adapter that
    # is not http, and a config carrying both must not answer with the one nobody set.
    check("...and a config with both answers with the top-level one",
          config_model({"model": "chosen", "request": {"model": "stale"}}), "chosen")
    check("...but an empty top-level key is not an answer",
          config_model({"model": "  ", "request": {"model": "real"}}), "real")
    check("a config that names no model says so", config_model({"request": {}}), "")
    check("...and so does one with no request block at all", config_model({}), "")
    check("...and nothing at all does not raise", config_model(None), "")
    # A REQUEST THAT IS NOT A MAPPING. Some shapes carry a template string or a list here,
    # and `.get` on either is an AttributeError in the line that builds every artifact.
    # CAUGHT, NOT CALLED BARE. The property here is that it does not raise, and a check that
    # calls it plainly cannot assert that: the exception escapes, the suite dies with a
    # traceback, and the label that would have named the defect never prints. Measured -- the
    # mutation that drops the isinstance guard reddened this file under no name at all.
    try:
        _got = config_model({"request": "POST {prompt}"})
    except Exception as _e:
        _got = type(_e).__name__
    check("a request that is not a mapping is not a crash", _got, "")
    if fails:
        print("\nFAIL — " + "; ".join(fails))
        sys.exit(1)
    print("  ok  config_model reads a model out of either shape")


def _shipped_configs():
    """The configs this repository ships, through the one enumeration of what a config is.

    NOT A GLOB. `target_configs` exists because eleven enumerations disagreed, and only it
    excluded the throwaway configs the end-to-end suites write into this directory -- so a
    claim about `the shipped configs` changed depending on whether a suite was running, or
    on whether an earlier one had been killed before its `finally`. That is not theoretical:
    two leftovers naming one target failed a duplicate-name check here, about files nobody
    ships.

    Filtered back to this directory because the claim is about what this repository ships;
    `target_configs` also honours `QATRATION_CONFIGS`, which is somebody else's config and
    not evidence about ours.
    """
    from target import target_configs as _tc
    return sorted(p for p in _tc(HERE)
                  if os.path.dirname(os.path.abspath(p)) == HERE)

def main():
    fails, checks = [], 0

    def check(label, ok, detail=""):
        nonlocal checks
        checks += 1
        print(f"{'PASS' if ok else 'FAIL'}  {label}")
        if not ok:
            fails.append(f"{label}: {detail}")

    # --- what out_dir() answers ----------------------------------------------------------
    real = os.environ.pop(workspace.ENV_VAR, None)
    try:
        check("with nothing set, the root is <repo>/out",
              workspace.out_dir() == os.path.join(ROOT, "out"), workspace.out_dir())

        os.environ[workspace.ENV_VAR] = os.path.join(ROOT, "elsewhere")
        check("a named root is honoured",
              workspace.out_dir() == os.path.join(ROOT, "elsewhere"), workspace.out_dir())

        # A relative root is the working-directory dependency this repo just removed, so it
        # is resolved once, here, rather than re-resolved by whoever opens the file.
        os.environ[workspace.ENV_VAR] = "runs/7f3a"
        check("a relative root is made absolute",
              os.path.isabs(workspace.out_dir()), workspace.out_dir())

        os.environ[workspace.ENV_VAR] = "   "
        check("a blank root falls back to the default, rather than to the current directory",
              workspace.out_dir() == os.path.join(ROOT, "out"), workspace.out_dir())
    finally:
        os.environ.pop(workspace.ENV_VAR, None)
        if real is not None:
            os.environ[workspace.ENV_VAR] = real

    # --- and the assertion that keeps mattering ------------------------------------------
    disagree = []
    for mod, attr in sorted(ROOTED.items()):
        try:
            m = importlib.import_module(mod)
        except Exception as e:
            disagree.append(f"{mod}: will not import ({type(e).__name__}: {e})")
            continue
        if not hasattr(m, attr):
            disagree.append(f"{mod}: no longer exposes {attr}")
            continue
        got = os.path.abspath(str(getattr(m, attr)))
        if got != os.path.abspath(workspace.OUT):
            disagree.append(f"{mod}.{attr} = {got}")
    check(f"all {len(ROOTED)} modules resolve to the one root",
          not disagree, "; ".join(disagree))

    # --- nobody builds it again -----------------------------------------------------------
    offenders = []
    for fp in sorted(glob.glob(os.path.join(HERE, "*.py"))):
        base = os.path.basename(fp)
        if base == "workspace.py" or base.startswith("test_"):
            continue
        for lineno, what in builds_its_own_root(open(fp, encoding="utf-8").read()):
            offenders.append(f"{base}:{lineno}: {what}")
    check("no module computes the artifact root itself", not offenders, "; ".join(offenders))

    # Both directions, or a scan that matches nothing reads exactly like a clean repo.
    check("...and the scan can see an os.path.join form",
          builds_its_own_root('import os\nX = os.path.join(ROOT, "out")\n'))
    check("...and the Path form too",
          builds_its_own_root('from pathlib import Path\nX = Path(".") / "out"\n'))
    check("...and it does not fire on prose naming the pattern",
          not builds_its_own_root('def f():\n    """It used to be os.path.join(ROOT, "out").”"""\n'))

    # --- and the two naming conventions live here too -----------------------------------
    check("a per-model copy is recognised, and the canonical file is not",
          workspace.is_per_model_copy("results_opsbot_qwen.json")
          and not workspace.is_per_model_copy("results_opsbot.json"))
    check("...on a full path as well as a bare name",
          workspace.is_per_model_copy(os.path.join("a", "b", "results_x_y.json")))

    names = ["nemo", "nemo-inputonly", "portalagent", "with_underscore"]
    check("a target resolves to itself", workspace.target_of("portalagent", names) == "portalagent")
    check("a per-model tag is stripped",
          workspace.target_of("portalagent_mistral-nemo", names) == "portalagent")
    check("the longest matching name wins over its own prefix",
          workspace.target_of("nemo-inputonly_qwen", names) == "nemo-inputonly")
    check("a name containing an underscore resolves to itself",
          workspace.target_of("with_underscore", names) == "with_underscore")
    check("an unknown stem resolves to nothing, so the caller can say so",
          workspace.target_of("somebody-elses-bot", names) is None)

    # Both conventions were carried in six and two modules respectively, each spelled out by
    # hand. This is what says a ninth module has grown its own copy.
    RULES = {'count("_")': "the per-model copy rule",
             'split("_")[0]': "resolving a target from a filename",
             # A config's `name:` is optional and eleven shipped ones omit it, so the name
             # falls back to the filename stem. That was written out four times and the copy
             # in `sarif` did not have the fallback at all: it compared `cfg["name"]` alone,
             # so those eleven targets exported every finding with no location — 148 of 498
             # across the fleet, 95 of them on httpbot, while the module's own comment says
             # the anchor exists so a reviewer gets a file that is really there.
             'len("targets_")': "deriving a target name from a config filename"}
    strays = []
    for fp in sorted(glob.glob(os.path.join(HERE, "*.py"))):
        base = os.path.basename(fp)
        if base in ("workspace.py",) or base.startswith("test_"):
            continue
        src = open(fp, encoding="utf-8").read()
        for lineno, line in enumerate(src.splitlines(), 1):
            code = line.split("#")[0]
            for needle, what in RULES.items():
                if needle in code and not code.lstrip().startswith(('"', "'")):
                    strays.append(f"{base}:{lineno}: {what}")
    check("no module re-implements an artifact-naming rule", not strays, "; ".join(strays))

    # --- NOBODY WRITES INTO A DIRECTORY NOBODY MADE ------------------------------------------
    #
    # `OUT` is a path, not a directory: it is resolved at import and deliberately NOT created
    # there, or `qatration <anything> --help` would litter the filesystem. So whoever writes
    # has to create it, and that was remembered in four modules and forgotten in two.
    #
    # `benign` was the expensive one. Walked as a first-time user against a live model: fifty
    # probes sent, all fifty rows printed, a tally printed, and then FileNotFoundError on the
    # write. The traceback goes to stderr and the table to buffered stdout, so the failure
    # scrolls past ABOVE the results and the last thing on screen is `36/50 clean` -- a
    # summary that reads like a finished run. Exit 1, no baseline written, and every later
    # finding on that target unattributable because `baseline.rates` had nothing to read.
    #
    # It hid because the README's order covers it: `run` creates the directory and comes
    # first there. The order `init` prints INTO THE CONFIG IT WRITES puts `benign` before
    # `run`, so following the tool's own instructions is the way to meet it.
    #
    # By AST, so a paragraph mentioning OUT_DIR cannot answer for the code, and asking about
    # the WRITE rather than about the module: a file that reads from OUT all day is fine.
    import ast as _ast2
    _unmade = []
    for fp in sorted(glob.glob(os.path.join(HERE, "*.py"))):
        base = os.path.basename(fp)
        if base in ("workspace.py",) or base.startswith("test_"):
            continue
        try:
            tree = _ast2.parse(open(fp, encoding="utf-8").read())
        except SyntaxError:
            continue
        makes = any(getattr(n.func, "attr", None) == "makedirs"
                    for n in _ast2.walk(tree) if isinstance(n, _ast2.Call))
        goes_through = any(getattr(n.func, "attr", None) == "artifact"
                           for n in _ast2.walk(tree) if isinstance(n, _ast2.Call))
        for n in _ast2.walk(tree):
            if not (isinstance(n, _ast2.Call) and getattr(n.func, "id", None) == "open"):
                continue
            mode = ""
            if len(n.args) > 1 and isinstance(n.args[1], _ast2.Constant):
                mode = str(n.args[1].value)
            if "w" not in mode and "a" not in mode:
                continue
            # THE PATH IS USUALLY IN A VARIABLE, WHICH THE FIRST VERSION OF THIS MISSED. It
            # looked for OUT_DIR among the names INSIDE the open() call, so it caught
            # `open(os.path.join(OUT_DIR, x), "w")` and not the two-line form every module
            # here actually uses. Mutating benign back to the broken write left it green —
            # a check about a value, written about an expression. Assignments are followed.
            _tainted = set()
            for a in _ast2.walk(tree):
                if not isinstance(a, _ast2.Assign):
                    continue
                if {"OUT_DIR", "OUT", "WORKSPACE_OUT"} & {
                        x.id for x in _ast2.walk(a.value) if isinstance(x, _ast2.Name)}:
                    _tainted |= {t.id for t in a.targets if isinstance(t, _ast2.Name)}
            names = {x.id for x in _ast2.walk(n.args[0]) if isinstance(x, _ast2.Name)} \
                if n.args else set()
            if not (({"OUT_DIR", "OUT", "WORKSPACE_OUT"} | _tainted) & names):
                continue
            if makes or goes_through:
                continue
            _unmade.append(f"{base}:{n.lineno}")
    check("every module writing into the artifact directory creates it first",
          not _unmade,
          "opens a path under OUT for writing without makedirs or workspace.artifact: "
          + ", ".join(_unmade))

    # --- AND THE RULE ITSELF, not only that one copy of it exists ---------------------------
    #
    # The needle scan above is a spellcheck: it says nobody wrote the pattern out again, and
    # nothing about what the surviving copy does. Both halves are asserted here, because the
    # defect was in the behaviour of the half that had no fallback.
    check("a config that names itself is called what it says",
          workspace.config_name("/x/targets_thing.yaml", {"name": "acme-bot"}) == "acme-bot")
    check("...and one that does not is called after its file",
          workspace.config_name("/x/targets_httpbot.yaml", {}) == "httpbot")
    check("...which is what lets SARIF anchor a finding to a config that omits `name:`",
          workspace.config_name("/x/targets_httpbot.yaml", {}) != "")
    check("a path that is not a targets_ file keeps its own stem",
          workspace.config_name("/x/something.yaml", {}) == "something.yaml")
    # ...and every reader agrees, since disagreeing is what cost the locations.
    import yaml as _y
    from target import target_configs as _tc
    _by_helper = {workspace.config_name(fp) for fp in _tc()}
    import detector_coverage as _dc
    check("the coverage map and the helper name the same fleet",
          set(_dc.contexts()) <= _by_helper,
          f"only in coverage: {sorted(set(_dc.contexts()) - _by_helper)[:4]}")
    check("...and so does fleet_names", workspace.fleet_names() <= _by_helper,
          f"only in fleet_names: {sorted(workspace.fleet_names() - _by_helper)[:4]}")

    # --- ONE NAME, ONE TARGET ------------------------------------------------------------
    #
    # The name is the target's identity on disk: `results_<name>.json`,
    # `benign_<name>.json`, `report_<name>.html`, `history/<name>.jsonl`. Two configs
    # sharing one are one target as far as every artifact is concerned, and the second run
    # replaces the first's evidence.
    #
    # `targets_nemo.yaml` and `targets_nemo_key.yaml` both declared `name: nemo`. They are
    # deliberately different -- the first arms both canaries, the second only the staff key,
    # which is the `one canary per question` discipline the NeMo configs were written for --
    # and `detector_coverage` had been reporting it for as long as they both existed: TWO
    # CONFIGS, ONE TARGET NAME, the first used and the others not, their stored probes
    # scored against the first config's oracle_context. Reported by the tool, gated by
    # nothing. Every sibling already had a distinct name.
    import yaml as _y6, glob as _g6, collections as _c6
    _by = _c6.defaultdict(list)
    for _p6 in _shipped_configs():
        try:
            _c = _y6.safe_load(open(_p6, encoding="utf-8").read()) or {}
        except (OSError, _y6.YAMLError):
            # NARROW ON PURPOSE. This was `except Exception` and it swallowed a NameError
            # from the line above, so the scan read nothing and reported no duplicates --
            # the check below would have passed over an empty set. The check that asks
            # whether anything was read is what caught it.
            continue          # a config that will not parse is another suite's business
        if isinstance(_c, dict) and _c.get("name"):
            _by[str(_c["name"])].append(os.path.basename(_p6))
    # A scan that read no config would find no duplicate and say so.
    check("the shipped configs declare names that can be enumerated", len(_by) >= 20,
          str(len(_by)))
    _dupes = sorted((n, f) for n, f in _by.items() if len(f) > 1)
    check("...and no two of them claim the same one", not _dupes, str(_dupes))

    # --- AND ONE ENUMERATION OF WHAT A CONFIG IS ---------------------------------------
    #
    # `target_configs` says in its own docstring why it exists: "ONE enumeration because
    # there were eleven, and only one of them excluded the temporary configs the end-to-end
    # suites write beside the real ones. The others' answers changed depending on whether a
    # suite was running." Eleven became one, and then thirteen more were written -- two in
    # shipped code and eleven across these suites, every one of them a bare
    # `glob("targets_*.yaml")`.
    #
    # It is not cosmetic. `honeytoken` derived the SHORTEST canary on the fleet that way --
    # the floor a minted token has to clear -- and `workspace` derived which context keys
    # are lists, cached for the life of the process and used to refuse a config. Both moved
    # if a scratch file was in the directory. The check five lines above is where it showed:
    # two leftovers from a killed run, both naming `e2e-bot`, failed a claim about the
    # configs this repository ships.
    #
    # OVER EVERY FILE, SUITES INCLUDED, because eleven of the thirteen were in suites and a
    # scan that skipped them would have found two.
    # THE PATTERN IS ASSEMBLED, not written out, so this scan does not find itself. A check
    # that flags its own source is a check somebody exempts, and the exemption is the hole.
    _pat7 = "targets_" + "*.yaml"

    def _enumerates(line):
        """Is this line of source a second enumeration? Code only, never a comment."""
        bare = line.split("#", 1)[0]
        return "glob" in bare and _pat7 in bare

    _files7 = sorted(_g6.glob(os.path.join(HERE, "*.py")))
    _globbers = []
    for _p7 in _files7:
        if os.path.basename(_p7) == "target.py":
            continue                     # the enumeration itself
        for _i7, _line in enumerate(open(_p7, encoding="utf-8").read().splitlines(), 1):
            if _enumerates(_line):
                _globbers.append("%s:%d" % (os.path.basename(_p7), _i7))
    check("only `target.py` enumerates the target configs", not _globbers,
          "; ".join(_globbers[:6]))
    check("...over every module here, suites included", len(_files7) >= 90, str(len(_files7)))
    # AND THE SCAN CAN SEE ONE, proved on a planted line rather than assumed: a check that
    # finds nothing because its pattern stopped matching reads exactly like a clean tree.
    check("the scan finds a planted enumeration",
          _enumerates("    for f in glob.glob(os.path.join(HERE, %r)):" % _pat7),
          "the planted line was not seen")
    check("...and ignores one that is only mentioned in a comment",
          not _enumerates("    # every glob of %s" % _pat7),
          "a comment was read as code")
    check("...and an ordinary line is not one",
          not _enumerates("    x = 1"), "an ordinary line matched")

    # --- AND THE SAME QUESTION FOR THE ARSENAL ------------------------------------------
    #
    # `build_generic` learned that a scratch file in this directory becomes part of the
    # arsenal, and wrote down why: `test_end_to_end` writes `attacks_e2e_<pid>_tmp.yaml`
    # here and removes it in a `finally`, so an interrupted run leaves it. It excluded the
    # suffix. `lint` -- the command that decides whether the corpus is fit to send -- globbed
    # in three places and did not, so a leftover was linted as a shipped arsenal file and
    # `qatration lint` failed on an error in a file nobody ships. Reproduced by planting one.
    #
    # There were three in this working tree at the time, from runs killed earlier: `lint`
    # reported `1070 attacks across 44 file(s)` where the corpus is 1,060 across 41.
    _pat8 = "attacks" + "*.yaml"

    def _enumerates_arsenal(line):
        bare = line.split("#", 1)[0]
        return "glob" in bare and _pat8 in bare

    _agl = []
    for _p8 in _files7:
        if os.path.basename(_p8) == "workspace.py":
            continue                     # the enumeration itself
        for _i8, _line in enumerate(open(_p8, encoding="utf-8").read().splitlines(), 1):
            if _enumerates_arsenal(_line):
                _agl.append("%s:%d" % (os.path.basename(_p8), _i8))
    check("only `workspace.py` enumerates the arsenal files", not _agl,
          "; ".join(_agl[:6]))
    check("the arsenal scan finds a planted enumeration",
          _enumerates_arsenal("    for f in glob.glob(os.path.join(HERE, %r)):" % _pat8),
          "the planted line was not seen")
    check("...and a comment naming the pattern is not one",
          not _enumerates_arsenal("    # every glob of %s" % _pat8),
          "a comment was read as code")

    # AND THE ENUMERATION ITSELF ANSWERS, rather than being trusted: a scratch name is
    # dropped, a real one is kept, and the count is not zero -- an empty answer would
    # satisfy every claim above it.
    from workspace import arsenal_files as _af
    _kept = [os.path.basename(p) for p in _af(HERE)]
    check("the arsenal enumeration finds the shipped files", len(_kept) >= 30,
          str(len(_kept)))
    check("...and keeps the main one", "attacks.yaml" in _kept, str(_kept[:4]))
    # PLANTED, NOT SURVEYED. Asking whether the shipped tree contains a scratch file is
    # satisfied by the tree being clean, which it is most of the time -- so the exclusion
    # could be deleted and this would still pass. It is asked of a directory built to hold
    # one.
    import tempfile as _tf8
    _d8 = _tf8.mkdtemp()
    try:
        for _n8 in ("attacks.yaml", "attacks_focus.yaml", "attacks_e2e_999_tmp.yaml",
                    "attacks_slice_7.yaml"):
            with open(os.path.join(_d8, _n8), "w", encoding="utf-8") as _f8:
                _f8.write("[]")
        _got8 = [os.path.basename(p) for p in _af(_d8)]
        check("...and drops a scratch file, whatever process left it",
              _got8 == ["attacks.yaml", "attacks_focus.yaml"], str(_got8))
    finally:
        __import__("shutil").rmtree(_d8, ignore_errors=True)

    # --- EVERY DOOR THAT WRITES EVIDENCE, NOT THE TWO THAT HAD THE GUARD ----------------
    #
    # `refuse_to_overwrite_evidence` was written after a `--attacks` run replaced a full
    # sweep's `results_httpbot.json` with eight rows and `coverage` reported 958 fewer
    # probes. It was wired into `run` and `benign`. Three more commands send probes and
    # write a per-target artifact into `out/` -- `recon`, `isolation` and `adaptive` --
    # and replaced a committed one in silence. The repository tracks 10 recon profiles,
    # 11 isolation maps and 3 adaptive transcripts.
    #
    # THE PROPERTY IS `SENDS PROBES AND WRITES`, not `writes`. `rejudge --write` rewrites
    # a committed results file on purpose -- that is the command -- and it recomputes from
    # the SAME stored probes, so nothing is destroyed. `runs` only appends new timestamped
    # records. Neither belongs here, and a gate that demanded the guard of everything that
    # writes JSON would have said so about both.
    #
    # THE FAMILIES COME FROM WHAT IS COMMITTED, not from a list here, so a prefix somebody
    # starts tracking tomorrow is covered without anybody editing this file.
    import io, subprocess as _sp7, collections as _co7, re as _re7
    _root = os.path.dirname(HERE)
    try:
        _ls = _sp7.run(["git", "ls-files", "out"], cwd=_root, capture_output=True,
                       text=True, timeout=60)
        _tracked = [l.strip() for l in (_ls.stdout or "").splitlines() if l.strip()]
    except Exception:
        _tracked = []

    _pref = _co7.Counter()
    for _f7 in _tracked:
        _b7 = os.path.basename(_f7)
        if not _b7.endswith(".json") or "_" not in _b7 or _b7.startswith("_"):
            continue
        _pref[_b7.split("_", 1)[0]] += 1
    # A family is a prefix worn by more than one file: `results_<target>.json` is a family,
    # `bench-nemo.json` is one page.
    _families = sorted(k for k, n in _pref.items() if n >= 2)
    check("the committed evidence families can be enumerated", len(_families) >= 4,
          str(sorted(_pref.items())))

    _writers, _unguarded = [], []
    for _m7 in sorted(glob.glob(os.path.join(HERE, "*.py"))):
        if os.path.basename(_m7).startswith("test_"):
            continue
        _src7 = io.open(_m7, encoding="utf-8").read()
        _builds = any(_re7.search(r'f"%s_\{' % _re7.escape(_fam), _src7)
                      for _fam in _families)
        _drives = ("safe_target_name(" in _src7) or ("load_target_or_explain(" in _src7)
        _writes = ("json.dump(" in _src7) or ("write_maps(" in _src7)
        if _builds and _drives and _writes:
            _writers.append(os.path.basename(_m7))
            if "refuse_to_overwrite_evidence(" not in _src7:
                _unguarded.append(os.path.basename(_m7))
    # A conjunction that matched nothing would satisfy the next check by having no subject.
    check("...and every command that sends probes and writes one is found",
          len(_writers) >= 5, str(_writers))
    check("...and every one of them refuses to replace a committed file",
          not _unguarded, "; ".join(_unguarded))

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  !", f)
        sys.exit(1)
    print("\nOK — one place decides where artifacts go.")


def check_measured_when():
    """A run's date must come from the run, not from the file it happens to sit in.

    `compare_targets` and `defense_report` both dated their evidence with
    `os.path.getmtime`. Git does not preserve mtimes, so a fresh clone stamps every artifact
    with the clone time: cloned this repository and all 45 results files came back with one
    date. The fleet page would print that date for runs three weeks old, and its staleness
    bar -- which exists to warn that rows were measured on different days -- would find no
    difference and never render. An absence of evidence about age, read as evidence of the
    same age.

    `meta["when"]` was added for this and 44 of the 45 shipped artifacts predate it, so the
    answer cannot be retrofitted; it can only be told apart from a guess.
    """
    import io as _io
    import os as _os
    import tempfile as _tf
    from workspace import measured_when
    bad = []

    def want(label, ok, detail=""):
        print(f"{'PASS' if ok else 'FAIL'}  {label}")
        if not ok:
            bad.append(f"{label}: {detail}")

    said, from_run = measured_when({"when": "2026-08-18 19:08:29"}, None)
    want("a run that recorded its date is dated by it",
         from_run and said.startswith("2026-08-18"), said)

    d = _tf.mkdtemp()
    fp = _os.path.join(d, "results_x.json")
    _io.open(fp, "w", encoding="utf-8").write("{}")
    said, from_run = measured_when({}, fp)
    want("a run that did not is dated by the file, and says so",
         said and from_run is False, "%r / %r" % (said, from_run))

    # THE FILE MUST NOT WIN over a date the run recorded, which is the whole defect.
    said, from_run = measured_when({"when": "2026-08-18 19:08:29"}, fp)
    want("...and the file never overrides what the run said",
         from_run and said.startswith("2026-08-18"), said)

    want("with neither, it claims nothing at all",
         measured_when({}, None) == ("", False), str(measured_when({}, None)))
    return bad



def check_dated():
    """One marker for a date that came off the filesystem, and the flag beside it.

    `measured_when` answers the question and five surfaces SAY the answer: the benign
    roll-up, the recon fleet page, the model matrix, the report's side panel and the page
    `rejudge --write` rebuilds. Each formatted it separately, so `measured 09-01` -- a claim
    about a run -- and `measured 09-01 (file)` -- a claim about a filesystem -- were one
    edit away from drifting apart.

    AND THE FLAG COMES BACK WITH THE TEXT. `benign --summary` needs to know which rows may
    join its staleness comparison, and it recovered that by testing the formatted string for
    the marker: a boolean it had held two lines earlier, read back out of its own prose. A
    renamed marker would have silently returned every file-dated baseline to the comparison
    it must stay out of, and nothing would have failed.
    """
    import io as _io_d
    import os as _os_d
    import re as _re_d
    import glob as _g_d
    import tempfile as _tf_d
    from workspace import dated, FILE_DATED
    bad = []

    def want(label, ok, detail=""):
        print(f"{'PASS' if ok else 'FAIL'}  {label}")
        if not ok:
            bad.append(f"{label}: {detail}")

    _shown, _said = dated({"when": "2026-08-18 19:08:29"}, None)
    want("a run that recorded its date is shown it, unmarked",
         _said and _shown == "2026-08-18 19:08", "%r / %r" % (_shown, _said))

    _d = _tf_d.mkdtemp()
    _fp = _os_d.path.join(_d, "results_x.json")
    _io_d.open(_fp, "w", encoding="utf-8").write("{}")
    _shown, _said = dated({}, _fp)
    want("a run that did not is marked, so the sentence changes meaning",
         _said is False and _shown.endswith(FILE_DATED), "%r / %r" % (_shown, _said))
    want("...and the date is still there to read",
         _re_d.match(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}", _shown), _shown)

    _shown, _said = dated({}, None)
    want("with neither, it claims nothing but is still marked",
         _said is False and _shown == FILE_DATED, repr(_shown))

    # AND THE MARKER IS VISIBLE. An empty one satisfies every `endswith` above and would
    # leave a file's timestamp reading exactly like a measurement -- a check that passes
    # because the property it tests cannot be reached is the defect this project names.
    want("the marker is something a reader can see", FILE_DATED.strip() != "",
         repr(FILE_DATED))

    # AND NOBODY PARSES IT BACK. The marker is a thing to SHOW; every caller that needs to
    # know already has the boolean returned beside it. Scanned rather than remembered,
    # because this is a habit rather than one line: it was written once and would be
    # written again by the next surface that needs the same distinction.
    _here_d = _os_d.path.dirname(_os_d.path.abspath(_io_d.__file__ or "."))
    _mod_dir = _os_d.path.dirname(_os_d.path.abspath(__file__))
    _parsers = []
    for _fp2 in sorted(_g_d.glob(_os_d.path.join(_mod_dir, "*.py"))):
        _nm = _os_d.path.basename(_fp2)
        if _nm.startswith("test_") or _nm == "workspace.py":
            continue
        _src = _io_d.open(_fp2, encoding="utf-8").read()
        for _line in _src.splitlines():
            if _line.lstrip().startswith("#"):
                continue
            if "(file)" in _line and ("in " in _line or "==" in _line or "find(" in _line):
                _parsers.append("%s: %s" % (_nm, _line.strip()[:70]))
    want("no surface recovers the flag by searching its own output",
         _parsers == [], "; ".join(_parsers))

    # AND THE MARKER IS WRITTEN IN ONE PLACE, or the five surfaces drift again.
    _literals = []
    for _fp3 in sorted(_g_d.glob(_os_d.path.join(_mod_dir, "*.py"))):
        _nm = _os_d.path.basename(_fp3)
        if _nm.startswith("test_") or _nm == "workspace.py":
            continue
        for _line in _io_d.open(_fp3, encoding="utf-8").read().splitlines():
            _s = _line.strip()
            if _s.startswith("#"):
                continue
            if '" (file)"' in _s or "' (file)'" in _s:
                _literals.append("%s: %s" % (_nm, _s[:70]))
    want("...and no surface writes the marker itself", _literals == [],
         "; ".join(_literals))
    return bad


def check_named_build():
    """An `unknown` build is an absence wearing a value.

    `engine_version` is best-effort and stamps the literal string when neither git nor
    an installed release can answer, which is the normal case in a tarball. Every
    comparison of two builds here is `a and b and a != b`, so that string breaks the
    rule in both directions at once: two unknowns compare EQUAL and withdraw a caveat
    nothing earned, and one against a real build compares UNEQUAL and raises a confound
    naming a change nobody measured -- `history.diff` printed exactly that, as
    `engine unknown -> a1b2c3`, three lines under a comment stating the correct rule.
    """
    from workspace import named_build
    bad = []

    def want(label, got, expect):
        print("%s  %s -> %r" % ("PASS" if got == expect else "FAIL", label, got))
        if got != expect:
            bad.append("%s: %r != %r" % (label, got, expect))

    want("a real build is a build", named_build("a1b2c3"), "a1b2c3")
    want("the sentinel is not", named_build("unknown"), "")
    want("...in any case", named_build("UNKNOWN"), "")
    want("...with whitespace around it", named_build("  unknown  "), "")
    want("a missing stamp is not a build either", named_build(None), "")
    want("...nor an empty one", named_build(""), "")
    # AND IT MUST NOT EAT A REAL BUILD that merely contains the word: git short revs are
    # hex, but an installed release stamps a version string and this must not judge it.
    want("a build that mentions it is still a build",
         named_build("0.4.1-unknown"), "0.4.1-unknown")
    return bad


def check_evidence_guard():
    """A run must not silently replace a results file somebody committed.

    WALKED INTO RATHER THAN IMAGINED. Eight attacks were run against a shipped practice bot from
    inside the checkout, and `out/results_httpbot.json` went from 1.6 MB of a full sweep to
    16 KB of an experiment. `detector_coverage` immediately reported 958 fewer probes, and the
    README, the site and the false-positive rates are all recounted from those files. Restored
    from git, which is the only reason it is a story rather than a wrong number in a release.

    The guard lives at the resource: both commands that write evidence call one function, so a
    third one cannot arrive without it by being written somewhere else.
    """
    import io
    import subprocess
    import tempfile
    from workspace import refuse_to_overwrite_evidence, tracked_by_git

    bad = []

    def want(label, ok, detail=""):
        print("%s  %s" % ("PASS" if ok else "FAIL", label))
        if not ok:
            bad.append("%s: %s" % (label, detail))

    with tempfile.TemporaryDirectory() as d:
        env = dict(os.environ, GIT_CONFIG_GLOBAL=os.path.join(d, "none"),
                   GIT_CONFIG_SYSTEM=os.path.join(d, "none"))

        def git(*a):
            return subprocess.run(["git", "-C", d] + list(a), capture_output=True, text=True,
                                  env=env)

        git("init", "-q")
        git("config", "user.name", "QAtration")
        git("config", "user.email", "qatration@gmail.com")
        kept = os.path.join(d, "results_kept.json")
        io.open(kept, "w", encoding="utf-8").write('{"results": []}')
        git("add", "-A")
        r = git("commit", "-qm", "evidence")
        if r.returncode != 0 and "cannot spawn" in (r.stdout + r.stderr).lower():
            print("SKIP  the evidence guard: git cannot commit here, so it was NOT checked")
            return bad

        loose = os.path.join(d, "results_loose.json")
        io.open(loose, "w", encoding="utf-8").write('{"results": []}')

        want("a committed results file is recognised as evidence", tracked_by_git(kept))
        want("...and an uncommitted one is not", not tracked_by_git(loose))
        want("writing over the committed one is refused",
             bool(refuse_to_overwrite_evidence(kept)))
        want("...and the refusal says how to write elsewhere",
             "QATRATION_OUT" in refuse_to_overwrite_evidence(kept))
        want("...and names the file, so the reader knows what was nearly lost",
             "results_kept.json" in refuse_to_overwrite_evidence(kept))
        want("the flag is an escape hatch, not a suggestion",
             refuse_to_overwrite_evidence(kept, force=True) == "")
        want("an ordinary artifact is written without ceremony",
             refuse_to_overwrite_evidence(loose) == "")
        want("a file that does not exist yet is not evidence",
             refuse_to_overwrite_evidence(os.path.join(d, "results_new.json")) == "")

    # BOTH WRITERS, EXECUTED RATHER THAN GREPPED. The first version of this checked that the
    # string `refuse_to_overwrite_evidence(` appeared in each module, and a mutation proved what
    # that is worth: `_refusal = None and refuse_to_overwrite_evidence(...)` keeps the string,
    # disarms the guard, and passed. Both commands are run for real against a committed file
    # and have to refuse. Neither reaches a target, because both check before they send.
    with tempfile.TemporaryDirectory() as d:
        env = dict(os.environ, GIT_CONFIG_GLOBAL=os.path.join(d, "none"),
                   GIT_CONFIG_SYSTEM=os.path.join(d, "none"), QATRATION_OUT=d)

        def git(*a):
            return subprocess.run(["git", "-C", d] + list(a), capture_output=True, text=True,
                                  env=env)

        git("init", "-q")
        git("config", "user.name", "QAtration")
        git("config", "user.email", "qatration@gmail.com")
        for name in ("results_httpbot.json", "benign_httpbot.json"):
            io.open(os.path.join(d, name), "w", encoding="utf-8").write('{"rows": [], "results": []}')
        git("add", "-A")
        r = git("commit", "-qm", "evidence")
        if r.returncode != 0 and "cannot spawn" in (r.stdout + r.stderr).lower():
            print("SKIP  the two commands: git cannot commit here, so they were NOT run")
            return bad

        cli = os.path.join(HERE, "cli.py")
        for label, argv in (
                ("qatration run", [cli, "run", "--target-config",
                                   os.path.join(HERE, "targets_httpbot.yaml"),
                                   "--attacks", os.path.join(HERE, "attacks_refusal.yaml"),
                                   "--trials", "1"]),
                ("qatration benign", [cli, "benign", "--target", "httpbot"])):
            # A GUARD THAT DOES NOT FIRE DOES NOT HANG THE SUITE, it fails by name. With the
            # check disarmed, `benign` starts its fifty-probe corpus against a live bot and the
            # call times out; without this the suite dies on a TimeoutExpired traceback and
            # says nothing about which guard was missing. Sixty seconds is generous: a guard
            # that works answers in under one.
            try:
                proc = subprocess.run([sys.executable] + argv, capture_output=True, text=True,
                                      env=env, timeout=60)
                said = proc.stdout + proc.stderr
                code = proc.returncode
            except subprocess.TimeoutExpired:
                said, code = "it started working instead of refusing", -1
            # 2, NOT 5, AND THE NUMBER IS THE POINT. This was pinned at 5 with nothing
            # saying why, next to the canary preconditions it shares no cause with. The
            # README's rule for these codes is that "the reason has to be recoverable from
            # the number alone", and 5 is documented there as "the canary is one this tool
            # publishes, or a declared honeytoken was not found in the target" -- so a CI
            # mapping the number would send somebody to check a canary that is fine. 2 is
            # "the config or the invocation was refused", nothing was sent either way, and
            # what clears this is a flag or QATRATION_OUT rather than anything about the bot.
            want("%s refuses to replace a committed artifact" % label,
                 code == 2, "exit %s: %s" % (code, said.strip()[:160]))
            want("...and says which file and how to write elsewhere",
                 "REFUSED" in said and "QATRATION_OUT" in said, said.strip()[:160])
            want("...and the file on disk is untouched",
                 io.open(os.path.join(d, "results_httpbot.json"), encoding="utf-8").read()
                 == '{"rows": [], "results": []}')
    return bad


if __name__ == "__main__":
    _bad = (check_evidence_guard() + check_measured_when() + check_named_build()
            + check_dated())
    if _bad:
        for _b in _bad:
            print('  !', _b)
        sys.exit(1)
    check_config_model()
    _f = (check_one_name_rule() + check_ctx_read_forms() + check_one_breach_rule()
          + check_unread_context_keys() + check_context_shapes() + check_esc()
          + check_every_command_refuses())
    if _f:
        raise SystemExit("unread_context_keys: " + "; ".join(_f))
    main()
