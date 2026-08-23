"""One command, so the tool can be installed rather than cloned.

Until this existed the answer to "how do I run it" was: clone the repository, work out which
interpreter has the dependencies, and invoke a module by path. That is not a tool, it is a
checkout, and the difference is not cosmetic: an install has one failure mode and a checkout
has as many as there are machines.

    pip install qatration
    qatration onboard --target-config mybot.yaml     # check the config against the live endpoint
    qatration run     --target-config mybot.yaml     # sweep it
    qatration benign  --target-config mybot.yaml     # what fires when NOBODY is attacking

Each subcommand hands its remaining arguments to the module that already implements it,
untouched. No flags are re-declared here, because a dispatcher that restates another module's
arguments is a second place for them to drift, and the drift is silent: a flag that exists in
one and not the other is simply ignored.

The commands are the ones a person testing THEIR OWN system needs, and `recon`, `generate` and
`isolation` are in that list because the docs already told people to run them — by a path into
this directory, under whichever interpreter has the dependencies. A tool the design record
walks you through and the command line cannot reach is documentation for something that is not
shipped.

Everything still absent is absent deliberately: it operates on the practice fleet or on a corpus
of stored runs, and listing it beside `run` would suggest a stranger has something to point it
at. Those remain reachable as `python -m qatration.<module>`.
"""

import importlib
import io
import os
import re
import sys

# subcommand -> (module, one-line help). The module must expose `main()`; test_packaging.py
# imports every one of them and fails if it does not, so this table cannot rot into a list of
# commands that raise AttributeError on the first Enter.
COMMANDS = {
    # FIRST, BECAUSE IT IS FIRST. This table is printed in order by `_usage`, and the order was
    # a history of what got written when. A stranger reading `qatration --help` needs the
    # command that produces the file every other command wants, at the top.
    "init":     ("init_config",     "write a starting target config, with a canary of your own"),
    "run":      ("run_redteam",     "run the arsenal against one target"),
    "mint":     ("mint",            "generate a canary of your own, and the verifier that proves you planted it"),
    "onboard":  ("onboard",         "check a target config against its live endpoint"),
    "benign":   ("benign",          "ordinary traffic through every detector: the false-positive rate"),
    "history":  ("history",         "what changed since the last run, and whether it can be believed"),
    "compare":  ("compare_targets", "one page across every target that has evidence"),
    "rejudge":  ("rejudge",         "re-score stored results with the current oracle, no model calls"),
    "sarif":    ("sarif",           "stored results as SARIF 2.1.0, for a code-scanning tab"),
    # THE THREE THAT HAD NO DOOR. Each ran from the day it was written, reachable only by
    # invoking a module inside an installed package, which nobody discovers. `fixes` is the
    # answer to "what do I change on Monday"; `discrimination` is what a sceptic asks for
    # before believing any of the rest; `index` ties a run together and the generated page
    # already linked to it.
    "fixes":    ("defense_report",  "breaches turned into a prioritised fix list, by root cause"),
    "discrimination": ("discrimination",
                       "the tool's own credibility: controls clean, breaches reliable not lucky"),
    "index":    ("build_index",     "one page tying a run's reports together"),
    "recon":    ("run_recon",       "profile a target with benign probes before attacking it"),
    "generate": ("run_generate",    "turn a recon profile into objectives for that target"),
    "isolation": ("run_isolation",  "map which of a target's defences are separable, one at a time"),
    "lint":     ("lint_arsenal",    "check the attack corpus for the mistakes that read as findings"),
    "coverage": ("detector_coverage", "which detectors have ever caught anything"),
}


def _usage(stream=sys.stdout):
    print("usage: qatration <command> [options]", file=stream)
    print("", file=stream)
    width = max(len(c) for c in COMMANDS)
    for name, (_, blurb) in COMMANDS.items():
        print("  %-*s  %s" % (width, name, blurb), file=stream)
    print("", file=stream)
    print("  qatration <command> --help   for that command's options", file=stream)
    print("  qatration --version", file=stream)


def package_version():
    """The version, whether this is an installed package or a file being run by path.

    `from . import __version__` is the right way and it raises when there is no package
    context, which is exactly how this file is run during development and in the offline
    suites. Falling back to reading the constant out of its own source keeps `--version`
    working in both, and keeps ONE definition of the number: the alternative is a copy in this
    file that agrees with `__init__.py` until somebody bumps one of them.
    """
    try:
        from . import __version__
        return __version__
    except ImportError:
        pass
    here = os.path.dirname(os.path.abspath(__file__))
    src = io.open(os.path.join(here, "__init__.py"), encoding="utf-8").read()
    found = re.search(r'^__version__\s*=\s*"([^"]+)"', src, re.M)
    return found.group(1) if found else "unknown"


def _version():
    line = "qatration %s" % package_version()
    # The engine version is the commit that would be stamped into any evidence written now.
    # Reported beside the release because they answer different questions and a bug report that
    # quotes only one of them cannot be placed.
    #
    # An installed copy has no repository to ask, so `engine_version()` answers "unknown" — and
    # printing "(engine unknown)" tells the reader nothing while looking like something is
    # broken. A version line that raises a question it cannot answer is worse than a short one.
    try:
        from target import engine_version
        ev = (engine_version() or "").strip()
        if ev and ev.lower() != "unknown":
            line += " (engine %s)" % ev
    except Exception:
        pass
    return line


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)

    if not argv or argv[0] in ("-h", "--help", "help"):
        _usage()
        return 0
    if argv[0] in ("-V", "--version", "version"):
        print(_version())
        return 0

    name = argv[0]
    if name not in COMMANDS:
        print("qatration: unknown command %r" % name, file=sys.stderr)
        print("", file=sys.stderr)
        _usage(sys.stderr)
        return 2

    module_name = COMMANDS[name][0]
    module = importlib.import_module(module_name)

    # The module parses `sys.argv` itself, so it has to see its own name in slot 0 or argparse
    # prints "usage: qatration" for a command called "qatration run" and the reader is told to
    # fix a flag on the wrong program.
    saved = sys.argv
    sys.argv = ["qatration " + name] + argv[1:]
    try:
        return module.main()
    except SystemExit as e:
        # `raise SystemExit("a message")` exits ONE, and one is the code this tool documents as
        # "the target was exploited or breached". Ten places raise it — an unset environment
        # variable, a url that is not a url, an adapter that cannot be imported — and every one
        # of them is a refusal where nothing was sent. Left alone, a CI reads a typo in a config
        # as a security finding, which is the same confusion the exit table exists to prevent,
        # arriving through the one door the table did not describe.
        #
        # Found by installing the package into a clean venv and running it as a stranger would,
        # not by reading: from inside the repository the default config works, so this path is
        # invisible exactly where the code is written.
        if isinstance(e.code, int) or e.code is None:
            raise
        print(str(e.code), file=sys.stderr)
        return 2
    finally:
        sys.argv = saved


if __name__ == "__main__":
    sys.exit(main() or 0)
