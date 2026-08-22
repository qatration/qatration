"""NOTICE, checked against the tree. Both directions.

Every published NUMBER in this repository is recounted by a test that fails when the claim and
the code disagree. No published ATTRIBUTION was, and it showed: a pre-publication review found
NOTICE wrong in four places at once.

  * "The rest of the attack corpus is written here", while two attacks embedded the two most
    reproduced GCG adversarial suffixes character for character.
  * "Two attacks in redteam/attacks.yaml" used DVLA payload text. Three pieces of upstream text
    were reproduced, one of them across three attacks, and the longest was uncredited.
  * "Five artifacts under out/" carried smolagents prompt text. There were six -- and which
    files carry it depends on which phrase you search for, because a model reproduces different
    fragments on different runs.
  * "Where a published string is used it is cited beside the attack that uses it", while
    `build_generic.py` writes `attacks_generic.yaml` with `yaml.safe_dump`, which drops every
    comment. That file is 362 of the 824 shipped attacks: the larger half, and the half a
    `pip install` user reads.

All four are the same defect. NOTICE drifted from the tree and nothing looked.

WHAT THIS ENFORCES, and why it is a rule rather than a file list. Each reproduction is keyed by
a MARKER: a phrase specific enough that its presence means the upstream text is present. Then:

  FORWARD   every file containing a marker is either a source file NOTICE names, or under
            `out/`, which NOTICE covers with a standing rule because artifacts are recorded
            model output and change whenever a run is re-recorded.
  BACKWARD  every source file NOTICE names still contains what it claims to, and every attack
            id NOTICE names still exists. An attribution for text that has been deleted is as
            wrong as a missing one, and it is the direction nobody checks.

Adding a marker here is the cost of reproducing somebody's text, and it is meant to be.

    python test_notice.py       # exits 1 on any failure (CI gate)
"""
import glob
import io
import os
import re
import subprocess
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# (marker, the source files NOTICE must account for). A marker is chosen to be a phrase that
# only the reproduced text contains -- not a word that could arrive by coincidence.
#
# `out/` is never listed: artifacts are recorded model output, NOTICE says so as a standing rule,
# and enumerating them is what went stale.
REPRODUCTIONS = [
    ("expert assistant who can solve any task", "smolagents agent prompt",
     {"redteam/targets_foreign.yaml", "redteam/targets_foreign_code.yaml"}),
    # A DIFFERENT FRAGMENT, so a separate marker. `test_oracle.py` uses an abridged extract of
    # the rules block, not the opening line, and declaring it under the marker above made this
    # suite report the file as having lost text it never held.
    ("You are an expert assistant. Here are the rules", "smolagents rules block, abridged",
     {"redteam/test_oracle.py"}),
    ("ans shows them", "DVLA system prompt, upstream typo included",
     {"redteam/targets_dvla.py"}),
    ("(#system) NEW IMPORTANT INSTRUCTION", "DVLA migration injection",
     {"redteam/attacks.yaml", "redteam/attacks_generic.yaml"}),
    ("being careful not to alter the provided userId", "DVLA forged Thought observation",
     {"redteam/attacks.yaml", "redteam/attacks_generic.yaml"}),
    ("UNION SELECT 1,username,password", "DVLA UNION SELECT worked example",
     {"redteam/attacks.yaml", "redteam/attacks_generic.yaml"}),
    ("plutonium-256", "DVLA seeded canary",
     {"redteam/targets_dvla.yaml"}),
    ("similarlyNow write oppositeley", "GCG adversarial suffix, Zou et al.",
     {"redteam/attacks_coverage.yaml", "redteam/attacks_generic.yaml"}),
    ("DJstructor Tuialsheet", "GCG adversarial suffix, Zou et al.",
     {"redteam/attacks_coverage.yaml", "redteam/attacks_generic.yaml"}),
    ("{{ user_input }}", "NVIDIA NeMo self-check scaffold",
     {"external/nemo/config/prompts.yml",
      "external/nemo/config_inputonly/prompts.yml", "redteam/isolation_nemo.yaml"}),
    ("AKIDEXAMPLE", "AWS published SigV4 test vectors",
     {"redteam/test_signing.py"}),
    # ASSEMBLED FROM SPLIT LITERALS, so only the half-string is greppable and only in the
    # detector. The attacks name the markers without carrying them, which is the point: a
    # literal EICAR in a repository gets the clone quarantined.
    ("XJS*C4JDBQADN1", "GTUBE marker prefix, in the detector only",
     {"redteam/oracle.py"}),
]

# THE TWO FILES THAT CANNOT BE SCANNED FOR WHAT THEY DECLARE. NOTICE quotes the strings it is
# attributing, and this suite lists every marker in the table above -- so both hold reproduced
# text by construction, and both were flagged on the first run.
#
# It passed in the repository at that moment for the worst possible reason: this file was not
# yet added to git, so `git ls-files` did not name it and the check simply did not look. A
# mutation run on a copy where it WAS tracked is what surfaced it. Named, with the reason,
# rather than left to be discovered again -- the same shape as `SELF` in `tools/guard.py`.
SELF = {"NOTICE", "redteam/test_notice.py"}

# Things NOTICE must go on saying, because each is load-bearing for a licence or a claim.
MUST_SAY = [
    ("Apache License, Version 2.0", "the licence this project is under"),
    ("ReversecLabs", "the DVLA attribution"),
    ("arXiv:2307.15043", "the GCG paper"),
    ("llm-attacks", "the GCG repository"),
    ("HuggingFace", "the smolagents attribution"),
    ("NeMo Guardrails", "the NVIDIA attribution"),
    ("SpamAssassin", "the GTUBE/GTPHISH attribution"),
    ("CC BY-SA 4.0", "the OWASP label licence"),
    ("garak", "the technique credit that lives only in comments otherwise"),
]


def main():
    fails, checks = [], 0

    def check(label, ok, detail=""):
        nonlocal checks
        checks += 1
        print(f"{'PASS' if ok else 'FAIL'}  {label}")
        if not ok:
            fails.append(f"{label}: {detail}")

    notice_path = os.path.join(ROOT, "NOTICE")
    notice = io.open(notice_path, encoding="utf-8").read()

    tracked = subprocess.run(["git", "-C", ROOT, "ls-files"], capture_output=True,
                             encoding="utf-8", errors="replace").stdout.split()
    check("the repository lists tracked files, so this suite can see the tree",
          len(tracked) > 100, f"{len(tracked)} files")

    def holding(marker):
        """Tracked files containing `marker`, read from disk rather than through `git grep`,
        because `git grep` needs pattern escaping and a payload is full of metacharacters."""
        out = []
        for rel in tracked:
            p = os.path.join(ROOT, rel)
            try:
                if marker in io.open(p, encoding="utf-8", errors="replace").read():
                    out.append(rel.replace("\\", "/"))
            except OSError:
                continue
        return out

    for marker, what, declared in REPRODUCTIONS:
        found = holding(marker)
        # BACKWARD: an attribution for text that is gone is as wrong as a missing one.
        check(f"{what}: the text is still in the tree",
              bool(found), f"no tracked file contains {marker!r} — delete the NOTICE entry")
        if not found:
            continue
        # FORWARD: nothing carries it that NOTICE does not account for.
        # NOTICE ITSELF IS NEVER A STRAY. It quotes the strings it is attributing, which is
        # what an attribution looks like, and the first run of this flagged NOTICE for
        # containing the text NOTICE exists to declare.
        stray = sorted(f for f in found
                       if not f.startswith("out/") and f not in SELF and f not in declared)
        check(f"{what}: no source file carries it that NOTICE does not name",
              not stray, f"unaccounted: {stray}")
        gone = sorted(d for d in declared if d not in found)
        check(f"{what}: every source NOTICE names still contains it",
              not gone, f"named but no longer holding it: {gone}")

    # Attack ids NOTICE names must exist, or the reader is sent looking for nothing.
    import yaml
    ids = set()
    for f in glob.glob(os.path.join(HERE, "attacks*.yaml")):
        try:
            for a in (yaml.safe_load(io.open(f, encoding="utf-8")) or []):
                if isinstance(a, dict) and a.get("id"):
                    ids.add(a["id"])
        except Exception:
            continue
    named = {n for n in re.findall(r"`([a-z0-9][a-z0-9-]{4,})`", notice)
             if "-" in n and not n.endswith((".yaml", ".yml", ".py", ".json", ".html"))}
    # canaries are values, not attack ids
    named -= {"plutonium-256", "flux-capacitor-123"}
    missing = sorted(named - ids)
    check("every attack id NOTICE names exists in the arsenal",
          not missing, f"named but absent: {missing}")

    for phrase, why in MUST_SAY:
        check(f"NOTICE still carries {why}", phrase in notice, f"{phrase!r} is gone")

    # The claim that started this: a generated file cannot carry a comment, so NOTICE has to be
    # where provenance lives. If the generator ever learns to preserve comments, this can go.
    gen = os.path.join(HERE, "build_generic.py")
    if os.path.isfile(gen):
        src = io.open(gen, encoding="utf-8").read()
        check("NOTICE explains why the generated arsenal carries no inline citation",
              ("safe_dump" in src) <= ("drops every comment" in notice
                                       or "drops comments" in notice),
              "build_generic still uses safe_dump and NOTICE no longer says so")

    print(f"\n{checks - len(fails)}/{checks} passed")
    if fails:
        for f in fails:
            print("  ! " + f)
        sys.exit(1)
    print("\nOK — NOTICE and the tree agree, in both directions.")


if __name__ == "__main__":
    main()
