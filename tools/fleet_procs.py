"""Find and stop the practice-fleet servers by what is actually running.

`fleet.sh down` used to work from a pid file, and it was wrong in a way that hid itself. The
number it recorded was the SUBSHELL's, not the detached server's, so `down` printed "stopped
13964" and exited 0 while eight servers kept listening. It had never once done what it said,
and nothing caught it because the only evidence was a `status` nobody ran afterwards. Eight of
them survived an hour that way.

So this does not trust a recorded number. It asks the operating system what is running and
matches on two things at once: the process is one of the fleet's own interpreters, AND it is
running one of the fleet's own scripts. Something else of yours on 8099 is left alone, which is
the property the pid file was there to provide — provided now by a check that can be wrong out
loud rather than by a note we wrote to ourselves.

MATCHING ON THE INTERPRETER RATHER THAN THE PORT IS THE POINT. The first version of this file
looked up whoever held each fleet port, which misses a server that has been started but has not
opened its socket yet: nemo spends the better part of a minute building embeddings before it
listens. `down` during that window would have called it "not running" and walked away, leaving
exactly the orphan this file exists to prevent — the same defect as the pid file, wearing a
better disguise. A booting server has a command line long before it has a port.

    python tools/fleet_procs.py owners --interp PY [--interp PY] [PORT ...]
    python tools/fleet_procs.py stop   --interp PY [--interp PY] [PORT ...]

Ports are optional and only decide what `status`-style reporting says; stopping does not depend
on them.

No psutil: the fleet's interpreter is whatever the target configs run under, and requiring a
package there to shut a server down would be a dependency bought at the worst moment.
"""

import csv
import io
import os
import re
import signal
import subprocess
import sys

# A process is ours only if its command line names one of these AND one of the interpreters
# passed in. Kept explicit rather than derived from the fleet table so that widening it is a
# deliberate edit: "anything python running a server.py" is exactly the blind kill this file
# exists to avoid, and there is more than one server.py on a developer's machine.
OURS = ("server.py", "server_code.py")

WINDOWS = os.name == "nt"


class CannotLook(Exception):
    """The operating system would not tell us what is running.

    A distinct exception rather than an empty result, because the empty result IS the bug this
    module was written to replace. `powershell` missing from PATH, blocked by policy, or in
    constrained-language mode made `command_lines()` return `{}`, `owners()` return `[]`, and
    `stop` print "no fleet server is running" and exit 0 — a confident claim backed by zero
    observations, which is exactly what the pid file used to do.
    """


def _run(cmd, required=False):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        if required:
            raise CannotLook("%s: %s" % (cmd[0], e))
        return ""
    if required and p.returncode != 0 and not (p.stdout or "").strip():
        raise CannotLook("%s exited %d: %s"
                         % (cmd[0], p.returncode, (p.stderr or "").strip()[:200]))
    return p.stdout or ""


def _norm(path):
    """Compare paths the way the OS does, not the way they were typed.

    Three ways the same interpreter fails to match itself, all of them seen here: fleet.sh
    builds paths with forward slashes from a bash `pwd` while Windows reports backslashes; the
    case differs; and `$HERE/../foreign-agent-env/...` keeps its `..`, which no running process
    ever has in its command line. That last one hid two servers on the first run — reported as
    not ours and left alive, which is this file's own failure mode turning up inside the fix for
    it. Collapse the path before comparing, never after.
    """
    return os.path.normpath(path).replace("\\", "/").lower()


def command_lines():
    """{pid: command line}. One call, not one per pid — eight PowerShell launches to shut down
    eight servers turns a stop into something you avoid running."""
    lines = {}
    if WINDOWS:
        ps = ("Get-CimInstance Win32_Process | "
              "Select-Object ProcessId,CommandLine | ConvertTo-Csv -NoTypeInformation")
        text = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                    required=True)
        for row in csv.DictReader(io.StringIO(text)):
            pid = (row.get("ProcessId") or "").strip()
            if pid.isdigit():
                lines[pid] = (row.get("CommandLine") or "").strip()
        if not lines:
            raise CannotLook("PowerShell returned no processes at all")
        return lines
    for line in _run(["ps", "-e", "-o", "pid=,args="], required=True).splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and parts[0].isdigit():
            lines[parts[0]] = parts[1]
    if not lines:
        raise CannotLook("ps returned no processes at all")
    return lines


def listeners():
    """{port: [pid, ...]} for TCP ports in a LISTEN state. Reporting only — see the module
    docstring for why stopping must not depend on this."""
    out = {}
    if WINDOWS:
        for line in _run(["netstat", "-ano", "-p", "TCP"]).splitlines():
            f = line.split()
            if len(f) < 5 or f[0] != "TCP" or f[3] != "LISTENING":
                continue
            port, pid = f[1].rsplit(":", 1)[-1], f[4]
            if port.isdigit() and pid.isdigit():
                out.setdefault(port, []).append(pid)
        return out
    text = _run(["ss", "-ltnpH"])
    if text:
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            port = parts[3].rsplit(":", 1)[-1]
            for chunk in line.split("pid=")[1:]:
                pid = chunk.split(",")[0].strip()
                if pid.isdigit() and port.isdigit():
                    out.setdefault(port, []).append(pid)
        if out:
            return out
    for line in _run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"]).splitlines()[1:]:
        f = line.split()
        if len(f) >= 9 and f[1].isdigit():
            port = f[8].rsplit(":", 1)[-1]
            if port.isdigit():
                out.setdefault(port, []).append(f[1])
    return out


def _names_script(cmdline):
    """Does this command line run one of OUR scripts, as a whole argument?

    Anchored, because a bare substring also matches `test_server.py`, `webserver.py` and
    `myserver.py` — and this function decides what gets killed.
    """
    for name in OURS:
        if re.search(r"(?:^|[\s/\\\"'])" + re.escape(name) + r"(?:[\s\"']|$)", cmdline):
            return True
    return False


def owners(interps):
    """[(pid, cmdline)] for every process that is recognisably one of ours, listening or not.

    Raises CannotLook when the OS would not answer. The caller must not turn that into "none".
    """
    wanted = [_norm(i) for i in interps if i]
    if not wanted:
        return []
    found = []
    for pid, cmd in command_lines().items():
        low = _norm(cmd)
        if any(i in low for i in wanted) and _names_script(low):
            found.append((pid, cmd))
    return found


def stop(pid):
    if WINDOWS:
        # The shortest ceiling here, because this is a SHUTDOWN. `taskkill /F /T` returns
        # in milliseconds or not at all, and a stop that blocks is a fleet nobody can bring
        # down without finding the pids by hand.
        try:
            subprocess.run(["taskkill", "/PID", pid, "/F", "/T"], capture_output=True,
                           timeout=30)
        except subprocess.TimeoutExpired:
            print("  ! taskkill did not return for pid %s; kill it by hand" % pid)
        return
    # os.kill rather than /bin/kill: one fewer executable that has to exist for a shutdown to
    # work, and a missing one would otherwise raise FileNotFoundError out of a cleanup path.
    try:
        os.kill(int(pid), signal.SIGKILL)
    except (OSError, ValueError):
        pass


def main(argv):
    action, interps, ports = None, [], []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--interp":
            i += 1
            if i < len(argv):
                interps.append(argv[i])
        elif action is None:
            action = a
        else:
            ports.append(a)
        i += 1

    if action not in ("owners", "stop"):
        print("usage: fleet_procs.py [owners|stop] --interp PY [--interp PY] [PORT ...]",
              file=sys.stderr)
        return 2
    if not interps:
        # Without an interpreter there is no safe match, and guessing one would mean killing
        # by script name alone. Refusing is the only honest answer.
        print("  refusing: no --interp given, so nothing can be identified as ours",
              file=sys.stderr)
        return 2

    try:
        mine = owners(interps)
    except CannotLook as e:
        # NOT "nothing is running". The point of this module is that a claim about what is
        # running must be backed by an observation, and here there is none. Exit 3 matches the
        # engine's own code for "nothing was measured".
        print("  CANNOT LOOK: %s" % e, file=sys.stderr)
        print("  Nothing was stopped, and nothing can be said about what is running.",
              file=sys.stderr)
        print("  This is a failure to observe, not an empty fleet.", file=sys.stderr)
        return 3

    if action == "owners":
        for pid, cmd in mine:
            print("%s %s" % (pid, cmd))
        return 0

    if not mine:
        # Distinguish an empty fleet from a fleet we failed to recognise. A port that answers
        # but is not ours is the one case where "nothing running" would be a lie.
        heard = listeners()
        held = [p for p in ports if heard.get(str(p))]
        if held:
            print("  nothing stopped: %s answering but not ours" % ", ".join(held))
        else:
            print("  nothing stopped: no fleet server is running")
        return 0

    for pid, _ in mine:
        stop(pid)
    print("  stopped %d: pids %s" % (len(mine), ", ".join(pid for pid, _ in mine)))

    try:
        left = owners(interps)
    except CannotLook as e:
        print("  could not re-check after stopping (%s) — run `status` before trusting this" % e,
              file=sys.stderr)
        return 3
    if left:
        print("  STILL UP: pids %s" % ", ".join(pid for pid, _ in left))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
