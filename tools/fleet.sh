#!/usr/bin/env bash
# Start, stop or check the practice fleet.
#
# Fifteen target configs point at a process on localhost, and until this existed there was no
# way to bring them up except by reading each config for its port and starting the right server
# by hand. A clone could not run most of the suite, and nothing said why: a target whose server
# is down errors on every trial, which the engine correctly refuses to write — so the result was
# an empty run rather than an explanation.
#
#     tools/fleet.sh up       # start whatever is not already listening
#     tools/fleet.sh status   # which ports answer
#     tools/fleet.sh down     # stop what this script started
#
# FOUR THINGS THIS GOT WRONG, every one of them found by running it rather than reading it, and
# every one of them a version of the same mistake: reporting something that did not happen.
#
# It hung. `( cd dir && cmd & )` does not detach while the parent holds the pipe, and
# redirecting the subshell's streams was not enough on its own — the subshell has to be
# backgrounded and disowned too. Until it was, `up` never returned: a shell sat waiting on
# children for an hour, costing no CPU and no GPU, which is exactly why nobody saw it.
#
# It assumed one interpreter, twice. `foreign-agent/` needs smolagents and `external/nemo/`
# needs nemoguardrails, each in its own environment; driving either with the main python starts
# a process that dies on the import, leaving a port that never opens and a script that says it
# started something. Each entry names its own python now, and a missing one is said out loud.
#
# And `down` did not stop anything. It killed by a recorded pid, but the number recorded was the
# subshell's rather than the server's, so it printed success while eight servers kept listening.
# It now matches on what is actually running — see tools/fleet_procs.py.
#
# Needs an Ollama on :11434 serving the models the target configs name. The bots are the only
# reason any of this is required: testing your OWN endpoint needs none of it.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# A venv puts its interpreter in `Scripts/` on Windows and `bin/` everywhere else. Hardcoding
# one layout meant that on the other platforms every entry in the table below resolved
# to a path that does not exist, `up` printed "NO PYTHON" eight times, and the practice fleet
# was unusable on two of the three platforms it claims to run on. Invisible from whichever
# platform it was written on, which is the whole reason CI has a macOS and a Linux leg.
#
# THREE ENVIRONMENTS, THREE OVERRIDES, and the defaults below are where the documentation says
# to create them — not where yours has to be. If `up` prints NO PYTHON for a target, point it at
# the interpreter you have rather than moving the directory:
#
#     QATRATION_PYTHON=/path/to/python      the practice bots built on langchain
#     SMOLAGENTS_PYTHON=/path/to/python     foreign-agent/, which needs smolagents
#     NEMO_PYTHON=/path/to/python           external/nemo/, which needs nemoguardrails
#
# They cannot share one environment: that assumption is what the note above is about.
venv_python() {   # venv-dir -> the interpreter inside it, whichever layout this platform uses
  local d="$1"
  for candidate in "$d/bin/python" "$d/bin/python3" "$d/Scripts/python.exe" "$d/Scripts/python"; do
    [ -x "$candidate" ] || [ -f "$candidate" ] && { echo "$candidate"; return; }
  done
  # Nothing there. Echo the platform's expected path anyway, so `up` can say WHICH file it
  # wanted rather than printing an empty name.
  if [ -d "$d/Scripts" ]; then echo "$d/Scripts/python"; else echo "$d/bin/python"; fi
}

MAIN="${QATRATION_PYTHON:-$(venv_python "$HERE/dvla/env")}"
SMOL="${SMOLAGENTS_PYTHON:-$(venv_python "$HERE/foreign-agent/foreign-agent-env")}"
NEMO="${NEMO_PYTHON:-$(venv_python "$HERE/external/nemo/venv")}"
PIDS="$HERE/out/.fleet-pids"

# port | directory | interpreter | script | arguments
FLEET=(
  "8099|$HERE/httpbot|$MAIN|server.py|"
  "8102|$HERE/draftbot|$MAIN|server.py|"
  # Two mistakes lived on these two lines. nemoguardrails has its own environment, and pointing
  # $MAIN at it was the smolagents error made a second time in the same table: `up` prints
  # "starting", the import dies, and only a `status` afterwards shows a port that never opened.
  #
  # The second was worse, because it looked like it worked. This column used to hold an
  # environment assignment, and 8101 set `PORT=8101` — but this server takes its config and its
  # port as ARGUMENTS and never reads that variable. So it launched a second copy of the DEFAULT
  # config, which could not bind 8100 and died, while targets_nemo_inputonly.yaml and
  # targets_nemo_rag_inputonly.yaml pointed at an 8101 that was never going to answer. The
  # column carries arguments now, and nothing in the table needs an environment variable.
  "8100|$HERE/external/nemo|$NEMO|server.py|config 8100"
  "8101|$HERE/external/nemo|$NEMO|server.py|config_inputonly 8101"
  "8200|$HERE/external/guardedrag|$MAIN|server.py|"
  "8130|$HERE/foreign-agent|$SMOL|server.py|"
  "8131|$HERE/foreign-agent|$SMOL|server_code.py|"
  "8140|$HERE/foreign-langchain|$MAIN|server.py|"
)

# ONLY `status` COULD LIE, AND IT DID. `listening()` returns the exit status of $MAIN, and a
# missing interpreter exits 127 — indistinguishable from a closed port. On a fresh clone, or on
# Linux, `dvla/env/Scripts/python` does not exist, so every port read as down while servers were
# demonstrably answering. `up` says "NO PYTHON" out loud and `down` fails noisily; `status` was
# the one command that turned "I cannot check" into "it is not running".
require_python() {
  if "$MAIN" -c "pass" >/dev/null 2>&1; then return 0; fi
  echo "  CANNOT CHECK: no usable interpreter at $MAIN" >&2
  echo "  Nothing below would be a measurement, so nothing is printed. Set \$QATRATION_PYTHON" >&2
  echo "  to a python that exists, or create the environment this repo's README describes." >&2
  exit 3
}

listening() {
  "$MAIN" -c "
import socket,sys
s=socket.socket(); s.settimeout(0.4)
sys.exit(0 if s.connect_ex(('127.0.0.1',int('$1')))==0 else 1)" 2>/dev/null
}

detach() {   # dir interpreter script args
  # The subshell is backgrounded and disowned as well, because redirecting its streams was not
  # enough on its own: `up` still did not return, and a background shell sat waiting on children
  # for an hour before anyone noticed. It burned no CPU and touched no GPU the whole time, which
  # is precisely why it went unseen — a hang that costs nothing still hangs.
  local dir="$1" py="$2" script="$3" argstr="$4"
  (
    cd "$dir" || exit 1
    # Deliberately unquoted: the column holds a whitespace-separated argument list, and none of
    # the arguments in it contain spaces. If one ever does, give this an array rather than
    # quoting it, because quoting turns two arguments into one silently.
    # shellcheck disable=SC2086
    if command -v setsid >/dev/null 2>&1; then
      setsid "$py" "$script" $argstr </dev/null >/dev/null 2>&1 &
    else
      "$py" "$script" $argstr </dev/null >/dev/null 2>&1 &
    fi
    disown 2>/dev/null || true
  ) </dev/null >/dev/null 2>&1 &
  disown 2>/dev/null || true
}

case "${1:-status}" in
  up)
    require_python
    mkdir -p "$HERE/out"
    # Kept as a breadcrumb only. `down` does not read it, and the reason it does not is
    # that believing it is what let eight servers outlive the run that started them.
    : > "$PIDS"
    for entry in "${FLEET[@]}"; do
      IFS='|' read -r port dir py script args <<< "$entry"
      if listening "$port"; then echo "  $port already up"; continue; fi
      if [ ! -f "$dir/$script" ]; then echo "  $port MISSING  $dir/$script"; continue; fi
      # A missing interpreter is said out loud. Starting a server with the wrong python opens
      # no port and prints nothing, which reads exactly like a target that is simply slow.
      if [ ! -x "$py" ] && [ ! -f "$py" ] && [ ! -f "$py.exe" ]; then
        echo "  $port NO PYTHON  $py"
        continue
      fi
      detach "$dir" "$py" "$script" "$args"
      echo "  $port starting  $(basename "$dir")/$script"
    done
    echo "give them a few seconds, then: tools/fleet.sh status"
    ;;
  status)
    require_python
    up=0
    for entry in "${FLEET[@]}"; do
      IFS='|' read -r port dir py script args <<< "$entry"
      if listening "$port"; then echo "  UP    $port  $(basename "$dir")/$script"; up=$((up+1))
      else echo "  down  $port  $(basename "$dir")/$script"; fi
    done
    echo "$up of ${#FLEET[@]} listening"
    ;;
  down)
    # By what is RUNNING, not by a number we wrote down. See tools/fleet_procs.py: the pid file
    # recorded the subshell rather than the server, so this reported success while eight servers
    # kept listening. Still not a blind kill by port — a process is stopped only when its own
    # command line names one of the fleet's scripts.
    ports=()
    for entry in "${FLEET[@]}"; do
      IFS='|' read -r port dir py script args <<< "$entry"
      ports+=("$port")
    done
    # Every interpreter the table names, because a server started under the wrong one is
    # exactly the orphan worth catching. The ports only decide what the failure message says.
    "$MAIN" "$HERE/tools/fleet_procs.py" stop \
      --interp "$MAIN" --interp "$SMOL" --interp "$NEMO" "${ports[@]}"
    rc=$?
    rm -f "$PIDS"
    exit $rc
    ;;
  *)
    echo "usage: tools/fleet.sh [up|status|down]" >&2
    exit 2
    ;;
esac
