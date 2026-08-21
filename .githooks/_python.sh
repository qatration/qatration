# Find an interpreter that RUNS, not one that merely resolves. Sourced by both hooks.
#
# `command -v python` succeeds on Windows for the Microsoft Store alias — a stub that exists on
# PATH, exits non-zero, and prints "Python was not found". So the hook refused a commit, and it
# refused it for the wrong reason: the first end-to-end test of this planted a GitHub token,
# watched the commit fail, and read that as the token being caught. A gate that fails closed is
# right; a gate that cannot tell you WHY it failed teaches people to pass --no-verify.
#
# So each candidate is executed before it is trusted, and if none works the hook says exactly
# that rather than implying a check was performed.
find_python() {
    for candidate in python3 python "py -3"; do
        # shellcheck disable=SC2086
        if $candidate -c "import sys; sys.exit(0)" >/dev/null 2>&1; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}
