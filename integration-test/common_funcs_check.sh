#!/usr/bin/env bash
#
# Self-check for the process helpers in lib/common_funcs.sh. Needs no root,
# network namespaces or built binaries, so it runs anywhere:
#
#   ./integration-test/common_funcs_check.sh
#
# Deliberately not named *-test.sh, so `make docker-test` does not pick it up
# as an integration test.

set -euo pipefail

source "$(dirname "$0")/lib/common_funcs.sh"

WORKDIR=$(mktemp -d)
WRAPPER_PIDS=()
trap 'for w in "${WRAPPER_PIDS[@]}"; do pkill -P "$w" 2> /dev/null || true; done; rm -rf "$WORKDIR"' EXIT

FAILURES=0

# Report a failed check and remember it for the exit status.
function fail() {
  echo "FAIL: $1"
  FAILURES=$((FAILURES + 1))
}

# Start a fake ph serving control socket $1 and set FAKE_PH_PID to its PID
# and FAKE_WRAPPER_PID to the PID of the process wrapping it.
#
# The tests launch ph as
#   sudo ... ip netns exec ... sudo ... env ... $PH_BIN adapter --control-path S
# so every wrapper's command line also contains "--control-path S", and the
# outermost wrapper has the lowest PID. Model that with a bash parent whose
# command line contains the whole ph invocation, and a child whose command
# line starts with $PH_BIN, the way ph's does once env has exec'd it.
function start_fake_ph() {
  bash -c "(exec -a '$PH_BIN adapter --control-path $1 --name adapter1' sleep 30); true" 2> /dev/null &
  FAKE_WRAPPER_PID=$!
  WRAPPER_PIDS+=("$FAKE_WRAPPER_PID")

  FAKE_PH_PID=""
  for _ in $(seq 50); do
    FAKE_PH_PID=$(pgrep -P "$FAKE_WRAPPER_PID" || true)
    [ -n "$FAKE_PH_PID" ] && return 0
    sleep 0.1
  done
  echo "FAIL: fake ph for $1 did not start"
  exit 1
}

# The binary path carries regex metacharacters ("+", "."), which must match
# literally.
PH_BIN="$WORKDIR/build+asan/ph"
SOCK="adapter1-$$.sock"

# A decoy whose socket name matches "$SOCK" read as a regex ("." matching
# "X"). Started first so it has the lower PID, which `head -n 1` would pick.
start_fake_ph "adapter1-$$Xsock"
DECOY_PID=$FAKE_PH_PID

start_fake_ph "$SOCK"
PH_PID=$FAKE_PH_PID
PH_WRAPPER_PID=$FAKE_WRAPPER_PID

# ph_pid_for_socket must pick ph itself: not a process that wraps it
# (zipline#116), and not a process whose socket merely matches as a regex.
FOUND=$(ph_pid_for_socket "$SOCK")
[ "$FOUND" = "$PH_PID" ] \
  || fail "ph_pid_for_socket returned '$FOUND', want ph at $PH_PID (wrapper $PH_WRAPPER_PID, decoy $DECOY_PID)"

FOUND=$(ph_pid_for_socket "other-$$.sock")
[ -z "$FOUND" ] || fail "ph_pid_for_socket matched an unrelated socket: '$FOUND'"

# process_exited must be false for a live process and true once it is gone.
process_exited "$PH_PID" && fail "process_exited says live PID $PH_PID has exited"
kill "$PH_PID"
wait "$PH_WRAPPER_PID" 2> /dev/null || true
process_exited "$PH_PID" || fail "process_exited says dead PID $PH_PID is still alive"

if [ "$FAILURES" -ne 0 ]; then
  echo "$FAILURES check(s) failed"
  exit 1
fi
echo "PASS"
