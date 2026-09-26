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
WRAPPER_PID=""
trap '[ -n "$WRAPPER_PID" ] && { pkill -P "$WRAPPER_PID" 2> /dev/null || true; }; rm -rf "$WORKDIR"' EXIT

FAILURES=0

# Report a failed check and remember it for the exit status.
function fail() {
  echo "FAIL: $1"
  FAILURES=$((FAILURES + 1))
}

# ph_pid_for_socket must pick ph itself, not a process that wraps it
# (zipline#116). The tests launch ph as
#   sudo ... ip netns exec ... sudo ... env ... $PH_BIN adapter --control-path S
# so every wrapper's command line also contains "--control-path S", and the
# outermost wrapper has the lowest PID. Model that with a bash parent whose
# command line contains the whole ph invocation, and a child whose command
# line starts with $PH_BIN, the way ph's does once env has exec'd it.
PH_BIN="$WORKDIR/target/debug/ph"
SOCK="adapter1-$$.sock"
bash -c "(exec -a '$PH_BIN adapter --control-path $SOCK --name adapter1' sleep 30); true" 2> /dev/null &
WRAPPER_PID=$!

CHILD_PID=""
for _ in $(seq 50); do
  CHILD_PID=$(pgrep -P "$WRAPPER_PID" || true)
  [ -n "$CHILD_PID" ] && break
  sleep 0.1
done
[ -n "$CHILD_PID" ] || { echo "FAIL: fake ph did not start"; exit 1; }

FOUND=$(ph_pid_for_socket "$SOCK")
[ "$FOUND" = "$CHILD_PID" ] \
  || fail "ph_pid_for_socket returned '$FOUND', want ph at $CHILD_PID (wrapper is $WRAPPER_PID)"

FOUND=$(ph_pid_for_socket "other-$$.sock")
[ -z "$FOUND" ] || fail "ph_pid_for_socket matched an unrelated socket: '$FOUND'"

# process_exited must be false for a live process and true once it is gone.
process_exited "$CHILD_PID" && fail "process_exited says live PID $CHILD_PID has exited"
kill "$CHILD_PID"
wait "$WRAPPER_PID" 2> /dev/null || true
process_exited "$CHILD_PID" || fail "process_exited says dead PID $CHILD_PID is still alive"

if [ "$FAILURES" -ne 0 ]; then
  echo "$FAILURES check(s) failed"
  exit 1
fi
echo "PASS"
