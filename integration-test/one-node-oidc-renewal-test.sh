#!/usr/bin/env bash
# Silent-OIDC-renewal integration test (zipline#47).
#
# one-node-oidc-test.sh proves an OIDC *login* works. This proves the whole
# renewal loop that follows it, against the same fake IdP, with no Google and
# no browser. Three differences from that test:
#
#   1. The policy is oidc-renewal.bin2: `allow_offline_access = true`,
#      `expiration_seconds = 120`, `max_auth_age_seconds = 3600`. The node
#      renews at `auth_expires - min(AUTH_RENEWAL_LEAD, lifetime/2)`, so the
#      first renewal is due about 60 s after a login.
#   2. Logins run `ph-cli auth-agent <link> --no-browser` and the agent
#      processes are left RESIDENT. Renewal only happens while an AuthAgent
#      is registered and its process alive, so `connect` — which returns as
#      soon as the link is up — cannot renew. That is the whole point of the
#      *User-facing flow* table in adapter/cli/README.
#   3. The key-rotation leg is dropped (one-node-oidc-test.sh covers it) in
#      favour of a renewal leg and a revocation leg.
#
# Legs:
#
#   1. Connect. Both adapters log in through their resident agents; carrier
#      on every TUN; ping.
#   2. Renewal. Wait past the renewal lead and assert: a `reauthorize`
#      crossed the wire to the visa service, NO authorization-endpoint
#      request was made (the count of `GET /auth` in each IdP log is
#      unchanged — a silent renewal is a back-channel POST and nothing
#      else), `show-link` reports an authentication expiry, and traffic
#      still flows across the boundary.
#   3. Revocation. `fake-idp.py --revoke-refresh` models the user withdrawing
#      the application's access. Assert the next renewal fails, that the visa
#      service's authentication-expiry sweep then revokes the actor and drops
#      it, and that traffic across the boundary stops.
#
# Everything else — the per-netns fake IdPs (loopback is per-netns, so the
# pinned issuer https://127.0.0.1:9000 needs one instance per namespace that
# dials it), the test-CA TLS, the SSL_CERT_FILE trust plumbing — works exactly
# as in one-node-oidc-test.sh, which documents the reasoning.
#
# The run takes several minutes: the renewal cadence is a real wall clock and
# cannot be fast-forwarded from outside the processes.
#
# Observed passing on 2026-09-25 at zl-zpr-core 824d7a5, twice: by the
# operator on the host, and under Docker (make docker-test). Those runs
# predate the strengthened leg-3 assertions added by zipline#104 (which
# require the revocation leg to prove the revoked grant was actually
# presented and rejected — see LEG 3 below); with those assertions and the
# threaded fake IdP, observed passing under Docker on 2026-09-25.
set -euo pipefail

export RUST_BACKTRACE=1
DEBUG_TARGETS=${DEBUG_TARGETS:-all=INFO}
KM_IMPL=${KM_IMPL:-noise}


PH_BIN="${PH_BIN:-$(realpath "$(dirname "$0")/../target/debug/ph")}"
PH_DEBUG_BIN="${PH_DEBUG_BIN:-$(realpath "$(dirname "$0")/../target/debug/ph-cli")}"
VS_BIN="${VS_BIN:-$(realpath "$(dirname "$0")/vs")}"
VS_ADMIN_BIN="${VS_ADMIN_BIN:-$(realpath "$(dirname "$0")/vs-admin")}"
VALKEY_SERVER_BIN="${VALKEY_SERVER_BIN:-$(realpath -s "$(dirname "$0")/valkey-server")}"

PREGEN=$(realpath "$(dirname $0)/pregen")
FAKE_IDP=$(realpath "$(dirname $0)/lib/fake-idp.py")
NODE_AUTH_PRIVATE_KEY="${NODE_AUTH_PRIVATE_KEY:-$PREGEN/node-rsa-key.pem}"

# netem parameters to configure on all links; e.g. "loss random 10%"
# blank for no netem
NETEM_PARAMS=${NETEM_PARAMS:-}

source "$(dirname $0)/lib/common_funcs.sh"

ZPR_USER=$USER

NODE_SUBSTRATE_ADDR_VS=10.0.0.1
NODE_SUBSTRATE_ADDR_A=10.0.1.1
NODE_SUBSTRATE_ADDR_B=10.0.2.1
NODE_SUBSTRATE_ADDR_C=10.0.3.1
VS_SUBSTRATE_ADDR=10.0.0.2
A_SUBSTRATE_ADDR=10.0.1.2
B_SUBSTRATE_ADDR=10.0.2.2
C_SUBSTRATE_ADDR=10.0.3.2

# IPv6, two actors, and the renewal policy — fixed (no parse_arguments.sh):
# the fixture declares exactly this shape. oidc-renewal.bin2 compiles the very
# same oidc-test.zpl, so the topology and the ping rules are identical.
NUM_ACTORS=2
NODE_ZPR_ADDR=fd5a:5052::2
VS_ZPR_ADDR=fd5a:5052::1
A_ZPR_ADDR=fd5a:5052:8888::1:1
B_ZPR_ADDR=fd5a:5052:8888::2:1
C_ZPR_ADDR=fd5a:5052:8888::3:1
ZPR_SUBNET=fd5a:5052::/32
POLICY_BIN=oidc-renewal.bin2

# The link an adapter authenticates: its tether to the node. Link 1 is the
# internal local-actor link and is Active from startup (see
# one-node-oidc-test.sh), so the dock link is 2.
DOCK_LINK=2

# The issuer the pregen policy pins; each relevant netns runs an IdP
# instance answering it on its own loopback.
IDP_PORT=9000
IDP_ISSUER="https://127.0.0.1:$IDP_PORT"

# How long to wait for the first silent renewal. `expiration_seconds` is 120
# and the lead halves to 60, so a renewal is due ~60 s after the login; the
# keep-alive tick that carries the check runs every 3 s. Generous, because a
# slow CI runner delays the login itself.
RENEWAL_WAIT=180

# How long to wait, after revoking the refresh grant, for the visa service to
# sweep the actor away: the rest of the 120 s window plus one sweep period
# (MIN_VISA_LIFETIME, 30 s), plus slack.
REVOCATION_WAIT=240

if [ ! -e "$VS_BIN" ]; then
  echo "vs binary not found, expected it at $VS_BIN"
  exit 1
fi

if [ ! -e "$VS_ADMIN_BIN" ]; then
  echo "vs-admin binary not found, expected it at $VS_ADMIN_BIN"
  exit 1
fi

if systemctl is-active --quiet valkey-server 2>/dev/null; then
  echo "valkey-server system service is running. Please stop it before running this test:"
  echo "  sudo systemctl stop valkey-server"
  exit 1
fi

if [ ! -e "$VALKEY_SERVER_BIN" ]; then
  echo "valkey-server binary not found, expected it at $VALKEY_SERVER_BIN"
  exit 1
fi

if [ ! -e "$PREGEN/$POLICY_BIN" ]; then
  echo "policy file not found (expected .bin2): $PREGEN/$POLICY_BIN"
  exit 1
fi

if [ ! -x "$PH_BIN" ]; then
  echo "ph binary not found or not executable: $PH_BIN"
  exit 1
fi

if [ ! -x "$PH_DEBUG_BIN" ]; then
  echo "ph-cli binary not found or not executable: $PH_DEBUG_BIN"
  exit 1
fi

if [ ! -e "$NODE_AUTH_PRIVATE_KEY" ]; then
  echo "node auth private key not found: $NODE_AUTH_PRIVATE_KEY"
  exit 1
fi

NODE_SOCK=node.sock
VS_SOCK=vs.sock
ADAPTER1_SOCK=adapter1.sock
ADAPTER2_SOCK=adapter2.sock
NODE_CAP_SOCK=node_cap.sock
VS_CAP_SOCK=vs_cap.sock
ADAPTER1_CAP_SOCK=adapter1_cap.sock
ADAPTER2_CAP_SOCK=adapter2_cap.sock

function counters() {
  SOCKET=$1
  "$PH_DEBUG_BIN" -p "$SOCKET" counters
}

# Launch a fake IdP inside a netns. All instances share the signing keys, TLS
# material and state directory, so they serve identical documents and both
# --rotate and --revoke-refresh reach all of them at once; the `sub` differs
# per netns so each adapter logs in as its own user (the policy's user-a /
# user-b).
#
# $1 = netns, $2 = sub claim
function launch_fake_idp() {
  NETNS=$1
  SUB=$2
  sudo -E ip netns exec "$NETNS" sudo -E -u "$ZPR_USER" python3 "$FAKE_IDP" \
    --port "$IDP_PORT" \
    --state-dir idp-state \
    --tls-cert idp.crt --tls-key idp.key \
    --signing-key "$PREGEN/fake-idp-rsa.key" \
    --signing-key-2 "$PREGEN/fake-idp-rsa-2.key" \
    --client-id zpr-test-client \
    --sub "$SUB" --email "$SUB@example.com" --hd example.com \
    2>&1 | tee "idp-$NETNS.log" | prefix_log "idp-$NETNS" &
}

# How many authorization-endpoint requests an IdP instance has served. The
# renewal assertion turns on this number NOT moving: a silent renewal is a
# back-channel `grant_type=refresh_token` POST to /token, so any /auth hit
# during the renewal window means a browser leg happened.
#
# $1 = IdP log file
function auth_requests() {
  grep -c '"GET /auth' "$1" || true
}

# Wait for a pattern to appear in a log file.
# $1 = seconds, $2 = log file, $3 = grep -E pattern
function wait_for_log() {
  local DEADLINE=$(( SECONDS + $1 ))
  local FILE=$2
  local PATTERN=$3
  while (( SECONDS < DEADLINE )); do
    if grep -qE "$PATTERN" "$FILE" 2> /dev/null; then return 0; fi
    sleep 2
  done
  return 1
}

# Launch adapter1 — user-only: deliberately NO --bootstrap-key, so the only
# authentication path is the OIDC user blob supplied through the AuthAgent,
# and therefore the only way it stays connected is silent renewal.
function launch_adapter1() {
  sudo -E ip netns exec zpr-a sudo -E -u "$ZPR_USER" env SSL_CERT_FILE="$PWD/ca.crt" "$PH_BIN" \
    adapter \
    --logging "$DEBUG_TARGETS" \
    --control-path "$ADAPTER1_SOCK" \
    --capture-path "$ADAPTER1_CAP_SOCK" \
    --self-addr "$A_SUBSTRATE_ADDR" \
    --ca-file ca.crt \
    --name adapter1 \
    --km-impl "$KM_IMPL" \
    --tun-if tun0 \
    --io-engine io_uring \
    --node-addr "$NODE_SUBSTRATE_ADDR_A" \
    --zpr-addr "$A_ZPR_ADDR" 2>&1 | tee -a adapter1.log | prefix_log zpr-a &
}

# PIDs of the resident `ph-cli auth-agent` processes, so the cleanup can stop
# them and the legs can check they are still alive.
AGENT_PIDS=()

# Interactive OIDC login with no browser, through a RESIDENT authentication
# agent: run `ph-cli auth-agent $DOCK_LINK --no-browser` inside the adapter's
# netns, scrape the printed authorization URL, fetch it with curl (following
# the 302 to ph-cli's loopback callback listener), then wait for the link to
# reach Active.
#
# Unlike `connect`, `auth-agent` does not report the outcome and does not
# exit — it blocks serving credential requests until interrupted, which is
# precisely what makes silent renewal possible — so the caller polls
# `link show` for the outcome instead of waiting on the exit status.
#
# $1 = netns, $2 = control socket, $3 = log file
function oidc_auth_agent() {
  NETNS=$1
  SOCK=$2
  LOGIN_LOG=$3

  rm -f "$LOGIN_LOG"
  sudo -E ip netns exec "$NETNS" sudo -E -u "$ZPR_USER" \
    env -u BROWSER SSL_CERT_FILE="$PWD/ca.crt" \
    "$PH_DEBUG_BIN" -p "$SOCK" auth-agent "$DOCK_LINK" --no-browser \
    > "$LOGIN_LOG" 2>&1 &
  local AGENT_PID=$!
  AGENT_PIDS+=("$AGENT_PID")

  # The URL appears once ph calls back for a credential.
  AUTH_URL=""
  for _ in $(seq 1 60); do
    AUTH_URL=$(sed -n 's/.*Open this URL to continue: //p' "$LOGIN_LOG" | head -n 1)
    if [ -n "$AUTH_URL" ]; then break; fi
    if ! kill -0 "$AGENT_PID" 2> /dev/null; then break; fi
    sleep 1
  done

  if [ -z "$AUTH_URL" ]; then
    echo "oidc_auth_agent($NETNS): no authorization URL was printed:"
    cat "$LOGIN_LOG"
    return 1
  fi

  # Drive the browserless login: GET the authorization URL; the IdP 302s
  # to http://127.0.0.1:<port>/callback where ph-cli is listening.
  sudo -E ip netns exec "$NETNS" sudo -E -u "$ZPR_USER" \
    curl --silent --show-error --location --cacert ca.crt \
    --output /dev/null "$AUTH_URL" || true

  if ! wait_for 60 check_dock_link_active "$SOCK"; then
    echo "oidc_auth_agent($NETNS): dock link never reached Active:"
    cat "$LOGIN_LOG"
    "$PH_DEBUG_BIN" -p "$SOCK" link show "$DOCK_LINK" || true
    return 1
  fi
  return 0
}


# The dock link is down and startable: `auth-agent`/`link start` may fire
# Start without answering UnexpectedTransition.
#
# $1 = control socket
function check_dock_link_inactive() {
  "$PH_DEBUG_BIN" -p "$1" link show "$DOCK_LINK" | grep -q 'State: Inactive'
}

# $1 = control socket
function check_dock_link_active() {
  "$PH_DEBUG_BIN" -p "$1" link show "$DOCK_LINK" | grep -q 'State: Active'
}

# `link show <id>` for every link the node has. The summary view does not
# render LinkData (and so carries no `Auth expires:` line), and the node's
# dock-link ids are assigned as adapters arrive, so read the ids out of the
# summary and ask for each one's detail.
function node_link_details() {
  local ID
  for ID in $("$PH_DEBUG_BIN" -p "$NODE_SOCK" link show \
      | sed -n 's/^ *\([0-9]\+\):.*/\1/p'); do
    "$PH_DEBUG_BIN" -p "$NODE_SOCK" link show "$ID" || true
  done
}


#
# Set up automatic cleanup
#

trap cleanup EXIT

TMPDIR=$(mktemp -d)
pushd "$TMPDIR" > /dev/null

echo "Setting up network"

#
# Prepare for test
#

destroy_network

create_network

if [ -n "$NETEM_PARAMS" ]
then configure_netem $NETEM_PARAMS  # split on whitespace
fi

create_ca_key_and_cert ca
create_actor_key_and_cert ca vs.zpr

cp "$PREGEN/node.key" node.key
cp "$PREGEN/node-cert.pem" node.crt
cp "$PREGEN/node-pubkey.pem" node.pubkey
cp "$PREGEN/actor2-rsa.key" actor2-rsa.key
cp "$PREGEN/actorvs-rsa.key" actorvs-rsa.key

emit_vs_config ca vs.zpr > vs-config.toml

# The policy's `addresses` trusted service reads its grant data from
# file_ts_dir/addresses.json (file_ts_dir defaults to the vs config's
# directory, i.e. here). See lib/common_funcs.sh (zipline#107).
copy_address_store

#
# Fake IdP: TLS server cert for 127.0.0.1 signed by the test CA, shared
# rotation/revocation state, one instance per netns that dials the issuer.
#

echo "Launching fake IdPs"

mkdir idp-state
openssl req -new -newkey rsa:2048 -nodes -keyout idp.key \
  -subj "/CN=127.0.0.1" -out idp.csr 2> /dev/null
openssl x509 -req -in idp.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 1 -out idp.crt \
  -extfile <(printf "subjectAltName=IP:127.0.0.1") 2> /dev/null

# The zpr-vs instance only ever serves /jwks (the visa service's refresh);
# its sub is never minted into a token anyone presents.
launch_fake_idp zpr-vs user-vs-unused
launch_fake_idp zpr-a user-a
launch_fake_idp zpr-b user-b

# Each instance must answer discovery before anything dials it.
function check_idp() {
  sudo -E ip netns exec "$1" curl --silent --cacert ca.crt \
    --output /dev/null "$IDP_ISSUER/.well-known/openid-configuration"
}
wait_for 15 check_idp zpr-vs
wait_for 15 check_idp zpr-a
wait_for 15 check_idp zpr-b

#
# Launch ValKey + Visa Service
#

echo "Launching ValKey"

sudo -E ip netns exec zpr-vs sudo -E -u "$ZPR_USER" "$VALKEY_SERVER_BIN" \
    --save "" \
    --appendonly no 2>&1 | tee valkey.log | prefix_log valkey &

wait_for 15 check_vs_valkey_port

echo "Launching Visa Service"

# SSL_CERT_FILE: the visa service's JWKS refresh must trust the fake IdP's
# test-CA TLS certificate.
#
# -v (debug): the `reauthorize` handler logs its arrival at debug level
# (vs/src/vsapi_worker.rs), and "a reauthorize crossed the wire" is one of
# this test's assertions.
sudo -E ip netns exec zpr-vs sudo -E -u "$ZPR_USER" \
    env XDG_DATA_HOME=/tmp SSL_CERT_FILE="$PWD/ca.crt" "$VS_BIN" \
    -v \
    -c vs-config.toml \
    --clear-state \
    "$PREGEN/$POLICY_BIN" 2>&1 | tee vs.log | prefix_log vs &

sleep 2

#
# Launch PHs
#

echo "Launching Node"

sudo -E ip netns exec zpr-node sudo -E -u "$ZPR_USER" "$PH_BIN" \
  node \
  --logging "$DEBUG_TARGETS vss_rpc=DEBUG" \
  --control-path "$NODE_SOCK" \
  --capture-path "$NODE_CAP_SOCK" \
  --advertised-substrate-addr "$NODE_SUBSTRATE_ADDR_VS":5000 \
  --ca-file ca.crt \
  --certificate-file node.crt \
  --private-key-file node.key \
  --auth-private-key "$NODE_AUTH_PRIVATE_KEY" \
  --km-impl "$KM_IMPL" \
  --tun-if tun0 \
  --zpr-addr "$NODE_ZPR_ADDR" 2>&1 | tee node.log | prefix_log zpr-node &

sleep 2

echo "Launching Adapters"

sudo -E ip netns exec zpr-vs sudo -E -u "$ZPR_USER" "$PH_BIN" \
  adapter \
  --logging "$DEBUG_TARGETS" \
  --control-path "$VS_SOCK" \
  --capture-path "$VS_CAP_SOCK" \
  --self-addr "$VS_SUBSTRATE_ADDR" \
  --ca-file ca.crt \
  --certificate-file vs.zpr.crt \
  --private-key-file vs.zpr.key \
  --bootstrap-key actorvs-rsa.key \
  --km-impl "$KM_IMPL" \
  --tun-if tun0 \
  --io-engine auto \
  --node-addr "$NODE_SUBSTRATE_ADDR_VS" \
  --zpr-addr "$VS_ZPR_ADDR" 2>&1 | tee adapter-vs.log | prefix_log zpr-vs &

# The node only advertises the policy's OIDC IdP to a docking adapter once the
# visa service has pushed the auth-services list to it over VSS; see
# one-node-oidc-test.sh for why waiting for the push beats sleeping.
function check_node_has_auth_services() {
  grep -q "received services update with [1-9]" node.log
}
wait_for 30 check_node_has_auth_services || {
  echo "ERROR: node never received the auth-services list from the visa service"
  exit 1
}

# adapter1: user-only (no bootstrap key).
launch_adapter1

# adapter2: both blobs — bootstrap key here, user login below.
sudo -E ip netns exec zpr-b sudo -E -u "$ZPR_USER" env SSL_CERT_FILE="$PWD/ca.crt" "$PH_BIN" \
  adapter \
  --logging "$DEBUG_TARGETS" \
  --control-path "$ADAPTER2_SOCK" \
  --capture-path "$ADAPTER2_CAP_SOCK" \
  --self-addr "$B_SUBSTRATE_ADDR" \
  --ca-file ca.crt \
  --bootstrap-key actor2-rsa.key \
  --name adapter2 \
  --km-impl "$KM_IMPL" \
  --tun-if tun0 \
  --io-engine posix_unbatched \
  --node-addr "$NODE_SUBSTRATE_ADDR_B" \
  --zpr-addr "$B_ZPR_ADDR" 2>&1 | tee adapter2.log | prefix_log zpr-b &

sleep 2

#
# Leg 1 — connect through resident authentication agents
#

PASS=0

echo
echo "LEG 1: interactive logins through resident auth agents"

echo "Logging in adapter1 (user-only)"
oidc_auth_agent zpr-a "$ADAPTER1_SOCK" login1.log || PASS=1

if [[ "$PASS" == 0 ]] then
echo "Logging in adapter2 (device + user)"
# adapter2 has a bootstrap key, so it came up device-only at startup and the
# dock link has been Active since; both blobs only go out together on an
# authentication that runs with an agent already registered. Take the link
# down and let auth-agent bring it back up. See one-node-oidc-test.sh for the
# 5 s DEFAULT_LINK_RESTART_HOLDDOWN race this polling wins.
"$PH_DEBUG_BIN" -p "$ADAPTER2_SOCK" link stop "$DOCK_LINK"
wait_for 15 check_dock_link_inactive "$ADAPTER2_SOCK" \
  || echo "WARNING: adapter2 dock link did not return to Inactive; connecting anyway"
oidc_auth_agent zpr-b "$ADAPTER2_SOCK" login2.log || PASS=1
fi

#
# Wait for connectivity
#

if [[ "$PASS" == 0 ]] then
echo "Wait for TUN carrier..."
wait_for 15 check_carrier zpr-node tun0 || { PASS=1; }
fi
if [[ "$PASS" == 0 ]] then
wait_for 15 check_carrier zpr-vs tun0 || { PASS=1; }
fi
if [[ "$PASS" == 0 ]] then
wait_for 15 check_carrier zpr-a tun0 || { PASS=1; }
fi
if [[ "$PASS" == 0 ]] then
wait_for 15 check_carrier zpr-b tun0 || { PASS=1; }
fi

if [[ "$PASS" == 0 ]] then
echo "Carrier has arrived."
sleep 1

if ! ping_test
then
  echo "ERROR: leg 1 ping failed; the renewal legs need a working baseline"
  PASS=1
fi
fi

#
# Leg 2 — silent renewal
#

if [[ "$PASS" == 0 ]] then
echo
echo "LEG 2: silent renewal (waiting up to ${RENEWAL_WAIT}s for the renewal lead)"

# Snapshot the authorization-endpoint request counts. A silent renewal must
# not move these: it is a back-channel refresh-token POST, and a browser leg
# here would mean the user gets re-prompted every expiration_seconds, which
# is exactly the symptom this epic exists to remove.
AUTH_REQS_A_BEFORE=$(auth_requests idp-zpr-a.log)
AUTH_REQS_B_BEFORE=$(auth_requests idp-zpr-b.log)
echo "authorization requests so far: zpr-a=$AUTH_REQS_A_BEFORE zpr-b=$AUTH_REQS_B_BEFORE"

# The renewal runs on the side holding the visa-service connection, so the
# success line lands in the node's log.
if wait_for_log "$RENEWAL_WAIT" node.log "silently re-authenticated; new expiry"; then
  echo "renewal observed:"
  grep -E "silently re-authenticated; new expiry" node.log | head -n 4
else
  echo "ERROR: no silent re-authentication within ${RENEWAL_WAIT}s"
  echo "--- node.log renewal-related lines ---"
  grep -iE "renew|re-authenticat|AuthAgent|auth_expires|Auth expires" node.log | tail -n 30 || true
  echo "--- adapter1.log renewal-related lines ---"
  grep -iE "renew|re-authenticat|AuthAgent" adapter1.log | tail -n 30 || true
  PASS=1
fi
fi

if [[ "$PASS" == 0 ]] then
# A reauthorize crossed the wire: the visa service logs the RPC's arrival at
# debug level, and the node's success line above only prints after the call
# returned Ok.
if grep -qE "reauthorize from" vs.log; then
  echo "visa service saw the reauthorize RPC:"
  grep -E "reauthorize from" vs.log | head -n 2
else
  echo "ERROR: the visa service never logged a reauthorize RPC"
  PASS=1
fi

if grep -qE "reauth rejected" vs.log; then
  echo "ERROR: the visa service rejected a reauthorization:"
  grep -E "reauth rejected" vs.log | head -n 5
  PASS=1
fi
fi

if [[ "$PASS" == 0 ]] then
# No authorization-endpoint request during the renewal: silent means silent.
AUTH_REQS_A_AFTER=$(auth_requests idp-zpr-a.log)
AUTH_REQS_B_AFTER=$(auth_requests idp-zpr-b.log)
if (( AUTH_REQS_A_AFTER != AUTH_REQS_A_BEFORE )); then
  echo "ERROR: zpr-a hit the authorization endpoint during renewal ($AUTH_REQS_A_BEFORE -> $AUTH_REQS_A_AFTER)"
  PASS=1
fi
if (( AUTH_REQS_B_AFTER != AUTH_REQS_B_BEFORE )); then
  echo "ERROR: zpr-b hit the authorization endpoint during renewal ($AUTH_REQS_B_BEFORE -> $AUTH_REQS_B_AFTER)"
  PASS=1
fi

# And the refresh grant is what did the work.
if ! grep -qE '"POST /token' idp-zpr-a.log; then
  echo "ERROR: zpr-a's IdP served no token-endpoint request at all"
  PASS=1
fi
fi

if [[ "$PASS" == 0 ]] then
# The agents must still be resident: renewal depends on them, and an agent
# that exited would make every later leg meaningless.
for AGENT_PID in ${AGENT_PIDS[@]+"${AGENT_PIDS[@]}"}; do
  if ! kill -0 "$AGENT_PID" 2> /dev/null; then
    echo "ERROR: an auth-agent process ($AGENT_PID) exited before the renewal legs finished"
    PASS=1
  fi
done

# showLink surfaces the renewal picture (zipline#45): an authentication
# expiry is reported, where before this epic there was none. The value lives
# on the side that was told it by the visa service, i.e. the node, whose
# dock-link ids are assigned as adapters arrive — so enumerate them from the
# summary rather than guessing.
NODE_LINKS=$(node_link_details)
echo "node links:"
echo "$NODE_LINKS"
if ! grep -qE "Auth expires: in " <<< "$NODE_LINKS"; then
  echo "ERROR: no link on the node reports an authentication expiry"
  PASS=1
fi

# Traffic still flows across the boundary after the renewal.
if ! ping_test
then
  echo "ERROR: traffic stopped after the silent renewal"
  PASS=1
fi
fi

#
# Leg 3 — the IdP withdraws the grant
#

if [[ "$PASS" == 0 ]] then
echo
echo "LEG 3: revoke the refresh grant; expect disconnect within one sweep"

# One invocation reaches every serving instance: the flag is a file in the
# shared --state-dir, re-read on every request.
python3 "$FAKE_IDP" --state-dir idp-state --revoke-refresh

if wait_for_log "$REVOCATION_WAIT" node.log "silent re-authentication failed"; then
  echo "renewal failure observed:"
  grep -E "silent re-authentication failed" node.log | head -n 4
else
  echo "ERROR: no renewal failure within ${REVOCATION_WAIT}s of revoking the grant"
  grep -iE "renew|re-authenticat" node.log | tail -n 20 || true
  PASS=1
fi
fi

if [[ "$PASS" == 0 ]] then
# The revocation must be exercised END TO END, not merely produce *a*
# failure (zipline#104): in the 2026-09-25 run both post-revocation
# renewals failed on TRANSPORT (IdpUnreachable: the per-netns fake IdP had
# stopped accepting connections), the refresh grant was never presented,
# and leg 3 still passed. Two assertions close that hole:
#
# (a) The IdP actually rejected a refresh grant: its log carries a
#     `POST /token ... 400` (the login and the leg-2 renewal are 200s, so
#     any 400 here is the revoked grant). adapter1 is user-only, so its
#     IdP instance (zpr-a) must have seen it. The wait above accepts a
#     failure from EITHER adapter, and the two renew independently —
#     adapter2 can fail first while adapter1 is not yet due — so poll for
#     zpr-a's 400 within the window rather than asserting on whatever
#     happens to be in the log right now.
if wait_for_log "$REVOCATION_WAIT" idp-zpr-a.log '"POST /token[^"]*" 400'; then
  echo "zpr-a's IdP rejected the revoked refresh grant:"
  grep -E '"POST /token[^"]*" 400' idp-zpr-a.log | head -n 2
else
  echo "ERROR: zpr-a's IdP never answered a token-endpoint request with 400"
  echo "       (the revoked grant was never presented — an unreachable IdP"
  echo "       also fails renewal, but exercises nothing)"
  grep -E '"POST /token' idp-zpr-a.log | tail -n 5 || true
  PASS=1
fi

# (b) The failure the agent classified is the revoked grant: the adapter's
#     `AuthAgent could not renew the credential` line must carry the RFC
#     6749 `invalid_grant` code in its detail. A transport failure ("HTTP
#     error talking to the IdP: error sending request") means the IdP was
#     down — the bug this assertion exists to catch. (The node's own
#     `silent re-authentication failed` line only ever says AuthUnavailable:
#     the reason does not cross the ZDP wire, so it cannot carry this.)
#     adapter1 logs its classification only after the IdP's response makes
#     it back through the AuthAgent, so give that the same window; and the
#     lookup must be non-fatal — under `set -euo pipefail` a bare
#     `$(grep ...)` assignment with no match would kill the script right
#     here, skipping the diagnostic branch below and all cleanup.
wait_for_log "$REVOCATION_WAIT" adapter1.log "could not renew the credential" || true
FAILURE_LINE=$(grep -E "could not renew the credential" adapter1.log | head -n 1 || true)
if grep -qE "invalid_grant" <<< "$FAILURE_LINE"; then
  echo "the agent reported the revoked grant:"
  echo "$FAILURE_LINE"
else
  echo "ERROR: adapter1's renewal failure does not carry invalid_grant:"
  echo "$FAILURE_LINE"
  PASS=1
fi
fi

if [[ "$PASS" == 0 ]] then
# The authentication-expiry sweep revokes on the docking node and drops the
# actor, once the window the last good renewal bought finally closes.
if wait_for_log "$REVOCATION_WAIT" vs.log "authentication expired for actor .*removing actor"; then
  echo "sweep revoked the actor:"
  grep -E "authentication expired for actor" vs.log | head -n 4
else
  echo "ERROR: the authentication-expiry sweep never removed the actor"
  grep -iE "auth sweep|authentication expired" vs.log | tail -n 20 || true
  PASS=1
fi
fi

if [[ "$PASS" == 0 ]] then
# With its authentication gone, adapter1's actor can no longer reach anything.
# ping_test is expected to FAIL here — that is the assertion.
if ping_test
then
  echo "ERROR: traffic still flows after the actor's authentication was revoked"
  PASS=1
else
  echo "traffic across the boundary stopped, as expected"
fi
fi

#
# Check stats
#

for SOCK in "$NODE_SOCK" "$VS_SOCK" "$ADAPTER1_SOCK" "$ADAPTER2_SOCK"
do
	APOOO=$(counters "$SOCK" | awk -F': ' '$1 == "Actor Packets Out-Of-Order" { apooo += $2 } END { print apooo }' || true)
	if [ -n "$APOOO" ] && (( APOOO != 0 ))
	then
		echo "$(basename "$SOCK"): ERROR: found actor packets out-of-order: $APOOO"
		PASS=1
	fi
done


#
# Cleanup
#

for AGENT_PID in ${AGENT_PIDS[@]+"${AGENT_PIDS[@]}"}
do
  kill -SIGINT "$AGENT_PID" 2> /dev/null || true
done

sudo pkill -SIGTERM -f "fake-idp.py --port" || true

for pid in $(get_descendants)
do
  echo
  echo "Terminating $pid"
  sleep 1
  sudo kill -SIGINT "$pid"
  sleep 1
done

stty sane || true


#
# Report status
#

echo
if [[ "$PASS" == 0 ]]
then echo "SUCCESS"
else echo "FAILURE"
fi

exit "$PASS"
