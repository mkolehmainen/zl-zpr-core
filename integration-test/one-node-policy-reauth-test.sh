#!/usr/bin/env bash
# Policy-install re-authentication integration test (zipline#124, umbrella #118).
#
# one-node-oidc-renewal-test.sh proves the CLOCK-driven renewal loop. This
# proves the INSTALL-driven one (zipline#123): every policy install obliges
# every connected actor — the node itself and each docked adapter — to
# re-authenticate under the new policy generation (vinst) within the visa
# service's `reauth_deadline`, and whoever cannot is revoked. Modeled on the
# renewal test: same netns fixture, same fake IdP, same resident-auth-agent
# login; the differences are the policy fixtures and what the legs assert.
#
# Actors, chosen to cover both re-authentication arms of `reauthorize`:
#   - adapter1 is USER-ONLY (OIDC): no bootstrap key; its install-driven
#     re-auth is a silent back-channel refresh through the resident agent.
#   - adapter2 is DEVICE-ONLY (RSA): bootstrap key, never logs a user in;
#     its install-driven re-auth is the SS (bootstrap-signature) arm
#     (zipline#120/#122). The renewal test's adapter2 presents both blobs;
#     this one deliberately presents one, so the leg-3 key removal severs
#     its ONLY credential.
#   - The node re-authenticates itself in place over the existing VS session
#     (zipline#121: connect(Reconnect) -> challenge -> authenticate).
#
# Legs:
#
#   1. RSA survival. Install the same policy three times under a continuous
#      ping sourced from the RSA adapter. Assert: not one ping is lost; the
#      node self re-auths exactly once per install; adapter2's SS re-auth
#      lands exactly once per install; every obligation is satisfied and
#      pruned; nothing is revoked.
#   2. OIDC survival. One more install. Assert: adapter1 re-auths through a
#      back-channel refresh (a new `POST /token`, NO new `GET /auth` — the
#      user is never re-prompted), the agents stay resident, traffic flows.
#   3. Adapter key removed. Install a variant lacking adapter2's bootstrap
#      key. Assert: adapter2 PRESENTS its key and is REJECTED (the failure
#      is exercised end to end, zipline#104), the sweep revokes it within
#      reauth_deadline + one sweep period, and adapter1 is unaffected.
#   4. Node key removed. Install a variant lacking the node's bootstrap key.
#      Assert: the node's self re-auth is refused and the sweep disconnects
#      the node (with its adapters) within the same bound.
#
# The OIDC lifetimes in policy-reauth.zplc are LONG (3600 s window), so the
# clock-driven renewal lead (min(300 s, lifetime/2) before expiry) can never
# fire inside the run: every re-auth observed here is install-driven.
# `reauth_deadline` is a VISA SERVICE setting (vs-config.toml), set to 60 s
# so the revocation legs wait out 60 s + one 30 s sweep period + slack
# rather than the 300 s default.
#
# The run takes several minutes: legs 3 and 4 each wait out a real
# reauth-deadline clock that cannot be fast-forwarded from outside.
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

# IPv6, two actors, fixed policy shape (no parse_arguments.sh): the fixture
# declares exactly this topology. See pregen/policy-reauth.zplc.
NUM_ACTORS=2
NODE_ZPR_ADDR=fd5a:5052::2
VS_ZPR_ADDR=fd5a:5052::1
A_ZPR_ADDR=fd5a:5052:8888::1:1
B_ZPR_ADDR=fd5a:5052:8888::2:1
C_ZPR_ADDR=fd5a:5052:8888::3:1
ZPR_SUBNET=fd5a:5052::/32

# The base policy and its two key-removal variants (legs 3 and 4). All three
# compile the same policy-reauth.zpl: the RULES never change, so any
# revocation the variants cause comes from the failed re-authentication,
# not from a rule change.
POLICY_BIN=policy-reauth.bin2
POLICY_NO_ADAPTER2_BIN=policy-reauth-no-adapter2.bin2
POLICY_NO_NODE_BIN=policy-reauth-no-node.bin2

# The link an adapter authenticates: its tether to the node. Link 1 is the
# internal local-actor link and is Active from startup (see
# one-node-oidc-test.sh), so the dock link is 2.
DOCK_LINK=2

# The issuer the pregen policy pins; each relevant netns runs an IdP
# instance answering it on its own loopback.
IDP_PORT=9000
IDP_ISSUER="https://127.0.0.1:$IDP_PORT"

# The vs admin API, reached from inside the zpr-vs netns (the VS binds it on
# its ZPR address; zpr-vs's tun0 carries that address, so it is local there).
ADMIN_URL="https://[$VS_ZPR_ADDR]:8182"

# What the vs-config sets `reauth_deadline` to: how long a connected actor
# has, after an install, to re-authenticate before the sweep revokes it.
REAUTH_DEADLINE=60

# How long to wait for the install-driven re-auths of one install to land.
# They complete in seconds (the fan-out is immediate and the netns has no
# real latency); generous for slow CI runners.
REAUTH_WAIT=60

# How long the revocation legs allow the sweep to act, measured FROM THE
# POLICY INSTALL: the 60 s deadline plus one sweep period (MIN_VISA_LIFETIME,
# 30 s), plus a small explicit slack for the install RPC and log flushing.
# The wait is anchored at the install (LEG{3,4}_INSTALL_TS), not started
# fresh after the rejection check — a fresh 180 s wait on top of the earlier
# waits would pass revocations far beyond the configured bound.
SWEEP_PERIOD=30
REVOKE_SLACK=15

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

for P in "$POLICY_BIN" "$POLICY_NO_ADAPTER2_BIN" "$POLICY_NO_NODE_BIN"; do
  if [ ! -e "$PREGEN/$P" ]; then
    echo "policy file not found (expected .bin2): $PREGEN/$P"
    exit 1
  fi
done

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

function counters() {
  SOCKET=$1
  "$PH_DEBUG_BIN" -p "$SOCKET" counters
}

# Launch a fake IdP inside a netns. All instances share the signing keys, TLS
# material and state directory; the `sub` differs per netns so the adapter
# logs in as its own user (the policy's user-a).
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
# OIDC leg turns on this number NOT moving: an install-driven re-auth is a
# back-channel `grant_type=refresh_token` POST to /token, so any /auth hit
# after the login means the user was re-prompted — the symptom the silent
# path exists to remove.
#
# $1 = IdP log file
function auth_requests() {
  grep -c '"GET /auth' "$1" || true
}

# How many token-endpoint requests an IdP instance has served. The login is
# one (the code exchange); every silent refresh is one more.
#
# $1 = IdP log file
function token_requests() {
  grep -c '"POST /token' "$1" || true
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

# Count a pattern's occurrences in a log file (0 when the file is missing).
# $1 = log file, $2 = grep -E pattern
function count_log() {
  local N
  N=$(grep -cE "$2" "$1" 2> /dev/null || true)
  echo "${N:-0}"
}

# Wait until a pattern has appeared at least N times in a log file. The
# per-install assertions ratchet on counts — install i is only done when its
# re-auth line is the i-th of its kind — so equality checks afterwards can
# attribute exactly one occurrence to each install.
# $1 = seconds, $2 = log file, $3 = grep -E pattern, $4 = minimum count
function wait_for_log_count() {
  local DEADLINE=$(( SECONDS + $1 ))
  local FILE=$2
  local PATTERN=$3
  local WANT=$4
  while (( SECONDS < DEADLINE )); do
    if (( $(count_log "$FILE" "$PATTERN") >= WANT )); then return 0; fi
    sleep 2
  done
  return 1
}

# Assert an address is COMPLETELY unreachable from a netns. ping's exit code
# cannot carry this: with `-c 3`, exit 1 means "fewer than three replies",
# which includes one or two replies arriving — i.e. traffic still passing.
# So parse the summary and require ZERO received packets. Exit codes >= 2 are
# execution errors (bad netns, resolution, sockets), reported as such rather
# than read as unreachability.
# $1 = netns, $2 = address. Returns 0 iff ping ran and zero replies arrived.
function assert_unreachable() {
  local NETNS=$1
  local ADDR=$2
  local OUT RC RECEIVED
  OUT=$(sudo ip netns exec "$NETNS" ping -q -c 3 -w 5 "$ADDR" 2>&1) && RC=0 || RC=$?
  if (( RC >= 2 )); then
    echo "ERROR: ping to $ADDR from $NETNS failed to execute (exit $RC):"
    echo "$OUT"
    return 1
  fi
  RECEIVED=$(sed -nE 's/.* transmitted, ([0-9]+) (packets )?received.*/\1/p' <<< "$OUT")
  if [[ -z "$RECEIVED" ]]; then
    echo "ERROR: could not parse the ping summary for $ADDR:"
    echo "$OUT"
    return 1
  fi
  if (( RECEIVED != 0 )); then
    echo "ERROR: $RECEIVED of 3 pings to $ADDR were answered"
    return 1
  fi
  return 0
}

# Seconds remaining until the revocation bound for an install recorded at
# $1 (a $SECONDS snapshot taken just before install_policy): the configured
# reauth_deadline, plus one sweep period, plus REVOKE_SLACK. May be <= 0 if
# the intervening checks already overran the bound.
function revoke_budget() {
  echo $(( $1 + REAUTH_DEADLINE + SWEEP_PERIOD + REVOKE_SLACK - SECONDS ))
}

# Run vs-admin against the admin API from inside the zpr-vs netns.
function vs_admin() {
  sudo -E ip netns exec zpr-vs sudo -E -u "$ZPR_USER" \
    "$VS_ADMIN_BIN" --svc-url "$ADMIN_URL" --ca-cert ca.crt \
    --api-key-file vs-admin.key --format compact "$@"
}

# Hot-install a compiled policy container. vs-admin exits non-zero on a
# rejected install (zipline#38), so a failure here fails the leg.
# $1 = absolute path to the .bin2
function install_policy() {
  echo "Installing policy: $(basename "$1")"
  vs_admin install "$1"
}

# Launch adapter1 — user-only: deliberately NO --bootstrap-key, so the only
# authentication path is the OIDC user blob supplied through the AuthAgent,
# and its install-driven re-auth must be the silent refresh.
function launch_adapter1() {
  sudo -E ip netns exec zpr-a sudo -E -u "$ZPR_USER" env SSL_CERT_FILE="$PWD/ca.crt" "$PH_BIN" \
    adapter \
    --logging "$DEBUG_TARGETS" \
    --control-path "$ADAPTER1_SOCK" \
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
# agent — verbatim from one-node-oidc-renewal-test.sh, which documents the
# reasoning. Residency matters doubly here: the install-driven re-auth asks
# the agent for a fresh credential (interactive: false), which only a live
# registered agent holding the refresh token can answer.
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

# $1 = control socket
function check_dock_link_active() {
  "$PH_DEBUG_BIN" -p "$1" link show "$DOCK_LINK" | grep -q 'State: Active'
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

# The stock vs-config plus the short reauth deadline this test exists to
# wait out (the appended key stays inside the [core] table).
emit_vs_config ca vs.zpr > vs-config.toml
cat >> vs-config.toml <<EOF
reauth_deadline = $REAUTH_DEADLINE
EOF

# The policy's `addresses` trusted service reads its grant data from
# file_ts_dir/addresses.json (file_ts_dir defaults to the vs config's
# directory, i.e. here). See lib/common_funcs.sh (zipline#107).
copy_address_store

# Admin API key for the installs: mint one directly in the format vsapikey
# uses (vs/src/apikey.rs: zpr_vsapi.<id_hex>.<b64url_secret>; vs_keys.toml
# stores the sha256 of the secret). The vs reads vs_keys.toml from the
# config directory; vs-admin reads the full key string from vs-admin.key.
python3 - <<'PYEOF'
import base64, hashlib, secrets

key_id = secrets.token_bytes(4).hex()
secret = secrets.token_bytes(32)
b64 = base64.urlsafe_b64encode(secret).rstrip(b"=").decode()
with open("vs_keys.toml", "w") as f:
    f.write(f'[keys.{key_id}]\n')
    f.write('owner = "integration-test"\n')
    f.write('permission = "readwrite"\n')
    f.write('status = "active"\n')
    f.write('created = "2026-09-29"\n')
    f.write(f'secret_hash = "{hashlib.sha256(secret).hexdigest()}"\n')
    f.write('description = "one-node-policy-reauth-test"\n')
with open("vs-admin.key", "w") as f:
    f.write(f"zpr_vsapi.{key_id}.{b64}\n")
PYEOF
chmod 600 vs-admin.key

#
# Fake IdP: TLS server cert for 127.0.0.1 signed by the test CA, shared
# state, one instance per netns that dials the issuer: zpr-vs (the visa
# service's JWKS refresh) and zpr-a (adapter1's login and refreshes).
# adapter2 is device-only and never dials an IdP.
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

# Each instance must answer discovery before anything dials it.
function check_idp() {
  sudo -E ip netns exec "$1" curl --silent --cacert ca.crt \
    --output /dev/null "$IDP_ISSUER/.well-known/openid-configuration"
}
wait_for 15 check_idp zpr-vs
wait_for 15 check_idp zpr-a

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
# (vs/src/vsapi_worker.rs) — useful in the failure diagnostics even though
# the assertions key on info-level lines.
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

# adapter1: user-only (no bootstrap key); the login follows below.
launch_adapter1

# adapter2: DEVICE-ONLY — bootstrap key at launch, no user login ever. Its
# dock link authenticates at startup and stays Active; the only credential
# it can ever re-present is this RSA key.
sudo -E ip netns exec zpr-b sudo -E -u "$ZPR_USER" "$PH_BIN" \
  adapter \
  --logging "$DEBUG_TARGETS" \
  --control-path "$ADAPTER2_SOCK" \
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
# Baseline — adapter1 logs in through a resident auth agent; everyone pings
#

PASS=0

echo
echo "BASELINE: interactive login (adapter1) and connectivity"

echo "Logging in adapter1 (user-only)"
oidc_auth_agent zpr-a "$ADAPTER1_SOCK" login1.log || PASS=1

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
  echo "ERROR: baseline ping failed; the install legs need a working fabric"
  PASS=1
fi
fi

#
# Leg 1 — RSA survival: three installs of the same policy, continuous ping
#

# The same .bin2 re-installed is NOT a no-op: every hot install advances the
# policy generation (vinst) and records a re-auth obligation for it
# (zipline#123) — content dedup applies only across a VS restart. Keeping the
# content identical isolates the machinery under test: nothing about the
# RULES changes, so any disturbance can only come from the re-auth path.
CONT_PING_LOG=cont-ping.log

if [[ "$PASS" == 0 ]] then
echo
echo "LEG 1: RSA survival across three policy installs"

# Continuous boundary ping (adapter1 -> adapter2) for the whole leg. The
# assertion is ZERO loss: the node's self re-auth is in-place (zipline#121)
# and the adapters' renewals ride the existing links (zipline#122), so not
# one packet may drop while three installs go by.
sudo ip netns exec zpr-a ping -i 0.2 "$B_ZPR_ADDR" > "$CONT_PING_LOG" 2>&1 &
sleep 2

for I in 1 2 3; do
  if ! install_policy "$PREGEN/$POLICY_BIN"; then
    echo "ERROR: policy install $I failed"
    PASS=1; break
  fi
  # Counts ratchet: install i is only done when the i-th line of each kind
  # is in the log, so the equality checks below can attribute exactly one
  # re-auth of each kind to each install.
  if ! wait_for_log_count "$REAUTH_WAIT" node.log \
      "self re-authentication with the visa service succeeded" "$I"; then
    echo "ERROR: install $I: the node's self re-auth never landed"
    grep -iE "re-auth|request_auth" node.log | tail -n 20 || true
    PASS=1; break
  fi
  if ! wait_for_log_count "$REAUTH_WAIT" vs.log \
      "reauthorized adapter .* at address $B_ZPR_ADDR " "$I"; then
    echo "ERROR: install $I: adapter2's SS (bootstrap RSA) reauthorize never landed"
    grep -E "reauthorize|reauthorized" vs.log | tail -n 20 || true
    PASS=1; break
  fi
  if ! wait_for_log_count "$REAUTH_WAIT" vs.log \
      "reauthorized adapter .* at address $A_ZPR_ADDR " "$I"; then
    echo "ERROR: install $I: adapter1's OIDC reauthorize never landed"
    grep -E "reauthorize|reauthorized" vs.log | tail -n 20 || true
    PASS=1; break
  fi
  echo "install $I: node self re-auth + both adapter reauthorizes landed"
done
fi

# Stop the continuous ping (leg-1 scope) whether the leg passed or not, and
# give ping a moment to flush its summary.
sudo pkill -SIGINT -f "ping -i 0.2 $B_ZPR_ADDR" || true
sleep 2

if [[ "$PASS" == 0 ]] then
# Exactly one re-auth of each kind per install — a fourth one would mean
# something other than the installs drove a re-auth (the fixture's OIDC
# lifetimes are sized so the renewal clock cannot fire, see the header).
NODE_REAUTHS=$(count_log node.log "self re-authentication with the visa service succeeded")
A2_REAUTHS=$(count_log vs.log "reauthorized adapter .* at address $B_ZPR_ADDR ")
if (( NODE_REAUTHS != 3 )); then
  echo "ERROR: expected exactly 3 node self re-auths after 3 installs, found $NODE_REAUTHS"
  PASS=1
fi
if (( A2_REAUTHS != 3 )); then
  echo "ERROR: expected exactly 3 adapter2 reauthorizes after 3 installs, found $A2_REAUTHS"
  PASS=1
fi

# The re-signed policy re-approved everyone: nothing was rejected.
if grep -qE "reauthorize failed" vs.log; then
  echo "ERROR: the visa service rejected a reauthorization during leg 1:"
  grep -E "reauthorize failed" vs.log | head -n 5
  PASS=1
fi

# Zero loss on the boundary ping.
PING_TX=$(sed -n 's/^\([0-9]\+\) packets transmitted.*/\1/p' "$CONT_PING_LOG" | head -n 1)
PING_RX=$(sed -n 's/^[0-9]\+ packets transmitted, \([0-9]\+\) received.*/\1/p' "$CONT_PING_LOG" | head -n 1)
if [ -z "$PING_TX" ] || [ -z "$PING_RX" ] || (( PING_TX == 0 )); then
  echo "ERROR: the continuous ping produced no summary:"
  tail -n 5 "$CONT_PING_LOG" || true
  PASS=1
elif (( PING_RX != PING_TX )); then
  echo "ERROR: the continuous ping dropped packets across the installs: $PING_RX/$PING_TX"
  tail -n 5 "$CONT_PING_LOG" || true
  PASS=1
else
  echo "continuous ping across three installs: $PING_RX/$PING_TX, zero loss"
fi
fi

#
# Leg 2 — OIDC survival: one more install; the re-auth is a SILENT refresh
#

if [[ "$PASS" == 0 ]] then
echo
echo "LEG 2: OIDC survival (install-driven re-auth is a back-channel refresh)"

# Snapshot adapter1's IdP endpoints. The install-driven re-auth must move
# the token-endpoint count (a back-channel refresh-token POST) and must NOT
# move the authorization-endpoint count (a browser leg would mean the user
# is re-prompted on every policy install — the symptom zipline#118 removes).
AUTH_REQS_BEFORE=$(auth_requests idp-zpr-a.log)
TOKEN_REQS_BEFORE=$(token_requests idp-zpr-a.log)
echo "idp-zpr-a so far: GET /auth=$AUTH_REQS_BEFORE POST /token=$TOKEN_REQS_BEFORE"

if ! install_policy "$PREGEN/$POLICY_BIN"; then
  echo "ERROR: leg-2 policy install failed"
  PASS=1
fi
fi

if [[ "$PASS" == 0 ]] then
# Everyone re-auths once more (counts ratchet to 4).
if ! wait_for_log_count "$REAUTH_WAIT" vs.log \
    "reauthorized adapter .* at address $A_ZPR_ADDR " 4; then
  echo "ERROR: leg 2: adapter1's OIDC reauthorize never landed"
  grep -iE "renew|re-authenticat|AuthAgent" adapter1.log | tail -n 20 || true
  PASS=1
fi
if ! wait_for_log_count "$REAUTH_WAIT" node.log \
    "self re-authentication with the visa service succeeded" 4; then
  echo "ERROR: leg 2: the node's self re-auth never landed"
  PASS=1
fi
fi

if [[ "$PASS" == 0 ]] then
AUTH_REQS_AFTER=$(auth_requests idp-zpr-a.log)
TOKEN_REQS_AFTER=$(token_requests idp-zpr-a.log)
if (( AUTH_REQS_AFTER != AUTH_REQS_BEFORE )); then
  echo "ERROR: adapter1 hit the authorization endpoint during the install re-auth ($AUTH_REQS_BEFORE -> $AUTH_REQS_AFTER): the user was re-prompted"
  PASS=1
fi
if (( TOKEN_REQS_AFTER <= TOKEN_REQS_BEFORE )); then
  echo "ERROR: adapter1's IdP saw no back-channel refresh during the install re-auth (POST /token $TOKEN_REQS_BEFORE -> $TOKEN_REQS_AFTER)"
  PASS=1
fi

# The agent must still be resident: the refresh only exists while it lives.
for AGENT_PID in ${AGENT_PIDS[@]+"${AGENT_PIDS[@]}"}; do
  if ! kill -0 "$AGENT_PID" 2> /dev/null; then
    echo "ERROR: an auth-agent process ($AGENT_PID) exited during the install legs"
    PASS=1
  fi
done

# Traffic still flows after four installs.
if ! ping_test
then
  echo "ERROR: traffic stopped after the leg-2 install"
  PASS=1
fi
fi

if [[ "$PASS" == 0 ]] then
# Every obligation so far was satisfied by every connected actor and pruned
# (one line per obligation, four installs so far), and nothing was revoked.
if ! wait_for_log_count 90 vs.log \
    "satisfied by all connected actors, pruning" 4; then
  echo "ERROR: the sweep never pruned all four satisfied obligations"
  grep -E "reauth sweep" vs.log | tail -n 20 || true
  PASS=1
fi
if grep -qE "by the deadline" vs.log; then
  echo "ERROR: something was revoked during the survival legs:"
  grep -E "by the deadline" vs.log | head -n 5
  PASS=1
fi
fi

#
# Leg 3 — adapter key removed: adapter2 is revoked, adapter1 unaffected
#

if [[ "$PASS" == 0 ]] then
echo
echo "LEG 3: install a policy lacking adapter2's bootstrap key"

# Anchor the revocation bound HERE: the deadline clock starts at the install.
LEG3_INSTALL_TS=$SECONDS
if ! install_policy "$PREGEN/$POLICY_NO_ADAPTER2_BIN"; then
  echo "ERROR: leg-3 policy install failed"
  PASS=1
fi
fi

if [[ "$PASS" == 0 ]] then
# The removal must be exercised END TO END (the zipline#104 lesson): it is
# not enough that adapter2 goes away — it must have PRESENTED its key under
# the new generation and been REJECTED. The VS logs the rejection.
if ! wait_for_log "$REAUTH_WAIT" vs.log "reauthorize failed for actor $B_ZPR_ADDR "; then
  echo "ERROR: adapter2 never presented its (removed) key, or the VS never rejected it"
  echo "       (a revocation without a rejected attempt exercises nothing)"
  grep -E "reauthorize" vs.log | tail -n 10 || true
  PASS=1
else
  echo "the VS rejected adapter2's re-auth under the new policy:"
  grep -E "reauthorize failed for actor $B_ZPR_ADDR " vs.log | head -n 2
fi
fi

if [[ "$PASS" == 0 ]] then
# The sweep revokes adapter2 within reauth_deadline + one sweep period,
# measured from the INSTALL — the earlier rejection check already consumed
# part of that budget, so the wait must not restart the clock.
LEG3_BUDGET=$(revoke_budget "$LEG3_INSTALL_TS")
if (( LEG3_BUDGET <= 0 )); then
  echo "ERROR: the revocation bound ($((REAUTH_DEADLINE + SWEEP_PERIOD + REVOKE_SLACK))s from the install) elapsed before this check ran"
  PASS=1
elif ! wait_for_log "$LEG3_BUDGET" vs.log \
    "reauth sweep: adapter $B_ZPR_ADDR did not re-authenticate under vinst .* by the deadline; revoked"; then
  echo "ERROR: the sweep never revoked adapter2 within $((REAUTH_DEADLINE + SWEEP_PERIOD + REVOKE_SLACK))s of the install"
  grep -E "reauth sweep" vs.log | tail -n 20 || true
  PASS=1
else
  echo "sweep revoked adapter2 within bound ($(( SECONDS - LEG3_INSTALL_TS ))s after the install):"
  grep -E "reauth sweep: adapter $B_ZPR_ADDR" vs.log | head -n 2
fi

# The node must NOT have been disconnected: it re-authenticated fine.
if grep -qE "disconnecting it" vs.log; then
  echo "ERROR: the node was disconnected during leg 3:"
  grep -E "reauth sweep: node" vs.log | head -n 5
  PASS=1
fi
fi

if [[ "$PASS" == 0 ]] then
# adapter1 is unaffected: its user still reaches PingableVs across the
# boundary — while adapter2, revoked and its visas dropped, is unreachable.
if ! sudo ip netns exec zpr-a ping -q -c 5 -w 10 "$VS_ZPR_ADDR"; then
  echo "ERROR: adapter1's traffic stopped when adapter2 was revoked"
  PASS=1
fi
# adapter2 must be COMPLETELY unreachable — zero replies, not merely "fewer
# than three" (which is all ping's exit code can distinguish).
if ! assert_unreachable zpr-a "$B_ZPR_ADDR"; then
  echo "ERROR: traffic still flows to adapter2 after its revocation (or the probe failed; see above)"
  PASS=1
else
  echo "adapter1 unaffected; adapter2 unreachable, as expected"
fi
fi

#
# Leg 4 — node key removed: the node is disconnected
#

if [[ "$PASS" == 0 ]] then
echo
echo "LEG 4: install a policy lacking the node's bootstrap key"

# Anchor the revocation bound HERE, as in leg 3.
LEG4_INSTALL_TS=$SECONDS
if ! install_policy "$PREGEN/$POLICY_NO_NODE_BIN"; then
  echo "ERROR: leg-4 policy install failed"
  PASS=1
fi
fi

if [[ "$PASS" == 0 ]] then
# Same end-to-end discipline as leg 3: the node must ATTEMPT its in-place
# self re-auth and fail it (the VS refuses the challenge signature of a key
# no longer in policy).
if ! wait_for_log "$REAUTH_WAIT" node.log "self re-authentication with the visa service failed"; then
  echo "ERROR: the node never attempted (or never failed) its self re-auth"
  grep -iE "re-auth|request_auth" node.log | tail -n 20 || true
  PASS=1
else
  echo "the node's self re-auth was refused under the new policy:"
  grep -E "self re-authentication with the visa service failed" node.log | head -n 2
fi
fi

if [[ "$PASS" == 0 ]] then
# The sweep disconnects the node (and with it, its docked adapters) within
# the same deadline + sweep-period bound, measured from the leg-4 install.
LEG4_BUDGET=$(revoke_budget "$LEG4_INSTALL_TS")
if (( LEG4_BUDGET <= 0 )); then
  echo "ERROR: the disconnection bound ($((REAUTH_DEADLINE + SWEEP_PERIOD + REVOKE_SLACK))s from the install) elapsed before this check ran"
  PASS=1
elif ! wait_for_log "$LEG4_BUDGET" vs.log \
    "reauth sweep: node $NODE_ZPR_ADDR did not re-authenticate under vinst .* by the deadline; disconnecting it"; then
  echo "ERROR: the sweep never disconnected the node within $((REAUTH_DEADLINE + SWEEP_PERIOD + REVOKE_SLACK))s of the install"
  grep -E "reauth sweep" vs.log | tail -n 20 || true
  PASS=1
else
  echo "sweep disconnected the node within bound ($(( SECONDS - LEG4_INSTALL_TS ))s after the install):"
  grep -E "reauth sweep: node $NODE_ZPR_ADDR" vs.log | head -n 2
fi

if ! grep -qE "disconnect actor at $NODE_ZPR_ADDR for reason Admin" vs.log; then
  echo "ERROR: no Admin disconnect was recorded for the node"
  grep -E "disconnect actor" vs.log | tail -n 5 || true
  PASS=1
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
