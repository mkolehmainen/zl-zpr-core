#!/usr/bin/env bash
# oidc + file trusted-service interplay end-to-end test (zipline#27, the
# epic zipline#22 finale). one-node-oidc-test.sh's harness (fake IdP, no
# browser, no Google) minus the key-rotation leg, exercising the master
# plan's Background configuration end to end:
#
#   - `google` (api = "oidc", the fake IdP) authenticates adapter1's user
#     and mints the identity attribute user.sub (+ user.email).
#   - `happyfile` (api = "file") decorates that identity: happyfile.json is
#     keyed on user.sub and vends user.hair_color and the `lazy` tag.
#   - The only policy statement referencing a trusted-service attribute is
#     `allow lazy users to access Web.` — it references only happyfile's
#     tag, so `google` survives compilation by the identity-vendor
#     retention rule (zipline#23), not by an attribute reference. The
#     zpdump pre-check below asserts both services are in the binary; a
#     compiler without the rule prunes google and the check fails (the C1
#     revert-RED, provable without root).
#
# What is asserted, and why the refresh legs exist (zipline#24/#25/#26):
#   1. After the OIDC login, the actor carries user.sub, user.email,
#      user.zpr.tag.lazy and user.zpr.authority = google, and the `lazy`
#      visa works (adapter1 -> Web connectivity).
#   2. The same assertions hold across attribute-refresh cycles in which
#      the decorating store answers. This is the load-bearing part: the
#      Finding 3 regression (a decorating store displacing the
#      authenticator's user.zpr.authority) is invisible on the connect
#      path alone — the authority is displaced once, and the attribute
#      loss (google's vouched_here gate pruning user.sub, then happyfile's
#      lookup missing and `lazy` vanishing) only shows on the *following*
#      refresh. A test that connects and stops would pass against the
#      broken code.
#
# Refresh cycles are driven deterministically via the admin API:
# `vs-admin services --id happyfile --flush` records TrustedServiceChange,
# whose handler reconciles stale/TTL-expired trusted attributes on actors
# behind live visas (vs/src/event_mgr.rs). The final cycle first waits out
# happyfile's expiration_seconds (90 s, chosen to exceed the vs's 60 s
# MIN_ATTRIBUTE_TTL while keeping this wait bounded) so the TTL-expiry
# path is exercised too, not just the revision-moved path.
#
# The admin surface is the ZPR-address-keyed actor API (zipline#31):
# `vs-admin actors` lists {zpr_addr, cn}; `--addr` returns the descriptor
# with attrs. Assertions go through jq and tolerate extra fields.
set -euo pipefail

export RUST_BACKTRACE=1
DEBUG_TARGETS=${DEBUG_TARGETS:-all=INFO}
KM_IMPL=${KM_IMPL:-noise}

PH_BIN="${PH_BIN:-$(realpath "$(dirname "$0")/../target/debug/ph")}"
PH_DEBUG_BIN="${PH_DEBUG_BIN:-$(realpath "$(dirname "$0")/../target/debug/ph-cli")}"
VS_BIN="${VS_BIN:-$(realpath "$(dirname "$0")/vs")}"
VS_ADMIN_BIN="${VS_ADMIN_BIN:-$(realpath "$(dirname "$0")/vs-admin")}"
VALKEY_SERVER_BIN="${VALKEY_SERVER_BIN:-$(realpath -s "$(dirname "$0")/valkey-server")}"
# Optional: with a zpdump on hand the both-services check runs before any
# root-needing setup. Absent, the check is skipped with a warning (the
# fixture Makefile's compile is the fallback evidence).
ZPDUMP_BIN="${ZPDUMP_BIN:-$(realpath -s "$(dirname "$0")/zpdump" 2>/dev/null || true)}"

PREGEN=$(realpath "$(dirname $0)/pregen")
FAKE_IDP=$(realpath "$(dirname $0)/lib/fake-idp.py")
NODE_AUTH_PRIVATE_KEY="${NODE_AUTH_PRIVATE_KEY:-$PREGEN/node-rsa-key.pem}"

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

# Fixed shape: the fixture declares exactly this topology.
NUM_ACTORS=2
NODE_ZPR_ADDR=fd5a:5052::2
VS_ZPR_ADDR=fd5a:5052::1
A_ZPR_ADDR=fd00:1:1::1
B_ZPR_ADDR=fd00:1:2::1
C_ZPR_ADDR=fd00:1:3::1
ZPR_SUBNET=fd00:1::0/32
POLICY_BIN=oidc-file-interplay.bin2

# happyfile's expiration_seconds in the fixture; the TTL-expiry refresh leg
# waits this out (plus slack). Keep in sync with oidc-file-interplay.zplc.
HAPPYFILE_TTL=90

DOCK_LINK=2

IDP_PORT=9000
IDP_ISSUER="https://127.0.0.1:$IDP_PORT"

# The admin API listens on the VS ZPR address inside the zpr-vs netns.
ADMIN_URL="https://[$VS_ZPR_ADDR]:8182"

for BIN_DESC in "vs:$VS_BIN" "vs-admin:$VS_ADMIN_BIN"; do
  if [ ! -e "${BIN_DESC#*:}" ]; then
    echo "${BIN_DESC%%:*} binary not found, expected it at ${BIN_DESC#*:}"
    exit 1
  fi
done

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
  echo "build it: cd $PREGEN && make oidc-file-interplay.bin2"
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

if ! command -v jq > /dev/null; then
  echo "jq is required for the admin-surface assertions"
  exit 1
fi

#
# Pre-check, needs no root: both trusted services must be in the compiled
# policy. `google` is referenced by no ZPL statement, so its presence here
# is the identity-vendor retention rule (zipline#23) at work — a compiler
# without the rule prunes it, every login then fails with no OIDC service
# in the fabric, and this catches that without ever touching a netns.
#
if [ -n "$ZPDUMP_BIN" ] && [ -x "$ZPDUMP_BIN" ]; then
  DUMP=$("$ZPDUMP_BIN" "$PREGEN/$POLICY_BIN")
  for WANT in "google trusted (oidc)" "happyfile trusted (file)"; do
    if ! grep -qF "$WANT" <<<"$DUMP"; then
      echo "FAILURE: compiled policy is missing '$WANT' — was the fixture"
      echo "compiled with a zplc that lacks the identity-vendor retention rule (zipline#23)?"
      exit 1
    fi
  done
  echo "zpdump pre-check OK: both trusted services present in $POLICY_BIN"
else
  echo "WARNING: zpdump not available (set ZPDUMP_BIN); skipping the both-services pre-check"
fi

NODE_SOCK=node.sock
VS_SOCK=vs.sock
ADAPTER1_SOCK=adapter1.sock
ADAPTER2_SOCK=adapter2.sock
NODE_CAP_SOCK=node_cap.sock
VS_CAP_SOCK=vs_cap.sock
ADAPTER1_CAP_SOCK=adapter1_cap.sock
ADAPTER2_CAP_SOCK=adapter2_cap.sock

# Launch a fake IdP inside a netns (see one-node-oidc-test.sh for the
# per-netns-loopback reasoning). Only zpr-vs (JWKS refresh) and zpr-a (the
# one login) need one here.
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

# Interactive OIDC login with no browser (same mechanism as
# one-node-oidc-test.sh).
#
# $1 = netns, $2 = control socket, $3 = log file
function oidc_login() {
  NETNS=$1
  SOCK=$2
  LOGIN_LOG=$3

  rm -f "$LOGIN_LOG"
  sudo -E ip netns exec "$NETNS" sudo -E -u "$ZPR_USER" \
    env -u BROWSER SSL_CERT_FILE="$PWD/ca.crt" \
    "$PH_DEBUG_BIN" -p "$SOCK" connect "$DOCK_LINK" --no-browser \
    > "$LOGIN_LOG" 2>&1 &
  CONNECT_PID=$!

  AUTH_URL=""
  for _ in $(seq 1 60); do
    AUTH_URL=$(sed -n 's/.*Open this URL to continue: //p' "$LOGIN_LOG" | head -n 1)
    if [ -n "$AUTH_URL" ]; then break; fi
    if ! kill -0 "$CONNECT_PID" 2> /dev/null; then break; fi
    sleep 1
  done

  if [ -n "$AUTH_URL" ]; then
    sudo -E ip netns exec "$NETNS" sudo -E -u "$ZPR_USER" \
      curl --silent --show-error --location --cacert ca.crt \
      --output /dev/null "$AUTH_URL" || true
  fi

  if wait "$CONNECT_PID"; then
    return 0
  else
    echo "oidc_login($NETNS): connect failed:"
    cat "$LOGIN_LOG"
    return 1
  fi
}

# Run vs-admin against the admin API from inside the zpr-vs netns.
function vs_admin() {
  sudo -E ip netns exec zpr-vs sudo -E -u "$ZPR_USER" \
    "$VS_ADMIN_BIN" --svc-url "$ADMIN_URL" --ca-cert ca.crt \
    --api-key-file vs-admin.key --format compact "$@"
}

# Locate the user actor: the one whose attrs carry user.sub == user-a.
# Deliberately not keyed on the requested ZPR address or a CN — the actor
# API identifies actors by assigned ZPR address (zipline#31), and an
# OIDC-only actor has no CN.
function find_user_actor() {
  local ADDR DESC
  for ADDR in $(vs_admin actors | jq -r '.[].zpr_addr'); do
    DESC=$(vs_admin actors --addr "$ADDR" 2>/dev/null) || continue
    if jq -e '.attrs[] | select(.key=="user.sub") | select(.value == ["user-a"])' \
        >/dev/null 2>&1 <<<"$DESC"; then
      echo "$ADDR"
      return 0
    fi
  done
  return 1
}

# Assert the four interplay attributes on the user actor. user.sub and
# user.email come from google (the authenticator), user.zpr.tag.lazy from
# happyfile (the decorator; tag => presence is the assertion, not a value),
# and user.zpr.authority must name google — the credential verifier — and
# never happyfile (zipline#25/#26).
#
# $1 = phase label for the failure message
function assert_user_actor() {
  local PHASE=$1 DESC CHECK
  DESC=$(vs_admin actors --addr "$USER_ACTOR_ADDR") || {
    echo "ASSERTION FAILED ($PHASE): could not fetch actor $USER_ACTOR_ADDR"
    return 1
  }
  for CHECK in \
    '.attrs[] | select(.key=="user.sub")           | select(.value == ["user-a"])' \
    '.attrs[] | select(.key=="user.email")         | select(.value == ["user-a@example.com"])' \
    '.attrs[] | select(.key=="user.zpr.tag.lazy")' \
    '.attrs[] | select(.key=="user.zpr.authority") | select(.value == ["google"])'
  do
    if ! jq -e "$CHECK" >/dev/null <<<"$DESC"; then
      echo "ASSERTION FAILED ($PHASE): no attribute matching: $CHECK"
      echo "actor descriptor was:"
      jq . <<<"$DESC" || echo "$DESC"
      return 1
    fi
  done
  echo "actor assertions OK ($PHASE)"
}

# Drive one deterministic refresh cycle: flush happyfile's file store
# (TrustedServiceChange -> reconcile stale/TTL-expired attributes on actors
# behind live visas), then give the async reconcile a moment.
function refresh_cycle() {
  vs_admin services --id happyfile --flush
  sleep 5
}

# The `lazy` visa's evidence: adapter1 (the lazy user) reaches Web
# (provided by adapter2). Plus the node<->vs plumbing pings. Deliberately
# NOT ping_test: this policy grants adapter2's device no path to adapter1,
# so the b->a leg would fail by design.
function connectivity_test() {
  RESULT=0
  sudo ip netns exec zpr-node ping -q -c 5 -w 5 "$VS_ZPR_ADDR" & wait -f $!; let RESULT="RESULT||$?"
  sudo ip netns exec zpr-vs ping -q -c 5 -w 5 "$NODE_ZPR_ADDR" & wait -f $!; let RESULT="RESULT||$?"
  sudo ip netns exec zpr-a ping -q -c 5 -w 5 "$B_ZPR_ADDR" & wait -f $!; let RESULT="RESULT||$?"
  return "$RESULT"
}

function check_dock_link_inactive() {
  "$PH_DEBUG_BIN" -p "$1" link show "$DOCK_LINK" | grep -q 'State: Inactive'
}

#
# Set up automatic cleanup
#

trap cleanup EXIT

TMPDIR=$(mktemp -d)
pushd "$TMPDIR" > /dev/null

echo "Setting up network"

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

# happyfile's attribute data: the vs reads file_ts_dir/happyfile.json,
# and file_ts_dir defaults to the config file's directory ($TMPDIR).
cp "$PREGEN/happyfile.json" happyfile.json

emit_vs_config ca vs.zpr > vs-config.toml

# Admin API key: mint one directly in the format vsapikey uses
# (vs/src/apikey.rs: zpr_vsapi.<id_hex>.<b64url_secret>; vs_keys.toml
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
    f.write('created = "2026-09-14"\n')
    f.write(f'secret_hash = "{hashlib.sha256(secret).hexdigest()}"\n')
    f.write('description = "oidc-file-interplay-test"\n')
with open("vs-admin.key", "w") as f:
    f.write(f"zpr_vsapi.{key_id}.{b64}\n")
PYEOF
chmod 600 vs-admin.key

#
# Fake IdPs: TLS cert for 127.0.0.1 signed by the test CA; instances in
# zpr-vs (visa service JWKS fetch) and zpr-a (the login).
#

echo "Launching fake IdPs"

mkdir idp-state
openssl req -new -newkey rsa:2048 -nodes -keyout idp.key \
  -subj "/CN=127.0.0.1" -out idp.csr 2> /dev/null
openssl x509 -req -in idp.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 1 -out idp.crt \
  -extfile <(printf "subjectAltName=IP:127.0.0.1") 2> /dev/null

launch_fake_idp zpr-vs user-vs-unused
launch_fake_idp zpr-a user-a

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

sudo -E ip netns exec zpr-vs sudo -E -u "$ZPR_USER" \
    env XDG_DATA_HOME=/tmp SSL_CERT_FILE="$PWD/ca.crt" "$VS_BIN" \
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

# Same wait as one-node-oidc-test.sh: the node only advertises the IdP once
# the visa service pushed the auth-services list over VSS.
function check_node_has_auth_services() {
  grep -q "received services update with [1-9]" node.log
}
wait_for 30 check_node_has_auth_services || {
  echo "ERROR: node never received the auth-services list from the visa service"
  exit 1
}

# adapter1: user-only (no bootstrap key) — the interplay's subject.
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
  --zpr-addr "$A_ZPR_ADDR" 2>&1 | tee adapter1.log | prefix_log zpr-a &

# adapter2: device-only (bootstrap key, no login) — it provides Web.
sudo -E ip netns exec zpr-b sudo -E -u "$ZPR_USER" "$PH_BIN" \
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
# Login and connect-path assertions
#

PASS=0

echo "Logging in adapter1 (user-only, sub user-a)"
oidc_login zpr-a "$ADAPTER1_SOCK" login1.log || PASS=1

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

echo "TEST STARTING"

echo "Locating the user actor on the admin API"
USER_ACTOR_ADDR=""
for _ in $(seq 1 15); do
  USER_ACTOR_ADDR=$(find_user_actor) && break
  sleep 1
done
if [ -z "$USER_ACTOR_ADDR" ]; then
  echo "ERROR: no actor carrying user.sub == user-a found on the admin API"
  vs_admin actors || true
  PASS=1
else
  echo "user actor at $USER_ACTOR_ADDR"
fi
fi

if [[ "$PASS" == 0 ]] then
assert_user_actor "connect path" || PASS=1
fi

if [[ "$PASS" == 0 ]] then
echo "Checking the lazy visa (adapter1 -> Web connectivity)"
if ! connectivity_test
then PASS=1
fi
fi

#
# Refresh legs — the part a Finding 3 regression needs (zipline#24).
#

if [[ "$PASS" == 0 ]] then
echo "Refresh cycle 1 (happyfile flush -> reconcile)"
refresh_cycle
assert_user_actor "after refresh 1" || PASS=1
fi

# Cycle 2 matters independently of cycle 1: with the displacement bug the
# authority flips on the first refresh, and the *attribute loss* (sub/email
# pruned by the vouched_here gate, then lazy lost) follows on the next one.
if [[ "$PASS" == 0 ]] then
echo "Refresh cycle 2 (the following refresh)"
refresh_cycle
assert_user_actor "after refresh 2" || PASS=1
fi

# TTL leg: wait out happyfile's expiration_seconds so the next reconcile
# takes the TTL-expired path rather than the revision-moved one, then
# re-assert and re-verify the visa still carries traffic.
if [[ "$PASS" == 0 ]] then
echo "Waiting out happyfile's TTL (${HAPPYFILE_TTL}s + slack)"
sleep $((HAPPYFILE_TTL + 5))
refresh_cycle
assert_user_actor "after TTL-expired refresh" || PASS=1
fi

if [[ "$PASS" == 0 ]] then
if ! connectivity_test
then PASS=1
fi
fi

#
# Cleanup
#

sudo pkill -SIGINT -f "fake-idp.py --port" || true

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
