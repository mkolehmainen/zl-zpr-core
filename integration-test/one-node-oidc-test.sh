#!/usr/bin/env bash
# One-node OIDC integration test (zipline#16, OIDC master plan D5).
#
# one-node-test.sh adapted to exercise user (OIDC) authentication through a
# local fake IdP (lib/fake-idp.py) with no Google and no browser:
#
#   - adapter1 has NO --bootstrap-key: user-only, forced through OIDC.
#   - adapter2 keeps its bootstrap key AND logs in: both blobs.
#     (Device-only is already covered by one-node-v6-test.sh.)
#   - Logins run `ph-cli connect 1 --no-browser`; the printed authorization
#     URL is fetched with `curl -L --cacert` inside the adapter's netns,
#     driving the 302 to ph-cli's loopback callback listener.
#   - Key-rotation leg: `fake-idp.py --rotate`, restart adapter1, re-login;
#     the visa service sees an unknown kid and refreshes from the live JWKS
#     (the seed fixture deliberately carries only the first key).
#
# Issuer reachability across namespaces: every consumer dials the policy
# issuer https://127.0.0.1:9000, but loopback is per-netns, so one fake-idp
# instance runs in each netns that needs it (zpr-vs for the visa service's
# JWKS fetch, zpr-a and zpr-b for the logins). The instances share signing
# keys, the TLS cert, and one --state-dir on the (un-namespaced)
# filesystem, so a single --rotate switches all of them at once and the
# pregen policy's issuer string stays exactly as written.
#
# TLS: the compiler's issuer rule is https-absolute, so the IdP serves TLS
# with a cert signed by the test CA; the visa service and ph-cli trust it
# via SSL_CERT_FILE (rustls-native-certs honors it), curl via --cacert.
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

# IPv6, two actors, and the OIDC policy — fixed (no parse_arguments.sh):
# the fixture declares exactly this shape.
NUM_ACTORS=2
NODE_ZPR_ADDR=fd5a:5052::2
VS_ZPR_ADDR=fd5a:5052::1
A_ZPR_ADDR=fd00:1:1::1
B_ZPR_ADDR=fd00:1:2::1
C_ZPR_ADDR=fd00:1:3::1
ZPR_SUBNET=fd00:1::0/32
POLICY_BIN=oidc-test.bin2

# The issuer the pregen policy pins; each relevant netns runs an IdP
# instance answering it on its own loopback.
IDP_PORT=9000
IDP_ISSUER="https://127.0.0.1:$IDP_PORT"

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

# Launch a fake IdP inside a netns. All instances share the signing keys,
# TLS material and rotation state directory, so they serve identical
# discovery/JWKS documents and rotate together; the `sub` differs per netns
# so each adapter logs in as its own user (the policy's user-a / user-b).
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

# Launch adapter1 — user-only: deliberately NO --bootstrap-key, so the only
# authentication path is the OIDC user blob supplied through the AuthAgent.
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

# Interactive OIDC login with no browser: run `ph-cli connect 1 --no-browser`
# inside the adapter's netns, scrape the printed authorization URL, and fetch
# it with curl (following the 302 to ph-cli's loopback callback listener).
# connect exits 0 once the link is Active.
#
# $1 = netns, $2 = control socket, $3 = log file
function oidc_login() {
  NETNS=$1
  SOCK=$2
  LOGIN_LOG=$3

  rm -f "$LOGIN_LOG"
  sudo -E ip netns exec "$NETNS" sudo -E -u "$ZPR_USER" \
    env -u BROWSER SSL_CERT_FILE="$PWD/ca.crt" \
    "$PH_DEBUG_BIN" -p "$SOCK" connect 1 --no-browser \
    > "$LOGIN_LOG" 2>&1 &
  CONNECT_PID=$!

  # The URL appears once ph calls back for a credential.
  AUTH_URL=""
  for _ in $(seq 1 60); do
    AUTH_URL=$(sed -n 's/.*Open this URL to continue: //p' "$LOGIN_LOG" | head -n 1)
    if [ -n "$AUTH_URL" ]; then break; fi
    if ! kill -0 "$CONNECT_PID" 2> /dev/null; then break; fi
    sleep 1
  done

  if [ -n "$AUTH_URL" ]; then
    # Drive the browserless login: GET the authorization URL; the IdP 302s
    # to http://127.0.0.1:<port>/callback where ph-cli is listening.
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

#
# Fake IdP: TLS server cert for 127.0.0.1 signed by the test CA, shared
# rotation state, one instance per netns that dials the issuer.
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
  --logging "$DEBUG_TARGETS" \
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

sleep 5

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
# Interactive logins (no browser)
#

PASS=0

echo "Logging in adapter1 (user-only)"
oidc_login zpr-a "$ADAPTER1_SOCK" login1.log || PASS=1

if [[ "$PASS" == 0 ]] then
echo "Logging in adapter2 (device + user)"
oidc_login zpr-b "$ADAPTER2_SOCK" login2.log || PASS=1
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
# This sleep solves a display issue because magic
sleep 1

#
# Run test
#

echo "TEST STARTING"

if ! ping_test
then PASS=1
fi

sleep 1

fi

#
# Key-rotation leg: switch the signing key, restart adapter1, and log in
# again. The new token carries an unknown kid, forcing the visa service to
# refresh from the live JWKS (the seed only has the first key) — the
# rotation + stale-cache path.
#

if [[ "$PASS" == 0 ]] then
echo "Rotating fake-IdP signing key"
python3 "$FAKE_IDP" --state-dir idp-state --rotate

echo "Restarting adapter1"
ADAPTER1_PID=$(pgrep -f "control-path $ADAPTER1_SOCK" | head -n 1 || true)
if [ -z "$ADAPTER1_PID" ]; then
  echo "ERROR: cannot find adapter1 to restart"
  PASS=1
else
  sudo kill -SIGINT "$ADAPTER1_PID"
  sleep 2
  launch_adapter1
  sleep 2

  echo "Logging in adapter1 again (rotated key)"
  # Bounded retry: the first attempt races the visa service's JWKS refresh
  # (unknown-kid fetches are coalesced and rate-limited). Before retrying,
  # wait for the link to return to Inactive rather than sleeping a fixed
  # 5 s: after a rejected attempt ph auto-restarts the link after a 5 s
  # holddown (DEFAULT_LINK_RESTART_HOLDDOWN, adapter/ph/src/config.rs), and
  # if that automatic Start won the race the retry's startLink would return
  # UnexpectedTransition, which `connect` treats as fatal. Polling for
  # Inactive means the retry's Start lands at the beginning of a fresh
  # holddown window instead of racing the end of one. (If the automatic
  # restart is mid-attempt when we look, it fails fast — adapter1 has no
  # bootstrap key and no registered agent — and the link closes back to
  # Inactive, so the poll converges.)
  function check_link1_inactive() {
    "$PH_DEBUG_BIN" -p "$ADAPTER1_SOCK" link show 1 | grep -q 'State: Inactive'
  }
  if ! oidc_login zpr-a "$ADAPTER1_SOCK" login3.log; then
    echo "Retrying post-rotation login"
    wait_for 30 check_link1_inactive \
      || echo "WARNING: link 1 did not return to Inactive; retrying anyway"
    oidc_login zpr-a "$ADAPTER1_SOCK" login3.log || PASS=1
  fi

  if [[ "$PASS" == 0 ]] then
  wait_for 15 check_carrier zpr-a tun0 || { PASS=1; }
  fi

  if [[ "$PASS" == 0 ]] then
  if ! ping_test
  then PASS=1
  fi
  fi
fi
fi

#
# Check stats
#

for SOCK in "$NODE_SOCK" "$VS_SOCK" "$ADAPTER1_SOCK" "$ADAPTER2_SOCK"
do
	APOOO=$(counters "$SOCK" | awk -F': ' '$1 == "Actor Packets Out-Of-Order" { apooo += $2 } END { print apooo }')
	if (( APOOO != 0 ))
	then
		echo "$(basename "$SOCK"): ERROR: found actor packets out-of-order: $APOOO"
		PASS=1
	fi
done

# zipline#21: restarting adapter1 revokes its visas on the node; the node must
# withdraw the streams from the surviving adapter2 (UnbindEgressStreamIndication)
# so it re-requests a visa instead of blackholing on the dead stream. If the
# node dropped any packet as Unknown Stream ID, that withdrawal did not happen.
USID=$(counters "$NODE_SOCK" | awk -F': ' '$1 == "Unknown Stream ID" { usid += $2 } END { print usid+0 }')
if (( USID != 0 ))
then
	echo "$(basename "$NODE_SOCK"): ERROR: node dropped $USID packet(s) as Unknown Stream ID (stale peer stream binding after revocation)"
	PASS=1
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
