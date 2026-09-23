#!/usr/bin/env bash
# oidc + zpr-attr/1 trusted-service end-to-end test (zipline#81, epic #72
# E1). oidc-file-interplay-test.sh's harness (fake IdP, no browser, no
# Google) with the `file` decorator replaced by the networked `zpr-attr/1`
# attribute service — the reference `zpr-attr-server` from
# zl-zpr-visaservice (zipline#80) serving attr-query-data.json over pinned
# TLS on the zpr-vs namespace's loopback:
#
#   - `google` (api = "oidc", the fake IdP) authenticates adapter1's user
#     and mints the identity attribute user.sub (+ user.email).
#   - `zipline` (api = "zpr-attr/1") decorates that identity over HTTPS:
#     POST {url}/query keyed on user.sub, answering with user.dept and the
#     `contractor` tag, authenticated by the bearer token the vs reads from
#     <ts_secrets_dir>/zipline.token (zipline#78).
#   - The only policy statement referencing a trusted-service attribute is
#     `allow contractor users to access Web.` — it references only
#     zipline's tag, so `google` survives compilation by the
#     identity-vendor retention rule (zipline#23). The zpdump pre-check
#     below asserts both services are in the binary without needing root.
#
# The four legs, in order:
#   1. Decoration: after the OIDC login the actor carries user.sub,
#      user.email, user.dept, user.zpr.tag.contractor and
#      user.zpr.authority = google, and the `contractor` visa carries
#      traffic (adapter1 -> Web connectivity).
#   2. Untargeted notify: `zpr-attr-server --notify` with no identity pairs
#      posts the "everything changed" `{}` body (zipline#79); reconcile
#      re-queries with UNCHANGED data and must converge — same attributes,
#      no spurious revocation, connectivity intact. This leg runs before
#      the data edit on purpose: "no spurious revocation" is only provable
#      while the data still vends the tag.
#   3. Revocation: the store's data drops `contractor` (the server is
#      restarted on the edited JSON — the reference server loads its data
#      once at startup), then a TARGETED notify (user.sub=user-a) with a
#      `Permission::Notify` key bound to the zipline service id (the
#      zipline#79 V2 surface). The queued TrustedServiceChange event
#      re-queries, the tag disappears, the visa is revoked, and a fresh
#      connect attempt (ping) is denied.
#   4. SKIP_NOTIFY=1 negative knob: skips ONLY the notify posts (both of
#      them; the untargeted one is skipped too so the negative run reaches
#      the revocation window quickly). With no notify the revocation
#      assertion MUST fail inside its bounded poll window — proving leg 3
#      depends on the queued change event, not on TTL expiry. A SKIP_NOTIFY
#      run is therefore EXPECTED to end in FAILURE at "revocation". The
#      poll window (REVOKE_POLL_SECS) is deliberately far under the
#      fixture's 90 s attribute TTL so autonomous TTL-driven re-query
#      cannot fake a pass.
#
# The vs admin TLS cert is minted at runtime with an IP SAN for the VS ZPR
# address, signed by the pregen test CA — NOT emit_vs_config's pregen
# *.zpr.org cert — because `zpr-attr-server --notify` verifies TLS strictly
# (unlike vs-admin), and the admin URL names the VS by IP literal.
set -euo pipefail

export RUST_BACKTRACE=1
DEBUG_TARGETS=${DEBUG_TARGETS:-all=INFO}
KM_IMPL=${KM_IMPL:-noise}

# 1 = skip the notify posts (the negative leg; see header). Default 0.
SKIP_NOTIFY=${SKIP_NOTIFY:-0}

PH_BIN="${PH_BIN:-$(realpath "$(dirname "$0")/../target/debug/ph")}"
PH_DEBUG_BIN="${PH_DEBUG_BIN:-$(realpath "$(dirname "$0")/../target/debug/ph-cli")}"
VS_BIN="${VS_BIN:-$(realpath "$(dirname "$0")/vs")}"
VS_ADMIN_BIN="${VS_ADMIN_BIN:-$(realpath "$(dirname "$0")/vs-admin")}"
VALKEY_SERVER_BIN="${VALKEY_SERVER_BIN:-$(realpath -s "$(dirname "$0")/valkey-server")}"
# The reference zpr-attr/1 server (zl-zpr-visaservice zpr-attr-server,
# zipline#80). Staging convention pending zipline#82; until then build it in
# zl-zpr-visaservice (`cargo build -p zpr-attr-server`) and either copy it
# next to this script or point ZPR_ATTR_SERVER_BIN at the build output.
ZPR_ATTR_SERVER_BIN="${ZPR_ATTR_SERVER_BIN:-$(realpath -s "$(dirname "$0")/zpr-attr-server")}"
# Optional: with a zpdump on hand the both-services check runs before any
# root-needing setup. Absent, the check is skipped with a warning (the
# fixture Makefile's compile is the fallback evidence).
ZPDUMP_BIN="${ZPDUMP_BIN:-$(realpath -s "$(dirname "$0")/zpdump" 2>/dev/null || true)}"

PREGEN=$(realpath "$(dirname "$0")/pregen")
FAKE_IDP=$(realpath "$(dirname "$0")/lib/fake-idp.py")
NODE_AUTH_PRIVATE_KEY="${NODE_AUTH_PRIVATE_KEY:-$PREGEN/node-rsa-key.pem}"

NETEM_PARAMS=${NETEM_PARAMS:-}

source "$(dirname "$0")/lib/common_funcs.sh"

ZPR_USER=$USER

# The C actor is unused here (the fixture has two actors), but the shared
# create_network() in lib/common_funcs.sh always sets up the zpr-c namespace
# and requires its addresses.
NODE_SUBSTRATE_ADDR_VS=10.0.0.1
NODE_SUBSTRATE_ADDR_A=10.0.1.1
NODE_SUBSTRATE_ADDR_B=10.0.2.1
# The C namespace addresses: this test has no third actor (NUM_ACTORS=2, no
# adapter3), but common_funcs.sh:create_network provisions the fixed zpr-c
# namespace unconditionally and expands these under this script's `set -u` —
# same values as the other two-actor tests (oidc-file-interplay-test.sh).
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
POLICY_BIN=attr-query.bin2

DOCK_LINK=2

IDP_PORT=9000
IDP_ISSUER="https://127.0.0.1:$IDP_PORT"

# The attribute service listens on the zpr-vs namespace's loopback; the
# port is pinned in the fixture's [trusted_services.zipline] url.
ATTR_PORT=8443

# The admin API listens on the VS ZPR address inside the zpr-vs netns.
ADMIN_URL="https://[$VS_ZPR_ADDR]:8182"

# How long the revocation leg polls for the visa to go. Deliberately far
# under the fixture's 90 s attribute TTL: in a SKIP_NOTIFY=1 run nothing
# may revoke inside this window, and a window near the TTL would let an
# autonomous TTL-driven re-query fake a notify-driven pass.
REVOKE_POLL_SECS=25

for BIN_DESC in "vs:$VS_BIN" "vs-admin:$VS_ADMIN_BIN" "zpr-attr-server:$ZPR_ATTR_SERVER_BIN"; do
  if [ ! -e "${BIN_DESC#*:}" ]; then
    echo "${BIN_DESC%%:*} binary not found, expected it at ${BIN_DESC#*:}"
    if [ "${BIN_DESC%%:*}" = "zpr-attr-server" ]; then
      echo "build it in zl-zpr-visaservice: cargo build -p zpr-attr-server"
      echo "then copy target/debug/zpr-attr-server next to this script, or set ZPR_ATTR_SERVER_BIN"
    fi
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
  echo "build it: cd $PREGEN && make attr-query.bin2"
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
# is the identity-vendor retention rule (zipline#23) at work; `zipline`
# proves the zpr-attr/1 declaration (zipline#76) survived weaving.
#
if [ -n "$ZPDUMP_BIN" ] && [ -x "$ZPDUMP_BIN" ]; then
  DUMP=$("$ZPDUMP_BIN" "$PREGEN/$POLICY_BIN")
  for WANT in "google trusted (oidc)" "zipline trusted (zpr-attr/1)"; do
    if ! grep -qF "$WANT" <<<"$DUMP"; then
      echo "FAILURE: compiled policy is missing '$WANT' — was the fixture"
      echo "compiled with a zplc older than 0.19.0 (zipline#76)?"
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

# Launch the reference attribute server on the zpr-vs loopback, serving the
# given data file over TLS pinned to the pregen CA (the CA the fixture's
# ca_cert_path embeds into the policy).
#
# $1 = data file
function launch_attr_server() {
  DATA_FILE=$1
  sudo -E ip netns exec zpr-vs sudo -E -u "$ZPR_USER" \
    "$ZPR_ATTR_SERVER_BIN" \
    --listen "127.0.0.1:$ATTR_PORT" \
    --cert attr-server.crt --key attr-server.key \
    --token-file attr-server.token \
    --data "$DATA_FILE" \
    2>&1 | tee -a attr-server.log | prefix_log attr-server &
}

# The server is up when /schema answers 200 to the bearer token.
function check_attr_server() {
  sudo -E ip netns exec zpr-vs curl --silent --fail \
    --cacert "$PREGEN/ca-cert.pem" \
    -H "Authorization: Bearer $(cat attr-server.token)" \
    --output /dev/null "https://127.0.0.1:$ATTR_PORT/schema"
}

# Stop the serve-mode server (notify-mode invocations exit on their own).
#
# SIGTERM, not SIGINT: a job launched with `&` from a non-interactive shell
# inherits SIGINT *ignored*, and unlike ph/vs the reference server installs no
# handler to override that, so a SIGINT is silently dropped, the old server
# keeps the port, and the data-v2 relaunch fails with "Address already in use".
# Then wait for the listener to be gone rather than racing the relaunch.
function stop_attr_server() {
  sudo pkill -SIGTERM -f "zpr-attr-server --listen" || true
  wait_for 10 attr_server_down
}

function attr_server_down() {
  ! check_attr_server
}

# Post a change notification from inside the zpr-vs netns with the
# service-bound notify key (zipline#79). Extra args are the --notify
# identity pairs; none means the untargeted `{}` body.
function attr_notify() {
  sudo -E ip netns exec zpr-vs sudo -E -u "$ZPR_USER" \
    "$ZPR_ATTR_SERVER_BIN" \
    --notify "$@" \
    --vs-url "$ADMIN_URL" \
    --vs-service zipline \
    --vs-api-key-file notify.key \
    --vs-ca-cert "$PREGEN/ca-cert.pem"
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

# Assert the five interplay attributes on the user actor. user.sub and
# user.email come from google (the authenticator); user.dept and
# user.zpr.tag.contractor from the zipline attribute service (the
# decorator; tag => presence is the assertion, not a value); and
# user.zpr.authority must name google — the credential verifier — and
# never zipline (zipline#25/#26).
#
# $1 = phase label for the failure message
function assert_user_actor() {
  local PHASE=$1 DESC CHECK
  DESC=$(vs_admin actors --addr "$USER_ACTOR_ADDR") || {
    echo "ASSERTION FAILED ($PHASE): could not fetch actor $USER_ACTOR_ADDR"
    return 1
  }
  for CHECK in \
    '.attrs[] | select(.key=="user.sub")                 | select(.value == ["user-a"])' \
    '.attrs[] | select(.key=="user.email")               | select(.value == ["user-a@example.com"])' \
    '.attrs[] | select(.key=="user.dept")                | select(.value == ["engineering"])' \
    '.attrs[] | select(.key=="user.zpr.tag.contractor")' \
    '.attrs[] | select(.key=="user.zpr.authority")       | select(.value == ["google"])'
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

# True once the contractor tag is GONE from the user actor — the
# revocation leg's convergence signal.
function contractor_tag_gone() {
  local DESC
  DESC=$(vs_admin actors --addr "$USER_ACTOR_ADDR") || return 1
  ! jq -e '.attrs[] | select(.key=="user.zpr.tag.contractor")' \
      >/dev/null <<<"$DESC"
}

# The `contractor` visa's evidence: adapter1 (the contractor user) reaches
# Web (provided by adapter2). Plus the node<->vs plumbing pings.
# Deliberately NOT ping_test: this policy grants adapter2's device no path
# to adapter1, so the b->a leg would fail by design.
function connectivity_test() {
  RESULT=0
  sudo ip netns exec zpr-node ping -q -c 5 -w 5 "$VS_ZPR_ADDR" & wait -f $!; let RESULT="RESULT||$?"
  sudo ip netns exec zpr-vs ping -q -c 5 -w 5 "$NODE_ZPR_ADDR" & wait -f $!; let RESULT="RESULT||$?"
  sudo ip netns exec zpr-a ping -q -c 5 -w 5 "$B_ZPR_ADDR" & wait -f $!; let RESULT="RESULT||$?"
  return "$RESULT"
}

# After revocation a fresh connect attempt must be DENIED: the a -> Web
# ping has to fail. The plumbing pings must still work — revoking the
# contractor visa must not take the fabric down.
function connectivity_denied_test() {
  if sudo ip netns exec zpr-a ping -q -c 3 -w 5 "$B_ZPR_ADDR"; then
    echo "ASSERTION FAILED (revocation): adapter1 still reaches Web"
    return 1
  fi
  RESULT=0
  sudo ip netns exec zpr-node ping -q -c 3 -w 5 "$VS_ZPR_ADDR" & wait -f $!; let RESULT="RESULT||$?"
  sudo ip netns exec zpr-vs ping -q -c 3 -w 5 "$NODE_ZPR_ADDR" & wait -f $!; let RESULT="RESULT||$?"
  if [ "$RESULT" != 0 ]; then
    echo "ASSERTION FAILED (revocation): fabric plumbing went down with the visa"
    return 1
  fi
  echo "fresh connect denied, plumbing intact (revocation)"
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

# zipline#88 (the zipline#83 Step-4 configuration, now the test's normal
# shape): adapter1 is user-only and runs on the dynamic fd5a:5052:adda:1::/64
# address the fabric assigns, so its tun0 must NOT carry the pre-provisioned
# static fd00:1:1::1 — the adapter itself adds the granted address (and the
# fd5a:5052::/32 internal-net return route) on activation. Keep a bare
# fd00:1::/32 route so adapter1's outbound traffic to the static actors still
# enters the TUN (deleting the address removes its peer route too).
sudo ip -n zpr-a addr del "$A_ZPR_ADDR" peer "$ZPR_SUBNET" dev tun0
sudo ip -n zpr-a -6 route add "$ZPR_SUBNET" dev tun0

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

# The attribute data, two revisions: v1 vends dept + the contractor tag;
# v2 is v1 with contractor dropped (the revocation leg's edit).
cp "$PREGEN/attr-query-data.json" attr-data-v1.json
jq 'del(."user.sub"."user-a".contractor)' attr-data-v1.json > attr-data-v2.json

# The zipline bearer token (zipline#78), written twice: attr-server.token
# is the server's --token-file; zipline.token is what the vs reads from
# <ts_secrets_dir>/<id>.token. Same secret, two consumers.
openssl rand -hex 32 > attr-server.token
cp attr-server.token zipline.token
chmod 600 attr-server.token zipline.token

# The attribute server's TLS cert: 127.0.0.1 with an IP SAN, signed by the
# PREGEN CA — the CA the fixture's ca_cert_path embedded into the policy,
# so the vs's pinned client accepts it. -CAserial keeps openssl's serial
# bookkeeping in $TMPDIR instead of littering pregen/.
openssl req -new -newkey rsa:2048 -nodes -keyout attr-server.key \
  -subj "/CN=127.0.0.1" -out attr-server.csr 2> /dev/null
openssl x509 -req -in attr-server.csr -CA "$PREGEN/ca-cert.pem" \
  -CAkey "$PREGEN/ca-key.pem" -CAserial pregen-ca.srl -CAcreateserial \
  -days 1 -out attr-server.crt \
  -extfile <(printf "subjectAltName=IP:127.0.0.1") 2> /dev/null

# The vs admin TLS cert: the VS ZPR address as an IP SAN, signed by the
# pregen CA. `zpr-attr-server --notify` verifies TLS strictly (no
# danger_accept_invalid_certs, unlike vs-admin), and the admin URL names
# the VS by IP literal, so the pregen *.zpr.org cert cannot work here.
openssl req -new -newkey rsa:2048 -nodes -keyout vs-admin-tls.key \
  -subj "/CN=vs-admin" -out vs-admin-tls.csr 2> /dev/null
openssl x509 -req -in vs-admin-tls.csr -CA "$PREGEN/ca-cert.pem" \
  -CAkey "$PREGEN/ca-key.pem" -CAserial pregen-ca.srl -CAcreateserial \
  -days 1 -out vs-admin-tls.crt \
  -extfile <(printf "subjectAltName=IP:%s" "$VS_ZPR_ADDR") 2> /dev/null

# The vs config. Not emit_vs_config: admin_cert is the runtime-minted
# IP-SAN cert (see above), and ts_secrets_dir points the zipline token
# read at this directory (it defaults to the config dir; explicit is
# better than implicit here).
cat > vs-config.toml <<EOF
[core]
admin_cert = "$PWD/vs-admin-tls.crt"
admin_key = "$PWD/vs-admin-tls.key"
vk_uri = "redis://127.0.0.1:6379"
ts_secrets_dir = "."
EOF

# Admin API keys: mint two directly in the format vsapikey uses
# (vs/src/apikey.rs: zpr_vsapi.<id_hex>.<b64url_secret>; vs_keys.toml
# stores the sha256 of the secret). vs-admin.key is the readwrite key the
# assertions use; notify.key is a Permission::Notify key BOUND to the
# zipline service id (zipline#79) — the least-privilege key the attribute
# server posts change notifications with.
python3 - <<'PYEOF'
import base64, hashlib, secrets

def mint(permission, description, service=None):
    key_id = secrets.token_bytes(4).hex()
    secret = secrets.token_bytes(32)
    b64 = base64.urlsafe_b64encode(secret).rstrip(b"=").decode()
    lines = [
        f'[keys.{key_id}]',
        'owner = "integration-test"',
        f'permission = "{permission}"',
        'status = "active"',
        'created = "2026-09-22"',
        f'secret_hash = "{hashlib.sha256(secret).hexdigest()}"',
        f'description = "{description}"',
    ]
    if service is not None:
        lines.append(f'service = "{service}"')
    return "\n".join(lines) + "\n", f"zpr_vsapi.{key_id}.{b64}\n"

rw_toml, rw_key = mint("readwrite", "attr-query-test admin")
notify_toml, notify_key = mint("notify", "attr-query-test notify", service="zipline")
with open("vs_keys.toml", "w") as f:
    f.write(rw_toml + "\n" + notify_toml)
with open("vs-admin.key", "w") as f:
    f.write(rw_key)
with open("notify.key", "w") as f:
    f.write(notify_key)
PYEOF
chmod 600 vs-admin.key notify.key

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
# Launch the attribute server (before the vs: the policy install reads the
# zipline token and runs the advisory schema check against a live server).
#

echo "Launching zpr-attr-server (data v1: dept + contractor)"

launch_attr_server attr-data-v1.json
wait_for 15 check_attr_server

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

# adapter1: user-only (no bootstrap key) — the interplay's subject. No
# --zpr-addr: it accepts the dynamic fd5a:5052:adda:1::/64 address the
# fabric assigns (zipline#88); a static demand would be scrubbed by the
# visa service (no join policy) and the adapter would exit on the
# mismatch (zipline#83).
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
  --node-addr "$NODE_SUBSTRATE_ADDR_A" 2>&1 | tee adapter1.log | prefix_log zpr-a &

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
# Leg 1: login, decoration and connect-path assertions
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
echo "Checking the contractor visa (adapter1 -> Web connectivity)"
if ! connectivity_test
then PASS=1
fi
fi

#
# Leg 2: untargeted notify with UNCHANGED data — reconcile must converge
# with no spurious revocation. Runs before the data edit on purpose (see
# header). Skipped under SKIP_NOTIFY so the negative run posts no
# notifications at all.
#

if [[ "$PASS" == 0 ]] then
if [[ "$SKIP_NOTIFY" == 1 ]] then
echo "SKIP_NOTIFY=1: skipping the untargeted-notify leg"
else
echo "Untargeted notify (empty body: everything changed, data unchanged)"
attr_notify || PASS=1
if [[ "$PASS" == 0 ]] then
sleep 5
assert_user_actor "after untargeted notify" || PASS=1
fi
if [[ "$PASS" == 0 ]] then
if ! connectivity_test
then
  echo "ASSERTION FAILED (after untargeted notify): connectivity lost"
  PASS=1
fi
fi
fi
fi

#
# Leg 3: revocation. Drop `contractor` from the data (server restart — the
# reference server loads its data once at startup), post the TARGETED
# notify with the service-bound notify key, and poll for the visa to go.
# Under SKIP_NOTIFY=1 the notify is skipped and this poll MUST time out —
# quote that failure as the negative evidence (leg 4 of the plan).
#

if [[ "$PASS" == 0 ]] then
echo "Restarting zpr-attr-server on data v2 (contractor dropped)"
stop_attr_server
launch_attr_server attr-data-v2.json
wait_for 15 check_attr_server || PASS=1
fi

if [[ "$PASS" == 0 ]] then
if [[ "$SKIP_NOTIFY" == 1 ]] then
echo "SKIP_NOTIFY=1: NOT posting the targeted notify — the revocation poll"
echo "below must now FAIL inside ${REVOKE_POLL_SECS}s (well under the 90s TTL),"
echo "proving revocation rides on the queued change event, not TTL expiry."
else
echo "Targeted notify: user.sub=user-a changed"
attr_notify user.sub=user-a || PASS=1
fi
fi

if [[ "$PASS" == 0 ]] then
echo "Polling for the contractor tag to leave the actor (${REVOKE_POLL_SECS}s)"
REVOKED=""
for _ in $(seq 1 "$REVOKE_POLL_SECS"); do
  if contractor_tag_gone; then REVOKED=yes; break; fi
  sleep 1
done
if [ -z "$REVOKED" ]; then
  echo "ASSERTION FAILED (revocation): user.zpr.tag.contractor still on the"
  echo "actor after ${REVOKE_POLL_SECS}s — no revocation happened"
  PASS=1
else
  echo "contractor tag gone (revocation)"
fi
fi

if [[ "$PASS" == 0 ]] then
echo "Checking a fresh connect is denied"
connectivity_denied_test || PASS=1
fi

#
# Cleanup
#

# SIGTERM for the same reason as stop_attr_server (fake-idp is Python, which
# also leaves an inherited SIGINT-ignore in place).
sudo pkill -SIGTERM -f "fake-idp.py --port" || true
sudo pkill -SIGTERM -f "zpr-attr-server --listen" || true

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
