#!/usr/bin/env bash
# Smoke test for the fake OIDC identity provider (zipline#16, plan D5 step 1).
#
# Starts lib/fake-idp.py over TLS (cert signed by the pregen test CA), then
# curls all four endpoints and asserts on their content:
#   1. the discovery document carries the four endpoint URLs,
#   2. /auth 302-redirects with the caller's `state` and a fresh `code`,
#   3. /token returns a three-part RS256 JWT whose header `kid` matches the
#      current /jwks key and whose claims echo the /auth `nonce`,
#   4. after --rotate, /jwks serves the second `kid` and newly minted tokens
#      are signed with it.
#
# Needs no root and no network namespaces: everything binds 127.0.0.1.
set -euo pipefail

SCRIPT_DIR=$(realpath "$(dirname "$0")")
FAKE_IDP="$SCRIPT_DIR/lib/fake-idp.py"
PREGEN="$SCRIPT_DIR/pregen"
PORT="${FAKE_IDP_PORT:-9443}"
ISSUER="https://127.0.0.1:$PORT"

if [ ! -e "$FAKE_IDP" ]; then
  echo "FAILURE: fake IdP not found: $FAKE_IDP"
  exit 1
fi

TMPDIR=$(mktemp -d)
IDP_PID=""

cleanup() {
  if [ -n "$IDP_PID" ]; then kill "$IDP_PID" 2> /dev/null || true; fi
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

cd "$TMPDIR"

# Test CA: the same pregen pair the integration tests use (see
# lib/common_funcs.sh create_ca_key_and_cert).
cp "$PREGEN/ca-key.pem" ca.key
cp "$PREGEN/ca-cert.pem" ca.crt

# TLS server certificate for 127.0.0.1, signed by the test CA.
openssl req -new -newkey rsa:2048 -nodes -keyout idp.key \
  -subj "/CN=127.0.0.1" -out idp.csr 2> /dev/null
openssl x509 -req -in idp.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 1 -out idp.crt \
  -extfile <(printf "subjectAltName=IP:127.0.0.1") 2> /dev/null

CURL=(curl --silent --show-error --cacert ca.crt)

echo "Starting fake IdP on $ISSUER"
python3 "$FAKE_IDP" \
  --port "$PORT" \
  --state-dir "$TMPDIR" \
  --tls-cert idp.crt --tls-key idp.key \
  --signing-key "$PREGEN/fake-idp-rsa.key" \
  --signing-key-2 "$PREGEN/fake-idp-rsa-2.key" \
  --client-id zpr-test-client \
  --sub smoke-user --email smoke-user@example.com --hd example.com \
  > idp.log 2>&1 &
IDP_PID=$!

# Wait for the listener.
for _ in $(seq 1 30); do
  if "${CURL[@]}" --output /dev/null "$ISSUER/.well-known/openid-configuration" 2> /dev/null
  then break
  fi
  if ! kill -0 "$IDP_PID" 2> /dev/null; then
    echo "FAILURE: fake IdP exited early:"
    cat idp.log
    exit 1
  fi
  sleep 0.5
done

PASS=0
fail() { echo "FAILURE: $*"; PASS=1; }

#
# 1. Discovery document
#
DISCO=$("${CURL[@]}" "$ISSUER/.well-known/openid-configuration")
echo "discovery: $DISCO"
for KEY in issuer authorization_endpoint token_endpoint jwks_uri; do
  jq -e --arg k "$KEY" 'has($k)' > /dev/null <<< "$DISCO" \
    || fail "discovery document missing $KEY"
done
test "$(jq -r .issuer <<< "$DISCO")" = "$ISSUER" \
  || fail "discovery issuer is not $ISSUER"

AUTH_EP=$(jq -r .authorization_endpoint <<< "$DISCO")
TOKEN_EP=$(jq -r .token_endpoint <<< "$DISCO")
JWKS_EP=$(jq -r .jwks_uri <<< "$DISCO")

#
# 2. /auth: 302 back to redirect_uri with code + the same state
#
STATE="smoke-state-$$"
NONCE="smoke-nonce-$$"
REDIRECT="http://127.0.0.1:19999/callback"
LOCATION=$("${CURL[@]}" --output /dev/null --write-out '%{redirect_url}' \
  "$AUTH_EP?response_type=code&client_id=zpr-test-client&redirect_uri=$REDIRECT&scope=openid&state=$STATE&nonce=$NONCE&code_challenge=x&code_challenge_method=S256")
echo "auth redirect: $LOCATION"
case "$LOCATION" in
  "$REDIRECT"*) : ;;
  *) fail "/auth did not redirect to the redirect_uri: $LOCATION" ;;
esac
grep -q "state=$STATE" <<< "$LOCATION" || fail "/auth redirect lost the state"
CODE=$(sed -n 's/.*[?&]code=\([^&]*\).*/\1/p' <<< "$LOCATION")
test -n "$CODE" || fail "/auth redirect carries no code"

#
# 3. /token: three-part JWT, header kid matches /jwks, nonce echoed
#
TOKEN_RESP=$("${CURL[@]}" --data \
  "grant_type=authorization_code&code=$CODE&redirect_uri=$REDIRECT&client_id=zpr-test-client&code_verifier=x" \
  "$TOKEN_EP")
ID_TOKEN=$(jq -r .id_token <<< "$TOKEN_RESP")
test "$(awk -F. '{print NF}' <<< "$ID_TOKEN")" = 3 \
  || fail "id_token is not a three-part JWT: $TOKEN_RESP"

# base64url decode helper (jq handles the un-padded alphabet via @base64d
# only with padding, so pad manually).
b64d() {
  local S=${1//-/+}; S=${S//_/\/}
  case $(( ${#S} % 4 )) in 2) S="$S==";; 3) S="$S=";; esac
  base64 -d <<< "$S"
}

HEADER=$(b64d "$(cut -d. -f1 <<< "$ID_TOKEN")")
CLAIMS=$(b64d "$(cut -d. -f2 <<< "$ID_TOKEN")")
echo "jwt header: $HEADER"
echo "jwt claims: $CLAIMS"
test "$(jq -r .alg <<< "$HEADER")" = "RS256" || fail "id_token alg is not RS256"
KID=$(jq -r .kid <<< "$HEADER")

JWKS=$("${CURL[@]}" "$JWKS_EP")
jq -e --arg kid "$KID" '.keys[] | select(.kid == $kid)' > /dev/null <<< "$JWKS" \
  || fail "/jwks does not serve the token's kid $KID"

test "$(jq -r .nonce <<< "$CLAIMS")" = "$NONCE" || fail "nonce was not echoed"
test "$(jq -r .iss <<< "$CLAIMS")" = "$ISSUER" || fail "iss mismatch"
test "$(jq -r .aud <<< "$CLAIMS")" = "zpr-test-client" || fail "aud mismatch"
test "$(jq -r .hd <<< "$CLAIMS")" = "example.com" || fail "hd mismatch"

# A code is single use.
SECOND=$("${CURL[@]}" --output /dev/null --write-out '%{http_code}' --data \
  "grant_type=authorization_code&code=$CODE&redirect_uri=$REDIRECT&client_id=zpr-test-client&code_verifier=x" \
  "$TOKEN_EP")
test "$SECOND" = "400" || fail "reused code was not rejected (HTTP $SECOND)"

#
# 4. --rotate: /jwks switches kid; new tokens are signed with the new key
#
python3 "$FAKE_IDP" --state-dir "$TMPDIR" --rotate

JWKS2=$("${CURL[@]}" "$JWKS_EP")
KID2=$(jq -r '.keys[0].kid' <<< "$JWKS2")
echo "rotated kid: $KID -> $KID2"
test "$KID2" != "$KID" || fail "/jwks kid did not change after --rotate"

LOCATION=$("${CURL[@]}" --output /dev/null --write-out '%{redirect_url}' \
  "$AUTH_EP?response_type=code&client_id=zpr-test-client&redirect_uri=$REDIRECT&scope=openid&state=$STATE&nonce=$NONCE")
CODE=$(sed -n 's/.*[?&]code=\([^&]*\).*/\1/p' <<< "$LOCATION")
TOKEN_RESP=$("${CURL[@]}" --data \
  "grant_type=authorization_code&code=$CODE&redirect_uri=$REDIRECT&client_id=zpr-test-client&code_verifier=x" \
  "$TOKEN_EP")
ID_TOKEN=$(jq -r .id_token <<< "$TOKEN_RESP")
HEADER=$(b64d "$(cut -d. -f1 <<< "$ID_TOKEN")")
test "$(jq -r .kid <<< "$HEADER")" = "$KID2" \
  || fail "post-rotation token is not signed with the new kid"

echo
if [[ "$PASS" == 0 ]]
then echo "SUCCESS"
else echo "FAILURE"
fi
exit "$PASS"
