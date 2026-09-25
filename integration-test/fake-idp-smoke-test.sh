#!/usr/bin/env bash
# Smoke test for the fake OIDC identity provider (zipline#16, plan D5 step 1).
#
# Starts lib/fake-idp.py over TLS (cert signed by the pregen test CA), then
# curls all four endpoints and asserts on their content:
#   1. the discovery document carries the four endpoint URLs,
#   2. /auth 302-redirects with the caller's `state` and a fresh `code`,
#   3. /token returns a three-part RS256 JWT whose header `kid` matches the
#      current /jwks key and whose claims echo the /auth `nonce` — using a
#      genuine PKCE S256 challenge/verifier pair,
#   4. /token rejects a wrong client_id, a wrong redirect_uri, and a
#      code_verifier that does not hash to the stored code_challenge
#      (the code bindings a ph-cli regression would get wrong),
#   5. the offline_access / refresh-grant path (zipline#47): the code
#      exchange hands back a refresh_token only when `offline_access` was
#      requested, the refresh grant mints a fresh id_token with a strictly
#      greater `iat`, an UNCHANGED `auth_time` and NO `nonce` claim, and
#      --revoke-refresh turns every later grant into `invalid_grant`,
#   6. after --rotate, /jwks serves the second `kid` and newly minted tokens
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

# Genuine PKCE S256 pair (RFC 7636): challenge = b64url(sha256(verifier)),
# exactly what ph-cli computes. /token must verify this binding.
VERIFIER="smoke-verifier-$$-0123456789abcdefghijklmnopqrstuv"
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary \
  | base64 | tr '+/' '-_' | tr -d '=')

LOCATION=$("${CURL[@]}" --output /dev/null --write-out '%{redirect_url}' \
  "$AUTH_EP?response_type=code&client_id=zpr-test-client&redirect_uri=$REDIRECT&scope=openid&state=$STATE&nonce=$NONCE&code_challenge=$CHALLENGE&code_challenge_method=S256")
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
  "grant_type=authorization_code&code=$CODE&redirect_uri=$REDIRECT&client_id=zpr-test-client&code_verifier=$VERIFIER" \
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

# No `offline_access` in the request, so no refresh token in the response:
# offline access is a policy decision (`allow_offline_access`), not a default.
test "$(jq -r .refresh_token <<< "$TOKEN_RESP")" = "null" \
  || fail "an exchange without offline_access returned a refresh_token"

# A code is single use.
SECOND=$("${CURL[@]}" --output /dev/null --write-out '%{http_code}' --data \
  "grant_type=authorization_code&code=$CODE&redirect_uri=$REDIRECT&client_id=zpr-test-client&code_verifier=$VERIFIER" \
  "$TOKEN_EP")
test "$SECOND" = "400" || fail "reused code was not rejected (HTTP $SECOND)"

#
# 4. /token rejects an exchange that does not match the code's bindings.
# Each case gets its own fresh code (codes are single use, even on failure).
#

# Fetch a fresh authorization code bound to $CHALLENGE.
new_code() {
  local LOC
  LOC=$("${CURL[@]}" --output /dev/null --write-out '%{redirect_url}' \
    "$AUTH_EP?response_type=code&client_id=zpr-test-client&redirect_uri=$REDIRECT&scope=openid&state=$STATE&nonce=$NONCE&code_challenge=$CHALLENGE&code_challenge_method=S256")
  sed -n 's/.*[?&]code=\([^&]*\).*/\1/p' <<< "$LOC"
}

# POST to /token, print the HTTP status. $1 = form body.
token_status() {
  "${CURL[@]}" --output /dev/null --write-out '%{http_code}' \
    --data "$1" "$TOKEN_EP"
}

C=$(new_code)
RC=$(token_status "grant_type=authorization_code&code=$C&redirect_uri=$REDIRECT&client_id=wrong-client&code_verifier=$VERIFIER")
test "$RC" = "400" || fail "wrong client_id was not rejected (HTTP $RC)"

C=$(new_code)
RC=$(token_status "grant_type=authorization_code&code=$C&redirect_uri=http://127.0.0.1:19999/other&client_id=zpr-test-client&code_verifier=$VERIFIER")
test "$RC" = "400" || fail "wrong redirect_uri was not rejected (HTTP $RC)"

C=$(new_code)
RC=$(token_status "grant_type=authorization_code&code=$C&redirect_uri=$REDIRECT&client_id=zpr-test-client&code_verifier=not-the-verifier")
test "$RC" = "400" || fail "wrong code_verifier was not rejected (HTTP $RC)"

C=$(new_code)
RC=$(token_status "grant_type=authorization_code&code=$C&redirect_uri=$REDIRECT&client_id=zpr-test-client")
test "$RC" = "400" || fail "missing code_verifier was not rejected (HTTP $RC)"

# /auth advertises S256 only: a plain-method challenge must be refused.
RC=$("${CURL[@]}" --output /dev/null --write-out '%{http_code}' \
  "$AUTH_EP?response_type=code&client_id=zpr-test-client&redirect_uri=$REDIRECT&scope=openid&state=$STATE&nonce=$NONCE&code_challenge=$CHALLENGE&code_challenge_method=plain")
test "$RC" = "400" || fail "/auth accepted a non-S256 code_challenge_method (HTTP $RC)"

#
# 5. offline_access and the refresh grant (zipline#47)
#
# The properties the visa service's reauthorize path binds to, per
# zl-zpr-dev-context/docs/OIDC.md ("Credential lifetimes and
# re-authentication"): same sub, strictly
# increasing iat, unchanged auth_time.
#
# The renewed token carries NO nonce claim. OIDC Core 12.2 says a refreshed
# id_token SHOULD NOT have one, and MUST match the original only if it is
# present -- absent or original, never fresh, which is why the reauth path
# cannot check a nonce against a fresh challenge at all. Omitting is the
# spec-preferred branch and what Google does, so it is what the harness
# serves and what this asserts.
#

OFF_NONCE="offline-nonce-$$"

# Authorization request carrying `offline_access`, as ph-cli sends when the
# trusted service declares allow_offline_access.
LOCATION=$("${CURL[@]}" --output /dev/null --write-out '%{redirect_url}' \
  "$AUTH_EP?response_type=code&client_id=zpr-test-client&redirect_uri=$REDIRECT&scope=openid+offline_access&state=$STATE&nonce=$OFF_NONCE&code_challenge=$CHALLENGE&code_challenge_method=S256&access_type=offline&prompt=consent")
CODE=$(sed -n 's/.*[?&]code=\([^&]*\).*/\1/p' <<< "$LOCATION")
test -n "$CODE" || fail "/auth issued no code for the offline_access request"

TOKEN_RESP=$("${CURL[@]}" --data \
  "grant_type=authorization_code&code=$CODE&redirect_uri=$REDIRECT&client_id=zpr-test-client&code_verifier=$VERIFIER" \
  "$TOKEN_EP")
REFRESH=$(jq -r .refresh_token <<< "$TOKEN_RESP")
test -n "$REFRESH" -a "$REFRESH" != "null" \
  || fail "offline_access exchange returned no refresh_token: $TOKEN_RESP"

CLAIMS=$(b64d "$(cut -d. -f2 <<< "$(jq -r .id_token <<< "$TOKEN_RESP")")")
IAT1=$(jq -r .iat <<< "$CLAIMS")
AUTH_TIME1=$(jq -r .auth_time <<< "$CLAIMS")
echo "offline login: iat=$IAT1 auth_time=$AUTH_TIME1"

# POST a refresh grant, print the raw response. $1 = refresh token.
refresh_grant() {
  "${CURL[@]}" --data \
    "grant_type=refresh_token&refresh_token=$1&client_id=zpr-test-client" \
    "$TOKEN_EP"
}

# Let the wall clock move so this first renewal is the ordinary case; the
# same-second case is covered immediately below.
sleep 1
REFRESH_RESP=$(refresh_grant "$REFRESH")
ID_TOKEN=$(jq -r .id_token <<< "$REFRESH_RESP")
test "$(awk -F. '{print NF}' <<< "$ID_TOKEN")" = 3 \
  || fail "refresh grant returned no id_token: $REFRESH_RESP"
CLAIMS=$(b64d "$(cut -d. -f2 <<< "$ID_TOKEN")")
echo "renewed claims: $CLAIMS"
IAT2=$(jq -r .iat <<< "$CLAIMS")
test "$(jq -r .auth_time <<< "$CLAIMS")" = "$AUTH_TIME1" \
  || fail "refresh grant moved auth_time (the session ceiling would never bind)"
test "$IAT2" -gt "$IAT1" \
  || fail "refresh grant did not advance iat ($IAT1 -> $IAT2)"
test "$(jq -r 'has("nonce")' <<< "$CLAIMS")" = "false" \
  || fail "refresh grant carried a nonce claim (OIDC Core 12.2 says SHOULD NOT): $CLAIMS"
test "$(jq -r .sub <<< "$CLAIMS")" = "smoke-user" || fail "refresh grant changed sub"

# Two renewals inside one wall-clock second must still strictly advance iat:
# the visa service rejects a reauthorization whose iat did not move, and a
# 120s renewal cadence makes same-second renewals reachable in the e2e.
REFRESH_RESP=$(refresh_grant "$REFRESH")
CLAIMS=$(b64d "$(cut -d. -f2 <<< "$(jq -r .id_token <<< "$REFRESH_RESP")")")
IAT3=$(jq -r .iat <<< "$CLAIMS")
test "$IAT3" -gt "$IAT2" \
  || fail "back-to-back refresh grants did not advance iat ($IAT2 -> $IAT3)"

# An unknown refresh token is invalid_grant, not a 500 and not a token.
RC=$(token_status "grant_type=refresh_token&refresh_token=not-a-real-token&client_id=zpr-test-client")
test "$RC" = "400" || fail "unknown refresh token was not rejected (HTTP $RC)"

# --revoke-refresh models the user withdrawing the app's access: every later
# grant is invalid_grant, which is what makes ph-cli drop its stored token.
python3 "$FAKE_IDP" --state-dir "$TMPDIR" --revoke-refresh
REFRESH_RESP=$("${CURL[@]}" --write-out '\n%{http_code}' --data \
  "grant_type=refresh_token&refresh_token=$REFRESH&client_id=zpr-test-client" \
  "$TOKEN_EP")
test "$(tail -n 1 <<< "$REFRESH_RESP")" = "400" \
  || fail "refresh grant was accepted after --revoke-refresh"
test "$(jq -r .error <<< "$(head -n 1 <<< "$REFRESH_RESP")")" = "invalid_grant" \
  || fail "revoked refresh grant did not answer invalid_grant: $REFRESH_RESP"

#
# 6. --rotate: /jwks switches kid; new tokens are signed with the new key
#
python3 "$FAKE_IDP" --state-dir "$TMPDIR" --rotate

JWKS2=$("${CURL[@]}" "$JWKS_EP")
KID2=$(jq -r '.keys[0].kid' <<< "$JWKS2")
echo "rotated kid: $KID -> $KID2"
test "$KID2" != "$KID" || fail "/jwks kid did not change after --rotate"

LOCATION=$("${CURL[@]}" --output /dev/null --write-out '%{redirect_url}' \
  "$AUTH_EP?response_type=code&client_id=zpr-test-client&redirect_uri=$REDIRECT&scope=openid&state=$STATE&nonce=$NONCE&code_challenge=$CHALLENGE&code_challenge_method=S256")
CODE=$(sed -n 's/.*[?&]code=\([^&]*\).*/\1/p' <<< "$LOCATION")
TOKEN_RESP=$("${CURL[@]}" --data \
  "grant_type=authorization_code&code=$CODE&redirect_uri=$REDIRECT&client_id=zpr-test-client&code_verifier=$VERIFIER" \
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
