#!/usr/bin/env python3
"""Fake OIDC identity provider for the ZPR integration tests (zipline#16, D5).

A minimal OpenID Provider serving the four endpoints the ZPR OIDC flow
touches, so the whole relying-party path (ph-cli `connect --no-browser`,
visa-service JWKS fetch and token validation) runs with no Google and no
browser:

  GET  /.well-known/openid-configuration  discovery document
  GET  /auth                              302 to redirect_uri with code+state
                                          (no UI; nonce, client_id,
                                          redirect_uri and the PKCE challenge
                                          are remembered, keyed by the code)
  POST /token                             JSON with an RS256 id_token minted
                                          from a checked-in test key, echoing
                                          the nonce stored for the code —
                                          after checking that client_id and
                                          redirect_uri match what /auth saw
                                          and that the S256 hash of
                                          code_verifier matches the stored
                                          code_challenge, so a relying-party
                                          regression in any of those is
                                          rejected here just as Google would
  GET  /jwks                              JWKS for the currently active key,
                                          with a kid

Deliberately standard-library only. RS256 signatures are produced by
shelling out to `openssl dgst -sha256 -sign` (RSASSA-PKCS1-v1_5 with
SHA-256, exactly the JWS RS256 primitive); the openssl CLI is already an
integration-test prerequisite (docs/BUILD.md).

Serves TLS only: the compiler's `issuer` rule is https-absolute, so the
test issuer is `https://127.0.0.1:<port>` with a certificate signed by the
test CA, which clients trust via SSL_CERT_FILE / curl --cacert.

Key rotation: the server is started with two signing keys. Which one is
active lives in `<state-dir>/active-key` and is re-read on every request,
so a second invocation with `--rotate` (same --state-dir) switches the
serving process to the other key with no signal plumbing:

    fake-idp.py --state-dir "$DIR" --rotate

`--print-jwks` prints the JWKS for both keys and exits — the pregen
Makefile uses it to build the seed JWKS fixture from the same code that
serves /jwks, so the two cannot drift.
"""

import argparse
import base64
import hashlib
import json
import re
import secrets
import ssl
import subprocess
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


def b64url(data: bytes) -> str:
    """Base64url-encode without padding (RFC 7515 terminology)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def rsa_public_numbers(key_path: Path) -> tuple[bytes, bytes]:
    """Extract (modulus, exponent) big-endian bytes from an RSA private key
    by parsing `openssl rsa -noout -text` output (stdlib-only constraint)."""
    text = subprocess.run(
        ["openssl", "rsa", "-in", str(key_path), "-noout", "-text"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    mod_match = re.search(r"modulus:\n((?:\s+[0-9a-f:]+\n)+)", text)
    exp_match = re.search(r"publicExponent:\s*(\d+)", text)
    if not mod_match or not exp_match:
        raise ValueError(f"cannot parse RSA public numbers from {key_path}")
    mod_hex = re.sub(r"[\s:]", "", mod_match.group(1))
    modulus = bytes.fromhex(mod_hex).lstrip(b"\x00")
    exponent = int(exp_match.group(1))
    exp_bytes = exponent.to_bytes((exponent.bit_length() + 7) // 8, "big")
    return modulus, exp_bytes


class SigningKey:
    """One RSA signing key: its file, derived kid, and JWK."""

    def __init__(self, key_path: Path):
        self.path = key_path
        modulus, exponent = rsa_public_numbers(key_path)
        # Deterministic kid from the public key, so the seed JWKS fixture
        # (built via --print-jwks) always matches what the server serves.
        self.kid = "fake-idp-" + hashlib.sha256(modulus).hexdigest()[:16]
        self.jwk = {
            "kty": "RSA",
            "kid": self.kid,
            "use": "sig",
            "alg": "RS256",
            "n": b64url(modulus),
            "e": b64url(exponent),
        }

    def sign_rs256(self, signing_input: bytes) -> bytes:
        """RSASSA-PKCS1-v1_5 / SHA-256 over `signing_input` via the openssl
        CLI (`dgst -sha256 -sign` is exactly the JWS RS256 primitive)."""
        return subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(self.path)],
            input=signing_input,
            check=True,
            capture_output=True,
        ).stdout


class IdpState:
    """Server-wide state: the two keys, issued codes, and the rotation file."""

    def __init__(self, args):
        self.issuer = f"https://127.0.0.1:{args.port}"
        self.keys = [SigningKey(Path(args.signing_key))]
        if args.signing_key_2:
            self.keys.append(SigningKey(Path(args.signing_key_2)))
        self.client_id = args.client_id
        self.sub = args.sub
        self.email = args.email
        self.hd = args.hd
        self.state_dir = Path(args.state_dir)
        # code -> the authorization request's bindings (nonce, client_id,
        # redirect_uri, PKCE challenge), remembered by /auth so /token can
        # reject an exchange that does not match them. Codes are single use.
        self.codes: dict[str, dict] = {}

    def active_key(self) -> SigningKey:
        """The currently active signing key, re-read from the rotation file
        on every call so an external --rotate takes effect immediately."""
        index = read_active_index(self.state_dir)
        return self.keys[min(index, len(self.keys) - 1)]

    def mint_id_token(self, nonce: str) -> str:
        """Mint an RS256 id_token with the active key, echoing `nonce`."""
        key = self.active_key()
        now = int(time.time())
        header = {"alg": "RS256", "typ": "JWT", "kid": key.kid}
        claims = {
            "iss": self.issuer,
            "aud": self.client_id,
            "sub": self.sub,
            "email": self.email,
            "email_verified": True,
            "hd": self.hd,
            "nonce": nonce,
            "iat": now,
            "auth_time": now,
            "exp": now + 3600,
        }
        signing_input = (
            b64url(json.dumps(header).encode()) + "." + b64url(json.dumps(claims).encode())
        ).encode("ascii")
        signature = key.sign_rs256(signing_input)
        return signing_input.decode("ascii") + "." + b64url(signature)


ACTIVE_KEY_FILE = "active-key"


def read_active_index(state_dir: Path) -> int:
    """Read the active key index (0-based) from the rotation file; 0 if unset."""
    try:
        return int((state_dir / ACTIVE_KEY_FILE).read_text().strip())
    except (FileNotFoundError, ValueError):
        return 0


def rotate(state_dir: Path) -> None:
    """Toggle the active key index between 0 and 1 (the --rotate action)."""
    current = read_active_index(state_dir)
    new = 1 - current
    (state_dir / ACTIVE_KEY_FILE).write_text(str(new))
    print(f"rotated active key: {current} -> {new}")


class IdpHandler(BaseHTTPRequestHandler):
    """The four OIDC endpoints. `server.idp` carries the IdpState."""

    # Quieter default request logging (one line per request to stderr).
    def log_message(self, fmt, *log_args):
        sys.stderr.write("fake-idp: " + fmt % log_args + "\n")

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # Never cache: rotation must be observed immediately.
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 (http.server API)
        idp: IdpState = self.server.idp
        url = urllib.parse.urlparse(self.path)
        if url.path == "/.well-known/openid-configuration":
            self._json(
                200,
                {
                    "issuer": idp.issuer,
                    "authorization_endpoint": f"{idp.issuer}/auth",
                    "token_endpoint": f"{idp.issuer}/token",
                    "jwks_uri": f"{idp.issuer}/jwks",
                    "response_types_supported": ["code"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                    "code_challenge_methods_supported": ["S256"],
                },
            )
        elif url.path == "/auth":
            query = urllib.parse.parse_qs(url.query)
            state = query.get("state", [None])[0]
            nonce = query.get("nonce", [""])[0]
            client_id = query.get("client_id", [None])[0]
            redirect_uri = query.get("redirect_uri", [None])[0]
            code_challenge = query.get("code_challenge", [None])[0]
            code_challenge_method = query.get("code_challenge_method", [None])[0]
            if not state or not redirect_uri or not client_id:
                self._json(400, {"error": "invalid_request"})
                return
            # Only S256 is advertised in discovery; reject anything else so a
            # client silently downgrading PKCE fails loudly here.
            if code_challenge and code_challenge_method != "S256":
                self._json(400, {"error": "invalid_request"})
                return
            # No UI: authorize immediately. Remember the request's bindings
            # so /token can check the exchange against them.
            code = secrets.token_urlsafe(24)
            idp.codes[code] = {
                "nonce": nonce,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_challenge": code_challenge,
            }
            sep = "&" if "?" in redirect_uri else "?"
            location = (
                f"{redirect_uri}{sep}code={urllib.parse.quote(code)}"
                f"&state={urllib.parse.quote(state)}"
            )
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif url.path == "/jwks":
            self._json(200, {"keys": [idp.active_key().jwk]})
        else:
            self._json(404, {"error": "not_found"})

    def do_POST(self):  # noqa: N802 (http.server API)
        idp: IdpState = self.server.idp
        url = urllib.parse.urlparse(self.path)
        if url.path != "/token":
            self._json(404, {"error": "not_found"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())
        code = form.get("code", [None])[0]
        if form.get("grant_type", [None])[0] != "authorization_code" or code is None:
            self._json(400, {"error": "invalid_request"})
            return
        # Codes are single use: pop, so a replay is rejected.
        try:
            granted = idp.codes.pop(code)
        except KeyError:
            self._json(400, {"error": "invalid_grant"})
            return
        # The exchange must match the authorization request's bindings
        # (RFC 6749 §4.1.3): same client_id, same redirect_uri. A ph-cli
        # regression sending the wrong values fails here, as Google would
        # fail it.
        if form.get("client_id", [None])[0] != granted["client_id"]:
            self._json(400, {"error": "invalid_client"})
            return
        if form.get("redirect_uri", [None])[0] != granted["redirect_uri"]:
            self._json(400, {"error": "invalid_grant"})
            return
        # PKCE (RFC 7636 §4.6): when the authorization request carried a
        # code_challenge, the token request's code_verifier must S256-hash
        # to it.
        if granted["code_challenge"] is not None:
            verifier = form.get("code_verifier", [None])[0]
            if verifier is None:
                self._json(400, {"error": "invalid_grant"})
                return
            digest = hashlib.sha256(verifier.encode("utf-8")).digest()
            if b64url(digest) != granted["code_challenge"]:
                self._json(400, {"error": "invalid_grant"})
                return
        self._json(
            200,
            {
                "id_token": idp.mint_id_token(granted["nonce"]),
                "token_type": "Bearer",
                "expires_in": 3600,
            },
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=9000, help="listen port (default 9000)")
    parser.add_argument(
        "--state-dir",
        required=True,
        help="directory for the rotation state file (shared with --rotate)",
    )
    parser.add_argument("--tls-cert", help="TLS server certificate (PEM)")
    parser.add_argument("--tls-key", help="TLS server private key (PEM)")
    parser.add_argument("--signing-key", help="RSA private key for id_token signing (PEM)")
    parser.add_argument(
        "--signing-key-2",
        help="second RSA signing key, activated by --rotate",
    )
    parser.add_argument("--client-id", default="zpr-test-client", help="expected aud")
    parser.add_argument("--sub", default="fake-idp-user-1", help="sub claim")
    parser.add_argument("--email", default="user1@example.com", help="email claim")
    parser.add_argument("--hd", default="example.com", help="hd (hosted domain) claim")
    parser.add_argument(
        "--rotate",
        action="store_true",
        help="toggle the active signing key of a server sharing --state-dir, then exit",
    )
    parser.add_argument(
        "--print-jwks",
        action="store_true",
        help="print the JWKS for all provided signing keys and exit (seed fixture)",
    )
    args = parser.parse_args()

    if args.rotate:
        rotate(Path(args.state_dir))
        return 0

    if not args.signing_key:
        parser.error("--signing-key is required to serve")
    idp = IdpState(args)

    if args.print_jwks:
        print(json.dumps({"keys": [k.jwk for k in idp.keys]}, indent=2))
        return 0

    if not args.tls_cert or not args.tls_key:
        parser.error("--tls-cert and --tls-key are required to serve (issuer is https-only)")

    server = HTTPServer(("127.0.0.1", args.port), IdpHandler)
    server.idp = idp
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=args.tls_cert, keyfile=args.tls_key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    sys.stderr.write(f"fake-idp: serving {idp.issuer} (kid {idp.active_key().kid})\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
