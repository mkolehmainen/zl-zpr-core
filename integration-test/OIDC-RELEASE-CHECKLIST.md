# Manual OIDC release checklist — real Google (zipline#16, plan D5)

CI (the fake-IdP `one-node-oidc-test.sh`) cannot cover real Google. Before an
OIDC release is called done, run this checklist once against a real Google
Workspace and record the outcome on the umbrella issue
([mkolehmainen/zipline#1](https://github.com/mkolehmainen/zipline/issues/1)).
The `hd`-absent case in particular is the one a fake IdP is most likely to
model wrongly (docs/OIDC.md, "What CI cannot cover").

## Prerequisites

- [ ] A Google Cloud project with an OAuth 2.0 **Desktop app** client
      (loopback redirect; ph-cli binds `http://127.0.0.1:<port>/callback`).
- [ ] A real Google **Workspace** domain and a test account in it
      (`<user>@<workspace-domain>`).
- [ ] A **consumer** Gmail account (`...@gmail.com`) for the rejection case.
- [ ] A policy whose trusted service declares:
      `api = "oidc"`, `issuer = "https://accounts.google.com"`,
      `jwks_uri = "https://www.googleapis.com/oauth2/v3/certs"`,
      the Desktop client's `client_id`,
      `allowed_domains = ["<workspace-domain>"]`,
      `identity_attributes = ["sub"]`, and a seed JWKS snapshot of Google's
      current keys.
- [ ] A running ZPRnet (node, visa service with that policy, one adapter
      with **no** `--bootstrap-key` so authentication is forced through
      OIDC).

## 1. Workspace happy path

- [ ] `ph-cli connect <link>` opens a browser to a Google login.
- [ ] Log in as the Workspace test account; consent; the browser lands on
      the "you can close this window" page.
- [ ] `connect` exits 0 and the link reaches Active; ping across the TUN
      succeeds.
- [ ] The visa service log shows the user admitted with identity `sub` and
      `user.domain = <workspace-domain>` (from `hd`), and **no** log line
      anywhere contains the `id_token`, the authorization code, or the PKCE
      verifier.

## 2. Consumer gmail must be rejected — via `hd` absence

The security requirement (docs/OIDC.md "Security requirements"): match on
`hd`, never on the email domain. A consumer account's token simply has **no
`hd` claim**, and that absence must fail the domain check even if the
account's email address is made to look corporate.

- [ ] Repeat the login as the consumer Gmail account.
- [ ] `connect` fails (exit 5, visa service rejected the token) and the visa
      service reports the domain check failing with the `hd`-absent reason
      ("hd claim absent (consumer account?)").
- [ ] Confirm the rejection is `hd`-based, not email-based: the log must not
      reference the account's email domain in the decision.

## 3. `client_secret` — required for Google Desktop clients, or not?

Google's native-app documentation marks `client_secret` *optional* and
exempts only Android/iOS/Chrome clients, not Desktop (master plan, "What
changed since the spec"). The implementation carries an **optional,
non-secret** `client_secret` end to end; this run settles whether Google's
token endpoint actually demands it for a Desktop client.

- [ ] Run the happy path **without** `client_secret` in policy. Record:
      token exchange succeeded / failed with `invalid_client`.
- [ ] If it failed: add the Desktop client's `client_secret` to the trusted
      service, re-run, confirm success.
- [ ] **Record the outcome here and on zipline#1:**

      client_secret required for Google Desktop client: YES / NO (fill in)

## 4. `offline_access` — not implemented (deferred, X3)

`allow_offline_access` is plumbed end to end but the agent-side refresh
token / keyring support is deferred (master plan X3): non-interactive
requests fail with `NonInteractiveUnsupported`, so every login is
interactive.

- [ ] Confirm no refresh token is requested or stored during the runs above
      (no `offline_access` scope in the authorization URL).
- [ ] Note in the outcome record that re-authentication after
      `expiration_seconds` requires a fresh interactive login until X3
      lands.

## Recording

Close-out is the operator's step: after one full run, record the outcomes
(sections 1–4, including the `client_secret` answer) in a comment on
[zipline#1](https://github.com/mkolehmainen/zipline/issues/1), then close
the umbrella.
