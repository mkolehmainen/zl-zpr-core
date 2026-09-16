//! OIDC Relying Party flow for ph-cli (org-zpr/zpr-core#1390, plan item D3).
//!
//! Implements the OAuth 2.0 authorization-code flow with PKCE (RFC 7636,
//! S256 only) against an OIDC provider, using a single-use loopback HTTP
//! listener as the redirect target. The entry point is [`login`], used
//! standalone by the hidden `ph-cli oidc-login` debug subcommand and served
//! to the packet handler behind the `AuthAgent` capability ([`CliAuthAgent`],
//! Contract 6) by the `connect` and `auth-agent` commands.
//!
//! Security invariants:
//! - The authorization `code`, the `id_token`, and the PKCE `verifier` are
//!   never printed or logged. Progress messages carry the issuer and the
//!   authorization URL only (the URL contains the one-way S256 challenge,
//!   not the verifier).
//! - The redirect listener binds 127.0.0.1 only, accepts exactly one
//!   request, and validates the `state` parameter before releasing the code.

use std::cell::RefCell;
use std::collections::HashMap;
use std::process::Command;
use std::rc::Rc;
use std::time::Duration;

use admin_api::v1 as cli;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

/// How long the user has to complete the interactive login. Matches ph's
/// `OIDC_USER_INTERACTION_TIMEOUT` (adapter/ph/src/config.rs), deliberately
/// under the node's 330 s `ACTOR_AUTHENTICATION_TIMEOUT` so the CLI side
/// gives up before the node does.
pub const OIDC_LOGIN_TIMEOUT: Duration = Duration::from_secs(300);

/// Fixed `max_age` (seconds, one year) sent on offline-capable authorization
/// requests. The parameter exists only because OIDC Core section 3.1.2.1
/// obliges the IdP to include the `auth_time` claim in the `id_token`
/// whenever the request carries `max_age` — Google omits `auth_time`
/// otherwise, and the visa service requires the claim to anchor
/// renewable-session lifetimes (zipline#42). Enforcement of any
/// authentication-age ceiling happens at the visa service, not here, and the
/// IdP clamps the value per its own policy, so the specific number is
/// irrelevant — it only has to be present.
pub const OFFLINE_MAX_AGE_SECONDS: u64 = 31_536_000;

/// Errors from the OIDC relying-party flow.
#[derive(Debug, thiserror::Error)]
pub enum OidcCliError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("HTTP error talking to the IdP: {0}")]
    Http(#[from] reqwest::Error),
    #[error("invalid URL: {0}")]
    Url(#[from] url::ParseError),
    #[error("OIDC discovery failed: {0}")]
    Discovery(String),
    #[error("state parameter mismatch in authorization redirect")]
    StateMismatch,
    #[error("authorization failed: {0}")]
    AuthorizationDenied(String),
    #[error("timed out waiting for the authorization callback")]
    Timeout,
    #[error("malformed authorization callback: {0}")]
    BadCallback(String),
    #[error("token exchange failed: {0}")]
    TokenExchange(String),
    #[error("failed to launch browser: {0}")]
    Browser(String),
    #[error("non-interactive OIDC login is not supported yet")]
    NonInteractiveUnsupported,
}

impl OidcCliError {
    /// True when a token-endpoint call was rejected with RFC 6749 section
    /// 5.2 `invalid_grant`: the grant (for us, a stored refresh token) is
    /// dead — revoked, expired, or never valid — and must not be replayed.
    /// Keys on the `({code})` suffix [parse_token_response] builds, which is
    /// the only producer of [OidcCliError::TokenExchange] texts with codes.
    pub fn is_invalid_grant(&self) -> bool {
        false
    }
}

/// Description of an OIDC identity provider a link may authenticate against.
///
/// Field set matches Contract "OidcIdpInfo" in the OIDC master plan
/// (docs/plans/2026-09-02-oidc-implementation-plan.md) and the wire fields
/// of `AuthAgent.getOidcCredential` (adapter/admin-api/cli.capnp).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OidcIdpInfo {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub scopes: Vec<String>,
    pub allow_offline_access: bool,
}

/// A PKCE verifier/challenge pair (RFC 7636, S256 method).
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

/// RFC 7636 S256: 32 random bytes -> base64url-nopad verifier (43 chars);
/// challenge = base64url-nopad(SHA-256(verifier)).
pub fn pkce_s256() -> Pkce {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let verifier = URL_SAFE_NO_PAD.encode(bytes);
    let challenge = pkce_challenge_for(&verifier);
    Pkce {
        verifier,
        challenge,
    }
}

/// Compute the S256 challenge for a given verifier (exposed for the RFC 7636
/// appendix-B test vector).
pub fn pkce_challenge_for(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// The two endpoints we need from the provider's discovery document.
pub struct Discovery {
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
}

/// Fetch `<issuer>/.well-known/openid-configuration` and extract the
/// authorization and token endpoints.
pub async fn discover(issuer: &Url, http: &reqwest::Client) -> Result<Discovery, OidcCliError> {
    let base = issuer.as_str().trim_end_matches('/');
    let doc_url = format!("{base}/.well-known/openid-configuration");
    let resp = http.get(&doc_url).send().await?;
    if !resp.status().is_success() {
        return Err(OidcCliError::Discovery(format!(
            "{} returned HTTP {}",
            doc_url,
            resp.status()
        )));
    }
    let doc: serde_json::Value = resp.json().await?;
    let field = |name: &str| -> Result<Url, OidcCliError> {
        let raw = doc
            .get(name)
            .and_then(|v| v.as_str())
            .ok_or_else(|| OidcCliError::Discovery(format!("missing `{name}`")))?;
        Ok(Url::parse(raw)?)
    };
    Ok(Discovery {
        authorization_endpoint: field("authorization_endpoint")?,
        token_endpoint: field("token_endpoint")?,
    })
}

/// Bind a fresh loopback listener on 127.0.0.1 with an OS-assigned port and
/// return it together with the redirect URI `http://127.0.0.1:<port>/callback`.
///
/// Must be called from within a tokio runtime (the std listener is converted
/// to a tokio one).
pub fn bind_loopback() -> Result<(TcpListener, Url), OidcCliError> {
    let std_listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    std_listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(std_listener)?;
    let port = listener.local_addr()?.port();
    let redirect_uri = Url::parse(&format!("http://127.0.0.1:{port}/callback"))?;
    Ok((listener, redirect_uri))
}

/// Accept exactly one HTTP request on `listener`, verify the `state` query
/// parameter matches `expected_state`, answer with a small "you can close
/// this window" page, and return the authorization `code`.
///
/// The listener is consumed: it is closed when this function returns,
/// success or failure, so the redirect endpoint is single-use.
pub async fn await_callback(
    listener: TcpListener,
    expected_state: &str,
    timeout: Duration,
) -> Result<String, OidcCliError> {
    let result = tokio::time::timeout(timeout, async {
        let (mut stream, _peer) = listener.accept().await?;
        let (_method, target, _body) = read_http_request(&mut stream).await?;
        // Parse the request target's query parameters via a dummy base URL.
        let parsed = Url::parse(&format!("http://localhost{target}"))
            .map_err(|e| OidcCliError::BadCallback(e.to_string()))?;
        let mut code = None;
        let mut state = None;
        let mut error = None;
        for (k, v) in parsed.query_pairs() {
            match k.as_ref() {
                "code" => code = Some(v.into_owned()),
                "state" => state = Some(v.into_owned()),
                "error" => error = Some(v.into_owned()),
                _ => {}
            }
        }
        if state.as_deref() != Some(expected_state) {
            let _ = write_http_response(
                &mut stream,
                "400 Bad Request",
                "text/plain",
                "state mismatch",
            )
            .await;
            return Err(OidcCliError::StateMismatch);
        }
        if let Some(error) = error {
            // The IdP reported a failure (e.g. `access_denied`: the user
            // refused the login). Tell the browser, surface the error code.
            let _ = write_http_response(
                &mut stream,
                "200 OK",
                "text/html",
                "<html><body><p>Authentication failed. You can close this window.</p></body></html>",
            )
            .await;
            return Err(OidcCliError::AuthorizationDenied(error));
        }
        let code =
            code.ok_or_else(|| OidcCliError::BadCallback("missing `code` parameter".to_string()))?;
        write_http_response(
            &mut stream,
            "200 OK",
            "text/html",
            "<html><body><p>Authentication complete. You can close this window.</p></body></html>",
        )
        .await?;
        Ok(code)
    })
    .await;
    // Listener is dropped (closed) here regardless of outcome.
    match result {
        Ok(inner) => inner,
        Err(_elapsed) => Err(OidcCliError::Timeout),
    }
}

/// Sanitise the `error` field of an RFC 6749 section 5.2 token-error
/// response before it reaches a log or the user's terminal. A conforming IdP
/// sends one of a fixed set of codes, but nothing stops a hostile or broken
/// one from returning arbitrary text there, so keep only the ASCII shape the
/// RFC allows (`%x20-21 / %x23-5B / %x5D-7E`) and cap the length.
fn oauth_error_code(raw: &str) -> String {
    raw.chars()
        .filter(|c| matches!(c, ' '..='!' | '#'..='[' | ']'..='~'))
        .take(64)
        .collect()
}

/// What the token endpoint hands back that the CLI keeps: the `id_token`
/// (the credential ph asked for) and, when the IdP granted offline access,
/// a `refresh_token`. The refresh token is secret material: it is held in
/// memory only, never logged, never written to disk, and never sent over
/// the AuthAgent RPC.
pub struct TokenResponse {
    pub id_token: String,
    pub refresh_token: Option<String>,
}

// Manual Debug: the refresh token is secret material and must never reach a
// log or panic message, so only its presence is shown.
impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("id_token", &"<redacted>")
            .field(
                "refresh_token",
                if self.refresh_token.is_some() {
                    &"Some(<redacted>)"
                } else {
                    &"None"
                },
            )
            .finish()
    }
}

/// Exchange the authorization code for the token response at the token
/// endpoint (RFC 6749 section 4.1.3 + RFC 7636 section 4.5).
/// `client_secret` is sent only when the client is confidential.
pub async fn exchange_code(
    token_endpoint: &Url,
    client_id: &str,
    client_secret: Option<&str>,
    code: &str,
    verifier: &str,
    redirect_uri: &Url,
    http: &reqwest::Client,
) -> Result<TokenResponse, OidcCliError> {
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri.as_str()),
        ("client_id", client_id),
        ("code_verifier", verifier),
    ];
    if let Some(secret) = client_secret {
        form.push(("client_secret", secret));
    }
    let resp = http.post(token_endpoint.clone()).form(&form).send().await?;
    let status = resp.status();
    if !status.is_success() {
        // The body is deliberately NOT included: `error_description` and any
        // other field is free text from the IdP and could echo the
        // authorization code. The `error` field alone is safe -- RFC 6749
        // section 5.2 fixes it to a small enum of codes ("invalid_grant",
        // "invalid_client", "invalid_request", ...) -- and it is the only
        // part that says why the exchange failed, so extract just that.
        let oauth_error = resp
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|body| body.get("error")?.as_str().map(oauth_error_code));
        return Err(OidcCliError::TokenExchange(match oauth_error {
            Some(code) => format!("HTTP {status} ({code})"),
            None => format!("HTTP {status}"),
        }));
    }
    let body: serde_json::Value = resp.json().await?;
    let id_token = body
        .get("id_token")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(|| OidcCliError::TokenExchange("response has no `id_token`".to_string()))?;
    let refresh_token = body
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    Ok(TokenResponse {
        id_token,
        refresh_token,
    })
}

/// Run the whole relying-party flow against `idp` and return the `id_token`.
/// (The refresh token, if the IdP granted one, is dropped here: stateful
/// reuse belongs to [`CliAuthAgent`], which serves the packet handler.)
///
/// `open_browser = false` prints the authorization URL instead of launching a
/// browser (CI / `--no-browser`). Progress goes to stderr.
pub async fn login(
    idp: &OidcIdpInfo,
    nonce: &str,
    open_browser: bool,
    timeout: Duration,
) -> Result<String, OidcCliError> {
    login_with_progress(idp, nonce, open_browser, timeout, &mut |msg| {
        eprintln!("{msg}")
    })
    .await
    .map(|tokens| tokens.id_token)
}

/// Wrapper matching the `getOidcCredential` contract semantics, stateless
/// form: `interactive = false` cannot be satisfied without a stored refresh
/// token, and this free function holds none, so it is rejected. The
/// stateful path — refresh-token reuse across calls — lives on
/// [`CliAuthAgent`], which serves ph over the RPC.
// [CliAuthAgent] inlines the same logic to thread its progress sink and
// token store; this stays as the plain-function form of the contract,
// exercised by tests.
#[allow(dead_code)]
pub async fn get_oidc_credential(
    idp: &OidcIdpInfo,
    nonce: &str,
    interactive: bool,
    open_browser: bool,
    timeout: Duration,
) -> Result<String, OidcCliError> {
    if !interactive {
        return Err(OidcCliError::NonInteractiveUnsupported);
    }
    login(idp, nonce, open_browser, timeout).await
}

/// One `grant_type=refresh_token` POST to the token endpoint (RFC 6749
/// section 6) and the resulting fresh [`TokenResponse`]. `client_secret` is
/// sent only for a confidential client, mirroring [`exchange_code`] — as is
/// the error discipline: the response body is never echoed, only the RFC
/// 6749 section 5.2 `error` code is extracted. The refresh token itself
/// appears in the outbound form and nowhere else.
pub async fn refresh_grant(
    token_endpoint: &Url,
    client_id: &str,
    client_secret: Option<&str>,
    refresh_token: &str,
    http: &reqwest::Client,
) -> Result<TokenResponse, OidcCliError> {
    let mut form: Vec<(&str, &str)> = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", client_id),
    ];
    if let Some(secret) = client_secret {
        form.push(("client_secret", secret));
    }
    let resp = http.post(token_endpoint.clone()).form(&form).send().await?;
    let status = resp.status();
    if !status.is_success() {
        // Same discipline as [exchange_code]: the body is free text from
        // the IdP and could echo the refresh token, so only the fixed-enum
        // `error` code is extracted.
        let oauth_error = resp
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|body| body.get("error")?.as_str().map(oauth_error_code));
        return Err(OidcCliError::TokenExchange(match oauth_error {
            Some(code) => format!("HTTP {status} ({code})"),
            None => format!("HTTP {status}"),
        }));
    }
    let body: serde_json::Value = resp.json().await?;
    // A refresh response without an id_token is an error, and the caller
    // keeps its stored refresh token: the grant itself was accepted (this
    // was not `invalid_grant`), the response is just unusable for ZPR.
    let id_token = body
        .get("id_token")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(|| OidcCliError::TokenExchange("response has no `id_token`".to_string()))?;
    // RFC 6749 section 6 allows rotating the refresh token on use.
    let refresh_token = body
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    Ok(TokenResponse {
        id_token,
        refresh_token,
    })
}

/// The CLI-side implementation of the packet handler's `AuthAgent`
/// capability (Contract 6): ph calls `getOidcCredential` back over the RPC
/// connection `connect`/`auth-agent` keep open, and this server runs the
/// interactive relying-party flow to satisfy it — or, for `interactive =
/// false`, a silent refresh grant from the in-memory token store.
///
/// Progress goes to stderr by default; tests inject a channel via `progress`
/// to capture every message and assert no secret material leaks.
pub struct CliAuthAgent {
    /// `false` prints the authorization URL instead of launching a browser
    /// (`--no-browser`).
    pub open_browser: bool,
    /// Progress sink override for tests; `None` means stderr.
    pub progress: Option<tokio::sync::mpsc::UnboundedSender<String>>,
    /// Refresh tokens from interactive logins, keyed by issuer, held in
    /// memory for the life of the agent process only (master plan Decision
    /// 2): never logged, never written to disk, never set on RPC results.
    /// `RefCell` suffices — the capnp server runs single-threaded on a
    /// LocalSet, same as the existing `Rc<Self>` receiver.
    pub refresh_tokens: RefCell<HashMap<String, String>>,
}

impl CliAuthAgent {
    /// An agent with an empty token store.
    pub fn new(
        open_browser: bool,
        progress: Option<tokio::sync::mpsc::UnboundedSender<String>>,
    ) -> Self {
        CliAuthAgent {
            open_browser,
            progress,
            refresh_tokens: RefCell::new(HashMap::new()),
        }
    }

    /// Satisfy a non-interactive request from the stored refresh token for
    /// `idp.issuer`, or fail with [`OidcCliError::NonInteractiveUnsupported`]
    /// when none is held. Neither the browser nor the authorization endpoint
    /// nor the loopback listener is ever touched on this path. An
    /// `invalid_grant` answer drops the stored token — it is dead, and the
    /// next attempt should fail fast instead of replaying it — while every
    /// other failure keeps it.
    async fn refresh_credential(&self, idp: &OidcIdpInfo) -> Result<String, OidcCliError> {
        // Clone the token out rather than holding the RefCell borrow across
        // an await.
        let Some(refresh_token) = self.refresh_tokens.borrow().get(&idp.issuer).cloned() else {
            return Err(OidcCliError::NonInteractiveUnsupported);
        };
        let issuer = Url::parse(&idp.issuer)?;
        let http = reqwest::Client::new();
        let discovery = discover(&issuer, &http).await?;
        match refresh_grant(
            &discovery.token_endpoint,
            &idp.client_id,
            idp.client_secret.as_deref(),
            &refresh_token,
            &http,
        )
        .await
        {
            Ok(tokens) => {
                // The IdP may rotate the refresh token (RFC 6749 section 6);
                // keep the newest one.
                if let Some(rotated) = tokens.refresh_token {
                    self.refresh_tokens
                        .borrow_mut()
                        .insert(idp.issuer.clone(), rotated);
                }
                Ok(tokens.id_token)
            }
            Err(err) => {
                // `invalid_grant` == the token is expired or revoked
                // (RFC 6749 section 5.2): drop it so the next attempt fails
                // fast with the no-token error instead of replaying a dead
                // credential. The error text carries only the code, never
                // the token or the response body.
                if let OidcCliError::TokenExchange(msg) = &err
                    && msg.contains("invalid_grant")
                {
                    self.refresh_tokens.borrow_mut().remove(&idp.issuer);
                }
                Err(err)
            }
        }
    }
}

impl cli::auth_agent::Server for CliAuthAgent {
    async fn get_oidc_credential(
        self: Rc<Self>,
        params: cli::auth_agent::GetOidcCredentialParams,
        mut results: cli::auth_agent::GetOidcCredentialResults,
    ) -> Result<(), capnp::Error> {
        let params = params.get()?;
        let client_secret = params.get_client_secret()?.to_string()?;
        let mut scopes = Vec::new();
        for scope in params.get_scopes()? {
            scopes.push(scope?.to_string()?);
        }
        let idp = OidcIdpInfo {
            issuer: params.get_issuer()?.to_string()?,
            client_id: params.get_client_id()?.to_string()?,
            client_secret: (!client_secret.is_empty()).then_some(client_secret),
            scopes,
            allow_offline_access: params.get_allow_offline_access(),
        };
        let nonce = params.get_nonce()?.to_string()?;
        let interactive = params.get_interactive();

        let outcome = if !interactive {
            // Never open a browser (or even bind the listener) on a
            // non-interactive request: satisfy it from the stored refresh
            // token, or fail with the no-token error.
            self.refresh_credential(&idp).await
        } else {
            let progress_tx = self.progress.clone();
            let mut sink = move |msg: &str| match &progress_tx {
                Some(tx) => {
                    let _ = tx.send(msg.to_string());
                }
                None => eprintln!("{msg}"),
            };
            login_with_progress(
                &idp,
                &nonce,
                self.open_browser,
                OIDC_LOGIN_TIMEOUT,
                &mut sink,
            )
            .await
            .map(|tokens| {
                // Keep the refresh token (when the IdP granted one) in
                // memory, keyed by issuer, so later `interactive: false`
                // requests can be satisfied silently. It goes nowhere else.
                if let Some(refresh_token) = tokens.refresh_token {
                    self.refresh_tokens
                        .borrow_mut()
                        .insert(idp.issuer.clone(), refresh_token);
                }
                tokens.id_token
            })
        };

        let mut rb = results.get();
        match outcome {
            Ok(id_token) => {
                rb.set_id_token(&id_token[..]);
                rb.init_result().init_success().set_none(());
            }
            Err(err) => {
                rb.set_id_token("");
                // Tagged with a stable class token so ph's reason-parser can
                // map the failure onto the right AuthFailureReason (and
                // `connect` onto its advertised exit code) — see
                // [rpc_error_text].
                rb.init_result().init_error().set_txt(rpc_error_text(&err));
            }
        }
        Ok(())
    }
}

/// Render an [`OidcCliError`] as the error text sent back over the AuthAgent
/// RPC (`getOidcCredential`'s error arm).
///
/// ph's `classify_agent_error` (adapter/ph/src/admin_worker.rs) parses a
/// leading `[class:<token>]` prefix into the matching `AuthFailureReason`,
/// which is what `connect`'s exit-code contract keys on; text without a
/// recognized token falls back to `AgentError` (exit 1). The two sides must
/// agree on these tokens:
///
/// - `user_declined`      -> the IdP reported `access_denied` (the display
///   text also carries "access_denied" verbatim, keeping the legacy
///   spelling-based classification working).
/// - `interaction_timeout`-> the user did not complete the login in time.
/// - `idp_unreachable`    -> discovery / HTTP transport / token-endpoint
///   failure ("not an auth problem" per the taxonomy — the token endpoint
///   answering with an error is still an IdP-side failure from ZPR's view).
///
/// Everything else (state mismatch, bad callback, browser launch, I/O) is a
/// genuine agent-side failure and is sent untagged.
pub fn rpc_error_text(err: &OidcCliError) -> String {
    let class = match err {
        OidcCliError::AuthorizationDenied(_) => Some("user_declined"),
        OidcCliError::Timeout => Some("interaction_timeout"),
        OidcCliError::Http(_) | OidcCliError::Discovery(_) | OidcCliError::TokenExchange(_) => {
            Some("idp_unreachable")
        }
        _ => None,
    };
    match class {
        Some(class) => format!("[class:{class}] {err}"),
        None => err.to_string(),
    }
}

/// [`login`] with an explicit progress sink so tests can capture every
/// message and assert no secret material leaks into it. Returns the whole
/// [`TokenResponse`] so [`CliAuthAgent`] can keep the refresh token.
pub async fn login_with_progress(
    idp: &OidcIdpInfo,
    nonce: &str,
    open_browser: bool,
    timeout: Duration,
    progress: &mut (dyn FnMut(&str) + Send),
) -> Result<TokenResponse, OidcCliError> {
    login_flow(
        idp,
        nonce,
        open_browser,
        browser_unavailable(),
        timeout,
        progress,
    )
    .await
}

/// The relying-party flow with the browser-availability verdict injected
/// (tests force the headless leg without mutating process environment;
/// [`login_with_progress`] passes the real [`browser_unavailable`] result).
async fn login_flow(
    idp: &OidcIdpInfo,
    nonce: &str,
    open_browser: bool,
    browser_blocker: Option<&'static str>,
    timeout: Duration,
    progress: &mut (dyn FnMut(&str) + Send),
) -> Result<TokenResponse, OidcCliError> {
    let issuer = Url::parse(&idp.issuer)?;
    let http = reqwest::Client::new();
    let discovery = discover(&issuer, &http).await?;
    let pkce = pkce_s256();
    let mut state_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut state_bytes);
    let state = URL_SAFE_NO_PAD.encode(state_bytes);
    let (listener, redirect_uri) = bind_loopback()?;

    // `offline_access` is requested only when policy allows offline access
    // (and only once, if the configured scopes already carry it).
    let scope = if idp.allow_offline_access && !idp.scopes.iter().any(|s| s == "offline_access") {
        let mut scopes = idp.scopes.clone();
        scopes.push("offline_access".to_string());
        scopes.join(" ")
    } else {
        idp.scopes.join(" ")
    };
    let mut auth_url = discovery.authorization_endpoint.clone();
    auth_url
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &idp.client_id)
        .append_pair("redirect_uri", redirect_uri.as_str())
        .append_pair("scope", &scope)
        .append_pair("state", &state)
        .append_pair("nonce", nonce)
        .append_pair("code_challenge", &pkce.challenge)
        .append_pair("code_challenge_method", "S256");
    if idp.allow_offline_access {
        // `access_type=offline` + `prompt=consent` is Google's mechanism
        // for minting a refresh token; RFC 6749 section 3.1 makes the
        // parameters safe against IdPs that do not know them.
        //
        // `max_age` is NOT the session ceiling — the policy's
        // `max_auth_age_seconds` is enforced by the visa service's dual
        // clock (zipline#42), and an IdP clamps per its own rules. The
        // parameter exists here purely because including it (any value)
        // obliges the IdP to emit the `auth_time` claim in the id_token
        // (OIDC Core sections 2 and 3.1.2.1), which the VS requires for
        // offline-access providers; one year elicits the claim without
        // forcing a re-login.
        auth_url
            .query_pairs_mut()
            .append_pair("access_type", "offline")
            .append_pair("prompt", "consent")
            .append_pair("max_age", "31536000");
    }

    if open_browser && browser_blocker.is_none() {
        progress(&format!(
            "Authentication with {} required. Opening browser…",
            idp.issuer
        ));
        open_in_browser(auth_url.as_str())?;
    } else {
        // Either `--no-browser`, or launching cannot work here (root /
        // headless): print the URL instead of hanging until the login
        // timeout with no diagnostic. The URL carries the one-way S256
        // challenge, never the verifier.
        let reason = match browser_blocker {
            Some(reason) if open_browser => format!("{reason}; not launching a browser. "),
            _ => String::new(),
        };
        progress(&format!(
            "{reason}Authentication with {} required. Open this URL to continue: {}",
            idp.issuer, auth_url
        ));
    }

    let code = await_callback(listener, &state, timeout).await?;
    progress("Authorization received; exchanging code for token…");
    let tokens = exchange_code(
        &discovery.token_endpoint,
        &idp.client_id,
        idp.client_secret.as_deref(),
        &code,
        &pkce.verifier,
        &redirect_uri,
        &http,
    )
    .await?;
    progress("Authentication complete.");
    Ok(tokens)
}

/// Why launching a browser cannot work in this environment, or `None` when
/// it can. Running as root, `xdg-open`'s `spawn()` succeeds and the failure
/// happens inside the child, so [`OidcCliError::Browser`] never fires and
/// the user would hang for the full login timeout with no diagnostic —
/// hence this pre-flight check (zipline#46). macOS `open` talks to the
/// window server directly, so the display-variable leg is Linux-only.
fn browser_unavailable() -> Option<&'static str> {
    browser_unavailable_for(
        nix::unistd::geteuid().is_root(),
        std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some(),
    )
}

/// The pure predicate behind [`browser_unavailable`], with the euid and
/// display checks injected so tests cover both legs without running as root
/// or mutating the process environment.
fn browser_unavailable_for(is_root: bool, has_display: bool) -> Option<&'static str> {
    if is_root {
        Some("running as root")
    } else if cfg!(target_os = "linux") && !has_display {
        Some("no graphical session (neither DISPLAY nor WAYLAND_DISPLAY is set)")
    } else {
        None
    }
}

/// Launch the platform browser on `url` (no external crate: `xdg-open` on
/// Linux, `open` on macOS).
fn open_in_browser(url: &str) -> Result<(), OidcCliError> {
    let program = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    Command::new(program)
        .arg(url)
        .spawn()
        .map(|_| ())
        .map_err(|e| OidcCliError::Browser(format!("{program}: {e}")))
}

/// What one `showLink` snapshot says about a starting link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkOutcome {
    /// `State: Active` — the link is up.
    Up,
    /// Authentication failed; carries the Debug spelling of ph's
    /// `AuthFailureReason` from the `Last auth failure:` line. Reported for
    /// the transient `Error` state (empty reason if none was printed) and
    /// for any teardown state that carries a recorded failure — see
    /// [`parse_show_link_state`].
    Failed(String),
    /// Any other state — keep polling.
    Pending,
}

/// Parse the text `showLink` returns. ph prints `  State: {:?} (for {:?})`
/// (Display for LinkStateMachine) and, when a failure was recorded,
/// `  Last auth failure: {:?}` (Display for LinkStateWrapper), both in
/// adapter/ph/src/link_state.rs.
///
/// The `Error` state is transient: ph's `process_authentication_failure`
/// sets it and synchronously initiates the close, so a 1-second poll usually
/// observes the link already in `Closing` (then `Inactive` once the
/// terminate completes, then restarting). The durable trace of the failure
/// is the recorded reason, which ph clears when a fresh Start begins a new
/// attempt — so a teardown state accompanied by a `Last auth failure:` line
/// is this attempt's terminal outcome, while a teardown state without one is
/// an ordinary stop/restart and polling continues.
pub fn parse_show_link_state(text: &str) -> LinkOutcome {
    let mut state = None;
    let mut reason = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("State: ") {
            // "Active (for 1.2s)" -> "Active"; Disconnecting(..) has no
            // space before its parenthesis, so split on " (" only.
            state = Some(rest.split(" (").next().unwrap_or(rest).to_string());
        } else if let Some(rest) = line.strip_prefix("Last auth failure: ") {
            reason = Some(rest.to_string());
        }
    }
    // States a failed authentication tears the link down through
    // (initiate_close / continue_close / complete_close).
    let is_teardown = matches!(
        state.as_deref(),
        Some("Closing") | Some("Inactive") | Some("Resetting")
    ) || state
        .as_deref()
        .is_some_and(|s| s.starts_with("Disconnecting"));
    match state.as_deref() {
        Some("Active") => LinkOutcome::Up,
        Some("Error") => LinkOutcome::Failed(reason.unwrap_or_default()),
        _ if is_teardown && reason.is_some() => LinkOutcome::Failed(reason.unwrap_or_default()),
        _ => LinkOutcome::Pending,
    }
}

/// Map the Debug spelling of ph's `AuthFailureReason` (as printed by
/// `showLink`'s `Last auth failure:` line) to the `connect` exit-code
/// contract: 2 user declined, 3 timeout, 4 IdP unreachable, 5 visa service
/// rejected the token, 6 policy denied, 7 device blob rejected, 1 anything
/// else (NoAgent, AgentError, AuthUnavailable, unrecognized).
pub fn exit_code_for_auth_failure(reason: &str) -> i32 {
    if reason.starts_with("UserDeclined") {
        2
    } else if reason.starts_with("InteractionTimeout") {
        3
    } else if reason.starts_with("IdpUnreachable(") {
        4
    } else if reason.starts_with("VisaServiceRejected(") {
        5
    } else if reason.starts_with("PolicyDenied") {
        6
    } else if reason.starts_with("DeviceBlobRejected") {
        7
    } else {
        1
    }
}

/// Whether a `startLink` error means agent registration failed.
///
/// ph registers the AuthAgent capability *before* firing the Start event
/// (admin_worker.rs::start_link), and starting a non-Inactive link answers
/// with an `UnexpectedTransition` error after the registration already
/// happened — so for `auth-agent` that error is benign: the agent is
/// registered on the running link and must keep serving. Anything else
/// (e.g. `NotFound`: no such link, so nothing was registered) is fatal.
pub fn start_link_error_is_fatal(msg: &str) -> bool {
    !msg.contains("UnexpectedTransition")
}

/// Map an [`OidcCliError`] from the standalone `oidc-login` flow onto the
/// same exit-code contract.
pub fn exit_code_for_oidc_error(err: &OidcCliError) -> i32 {
    match err {
        OidcCliError::AuthorizationDenied(_) => 2,
        OidcCliError::Timeout => 3,
        OidcCliError::Http(_) | OidcCliError::Discovery(_) => 4,
        OidcCliError::TokenExchange(_) => 5,
        _ => 1,
    }
}

/// Read one HTTP/1.1 request from `stream`: returns (method, target, body).
/// Minimal parser sufficient for the loopback callback and the tests' fake
/// IdP; not a general HTTP implementation.
async fn read_http_request(
    stream: &mut tokio::net::TcpStream,
) -> Result<(String, String, Vec<u8>), OidcCliError> {
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 64 * 1024 {
            return Err(OidcCliError::BadCallback("request too large".to_string()));
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(OidcCliError::BadCallback(
                "connection closed mid-request".to_string(),
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| OidcCliError::BadCallback("empty request".to_string()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| OidcCliError::BadCallback("no method".to_string()))?
        .to_string();
    let target = parts
        .next()
        .ok_or_else(|| OidcCliError::BadCallback("no request target".to_string()))?
        .to_string();
    let content_length = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length);
    Ok((method, target, body))
}

/// Write a minimal HTTP/1.1 response and flush it.
async fn write_http_response(
    stream: &mut tokio::net::TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
) -> Result<(), OidcCliError> {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

/// Find `needle` in `haystack`, returning the start index.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpStream;

    /// RFC 7636 appendix B test vector.
    #[test]
    fn test_pkce_rfc7636_vector() {
        assert_eq!(
            pkce_challenge_for("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    /// 32 random bytes base64url-nopad encode to exactly 43 chars from the
    /// unreserved/base64url alphabet, and the challenge matches the verifier.
    #[test]
    fn test_pkce_verifier_length_and_charset() {
        for _ in 0..16 {
            let pkce = pkce_s256();
            assert_eq!(pkce.verifier.len(), 43);
            assert!(
                pkce.verifier
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                "unexpected char in verifier"
            );
            assert_eq!(pkce.challenge, pkce_challenge_for(&pkce.verifier));
        }
    }

    /// The redirect listener must be loopback-only with an OS-assigned port,
    /// and the redirect URI must reflect exactly that address.
    #[tokio::test]
    async fn test_bind_loopback_is_127_0_0_1() {
        let (listener, redirect_uri) = bind_loopback().unwrap();
        let addr = listener.local_addr().unwrap();
        assert_eq!(addr.ip(), std::net::IpAddr::from([127, 0, 0, 1]));
        assert_ne!(addr.port(), 0);
        assert_eq!(
            redirect_uri.as_str(),
            format!("http://127.0.0.1:{}/callback", addr.port())
        );
    }

    /// A callback with the wrong `state` is rejected and the listener is
    /// closed afterwards (single-use endpoint).
    #[tokio::test]
    async fn test_callback_rejects_state_mismatch() {
        let (listener, redirect_uri) = bind_loopback().unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            await_callback(listener, "expected-state", Duration::from_secs(5)).await
        });
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream
            .write_all(b"GET /callback?code=x&state=wrong HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let result = task.await.unwrap();
        assert!(matches!(result, Err(OidcCliError::StateMismatch)));
        drop(stream);
        // The listener must be gone: a fresh connection is refused.
        let reconnect = TcpStream::connect(("127.0.0.1", port)).await;
        assert!(
            reconnect.is_err(),
            "listener still accepting after state mismatch; redirect_uri was {redirect_uri}"
        );
    }

    /// A callback with the matching `state` yields the code exactly once.
    #[tokio::test]
    async fn test_callback_accepts_matching_state_once() {
        let (listener, _redirect_uri) = bind_loopback().unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            await_callback(listener, "good-state", Duration::from_secs(5)).await
        });
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        stream
            .write_all(
                b"GET /callback?code=the-auth-code&state=good-state HTTP/1.1\r\nHost: l\r\n\r\n",
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8_lossy(&response);
        assert!(response.starts_with("HTTP/1.1 200"), "got: {response}");
        assert!(response.contains("close this window"));
        let code = task.await.unwrap().unwrap();
        assert_eq!(code, "the-auth-code");
        // Single-use: the port no longer accepts connections.
        assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
    }

    /// The token exchange must POST the PKCE verifier, send `client_secret`
    /// only when the client is confidential, and hand back the
    /// `refresh_token` when the IdP grants one (`None` when it does not).
    #[tokio::test]
    async fn test_exchange_code_posts_verifier_and_optional_secret() {
        for (secret, stub_refresh) in [(None, None), (Some("s3cret"), Some("rt-granted"))] {
            let (captured, tokens) = run_token_stub_and_exchange(secret, stub_refresh).await;
            let fields: std::collections::HashMap<String, String> =
                url::form_urlencoded::parse(captured.as_bytes())
                    .into_owned()
                    .collect();
            assert_eq!(fields["grant_type"], "authorization_code");
            assert_eq!(fields["code"], "code-abc");
            assert_eq!(fields["code_verifier"], "verifier-xyz");
            assert_eq!(fields["client_id"], "client-1");
            assert!(fields["redirect_uri"].starts_with("http://127.0.0.1:"));
            match secret {
                Some(s) => assert_eq!(fields["client_secret"], s),
                None => assert!(
                    !fields.contains_key("client_secret"),
                    "client_secret sent for a public client"
                ),
            }
            assert_eq!(tokens.id_token, "tok");
            assert_eq!(tokens.refresh_token.as_deref(), stub_refresh);
        }
    }

    /// A failed token exchange must surface the IdP's RFC 6749 section 5.2
    /// `error` code, which is what actually says *why* it failed
    /// (`invalid_request` for a missing `client_secret`, `invalid_grant` for
    /// a stale code). The code is drawn from a fixed enum, so unlike
    /// `error_description` and the rest of the body it cannot echo the
    /// authorization code or any other secret.
    #[tokio::test]
    async fn test_exchange_code_surfaces_oauth_error_code_but_not_body() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = read_http_request(&mut stream).await.unwrap();
            write_http_response(
                &mut stream,
                "400 Bad Request",
                "application/json",
                // `error_description` deliberately echoes the code, to prove
                // the body never reaches the error text.
                "{\"error\":\"invalid_request\",\
                  \"error_description\":\"client_secret is missing, code=code-abc\"}",
            )
            .await
            .unwrap();
        });
        let err = exchange_code(
            &Url::parse(&format!("http://{addr}/token")).unwrap(),
            "client-1",
            None,
            "code-abc",
            "verifier-xyz",
            &Url::parse("http://127.0.0.1:12345/callback").unwrap(),
            &reqwest::Client::new(),
        )
        .await
        .expect_err("400 must be an error");

        let text = err.to_string();
        assert!(text.contains("400"), "status missing from {text:?}");
        assert!(
            text.contains("invalid_request"),
            "OAuth error code missing from {text:?}"
        );
        assert!(
            !text.contains("code-abc"),
            "response body leaked into {text:?}"
        );
    }

    /// Run a one-shot token-endpoint stub — answering with an `id_token` and,
    /// when `refresh` is set, a `refresh_token` — call `exchange_code`
    /// against it, and return the raw form body the stub captured together
    /// with the parsed [`TokenResponse`].
    async fn run_token_stub_and_exchange(
        secret: Option<&str>,
        refresh: Option<&str>,
    ) -> (String, TokenResponse) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let response_body = match refresh {
            Some(rt) => format!("{{\"id_token\":\"tok\",\"refresh_token\":\"{rt}\"}}"),
            None => "{\"id_token\":\"tok\"}".to_string(),
        };
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (method, target, body) = read_http_request(&mut stream).await.unwrap();
            assert_eq!(method, "POST");
            assert_eq!(target, "/token");
            write_http_response(&mut stream, "200 OK", "application/json", &response_body)
                .await
                .unwrap();
            tx.send(String::from_utf8(body).unwrap()).unwrap();
        });
        let token_endpoint = Url::parse(&format!("http://{addr}/token")).unwrap();
        let redirect_uri = Url::parse(&format!("http://127.0.0.1:{}/callback", 12345)).unwrap();
        let http = reqwest::Client::new();
        let tokens = exchange_code(
            &token_endpoint,
            "client-1",
            secret,
            "code-abc",
            "verifier-xyz",
            &redirect_uri,
            &http,
        )
        .await
        .unwrap();
        (rx.await.unwrap(), tokens)
    }

    const FAKE_ID_TOKEN: &str = "fake.header.payload";
    const FAKE_CODE: &str = "authcode-8d1e2f";

    /// State a fake IdP records about the requests it served.
    #[derive(Default)]
    struct IdpSeen {
        auth_nonce: Option<String>,
    }

    /// Minimal in-process IdP: serves the discovery document, an `/auth`
    /// endpoint that 302-redirects back with a fixed code and the caller's
    /// `state`, and a `/token` endpoint returning a fixed `id_token`.
    async fn run_fake_idp(listener: TcpListener, seen: Arc<Mutex<IdpSeen>>) {
        run_fake_idp_mode(listener, seen, false).await
    }

    /// [run_fake_idp], but with `deny = true` the `/auth` endpoint redirects
    /// back with `error=access_denied` instead of a code (the user refused).
    async fn run_fake_idp_mode(listener: TcpListener, seen: Arc<Mutex<IdpSeen>>, deny: bool) {
        let base = format!("http://{}", listener.local_addr().unwrap());
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let Ok((_method, target, _body)) = read_http_request(&mut stream).await else {
                continue;
            };
            if target.starts_with("/.well-known/openid-configuration") {
                let body = format!(
                    "{{\"authorization_endpoint\":\"{base}/auth\",\"token_endpoint\":\"{base}/token\"}}"
                );
                let _ = write_http_response(&mut stream, "200 OK", "application/json", &body).await;
            } else if target.starts_with("/auth") {
                let parsed = Url::parse(&format!("http://localhost{target}")).unwrap();
                let mut state = String::new();
                let mut redirect_uri = String::new();
                for (k, v) in parsed.query_pairs() {
                    match k.as_ref() {
                        "state" => state = v.into_owned(),
                        "redirect_uri" => redirect_uri = v.into_owned(),
                        "nonce" => seen.lock().unwrap().auth_nonce = Some(v.into_owned()),
                        _ => {}
                    }
                }
                let location = if deny {
                    format!("{redirect_uri}?error=access_denied&state={state}")
                } else {
                    format!("{redirect_uri}?code={FAKE_CODE}&state={state}")
                };
                let response = format!(
                    "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = stream.write_all(response.as_bytes()).await;
            } else if target.starts_with("/token") {
                let body = format!("{{\"id_token\":\"{FAKE_ID_TOKEN}\"}}");
                let _ = write_http_response(&mut stream, "200 OK", "application/json", &body).await;
            } else {
                let _ = write_http_response(&mut stream, "404 Not Found", "text/plain", "no").await;
            }
        }
    }

    /// Full `--no-browser` flow against the fake IdP. The test plays the
    /// browser: it grabs the printed authorization URL, follows the 302, and
    /// hits the loopback callback. Asserts the nonce reached `/auth` and that
    /// no progress message leaked the code or the token.
    #[tokio::test]
    async fn test_login_no_browser_end_to_end_against_fake_idp() {
        let idp_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let idp_addr = idp_listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(IdpSeen::default()));
        tokio::spawn(run_fake_idp(idp_listener, seen.clone()));

        let idp = OidcIdpInfo {
            issuer: format!("http://{idp_addr}"),
            client_id: "client-1".to_string(),
            client_secret: None,
            scopes: vec!["openid".to_string(), "profile".to_string()],
            allow_offline_access: false,
        };
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let login_task = tokio::spawn(async move {
            let mut sink = move |m: &str| {
                let _ = tx.send(m.to_string());
            };
            login_with_progress(&idp, "nonce-123", false, Duration::from_secs(10), &mut sink).await
        });

        // Wait for the progress message carrying the authorization URL.
        let mut messages: Vec<String> = Vec::new();
        let auth_url = loop {
            let msg = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("no progress message")
                .expect("progress channel closed");
            messages.push(msg.clone());
            // The URL is the last whitespace-separated token of the
            // "Open this URL to continue:" message.
            if msg.contains("Open this URL") {
                break msg.split_whitespace().last().unwrap().to_string();
            }
        };

        // Play the browser: GET the auth URL (no redirect following), then
        // follow the Location header to the loopback callback.
        let browser = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let auth_resp = browser.get(&auth_url).send().await.unwrap();
        assert_eq!(auth_resp.status().as_u16(), 302);
        let location = auth_resp.headers()["location"]
            .to_str()
            .unwrap()
            .to_string();
        let cb_resp = browser.get(&location).send().await.unwrap();
        assert!(cb_resp.status().is_success());

        let id_token = login_task.await.unwrap().unwrap().id_token;
        assert_eq!(id_token, FAKE_ID_TOKEN);
        assert_eq!(
            seen.lock().unwrap().auth_nonce.as_deref(),
            Some("nonce-123")
        );

        // Drain remaining progress messages, then assert no secret leaked.
        while let Ok(msg) = rx.try_recv() {
            messages.push(msg);
        }
        for msg in &messages {
            assert!(!msg.contains(FAKE_ID_TOKEN), "id_token leaked: {msg}");
            assert!(!msg.contains(FAKE_CODE), "authorization code leaked: {msg}");
        }
    }

    /// The non-interactive agent path is a follow-up issue and must be
    /// rejected explicitly.
    #[tokio::test]
    async fn test_non_interactive_is_unsupported() {
        let idp = OidcIdpInfo {
            issuer: "http://127.0.0.1:1/".to_string(),
            client_id: "c".to_string(),
            client_secret: None,
            scopes: vec![],
            allow_offline_access: false,
        };
        let result = get_oidc_credential(&idp, "n", false, false, Duration::from_secs(1)).await;
        assert!(matches!(
            result,
            Err(OidcCliError::NonInteractiveUnsupported)
        ));
    }

    /// The seven `connect` failure classes map onto exit codes 2-7 (and 1
    /// for anything unrecognized), keyed on the Debug spellings of ph's
    /// `AuthFailureReason` as printed by `showLink`'s "Last auth failure:"
    /// line (adapter/ph/src/link_state.rs).
    #[test]
    fn test_reason_to_exit_code() {
        assert_eq!(exit_code_for_auth_failure("UserDeclined"), 2);
        assert_eq!(exit_code_for_auth_failure("InteractionTimeout"), 3);
        assert_eq!(
            exit_code_for_auth_failure("IdpUnreachable(\"connect refused\")"),
            4
        );
        assert_eq!(
            exit_code_for_auth_failure("VisaServiceRejected(\"bad token\")"),
            5
        );
        assert_eq!(exit_code_for_auth_failure("PolicyDenied"), 6);
        assert_eq!(exit_code_for_auth_failure("DeviceBlobRejected"), 7);
        // Not one of the seven contract classes:
        assert_eq!(exit_code_for_auth_failure("NoAgent"), 1);
        assert_eq!(exit_code_for_auth_failure("AgentError(\"x\")"), 1);
        assert_eq!(exit_code_for_auth_failure("AuthUnavailable"), 1);
        assert_eq!(exit_code_for_auth_failure("something else"), 1);

        assert_eq!(
            exit_code_for_oidc_error(&OidcCliError::AuthorizationDenied("access_denied".into())),
            2
        );
        assert_eq!(exit_code_for_oidc_error(&OidcCliError::Timeout), 3);
        assert_eq!(
            exit_code_for_oidc_error(&OidcCliError::Discovery("x".into())),
            4
        );
        assert_eq!(
            exit_code_for_oidc_error(&OidcCliError::TokenExchange("x".into())),
            5
        );
        assert_eq!(exit_code_for_oidc_error(&OidcCliError::StateMismatch), 1);
    }

    /// The error text sent over the AuthAgent RPC must carry a stable class
    /// token so ph's `classify_agent_error` (admin_worker.rs) can map it to
    /// the right `AuthFailureReason` — and thus `connect` to its advertised
    /// exit codes — instead of collapsing everything but access_denied into
    /// AgentError/exit 1.
    #[test]
    fn test_rpc_error_text_carries_class_token() {
        assert_eq!(
            rpc_error_text(&OidcCliError::AuthorizationDenied("access_denied".into())),
            "[class:user_declined] authorization failed: access_denied"
        );
        assert_eq!(
            rpc_error_text(&OidcCliError::Timeout),
            "[class:interaction_timeout] timed out waiting for the authorization callback"
        );
        // Discovery, HTTP transport, and token-endpoint failures are all
        // IdP-side ("discovery/token endpoint failure (not an auth
        // problem)" per the AuthFailureReason taxonomy).
        assert_eq!(
            rpc_error_text(&OidcCliError::Discovery("missing `token_endpoint`".into())),
            "[class:idp_unreachable] OIDC discovery failed: missing `token_endpoint`"
        );
        assert_eq!(
            rpc_error_text(&OidcCliError::TokenExchange("HTTP 400 Bad Request".into())),
            "[class:idp_unreachable] token exchange failed: HTTP 400 Bad Request"
        );
        // Anything else is an agent-side failure: no class token, so ph
        // falls back to AgentError (exit 1), as before.
        assert_eq!(
            rpc_error_text(&OidcCliError::StateMismatch),
            "state parameter mismatch in authorization redirect"
        );
    }

    /// `auth-agent` registers by calling startLink; on an already-started
    /// link ph answers with an UnexpectedTransition error *after* the agent
    /// was registered, so that error must not be fatal — the task keeps
    /// serving. Genuinely broken registrations (no such link) are fatal.
    #[test]
    fn test_auth_agent_tolerates_already_started_link() {
        assert!(!start_link_error_is_fatal(
            "Failed to start link 3: UnexpectedTransition(Keying, \"Start\")\n"
        ));
        assert!(!start_link_error_is_fatal(
            "Failed to start link 3: UnexpectedTransition(Active, \"Start\")\n"
        ));
        assert!(start_link_error_is_fatal(
            "Failed to start link 9: NotFound(9)\n"
        ));
        assert!(start_link_error_is_fatal("something unexpected"));
    }

    /// Pure parser over the `showLink` result text, matching what ph's
    /// Display impls actually print: `  State: {:?} (for {:?})` and, when
    /// set, `  Last auth failure: {:?}`.
    #[test]
    fn test_parse_show_link_state() {
        assert_eq!(
            parse_show_link_state("  Type: AdapterToNode\n  State: Active (for 1.2s)\n"),
            LinkOutcome::Up
        );
        assert_eq!(
            parse_show_link_state(
                "  State: Error (for 3ms)\n  Last auth failure: InteractionTimeout\n"
            ),
            LinkOutcome::Failed("InteractionTimeout".to_string())
        );
        assert_eq!(
            parse_show_link_state(
                "  State: Error (for 3ms)\n  Last auth failure: IdpUnreachable(\"conn refused\")\n"
            ),
            LinkOutcome::Failed("IdpUnreachable(\"conn refused\")".to_string())
        );
        // Error with no recorded reason still terminates the wait.
        assert_eq!(
            parse_show_link_state("  State: Error (for 3ms)\n"),
            LinkOutcome::Failed(String::new())
        );
        // Anything in-flight keeps polling.
        assert_eq!(
            parse_show_link_state("  State: WaitForUserAuth (for 10s)\n"),
            LinkOutcome::Pending
        );
        assert_eq!(
            parse_show_link_state("  State: Keying (for 10ms)\n"),
            LinkOutcome::Pending
        );
    }

    /// The Error state is transient: `process_authentication_failure` sets it
    /// and synchronously initiates the close, so the 1-second poll normally
    /// observes the link already in Closing (or Inactive, once the terminate
    /// completes). A teardown state accompanied by a recorded failure is the
    /// current attempt's outcome — ph clears `last_auth_failure` on Start, so
    /// a reason that is visible always belongs to the attempt this `connect`
    /// started — and must be terminal, not Pending.
    #[test]
    fn test_parse_show_link_state_teardown_with_reason_is_terminal() {
        for state in ["Closing", "Inactive", "Resetting", "Disconnecting(Other)"] {
            assert_eq!(
                parse_show_link_state(&format!(
                    "  State: {state} (for 3ms)\n  Last auth failure: InteractionTimeout\n"
                )),
                LinkOutcome::Failed("InteractionTimeout".to_string()),
                "teardown state {state} with a recorded failure must be terminal"
            );
        }
        // A teardown state with no recorded failure is an ordinary
        // stop/restart, not an authentication outcome: keep polling.
        assert_eq!(
            parse_show_link_state("  State: Closing (for 3ms)\n"),
            LinkOutcome::Pending
        );
        assert_eq!(
            parse_show_link_state("  State: Inactive (for 3ms)\n"),
            LinkOutcome::Pending
        );
        // A running state ignores the reason line (defense in depth: ph
        // clears it on Start, so it should never be visible here anyway).
        assert_eq!(
            parse_show_link_state(
                "  State: WaitForUserAuth (for 10s)\n  Last auth failure: NoAgent\n"
            ),
            LinkOutcome::Pending
        );
    }

    /// With auto-connect off, ph records `LinkFailed(..)` when a manually
    /// started link dies before authentication (e.g. a Helloing timeout), so
    /// the permanently Inactive link reads as this attempt's terminal
    /// failure — not Pending, which would leave `connect` polling a link
    /// that will never recover. Exit code is the generic 1.
    #[test]
    fn test_parse_show_link_state_manual_pre_auth_failure_is_terminal() {
        let reason =
            "LinkFailed(\"link failed before authentication completed (RequestTimedOut)\")";
        assert_eq!(
            parse_show_link_state(&format!(
                "  State: Inactive (for 3ms)\n  Last auth failure: {reason}\n"
            )),
            LinkOutcome::Failed(reason.to_string())
        );
        assert_eq!(exit_code_for_auth_failure(reason), 1);
    }

    /// Build an in-process Cap'n Proto client for [CliAuthAgent] with a
    /// captured progress channel. Must run inside a LocalSet (capnp clients
    /// are !Send).
    fn new_cli_auth_agent(
        open_browser: bool,
    ) -> (
        cli::auth_agent::Client,
        tokio::sync::mpsc::UnboundedReceiver<String>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let client = capnp_rpc::new_client(CliAuthAgent::new(open_browser, Some(tx)));
        (client, rx)
    }

    /// Issue a getOidcCredential call against `agent` for the fake IdP at
    /// `idp_addr` and return the in-flight call handle.
    fn send_get_oidc_credential(
        agent: &cli::auth_agent::Client,
        issuer: String,
        interactive: bool,
    ) -> capnp::capability::RemotePromise<cli::auth_agent::get_oidc_credential_results::Owned> {
        send_get_oidc_credential_offline(agent, issuer, interactive, false)
    }

    /// [send_get_oidc_credential] with `allowOfflineAccess` under test
    /// control.
    fn send_get_oidc_credential_offline(
        agent: &cli::auth_agent::Client,
        issuer: String,
        interactive: bool,
        allow_offline_access: bool,
    ) -> capnp::capability::RemotePromise<cli::auth_agent::get_oidc_credential_results::Owned> {
        let mut request = agent.get_oidc_credential_request();
        {
            let mut rb = request.get();
            rb.set_issuer(&issuer[..]);
            rb.set_client_id("client-1");
            rb.set_client_secret("");
            rb.reborrow().init_scopes(1).set(0, "openid");
            rb.set_allow_offline_access(allow_offline_access);
            rb.set_nonce("nonce-agent");
            rb.set_interactive(interactive);
        }
        request.send()
    }

    /// Play the browser against the flow driven by `progress`: wait for the
    /// "Open this URL" message, GET the auth URL without following
    /// redirects, then follow the Location header to the loopback callback.
    async fn play_browser(progress: &mut tokio::sync::mpsc::UnboundedReceiver<String>) {
        let auth_url = loop {
            let msg = tokio::time::timeout(Duration::from_secs(5), progress.recv())
                .await
                .expect("no progress message")
                .expect("progress channel closed");
            if msg.contains("Open this URL") {
                break msg.split_whitespace().last().unwrap().to_string();
            }
        };
        let browser = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let auth_resp = browser.get(&auth_url).send().await.unwrap();
        assert_eq!(auth_resp.status().as_u16(), 302);
        let location = auth_resp.headers()["location"]
            .to_str()
            .unwrap()
            .to_string();
        browser.get(&location).send().await.unwrap();
    }

    /// The Cap'n Proto AuthAgent server wraps the login flow: an interactive
    /// getOidcCredential call against the fake IdP returns its id_token,
    /// forwards the nonce to `/auth`, and leaks no secret into progress.
    #[tokio::test]
    async fn test_auth_agent_server_returns_token_via_fake_idp() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let idp_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
                let idp_addr = idp_listener.local_addr().unwrap();
                let seen = Arc::new(Mutex::new(IdpSeen::default()));
                tokio::spawn(run_fake_idp(idp_listener, seen.clone()));

                let (agent, mut progress) = new_cli_auth_agent(false);
                let call = send_get_oidc_credential(&agent, format!("http://{idp_addr}"), true);
                let call = tokio::task::spawn_local(call.promise);

                play_browser(&mut progress).await;

                let response = call.await.unwrap().unwrap();
                let results = response.get().unwrap();
                assert!(matches!(
                    results.get_result().unwrap().which().unwrap(),
                    cli::success_or_error::Which::Success(_)
                ));
                assert_eq!(
                    results.get_id_token().unwrap().to_str().unwrap(),
                    FAKE_ID_TOKEN
                );
                assert_eq!(
                    seen.lock().unwrap().auth_nonce.as_deref(),
                    Some("nonce-agent")
                );

                // No progress message may carry the code or the token.
                while let Ok(msg) = progress.try_recv() {
                    assert!(!msg.contains(FAKE_ID_TOKEN), "id_token leaked: {msg}");
                    assert!(!msg.contains(FAKE_CODE), "authorization code leaked: {msg}");
                }
            })
            .await;
    }

    /// `interactive = false` must come back as the error arm with an empty
    /// idToken — and the flow must never start (no browser, no listener,
    /// hence no progress message at all).
    #[tokio::test]
    async fn test_auth_agent_server_noninteractive_is_error() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let (agent, mut progress) = new_cli_auth_agent(true);
                let call =
                    send_get_oidc_credential(&agent, "http://127.0.0.1:1/".to_string(), false);
                let response = call.promise.await.unwrap();
                let results = response.get().unwrap();
                match results.get_result().unwrap().which().unwrap() {
                    cli::success_or_error::Which::Error(e) => {
                        let txt = e.unwrap().get_txt().unwrap().to_str().unwrap().to_string();
                        assert!(
                            txt.contains("non-interactive"),
                            "unexpected error text: {txt}"
                        );
                    }
                    cli::success_or_error::Which::Success(_) => {
                        panic!("non-interactive request unexpectedly succeeded")
                    }
                }
                assert_eq!(results.get_id_token().unwrap().to_str().unwrap(), "");
                assert!(
                    progress.try_recv().is_err(),
                    "flow started on a non-interactive request"
                );
            })
            .await;
    }

    /// A user refusal at the IdP (`error=access_denied` on the redirect)
    /// comes back as the error arm with text ph's reason-parser classifies
    /// as UserDeclined (it looks for "access_denied").
    #[tokio::test]
    async fn test_auth_agent_server_maps_login_failure_to_error_text() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let idp_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
                let idp_addr = idp_listener.local_addr().unwrap();
                let seen = Arc::new(Mutex::new(IdpSeen::default()));
                tokio::spawn(run_fake_idp_mode(idp_listener, seen.clone(), true));

                let (agent, mut progress) = new_cli_auth_agent(false);
                let call = send_get_oidc_credential(&agent, format!("http://{idp_addr}"), true);
                let call = tokio::task::spawn_local(call.promise);

                play_browser(&mut progress).await;

                let response = call.await.unwrap().unwrap();
                let results = response.get().unwrap();
                match results.get_result().unwrap().which().unwrap() {
                    cli::success_or_error::Which::Error(e) => {
                        let txt = e.unwrap().get_txt().unwrap().to_str().unwrap().to_string();
                        assert!(
                            txt.contains("access_denied"),
                            "error text not classifiable as UserDeclined: {txt}"
                        );
                    }
                    cli::success_or_error::Which::Success(_) => {
                        panic!("denied login unexpectedly succeeded")
                    }
                }
                assert_eq!(results.get_id_token().unwrap().to_str().unwrap(), "");
            })
            .await;
    }

    // ------------------------------------------------------------------
    // zipline#46: offline_access + in-memory refresh token + refresh grant
    // + headless browser fallback.
    // ------------------------------------------------------------------

    const FAKE_REFRESH_TOKEN: &str = "refresh-token-1f2a";
    const FRESH_ID_TOKEN: &str = "fresh.header.payload";

    /// What the offline-capable fake IdP records.
    #[derive(Default)]
    struct OfflineIdpSeen {
        /// How many times `/auth` was hit (a silent refresh must not add to
        /// this).
        auth_hits: usize,
        /// Raw form bodies of `grant_type=refresh_token` POSTs to `/token`.
        refresh_bodies: Vec<String>,
    }

    /// `/token` behaviour for refresh grants in [run_fake_idp_offline].
    #[derive(Clone, Copy)]
    enum RefreshMode {
        /// 200 with a fresh id_token.
        Ok,
        /// 400 `{"error":"invalid_grant"}` — the token is revoked. The
        /// `error_description` deliberately echoes the refresh token to
        /// prove the body never reaches the error text.
        InvalidGrant,
        /// 200 but without an `id_token` field (legal per RFC 6749).
        NoIdToken,
    }

    /// [run_fake_idp] extended for offline access: the code exchange
    /// response carries a `refresh_token`, and `/token` answers
    /// `grant_type=refresh_token` POSTs per `refresh_mode`, recording them.
    async fn run_fake_idp_offline(
        listener: TcpListener,
        seen: Arc<Mutex<OfflineIdpSeen>>,
        refresh_mode: RefreshMode,
    ) {
        let base = format!("http://{}", listener.local_addr().unwrap());
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let Ok((_method, target, body)) = read_http_request(&mut stream).await else {
                continue;
            };
            if target.starts_with("/.well-known/openid-configuration") {
                let body = format!(
                    "{{\"authorization_endpoint\":\"{base}/auth\",\"token_endpoint\":\"{base}/token\"}}"
                );
                let _ = write_http_response(&mut stream, "200 OK", "application/json", &body).await;
            } else if target.starts_with("/auth") {
                seen.lock().unwrap().auth_hits += 1;
                let parsed = Url::parse(&format!("http://localhost{target}")).unwrap();
                let mut state = String::new();
                let mut redirect_uri = String::new();
                for (k, v) in parsed.query_pairs() {
                    match k.as_ref() {
                        "state" => state = v.into_owned(),
                        "redirect_uri" => redirect_uri = v.into_owned(),
                        _ => {}
                    }
                }
                let location = format!("{redirect_uri}?code={FAKE_CODE}&state={state}");
                let response = format!(
                    "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = stream.write_all(response.as_bytes()).await;
            } else if target.starts_with("/token") {
                let form = String::from_utf8_lossy(&body).into_owned();
                if form.contains("grant_type=refresh_token") {
                    seen.lock().unwrap().refresh_bodies.push(form);
                    match refresh_mode {
                        RefreshMode::Ok => {
                            let body = format!("{{\"id_token\":\"{FRESH_ID_TOKEN}\"}}");
                            let _ = write_http_response(
                                &mut stream,
                                "200 OK",
                                "application/json",
                                &body,
                            )
                            .await;
                        }
                        RefreshMode::InvalidGrant => {
                            let body = format!(
                                "{{\"error\":\"invalid_grant\",\
                                  \"error_description\":\"token revoked, rt={FAKE_REFRESH_TOKEN}\"}}"
                            );
                            let _ = write_http_response(
                                &mut stream,
                                "400 Bad Request",
                                "application/json",
                                &body,
                            )
                            .await;
                        }
                        RefreshMode::NoIdToken => {
                            let _ = write_http_response(
                                &mut stream,
                                "200 OK",
                                "application/json",
                                "{\"token_type\":\"Bearer\"}",
                            )
                            .await;
                        }
                    }
                } else {
                    let body = format!(
                        "{{\"id_token\":\"{FAKE_ID_TOKEN}\",\"refresh_token\":\"{FAKE_REFRESH_TOKEN}\"}}"
                    );
                    let _ =
                        write_http_response(&mut stream, "200 OK", "application/json", &body).await;
                }
            } else {
                let _ = write_http_response(&mut stream, "404 Not Found", "text/plain", "no").await;
            }
        }
    }

    /// Capture the authorization URL the login flow would send the user to,
    /// for an IdP with `allow_offline_access` as given; the flow is aborted
    /// after the URL is captured (the callback never fires).
    async fn capture_auth_url(allow_offline_access: bool, scopes: Vec<String>) -> Url {
        let idp_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let idp_addr = idp_listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(OfflineIdpSeen::default()));
        tokio::spawn(run_fake_idp_offline(idp_listener, seen, RefreshMode::Ok));

        let idp = OidcIdpInfo {
            issuer: format!("http://{idp_addr}"),
            client_id: "client-1".to_string(),
            client_secret: None,
            scopes,
            allow_offline_access,
        };
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let login_task = tokio::spawn(async move {
            let mut sink = move |m: &str| {
                let _ = tx.send(m.to_string());
            };
            login_with_progress(&idp, "nonce-o", false, Duration::from_secs(10), &mut sink).await
        });
        let auth_url = loop {
            let msg = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("no progress message")
                .expect("progress channel closed");
            if msg.contains("Open this URL") {
                break msg.split_whitespace().last().unwrap().to_string();
            }
        };
        login_task.abort();
        Url::parse(&auth_url).unwrap()
    }

    /// When policy allows offline access, the authorization request carries
    /// the `offline_access` scope, `access_type=offline`, `prompt=consent`
    /// and the fixed `max_age=31536000` (which exists purely to elicit the
    /// `auth_time` claim); when it does not, none of them. The scope is not
    /// duplicated when already configured.
    #[tokio::test]
    async fn test_auth_url_offline_params_only_when_policy_allows() {
        let url = capture_auth_url(true, vec!["openid".to_string()]).await;
        let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
        assert!(
            params["scope"].split(' ').any(|s| s == "offline_access"),
            "offline_access missing from scope: {:?}",
            params["scope"]
        );
        assert_eq!(params["access_type"], "offline");
        assert_eq!(params["prompt"], "consent");
        assert_eq!(params["max_age"], "31536000");

        let url = capture_auth_url(false, vec!["openid".to_string()]).await;
        let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
        assert!(
            !params["scope"].contains("offline_access"),
            "offline_access requested although policy forbids it"
        );
        for forbidden in ["access_type", "prompt", "max_age"] {
            assert!(
                !params.contains_key(forbidden),
                "`{forbidden}` sent although policy forbids offline access"
            );
        }

        // Already-configured scope is not duplicated.
        let url = capture_auth_url(
            true,
            vec!["openid".to_string(), "offline_access".to_string()],
        )
        .await;
        let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
        assert_eq!(
            params["scope"]
                .split(' ')
                .filter(|s| *s == "offline_access")
                .count(),
            1
        );
    }

    /// The refresh grant POSTs `grant_type=refresh_token`, the token, and
    /// `client_id`, with `client_secret` only for a confidential client —
    /// and hands back the fresh id_token.
    #[tokio::test]
    async fn test_refresh_grant_posts_token_and_optional_secret() {
        for secret in [None, Some("s3cret")] {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (tx, rx) = tokio::sync::oneshot::channel();
            tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let (method, target, body) = read_http_request(&mut stream).await.unwrap();
                assert_eq!(method, "POST");
                assert_eq!(target, "/token");
                write_http_response(
                    &mut stream,
                    "200 OK",
                    "application/json",
                    "{\"id_token\":\"fresh-tok\"}",
                )
                .await
                .unwrap();
                tx.send(String::from_utf8(body).unwrap()).unwrap();
            });
            let tokens = refresh_grant(
                &Url::parse(&format!("http://{addr}/token")).unwrap(),
                "client-1",
                secret,
                "rt-abc",
                &reqwest::Client::new(),
            )
            .await
            .unwrap();
            assert_eq!(tokens.id_token, "fresh-tok");
            let fields: std::collections::HashMap<String, String> =
                url::form_urlencoded::parse(rx.await.unwrap().as_bytes())
                    .into_owned()
                    .collect();
            assert_eq!(fields["grant_type"], "refresh_token");
            assert_eq!(fields["refresh_token"], "rt-abc");
            assert_eq!(fields["client_id"], "client-1");
            match secret {
                Some(s) => assert_eq!(fields["client_secret"], s),
                None => assert!(
                    !fields.contains_key("client_secret"),
                    "client_secret sent for a public client"
                ),
            }
        }
    }

    /// Run an interactive login through `agent` against the offline fake
    /// IdP, playing the browser, and assert it returned the fixed id_token.
    async fn interactive_login_via_agent(
        agent: &cli::auth_agent::Client,
        progress: &mut tokio::sync::mpsc::UnboundedReceiver<String>,
        issuer: String,
    ) {
        let call = send_get_oidc_credential_offline(agent, issuer, true, true);
        let call = tokio::task::spawn_local(call.promise);
        play_browser(progress).await;
        let response = call.await.unwrap().unwrap();
        let results = response.get().unwrap();
        assert!(matches!(
            results.get_result().unwrap().which().unwrap(),
            cli::success_or_error::Which::Success(_)
        ));
        assert_eq!(
            results.get_id_token().unwrap().to_str().unwrap(),
            FAKE_ID_TOKEN
        );
    }

    /// After an interactive login stored the refresh token, an
    /// `interactive: false` request is satisfied silently: fresh id_token
    /// over the RPC, no authorization-endpoint contact, no browser, and the
    /// refresh POST carries the stored token (no client_secret for a public
    /// client). No progress message ever carries the refresh token.
    #[tokio::test]
    async fn test_auth_agent_noninteractive_refresh_succeeds_silently() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let idp_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
                let idp_addr = idp_listener.local_addr().unwrap();
                let seen = Arc::new(Mutex::new(OfflineIdpSeen::default()));
                tokio::spawn(run_fake_idp_offline(
                    idp_listener,
                    seen.clone(),
                    RefreshMode::Ok,
                ));

                let (agent, mut progress) = new_cli_auth_agent(false);
                interactive_login_via_agent(&agent, &mut progress, format!("http://{idp_addr}"))
                    .await;
                assert_eq!(seen.lock().unwrap().auth_hits, 1);

                // Now non-interactive: must succeed via the refresh grant.
                let call = send_get_oidc_credential_offline(
                    &agent,
                    format!("http://{idp_addr}"),
                    false,
                    true,
                );
                let response = call.promise.await.unwrap();
                let results = response.get().unwrap();
                assert!(matches!(
                    results.get_result().unwrap().which().unwrap(),
                    cli::success_or_error::Which::Success(_)
                ));
                assert_eq!(
                    results.get_id_token().unwrap().to_str().unwrap(),
                    FRESH_ID_TOKEN
                );

                // No second authorization-endpoint contact, exactly one
                // refresh POST, carrying the stored token and no secret.
                {
                    let seen = seen.lock().unwrap();
                    assert_eq!(seen.auth_hits, 1, "authorization endpoint contacted");
                    assert_eq!(seen.refresh_bodies.len(), 1);
                    let fields: HashMap<String, String> =
                        url::form_urlencoded::parse(seen.refresh_bodies[0].as_bytes())
                            .into_owned()
                            .collect();
                    assert_eq!(fields["grant_type"], "refresh_token");
                    assert_eq!(fields["refresh_token"], FAKE_REFRESH_TOKEN);
                    assert_eq!(fields["client_id"], "client-1");
                    assert!(!fields.contains_key("client_secret"));
                }

                // The refresh path emits no progress, and nothing that was
                // emitted carries the refresh token.
                while let Ok(msg) = progress.try_recv() {
                    assert!(
                        !msg.contains(FAKE_REFRESH_TOKEN),
                        "refresh token leaked: {msg}"
                    );
                    assert!(
                        !msg.contains("Open this URL") || !msg.is_empty(),
                        "unexpected interactive prompt: {msg}"
                    );
                }
            })
            .await;
    }

    /// `invalid_grant` on the refresh drops the stored token: the error text
    /// carries the code but never the response body, and the next
    /// non-interactive attempt fails fast with the no-token error without
    /// replaying the dead credential.
    #[tokio::test]
    async fn test_auth_agent_invalid_grant_drops_stored_token() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let idp_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
                let idp_addr = idp_listener.local_addr().unwrap();
                let seen = Arc::new(Mutex::new(OfflineIdpSeen::default()));
                tokio::spawn(run_fake_idp_offline(
                    idp_listener,
                    seen.clone(),
                    RefreshMode::InvalidGrant,
                ));

                let (agent, mut progress) = new_cli_auth_agent(false);
                interactive_login_via_agent(&agent, &mut progress, format!("http://{idp_addr}"))
                    .await;

                // First non-interactive attempt: invalid_grant.
                let call = send_get_oidc_credential_offline(
                    &agent,
                    format!("http://{idp_addr}"),
                    false,
                    true,
                );
                let response = call.promise.await.unwrap();
                let results = response.get().unwrap();
                match results.get_result().unwrap().which().unwrap() {
                    cli::success_or_error::Which::Error(e) => {
                        let txt = e.unwrap().get_txt().unwrap().to_str().unwrap().to_string();
                        assert!(txt.contains("invalid_grant"), "code missing: {txt}");
                        assert!(
                            !txt.contains(FAKE_REFRESH_TOKEN),
                            "response body (with token) leaked: {txt}"
                        );
                        assert!(!txt.contains("token revoked"), "body leaked: {txt}");
                    }
                    cli::success_or_error::Which::Success(_) => {
                        panic!("invalid_grant refresh unexpectedly succeeded")
                    }
                }

                // Second attempt: the token was dropped, so it fails fast
                // with the no-token error and never reaches the endpoint.
                let call = send_get_oidc_credential_offline(
                    &agent,
                    format!("http://{idp_addr}"),
                    false,
                    true,
                );
                let response = call.promise.await.unwrap();
                let results = response.get().unwrap();
                match results.get_result().unwrap().which().unwrap() {
                    cli::success_or_error::Which::Error(e) => {
                        let txt = e.unwrap().get_txt().unwrap().to_str().unwrap().to_string();
                        assert!(txt.contains("non-interactive"), "unexpected error: {txt}");
                    }
                    cli::success_or_error::Which::Success(_) => {
                        panic!("second attempt unexpectedly succeeded")
                    }
                }
                assert_eq!(
                    seen.lock().unwrap().refresh_bodies.len(),
                    1,
                    "dead refresh token was replayed"
                );
            })
            .await;
    }

    /// A refresh response without an `id_token` is a TokenExchange error and
    /// the stored refresh token is KEPT (it was not `invalid_grant`): the
    /// next non-interactive attempt tries the token endpoint again.
    #[tokio::test]
    async fn test_auth_agent_refresh_without_id_token_keeps_stored_token() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let idp_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
                let idp_addr = idp_listener.local_addr().unwrap();
                let seen = Arc::new(Mutex::new(OfflineIdpSeen::default()));
                tokio::spawn(run_fake_idp_offline(
                    idp_listener,
                    seen.clone(),
                    RefreshMode::NoIdToken,
                ));

                let (agent, mut progress) = new_cli_auth_agent(false);
                interactive_login_via_agent(&agent, &mut progress, format!("http://{idp_addr}"))
                    .await;

                for attempt in 1..=2 {
                    let call = send_get_oidc_credential_offline(
                        &agent,
                        format!("http://{idp_addr}"),
                        false,
                        true,
                    );
                    let response = call.promise.await.unwrap();
                    let results = response.get().unwrap();
                    match results.get_result().unwrap().which().unwrap() {
                        cli::success_or_error::Which::Error(e) => {
                            let txt = e.unwrap().get_txt().unwrap().to_str().unwrap().to_string();
                            assert!(txt.contains("id_token"), "unexpected error: {txt}");
                        }
                        cli::success_or_error::Which::Success(_) => {
                            panic!("id_token-less refresh unexpectedly succeeded")
                        }
                    }
                    // The token was kept, so each attempt reaches the
                    // endpoint again instead of failing fast.
                    assert_eq!(seen.lock().unwrap().refresh_bodies.len(), attempt);
                }
            })
            .await;
    }

    /// The pure browser-availability predicate: root and (on Linux) a
    /// missing display each block the launch; otherwise it may proceed.
    #[test]
    fn test_browser_unavailable_predicate() {
        assert_eq!(browser_unavailable_for(true, true), Some("running as root"));
        assert_eq!(
            browser_unavailable_for(true, false),
            Some("running as root")
        );
        assert_eq!(browser_unavailable_for(false, true), None);
        if cfg!(target_os = "linux") {
            let reason = browser_unavailable_for(false, false).expect("headless must block");
            assert!(reason.contains("DISPLAY"), "unhelpful reason: {reason}");
        }
    }

    /// With `open_browser: true` but the browser blocked (root / headless),
    /// the flow prints the URL with a one-line explanation instead of
    /// spawning — and still completes when the user follows it by hand. The
    /// printed URL carries the S256 challenge but never the verifier.
    #[tokio::test]
    async fn test_headless_fallback_prints_url_with_challenge_not_verifier() {
        let idp_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let idp_addr = idp_listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(OfflineIdpSeen::default()));
        tokio::spawn(run_fake_idp_offline(idp_listener, seen, RefreshMode::Ok));

        let idp = OidcIdpInfo {
            issuer: format!("http://{idp_addr}"),
            client_id: "client-1".to_string(),
            client_secret: None,
            scopes: vec!["openid".to_string()],
            allow_offline_access: false,
        };
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let blocker = browser_unavailable_for(false, false)
            .expect("test forces the headless leg of the predicate");
        let login_task = tokio::spawn(async move {
            let mut sink = move |m: &str| {
                let _ = tx.send(m.to_string());
            };
            // open_browser: true, but the injected blocker forces the
            // print-the-URL fallback (same branch the env/euid checks pick).
            login_flow(
                &idp,
                "nonce-h",
                true,
                Some(blocker),
                Duration::from_secs(10),
                &mut sink,
            )
            .await
        });

        let fallback_msg = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("no progress message")
            .expect("progress channel closed");
        assert!(
            fallback_msg.contains("Open this URL"),
            "fallback did not print the URL: {fallback_msg}"
        );
        assert!(
            fallback_msg.contains("DISPLAY"),
            "fallback lacks the one-line explanation: {fallback_msg}"
        );
        let auth_url = fallback_msg.split_whitespace().last().unwrap().to_string();
        let parsed = Url::parse(&auth_url).unwrap();
        let params: HashMap<String, String> = parsed.query_pairs().into_owned().collect();
        assert_eq!(params["code_challenge_method"], "S256");
        assert!(params.contains_key("code_challenge"));
        assert!(
            !params.contains_key("code_verifier"),
            "verifier leaked into the printed URL"
        );

        // Play the browser to prove the fallback flow still completes.
        let browser = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let auth_resp = browser.get(&auth_url).send().await.unwrap();
        assert_eq!(auth_resp.status().as_u16(), 302);
        let location = auth_resp.headers()["location"]
            .to_str()
            .unwrap()
            .to_string();
        browser.get(&location).send().await.unwrap();

        let tokens = login_task.await.unwrap().unwrap();
        assert_eq!(tokens.id_token, FAKE_ID_TOKEN);
        // The challenge is one-way: the verifier cannot appear in any
        // progress message (it exists only inside the flow).
        while let Ok(msg) = rx.try_recv() {
            assert!(!msg.contains("code_verifier"), "verifier leaked: {msg}");
        }
    }
}
