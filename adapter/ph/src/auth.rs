//! This module implements the bootstrap authentication scheme which is used
//! when we need to join a ZPRnet but there are no authentication services
//! attached yet.  Also includes other "auth" related functionality.

use aws_lc_rs::signature::RsaKeyPair;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use zerocopy::byteorder::network_endian::*;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use reqwest::StatusCode;
use reqwest::header;
use reqwest::redirect::Policy;
use reqwest::tls::Certificate;

use base64::prelude::*;
use thiserror::Error;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use x509_cert::Certificate as X509Certificate;
use zpr_utils::rsa_sign::{load_rsa_key, sign_rsa_key};

use crate::pki;

/// When a node signs a challenge for an adapter it uses this sort of key.
pub const AUTH_KEY_SIZE_BYTES: usize = 32; // blake3 256bit key

/// "self signed" blob type
pub const BLOB_TYPE_SS: &str = "SS";

/// Auth Code blob type
pub const BLOB_TYPE_AC: &str = "AC";

/// OIDC blob type
pub const BLOB_TYPE_OIDC: &str = "OIDC";

/// When checking a challenge returned to a node by an adapter, it may
/// be no older than this.
pub const MAX_BLOB_AGE_SECONDS: u64 = 120; // 2 minutes

/// OIDC-specific challenge freshness window. The challenge is issued before
/// the end user completes the OIDC browser flow, which is allowed up to
/// OIDC_USER_INTERACTION_TIMEOUT (300 s, D2); this bound must cover that plus
/// margin, consistent with ACTOR_AUTHENTICATION_TIMEOUT (330 s).
pub const MAX_OIDC_BLOB_AGE_SECONDS: u64 = 330;

// TODO: Not sure how we get these out or if we need them.
pub const HARD_CODED_BAS_TLS_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIFmzCCA4OgAwIBAgIUJSg4OHOfPqY+lD7ymZy6akX/ZZ8wDQYJKoZIhvcNAQEL
BQAwXTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAktZMRMwEQYDVQQHDApMb3Vpc3Zp
bGxlMQswCQYDVQQKDAJBSTEMMAoGA1UECwwDWlBSMREwDwYDVQQDDAhhdXRoLnpw
cjAeFw0yNTA0MTYxOTQ4MjRaFw0yNjA0MTYxOTQ4MjRaMF0xCzAJBgNVBAYTAlVT
MQswCQYDVQQIDAJLWTETMBEGA1UEBwwKTG91aXN2aWxsZTELMAkGA1UECgwCQUkx
DDAKBgNVBAsMA1pQUjERMA8GA1UEAwwIYXV0aC56cHIwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQDl6DwVoQJsWAOTK4JWZYp3YL7b647ypIadVioKaGAk
1Fk4FwogcZG/tBqsxCCW+pv7FXfjbwp6ChrxUGaTZUGzF5ft5L7q4oqSKOHvL1i9
DiyU3xwk/biMiPTyuB8YYIiwQDiHAtYncJVMGMJPefDTl8OPNsjGQyJI+xuoBP/n
PhbNIgn6E8YxrNl0/u+xWHjM6iOe5bZhXH1nkJQ+hviTxAtRDfayGM0nXrkEzdkC
Aav95Kgp91cIa2lgoPpHm+HwQANp8jEPvsTVFMbwlPuFx9nopyXLzAdkgv9Z3+S3
W9ISFWdaAQ4TJDrWfAQyPgPy8UPLOzoK/TC9qbRx2QLQaY3v6+hurnWUm0cHAZ5n
zs8KflWXfRR+DA3Vc4aDF5vhT0IBDxs5rGu3/gtlJKwfwzMGDtprtuAXpXyZ48yM
f17WymXsamWDIN58cHjPWgLYoUsr87HtRFGVmlqvCBzaQf4zGCOoW5LWSlkzD2da
6ak3xBbogGExSk7RAhi9XLCl0LKfjTRsEGuAKpbGvt4h8i2Bq5YLmrzrqzI5XDYt
u3W1hWwSwwAzK6SHvYLyOMTI75UMy9Zsh4VoUJUNkYm4XgO0WFaA9bs5Cq73d1zY
i70s8jccheYhoAVXOWLDBQxCu2beHR7tkNXwyZ/RBhL/4/tyc+FKzF6C9sE9f6hv
EQIDAQABo1MwUTAdBgNVHQ4EFgQU+bscgkfPxWQLdX4AypBqXnzmvxwwHwYDVR0j
BBgwFoAU+bscgkfPxWQLdX4AypBqXnzmvxwwDwYDVR0TAQH/BAUwAwEB/zANBgkq
hkiG9w0BAQsFAAOCAgEASZvKIbzeXKd1WuMmZT7kCywYqmWfgo7O51VNWni3FLdQ
5De44BGIOVUFn+0vC0xQQbQ4iM9yTMb27AQJGm9Aor92w9G7LvR6Mp5py16eJb+F
MSMZwN7PqK/QdnbIwiUGplDkKndd1dA/ZcHg5oJdE1areX0Zw8ZZ5yZoO12xnhc4
AK2Mop897EGSYHyrxidYbocPj5Bn7m3mVC7U2quh1HwnZzbWfpx9g8Ry4T8kUco3
dwZa2RHWhy2yrky2t3pg5tqaw79f/pXoTkcxvRSwZU3EcY23rq5OYQc7SLBIMm/a
n8ZSJIduRRTLNE7T6Y7o43jDU8u+tcfB5ZE9ytuJA/NgtIYeEiNHMRepYNI2pffj
MGELMS4xR3NIEyA6ZGVRBnI4dDr/3AmliOKKSt77iueSYCaPDBaxbbwcvEBBJtB0
TPzKFsY5IH5ve5pZu7IhHIbE/yrAicbNtfX487WQTZfY+Qo8bf+XbdQIcRzkD+Q4
VAvgJld9s5RI6x8CocU/PQvtQcWPFj//SbnnaMv2TTMLYgP+XWFwD1K1WQFpx2PK
YM6AGtFc6p9klbags4r80QK+yEwYiBaNjDKmiNfQ1J38HCmd9lnMbzt9p7T838fP
FiCJxns37RAqhGyryo9L0cryIEPwerjtNoLxmg94rfdovRmY+pm+HokRbD4Vycw=
-----END CERTIFICATE-----
"#;

/// This is the data payload in a [zdp::PacketType::InitAuthenticationRequest] packet.
#[derive(Clone, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned, Default)]
#[repr(packed)]
pub struct ZdpInitAuthenticationPayload {
    /// 8 bytes random data
    pub nonce: [u8; 8],

    /// Unix time seconds, big endian
    pub ctime: U64,

    /// blake3 hmac over nonce and ctime
    pub hmac: [u8; 32],
}

// Implement our own Debug to format the buffers in human friendly way.
impl std::fmt::Debug for ZdpInitAuthenticationPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let nonce_str = self
            .nonce
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<String>>()
            .join("");
        let hmac_str = self
            .hmac
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<String>>()
            .join("");
        write!(
            f,
            "ZdpInitAuthenticationPayload {{ nonce: [{}], ctime: {}, hmac: [{}] }}",
            nonce_str,
            self.ctime.get(),
            hmac_str,
        )
    }
}

/// The "self signed" authentication BLOB which originates on an adatper and is
/// passed to a node via a [zdp::PacketType::AcquireZprAddressRequest]
/// message.
///
/// Note that this passed around as JSON text encoded in base64.
#[derive(Serialize, Deserialize, Debug)]
pub struct ZdpSelfSignedBlob {
    pub blob_type: String, // "SS"
    pub ts: u64,
    pub cn: String,
    pub challenge: String, // byte buffer, base64 encoded
    pub sig: String,       // byte buffer, base64 encoded
}

/// The "Auth Code" authentication BLOB which originates on an adatper and is
/// passed to a node via a [zdp::PacketType::AcquireZprAddressRequest]
/// message.
///
/// Note that this passed around as JSON text encoded in base64.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ZdpAuthCodeBlob {
    pub blob_type: String, // "AC"
    pub code: String,
    pub pkce: String,
    pub client_id: String,
    pub asa: String,
}

/// The OIDC authentication BLOB which originates on an adapter and is passed
/// to a node via a [zdp::PacketType::AcquireZprAddressRequest] message.
///
/// Carries an OIDC ID token from an off-net identity provider plus the node's
/// init-auth challenge, binding the token presentation to this link.
///
/// Note that this passed around as JSON text encoded in base64.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ZdpOidcBlob {
    pub blob_type: String, // "OIDC"
    /// Issuer URL of the identity provider that minted `id_token`.
    pub issuer: String,
    /// The OIDC ID token (JWT) as obtained from the IdP.
    pub id_token: String,
    /// The node's init-auth challenge (nonce, ctime, hmac), base64 encoded.
    pub challenge: String,
}

/// Enum used to return different blob types based on their blob_type field.
#[allow(dead_code)]
#[derive(Debug)]
pub enum AuthBlob {
    SelfSigned(ZdpSelfSignedBlob),
    AuthCode(ZdpAuthCodeBlob),
    Oidc(ZdpOidcBlob),
}

/// What a client adapter needs to talk to an off-net OIDC identity provider.
/// Advertised by the node in HelloResponse via `OIDC_IDP` TLVs (JSON encoded);
/// mirrors the visa service's `OidcClientConfig`. All public data.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OidcIdpInfo {
    pub issuer: String,
    pub client_id: String,
    /// `None` for public clients (RFC 8252 s8.5); not a secret when present.
    pub client_secret: Option<String>,
    pub scopes: Vec<String>,
    pub allow_offline_access: bool,
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("OpenSSL Error: {0}")]
    OpenSSLError(String),

    #[error("I/O Error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("Serialization Error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Format error: {0}")]
    FormatError(String),

    #[error("Invalid Base64: {0}")]
    DecodeError(#[from] base64::DecodeError),

    #[error("Invalid HMAC")]
    InvalidHmac,

    #[error("Challenge Too Old")]
    ChallengeTooOld,

    #[error("Authentication Error: {0}")]
    AuthError(String),
}

#[derive(Debug, Clone)]
pub struct RsaBootstrapAuth {
    pkey: Arc<RsaKeyPair>,
    cn: String,
}

/// OAuthRsa holds small amount of state needed to talk to a
/// zpr-oauthrsa authentication service.
#[derive(Debug, Clone)]
pub struct OAuthRsa {
    client_id: String,
    private_key: Arc<RsaKeyPair>,
}

impl ZdpAuthCodeBlob {
    /// Gets the "encoded" form of the blob: base64 encoded JSON.
    pub fn encode(&self) -> String {
        let json_txt = serde_json::to_string(self).unwrap();
        BASE64_STANDARD.encode(&json_txt)
    }
}

impl ZdpSelfSignedBlob {
    /// Gets the "encoded" form of the blob: base64 encoded JSON.
    pub fn encode(&self) -> String {
        let json_txt = serde_json::to_string(self).unwrap();
        BASE64_STANDARD.encode(&json_txt)
    }

    /// The `challenge` field in the blob is a base64 encoded [zdp::ZdpInitAuthenticationPayload].
    /// This extracts that data and checks that:
    ///   - If the peer presented a certificate during keying, the CN in that
    ///     certificate matches the CN in the blob. Adapters using self-generated
    ///     keys send no certificate (`peer_cert` is `None`); there is then no
    ///     cert CN to bind to, so this check is skipped and the blob CN is
    ///     authenticated solely by the visa service's RSA signature check.
    ///   - The HMAC in the blob is valid for the provided `key`.
    ///   - The blob is not older than `MAX_BLOB_AGE_SECONDS`.
    pub fn verify_blob_challenge(
        &self,
        peer_cert: Option<&X509Certificate>,
        key: &[u8; AUTH_KEY_SIZE_BYTES],
    ) -> Result<(), AuthError> {
        if let Some(peer_cert) = peer_cert {
            if let Some(link_cn) = pki::common_name(peer_cert) {
                if link_cn != self.cn {
                    return Err(AuthError::FormatError(format!(
                        "CN mismatch: expected {link_cn} found {}",
                        self.cn
                    )));
                }
            } else {
                return Err(AuthError::FormatError("no CN in peer cert".to_string()));
            }
        }

        let payload_bytes = BASE64_STANDARD.decode(self.challenge.clone())?;
        verify_challenge_bytes(&payload_bytes, key, MAX_BLOB_AGE_SECONDS)?;
        Ok(())
    }
}

impl ZdpOidcBlob {
    /// Gets the "encoded" form of the blob: base64 encoded JSON.
    #[allow(dead_code)]
    pub fn encode(&self) -> String {
        let json_txt = serde_json::to_string(self).unwrap();
        BASE64_STANDARD.encode(&json_txt)
    }

    /// The `challenge` field in the blob is a base64 encoded
    /// [ZdpInitAuthenticationPayload]. This extracts that data and checks that:
    ///   - The HMAC in the challenge is valid for the provided `key`.
    ///   - The challenge is not older than `MAX_OIDC_BLOB_AGE_SECONDS` — the
    ///     OIDC window, not `MAX_BLOB_AGE_SECONDS`: the challenge is issued
    ///     before the user completes the browser flow, so the bound must cover
    ///     the permitted user-interaction time.
    ///
    /// Unlike [ZdpSelfSignedBlob::verify_blob_challenge] there is no CN leg:
    /// an OIDC blob carries no CN, identity comes from the ID token which the
    /// visa service verifies.
    ///
    /// On success, returns the verified challenge bytes so the caller can
    /// derive the OIDC nonce from data it has authenticated.
    pub fn verify_challenge(&self, key: &[u8; AUTH_KEY_SIZE_BYTES]) -> Result<[u8; 48], AuthError> {
        let payload_bytes = BASE64_STANDARD.decode(self.challenge.clone())?;
        verify_challenge_bytes(&payload_bytes, key, MAX_OIDC_BLOB_AGE_SECONDS)?;
        let mut challenge = [0u8; 48];
        challenge.copy_from_slice(&payload_bytes);
        Ok(challenge)
    }
}

/// Shared challenge-verification core: checks that `payload_bytes` is a
/// well-formed [ZdpInitAuthenticationPayload] (48 bytes), that its HMAC is
/// valid for `key`, and that it is not older than `max_age_seconds`.
fn verify_challenge_bytes(
    payload_bytes: &[u8],
    key: &[u8; AUTH_KEY_SIZE_BYTES],
    max_age_seconds: u64,
) -> Result<(), AuthError> {
    if payload_bytes.len() != size_of::<ZdpInitAuthenticationPayload>() {
        return Err(AuthError::FormatError(
            "challenge size is incorrect".to_string(),
        ));
    }
    let zpayload = match ZdpInitAuthenticationPayload::read_from_bytes(payload_bytes) {
        Ok(zpayload) => zpayload,
        Err(e) => {
            return Err(AuthError::FormatError(format!(
                "failed to deserialize ZdpInitAuthenticationPayload: {e}"
            )));
        }
    };

    let hash_ok = {
        let mut hasher = blake3::Hasher::new_keyed(key);
        hasher.update(&zpayload.nonce);
        hasher.update(&zpayload.ctime.to_bytes());
        let computed_hmac = hasher.finalize();
        let presented_hmac = blake3::Hash::from_bytes(zpayload.hmac);
        computed_hmac == presented_hmac
    };

    if !hash_ok {
        return Err(AuthError::InvalidHmac);
    }

    // Now can check age of blob.
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u64;

    if now > zpayload.ctime.get() + max_age_seconds {
        return Err(AuthError::ChallengeTooOld);
    }

    Ok(())
}

/// The OIDC `nonce` claim binding an ID token to a link challenge:
/// base64url (no padding) of the SHA-256 of the raw challenge bytes.
pub fn oidc_nonce_for_challenge(challenge: &[u8; 48]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(challenge);
    BASE64_URL_SAFE_NO_PAD.encode(digest)
}

impl ZdpInitAuthenticationPayload {
    pub fn new(key: &[u8; AUTH_KEY_SIZE_BYTES]) -> Self {
        let ctime = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u64;
        let be_time = ctime.to_be_bytes();
        let mut nonce = [0u8; 8];
        aws_lc_rs::rand::fill(&mut nonce).expect("failed to generate random bytes for nonce");
        let mut hasher = blake3::Hasher::new_keyed(&key);
        hasher.update(&nonce);
        hasher.update(&be_time);
        let hmac = hasher.finalize();
        ZdpInitAuthenticationPayload {
            nonce,
            ctime: ctime.into(),
            hmac: hmac.into(),
        }
    }
}

/// Decode a single JSON blob object (already parsed) into an [AuthBlob],
/// dispatching on its "blob_type" field.
fn decode_blob_value(jobj: &Value) -> Result<AuthBlob, AuthError> {
    let blob_type = jobj.get("blob_type").ok_or_else(|| {
        AuthError::FormatError(format!("missing blob_type field in blob: {}", jobj))
    })?;

    match blob_type.as_str() {
        Some(BLOB_TYPE_SS) => {
            let ss_blob = serde_json::from_value::<ZdpSelfSignedBlob>(jobj.clone())?;
            Ok(AuthBlob::SelfSigned(ss_blob))
        }
        Some(BLOB_TYPE_AC) => {
            let ac_blob = serde_json::from_value::<ZdpAuthCodeBlob>(jobj.clone())?;
            Ok(AuthBlob::AuthCode(ac_blob))
        }
        Some(BLOB_TYPE_OIDC) => {
            let oidc_blob = serde_json::from_value::<ZdpOidcBlob>(jobj.clone())?;
            Ok(AuthBlob::Oidc(oidc_blob))
        }
        _ => Err(AuthError::FormatError(format!(
            "unknown blob_type: {:?}",
            blob_type
        ))),
    }
}

/// Decode a blob string into a list of [AuthBlob] objects.
///
/// The blob string is base64 encoded JSON: either a single blob object
/// (the legacy encoding) or a non-empty top-level array of blob objects. A
/// bare object decodes to a one-element list. An empty array or any element
/// with an unknown or missing `blob_type` fails the whole decode: every
/// accepted request must carry authentication material.
pub fn decode_blobs(blob_str: &str) -> Result<Vec<AuthBlob>, AuthError> {
    let json_txt = BASE64_STANDARD.decode(blob_str)?;

    let jval: Value = serde_json::from_slice(&json_txt)?;
    match jval {
        Value::Array(items) => {
            if items.is_empty() {
                return Err(AuthError::FormatError("empty blob array".to_string()));
            }
            items.iter().map(decode_blob_value).collect()
        }
        obj => Ok(vec![decode_blob_value(&obj)?]),
    }
}

/// Encode a list of [AuthBlob] objects as a blob string:
/// base64 encoded JSON, always a top-level array.
#[allow(dead_code)]
pub fn encode_blobs(blobs: &[AuthBlob]) -> String {
    let values: Vec<Value> = blobs
        .iter()
        .map(|blob| match blob {
            AuthBlob::SelfSigned(ss) => serde_json::to_value(ss).unwrap(),
            AuthBlob::AuthCode(ac) => serde_json::to_value(ac).unwrap(),
            AuthBlob::Oidc(oidc) => serde_json::to_value(oidc).unwrap(),
        })
        .collect();
    let json_txt = serde_json::to_string(&Value::Array(values)).unwrap();
    BASE64_STANDARD.encode(&json_txt)
}

/// Implementes BootstrapAuth using our RSA signature scheme.
impl RsaBootstrapAuth {
    /// Create a new RsaBootstrapAuth object.
    /// The `cn` is the common name of the actor.
    /// The `rsa_keyfile` is the path to the PEM file containing the RSA private key.
    /// The visa service (policy) must be configured with the corresponding public key.
    pub fn new(cn: &str, rsa_keyfile: &Path) -> Result<Self, AuthError> {
        let pemdata = std::fs::read(rsa_keyfile)?;
        let pkey = Arc::new(
            load_rsa_key(&pemdata)
                .map_err(|e| AuthError::OpenSSLError(format!("Failed to load RSA key: {}", e)))?,
        );
        Ok(RsaBootstrapAuth {
            pkey,
            cn: cn.to_string(),
        })
    }

    /// The returned string is a "SelfSignedBlob" object serialized to JSON and then base64 encoded.
    ///
    /// The signature here is created by signing:
    ///  - the current timestamp (in seconds since the epoch)
    ///  - the common name (cn) of the actor
    ///  - the challenge from the ZDP server, which is the (nonce, ctime, hmac) all concatentated
    ///    together in a byte buffer.
    pub fn authenticate(
        &self,
        payload: &ZdpInitAuthenticationPayload,
    ) -> Result<String, AuthError> {
        // TODO: Check the payload.flags?
        // TODO: This could be an impl function in zdp
        let mut challenge = [0u8; 48];
        challenge[0..8].copy_from_slice(&payload.nonce);
        challenge[8..16].copy_from_slice(&payload.ctime.to_bytes());
        challenge[16..48].copy_from_slice(&payload.hmac);

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u64;

        let mut data = Vec::new();
        data.extend_from_slice(&ts.to_be_bytes());
        data.extend_from_slice(self.cn.as_bytes());
        data.extend_from_slice(&challenge);

        let signature = sign_rsa_key(&self.pkey, &data);

        let sig_str = BASE64_STANDARD.encode(&signature);

        let blob = ZdpSelfSignedBlob {
            blob_type: BLOB_TYPE_SS.to_string(),
            ts,
            cn: self.cn.clone(),
            challenge: BASE64_STANDARD.encode(&challenge),
            sig: sig_str,
        };
        Ok(blob.encode())
    }

    #[cfg(test)]
    pub fn cn(&self) -> &str {
        &self.cn
    }
}

/// Response json object to initial auth request from an actor
/// from a zpr-oauthrsa authentication service.
#[derive(Deserialize, Debug)]
struct PreauthResp {
    nonce: String,
}

/// Request json object from an actor to a zpr-oauthrsa authentication service.
/// Includes the nonce from preauth step and the payload which is the RSA
/// signature of the nonce.  The `client_id` must match one known to the
/// authentication service (for now we are using CNs here).
#[derive(Serialize, Debug)]
struct AuthReq {
    client_id: String,
    nonce: String,
    payload: String,
}

/// Implements the ZPR oauthrsa protocol.
///
/// Works like this:
/// - Adapter sends a GET request to /preauthorize with form encoded params in query string
///   of (response_type, client_id, scope, state).
/// - Service returns json object with a "nonce" field, a base64 encoded byte buffer.
/// - Adapter sends a POST to /authorize with a json object having fields: (client_id, nonce, payload).
///   `nonce` is copied from the service response.  `payload` is the base64 encoded signature of
///   the nonce using the adapters private RSA key.  The `client_id` (in the case of BAS) is
///   the CN of the adapter.
/// - The service response with an auth-code which will be part of a redirect `location` header.
///   The format is `https://auth.zpr?code=<CODE>`).
///
/// Once we have an auth-code back from the authentication service we can construct the
/// auth-code blob as:
/// - blob_type: "AC"
/// - code: "<CODE>" (the auth-code)
/// - pkce: empty for now
/// - client_id: the CN of the adapter
/// - asa: The ZPR address of the authentication service
///
/// The blob should be passed to the Node which will forward it to the visa service.
impl OAuthRsa {
    /// Create a new OAuthRsa object.
    /// - `client_id` is the adapter CN
    /// - `private_key` is the RSA private key used to sign the nonce
    pub fn new(client_id: &str, private_key: Arc<RsaKeyPair>) -> Self {
        OAuthRsa {
            client_id: client_id.to_string(),
            private_key,
        }
    }

    /// Performs the two calls to the authentication service and the signing of the nonce.
    /// On success returns the auth-code blob.
    /// - `service_addr` is the address of the authentication service
    /// - `tls_cert` is the TLS certificate used by the authentication service
    pub async fn authenticate(
        &self,
        service_addr: SocketAddr,
        tls_cert: X509Certificate,
    ) -> Result<ZdpAuthCodeBlob, AuthError> {
        let der = pki::to_der(&tls_cert)
            .map_err(|e| AuthError::FormatError(format!("cannot encode TLS certificate: {e}")))?;
        let tls_cert = Certificate::from_der(&der).unwrap();

        let nonce_buf = self.preauthorize(service_addr, &tls_cert).await?;

        let signature = sign_rsa_key(&self.private_key, &nonce_buf);

        let auth_code = self
            .authorize(service_addr, &tls_cert, &nonce_buf, &signature)
            .await?;

        Ok(ZdpAuthCodeBlob {
            blob_type: BLOB_TYPE_AC.to_string(),
            code: auth_code,
            pkce: String::new(),
            client_id: self.client_id.clone(),
            asa: service_addr.to_string(),
        })
    }

    /// Call preauthorize function on authentication service.
    /// Returns the nonce.
    async fn preauthorize(
        &self,
        service_addr: SocketAddr,
        tls_cert: &Certificate,
    ) -> Result<Vec<u8>, AuthError> {
        // See https://github.com/org-zpr/zpr-core/issues/861
        let cb = reqwest::ClientBuilder::new()
            .add_root_certificate(tls_cert.clone())
            .danger_accept_invalid_certs(true) // TODO: Figure this TLS stuff out and get rid of this
            .timeout(std::time::Duration::from_secs(10));
        let client = cb.build().unwrap();

        let resp = client
            .get(format!("https://{}/preauthorize", service_addr))
            .query(&[("response_type", "code"), ("client_id", &self.client_id)])
            .send()
            .await
            .map_err(|e| AuthError::AuthError(format!("failed to send request: {}", e)))?;

        let pa_resp: PreauthResp = resp
            .json()
            .await
            .map_err(|e| AuthError::AuthError(format!("failed to parse response: {}", e)))?;

        Ok(BASE64_STANDARD.decode(pa_resp.nonce.as_bytes())?)
    }

    /// Call the authorize function on the authentication service.
    /// Returns the auth-code.
    async fn authorize(
        &self,
        service_addr: SocketAddr,
        tls_cert: &Certificate,
        nonce: &[u8],
        payload: &[u8],
    ) -> Result<String, AuthError> {
        let authreq = AuthReq {
            client_id: self.client_id.clone(),
            nonce: BASE64_STANDARD.encode(nonce),
            payload: BASE64_STANDARD.encode(payload),
        };

        // Note client set to NOT follow redirects since that is how we get our response.
        let cb = reqwest::ClientBuilder::new()
            .add_root_certificate(tls_cert.clone())
            .danger_accept_invalid_certs(true) // TODO: Figure this TLS stuff out and get rid of this
            .redirect(Policy::none())
            .timeout(std::time::Duration::from_secs(10));
        let client = cb.build().unwrap();

        let resp = client
            .post(format!("https://{}/authorize", service_addr))
            .json(&authreq)
            .send()
            .await
            .map_err(|e| AuthError::AuthError(format!("failed to send POST request: {}", e)))?;

        // Expect status code FOUND
        if resp.status() != StatusCode::FOUND {
            return Err(AuthError::AuthError(format!(
                "failed to authorize: {}",
                resp.status()
            )));
        }

        // Now extract the auth-code from the location header.
        if let Some(loc) = resp.headers().get(header::LOCATION) {
            if let Ok(loc_str) = loc.to_str() {
                if loc_str.contains("error") {
                    // TODO: We could parse this URL and get error & error_description
                    return Err(AuthError::AuthError(format!(
                        "failed to authorize: {}",
                        loc_str
                    )));
                }
                if let Some(code) = loc_str.split("code=").nth(1) {
                    return Ok(code.to_string());
                } else {
                    return Err(AuthError::AuthError(format!(
                        "failed to find code in location header: {}",
                        loc_str
                    )));
                }
            } else {
                return Err(AuthError::AuthError(format!(
                    "failed to parse location header: {}",
                    loc.to_str().unwrap_or("invalid utf8")
                )));
            }
        } else {
            return Err(AuthError::AuthError(
                "failed to find location header in response".to_string(),
            ));
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use aws_lc_rs::signature::{KeyPair, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
    use std::path::PathBuf;

    fn make_ss_blob() -> ZdpSelfSignedBlob {
        ZdpSelfSignedBlob {
            blob_type: BLOB_TYPE_SS.to_string(),
            ts: 12345,
            cn: "test.cn.zpr".to_string(),
            challenge: BASE64_STANDARD.encode([1u8; 48]),
            sig: BASE64_STANDARD.encode([2u8; 16]),
        }
    }

    fn make_oidc_blob() -> ZdpOidcBlob {
        ZdpOidcBlob {
            blob_type: BLOB_TYPE_OIDC.to_string(),
            issuer: "https://accounts.google.com".to_string(),
            id_token: "eyJ.header.payload".to_string(),
            challenge: BASE64_STANDARD.encode([3u8; 48]),
        }
    }

    #[test]
    fn test_decode_blobs_legacy_object() {
        // A legacy bare (non-array) SS blob object decodes to a one-element vec.
        let encoded = make_ss_blob().encode();
        let blobs = decode_blobs(&encoded).unwrap();
        assert_eq!(blobs.len(), 1);
        match &blobs[0] {
            AuthBlob::SelfSigned(ss) => assert_eq!(ss.cn, "test.cn.zpr"),
            other => panic!("expected SelfSigned, got {other:?}"),
        }
    }

    #[test]
    fn test_decode_blobs_array_ss_and_oidc() {
        // A JSON-array blob string decodes to all elements, order preserved.
        let encoded = encode_blobs(&[
            AuthBlob::SelfSigned(make_ss_blob()),
            AuthBlob::Oidc(make_oidc_blob()),
        ]);
        let blobs = decode_blobs(&encoded).unwrap();
        assert_eq!(blobs.len(), 2);
        match &blobs[0] {
            AuthBlob::SelfSigned(ss) => assert_eq!(ss.cn, "test.cn.zpr"),
            other => panic!("expected SelfSigned first, got {other:?}"),
        }
        match &blobs[1] {
            AuthBlob::Oidc(oidc) => {
                assert_eq!(oidc.issuer, "https://accounts.google.com");
                assert_eq!(oidc.id_token, "eyJ.header.payload");
            }
            other => panic!("expected Oidc second, got {other:?}"),
        }
    }

    #[test]
    fn test_decode_blobs_unknown_type_errors() {
        let json = r#"[{"blob_type": "XX", "stuff": 1}]"#;
        let encoded = BASE64_STANDARD.encode(json);
        match decode_blobs(&encoded) {
            Err(AuthError::FormatError(_)) => {}
            other => panic!("expected FormatError, got {other:?}"),
        }
    }

    #[test]
    fn test_decode_blobs_empty_array_errors() {
        // "[]" must not decode to zero blobs: an accepted acquire request
        // always carries authentication material.
        let encoded = BASE64_STANDARD.encode("[]");
        match decode_blobs(&encoded) {
            Err(AuthError::FormatError(_)) => {}
            other => panic!("expected FormatError, got {other:?}"),
        }
    }

    #[test]
    fn test_oidc_nonce_is_b64url_sha256() {
        // Vector computed independently (python3 hashlib/base64):
        // challenge = bytes(range(48))
        // base64.urlsafe_b64encode(hashlib.sha256(challenge).digest()).rstrip(b'=')
        let mut challenge = [0u8; 48];
        for (i, b) in challenge.iter_mut().enumerate() {
            *b = i as u8;
        }
        assert_eq!(
            oidc_nonce_for_challenge(&challenge),
            "Tb3CsrYssAdJeFvIQgIjbbw3d9dGYGEbjliBLwz95sM"
        );
    }

    #[test]
    fn test_oidc_blob_verify_challenge_rejects_bad_hmac_and_old_ctime() {
        let key = [7u8; AUTH_KEY_SIZE_BYTES];

        // A fresh, correctly HMAC'd challenge verifies and returns its bytes.
        let payload = ZdpInitAuthenticationPayload::new(&key);
        let mut challenge = [0u8; 48];
        challenge[0..8].copy_from_slice(&payload.nonce);
        challenge[8..16].copy_from_slice(&payload.ctime.to_bytes());
        challenge[16..48].copy_from_slice(&payload.hmac);
        let mut blob = make_oidc_blob();
        blob.challenge = BASE64_STANDARD.encode(challenge);
        let verified = blob.verify_challenge(&key).unwrap();
        assert_eq!(verified, challenge);

        // Flipping one HMAC byte fails.
        let mut bad = challenge;
        bad[16] ^= 0x01;
        blob.challenge = BASE64_STANDARD.encode(bad);
        match blob.verify_challenge(&key) {
            Err(AuthError::InvalidHmac) => {}
            other => panic!("expected InvalidHmac, got {other:?}"),
        }

        // A correctly HMAC'd but stale ctime fails. The OIDC window is
        // MAX_OIDC_BLOB_AGE_SECONDS (covers the browser flow), not the
        // 120-second SS window.
        let old_ctime = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - MAX_OIDC_BLOB_AGE_SECONDS
            - 10;
        let nonce = [9u8; 8];
        let be_time = old_ctime.to_be_bytes();
        let mut hasher = blake3::Hasher::new_keyed(&key);
        hasher.update(&nonce);
        hasher.update(&be_time);
        let hmac = hasher.finalize();
        let mut stale = [0u8; 48];
        stale[0..8].copy_from_slice(&nonce);
        stale[8..16].copy_from_slice(&be_time);
        stale[16..48].copy_from_slice(hmac.as_bytes());
        blob.challenge = BASE64_STANDARD.encode(stale);
        match blob.verify_challenge(&key) {
            Err(AuthError::ChallengeTooOld) => {}
            other => panic!("expected ChallengeTooOld, got {other:?}"),
        }
    }

    #[test]
    fn test_rsa_bootstrap_auth() {
        let mut keypath = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        keypath.push("tests");
        keypath.push("data");
        keypath.push("rsa-key.pem");

        let cn = "test.cn.zpr";
        let bs = RsaBootstrapAuth::new(cn, &keypath).unwrap();

        let ctime = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u64;

        let payload = ZdpInitAuthenticationPayload {
            nonce: [42u8; 8],
            ctime: ctime.into(),
            hmac: [24u8; 32],
        };

        let blob = bs.authenticate(&payload).unwrap();
        assert!(!blob.is_empty());

        let blob_json = BASE64_STANDARD.decode(&blob).unwrap();
        let blob = serde_json::from_slice::<ZdpSelfSignedBlob>(&blob_json).unwrap();

        assert_eq!(blob.blob_type, BLOB_TYPE_SS);
        assert!(blob.ts > 0);
        assert!(blob.ts >= ctime);
        assert_eq!(blob.cn, cn);

        let challenge_buffer = BASE64_STANDARD.decode(&blob.challenge).unwrap();
        assert_eq!(challenge_buffer.len(), 48);
        {
            // Challenge buffer layout:
            // [ 0..8 ] nonce
            // [ 8..16] ctime
            // [16..48] hmac
            for i in 0..8 {
                assert_eq!(challenge_buffer[i], payload.nonce[i]);
                assert_eq!(challenge_buffer[i + 8], payload.ctime.to_bytes()[i]);
            }
            for i in 0..32 {
                assert_eq!(challenge_buffer[i + 16], payload.hmac[i]);
            }
        }
        let sig_data = BASE64_STANDARD.decode(&blob.sig).unwrap();

        let mut data = Vec::new();
        data.extend_from_slice(&blob.ts.to_be_bytes());
        data.extend_from_slice(blob.cn.as_bytes());
        data.extend_from_slice(&challenge_buffer);

        let public_key =
            UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, bs.pkey.public_key().as_ref());
        public_key
            .verify(&data, &sig_data)
            .expect("signature verification failed");
    }
}
