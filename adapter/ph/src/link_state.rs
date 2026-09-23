use crate::auth::{self, AUTH_KEY_SIZE_BYTES, AuthBlob, ZdpSelfSignedBlob};
use crate::counters::ManagementCounterType;
use crate::km::ZPIPair;
use crate::km_multiplexor;
use crate::mgmt;
use crate::mgmt::core::{MgmtSendError, PacketStatus};
use crate::pki;
use crate::prelude::*;
use crate::sample_ring::SampleRing;
use crate::special_peers;
use crate::special_peers::SpecialPeerName;
use crate::visa_mgmt;
use crate::zdp::{self, ResponseCode, TerminateReason};

use base64::prelude::*;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::num::NonZero;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};
use thiserror::Error;
use zpr::addrs::{ZPR_INTERNAL_NETWORK, ZPRNET_PREFIX_LEN};
use zpr_utils::net_defs::IpAddress;

/// State machine for links and docking sessions

// Node-to-Node
// +--------------+       +----------+       +--------+
// | UNCONFIGURED |--CD-->| INACTIVE |--ST-->| KEYING |
// +--------------+       +----------+       +--------+
//     ^                       ^               | |  |
//     |                       |   +------KDe--+ |  +--KDu--------+
//     |                       CC  |       C    KDo               |
//     |                       |   V             V                V
//     |                   +---------+  HDe  +----------+     +----------+
//     |                   | CLOSING |<--C---| HELLOING |     | HELLOING |
//     |                   +---------+       +----------+     | SILENT   |
//     R                       ^                  |   |       +----------+
//     |                       |                 HDo HDu          |    |
//     |                       C                  |   |          HDu   C
//     |                       |                  |   +------+   HDo  HDe
//     |                       |                  V          V    V     |
//     |                       | KDe, C, KF   +--------+    +--------+  |
//     |                       +----------+---| ACTIVE |--->| ACTIVE |  |
//     |                                  |   +--------+ KDu| Silent |  |
//     +<-R-[ANY STATE]                   |            +--------+  |
//     |                                  |                |       |
// +-------+                              |                C       |
// | ERROR |<-- Error -- [ANY STATE]      |                |       |
// +-------+                              +----------------+-------+

// Node-to-Adapter
// NOTE: The LISTENING state, just like the UNCONFIGURED state, is implicit
// +--------------+       +-----------+                    +--------+
// | UNCONFIGURED |--CD-->| LISTENING |---------------RKM->| KEYING |
// +--------------+       +-----------+                    +--------+
//     ^                    ^                                | |  |
//     |                    | +------KDe---------------------+ |  +--KDu--+
//     |                   CC |       C                       KDo         |
//     |                    | |                             +--+          |
//     |                    | V                             V             V
//     |              +---------+              HDe   +----------+  +----------+
//     |              | CLOSING |<---------------C---| HELLOING |  | HELLOING |
//     |              +---------+                    +----------+  | SILENT   |
//     R                  ^                               |   |    +----------+
//     |                  |                              HDo HDu        |    |
//     |                  C             +-----------------+   |      HDo,HDu C
//     |                  |             |             +-------+<--------+   HDe
//     |                  |             V             |                      |
//     |                  |        +-------------+  +-------------+          |
//     |                  +<-RADe--| REGISTER AA |  | REGISTER AA |          |
//     |                  |   C    +-------------+  |    SILENT   |-----C--->+
//     |                  |              |    |     +-------------+          |
//     |                  |             RADo  RADu     |                     |
//     |                  |              |    |       RAD                    |
//     |              +---+              |    +-----+  |                     |
//     |              |                  V          V  V                     |
//     |              | KDe, RADe, C +--------+    +--------+                |
//     |              +----------+---| ACTIVE |--->| ACTIVE |                |
//     |                 KF      |   +--------+KDu,| Silent |                |
//     +<-R-[ANY STATE]           \           RADu +--------+                |
//     |                           \                   |                     |
// +-------+                        \                  C                     |
// | ERROR |<-- Error - [ANY STATE]  \                 |                     |
// +-------+                          +----------------+---------------------+

// Adapter-to-Node
// +--------------+       +----------+                     +--------+
// | UNCONFIGURED |--CD-->| INACTIVE |---------ST--------->| KEYING |
// +--------------+       +----------+                     +--------+
//     ^                   ^                                 | |  |
//     |                   |  +------KDe---------------------+ |  +--KDu-----+
//     |                   CC |       C                       KDo            |
//     |                   |  |                                |             |
//     |                   |  V                                V             V
//     |              +---------+             HDe   +----------+  +----------+
//     |              | CLOSING |<-------------C----| HELLOING |  | HELLOING |
//     |              +---------+                   +----------+  | SILENT   |
//     R                  ^                              |   |    +----------+
//     |                  |                             HDo HDu        |    |
//     |                  C            +-----------------+   |      HDu,HDo C
//     |                  |            |             +-------+<--------+   HDe
//     |                  |            V             |                      |
//     |                  |       +-------------+  +-------------+          |
//     |                  +<-RADe-| REGISTER AA |  | REGISTER AA |          |
//     |                  |   C   +-------------+  |    SILENT   |----C---->+
//     |                  |             |    |     +-------------+          |
//     |                  |            RADo  RADu     |                     |
//     |             +----+             |    |       RAD                    |
//     |             |                  |    +-----+  |                     |
//     |             |                  V          V  V                     |
//     |             | KDe, RADe, C +--------+    +--------+                |
//     |             +----------+---| ACTIVE |--->| ACTIVE |                |
//     |                  KF    |   +--------+KDu,| Silent |                |
//     +<-R-[ANY STATE]          \           RADu +--------+                |
//     |                          \                   |                     |
// +-------+                       \                  C                     |
// | ERROR |<- Error - [ANY STATE]  \                 |                     |
// +-------+                         +----------------+---------------------+

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum LinkState {
    Inactive,
    Keying,
    Helloing,
    /// disconnecting from visa service; only entered for the node->VS adapter link
    Disconnecting(TerminateReason),
    Closing,
    Resetting,
    Active,
    RegisterAA, // aka acquiring ZPR address
    WaitForInitAuth,
    WaitForAcquireZprAddress,
    /// Adapter side: waiting for the out-of-band AuthAgent (a human in a
    /// browser) to return an OIDC credential. Bounded by
    /// [config::OIDC_USER_INTERACTION_TIMEOUT].
    WaitForUserAuth,
    Error,
}

/// Why an out-of-band authentication attempt failed, as reported to ph-cli.
/// Mirrors the spec's error taxonomy (see zipline#13 / OIDC master plan D2).
#[allow(dead_code)] // some variants are constructed only by later deliverables
#[derive(Clone, Debug, PartialEq, strum::IntoStaticStr)]
pub enum AuthFailureReason {
    /// OIDC required but startLink registered no AuthAgent.
    NoAgent,
    /// The agent returned access_denied: the user refused the login.
    UserDeclined,
    /// The user did not complete the login within OIDC_USER_INTERACTION_TIMEOUT.
    InteractionTimeout,
    /// Discovery/token endpoint failure (not an authentication problem).
    IdpUnreachable(String),
    AgentError(String),
    /// ResponseCode::AuthFailed -> misconfiguration / token rejected.
    VisaServiceRejected(String),
    /// ResponseCode::PolicyDenied -> login worked, endpoint not admitted.
    PolicyDenied,
    /// ResponseCode::AuthUnavailable.
    AuthUnavailable,
    DeviceBlobRejected,
    /// The link failed before (or without) an authentication verdict — e.g.
    /// a handshake timeout in Helloing — and, with auto-connect off, no
    /// restart is coming (zipline#28). Recorded on the close path so ph-cli
    /// `connect` sees the permanently Inactive link as this attempt's
    /// terminal outcome instead of polling it as Pending forever. Carries
    /// the TerminateReason's Debug spelling.
    LinkFailed(String),
    /// The fabric granted a ZPR address set differing from the configured
    /// `--zpr-addr` / `zpr_addr` (zipline#83): the configured address is a
    /// demand, not a request, so the adapter refuses to run on the granted
    /// one — it logs both addresses with the remedy (remove the configured
    /// address and retry), tears the link down, and exits non-zero. Carries
    /// both address sets so `ph-cli link show` names them.
    GrantedAddressMismatch {
        requested: Vec<IpAddr>,
        granted: Vec<IpAddr>,
    },
}

/// A single credential request forwarded to the out-of-band AuthAgent
/// (ph-cli). The admin worker bridges these onto the Cap'n Proto client it
/// received in startLink.
pub struct OidcCredentialRequest {
    /// The advertised identity provider to authenticate against.
    pub idp: auth::OidcIdpInfo,
    /// OIDC nonce derived from the link challenge
    /// ([auth::oidc_nonce_for_challenge]).
    pub nonce: String,
    /// `false` means "satisfy from a stored refresh token or fail"; the agent
    /// must never open a browser on a non-interactive request.
    pub interactive: bool,
    /// `Ok(id_token)` on success, otherwise the failure reason.
    pub reply: tokio::sync::oneshot::Sender<Result<String, AuthFailureReason>>,
}

/// Handle to the AuthAgent registered for a link via startLink.
pub type AuthAgentHandle = tokio::sync::mpsc::UnboundedSender<OidcCredentialRequest>;

/// The identity a link's actor originally authenticated with, stashed at
/// auth time so silent renewal (zipline#45) can re-prove against the SAME
/// issuer. On renewal failure the adapter/user reconnects and re-picks from
/// the then-advertised providers, so this is never updated in place.
#[derive(Clone, Debug)]
pub struct RenewalIdentity {
    /// The advertised IdP (issuer, client config) the original OIDC blob
    /// named. Resolved from the node's auth-services list at auth time.
    pub idp: auth::OidcIdpInfo,
    /// The challenge-derived OIDC nonce ([auth::oidc_nonce_for_challenge])
    /// bound into the original credential. Reused verbatim on the renewal
    /// blob because the VS ignores the nonce on the reauthorize path and
    /// there is no empty-string special case on the wire. It cannot be
    /// checked against the renewed id_token in any case: OIDC Core §12.2
    /// says a refresh-grant id_token SHOULD NOT carry a nonce claim, and
    /// MUST match the original only if it does — absent or original, never
    /// fresh.
    pub nonce: String,
}

/// The effective renewal lead for a granted authentication lifetime:
/// the configured lead clamped to half the lifetime, so short
/// `expiration_seconds` values still renew ahead of expiry by a workable
/// margin instead of the lead swallowing the whole window (zipline#45).
pub fn renewal_lead(configured: Duration, granted_lifetime: Duration) -> Duration {
    configured.min(granted_lifetime / 2)
}

/// The instant renewal becomes due for an authentication granted at
/// `granted_at` and expiring at `auth_expires`:
/// `auth_expires - renewal_lead(configured, lifetime)`.
/// An already-past (or zero-length) expiry yields a deadline that is never
/// in the future, so renewal is due immediately.
pub fn renewal_deadline(
    granted_at: SystemTime,
    auth_expires: SystemTime,
    configured_lead: Duration,
) -> SystemTime {
    let lifetime = auth_expires
        .duration_since(granted_at)
        .unwrap_or(Duration::ZERO);
    let lead = renewal_lead(configured_lead, lifetime);
    auth_expires.checked_sub(lead).unwrap_or(auth_expires)
}

/// Floor for one silent-renewal attempt's wait on the AuthAgent: even with
/// (nearly) no window left, give a healthy agent a moment to answer from its
/// refresh-token cache instead of a zero-length wait.
pub const RENEWAL_ATTEMPT_TIMEOUT_FLOOR: Duration = Duration::from_secs(5);

/// How long ONE silent-renewal attempt may wait on the AuthAgent: half the
/// time remaining before `auth_expires`, clamped between
/// [RENEWAL_ATTEMPT_TIMEOUT_FLOOR] and the bridge's own per-call bound
/// ([config::OIDC_USER_INTERACTION_TIMEOUT]). Bounding by the remaining
/// window means a hung request cannot pin `renewal_in_flight` past the point
/// where a retry could still succeed against the current authentication —
/// half, so at least one full retry fits in the window left (PR #14 review).
pub fn renewal_attempt_timeout(now: SystemTime, auth_expires: SystemTime) -> Duration {
    let remaining = auth_expires.duration_since(now).unwrap_or(Duration::ZERO);
    (remaining / 2).clamp(
        RENEWAL_ATTEMPT_TIMEOUT_FLOOR,
        config::OIDC_USER_INTERACTION_TIMEOUT,
    )
}

#[allow(dead_code)]
#[derive(Clone, Debug, strum::IntoStaticStr)]
pub enum LinkEvent {
    Start,
    KeyingDone,
    ReceivedHelloRequest,
    AssignedAAA(IpAddress), // Assigned AAA address for this link
    ReceivedHelloResponse(
        ResponseCode,
        Option<IpAddress>,
        Option<Vec<auth::OidcIdpInfo>>,
    ), // (response code, AAA address, advertised OIDC IdPs)

    ReceivedInitAuth((bool, Option<auth::ZdpInitAuthenticationPayload>)), // (bootstrap_flag, challenge)
    ReceivedInitAuthAck,
    ReceivedInitAuthTimeout,

    /// Adapter side (zipline#66): the node asks for a renewed credential,
    /// carrying the fresh challenge it minted.
    ReceivedRenewAuthRequest(auth::ZdpInitAuthenticationPayload),
    /// Node side (zipline#66): the adapter's answer — the echoed challenge
    /// of the request it answers (so it can be correlated with the attempt
    /// that is actually outstanding, PR #17 review), plus Ok(blob string)
    /// on success or Err(the response's failure code) otherwise.
    ReceivedRenewAuthResponse([u8; 48], Result<String, ResponseCode>),

    ReceivedAcquireZprAddressRequest(Option<Vec<IpAddress>>, String), // (requested_addrs, auth_blob)

    /// Ok(granted_addrs) on success, Err(the grant's failure code) otherwise.
    ReceivedGrantZprAddressRequest(Result<Vec<IpAddress>, ResponseCode>),

    AuthenticationSuccess(Vec<AuthBlob>), // Blobs collected from the configured authentication method(s)
    AuthenticationFailure(AuthFailureReason), // Why authentication failed

    ReceivedAuthorizeResponse(IpAddress), // from visa service
    /// Visa service refused the authorize; carries the VS error code and message.
    ReceivedAuthorizeFailure(zpr::vsapi_types::ErrorCode, String),
    ReceivedKeepAliveResponse,
    ReceivedTerminateLink(TerminateReason),
    ReceivedTerminateAck,
    ReceivedDisconnectAck, // from visa service
    Close(TerminateReason),
    CloseDone,
    Error,
    Timeout {
        logical_clock: u64,
    },
}

#[derive(Error, Debug)]
pub enum LinkStateError {
    #[error("Got unexpected event {1} on state {0:?}")]
    UnexpectedTransition(LinkState, &'static str),
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
    #[error("Link {0} does not exist in peer table")]
    NotFound(LinkId),
    #[error("This operation is not supported yet")]
    OperationNotSupportedYet,
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum LinkType {
    Internal,
    AdapterToNode,
    #[allow(dead_code)]
    NodeToNode, // Currently unsupported
    NodeToAdapter,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum LinkStatus {
    Up,
    Down,
}

/// Lives in a [LinkStateWrapper]
pub struct LinkData {
    echo_success: u64, // Echo requests received response
    echo_timeout: u64, // Echo requests timed out
    // TODO: configurable keep-alive period
    // For now, keep-alives are attempted every 3 seconds
    // Assuming no loss, 100 samples will store 5 minutes of latency data
    latency_data: SampleRing<Duration, 100>,
    aaa_address: Option<IpAddress>, // AAA address assigned this link (if any)
    /// OIDC identity providers advertised by our peer in HelloResponse, if any.
    oidc_idps: Option<Vec<auth::OidcIdpInfo>>,
    /// The out-of-band AuthAgent registered for this link via startLink, if any.
    auth_agent: Option<AuthAgentHandle>,
    /// The most recent out-of-band authentication failure, surfaced in showLink.
    last_auth_failure: Option<AuthFailureReason>,
    /// Nodes only: when the docked actor's authentication expires, from the
    /// VS `Connection` response (zipline#45). None until authorized.
    auth_expires: Option<SystemTime>,
    /// Nodes only: the precomputed instant renewal becomes due —
    /// `auth_expires - min(configured lead, lifetime/2)`; see
    /// [renewal_deadline].
    auth_renewal_deadline: Option<SystemTime>,
    /// Nodes only: the issuer/nonce identity the actor originally
    /// authenticated with, for silent renewal. None on device-only links.
    renewal_identity: Option<RenewalIdentity>,
    /// Nodes only: a renewal attempt is underway; suppresses further
    /// attempts until it completes (one attempt per due tick at most).
    renewal_in_flight: bool,
    /// Nodes only: the challenge minted for the in-flight ZDP renewal
    /// credential request (zipline#66). The RenewAuthenticationResponse's
    /// blob must carry exactly these bytes; taken (cleared) on completion
    /// or attempt timeout.
    renewal_challenge: Option<[u8; 48]>,
    /// Adapters only: the task awaiting the AuthAgent's answer to the
    /// current renewal credential request (zipline#66). A new request
    /// supersedes it: the node only retries after abandoning its previous
    /// attempt, so the old task is aborted — dropping its reply receiver,
    /// which the serial bridge observes (`reply.closed()`) and cancels the
    /// in-flight RPC instead of letting retries queue behind it
    /// (PR #17 review).
    adapter_renewal_task: Option<tokio::task::AbortHandle>,
    /// Nodes only: the one-shot "renewal due but no AuthAgent registered"
    /// warning has fired for the current authentication window.
    renewal_no_agent_warned: bool,
}

impl LinkData {
    pub fn new() -> Self {
        Self {
            echo_success: 0,
            echo_timeout: 0,
            latency_data: SampleRing::new(Duration::ZERO),
            aaa_address: None,
            oidc_idps: None,
            auth_agent: None,
            last_auth_failure: None,
            auth_expires: None,
            auth_renewal_deadline: None,
            renewal_identity: None,
            renewal_in_flight: false,
            renewal_challenge: None,
            adapter_renewal_task: None,
            renewal_no_agent_warned: false,
        }
    }
}

struct InitAuthData {
    bootstrap: bool,
    challenge: Option<auth::ZdpInitAuthenticationPayload>,
}

pub struct LinkStateMachine {
    id: LinkId,
    state: LinkState,
    status: LinkStatus,
    silent: bool,

    /// On a node, actual assigned actor addresses to remote PEER.
    actor_addresses: Vec<IpAddress>,

    last_state_change: Instant,
    /// used to prevent A/B/A errors with timeouts
    logical_clock: u64,
    timeout_handle: Option<tokio::task::AbortHandle>,
    /// Counter available for use by states which wish to count timeouts.
    /// Reset to 0 on any state transition.
    timeout_count: usize,
    /// Used in Helloing when a racy InitAuthRequest arrived
    stowed_init_auth: Option<InitAuthData>,
    /// Handle to an outstanding echo/keepalive task; used only during Active.
    /// Instant is time at which the echo was sent.
    echo_handle: Option<(Instant, tokio::task::AbortHandle)>,
    shutting_down: bool, // only ever goes from False -> True once
}

impl LinkStateMachine {
    pub fn new(link_id: LinkId) -> Self {
        Self {
            id: link_id,
            state: LinkState::Inactive,
            status: LinkStatus::Down,
            silent: false,
            actor_addresses: Default::default(),
            last_state_change: std::time::Instant::now(),
            logical_clock: 0,
            timeout_handle: None,
            timeout_count: 0,
            stowed_init_auth: None,
            echo_handle: None,
            shutting_down: false,
        }
    }

    pub fn set_state(&mut self, new_state: LinkState) {
        if new_state != self.state {
            debug!(target: LINK_STATE, "Link {} state transition {:?} => {:?}", self.id, self.state, new_state);
        }
        self.state = new_state;
        self.last_state_change = std::time::Instant::now();
        self.cancel_timeout();
        self.timeout_count = 0;
    }

    /// Schedule the given callback to be invoked asynchronously after the
    /// specified duration.
    ///
    /// The callback will be passed the logical clock at which time the
    /// timeout was set, and, after obtaining a lock on the state machine,
    /// the callback should compare this value to the current logical clock
    /// to determine whether it is still valid.
    ///
    /// Any existing callback is cancelled as with `cancel_timeout()`.
    ///
    /// The timeout will be canceled automatically at the next state change.
    /// (Note that any call to `set_state()` will cancel the timeout, even
    /// if the state does not actually change.)
    pub fn set_timeout_callback(
        &mut self,
        duration: std::time::Duration,
        callback: impl FnOnce(u64) + Send + 'static,
    ) {
        // cancel old timeout if present
        self.cancel_timeout();

        // launch new timeout tied to the current (new) logical clock
        let logical_clock = self.logical_clock;
        let jh = tokio::task::spawn_local(async move {
            tokio::time::sleep(duration).await;
            callback(logical_clock);
        });

        // store new timeout handle
        self.timeout_handle = Some(jh.abort_handle());
    }

    /// Try to cancel any existing timeout.
    ///
    /// Any existing callback may or may not be invoked at a later time.  It
    /// is the responsibility of the callback to ensure atomic behavior by
    /// comparing the logical clock as detailed in `set_timeout_callback()`.
    pub fn cancel_timeout(&mut self) {
        // request to abort existing timeout task if present
        self.timeout_handle.take().inspect(|h| h.abort());
        // increment logical clock to avoid duplicate timeouts
        self.logical_clock = self.logical_clock.wrapping_add(1);
    }
}

pub struct LinkStateWrapper {
    pub id: LinkId, // set at constructor, never changes.
    /// Process-unique instance id: distinguishes THIS link from a later link
    /// that reuses the same slab `id` after teardown. Renewal completions
    /// carry the uid they were spawned under and are discarded when the
    /// looked-up peer's uid differs (PR #14 review).
    uid: u64,
    link_type: LinkType,
    locked_fsm: Mutex<LinkStateMachine>,
    pub locked_data: Mutex<LinkData>,
    /// Internal links _may_ be associated with another internal link
    /// representing its remote side.
    pub internal_peer_id: Option<NonZero<LinkId>>,
}

impl LinkStateWrapper {
    pub fn new(new_id: LinkId, new_link_type: LinkType) -> Self {
        // Monotonic instance counter; see the `uid` field.
        static NEXT_UID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let mut lsm = LinkStateMachine::new(new_id);

        if matches!(new_link_type, LinkType::Internal) {
            // Internal links are always up and active, that is, `is_ready()`.
            lsm.state = LinkState::Active;
            lsm.status = LinkStatus::Up;
        }

        Self {
            id: new_id,
            uid: NEXT_UID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            link_type: new_link_type,
            locked_fsm: Mutex::new(lsm),
            locked_data: Mutex::new(LinkData::new()),
            internal_peer_id: None,
        }
    }

    pub fn is_internal(&self) -> bool {
        matches!(self.link_type, LinkType::Internal)
    }

    /// Get the link's current state
    pub fn get_state(&self) -> LinkState {
        self.locked_fsm.lock().unwrap().state
    }

    pub fn is_ready(&self) -> bool {
        let locked_fsm = self.locked_fsm.lock().unwrap();
        locked_fsm.status == LinkStatus::Up
            && (locked_fsm.state == LinkState::Active || locked_fsm.state == LinkState::RegisterAA)
    }

    pub fn get_link_type(&self) -> LinkType {
        self.link_type
    }

    /// Register (or replace) the out-of-band AuthAgent handle for this link.
    /// Set by the admin worker's startLink handler; lives for the link's lifetime.
    pub fn set_auth_agent(&self, agent: AuthAgentHandle) {
        self.locked_data.lock().unwrap().auth_agent = Some(agent);
    }

    /// Clear the AuthAgent slot, but only if it still holds `handle`'s
    /// channel (zipline#45): the bridge for a dead capnp client must not
    /// clobber a NEWER agent registered after it (e.g. the user re-ran
    /// `ph-cli auth-agent`). Returns true if the slot was cleared.
    pub fn clear_auth_agent_if(&self, handle: &AuthAgentHandle) -> bool {
        let mut data = self.locked_data.lock().unwrap();
        if data
            .auth_agent
            .as_ref()
            .is_some_and(|current| current.same_channel(handle))
        {
            data.auth_agent = None;
            return true;
        }
        false
    }

    /// True if `attempt_clock` still identifies the FSM's current
    /// timeout/attempt. The logical clock advances on every state change
    /// (and every re-armed timeout), so a mismatch means the attempt that
    /// captured the value has been superseded. Used to discard a stale
    /// AuthAgent completion so it cannot be consumed by a newer
    /// WaitForUserAuth attempt with a different challenge.
    fn auth_attempt_is_current(&self, attempt_clock: u64) -> bool {
        self.locked_fsm.lock().unwrap().logical_clock == attempt_clock
    }

    /// The most recent out-of-band authentication failure on this link, if any.
    pub fn get_last_auth_failure(&self) -> Option<AuthFailureReason> {
        self.locked_data.lock().unwrap().last_auth_failure.clone()
    }

    /// Record why authentication failed, for showLink / ph-cli reporting.
    fn record_auth_failure(&self, reason: AuthFailureReason) {
        self.locked_data.lock().unwrap().last_auth_failure = Some(reason);
    }

    /// Record the actor's authentication expiry from a VS `Connection`
    /// response and precompute the renewal deadline from the configured
    /// lead (zipline#45). `granted_at` anchors the lifetime the `remaining/2`
    /// clamp is computed against (normally "now", when the grant arrived).
    /// Resets the per-window renewal bookkeeping so a fresh grant warns and
    /// retries anew.
    pub fn set_auth_expires(
        &self,
        granted_at: SystemTime,
        auth_expires: SystemTime,
        configured_lead: Duration,
    ) {
        let deadline = renewal_deadline(granted_at, auth_expires, configured_lead);
        let mut data = self.locked_data.lock().unwrap();
        data.auth_expires = Some(auth_expires);
        data.auth_renewal_deadline = Some(deadline);
        data.renewal_in_flight = false;
        data.renewal_no_agent_warned = false;
    }

    /// The actor's authentication expiry, if the VS has reported one.
    #[cfg(test)]
    pub fn get_auth_expires(&self) -> Option<SystemTime> {
        self.locked_data.lock().unwrap().auth_expires
    }

    /// Stash the issuer/nonce identity the actor originally authenticated
    /// with, so silent renewal can re-prove against the same issuer.
    pub fn set_renewal_identity(&self, identity: RenewalIdentity) {
        self.locked_data.lock().unwrap().renewal_identity = Some(identity);
    }

    /// The stored renewal identity, if the actor authenticated via OIDC.
    #[cfg(test)]
    pub fn get_renewal_identity(&self) -> Option<RenewalIdentity> {
        self.locked_data.lock().unwrap().renewal_identity.clone()
    }

    /// Stash the challenge minted for an in-flight ZDP renewal credential
    /// request (zipline#66); the response must echo exactly these bytes.
    fn stash_renewal_challenge(&self, challenge: [u8; 48]) {
        self.locked_data.lock().unwrap().renewal_challenge = Some(challenge);
    }

    /// Take the stashed renewal challenge only if it still equals
    /// `challenge`. Used by the attempt-timeout task so it cannot clobber a
    /// LATER attempt's challenge: true means this attempt was still the
    /// in-flight one and has now been failed.
    fn take_renewal_challenge_if(&self, challenge: &[u8; 48]) -> bool {
        let mut data = self.locked_data.lock().unwrap();
        if data.renewal_challenge.as_ref() == Some(challenge) {
            data.renewal_challenge = None;
            return true;
        }
        false
    }

    /// Test-only: peek the stashed renewal challenge without consuming it.
    #[cfg(test)]
    pub fn test_renewal_challenge(&self) -> Option<[u8; 48]> {
        self.locked_data.lock().unwrap().renewal_challenge
    }

    /// Test-only: whether the one-shot "renewal due, no agent" warning fired.
    #[cfg(test)]
    pub fn test_renewal_no_agent_warned(&self) -> bool {
        self.locked_data.lock().unwrap().renewal_no_agent_warned
    }

    /// Test-only: whether a renewal attempt is currently in flight.
    #[cfg(test)]
    pub fn test_renewal_in_flight(&self) -> bool {
        self.locked_data.lock().unwrap().renewal_in_flight
    }

    /// Test-only: clear the recorded auth failure.
    #[cfg(test)]
    pub fn test_clear_last_auth_failure(&self) {
        self.locked_data.lock().unwrap().last_auth_failure = None;
    }

    /// Test-only: whether an AuthAgent handle is registered on this link.
    #[cfg(test)]
    pub fn test_has_auth_agent(&self) -> bool {
        self.locked_data.lock().unwrap().auth_agent.is_some()
    }

    /// Test-only: force the FSM into a state without walking the transitions.
    #[cfg(test)]
    pub fn test_set_state(&self, state: LinkState) {
        self.locked_fsm.lock().unwrap().set_state(state);
    }

    /// Test-only: the FSM's current logical clock, for synthesizing a
    /// `LinkEvent::Timeout` that `process_timeout` accepts as current.
    #[cfg(test)]
    pub fn test_logical_clock(&self) -> u64 {
        self.locked_fsm.lock().unwrap().logical_clock
    }

    /// Test-only: pretend a HelloResponse advertised these IdPs.
    #[cfg(test)]
    pub fn test_set_oidc_idps(&self, idps: Vec<auth::OidcIdpInfo>) {
        self.locked_data.lock().unwrap().oidc_idps = Some(idps);
    }

    /// Schedule a `Timeout` event to occur after the specified duration.
    ///
    /// Any existing timeout is canceled atomically.
    ///
    /// The timeout will also be canceled automatically and atomically at the next state change.
    ///
    /// The timeout may be cancelled manually using `LinkStateMachine::cancel_timeout()`.
    /// It will be cancelled atomically.
    fn set_timeout(
        &self,
        asm: &Arc<Assembly>,
        locked_fsm: &mut MutexGuard<'_, LinkStateMachine>,
        duration: std::time::Duration,
    ) {
        let link_id = self.id;
        let task_asm = asm.clone();
        locked_fsm.set_timeout_callback(duration, move |logical_clock| {
            if let Err(e) =
                task_asm.process_link_state_event(link_id, LinkEvent::Timeout { logical_clock })
            {
                error!(target: LINK_STATE, "error handling timeout: {e}");
            }
        });
    }

    /// Takes lock, returns copy of addresses.
    /// Will hang if you already have fsm lock!
    ///
    /// This returns the address assigned to the remote peer on this link.
    /// Designed to be used in a NODE context.  Also includes the AAA address (if present)
    ///
    pub fn get_actor_addresses(&self) -> Vec<IpAddress> {
        let mut addr_list = Vec::new();

        addr_list.extend(self.locked_fsm.lock().unwrap().actor_addresses.iter());

        match self.locked_data.lock().unwrap().aaa_address.as_ref() {
            Some(aaa_addr) => addr_list.push(aaa_addr.clone()),
            None => (),
        }

        addr_list
    }

    /// Returns true if the specified address matches any of this link's assigned actor addresses.
    pub fn has_actor_address(&self, addr: &IpAddress) -> bool {
        self.locked_fsm
            .lock()
            .unwrap()
            .actor_addresses
            .iter()
            .any(|a| a == addr)
            || self.locked_data.lock().unwrap().aaa_address.as_ref() == Some(addr)
    }

    /// Sets the actor address of an internal link.
    pub fn add_internal_actor_address(&self, addr: IpAddress) {
        assert!(
            self.is_internal(),
            "attempt to directly set actor address of non-internal link"
        );
        self.locked_fsm.lock().unwrap().actor_addresses.push(addr);
    }

    /// Test-only: dock an actor address on this link regardless of type.
    #[cfg(test)]
    pub fn test_add_actor_address(&self, addr: IpAddress) {
        self.locked_fsm.lock().unwrap().actor_addresses.push(addr);
    }

    /// Tell the VS that this actor has disconnected.
    /// Used in a NODE context only.
    fn deregister_actor_addresses(&self, asm: &Arc<Assembly>) -> tokio::task::JoinSet<()> {
        let mut join_set = tokio::task::JoinSet::new();
        let vs_id = asm
            .peer_table
            .lookup_special_peer(SpecialPeerName::VisaServiceAdapter);
        if vs_id.is_some() && vs_id.unwrap().get() == self.id {
            return join_set;
        }
        for addr in self.locked_fsm.lock().unwrap().actor_addresses.drain(..) {
            debug!(target: LINK_STATE, "Deregistering {addr}");
            join_set.spawn_local(visa_mgmt::actor_disconnect(asm.clone(), addr));
        }
        join_set
    }

    pub fn process_event(
        &self,
        asm: &Arc<Assembly>,
        event: LinkEvent,
    ) -> Result<(), LinkStateError> {
        match event {
            LinkEvent::ReceivedKeepAliveResponse | LinkEvent::Timeout { .. } => {
                trace!(target: LINK_STATE, "{}: *EVENT* {event:?}", asm.formatted_link_id(self.id))
            }

            _ => {
                debug!(target: LINK_STATE, "{}: *EVENT* {event:?}", asm.formatted_link_id(self.id))
            }
        }

        match event {
            LinkEvent::Start => self.process_start(asm),
            LinkEvent::KeyingDone => self.process_keying_done(asm),
            LinkEvent::ReceivedHelloRequest => self.process_hello_request(asm),
            LinkEvent::AssignedAAA(addr) => self.process_assigned_aaa(asm, addr),
            LinkEvent::ReceivedHelloResponse(code, aaa_addr, maybe_oidc_idps) => {
                self.process_hello_response(asm, code, aaa_addr, maybe_oidc_idps)
            }

            LinkEvent::ReceivedAcquireZprAddressRequest(addrs, blob) => {
                self.process_acquire_zpr_address_request(asm, addrs, blob)
            }

            LinkEvent::ReceivedInitAuth((bootstrap_flag, challenge)) => {
                self.process_init_auth(asm, bootstrap_flag, challenge)
            }

            LinkEvent::ReceivedInitAuthAck => self.process_init_auth_ack(asm),
            LinkEvent::ReceivedInitAuthTimeout => self.process_init_auth_timeout(asm),

            LinkEvent::ReceivedRenewAuthRequest(challenge) => {
                self.process_renew_auth_request(asm, challenge)
            }
            LinkEvent::ReceivedRenewAuthResponse(challenge, result) => {
                self.process_renew_auth_response(asm, challenge, result)
            }

            LinkEvent::ReceivedGrantZprAddressRequest(result) => {
                self.process_grant_zpr_address_request(asm, result)
            }
            LinkEvent::AuthenticationFailure(reason) => {
                self.process_authentication_failure(asm, reason)
            }

            LinkEvent::AuthenticationSuccess(blobs) => {
                self.process_authentication_success(asm, blobs)
            }

            LinkEvent::ReceivedAuthorizeResponse(zpr_addr) => {
                self.process_authorize_response(asm, zpr_addr)
            }

            LinkEvent::ReceivedAuthorizeFailure(code, msg) => {
                self.process_authorize_failure(asm, code, msg)
            }

            LinkEvent::ReceivedKeepAliveResponse => self.process_keep_alive_response(asm),
            LinkEvent::ReceivedTerminateLink(code) => self.process_terminate_link(asm, code),
            LinkEvent::ReceivedTerminateAck => self.process_terminate_ack(asm),
            LinkEvent::ReceivedDisconnectAck => self.process_disconnect_ack(asm),
            LinkEvent::Close(code) => self.initiate_close(asm, code),
            LinkEvent::CloseDone => Ok(self.complete_close(asm)),
            LinkEvent::Error => self.process_error_response(asm),
            LinkEvent::Timeout { logical_clock } => self.process_timeout(asm, logical_clock),
        }
    }

    /// Start an inactive link/tether
    /// Transitions from Inactive -> Keying
    /// Will trigger key management messages to be sent if this is an adapter
    fn process_start(&self, asm: &Assembly) -> Result<(), LinkStateError> {
        assert!(self.id != LINK_ID_UNKNOWN);
        let link_id = self.id;
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        if locked_fsm.state != LinkState::Inactive {
            return Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "Start",
            ));
        }

        locked_fsm.status = LinkStatus::Up;
        locked_fsm.set_state(LinkState::Keying);

        // A Start begins a fresh authentication attempt: drop the previous
        // attempt's recorded failure so showLink (and ph-cli's `connect`
        // poll, which treats a teardown state with a recorded failure as
        // that attempt's terminal outcome) never reports a stale reason
        // against the new attempt.
        self.locked_data.lock().unwrap().last_auth_failure = None;

        // A Start also begins a fresh ZDP-R session.  An adapter keeps one
        // peer table entry per link for the life of the process, but the
        // node it docks with allocates a new link -- and so a new ZDP-R
        // session, restarting at sequence number 0 -- for every attempt.
        // Carrying the previous attempt's sequence numbers and receive
        // window into this one would have each side silently discard the
        // other's traffic.
        if let Some(peer) = asm.peer_table.get(link_id) {
            peer.reset_zdpr_session();
        }

        info!(target: LINK_STATE, "{} started.  Keying in progress", asm.formatted_link_id(link_id));

        match self.link_type {
            LinkType::AdapterToNode => {
                km_multiplexor::add_adapter_link(
                    asm,
                    link_id,
                    ZPIPair::new(ZPI_ENCRYPTED_HEADER_FLAG | 5, 6),
                    asm.self_noise_keypair.clone().unwrap(),
                    asm.certx.clone().unwrap(),
                )
                .unwrap();
                Ok(())
            }
            LinkType::NodeToNode => {
                error!(target: LINK_STATE, "Error: Node to node not supported yet");
                locked_fsm.set_state(LinkState::Error);
                Err(LinkStateError::OperationNotSupportedYet)
            }
            LinkType::NodeToAdapter => {
                km_multiplexor::add_node_link(
                    asm,
                    link_id,
                    ZPIPair::new(ZPI_ENCRYPTED_HEADER_FLAG | 3, 4),
                    asm.self_noise_keypair.clone().unwrap(),
                    asm.certx.clone().unwrap(),
                )
                .unwrap();
                Ok(())
            }
            LinkType::Internal => {
                error!(target: LINK_STATE, "Coding error: internal link state machine should not be controlled");
                Err(LinkStateError::InvalidOperation("coding error".into()))
            }
        }
    }

    /// The Key Manager sends in the [LinkEvent::KeyingDone] event when it is done with initial keying.
    /// Transitions from Keying -> Helloing
    /// Will trigger a Hello to be sent if this is an adapter
    fn process_keying_done(&self, asm: &Arc<Assembly>) -> Result<(), LinkStateError> {
        let link_id = self.id;
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        if locked_fsm.state != LinkState::Keying {
            return Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "KeyingDone",
            ));
        }

        let Some(peer_state) = asm.peer_table.get(link_id) else {
            return Err(LinkStateError::NotFound(link_id));
        };

        let Some(sa) = peer_state.get_established_transport_association() else {
            return Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "KeyingDone when SA not established",
            ));
        };

        if let Some(ref peer_cert) = sa.peer_cert {
            let cert = peer_cert.get_cert();
            let is_verified = peer_cert.is_verified();

            // Note, keying will have failed if we requested verification (i.e. were
            // connecting to node) but the cert couldn't be verified.  So here,
            // we only need to verify the case that we are only conditionally verifying
            // (i.e., we are being connected to by a special adapter).

            if is_verified {
                info!(target: LINK_STATE, "{} has verified name {}", asm.formatted_link_id(link_id), pki::subject_name(cert));
            } else {
                warn!(target: LINK_STATE, "{} has unverified name {}", asm.formatted_link_id(link_id), pki::subject_name(cert));
            }

            let subject_der = match pki::subject_der(cert) {
                Ok(der) => der,
                Err(e) => {
                    warn!(target: LINK_STATE, "{} cannot encode certificate subject DN: {e}", asm.formatted_link_id(link_id));
                    Vec::new()
                }
            };

            if !is_verified {
                for name in special_peers::special_peer_names_from_subject_der(&subject_der) {
                    warn!(
                        target: LINK_STATE,
                        "{} presented unverified certificate claiming special peer name {name:?}; ignoring", asm.formatted_link_id(link_id)
                    );
                }
            } else {
                // assign special-peer name if this peer is special
                for name in special_peers::special_peer_names_from_subject_der(&subject_der) {
                    match asm.peer_table.assign_special_name(name, link_id) {
                        Ok(()) => {
                            info!(target: LINK_STATE, "{} assigned special name {name:?}", asm.formatted_link_id(link_id))
                        }
                        Err(_) => {
                            warn!(target: LINK_STATE, "Unable to assign {} special name {name:?}", asm.formatted_link_id(link_id))
                        }
                    }
                }
            }
        }

        debug!(target: LINK_STATE, "{} finished keying.  Starting hello", asm.formatted_link_id(link_id));

        locked_fsm.set_state(LinkState::Helloing);

        // IF this is an adapter, it's expected to issue the hello
        if self.link_type == LinkType::AdapterToNode {
            // Grab public key from keypair to send in hello request
            let pubkey = x25519_dalek::PublicKey::from(&asm.a2a_dh_keypair);
            mgmt::requests::send_hello_request(asm, self.id, pubkey).enqueue();
            self.set_timeout(asm, &mut locked_fsm, config::LINK_HELLO_TIMEOUT);
            debug!(
                target: LINK_STATE,
                "{} sent HelloRequest.  Waiting for other side to respond.", asm.formatted_link_id(link_id)
            );
        }
        // Otherwise we are a node so wait for an adapter to reach out
        Ok(())
    }

    /// Update link state based on received hello request
    /// Transitions from Helloing to Registering Actor Address
    /// Does not generate any packets
    fn process_hello_request(&self, asm: &Arc<Assembly>) -> Result<(), LinkStateError> {
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        let link_id = self.id;
        match (self.link_type, locked_fsm.state) {
            (LinkType::NodeToNode, LinkState::Helloing) => {
                locked_fsm.set_state(LinkState::Active);
                debug!(target: LINK_STATE, "{} finished helloing.  Becoming active", asm.formatted_link_id(link_id));
                Ok(())
            }
            (LinkType::NodeToAdapter, LinkState::Helloing) => {
                debug!(
                    target: LINK_STATE,
                    "{} received hello request", asm.formatted_link_id(link_id)
                );

                // Reply with a Hello Response.

                // Technically we do not need to supply an AAA address to an adapter fronting the visa service,
                // or if we do not have an external authentication service available.  For simplicity we just
                // always hand one out -- if we have a pool. And we only have a pool if we have already
                // connected to the visa service.
                let maybe_aaa_address = {
                    let mut address_pool = asm.address_pool.lock().unwrap();
                    if let Some(pool) = address_pool.as_mut() {
                        let aaa_address = pool.get_aaa_address();
                        debug!(target: LINK_STATE, "{}: HelloResponse - allocated AAA address: {aaa_address} (active pool size: {})",
                            asm.formatted_link_id(link_id), pool.len());
                        Some(aaa_address)
                    } else {
                        None
                    }
                };
                if let Some(aaa_address) = maybe_aaa_address {
                    self.process_assigned_aaa(asm, aaa_address)?;
                } else {
                    // No pool.  Use dummy address.
                    debug!(target: LINK_STATE, "{}: HelloResponse - no AAA pool available, no AAA address assigned", asm.formatted_link_id(link_id));
                }

                let policy_id: i64 = 0; // TODO: We get policy ID from visa service. Record that somewhere, access it here.
                let oidc_idps = get_available_oidc_idps(&asm, link_id);

                mgmt::requests::send_hello_success_response(
                    &asm,
                    link_id,
                    policy_id,
                    &oidc_idps,
                    maybe_aaa_address,
                )
                .enqueue();

                // Now follow with an init auth request.

                locked_fsm.set_state(LinkState::WaitForAcquireZprAddress);
                self.send_init_authentication_request(asm);
                debug!(
                    target: LINK_STATE,
                    "{} finished helloing.  Waiting for other side to respond to init-auth", asm.formatted_link_id(link_id)
                );
                Ok(())
            }

            (LinkType::AdapterToNode, _) => {
                // Adapters should not be receiving these messages from nodes
                Err(LinkStateError::InvalidOperation(
                    "Discarded unsolicited Hello Request".to_string(),
                ))
            }

            (_, _) => Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "ReceivedHelloRequest",
            )),
        }
    }

    /// This is called when we receive an AAA address assignment.
    /// Does not generate an error.
    fn process_assigned_aaa(
        &self,
        _asm: &Arc<Assembly>,
        aaa_addr: IpAddress,
    ) -> Result<(), LinkStateError> {
        // Just keep track of this for cleanup later.
        let link_id = self.id;
        debug!(target: LINK_STATE, "Link {link_id} assigned AAA address {aaa_addr}");
        let mut link_data = self.locked_data.lock().unwrap();
        link_data.aaa_address = Some(aaa_addr);
        Ok(())
    }

    /// This is kicked off by [LinkEvent::ReceivedHelloResponse].
    /// That event may be generated when we have sent hello
    /// message ourselves [LinkStateWrapper::maybe_send_hello]
    ///
    /// Update link state based on received hello response
    /// Transitions from Helloing to Registering Actor Address
    /// Sends a Register Actor Address request if this is an adapter
    fn process_hello_response(
        &self,
        asm: &Arc<Assembly>,
        code: ResponseCode,
        maybe_aaa_addr: Option<IpAddress>,
        maybe_oidc_idps: Option<Vec<auth::OidcIdpInfo>>,
    ) -> Result<(), LinkStateError> {
        if code == ResponseCode::Other {
            // Received an error response.
            return self.process_error_response(&asm);
        }

        let link_id = self.id;
        let mut locked_fsm = self.locked_fsm.lock().unwrap();

        match (self.link_type, locked_fsm.state) {
            (LinkType::AdapterToNode, LinkState::Helloing) => {
                let mut link_data = self.locked_data.lock().unwrap();
                link_data.oidc_idps = maybe_oidc_idps;

                // On the node side, the aaa_address link_data field is used to keep track of the
                // AAA we handed out to the peer.  On the client-adapter side, we hold the AAA
                // we got from the node in there.
                link_data.aaa_address = maybe_aaa_addr;
                drop(link_data);

                // The adapter is waiting for an init-auth-request.
                locked_fsm.set_state(LinkState::WaitForInitAuth);
                debug!(
                    target: LINK_STATE,
                    "{} finished helloing.  Now waiting for init auth.", asm.formatted_link_id(link_id)
                );
                let stowed_init_auth = std::mem::take(&mut locked_fsm.stowed_init_auth);
                drop(locked_fsm);
                if let Some(stowed_init_auth) = stowed_init_auth {
                    self.process_init_auth(
                        asm,
                        stowed_init_auth.bootstrap,
                        stowed_init_auth.challenge,
                    )
                } else {
                    Ok(())
                }
            }
            (LinkType::NodeToNode, LinkState::Helloing) => {
                locked_fsm.set_state(LinkState::Active);
                debug!(target: LINK_STATE, "{} finished helloing.  Becoming active", asm.formatted_link_id(link_id));
                Ok(())
            }
            (LinkType::NodeToAdapter, _) => {
                // Nodes should not be receiving these messages from adapters
                Err(LinkStateError::InvalidOperation(
                    "Discarded unsolicited Hello Response".to_string(),
                ))
            }
            (_, _) => Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "ReceivedHelloRespone",
            )),
        }
    }

    /// The ZprAddressRequest is from adapter to node (future: joining node to node).
    /// Includes authentication blob from sender, as well as the requested addresses.
    /// Inclusion of requested addresses is temporary.
    ///
    /// A Node expects this message from an adapter sometime after sending it an
    /// init-authentication message.
    ///
    /// This will call off to visa service for checking.
    /// Results comes back through a ReceivedAuthorizeResponse event.
    fn process_acquire_zpr_address_request(
        &self,
        asm: &Arc<Assembly>,
        addrs: Option<Vec<IpAddress>>,
        blob: String,
    ) -> Result<(), LinkStateError> {
        let link_id = self.id;
        let a2a_dh_public_key = asm //grab public key from its peer state
            .peer_table
            .inspect(link_id, |ps| *ps.a2a_dh_pubkey.get())
            .flatten();
        let mut locked_fsm = self.locked_fsm.lock().unwrap();

        match (self.link_type, locked_fsm.state) {
            (LinkType::NodeToAdapter, LinkState::WaitForAcquireZprAddress) => {}

            (_, _) => {
                return Err(LinkStateError::InvalidOperation(
                    "Discarded unsolicited acquire ZPR address request".to_string(),
                ));
            }
        }

        // The client adapter may already be configured with an address. It will then
        // be up to the visa service to decide if that is allowed.  If no address is
        // passed here we expect the visa service to assign an address.
        //
        let requested_addr = match addrs {
            Some(addr) => {
                if addr.len() == 1 {
                    addr[0]
                } else if addr.is_empty() {
                    IpAddress::UNSPECIFIED
                } else {
                    // If we have multiple addresses, we cannot handle that. (yet?)
                    warn!(target: LINK_STATE, "{} received acquire request with multiple addresses", asm.formatted_link_id(link_id));
                    drop(locked_fsm);
                    return self.process_error_response(asm);
                }
            }
            None => IpAddress::UNSPECIFIED,
        };

        debug!(
            target: LINK_STATE,
            "{} received acquire addr request for actor (requested_addr = {}).", asm.formatted_link_id(link_id), requested_addr
        );

        // Every blob needs its challenge checked before we forward it on.

        let Ok(d_blobs) = auth::decode_blobs(&blob) else {
            warn!(target: LINK_STATE, "{} received acquire request with invalid blob", asm.formatted_link_id(link_id));
            drop(locked_fsm);
            return self.process_error_response(asm);
        };

        for d_blob in &d_blobs {
            match d_blob {
                AuthBlob::SelfSigned(ss_blob) => {
                    if !self.check_self_signed_blob(asm, link_id, ss_blob) {
                        drop(locked_fsm);
                        return self.process_error_response(asm);
                    }
                }
                AuthBlob::Oidc(oidc_blob) => {
                    if !self.check_oidc_blob(asm, link_id, oidc_blob) {
                        drop(locked_fsm);
                        return self.process_error_response(asm);
                    }
                }
            }
        }

        // Stash the OIDC identity the actor is authenticating with so silent
        // renewal (zipline#45) can re-prove against the SAME issuer later.
        // The nonce is derived from the (verified) challenge exactly as
        // build_connect_request derives the one sent to the VS.
        if let Some(oidc_blob) = d_blobs.iter().find_map(|b| match b {
            AuthBlob::Oidc(oidc) => Some(oidc),
            _ => None,
        }) {
            self.stash_renewal_identity(asm, link_id, oidc_blob);
        }

        locked_fsm.set_state(LinkState::RegisterAA);

        let is_vs_link = asm
            .peer_table
            .lookup_special_peer(SpecialPeerName::VisaServiceAdapter)
            .is_some_and(|vs_id| vs_id.get() == link_id);

        // Now we have verified our part of the blob, we can send to the visa service for checking the signature.
        // The vs is also sent the public key so it can distribute to peer adapter
        let conn_req =
            visa_mgmt::build_connect_request(asm, requested_addr, &d_blobs, a2a_dh_public_key)?;
        drop(locked_fsm);

        if !is_vs_link {
            visa_mgmt::authorize_connect(asm, link_id, conn_req);
            return Ok(());
        }

        debug!(target: LINK_STATE, "deferring visa service authorize call, authorizing ourselves (requested_addr = {requested_addr})");
        *asm.deferred_vs_connect.lock().unwrap() = Some((link_id, requested_addr, conn_req));

        // Need to send a grant here anyway to "turn on" the adapter (and outselves)
        // So pretend we are the visa service and handle our own authorization.
        if let Err(e) = asm.process_link_state_event(
            link_id,
            LinkEvent::ReceivedAuthorizeResponse(requested_addr),
        ) {
            error!(target: LINK_STATE, "{} failed to process authorize response: {e}", asm.formatted_link_id(link_id));
        }

        Ok(())
    }

    fn check_self_signed_blob(
        &self,
        asm: &Arc<Assembly>,
        link_id: LinkId,
        ss_blob: &ZdpSelfSignedBlob,
    ) -> bool {
        // Now check that the CN in the presented blob matches the CN the peer used to establish link.
        let Some(peer_state) = asm.peer_table.get(link_id) else {
            warn!(target: LINK_STATE, "{} blob check failed: cannot find peer state entry", asm.formatted_link_id(link_id));
            return false;
        };
        let Some(sa) = peer_state.get_established_transport_association() else {
            warn!(target: LINK_STATE, "{} blob check failed: cannot find SA", asm.formatted_link_id(link_id));
            return false;
        };

        let key = asm.peer_table.inspect(link_id, {
            |peer| {
                let mut key = [0u8; AUTH_KEY_SIZE_BYTES];
                key[0..AUTH_KEY_SIZE_BYTES].copy_from_slice(&peer.auth_key[0..AUTH_KEY_SIZE_BYTES]);
                key
            }
        });
        if key.is_none() {
            warn!(target: LINK_STATE, "{} received acquire request but have no auth key", asm.formatted_link_id(link_id));
            return false;
        }
        let key = key.unwrap();

        // Adapters using self-generated keys present no certificate during
        // keying, so there is no cert CN to bind the blob to; the visa
        // service still authenticates the blob CN via the RSA signature.
        if let Err(e) =
            ss_blob.verify_blob_challenge(sa.peer_cert.as_ref().map(|c| c.get_cert()), &key)
        {
            warn!(target: LINK_STATE, "{} challenge verification failed: {e}", asm.formatted_link_id(link_id));
            return false;
        }
        true
    }

    /// Verify an OIDC blob's challenge: HMAC with this link's auth key plus
    /// freshness. Identity itself is carried by the ID token, which the visa
    /// service verifies; there is no CN leg here.
    fn check_oidc_blob(
        &self,
        asm: &Arc<Assembly>,
        link_id: LinkId,
        oidc_blob: &auth::ZdpOidcBlob,
    ) -> bool {
        let key = asm.peer_table.inspect(link_id, {
            |peer| {
                let mut key = [0u8; AUTH_KEY_SIZE_BYTES];
                key[0..AUTH_KEY_SIZE_BYTES].copy_from_slice(&peer.auth_key[0..AUTH_KEY_SIZE_BYTES]);
                key
            }
        });
        let Some(key) = key else {
            warn!(target: LINK_STATE, "{} received acquire request but have no auth key", asm.formatted_link_id(link_id));
            return false;
        };

        if let Err(e) = oidc_blob.verify_challenge(&key) {
            warn!(target: LINK_STATE, "{} OIDC challenge verification failed: {e}", asm.formatted_link_id(link_id));
            return false;
        }
        true
    }

    /// Store the OIDC identity (issuer's advertised client config + the
    /// challenge-derived nonce) this actor is authenticating with, so silent
    /// renewal (zipline#45) re-proves against the SAME issuer. The issuer is
    /// resolved from the node's auth-services list; a blob naming an issuer
    /// the VS no longer advertises just means renewal will not be possible.
    fn stash_renewal_identity(
        &self,
        asm: &Arc<Assembly>,
        link_id: LinkId,
        oidc_blob: &auth::ZdpOidcBlob,
    ) {
        let Some(idp) = get_available_oidc_idps(asm, link_id)
            .into_iter()
            .find(|idp| idp.issuer == oidc_blob.issuer)
        else {
            warn!(target: LINK_STATE,
                "{}: OIDC issuer {} is not in the advertised auth services; silent renewal will not be available",
                asm.formatted_link_id(link_id), oidc_blob.issuer);
            return;
        };

        // Same derivation as build_connect_request: the nonce bound into the
        // credential is SHA-256 of the (already HMAC-verified) challenge.
        let challenge_bytes = BASE64_STANDARD
            .decode(&oidc_blob.challenge)
            .unwrap_or_default();
        let mut challenge = [0u8; 48];
        if challenge_bytes.len() == 48 {
            challenge.copy_from_slice(&challenge_bytes);
        }
        let nonce = auth::oidc_nonce_for_challenge(&challenge);
        self.set_renewal_identity(RenewalIdentity { idp, nonce });
    }

    /// Grant ZPR Address message is from a node to an adapter and includes the
    /// result of authentication verification.
    ///
    /// If this inidicates success it will include the ZPR addresses we are
    /// supposed to use.  If this indicates failure we should tear down the link.
    ///
    /// **The address model (zipline#83):** a configured `--zpr-addr` /
    /// `zpr_addr` is a *demand*, not a request. We forward it to the fabric in
    /// the acquire request, and the fabric normally grants it back — but when
    /// the visa service scrubs the request (e.g. a user-only actor matching no
    /// join policy) it assigns a dynamic address instead. An adapter with a
    /// configured address cannot honor such a grant: its TUN device and routes
    /// were provisioned for the configured address, so it would keep sourcing
    /// traffic from an address it no longer owns and the node would deny every
    /// bind — silently, from the user's point of view. So a granted set that
    /// differs from the non-empty configured set is a fatal error: log both
    /// addresses with the remedy (remove the `--zpr-addr` argument / `zpr_addr`
    /// config line and try again), record
    /// [AuthFailureReason::GrantedAddressMismatch] for `ph-cli link show`,
    /// tear the link down, and exit the process non-zero — even if other links
    /// exist. An adapter with *no* configured address accepts whatever the
    /// fabric grants: the granted address is added to the TUN and becomes the
    /// local ZPR address set.
    ///
    /// `result` is Ok(granted addresses) on success; Err(code) carries the
    /// node's failure code, which we map to an [AuthFailureReason] so ph-cli
    /// can report why the connection failed.
    fn process_grant_zpr_address_request(
        &self,
        asm: &Arc<Assembly>,
        result: Result<Vec<IpAddress>, ResponseCode>,
    ) -> Result<(), LinkStateError> {
        let link_id = self.id;
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        match (self.link_type, locked_fsm.state) {
            (LinkType::AdapterToNode, LinkState::RegisterAA) => {
                match result {
                    Ok(addrs) => {
                        // zipline#83: a configured `--zpr-addr` / `zpr_addr`
                        // is a demand (see the doc comment above). A grant
                        // differing from a non-empty configured set means the
                        // fabric refused it (e.g. the visa service scrubbed
                        // the unauthenticated claim: no matching join
                        // policy). Running on the granted address would leave
                        // the TUN/routes sourcing from the configured one and
                        // the node denying every bind — so refuse to run:
                        // record the mismatch, tear the link down, and exit
                        // the process non-zero with the remedy.
                        //
                        // The demand compared against is the STARTUP
                        // configuration, frozen in
                        // `Assembly::configured_zpr_addr_demand` — not the
                        // current `config.zpr_addr`, which
                        // `set_local_zpr_addrs` overwrites with each dynamic
                        // grant. An adapter started without `--zpr-addr`
                        // must keep accepting fabric-assigned addresses on
                        // every reconnect, even when they differ from the
                        // previous grant.
                        let configured = asm.configured_zpr_addr_demand.clone();
                        let granted_std: Vec<IpAddr> = addrs.iter().map(IpAddr::from).collect();
                        if !configured.is_empty() && {
                            let mut c = configured.clone();
                            let mut g = granted_std.clone();
                            c.sort();
                            g.sort();
                            c != g
                        } {
                            let msg = format!(
                                "fabric granted ZPR address(es) {granted_std:?} but this adapter \
                                 is configured to demand {configured:?}; it cannot originate \
                                 traffic from an address it was not granted. Remove the \
                                 --zpr-addr argument / zpr_addr config line and try again \
                                 to accept a fabric-assigned address."
                            );
                            error!(target: LINK_STATE, "{} {msg}", asm.formatted_link_id(link_id));
                            self.record_auth_failure(AuthFailureReason::GrantedAddressMismatch {
                                requested: configured,
                                granted: granted_std,
                            });
                            locked_fsm.set_state(LinkState::Error);
                            drop(locked_fsm);
                            asm.signal_fatal_error(msg);
                            return self.initiate_close(asm, TerminateReason::Other);
                        }

                        info!(target: LINK_STATE, "{} granted ZPR addresses {:?}, becoming ACTIVE", asm.formatted_link_id(link_id), addrs);

                        let data = self.locked_data.lock().unwrap();
                        if let Some(aaa_addr) = data.aaa_address {
                            drop(data);
                            // TODO: deal with the potential i/o blocking here ( https://github.com/org-zpr/zpr-core/issues/938 )
                            match asm
                                .tun_ctl
                                .clear_address(aaa_addr.into(), ZPRNET_PREFIX_LEN)
                            {
                                Ok(()) => {}
                                Err(e) => {
                                    warn!(target: LINK_STATE, "{} failed to clear AAA address: {e}", asm.formatted_link_id(link_id));
                                    // continue...
                                }
                            }
                        } else {
                            drop(data);
                        }
                        // I keep the aaa address around... TODO: should we clear it?

                        if addrs.len() > 1 {
                            warn!(target: LINK_STATE, "{} multiple addresses in Grant ZPR Address not supported: using first one only", asm.formatted_link_id(link_id));
                        }

                        // TODO: deal with the potential i/o blocking here ( https://github.com/org-zpr/zpr-core/issues/938 )
                        if let Err(e) = asm.tun_ctl.add_address(addrs[0].into(), ZPRNET_PREFIX_LEN)
                        {
                            warn!(target: LINK_STATE, "{} failed to set ZPR address: {e}", asm.formatted_link_id(link_id));
                            locked_fsm.set_state(LinkState::Error);
                            drop(locked_fsm);
                            return self.initiate_close(asm, TerminateReason::Other);
                        }

                        // zipline#88: replies to a peer on a fabric-assigned
                        // (dynamic-pool) address are dropped unless every
                        // adapter's TUN routes the whole ZPR internal network
                        // — add_address above only yields an on-link route
                        // for OUR prefix. Install fd5a:5052::/32 on-link.
                        //
                        // Failure handling differs by path (operator ruling,
                        // zipline#88): on a dynamic grant (nothing was
                        // configured) fabric-installed state is all the
                        // adapter has, so a failed install means the link
                        // cannot function — fail the activation ASAP, like a
                        // failed add_address. On the static path the
                        // deployment provisioned addressing and routes out of
                        // band and may well already carry them, so warn and
                        // continue.
                        if let Err(e) = asm
                            .tun_ctl
                            .add_route(IpAddr::V6(ZPR_INTERNAL_NETWORK), ZPRNET_PREFIX_LEN)
                        {
                            if configured.is_empty() {
                                warn!(target: LINK_STATE, "{} failed to install ZPR internal-network route {ZPR_INTERNAL_NETWORK}/{ZPRNET_PREFIX_LEN}: {e}; a dynamically addressed adapter cannot function without it", asm.formatted_link_id(link_id));
                                locked_fsm.set_state(LinkState::Error);
                                drop(locked_fsm);
                                return self.initiate_close(asm, TerminateReason::Other);
                            }
                            warn!(target: LINK_STATE, "{} failed to install ZPR internal-network route {ZPR_INTERNAL_NETWORK}/{ZPRNET_PREFIX_LEN}: {e}; continuing — statically provisioned deployments may already carry it", asm.formatted_link_id(link_id));
                        }

                        // Update the global view of our ZPR addresses.
                        asm.set_local_zpr_addrs(addrs);

                        asm.tun_ctl.set_carrier(true).unwrap();
                        debug!(
                            target: LINK_STATE,
                            "{} finished registering actor address: becoming active", asm.formatted_link_id(link_id)
                        );
                        self.run_active(asm, locked_fsm)
                    }
                    Err(code) => {
                        // Grant failed: record why so showLink / ph-cli can report it.
                        let reason = match code {
                            ResponseCode::PolicyDenied => AuthFailureReason::PolicyDenied,
                            ResponseCode::AuthUnavailable => AuthFailureReason::AuthUnavailable,
                            ResponseCode::AuthFailed => AuthFailureReason::VisaServiceRejected(
                                "visa service rejected authentication".to_string(),
                            ),
                            other => AuthFailureReason::VisaServiceRejected(format!(
                                "grant failed with code {other:?}"
                            )),
                        };
                        warn!(target: LINK_STATE, "{} failed to be granted ZPR address: {reason:?}", asm.formatted_link_id(link_id));
                        self.record_auth_failure(reason);
                        locked_fsm.set_state(LinkState::Error);
                        drop(locked_fsm);
                        self.initiate_close(asm, TerminateReason::Other)
                    }
                }
            }
            (LinkType::AdapterToNode, LinkState::Active) => {
                // Assume this is just a retransmit.
                debug!(target: LINK_STATE, "{} received unsolicited Grant ZPR Address request while already in active, ignoring", asm.formatted_link_id(link_id));
                Ok(())
            }
            (_, _) => Err(LinkStateError::InvalidOperation(
                "Discarded unsolicited Grant Zpr Address request".to_string(),
            )),
        }
    }

    /// This is the event handler fro the return path from the visa service AUTHORIZE operation.
    /// This needs to trigger sending of the Grant Address message.
    ///
    /// This is happening on a NODE.
    ///
    /// This is only called for SUCCESSFUL responses (unsuccessful responses trigger a link error).
    ///
    /// Transitions to [LinkState::Active].  (Adapter will terminate the link if it doesn't like our grant.)
    ///
    fn process_authorize_response(
        &self,
        asm: &Arc<Assembly>,
        zpr_addr: IpAddress,
    ) -> Result<(), LinkStateError> {
        let mut locked_fsm = self.locked_fsm.lock().unwrap();

        info!(target: LINK_STATE, "{} received authorize response with ZPR address {}", asm.formatted_link_id(self.id), zpr_addr);

        match (self.link_type, locked_fsm.state) {
            (LinkType::NodeToAdapter, LinkState::RegisterAA) => {} // ok
            (_, _) => {
                return Err(LinkStateError::InvalidOperation(
                    "Discarded unsolicited authorize response".to_string(),
                ));
            }
        }

        locked_fsm.actor_addresses.clear();
        locked_fsm.actor_addresses.push(zpr_addr);

        // Send a Grant message, consume the response and then send in an event
        // indicating we got it (ReceivedGrantResponse).

        // Will call back via ReceivedGrantResponse event if successful.
        self.send_grant_zpr_address_request(asm, &locked_fsm.actor_addresses);
        debug!(target: LINK_STATE, "{} has ACKd the grant.  Becoming active", asm.formatted_link_id(self.id));
        self.run_active(asm, locked_fsm)
    }

    /// Handle an authorize failure from the visa service: report the reason to
    /// the adapter in a Grant with the mapped failure code and no addresses,
    /// then tear the link down.
    ///
    /// This is happening on a NODE.
    fn process_authorize_failure(
        &self,
        asm: &Arc<Assembly>,
        code: zpr::vsapi_types::ErrorCode,
        msg: String,
    ) -> Result<(), LinkStateError> {
        let link_id = self.id;
        let mut locked_fsm = self.locked_fsm.lock().unwrap();

        warn!(target: LINK_STATE, "{} visa service refused authorization: {code:?}: {msg}",
            asm.formatted_link_id(link_id));

        match (self.link_type, locked_fsm.state) {
            (LinkType::NodeToAdapter, LinkState::RegisterAA) => {} // ok
            (_, _) => {
                return Err(LinkStateError::InvalidOperation(
                    "Discarded unsolicited authorize failure".to_string(),
                ));
            }
        }

        // The failure grant must go out before the close, or the adapter only
        // ever observes a terminated link with no reason.
        mgmt::requests::send_grant_zpr_address_request(
            asm,
            link_id,
            visa_mgmt::grant_code_for_vs_error(&code),
            &[],
        )
        .enqueue();

        asm.counters.management[ManagementCounterType::PeerHandshakeFailure].increment();
        locked_fsm.set_state(LinkState::Error);
        drop(locked_fsm);
        self.initiate_close(asm, TerminateReason::Other)
    }

    /// Handle an init-auth message from sender.
    ///
    /// This is a slow function that is called AFTER we send a reply to the
    /// init-auth message.
    ///
    /// If this is bootstrap and we are configured for bootstrap we can self-authenticate
    /// and send in an AcquireZprAddressRequest.
    ///
    /// For now we must be in WaitForInitAuth to accept this message.
    /// We transition to RegisterAA if we successfully self-auth, otherwise we go to
    /// error and shutdown the link.
    fn process_init_auth(
        &self,
        asm: &Arc<Assembly>,
        bootstrap: bool,
        challenge: Option<auth::ZdpInitAuthenticationPayload>,
    ) -> Result<(), LinkStateError> {
        let link_id = self.id;

        // Grab a copy of what we know about OIDC from the hello exchange.
        let data = self.locked_data.lock().unwrap();
        let oidc_idps = data.oidc_idps.clone().unwrap_or_default();
        let auth_agent = data.auth_agent.clone();
        drop(data);

        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        match (self.link_type, locked_fsm.state) {
            // NOTE: This is not exactly right, in general we can get an InitAuth at any time, though we
            // may not want to act on it and sometimes may be a protocol error.
            (LinkType::AdapterToNode, LinkState::WaitForInitAuth) => {
                debug!(target: LINK_STATE, "{} received init auth (bootstrap_supported: {}, bootstrap_configured: {}, oidc_idps: {}, agent: {})",
                    asm.formatted_link_id(link_id), bootstrap, asm.config.get().bootstrap.is_some(),
                    oidc_idps.len(), auth_agent.is_some());

                // An advertised OIDC IdP means the network wants user
                // authentication: run it through the out-of-band AuthAgent,
                // adding a bootstrap (SS) blob alongside when a key is
                // configured. With no agent registered we can still proceed
                // on the legacy device-only paths below if bootstrap is
                // available; otherwise the connection cannot be authenticated.
                if !oidc_idps.is_empty() {
                    let Some(challenge) = challenge.clone() else {
                        error!(target: LINK_STATE, "{} received init auth with no challenge", asm.formatted_link_id(link_id));
                        locked_fsm.set_state(LinkState::Error);
                        drop(locked_fsm);
                        return self.initiate_close(asm, TerminateReason::Other);
                    };

                    if let Some(agent) = auth_agent {
                        // Bootstrap key configured -> the SS blob rides along.
                        let mut blobs = Vec::new();
                        if let Some(bs) = asm.config.get().bootstrap.as_ref() {
                            match bs.authenticate_blob(&challenge) {
                                Ok(ss_blob) => blobs.push(AuthBlob::SelfSigned(ss_blob)),
                                Err(e) => {
                                    error!(target: LINK_STATE, "{} failed to self-authenticate: {e:?}", asm.formatted_link_id(link_id));
                                    locked_fsm.set_state(LinkState::Error);
                                    drop(locked_fsm);
                                    return self.initiate_close(asm, TerminateReason::Other);
                                }
                            }
                        }

                        locked_fsm.set_state(LinkState::WaitForUserAuth);
                        self.set_timeout(
                            asm,
                            &mut locked_fsm,
                            config::OIDC_USER_INTERACTION_TIMEOUT,
                        );
                        // Tag this attempt with the logical clock its timeout
                        // was armed with; do_oidc_authenticate discards the
                        // completion if the clock has moved on (timeout fired,
                        // link restarted, a newer attempt is underway).
                        let attempt_clock = locked_fsm.logical_clock;
                        drop(locked_fsm);
                        self.do_oidc_authenticate(
                            asm,
                            agent,
                            oidc_idps[0].clone(),
                            &challenge,
                            blobs,
                            attempt_clock,
                        );
                        return Ok(());
                    }

                    if asm.config.get().bootstrap.is_none() {
                        // OIDC required, no agent, and no device key either.
                        warn!(target: LINK_STATE, "{} OIDC IdP advertised but no AuthAgent registered and no bootstrap key", asm.formatted_link_id(link_id));
                        drop(locked_fsm);
                        return self
                            .process_authentication_failure(asm, AuthFailureReason::NoAgent);
                    }
                    // No agent but a bootstrap key exists: fall through to the
                    // device-only bootstrap path, exactly as before OIDC.
                }

                // If we can do bootstrap and it is allowed, then do that.
                if bootstrap && asm.config.get().bootstrap.is_some() {
                    if challenge.is_none() {
                        error!(target: LINK_STATE, "{} received init auth with no challenge", asm.formatted_link_id(link_id));
                        locked_fsm.set_state(LinkState::Error);
                        drop(locked_fsm);
                        return self.initiate_close(asm, TerminateReason::Other);
                    }
                    let challenge = challenge.unwrap();
                    if let Some(bs) = asm.config.get().bootstrap.as_ref() {
                        match bs.authenticate(&challenge) {
                            Ok(blobstr) => {
                                // The send function below will invoke a state event callback.
                                // We staty in RegisterAA state until we get a grant.
                                let requested_addrs = asm.get_local_zpr_addrs_std();
                                self.send_acquire_zpr_address_request(
                                    asm,
                                    &requested_addrs,
                                    &blobstr,
                                );
                                locked_fsm.set_state(LinkState::RegisterAA);
                                self.set_timeout(
                                    asm,
                                    &mut locked_fsm,
                                    config::VS_GRANT_REQUEST_TIMEOUT,
                                );
                            }
                            Err(e) => {
                                error!(target: LINK_STATE, "{} failed to self-authenticate: {e:?}", asm.formatted_link_id(link_id));
                                // Shutdown the link
                                locked_fsm.set_state(LinkState::Error);
                                drop(locked_fsm);
                                return self.initiate_close(asm, TerminateReason::Other);
                            }
                        }
                    }
                } else {
                    // Bootstrap not allowed or not configured, and no OIDC IdP
                    // was advertised: there is no way to authenticate this
                    // link. The legacy BAS/OAuthRsa fallback that used to live
                    // here was removed (zipline#15).
                    warn!(target: LINK_STATE, "{} received init auth but no authentication method is available (no OIDC IdP advertised, no bootstrap key)", asm.formatted_link_id(link_id));
                    drop(locked_fsm);
                    return self
                        .process_authentication_failure(asm, AuthFailureReason::AuthUnavailable);
                }
            }
            (LinkType::AdapterToNode, LinkState::Helloing) => {
                // init auth can race helloing; if so, stow it away until we finish helloing
                locked_fsm.stowed_init_auth = Some(InitAuthData {
                    bootstrap,
                    challenge,
                });
            }
            (_, _) => {
                return Err(LinkStateError::UnexpectedTransition(
                    locked_fsm.state,
                    "ReceivedInitAuth",
                ));
            }
        }

        Ok(())
    }

    /// The node sends init-authentication to the adapter, we await the ACK to
    /// clear our timeout.  The adapter will in the meantime take care of doing
    /// whatever authentication it needs to and will eventually send us an acquire-zpr-address
    /// message with the authentication results (blob).
    fn process_init_auth_ack(&self, asm: &Arc<Assembly>) -> Result<(), LinkStateError> {
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        match (self.link_type, locked_fsm.state) {
            (LinkType::NodeToAdapter, LinkState::WaitForAcquireZprAddress) => {
                debug!(target: LINK_STATE, "{} received init auth ack", asm.formatted_link_id(self.id));
                // Now we are waiting on the adapter to perform authentication and
                // that may involve external services and could be quite slow relative to a
                // straightforward ZDP response.  So, we set a longer timeout.  We do not retransmit
                // anything... if we do not get auth within a reasonable amount of time we shut down
                // the link.
                self.set_timeout(asm, &mut locked_fsm, config::ACTOR_AUTHENTICATION_TIMEOUT);
                Ok(())
            }
            (_, _) => Err(LinkStateError::InvalidOperation(
                "Discarded unsolicited init auth ack".to_string(),
            )),
        }
    }

    fn process_init_auth_timeout(&self, asm: &Arc<Assembly>) -> Result<(), LinkStateError> {
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        match (self.link_type, locked_fsm.state) {
            (LinkType::NodeToAdapter, LinkState::WaitForAcquireZprAddress) => {
                error!(target: LINK_STATE, "{} received init auth timeout", asm.formatted_link_id(self.id));
                locked_fsm.set_state(LinkState::Error);
                drop(locked_fsm);
                self.initiate_close(asm, TerminateReason::RequestTimedOut)
            }
            (_, _) => Err(LinkStateError::InvalidOperation(
                "Discarded unsolicited init auth timeout".to_string(),
            )),
        }
    }

    /// Send off the Init-Authentication message with a blob that the receiver could
    /// use for authentication.
    fn send_init_authentication_request(&self, asm: &Arc<Assembly>) {
        let link_id = self.id;

        // TODO: Whether or not we are in bootstrap mode comes from visa service.  For now hardcoded ON.
        let is_bootstrap = true;

        let payload: auth::ZdpInitAuthenticationPayload;
        let mut flags = 0u8;

        if is_bootstrap {
            flags |= zdp::init_authentication_flags::BOOTSTRAP_SUPPORT;

            // TODO: Pretty sure I do not need `inspect_sync` below. The key is set at create time and not changed.
            let key = asm.peer_table.inspect(link_id, {
                |peer| {
                    let mut key = [0u8; auth::AUTH_KEY_SIZE_BYTES];
                    key[0..auth::AUTH_KEY_SIZE_BYTES]
                        .copy_from_slice(&peer.auth_key[0..auth::AUTH_KEY_SIZE_BYTES]);
                    key
                }
            });
            match key {
                Some(key) => payload = auth::ZdpInitAuthenticationPayload::new(&key),
                None => {
                    // TODO: Possibly we want to send the Init Authentication message anyway, but
                    //       just not support bootstrap mode.
                    error!(target: LINK_STATE, "unable to send Init Authentication: no auth key found for {}", asm.formatted_link_id(link_id));
                    if let Err(e) = asm.process_link_state_event(link_id, LinkEvent::Error) {
                        error!(target: LINK_STATE, "event handling error: {e}");
                    }
                    return;
                }
            }
        } else {
            payload = auth::ZdpInitAuthenticationPayload::default(); // empty
        }

        let task_asm = asm.clone();
        tokio::task::spawn_local(async move {
            match mgmt::requests::send_init_authentication_request(
                &task_asm, link_id, flags, payload,
            )
            .limit_retries(config::DEFAULT_ZDPR_RETRY_LIMIT)
            .await
            {
                Ok(PacketStatus::Acked) => {
                    // ignore error here, it just means we've moved on to another state and got the ACK (very) late
                    let _ =
                        task_asm.process_link_state_event(link_id, LinkEvent::ReceivedInitAuthAck);
                }

                Ok(PacketStatus::Canceled) => {
                    // timed out getting the ACK, tear down the link
                    let _ = task_asm
                        .process_link_state_event(link_id, LinkEvent::ReceivedInitAuthTimeout);
                }

                Err(MgmtSendError::LinkClosed) => {
                    // link was terminated, simply return
                    return;
                }
            }
        });
    }

    /// Send the Grant message
    fn send_grant_zpr_address_request(&self, asm: &Arc<Assembly>, addrs: &[IpAddress]) {
        // Convert the IpAddresses into IpAddrs
        let ipaddrs = addrs
            .iter()
            .map(|addr| IpAddr::from(addr))
            .collect::<Vec<_>>();

        mgmt::requests::send_grant_zpr_address_request(
            asm,
            self.id,
            ResponseCode::Success,
            &ipaddrs,
        )
        .enqueue();
    }

    /// Run the out-of-band OIDC authentication through the registered
    /// AuthAgent in a tokio task.
    /// - [LinkEvent::AuthenticationSuccess] with `base_blobs` plus the OIDC
    ///   blob on success
    /// - [LinkEvent::AuthenticationFailure] with the agent's reason on failure
    ///
    /// The caller has already entered [LinkState::WaitForUserAuth], armed
    /// [config::OIDC_USER_INTERACTION_TIMEOUT], and passed the logical clock
    /// captured at arming as `attempt_clock`. A completion whose clock no
    /// longer matches the FSM's is STALE — its timeout fired, the link was
    /// closed/restarted, or a newer attempt (with a different challenge) is
    /// underway — and is discarded here rather than delivered, so an old
    /// token bound to an old challenge can never be consumed by a newer
    /// WaitForUserAuth attempt.
    fn do_oidc_authenticate(
        &self,
        asm: &Arc<Assembly>,
        agent: AuthAgentHandle,
        idp: auth::OidcIdpInfo,
        challenge_payload: &auth::ZdpInitAuthenticationPayload,
        base_blobs: Vec<AuthBlob>,
        attempt_clock: u64,
    ) {
        let link_id = self.id;

        // The raw 48-byte challenge: nonce || ctime || hmac.
        let mut challenge = [0u8; 48];
        challenge[0..8].copy_from_slice(&challenge_payload.nonce);
        challenge[8..16].copy_from_slice(&challenge_payload.ctime.to_bytes());
        challenge[16..48].copy_from_slice(&challenge_payload.hmac);

        let nonce = auth::oidc_nonce_for_challenge(&challenge);
        let issuer = idp.issuer.clone();
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let request = OidcCredentialRequest {
            idp,
            nonce,
            interactive: true,
            reply: reply_tx,
        };

        if agent.send(request).is_err() {
            // The agent went away (ph-cli disconnected).
            warn!(target: LINK_STATE, "{}: AuthAgent is gone, cannot authenticate", asm.formatted_link_id(link_id));
            if let Err(e) = asm.process_link_state_event(
                link_id,
                LinkEvent::AuthenticationFailure(AuthFailureReason::NoAgent),
            ) {
                error!(target: LINK_STATE, "{}: event handling error {e}", asm.formatted_link_id(link_id));
            }
            return;
        }

        let task_asm = asm.clone();
        tokio::task::spawn_local(async move {
            let outcome = reply_rx.await;

            // Discard a stale completion: if the logical clock moved on, this
            // attempt's timeout fired (or the link was closed/restarted) and a
            // newer attempt may be underway with a different challenge. The
            // old token must not be delivered as that newer attempt's result.
            let is_current = task_asm
                .peer_table
                .get(link_id)
                .map(|peer| {
                    peer.link_state_machine
                        .auth_attempt_is_current(attempt_clock)
                })
                .unwrap_or(false);
            if !is_current {
                debug!(target: LINK_STATE, "{}: discarding stale AuthAgent completion (attempt superseded)",
                    task_asm.formatted_link_id(link_id));
                return;
            }

            let event = match outcome {
                Ok(Ok(id_token)) => {
                    let oidc_blob = auth::ZdpOidcBlob {
                        blob_type: auth::BLOB_TYPE_OIDC.to_string(),
                        issuer,
                        id_token,
                        challenge: BASE64_STANDARD.encode(challenge),
                    };
                    let mut blobs = base_blobs;
                    blobs.push(AuthBlob::Oidc(oidc_blob));
                    LinkEvent::AuthenticationSuccess(blobs)
                }
                Ok(Err(reason)) => LinkEvent::AuthenticationFailure(reason),
                // The bridge dropped the reply without answering.
                Err(_) => LinkEvent::AuthenticationFailure(AuthFailureReason::AgentError(
                    "AuthAgent dropped the request".to_string(),
                )),
            };
            if let Err(e) = task_asm.process_link_state_event(link_id, event) {
                error!(target: LINK_STATE, "{}: event handling error {e}", task_asm.formatted_link_id(link_id));
            }
        });
    }

    /// Callback via the AuthenticationFailure event.
    /// Records the reason (for showLink / ph-cli) and tears the link down.
    fn process_authentication_failure(
        &self,
        asm: &Arc<Assembly>,
        reason: AuthFailureReason,
    ) -> Result<(), LinkStateError> {
        let link_id = self.id;
        self.record_auth_failure(reason.clone());
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        locked_fsm.set_state(LinkState::Error);
        drop(locked_fsm);
        info!(target: LINK_STATE, "{}: authentication failed: {reason:?}", asm.formatted_link_id(link_id));
        self.initiate_close(asm, TerminateReason::Other)
    }

    /// Callback via the AuthenticationSuccess event.
    ///
    /// We expect to be in the RegisterAA state (legacy ASA path) or
    /// WaitForUserAuth (OIDC via AuthAgent). Either way we send the encoded
    /// blob array in an acquire request and move to RegisterAA to wait for
    /// the grant.
    fn process_authentication_success(
        &self,
        asm: &Arc<Assembly>,
        blobs: Vec<AuthBlob>,
    ) -> Result<(), LinkStateError> {
        let link_id = self.id;
        let mut locked_fsm = self.locked_fsm.lock().unwrap();

        if !matches!(
            locked_fsm.state,
            LinkState::RegisterAA | LinkState::WaitForUserAuth
        ) {
            error!(
                "{}: authentication success ignored in unexpected state {:?}",
                asm.formatted_link_id(link_id),
                locked_fsm.state
            );
            return Ok(());
        }

        info!(target: LINK_STATE, "{}: authentication success ({} blob(s))", asm.formatted_link_id(link_id), blobs.len());
        let blobstr = auth::encode_blobs(&blobs);
        let requested_addrs = asm.get_local_zpr_addrs_std();
        self.send_acquire_zpr_address_request(asm, &requested_addrs, &blobstr);
        locked_fsm.set_state(LinkState::RegisterAA);
        self.set_timeout(asm, &mut locked_fsm, config::VS_AUTHENTICATION_TIMEOUT);
        Ok(())
    }

    /// Send Acquire message
    fn send_acquire_zpr_address_request(
        &self,
        asm: &Arc<Assembly>,
        requesting_addrs: &[IpAddr],
        blob: &str,
    ) {
        mgmt::requests::send_acquire_zpr_address_request(
            asm,
            self.id,
            requesting_addrs,
            Some(blob.as_bytes()),
        )
        .enqueue();
    }

    fn process_error_response(&self, asm: &Arc<Assembly>) -> Result<(), LinkStateError> {
        let link_id = self.id;
        asm.counters.management[ManagementCounterType::PeerHandshakeFailure].increment();
        warn!(target: LINK_STATE, "{}: bringup failed at state {:?}",
            asm.formatted_link_id(link_id),
            self.locked_fsm.lock().unwrap().state);

        self.initiate_close(&asm, TerminateReason::Other)
    }

    fn process_timeout(
        &self,
        asm: &Arc<Assembly>,
        logical_clock: u64,
    ) -> Result<(), LinkStateError> {
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        if logical_clock != locked_fsm.logical_clock {
            // timeout was for some earlier state & we won the task abort race; ignore
            return Ok(());
        }

        // handle the timeout...
        match (self.link_type, locked_fsm.state) {
            (LinkType::AdapterToNode, LinkState::WaitForUserAuth) => {
                // The user did not complete the out-of-band login in time.
                error!(target: LINK_STATE, "{}: user authentication timed out", asm.formatted_link_id(self.id));
                drop(locked_fsm);
                return self
                    .process_authentication_failure(asm, AuthFailureReason::InteractionTimeout);
            }

            (LinkType::AdapterToNode, LinkState::RegisterAA)
            | (LinkType::AdapterToNode, LinkState::Helloing) => {
                // Timeout here means we give up on the link.
                error!(target: LINK_STATE, "{}: timed out in state {:?}", asm.formatted_link_id(self.id), locked_fsm.state);
                locked_fsm.set_state(LinkState::Error);
                drop(locked_fsm);
                return self.initiate_close(asm, TerminateReason::RequestTimedOut);
            }

            (_, LinkState::Active) => {
                match locked_fsm.echo_handle.take() {
                    Some((_start_time, echo_handle)) => {
                        // there was an outstanding echo, and we've timed out
                        echo_handle.abort();
                        self.locked_data.lock().unwrap().echo_timeout += 1;
                        error!(target: LINK_STATE, "{} failed to respond to keep-alive messages", asm.formatted_link_id(self.id));
                        locked_fsm.set_state(LinkState::Error);
                        drop(locked_fsm);
                        return self.initiate_close(asm, TerminateReason::RequestTimedOut);
                    }

                    None => {
                        // no outstanding echo, time for a new one!
                        let link_id = self.id;
                        let task_asm = asm.clone();
                        let jh = tokio::task::spawn_local(async move {
                            match mgmt::requests::send_echo_request(&task_asm, link_id)
                                .acked()
                                .await
                            {
                                Ok(()) => {
                                    // success! poke the state machine
                                    // ignore any errors, that just means we've left Active and are already shutting down the link
                                    let _ = task_asm.process_link_state_event(
                                        link_id,
                                        LinkEvent::ReceivedKeepAliveResponse,
                                    );
                                }

                                // ignore link closed, we are already shutting down
                                Err(mgmt::core::MgmtSendError::LinkClosed) => (),
                            }
                        });

                        // store new echo handle and kick off timeout
                        locked_fsm.echo_handle = Some((Instant::now(), jh.abort_handle()));
                        self.set_timeout(asm, &mut locked_fsm, config::DEFAULT_KEEP_ALIVE_TIMEOUT);
                        Ok(())
                    }
                }
            }

            (_, LinkState::Closing) => {
                // This is a timeout while we are waiting for a terminate response post initiate close.
                // Now we finish the job,
                debug!(target: LINK_STATE, "{} received timeout waiting on terminate response, shutting down link", asm.formatted_link_id(self.id));
                drop(locked_fsm);
                self.clean_up_link_state(asm).detach_all();
                Ok(())
            }

            (_, _) => Err(LinkStateError::InvalidOperation(format!(
                "Ignoring unexpected timeout in state {:?}",
                locked_fsm.state
            ))),
        }
    }

    /// Nodes only. Check if this is the link to the adapter in front of the visa service
    /// and if so try to de-register this node from the VS and also stop the VSConn.
    ///
    /// If the link is still working then this can also try to send a polite
    /// "de-register" message to the visa service before we shut off our
    /// VSConn processor.
    fn maybe_disconnect_visa_service_client(
        &self,
        asm: &Arc<Assembly>,
        deregister: bool,
        reason: TerminateReason,
    ) -> Result<(), LinkStateError> {
        let mut locked_fsm = self.locked_fsm.lock().unwrap();

        if matches!(reason, TerminateReason::Shutdown) {
            locked_fsm.shutting_down = true;
        }

        if matches!(self.link_type, LinkType::NodeToAdapter) {
            let link_id = self.id;
            let vs_id = asm
                .peer_table
                .lookup_special_peer(SpecialPeerName::VisaServiceAdapter);
            if vs_id.is_some() && vs_id.unwrap().get() == link_id {
                if let Some(vsconn) = asm.vsconn.as_ref() {
                    locked_fsm.set_state(LinkState::Disconnecting(reason));

                    let task_asm = asm.clone();
                    let spawn_hndl = vsconn.clone();
                    tokio::task::spawn_local(async move {
                        debug!(target: LINK_STATE, "deregister of VS peer detected, stopping VSConn (deregister:{deregister})");
                        if let Err(e) = spawn_hndl.stop(deregister).await {
                            error!(target: LINK_STATE, "stop command to VSConn failed: {e}");
                        }
                        debug!(target: LINK_STATE, "VSConn shut down");

                        // ignore error here, it just means we've moved on to another state and got the ACK (very) late
                        let _ = task_asm
                            .process_link_state_event(link_id, LinkEvent::ReceivedDisconnectAck);
                    });

                    return Ok(());
                } // else fallthrough
            } // else fallthrough
        } // else fallthrough

        // else all the above...
        self.continue_close(asm, locked_fsm, reason)
    }

    /// Initiate the shutdown of the link
    /// Transitions to Closing from any running state
    /// Generates a Terminate Request packet
    /// Sets a timeout in case we do not get a terminate response.
    fn initiate_close(
        &self,
        asm: &Arc<Assembly>,
        reason: TerminateReason,
    ) -> Result<(), LinkStateError> {
        if matches!(self.link_type, LinkType::Internal) {
            return Err(LinkStateError::InvalidOperation(
                "cannot shutdown internal link".to_owned(),
            ));
        }

        let link_id = self.id;
        info!(target: LINK_STATE,"Initiating shutdown on {}", asm.formatted_link_id(link_id));

        // With auto-connect off (zipline#28) a completed close is terminal:
        // the tether stays Inactive until the next startLink RPC. Every
        // failure path parks the FSM in Error before initiating the close,
        // while an operator stop arrives from a running state — so an Error
        // entry with no recorded auth failure (e.g. a Helloing timeout,
        // which fails before authentication) must record one here, or
        // ph-cli's `connect` poll reads the permanently Inactive link as
        // "Pending: restart forthcoming" and hangs until its deadline.
        if self.link_type == LinkType::AdapterToNode
            && !asm.config.get().auto_connect
            && self.get_state() == LinkState::Error
            && self.get_last_auth_failure().is_none()
        {
            self.record_auth_failure(AuthFailureReason::LinkFailed(format!(
                "link failed before authentication completed ({reason:?})"
            )));
        }

        self.maybe_disconnect_visa_service_client(asm, true, reason)
    }

    fn process_disconnect_ack(&self, asm: &Arc<Assembly>) -> Result<(), LinkStateError> {
        let locked_fsm = self.locked_fsm.lock().unwrap();
        match (self.link_type, locked_fsm.state) {
            (LinkType::NodeToAdapter, LinkState::Disconnecting(reason)) => {
                debug!(target: LINK_STATE, "{} received disconnect ack", asm.formatted_link_id(self.id));
                self.continue_close(asm, locked_fsm, reason)
            }
            (_, _) => Err(LinkStateError::InvalidOperation(
                "Discarded unsolicited init auth ack".to_string(),
            )),
        }
    }

    /// Continue shutdown of the link.  Occurs after having disconnected
    /// from the visa service (if applicable).
    fn continue_close(
        &self,
        asm: &Arc<Assembly>,
        mut locked_fsm: MutexGuard<LinkStateMachine>,
        reason: TerminateReason,
    ) -> Result<(), LinkStateError> {
        locked_fsm.set_state(LinkState::Closing);

        // If this timeout fires, we end up going to `clean_up_link_state`.
        // If we get a response to our terminate we also go to `clean_up_link_state`.
        self.set_timeout(asm, &mut locked_fsm, config::DEFAULT_TERMINATE_TIMEOUT);
        let task_asm = asm.clone();
        let ingress_link_id = self.id;
        tokio::task::spawn_local(async move {
            let acked = mgmt::requests::send_terminate_link_or_docking_session(
                &task_asm,
                ingress_link_id,
                reason,
            )
            .acked();
            match acked.await {
                // FIXME why do we never get an ACK?
                Ok(()) => {
                    let _ = task_asm
                        .process_link_state_event(ingress_link_id, LinkEvent::ReceivedTerminateAck);
                }
                Err(mgmt::core::MgmtSendError::LinkClosed) => (),
            }
        });
        Ok(())
    }

    /// Tear down link state.
    /// This sends notice to the visa service that we have lost an actor.
    /// Sends a CloseDone event (which triggers [LinkStateWrapper::complete_close])
    fn clean_up_link_state(&self, asm: &Arc<Assembly>) -> tokio::task::JoinSet<()> {
        let link_id = self.id;
        let mut join_set = tokio::task::JoinSet::new();

        let locked_fsm = self.locked_fsm.lock().unwrap();

        match locked_fsm.state {
            LinkState::Closing | LinkState::Resetting => {
                drop(locked_fsm);
                info!(target: LINK_STATE, "{} is clearing its state", asm.formatted_link_id(link_id));

                let mut link_data = self.locked_data.lock().unwrap();
                if let Some(aaa_addr) = link_data.aaa_address.take() {
                    if let Some(pool) = asm.address_pool.lock().unwrap().as_mut() {
                        match pool.release_address(aaa_addr) {
                            Ok(_) => {
                                debug!(target: LINK_STATE, "{} released AAA address {aaa_addr}", asm.formatted_link_id(link_id))
                            }
                            Err(e) => {
                                error!(target: LINK_STATE, "Failed to release AAA address {aaa_addr}: {e:?}")
                            }
                        };
                    }
                }

                asm.peer_table.clear_peer_state(link_id);

                match self.link_type {
                    LinkType::AdapterToNode => asm.tun_ctl.set_carrier(false).unwrap(),
                    LinkType::NodeToAdapter => join_set = self.deregister_actor_addresses(asm),
                    _ => {}
                }

                let task_asm = asm.clone();
                join_set.spawn_local(async move {
                    // NOTE: Any mgmt messages MUST have been sent before this is called
                    km_multiplexor::drop_link(&task_asm, link_id).await;

                    if let Err(e) = task_asm.process_link_state_event(link_id, LinkEvent::CloseDone)
                    {
                        error!(target: LINK_STATE, "Error shutting down {}: {e:?}", task_asm.formatted_link_id(link_id));
                    }
                });
            }
            _ => {
                // Unexpcted call.
                warn!(target: LINK_STATE, "cannot clean_up_link_state in state {:?}", locked_fsm.state);
            }
        }
        join_set
    }

    /// Complete a link shutdown, upon receiving a terminate request or response
    /// Transitions from Closing to Inactive
    /// Generates no packets
    fn complete_close(&self, asm: &Arc<Assembly>) {
        let link_id = self.id;
        info!(target: LINK_STATE, "Shutting down {}", asm.formatted_link_id(link_id));
        let mut locked_fsm = self.locked_fsm.lock().unwrap();

        match (locked_fsm.state, self.link_type) {
            (LinkState::Closing, LinkType::NodeToAdapter) | (LinkState::Resetting, _) => {
                // Clear whole peer out
                drop(locked_fsm);
                asm.drop_peer(link_id);
                return;
            }
            (LinkState::Closing, _) => {
                locked_fsm.silent = false;
                locked_fsm.set_state(LinkState::Inactive);
                info!(target: LINK_STATE, "{} has fully shut down", asm.formatted_link_id(link_id));
                if !locked_fsm.shutting_down {
                    drop(locked_fsm);
                    // With auto-connect off (zipline#28) the AdapterToNode
                    // tether does not restart itself: it stays Inactive
                    // until the next startLink RPC (ph-cli connect / link
                    // start). Every connect is operator-initiated.
                    if self.link_type == LinkType::AdapterToNode && !asm.config.get().auto_connect {
                        info!(target: LINK_STATE, "{} idle (auto-connect off); waiting for startLink", asm.formatted_link_id(link_id));
                    } else {
                        self.setup_restart(asm);
                    }
                } else {
                    drop(locked_fsm);
                    asm.drop_peer(link_id); // buh bye!
                }
            }
            _ => {
                error!(
                    target: LINK_STATE,
                    "{} tried to close from state {:?}",
                    asm.formatted_link_id(link_id),
                    locked_fsm.state
                );
            }
        }
    }

    /// Set a timer to attempt a link restart after a holddown period
    fn setup_restart(&self, asm: &Arc<Assembly>) {
        // TODO: use timeout mechanism
        let link_id = self.id;
        let task_asm = asm.clone();
        tokio::task::spawn_local(async move {
            tokio::time::sleep(config::DEFAULT_LINK_RESTART_HOLDDOWN).await;
            info!(target: LINK_STATE, "Attempting to restart {}", task_asm.formatted_link_id(link_id));
            let _ = task_asm.process_link_state_event(link_id, LinkEvent::Start);
        });
    }

    /// Reset the link, shutting it down and wiping its configuration
    /// Instead of transitioning, the state machine will be destroyed
    /// Sends a Terminate Indication
    pub async fn reset(&self, asm: &Arc<Assembly>) {
        let link_id = self.id;
        info!(target: LINK_STATE,
            "Resetting {} from state {:?}",
            asm.formatted_link_id(link_id),
            self.locked_fsm.lock().unwrap().state
        );
        self.locked_fsm
            .lock()
            .unwrap()
            .set_state(LinkState::Resetting);
        mgmt::requests::send_terminate_link_or_docking_session(
            asm,
            link_id,
            TerminateReason::Reset,
        )
        .enqueue();
        let _ = self.clean_up_link_state(asm).join_all().await;
    }

    /// Handle a terminate link acknowledgement.
    /// This means we sent a terminate request and set a timeout. Timeout is cancelled here
    /// before we proceed with shutting down the link.
    fn process_terminate_ack(&self, asm: &Arc<Assembly>) -> Result<(), LinkStateError> {
        let link_id = self.id;
        info!(target: LINK_STATE,"Received terminate response for {}", asm.formatted_link_id(link_id));
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        match locked_fsm.state {
            LinkState::Closing => {
                locked_fsm.cancel_timeout();
                drop(locked_fsm);
                self.clean_up_link_state(asm).detach_all();
                Ok(())
            }
            _ => Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "ReceivedTerminateAck",
            )),
        }
    }

    /// Peer has sent a terminate-link message.
    /// May generate an RPC message (over TUN) to the visa service.
    /// Peer has shut down or shutting down so don't expect it to be there anymore.
    ///
    /// Returns Ok unless this is in a state that cannot handle this message.
    fn process_terminate_link(
        &self,
        asm: &Arc<Assembly>,
        reason: TerminateReason,
    ) -> Result<(), LinkStateError> {
        let link_id = self.id;
        info!(target: LINK_STATE,
            "Received terminate for {} with reason {:?}", asm.formatted_link_id(link_id), reason
        );
        self.locked_fsm
            .lock()
            .unwrap()
            .set_state(LinkState::Closing);
        self.clean_up_link_state(asm).detach_all();
        Ok(())
    }

    pub fn process_keep_alive_response(&self, asm: &Arc<Assembly>) -> Result<(), LinkStateError> {
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        if !matches!(locked_fsm.state, LinkState::Active) {
            // we only expect keep alives responses in Active
            return Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "ReceivedKeepAliveResponse",
            ));
        }

        let Some((start_time, _echo_handle)) = locked_fsm.echo_handle.take() else {
            // we do not have an outstanding echo request
            return Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "ReceivedKeepAliveResponse",
            ));
        };

        // we got a successful echo response, track it
        let mut link_data = self.locked_data.lock().unwrap();
        link_data.echo_success += 1;
        link_data
            .latency_data
            .add(Instant::now().duration_since(start_time));
        drop(link_data);

        // delay before kicking off next echo request
        self.set_timeout(asm, &mut locked_fsm, config::DEFAULT_KEEP_ALIVE_PERIOD);
        drop(locked_fsm);

        // Piggyback the auth-renewal check on the keep-alive heartbeat
        // (zipline#45): every successful echo response on an Active link is
        // a renewal tick.
        self.maybe_renew_auth(asm);

        Ok(())
    }

    /// One auth-renewal tick (zipline#45). No-op until the precomputed
    /// renewal deadline passes; then, per tick:
    /// - no AuthAgent registered (or no OIDC renewal identity): warn ONCE
    ///   per authentication window and record [AuthFailureReason::NoAgent];
    ///   no repeat warnings, no attempts.
    /// - agent registered: at most one in-flight attempt at a time — a
    ///   non-interactive getOidcCredential (never opens a browser) bound to
    ///   the ORIGINAL issuer and challenge-derived nonce the actor
    ///   authenticated with, then `vsconn.reauthorize`. Success refreshes
    ///   `auth_expires` (restarting the window); any failure warns, records
    ///   the reason, and clears the in-flight flag so the next due tick
    ///   retries.
    fn maybe_renew_auth(&self, asm: &Arc<Assembly>) {
        let link_id = self.id;

        // Snapshot under the data lock; bail on the cheap paths.
        let (identity, auth_expires) = {
            let mut data = self.locked_data.lock().unwrap();
            let Some(deadline) = data.auth_renewal_deadline else {
                return; // never authorized via the VS: nothing to renew
            };
            if SystemTime::now() < deadline || data.renewal_in_flight {
                return;
            }
            if data.renewal_identity.is_none() {
                // No OIDC identity stashed: there is nothing to renew with,
                // on either side of the hop.
                if !data.renewal_no_agent_warned {
                    data.renewal_no_agent_warned = true;
                    data.last_auth_failure = Some(AuthFailureReason::NoAgent);
                    warn!(target: LINK_STATE,
                        "{}: authentication expires soon but no AuthAgent is available to renew it;                          the actor must reconnect to re-authenticate",
                        asm.formatted_link_id(link_id));
                }
                return;
            }
            if data.auth_agent.is_none() {
                if matches!(self.link_type, LinkType::NodeToAdapter) {
                    // R8 (zipline#66): the AuthAgent registers on the
                    // ADAPTER's side of the hop, so this node asks the
                    // adapter for a renewed credential over ZDP instead of
                    // giving up.
                    data.renewal_in_flight = true;
                    let auth_expires = data.auth_expires.unwrap();
                    drop(data);
                    self.send_renewal_credential_request(asm, auth_expires);
                    return;
                }
                if !data.renewal_no_agent_warned {
                    data.renewal_no_agent_warned = true;
                    data.last_auth_failure = Some(AuthFailureReason::NoAgent);
                    warn!(target: LINK_STATE,
                        "{}: authentication expires soon but no AuthAgent is available to renew it;                          the actor must reconnect to re-authenticate",
                        asm.formatted_link_id(link_id));
                }
                return;
            }
            data.renewal_in_flight = true;
            (
                data.renewal_identity.clone().unwrap(),
                // A renewal deadline implies set_auth_expires ran: present.
                data.auth_expires.unwrap(),
            )
        };

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let request = OidcCredentialRequest {
            idp: identity.idp.clone(),
            nonce: identity.nonce.clone(),
            interactive: false, // renewal must never open a browser
            reply: reply_tx,
        };

        // Send to the agent bridge; a closed channel means the bridge task
        // is gone (its admin connection died), so clear the stale slot (C2).
        {
            let mut data = self.locked_data.lock().unwrap();
            let Some(agent) = data.auth_agent.clone() else {
                data.renewal_in_flight = false;
                return;
            };
            if agent.send(request).is_err() {
                data.auth_agent = None;
                data.renewal_in_flight = false;
                data.last_auth_failure = Some(AuthFailureReason::AgentError(
                    "AuthAgent bridge is gone".to_string(),
                ));
                warn!(target: LINK_STATE,
                    "{}: AuthAgent bridge is gone; cleared the stale agent registration",
                    asm.formatted_link_id(link_id));
                return;
            }
        }

        let task_asm = asm.clone();
        let issuer = identity.idp.issuer.clone();
        let nonce = identity.nonce;
        // Bind the completion to THIS link instance: after teardown the slab
        // id can be reused by a new peer, and the stale task must not act on
        // it (PR #14 review).
        let link_uid = self.uid;
        // Bound the wait by the remaining authentication window so a hung
        // agent cannot pin renewal_in_flight past expiry (PR #14 review).
        let attempt_timeout = renewal_attempt_timeout(SystemTime::now(), auth_expires);
        tokio::task::spawn_local(async move {
            let outcome = match tokio::time::timeout(attempt_timeout, reply_rx).await {
                Ok(outcome) => outcome.map_err(|_| {
                    AuthFailureReason::AgentError(
                        "AuthAgent dropped the renewal request".to_string(),
                    )
                }),
                // Dropping reply_rx tells the bridge (via reply.closed()) to
                // cancel the abandoned RPC.
                Err(_elapsed) => Err(AuthFailureReason::AgentError(format!(
                    "renewal attempt timed out after {attempt_timeout:?}"
                ))),
            };
            Self::handle_renewal_reply(&task_asm, link_id, link_uid, issuer, nonce, outcome).await;
        });
    }

    /// Completion of one silent-renewal attempt (zipline#45): submit the
    /// obtained id token to the VS (or record the failure). `link_uid` is the
    /// [LinkStateWrapper::uid] of the link instance the attempt was spawned
    /// for; a reply whose looked-up peer carries a DIFFERENT uid belongs to a
    /// closed link whose slab id was reused, and is discarded without
    /// touching the new link's state (PR #14 review).
    async fn handle_renewal_reply(
        asm: &Arc<Assembly>,
        link_id: LinkId,
        link_uid: u64,
        issuer: String,
        nonce: String,
        outcome: Result<Result<String, AuthFailureReason>, AuthFailureReason>,
    ) {
        let Some(peer) = asm.peer_table.get(link_id) else {
            return; // link torn down while we waited
        };
        let lsm = &peer.link_state_machine;
        if lsm.uid != link_uid {
            // The slab id was reused by a NEW link while this request was
            // pending: the reply belongs to the closed link's actor and
            // must not touch the new link's state (PR #14 review).
            debug!(target: LINK_STATE,
                "{}: discarding renewal reply for a closed link instance (id reused)",
                asm.formatted_link_id(link_id));
            return;
        }

        let id_token = match outcome {
            Ok(Ok(id_token)) => id_token,
            Ok(Err(reason)) | Err(reason) => {
                lsm.finish_renewal_failure(asm, reason);
                return;
            }
        };

        let Some(vsconn) = asm.vsconn.as_ref() else {
            lsm.finish_renewal_failure(
                asm,
                AuthFailureReason::AgentError("no visa service connection for renewal".to_string()),
            );
            return;
        };
        let Some(actor_addr) = lsm.get_actor_addresses().first().cloned() else {
            lsm.finish_renewal_failure(
                asm,
                AuthFailureReason::AgentError("no actor address to renew".to_string()),
            );
            return;
        };

        use zpr::vsapi_types as vst;
        let req = vst::ReauthRequest {
            zpr_addr: std::net::IpAddr::from(actor_addr),
            blobs: vec![vst::AuthBlob::Oidc(vst::OidcBlob {
                issuer,
                id_token,
                nonce,
            })],
        };
        match vsconn.reauthorize(req).await {
            Ok(conn) => {
                let expires = std::time::UNIX_EPOCH + Duration::from_secs(conn.auth_expires);
                info!(target: LINK_STATE,
                    "{}: silently re-authenticated; new expiry {expires:?}",
                    asm.formatted_link_id(link_id));
                // Restarts the renewal window and clears the
                // in-flight/warned bookkeeping.
                lsm.set_auth_expires(
                    SystemTime::now(),
                    expires,
                    asm.config.get().auth_renewal_lead,
                );
            }
            Err(e) => {
                lsm.finish_renewal_failure(
                    asm,
                    AuthFailureReason::VisaServiceRejected(e.to_string()),
                );
            }
        }
    }

    /// A renewal attempt ended in failure: warn, record the reason for
    /// showLink, and clear the in-flight flag so the next due keep-alive
    /// tick may retry (zipline#45).
    fn finish_renewal_failure(&self, asm: &Arc<Assembly>, reason: AuthFailureReason) {
        warn!(target: LINK_STATE,
            "{}: silent re-authentication failed: {reason:?}",
            asm.formatted_link_id(self.id));
        let mut data = self.locked_data.lock().unwrap();
        data.renewal_in_flight = false;
        data.last_auth_failure = Some(reason);
    }

    /// R8 (zipline#66), node side: ask the adapter for a renewed credential
    /// over ZDP. Mints a fresh challenge exactly as
    /// [Self::send_init_authentication_request] does (so
    /// [auth::oidc_nonce_for_challenge] applies unchanged), stashes it for
    /// the response to be verified against, sends a
    /// RenewAuthenticationRequest, and bounds the wait by
    /// [renewal_attempt_timeout] so a lost response cannot pin
    /// `renewal_in_flight` past the point a retry could still succeed.
    ///
    /// The caller has already set `renewal_in_flight`.
    fn send_renewal_credential_request(&self, asm: &Arc<Assembly>, auth_expires: SystemTime) {
        let link_id = self.id;

        let key = asm.peer_table.inspect(link_id, {
            |peer| {
                let mut key = [0u8; AUTH_KEY_SIZE_BYTES];
                key[0..AUTH_KEY_SIZE_BYTES].copy_from_slice(&peer.auth_key[0..AUTH_KEY_SIZE_BYTES]);
                key
            }
        });
        let Some(key) = key else {
            self.finish_renewal_failure(
                asm,
                AuthFailureReason::AgentError(
                    "no auth key to mint a renewal challenge".to_string(),
                ),
            );
            return;
        };

        let payload = auth::ZdpInitAuthenticationPayload::new(&key);
        let mut challenge = [0u8; 48];
        challenge[0..8].copy_from_slice(&payload.nonce);
        challenge[8..16].copy_from_slice(&payload.ctime.to_bytes());
        challenge[16..48].copy_from_slice(&payload.hmac);
        self.stash_renewal_challenge(challenge);

        mgmt::requests::send_renew_authentication_request(asm, link_id, payload).enqueue();

        // Bound the wait: if the response never arrives, fail this attempt so
        // the next due keep-alive tick can retry while auth is still valid.
        // Guarded by the challenge bytes (a completed or newer attempt has
        // taken or replaced them) and the link uid (the slab id may be
        // reused by a new link after teardown).
        let task_asm = asm.clone();
        let link_uid = self.uid;
        let attempt_timeout = renewal_attempt_timeout(SystemTime::now(), auth_expires);
        tokio::task::spawn_local(async move {
            tokio::time::sleep(attempt_timeout).await;
            let Some(peer) = task_asm.peer_table.get(link_id) else {
                return; // link torn down while we waited
            };
            let lsm = &peer.link_state_machine;
            if lsm.uid != link_uid {
                return; // slab id reused by a new link
            }
            if lsm.take_renewal_challenge_if(&challenge) {
                lsm.finish_renewal_failure(
                    &task_asm,
                    AuthFailureReason::AgentError(format!(
                        "renewal credential request timed out after {attempt_timeout:?}"
                    )),
                );
            }
        });
    }

    /// R8 (zipline#66), adapter side: the node asked for a renewed
    /// credential. Satisfy it from the registered AuthAgent with
    /// `interactive: false` (the R6 bridge, unchanged) and return the blob
    /// in a RenewAuthenticationResponse; with no agent (or no advertised
    /// IdP) answer [ResponseCode::AuthUnavailable] instead of dropping the
    /// packet, so the node records why renewal is impossible.
    fn process_renew_auth_request(
        &self,
        asm: &Arc<Assembly>,
        challenge_payload: auth::ZdpInitAuthenticationPayload,
    ) -> Result<(), LinkStateError> {
        let link_id = self.id;
        {
            let locked_fsm = self.locked_fsm.lock().unwrap();
            match (self.link_type, locked_fsm.state) {
                // Renewal runs on an Active link, unlike InitAuthentication.
                (LinkType::AdapterToNode, LinkState::Active) => {}
                (_, _) => {
                    return Err(LinkStateError::UnexpectedTransition(
                        locked_fsm.state,
                        "ReceivedRenewAuthRequest",
                    ));
                }
            }
        }

        // The raw 48-byte challenge: nonce || ctime || hmac. Assembled
        // before any answer so every response — success or failure — can
        // echo it for correlation on the node side (PR #17 review).
        let mut challenge = [0u8; 48];
        challenge[0..8].copy_from_slice(&challenge_payload.nonce);
        challenge[8..16].copy_from_slice(&challenge_payload.ctime.to_bytes());
        challenge[16..48].copy_from_slice(&challenge_payload.hmac);

        // A new request supersedes any still-outstanding agent call: the
        // node only retries after abandoning its previous attempt, so
        // cancel the abandoned call instead of letting this retry queue
        // behind it on the serial bridge for up to
        // OIDC_USER_INTERACTION_TIMEOUT (PR #17 review). Aborting the wait
        // task drops its reply receiver, which the bridge observes
        // (`reply.closed()`) and drops the in-flight RPC.
        if let Some(task) = self.locked_data.lock().unwrap().adapter_renewal_task.take() {
            debug!(target: LINK_STATE,
                "{}: a new renewal credential request supersedes the outstanding one; cancelling it",
                asm.formatted_link_id(link_id));
            task.abort();
        }

        let (agent, idp) = {
            let data = self.locked_data.lock().unwrap();
            (
                data.auth_agent.clone(),
                data.oidc_idps.as_ref().and_then(|v| v.first().cloned()),
            )
        };
        let (Some(agent), Some(idp)) = (agent, idp) else {
            info!(target: LINK_STATE,
                "{}: node asked for credential renewal but no AuthAgent/IdP is available; answering AuthUnavailable",
                asm.formatted_link_id(link_id));
            mgmt::requests::send_renew_authentication_response(
                asm,
                link_id,
                ResponseCode::AuthUnavailable,
                &challenge,
                &[],
            )
            .enqueue();
            return Ok(());
        };

        let nonce = auth::oidc_nonce_for_challenge(&challenge);
        let issuer = idp.issuer.clone();
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let request = OidcCredentialRequest {
            idp,
            nonce,
            interactive: false, // renewal must never open a browser
            reply: reply_tx,
        };

        if agent.send(request).is_err() {
            // The bridge task is gone (its admin connection died): clear the
            // stale slot, same as the agent-direct renewal path (C2).
            self.clear_auth_agent_if(&agent);
            warn!(target: LINK_STATE,
                "{}: AuthAgent bridge is gone; answering renewal with AuthUnavailable",
                asm.formatted_link_id(link_id));
            mgmt::requests::send_renew_authentication_response(
                asm,
                link_id,
                ResponseCode::AuthUnavailable,
                &challenge,
                &[],
            )
            .enqueue();
            return Ok(());
        }

        let task_asm = asm.clone();
        let link_uid = self.uid;
        let task = tokio::task::spawn_local(async move {
            // The bridge bounds each call by OIDC_USER_INTERACTION_TIMEOUT
            // and answers or drops the reply either way, so awaiting the
            // reply is itself bounded.
            let outcome = reply_rx.await;

            let Some(peer) = task_asm.peer_table.get(link_id) else {
                return; // link torn down while we waited
            };
            if peer.link_state_machine.uid != link_uid {
                return; // slab id reused by a new link
            }

            let (status, blob) = match outcome {
                Ok(Ok(id_token)) => {
                    let oidc_blob = auth::ZdpOidcBlob {
                        blob_type: auth::BLOB_TYPE_OIDC.to_string(),
                        issuer,
                        id_token,
                        challenge: BASE64_STANDARD.encode(challenge),
                    };
                    (ResponseCode::Success, oidc_blob.encode())
                }
                Ok(Err(reason)) => {
                    warn!(target: LINK_STATE,
                        "{}: AuthAgent could not renew the credential: {reason:?}",
                        task_asm.formatted_link_id(link_id));
                    (ResponseCode::AuthUnavailable, String::new())
                }
                Err(_) => {
                    warn!(target: LINK_STATE,
                        "{}: AuthAgent dropped the renewal request",
                        task_asm.formatted_link_id(link_id));
                    (ResponseCode::AuthUnavailable, String::new())
                }
            };
            mgmt::requests::send_renew_authentication_response(
                &task_asm,
                link_id,
                status,
                &challenge,
                blob.as_bytes(),
            )
            .enqueue();
        });
        // Remember the wait task so the NEXT request can cancel it if the
        // node abandons this attempt. Aborting an already-finished task is
        // a no-op, so a stale handle here is harmless.
        self.locked_data.lock().unwrap().adapter_renewal_task = Some(task.abort_handle());

        Ok(())
    }

    /// R8 (zipline#66), node side: the adapter answered the renewal
    /// credential request. Verify the returned blob against the stashed
    /// challenge (HMAC with this link's auth key plus byte-for-byte
    /// equality), then complete exactly as the agent-direct path does —
    /// `reauthorize` (never `authorizeConnect`), refreshed expiry on
    /// success, recorded failure otherwise. The link stays Active
    /// throughout; a failed renewal leaves the existing expiry to the sweep.
    fn process_renew_auth_response(
        &self,
        asm: &Arc<Assembly>,
        echoed_challenge: [u8; 48],
        result: Result<String, ResponseCode>,
    ) -> Result<(), LinkStateError> {
        let link_id = self.id;
        {
            let locked_fsm = self.locked_fsm.lock().unwrap();
            match (self.link_type, locked_fsm.state) {
                (LinkType::NodeToAdapter, LinkState::Active) => {}
                (_, _) => {
                    return Err(LinkStateError::UnexpectedTransition(
                        locked_fsm.state,
                        "ReceivedRenewAuthResponse",
                    ));
                }
            }
        }

        // Correlate before consuming: the response echoes the challenge of
        // the request it answers, and only a response to the CURRENT
        // attempt may take the stash. A delayed answer to an abandoned
        // attempt (it timed out; a newer attempt is in flight) must not
        // consume the newer attempt's challenge and be recorded as its
        // failure (PR #17 review). No match — stale or unsolicited — is
        // discarded without touching the renewal state; if a newer attempt
        // is outstanding, its own response or timeout settles it.
        if !self.take_renewal_challenge_if(&echoed_challenge) {
            debug!(target: LINK_STATE,
                "{}: discarding renewal response that answers no outstanding request",
                asm.formatted_link_id(link_id));
            return Ok(());
        }
        let challenge = echoed_challenge;

        let blob_str = match result {
            Ok(blob_str) => blob_str,
            Err(code) => {
                let reason = match code {
                    ResponseCode::AuthUnavailable => AuthFailureReason::AuthUnavailable,
                    other => AuthFailureReason::AgentError(format!(
                        "adapter answered renewal with code {other:?}"
                    )),
                };
                self.finish_renewal_failure(asm, reason);
                return Ok(());
            }
        };

        // Decode and verify: the blob's challenge must HMAC-verify with this
        // link's auth key AND be byte-for-byte the one we minted for this
        // attempt, so a response cannot smuggle a credential bound elsewhere.
        let oidc_blob = match auth::decode_blobs(&blob_str) {
            Ok(blobs) => blobs.into_iter().find_map(|b| match b {
                AuthBlob::Oidc(oidc) => Some(oidc),
                _ => None,
            }),
            Err(e) => {
                self.finish_renewal_failure(
                    asm,
                    AuthFailureReason::AgentError(format!("invalid renewal blob: {e}")),
                );
                return Ok(());
            }
        };
        let Some(oidc_blob) = oidc_blob else {
            self.finish_renewal_failure(
                asm,
                AuthFailureReason::AgentError("renewal response carried no OIDC blob".to_string()),
            );
            return Ok(());
        };
        if !self.check_oidc_blob(asm, link_id, &oidc_blob) {
            self.finish_renewal_failure(
                asm,
                AuthFailureReason::AgentError(
                    "renewal blob challenge failed verification".to_string(),
                ),
            );
            return Ok(());
        }
        let returned_challenge = BASE64_STANDARD
            .decode(&oidc_blob.challenge)
            .unwrap_or_default();
        if returned_challenge != challenge {
            self.finish_renewal_failure(
                asm,
                AuthFailureReason::AgentError(
                    "renewal blob is bound to a different challenge".to_string(),
                ),
            );
            return Ok(());
        }

        // Same guard as the original credential (stash_renewal_identity):
        // the renewed one must come from the issuer the actor originally
        // authenticated with.
        let expected_issuer = self
            .locked_data
            .lock()
            .unwrap()
            .renewal_identity
            .as_ref()
            .map(|identity| identity.idp.issuer.clone());
        if expected_issuer.as_deref() != Some(oidc_blob.issuer.as_str()) {
            self.finish_renewal_failure(
                asm,
                AuthFailureReason::AgentError(format!(
                    "renewed credential from unexpected issuer {}",
                    oidc_blob.issuer
                )),
            );
            return Ok(());
        }

        // Complete exactly as the agent-direct path: reauthorize with the
        // fresh challenge-derived nonce. handle_renewal_reply refreshes
        // auth_expires (clearing in-flight) on success and records the
        // failure (clearing in-flight) otherwise.
        let task_asm = asm.clone();
        let link_uid = self.uid;
        let issuer = oidc_blob.issuer.clone();
        let nonce = auth::oidc_nonce_for_challenge(&challenge);
        let id_token = oidc_blob.id_token;
        tokio::task::spawn_local(async move {
            Self::handle_renewal_reply(
                &task_asm,
                link_id,
                link_uid,
                issuer,
                nonce,
                Ok(Ok(id_token)),
            )
            .await;
        });
        Ok(())
    }

    /// Common code to enter the `Active` state and kick off our keepalive mechanism
    fn run_active(
        &self,
        asm: &Arc<Assembly>,
        mut locked_fsm: MutexGuard<'_, LinkStateMachine>,
    ) -> Result<(), LinkStateError> {
        locked_fsm.set_state(LinkState::Active);
        asm.counters.management[ManagementCounterType::PeerHandshakeSuccess].increment();
        debug!(target: LINK_STATE, "{} entering active state", asm.formatted_link_id(self.id));

        // kick off our keepalive mechanism
        locked_fsm.echo_handle.take().inspect(|(_, h)| h.abort()); // should already be None (indicating no echo outstanding) but let's be sure
        self.set_timeout(asm, &mut locked_fsm, config::DEFAULT_KEEP_ALIVE_TIMEOUT);

        Ok(())
    }
}

/// Collect OIDC identity-provider advertisements from the auth-services list:
/// one [auth::OidcIdpInfo] per descriptor with `stype == OidcAuthentication`
/// that carries an `OidcClientConfig`.
fn get_available_oidc_idps(asm: &Assembly, link_id: LinkId) -> Vec<auth::OidcIdpInfo> {
    use zpr::vsapi_types::ServiceT;

    let mut idps = Vec::new();

    let svclist = asm.vs_auth_services.read().unwrap();
    if svclist.is_valid() {
        for authservice in &svclist.services {
            if authservice.stype != ServiceT::OidcAuthentication {
                continue;
            }
            let Some(cfg) = &authservice.oidc else {
                warn!(target: LINK_STATE, "{}: HelloResponse - OIDC service {} has no client config",
                    asm.formatted_link_id(link_id), authservice.service_id);
                continue;
            };
            debug!(target: LINK_STATE, "{}: HelloResponse - adding OIDC IdP: {}",
                asm.formatted_link_id(link_id), cfg.issuer);
            idps.push(auth::OidcIdpInfo {
                issuer: cfg.issuer.clone(),
                client_id: cfg.client_id.clone(),
                client_secret: cfg.client_secret.clone(),
                scopes: cfg.scopes.clone(),
                allow_offline_access: cfg.allow_offline_access,
            });
        }
    }

    idps
}

impl Display for LinkStateWrapper {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // FIXME: This doesn't print link ID because the caller is printing link ID
        // followed by substrate addr, which is out of scope for this display function
        write!(f, "  Type: {:?}\n", self.link_type)?;

        write!(f, "{}", self.locked_fsm.lock().unwrap())?;
        if let Some(reason) = self.get_last_auth_failure() {
            write!(f, "  Last auth failure: {:?}\n", reason)?;
        }
        if self.get_state() == LinkState::Active {
            write!(f, "{}", self.locked_data.lock().unwrap())?;
        }
        Ok(())
    }
}

impl Display for LinkStateMachine {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.actor_addresses.is_empty() {
            write!(f, "  Actor Addresses: None\n")?;
        } else {
            write!(f, "  Actor Addresses: [ {}", self.actor_addresses[0])?;
            for addr in &self.actor_addresses[1..self.actor_addresses.len()] {
                write!(f, ", {}", addr)?;
            }
            write!(f, " ]\n")?;
        }

        // TODO: Format time since last state change better
        write!(
            f,
            "  State: {:?} (for {:?})\n",
            self.state,
            Instant::now().duration_since(self.last_state_change)
        )?;
        write!(f, "  Status: {:?}\n", self.status)
    }
}

impl Display for LinkData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let (total, count) = self.latency_data.get_total_and_count();
        let average = if count > 0 {
            total.div_f64(count as f64)
        } else {
            Duration::ZERO
        };

        write!(f, "  Echo stats:\n")?;
        write!(f, "    Successes: {}\n", self.echo_success)?;
        write!(f, "    Timeouts: {}\n", self.echo_timeout)?;
        write!(
            f,
            "    Latency: Min {:?}, Max {:?}, Avg {average:?}\n",
            self.latency_data.get_min(),
            self.latency_data.get_max(),
        )?;
        // Surface the renewal picture in showLink (zipline#45).
        if let Some(expires) = self.auth_expires {
            match expires.duration_since(SystemTime::now()) {
                Ok(remaining) => {
                    write!(f, "  Auth expires: in {remaining:?}")?;
                }
                Err(_) => {
                    write!(f, "  Auth expires: EXPIRED")?;
                }
            }
            if self.renewal_in_flight {
                write!(f, " (renewal in progress)")?;
            }
            write!(f, "\n")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthFailureReason, LinkEvent, LinkState, LinkStateMachine, LinkType};
    use crate::assembly::test::{TestAssemblyBuilder, create_assembly};
    use crate::auth;
    use crate::peer_table;
    use crate::prelude::*;
    use crate::zdp::ResponseCode;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use std::time::SystemTime;
    use tokio::sync::oneshot;
    use tokio::task::LocalSet;
    use zpr::addrs::{ZPR_INTERNAL_NETWORK, ZPRNET_PREFIX_LEN};
    use zpr_utils::net_defs;

    /// Insert an adapter-side (AdapterToNode) peer into the table and return
    /// its link id. Each call gets a distinct substrate port: the peer table
    /// rejects duplicate substrate addresses.
    fn add_adapter_peer(asm: &Arc<Assembly>) -> LinkId {
        let entry = asm.peer_table.vacant_entry().unwrap();
        let link_id = entry.key();
        let ps = peer_table::test::create_dummy_peer_state(
            link_id,
            LinkType::AdapterToNode,
            SubstrateAddr::from(([127, 0, 0, 1], 9000 + link_id.get() as u16)),
            net_defs::ScopedIpAddr::V4(Ipv4Addr::new(127, 0, 0, 2).into()),
        );
        entry.insert(ps).get()
    }

    /// A fixed InitAuth challenge payload. The adapter side does not verify
    /// the HMAC (the node minted it), so arbitrary bytes are fine.
    fn test_challenge_payload() -> auth::ZdpInitAuthenticationPayload {
        auth::ZdpInitAuthenticationPayload {
            nonce: [7u8; 8],
            ctime: 424242u64.into(),
            hmac: [9u8; 32],
        }
    }

    /// A minimal advertised OIDC identity provider.
    fn test_idp() -> auth::OidcIdpInfo {
        auth::OidcIdpInfo {
            issuer: "https://idp.test".to_string(),
            client_id: "test-client".to_string(),
            client_secret: None,
            scopes: vec!["openid".to_string()],
            allow_offline_access: false,
        }
    }

    /// `renewal_lead` clamps the configured lead to half the granted
    /// lifetime, so short `expiration_seconds` values still renew ahead of
    /// expiry by a workable margin (zipline#45).
    #[test]
    fn test_renewal_lead_clamps_to_half_lifetime() {
        let configured = Duration::from_secs(300);
        // Long lifetime: the configured lead stands.
        assert_eq!(
            super::renewal_lead(configured, Duration::from_secs(3600)),
            Duration::from_secs(300)
        );
        // Lifetime of exactly 2x the lead: still the configured lead.
        assert_eq!(
            super::renewal_lead(configured, Duration::from_secs(600)),
            Duration::from_secs(300)
        );
        // Short lifetime: clamped to half.
        assert_eq!(
            super::renewal_lead(configured, Duration::from_secs(120)),
            Duration::from_secs(60)
        );
        // Zero lifetime: zero lead (due at expiry, i.e. immediately).
        assert_eq!(
            super::renewal_lead(configured, Duration::ZERO),
            Duration::ZERO
        );
    }

    /// `renewal_deadline` is `auth_expires - effective lead`; an
    /// already-past expiry is due immediately (deadline not in the future).
    #[test]
    fn test_renewal_deadline_including_past_expiry() {
        use std::time::SystemTime;
        let configured = Duration::from_secs(300);
        let now = SystemTime::now();

        // 1h lifetime: deadline is expiry minus the full 300s lead.
        let expires = now + Duration::from_secs(3600);
        assert_eq!(
            super::renewal_deadline(now, expires, configured),
            expires - Duration::from_secs(300)
        );

        // 120s lifetime: lead clamps to 60s.
        let expires = now + Duration::from_secs(120);
        assert_eq!(
            super::renewal_deadline(now, expires, configured),
            expires - Duration::from_secs(60)
        );

        // Expiry already in the past: lifetime saturates to zero, so the
        // deadline equals the (past) expiry — renewal is due immediately.
        let expires = now - Duration::from_secs(10);
        let deadline = super::renewal_deadline(now, expires, configured);
        assert_eq!(deadline, expires);
        assert!(deadline <= now, "past expiry must be due immediately");
    }

    /// `auth_expires` round-trips through the LinkStateWrapper setter/getter
    /// (zipline#45): unset until authorized, then reads back what was set.
    #[tokio::test]
    async fn test_link_data_auth_expires_round_trip() {
        use std::time::SystemTime;
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let link_id = add_adapter_peer(&asm);
                let peer = asm.peer_table.get(link_id).unwrap();
                assert_eq!(peer.link_state_machine.get_auth_expires(), None);

                let now = SystemTime::now();
                let expires = now + Duration::from_secs(3600);
                peer.link_state_machine
                    .set_auth_expires(now, expires, Duration::from_secs(300));
                assert_eq!(peer.link_state_machine.get_auth_expires(), Some(expires));
            })
            .await
    }

    /// The renewal identity (original issuer + challenge-derived nonce)
    /// round-trips through the LinkStateWrapper setter/getter.
    #[tokio::test]
    async fn test_link_data_renewal_identity_round_trip() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let link_id = add_adapter_peer(&asm);
                let peer = asm.peer_table.get(link_id).unwrap();
                assert!(peer.link_state_machine.get_renewal_identity().is_none());

                let challenge = [3u8; 48];
                peer.link_state_machine
                    .set_renewal_identity(super::RenewalIdentity {
                        idp: test_idp(),
                        nonce: auth::oidc_nonce_for_challenge(&challenge),
                    });
                let stored = peer
                    .link_state_machine
                    .get_renewal_identity()
                    .expect("identity must be stored");
                assert_eq!(stored.idp.issuer, "https://idp.test");
                assert_eq!(stored.nonce, auth::oidc_nonce_for_challenge(&challenge));
            })
            .await
    }

    /// Insert a node-side (NodeToAdapter) peer into the table and return its
    /// link id. Distinct substrate port per call, same as [add_adapter_peer].
    fn add_node_peer(asm: &Arc<Assembly>) -> LinkId {
        let entry = asm.peer_table.vacant_entry().unwrap();
        let link_id = entry.key();
        let ps = peer_table::test::create_dummy_peer_state(
            link_id,
            LinkType::NodeToAdapter,
            SubstrateAddr::from(([127, 0, 0, 1], 9500 + link_id.get() as u16)),
            net_defs::ScopedIpAddr::V4(Ipv4Addr::new(127, 0, 0, 3).into()),
        );
        entry.insert(ps).get()
    }

    /// A test assembly whose management substrate egress is observable: the
    /// returned receiver sees every packet the code under test sends.
    fn assembly_with_observable_egress() -> (
        Arc<Assembly>,
        crate::packet_queue::Receiver<{ config::PACKET_BUFFER_SIZE }>,
    ) {
        let (egress_tx, egress_rx) = crate::packet_queue::packet_queue(8);
        let mut builder = TestAssemblyBuilder::new();
        builder.mgmt_substrate_egress = Some(crate::queues::MgmtSubstrateEgress::new(egress_tx));
        (Arc::new(create_assembly(builder)), egress_rx)
    }

    /// Pop one packet off the observable egress queue, or None if empty.
    fn try_recv_egress(
        rx: &mut crate::packet_queue::Receiver<{ config::PACKET_BUFFER_SIZE }>,
    ) -> Option<Packet> {
        rx.try_recv(vec![0u8; config::PACKET_BUFFER_SIZE].into_boxed_slice())
            .ok()
    }

    /// R8 (zipline#66): on a node link whose renewal is due, with the
    /// renewal identity stashed but NO local AuthAgent — the combination the
    /// production paths actually produce, since the agent registers on the
    /// ADAPTER's link — the tick must send a RenewAuthenticationRequest
    /// (ZDP type 142) toward the adapter instead of taking the one-shot
    /// NoAgent warning path.
    #[tokio::test]
    async fn test_due_renewal_on_node_link_without_agent_sends_zdp_request() {
        LocalSet::new()
            .run_until(async {
                let (asm, mut egress_rx) = assembly_with_observable_egress();
                let link_id = add_node_peer(&asm);
                let peer = asm.peer_table.get(link_id).unwrap();
                let lsm = &peer.link_state_machine;
                lsm.test_set_state(LinkState::Active);
                lsm.set_renewal_identity(super::RenewalIdentity {
                    idp: test_idp(),
                    nonce: auth::oidc_nonce_for_challenge(&[7u8; 48]),
                });
                // Renewal due (deadline in the past) but the authentication
                // itself still valid for another minute.
                let now = SystemTime::now();
                lsm.set_auth_expires(
                    now - Duration::from_secs(600),
                    now + Duration::from_secs(60),
                    Duration::from_secs(300),
                );

                lsm.maybe_renew_auth(&asm);

                // Must NOT give up with the NoAgent warning: the adapter may
                // well have an agent, and asking it is this issue's point.
                assert!(
                    !lsm.test_renewal_no_agent_warned(),
                    "node tick took the NoAgent warning path instead of asking the adapter"
                );
                assert!(
                    lsm.get_last_auth_failure().is_none(),
                    "node tick recorded a failure instead of asking the adapter"
                );
                assert!(
                    lsm.test_renewal_in_flight(),
                    "the ZDP credential request must mark the renewal in flight"
                );

                // ...and must emit a RenewAuthenticationRequest on the link.
                let pkt = try_recv_egress(&mut egress_rx)
                    .expect("a renewal credential request must be sent toward the adapter");
                assert_eq!(pkt.metadata().egress_link_id, link_id);
                // body[0] is ZdpBaseHeader.packet_type;
                // RenewAuthenticationRequest = 142 per the approved plan.
                assert_eq!(
                    pkt.body()[0],
                    142,
                    "expected a RenewAuthenticationRequest (142), got type {}",
                    pkt.body()[0]
                );
            })
            .await
    }

    /// R8 (zipline#66) step 3: an adapter link in Active with a registered
    /// AuthAgent that receives a RenewAuthenticationRequest forwards exactly
    /// one `OidcCredentialRequest { interactive: false }` to the agent and
    /// returns the resulting blob in a Success RenewAuthenticationResponse.
    #[tokio::test]
    async fn test_adapter_renew_request_asks_agent_and_answers_with_blob() {
        LocalSet::new()
            .run_until(async {
                let (asm, mut egress_rx) = assembly_with_observable_egress();
                let link_id = add_adapter_peer(&asm);
                let peer = asm.peer_table.get(link_id).unwrap();
                let lsm = &peer.link_state_machine;
                lsm.test_set_state(LinkState::Active);
                lsm.test_set_oidc_idps(vec![test_idp()]);
                let (agent_tx, mut agent_rx) = tokio::sync::mpsc::unbounded_channel();
                lsm.set_auth_agent(agent_tx);
                drop(peer);

                let challenge_payload = test_challenge_payload();
                asm.process_link_state_event(
                    link_id,
                    LinkEvent::ReceivedRenewAuthRequest(challenge_payload.clone()),
                )
                .unwrap();

                // Exactly one non-interactive request, bound to the
                // advertised IdP and the challenge-derived nonce.
                let req = agent_rx.try_recv().expect("agent must be called once");
                assert!(
                    !req.interactive,
                    "renewal must never open a browser (interactive must be false)"
                );
                assert_eq!(req.idp.issuer, "https://idp.test");
                let mut challenge = [0u8; 48];
                challenge[0..8].copy_from_slice(&challenge_payload.nonce);
                challenge[8..16].copy_from_slice(&challenge_payload.ctime.to_bytes());
                challenge[16..48].copy_from_slice(&challenge_payload.hmac);
                assert_eq!(req.nonce, auth::oidc_nonce_for_challenge(&challenge));
                assert!(agent_rx.try_recv().is_err(), "a second agent call was made");

                // The agent answers; the response goes out with the blob.
                req.reply.send(Ok("renewed-id-token".to_string())).unwrap();
                let mut pkt = None;
                for _ in 0..50 {
                    tokio::task::yield_now().await;
                    pkt = try_recv_egress(&mut egress_rx);
                    if pkt.is_some() {
                        break;
                    }
                }
                let pkt = pkt.expect("a RenewAuthenticationResponse must be sent");
                assert_eq!(pkt.metadata().egress_link_id, link_id);
                // body: [0]=type, [1]=excess, [2..10]=seq, [10]=status,
                // [11..13]=blob_len, [13..61]=echoed challenge, [61..]=blob.
                assert_eq!(pkt.body()[0], 143, "expected RenewAuthenticationResponse");
                assert_eq!(
                    pkt.body()[10],
                    0, // ResponseCode::Success
                    "expected a Success response"
                );
                let blob_len = u16::from_be_bytes([pkt.body()[11], pkt.body()[12]]) as usize;
                assert!(blob_len > 0, "success response must carry the blob");
                assert_eq!(
                    &pkt.body()[13..61],
                    &challenge[..],
                    "the response must echo the request's challenge"
                );
                let blob_str =
                    std::str::from_utf8(&pkt.body()[61..61 + blob_len]).expect("utf8 blob");
                let blobs = auth::decode_blobs(blob_str).expect("valid blob encoding");
                match &blobs[0] {
                    crate::auth::AuthBlob::Oidc(oidc) => {
                        assert_eq!(oidc.id_token, "renewed-id-token");
                        assert_eq!(oidc.issuer, "https://idp.test");
                        assert_eq!(
                            oidc.challenge,
                            base64::Engine::encode(
                                &base64::engine::general_purpose::STANDARD,
                                challenge
                            ),
                            "the blob must be bound to the node's challenge"
                        );
                    }
                    other => panic!("expected an OIDC blob, got {other:?}"),
                }
                // The link never left Active.
                assert_eq!(
                    asm.peer_table
                        .get(link_id)
                        .unwrap()
                        .link_state_machine
                        .get_state(),
                    LinkState::Active
                );
            })
            .await
    }

    /// R8 (zipline#66) step 3: an adapter link WITHOUT a registered agent
    /// answers a RenewAuthenticationRequest with
    /// [ResponseCode::AuthUnavailable] instead of dropping the packet.
    #[tokio::test]
    async fn test_adapter_renew_request_without_agent_answers_auth_unavailable() {
        LocalSet::new()
            .run_until(async {
                let (asm, mut egress_rx) = assembly_with_observable_egress();
                let link_id = add_adapter_peer(&asm);
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.link_state_machine.test_set_state(LinkState::Active);
                    // no agent, no IdP registered
                }

                asm.process_link_state_event(
                    link_id,
                    LinkEvent::ReceivedRenewAuthRequest(test_challenge_payload()),
                )
                .unwrap();

                let pkt = try_recv_egress(&mut egress_rx)
                    .expect("an agentless adapter must still answer");
                assert_eq!(pkt.body()[0], 143, "expected RenewAuthenticationResponse");
                assert_eq!(
                    pkt.body()[10],
                    4, // ResponseCode::AuthUnavailable
                    "expected AuthUnavailable"
                );
                assert_eq!(
                    asm.peer_table
                        .get(link_id)
                        .unwrap()
                        .link_state_machine
                        .get_state(),
                    LinkState::Active,
                    "answering must not perturb the link"
                );
            })
            .await
    }

    /// Codex P1 (PR #17, thread 1): a second RenewAuthenticationRequest on
    /// the same link supersedes the first — the node only retries after
    /// abandoning its previous attempt, so the adapter must cancel the
    /// superseded agent call (drop its reply channel, which the serial
    /// bridge observes via `reply.closed()`) instead of leaving it to run
    /// for up to OIDC_USER_INTERACTION_TIMEOUT while retries queue behind
    /// it.
    #[tokio::test]
    async fn test_adapter_second_renew_request_cancels_superseded_agent_call() {
        LocalSet::new()
            .run_until(async {
                let (asm, _egress_rx) = assembly_with_observable_egress();
                let link_id = add_adapter_peer(&asm);
                let peer = asm.peer_table.get(link_id).unwrap();
                let lsm = &peer.link_state_machine;
                lsm.test_set_state(LinkState::Active);
                lsm.test_set_oidc_idps(vec![test_idp()]);
                let (agent_tx, mut agent_rx) = tokio::sync::mpsc::unbounded_channel();
                lsm.set_auth_agent(agent_tx);
                drop(peer);

                // Attempt A: the agent receives the call and sits on it
                // (a hung or slow AuthAgent).
                asm.process_link_state_event(
                    link_id,
                    LinkEvent::ReceivedRenewAuthRequest(test_challenge_payload()),
                )
                .unwrap();
                let req_a = agent_rx.try_recv().expect("first agent call");
                assert!(
                    !req_a.reply.is_closed(),
                    "attempt A's reply channel must be open while A is current"
                );

                // The node abandoned A (its attempt timeout fired) and
                // retried: attempt B's request arrives on the same link.
                let payload_b = auth::ZdpInitAuthenticationPayload {
                    nonce: [8u8; 8],
                    ctime: 434343u64.into(),
                    hmac: [10u8; 32],
                };
                asm.process_link_state_event(
                    link_id,
                    LinkEvent::ReceivedRenewAuthRequest(payload_b),
                )
                .unwrap();
                let _req_b = agent_rx.try_recv().expect("second agent call");

                // The superseded call must be cancelled: aborting the wait
                // task drops its reply receiver, which tells the bridge to
                // drop the in-flight RPC and service the next request.
                let mut closed = false;
                for _ in 0..50 {
                    tokio::task::yield_now().await;
                    if req_a.reply.is_closed() {
                        closed = true;
                        break;
                    }
                }
                assert!(
                    closed,
                    "the superseded renewal call must be cancelled so the \
                     serial bridge can service the retry"
                );
            })
            .await
    }

    /// R8 (zipline#66) step 4: a RenewAuthenticationResponse whose blob is
    /// bound to the node's outstanding challenge (HMAC-verified with this
    /// link's auth key) completes the renewal: the challenge is consumed and
    /// the completion path (reauthorize) is invoked. The test assembly has
    /// no VS connection, so the completion ends in the recorded
    /// "no visa service connection" failure — reaching THAT failure proves
    /// blob decoding, HMAC verification, challenge equality and issuer
    /// pinning all passed. The link stays Active throughout, and
    /// `renewal_in_flight` is cleared by the completion.
    #[tokio::test]
    async fn test_node_renew_response_with_valid_blob_reaches_reauthorize() {
        LocalSet::new()
            .run_until(async {
                let (asm, mut egress_rx) = assembly_with_observable_egress();
                let link_id = add_node_peer(&asm);
                let peer = asm.peer_table.get(link_id).unwrap();
                let lsm = &peer.link_state_machine;
                lsm.test_set_state(LinkState::Active);
                lsm.set_renewal_identity(super::RenewalIdentity {
                    idp: test_idp(),
                    nonce: auth::oidc_nonce_for_challenge(&[7u8; 48]),
                });
                let now = SystemTime::now();
                lsm.set_auth_expires(
                    now - Duration::from_secs(600),
                    now + Duration::from_secs(60),
                    Duration::from_secs(300),
                );

                // The due tick sends the request and stashes the challenge.
                lsm.maybe_renew_auth(&asm);
                assert!(lsm.test_renewal_in_flight());
                let req_pkt = try_recv_egress(&mut egress_rx).expect("request must be sent");
                assert_eq!(req_pkt.body()[0], 142);
                // body: [0]=type, [1]=excess, [2..10]=seq, [10..12]=data_len,
                // [12..60]=challenge (nonce || ctime || hmac).
                let mut challenge = [0u8; 48];
                challenge.copy_from_slice(&req_pkt.body()[12..60]);

                // The adapter answers with a blob bound to that challenge.
                let blob = auth::encode_blobs(&[crate::auth::AuthBlob::Oidc(auth::ZdpOidcBlob {
                    blob_type: auth::BLOB_TYPE_OIDC.to_string(),
                    issuer: "https://idp.test".to_string(),
                    id_token: "renewed-id-token".to_string(),
                    challenge: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        challenge,
                    ),
                })]);
                asm.process_link_state_event(
                    link_id,
                    LinkEvent::ReceivedRenewAuthResponse(challenge, Ok(blob)),
                )
                .unwrap();

                // Let the spawned completion task run.
                for _ in 0..50 {
                    tokio::task::yield_now().await;
                    if !lsm.test_renewal_in_flight() {
                        break;
                    }
                }
                assert!(
                    !lsm.test_renewal_in_flight(),
                    "completion must clear the in-flight flag"
                );
                // No vsconn in the test assembly: the completion reaches the
                // reauthorize step and records exactly this failure. Any
                // verification failure would have recorded a different one.
                match lsm.get_last_auth_failure() {
                    Some(AuthFailureReason::AgentError(msg)) => assert!(
                        msg.contains("no visa service connection"),
                        "expected the reauthorize-step failure, got: {msg}"
                    ),
                    other => {
                        panic!("expected AgentError(no visa service connection), got {other:?}")
                    }
                }
                assert_eq!(
                    lsm.get_state(),
                    LinkState::Active,
                    "the link must stay Active through a renewal round-trip"
                );
            })
            .await
    }

    /// R8 (zipline#66) step 4: a response whose blob is bound to a DIFFERENT
    /// challenge than the outstanding one is rejected — failure recorded,
    /// in-flight cleared (so the next due tick retries), link still Active,
    /// and the existing expiry left to the sweep.
    #[tokio::test]
    async fn test_node_renew_response_with_wrong_challenge_is_rejected() {
        LocalSet::new()
            .run_until(async {
                let (asm, mut egress_rx) = assembly_with_observable_egress();
                let link_id = add_node_peer(&asm);
                let peer = asm.peer_table.get(link_id).unwrap();
                let lsm = &peer.link_state_machine;
                lsm.test_set_state(LinkState::Active);
                lsm.set_renewal_identity(super::RenewalIdentity {
                    idp: test_idp(),
                    nonce: auth::oidc_nonce_for_challenge(&[7u8; 48]),
                });
                let now = SystemTime::now();
                let expires = now + Duration::from_secs(60);
                lsm.set_auth_expires(
                    now - Duration::from_secs(600),
                    expires,
                    Duration::from_secs(300),
                );

                lsm.maybe_renew_auth(&asm);
                let req_pkt = try_recv_egress(&mut egress_rx).expect("request must be sent");
                // The outstanding challenge, echoed by the (well-behaved)
                // adapter on its response header.
                let mut outstanding = [0u8; 48];
                outstanding.copy_from_slice(&req_pkt.body()[12..60]);

                // A blob correctly HMAC'd with this link's auth key ([42; 32]
                // in the dummy peer) but bound to a DIFFERENT challenge.
                let key = [42u8; auth::AUTH_KEY_SIZE_BYTES];
                let other_payload = auth::ZdpInitAuthenticationPayload::new(&key);
                let mut other_challenge = [0u8; 48];
                other_challenge[0..8].copy_from_slice(&other_payload.nonce);
                other_challenge[8..16].copy_from_slice(&other_payload.ctime.to_bytes());
                other_challenge[16..48].copy_from_slice(&other_payload.hmac);
                let blob = auth::encode_blobs(&[crate::auth::AuthBlob::Oidc(auth::ZdpOidcBlob {
                    blob_type: auth::BLOB_TYPE_OIDC.to_string(),
                    issuer: "https://idp.test".to_string(),
                    id_token: "renewed-id-token".to_string(),
                    challenge: base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        other_challenge,
                    ),
                })]);
                asm.process_link_state_event(
                    link_id,
                    LinkEvent::ReceivedRenewAuthResponse(outstanding, Ok(blob)),
                )
                .unwrap();

                assert!(
                    !lsm.test_renewal_in_flight(),
                    "a rejected response must clear in-flight so the next tick retries"
                );
                match lsm.get_last_auth_failure() {
                    Some(AuthFailureReason::AgentError(msg)) => assert!(
                        msg.contains("different challenge"),
                        "expected the challenge-mismatch failure, got: {msg}"
                    ),
                    other => panic!("expected AgentError(different challenge), got {other:?}"),
                }
                assert_eq!(lsm.get_state(), LinkState::Active, "link must stay Active");
                assert_eq!(
                    lsm.get_auth_expires(),
                    Some(expires),
                    "a failed renewal leaves the existing expiry to the sweep"
                );
            })
            .await
    }

    /// R8 (zipline#66) step 4: an AuthUnavailable response records
    /// [AuthFailureReason::AuthUnavailable], clears in-flight, and leaves
    /// the link Active with its expiry intact.
    #[tokio::test]
    async fn test_node_renew_response_auth_unavailable_records_failure() {
        LocalSet::new()
            .run_until(async {
                let (asm, mut egress_rx) = assembly_with_observable_egress();
                let link_id = add_node_peer(&asm);
                let peer = asm.peer_table.get(link_id).unwrap();
                let lsm = &peer.link_state_machine;
                lsm.test_set_state(LinkState::Active);
                lsm.set_renewal_identity(super::RenewalIdentity {
                    idp: test_idp(),
                    nonce: auth::oidc_nonce_for_challenge(&[7u8; 48]),
                });
                let now = SystemTime::now();
                let expires = now + Duration::from_secs(60);
                lsm.set_auth_expires(
                    now - Duration::from_secs(600),
                    expires,
                    Duration::from_secs(300),
                );

                lsm.maybe_renew_auth(&asm);
                let req_pkt = try_recv_egress(&mut egress_rx).expect("request must be sent");
                let mut outstanding = [0u8; 48];
                outstanding.copy_from_slice(&req_pkt.body()[12..60]);

                asm.process_link_state_event(
                    link_id,
                    LinkEvent::ReceivedRenewAuthResponse(
                        outstanding,
                        Err(ResponseCode::AuthUnavailable),
                    ),
                )
                .unwrap();

                assert!(!lsm.test_renewal_in_flight());
                assert_eq!(
                    lsm.get_last_auth_failure(),
                    Some(AuthFailureReason::AuthUnavailable)
                );
                assert_eq!(lsm.get_state(), LinkState::Active);
                assert_eq!(lsm.get_auth_expires(), Some(expires));
            })
            .await
    }

    /// Codex P1 (PR #17, thread 2): attempt A times out, attempt B starts,
    /// and A's DELAYED response then arrives. The stale response must not
    /// consume (or fail against) B's challenge: B's attempt stays in
    /// flight, and B's own valid response still completes the renewal.
    /// Without correlation, A's response is recorded as B's failure and
    /// B's valid response is discarded as unsolicited.
    #[tokio::test]
    async fn test_node_stale_renew_response_does_not_consume_new_attempts_challenge() {
        LocalSet::new()
            .run_until(async {
                let (asm, mut egress_rx) = assembly_with_observable_egress();
                let link_id = add_node_peer(&asm);
                let peer = asm.peer_table.get(link_id).unwrap();
                let lsm = &peer.link_state_machine;
                lsm.test_set_state(LinkState::Active);
                lsm.set_renewal_identity(super::RenewalIdentity {
                    idp: test_idp(),
                    nonce: auth::oidc_nonce_for_challenge(&[7u8; 48]),
                });
                let now = SystemTime::now();
                lsm.set_auth_expires(
                    now - Duration::from_secs(600),
                    now + Duration::from_secs(60),
                    Duration::from_secs(300),
                );

                // Attempt A: request sent, challenge A stashed.
                lsm.maybe_renew_auth(&asm);
                let pkt_a = try_recv_egress(&mut egress_rx).expect("attempt A request");
                let mut challenge_a = [0u8; 48];
                challenge_a.copy_from_slice(&pkt_a.body()[12..60]);

                // A's attempt timeout fires — exactly what the spawned
                // timer does: fail the attempt and clear its challenge.
                assert!(lsm.take_renewal_challenge_if(&challenge_a));
                lsm.finish_renewal_failure(
                    &asm,
                    AuthFailureReason::AgentError(
                        "renewal credential request timed out (test)".to_string(),
                    ),
                );

                // Attempt B on the next due tick: fresh challenge stashed.
                // (Its request packet may sit in the ZDP-R send window
                // behind unacked attempt A — the transport is not under
                // test — so read the challenge from the stash.)
                lsm.maybe_renew_auth(&asm);
                assert!(lsm.test_renewal_in_flight());
                let challenge_b = lsm
                    .test_renewal_challenge()
                    .expect("attempt B must stash its challenge");
                assert_ne!(
                    challenge_a, challenge_b,
                    "attempts must mint fresh challenges"
                );

                // A's DELAYED response arrives while B is in flight. Its
                // blob is well-formed and HMAC-valid — just bound to A.
                let blob_a =
                    auth::encode_blobs(&[crate::auth::AuthBlob::Oidc(auth::ZdpOidcBlob {
                        blob_type: auth::BLOB_TYPE_OIDC.to_string(),
                        issuer: "https://idp.test".to_string(),
                        id_token: "stale-id-token".to_string(),
                        challenge: base64::Engine::encode(
                            &base64::engine::general_purpose::STANDARD,
                            challenge_a,
                        ),
                    })]);
                asm.process_link_state_event(
                    link_id,
                    LinkEvent::ReceivedRenewAuthResponse(challenge_a, Ok(blob_a)),
                )
                .unwrap();

                // The stale response must be discarded: B stays in flight
                // and its failure record is not overwritten with a
                // misattributed challenge-mismatch failure.
                assert!(
                    lsm.test_renewal_in_flight(),
                    "a stale response from a timed-out attempt must not fail \
                     the newer attempt"
                );

                // B's own valid response still completes the renewal (the
                // test assembly has no VS connection, so completion ends in
                // exactly the reauthorize-step failure — reaching it proves
                // B's challenge was still stashed and verified).
                let blob_b =
                    auth::encode_blobs(&[crate::auth::AuthBlob::Oidc(auth::ZdpOidcBlob {
                        blob_type: auth::BLOB_TYPE_OIDC.to_string(),
                        issuer: "https://idp.test".to_string(),
                        id_token: "renewed-id-token".to_string(),
                        challenge: base64::Engine::encode(
                            &base64::engine::general_purpose::STANDARD,
                            challenge_b,
                        ),
                    })]);
                asm.process_link_state_event(
                    link_id,
                    LinkEvent::ReceivedRenewAuthResponse(challenge_b, Ok(blob_b)),
                )
                .unwrap();
                for _ in 0..50 {
                    tokio::task::yield_now().await;
                    if !lsm.test_renewal_in_flight() {
                        break;
                    }
                }
                assert!(
                    !lsm.test_renewal_in_flight(),
                    "B's valid response must complete the attempt"
                );
                match lsm.get_last_auth_failure() {
                    Some(AuthFailureReason::AgentError(msg)) => assert!(
                        msg.contains("no visa service connection"),
                        "B's response must reach reauthorize, got: {msg}"
                    ),
                    other => {
                        panic!("expected AgentError(no visa service connection), got {other:?}")
                    }
                }
            })
            .await
    }

    /// R8 (zipline#66) step 4: a response with no outstanding request (no
    /// stashed challenge — completed, timed out, or never sent) is discarded
    /// without touching the renewal state.
    #[tokio::test]
    async fn test_node_unsolicited_renew_response_is_discarded() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let link_id = add_node_peer(&asm);
                let peer = asm.peer_table.get(link_id).unwrap();
                let lsm = &peer.link_state_machine;
                lsm.test_set_state(LinkState::Active);

                asm.process_link_state_event(
                    link_id,
                    LinkEvent::ReceivedRenewAuthResponse(
                        [3u8; 48],
                        Ok("not-even-base64".to_string()),
                    ),
                )
                .unwrap();

                assert!(
                    lsm.get_last_auth_failure().is_none(),
                    "an unsolicited response must not record a failure"
                );
                assert!(!lsm.test_renewal_in_flight());
                assert_eq!(lsm.get_state(), LinkState::Active);
            })
            .await
    }

    /// C4 (zipline#45): a due renewal tick with NO AuthAgent registered
    /// warns exactly once per authentication window and records
    /// [AuthFailureReason::NoAgent]; later due ticks are silent no-ops.
    #[tokio::test]
    async fn test_renewal_tick_without_agent_warns_once() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let link_id = add_adapter_peer(&asm);
                let peer = asm.peer_table.get(link_id).unwrap();
                let lsm = &peer.link_state_machine;

                // Renewal overdue: the expiry is already in the past.
                let past = SystemTime::now() - Duration::from_secs(10);
                lsm.set_auth_expires(
                    past - Duration::from_secs(600),
                    past,
                    Duration::from_secs(300),
                );

                lsm.maybe_renew_auth(&asm);
                assert!(lsm.test_renewal_no_agent_warned());
                assert!(matches!(
                    lsm.get_last_auth_failure(),
                    Some(AuthFailureReason::NoAgent)
                ));

                // Second due tick: no new failure is recorded (warned flag
                // holds), and nothing is attempted.
                lsm.test_clear_last_auth_failure();
                lsm.maybe_renew_auth(&asm);
                assert!(
                    lsm.get_last_auth_failure().is_none(),
                    "no-agent warning repeated on a later tick"
                );
                assert!(!lsm.test_renewal_in_flight());
            })
            .await
    }

    /// C4 (zipline#45): a renewal tick before the deadline attempts nothing,
    /// even with an agent registered.
    #[tokio::test]
    async fn test_renewal_tick_before_deadline_is_noop() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let link_id = add_adapter_peer(&asm);
                let peer = asm.peer_table.get(link_id).unwrap();
                let lsm = &peer.link_state_machine;

                let (agent_tx, mut agent_rx) = tokio::sync::mpsc::unbounded_channel();
                lsm.set_auth_agent(agent_tx);
                lsm.set_renewal_identity(super::RenewalIdentity {
                    idp: test_idp(),
                    nonce: auth::oidc_nonce_for_challenge(&[7u8; 48]),
                });
                // Expires an hour out with a 300s lead: not due yet.
                let now = SystemTime::now();
                lsm.set_auth_expires(
                    now,
                    now + Duration::from_secs(3600),
                    Duration::from_secs(300),
                );

                lsm.maybe_renew_auth(&asm);
                assert!(!lsm.test_renewal_in_flight());
                assert!(
                    agent_rx.try_recv().is_err(),
                    "agent was called before the renewal deadline"
                );
            })
            .await
    }

    /// C4 (zipline#45): a due tick with a registered agent sends exactly ONE
    /// non-interactive credential request bound to the ORIGINAL issuer and
    /// the stored challenge-derived nonce; while that attempt is in flight,
    /// further due ticks do not send another.
    #[tokio::test]
    async fn test_renewal_tick_sends_one_noninteractive_request() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let link_id = add_adapter_peer(&asm);
                let peer = asm.peer_table.get(link_id).unwrap();
                let lsm = &peer.link_state_machine;

                let (agent_tx, mut agent_rx) = tokio::sync::mpsc::unbounded_channel();
                lsm.set_auth_agent(agent_tx);
                let challenge = [7u8; 48];
                lsm.set_renewal_identity(super::RenewalIdentity {
                    idp: test_idp(),
                    nonce: auth::oidc_nonce_for_challenge(&challenge),
                });
                let past = SystemTime::now() - Duration::from_secs(1);
                lsm.set_auth_expires(
                    past - Duration::from_secs(600),
                    past,
                    Duration::from_secs(300),
                );

                lsm.maybe_renew_auth(&asm);
                let req = agent_rx.try_recv().expect("agent must be called once");
                assert!(
                    !req.interactive,
                    "renewal must never open a browser (interactive must be false)"
                );
                assert_eq!(req.idp.issuer, "https://idp.test");
                assert_eq!(req.nonce, auth::oidc_nonce_for_challenge(&challenge));

                // In flight: the next due tick must not send a second call.
                lsm.maybe_renew_auth(&asm);
                assert!(
                    agent_rx.try_recv().is_err(),
                    "second agent call while a renewal attempt is in flight"
                );
            })
            .await
    }

    /// PR #14 review: one silent-renewal attempt waits at most half the time
    /// remaining before expiry — clamped between the 5 s floor and the 300 s
    /// interaction timeout — so a hung attempt can always be retried while
    /// the current authentication is still valid.
    #[test]
    fn test_renewal_attempt_timeout_bounded_by_remaining_window() {
        let now = SystemTime::now();
        // Plenty of window: capped at the bridge's own per-call bound.
        assert_eq!(
            super::renewal_attempt_timeout(now, now + Duration::from_secs(3600)),
            config::OIDC_USER_INTERACTION_TIMEOUT,
        );
        // 600 s remaining (the default-lead case that motivated the review
        // finding): half the window, leaving room for a retry before expiry.
        assert_eq!(
            super::renewal_attempt_timeout(now, now + Duration::from_secs(600)),
            Duration::from_secs(300),
        );
        // 60 s remaining: 30 s, again half.
        assert_eq!(
            super::renewal_attempt_timeout(now, now + Duration::from_secs(60)),
            Duration::from_secs(30),
        );
        // Nearly (or already) expired: the floor keeps a healthy agent
        // answerable instead of a zero-length wait.
        assert_eq!(
            super::renewal_attempt_timeout(now, now + Duration::from_secs(4)),
            super::RENEWAL_ATTEMPT_TIMEOUT_FLOOR,
        );
        assert_eq!(
            super::renewal_attempt_timeout(now, now - Duration::from_secs(10)),
            super::RENEWAL_ATTEMPT_TIMEOUT_FLOOR,
        );
    }

    /// PR #14 review: an AuthAgent that never answers must not pin
    /// `renewal_in_flight` past the authentication window. The attempt times
    /// out (bounded by the remaining window), records a failure, and the next
    /// due tick retries.
    #[tokio::test(start_paused = true)]
    async fn test_hung_renewal_attempt_times_out_and_next_tick_retries() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let link_id = add_adapter_peer(&asm);
                let peer = asm.peer_table.get(link_id).unwrap();
                let lsm = &peer.link_state_machine;

                let (agent_tx, mut agent_rx) = tokio::sync::mpsc::unbounded_channel();
                lsm.set_auth_agent(agent_tx);
                lsm.set_renewal_identity(super::RenewalIdentity {
                    idp: test_idp(),
                    nonce: auth::oidc_nonce_for_challenge(&[7u8; 48]),
                });
                // Renewal overdue with ~20 s of validity left: the attempt
                // timeout must be ~10 s, far below the 300 s bridge bound.
                let now = SystemTime::now();
                lsm.set_auth_expires(
                    now - Duration::from_secs(580),
                    now + Duration::from_secs(20),
                    Duration::from_secs(300),
                );

                lsm.maybe_renew_auth(&asm);
                // The agent hangs: hold the request (and its reply sender)
                // without ever answering.
                let hung_req = agent_rx.try_recv().expect("agent must be called");
                assert!(lsm.test_renewal_in_flight());

                // Let the spawned completion task register its timeout timer
                // before advancing the paused clock.
                for _ in 0..10 {
                    tokio::task::yield_now().await;
                }
                // Well past the bounded attempt timeout, but well short of
                // the 300 s bridge bound the review flagged.
                tokio::time::advance(Duration::from_secs(30)).await;
                for _ in 0..50 {
                    tokio::task::yield_now().await;
                    if !lsm.test_renewal_in_flight() {
                        break;
                    }
                }
                assert!(
                    !lsm.test_renewal_in_flight(),
                    "hung attempt still in flight after the remaining-window timeout"
                );
                assert!(matches!(
                    lsm.get_last_auth_failure(),
                    Some(AuthFailureReason::AgentError(_))
                ));

                // The next due tick retries while auth is still valid.
                lsm.maybe_renew_auth(&asm);
                assert!(
                    agent_rx.try_recv().is_ok(),
                    "next due tick must retry after a timed-out attempt"
                );
                drop(hung_req);
            })
            .await
    }

    /// PR #14 review: a renewal task that outlives its link must not act on
    /// a NEW link that reused the same slab id. The reply from the closed
    /// link's AuthAgent request carries the old instance's uid; when the
    /// current occupant of the id has a different uid, the outcome must be
    /// discarded instead of pushing the old actor's renewal result onto the
    /// new link's state. The uid mismatch is driven directly through
    /// [LinkStateWrapper::handle_renewal_reply] (exactly the call the task
    /// spawned by maybe_renew_auth makes): the RCU slab defers slot
    /// reclamation, so a unit test cannot force a real id reuse without
    /// draining the epoch machinery.
    #[tokio::test]
    async fn test_stale_renewal_reply_after_link_id_reuse_is_discarded() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let link_id = add_adapter_peer(&asm);
                let current_uid = asm.peer_table.get(link_id).unwrap().link_state_machine.uid;

                // A stale task from the closed PREVIOUS occupant of this id
                // delivers a successful renewal outcome for the old actor.
                let stale_uid = current_uid.wrapping_add(1);
                super::LinkStateWrapper::handle_renewal_reply(
                    &asm,
                    link_id,
                    stale_uid,
                    "https://idp.test".to_string(),
                    auth::oidc_nonce_for_challenge(&[7u8; 48]),
                    Ok(Ok("stale-id-token".to_string())),
                )
                .await;

                {
                    let new_peer = asm.peer_table.get(link_id).unwrap();
                    let new_lsm = &new_peer.link_state_machine;
                    assert!(
                        new_lsm.get_last_auth_failure().is_none(),
                        "stale renewal task from the closed link wrote a failure onto the new link"
                    );
                    assert!(
                        !new_lsm.test_renewal_in_flight(),
                        "stale renewal task perturbed the new link's in-flight flag"
                    );
                    assert_eq!(
                        new_lsm.get_auth_expires(),
                        None,
                        "stale renewal task overwrote the new link's auth expiry"
                    );
                }

                // Control: the SAME reply with the matching uid is acted on
                // (the test assembly has no vsconn, so the Ok token ends in a
                // recorded failure) — proving the uid guard, not something
                // else, discarded the stale reply above.
                super::LinkStateWrapper::handle_renewal_reply(
                    &asm,
                    link_id,
                    current_uid,
                    "https://idp.test".to_string(),
                    auth::oidc_nonce_for_challenge(&[7u8; 48]),
                    Ok(Ok("current-id-token".to_string())),
                )
                .await;
                let peer = asm.peer_table.get(link_id).unwrap();
                assert!(
                    peer.link_state_machine.get_last_auth_failure().is_some(),
                    "a reply with the matching uid must be processed"
                );
            })
            .await
    }

    /// C4 (zipline#45): a failed attempt records the reason, clears the
    /// in-flight flag, and the NEXT due tick retries (one attempt per tick).
    #[tokio::test]
    async fn test_renewal_failure_records_reason_and_next_tick_retries() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let link_id = add_adapter_peer(&asm);
                let peer = asm.peer_table.get(link_id).unwrap();
                let lsm = &peer.link_state_machine;

                let (agent_tx, mut agent_rx) = tokio::sync::mpsc::unbounded_channel();
                lsm.set_auth_agent(agent_tx);
                lsm.set_renewal_identity(super::RenewalIdentity {
                    idp: test_idp(),
                    nonce: auth::oidc_nonce_for_challenge(&[7u8; 48]),
                });
                let past = SystemTime::now() - Duration::from_secs(1);
                lsm.set_auth_expires(
                    past - Duration::from_secs(600),
                    past,
                    Duration::from_secs(300),
                );

                // Attempt 1: the agent answers with a failure.
                lsm.maybe_renew_auth(&asm);
                let req = agent_rx.try_recv().expect("agent must be called");
                req.reply
                    .send(Err(AuthFailureReason::IdpUnreachable(
                        "refresh failed".to_string(),
                    )))
                    .unwrap();
                // Let the completion task run.
                for _ in 0..20 {
                    tokio::task::yield_now().await;
                    if !lsm.test_renewal_in_flight() {
                        break;
                    }
                }
                assert!(
                    !lsm.test_renewal_in_flight(),
                    "failure must clear in-flight"
                );
                assert!(matches!(
                    lsm.get_last_auth_failure(),
                    Some(AuthFailureReason::IdpUnreachable(_))
                ));

                // Attempt 2 on the next due tick.
                lsm.maybe_renew_auth(&asm);
                assert!(
                    agent_rx.try_recv().is_ok(),
                    "registered-but-failing agent must be retried once per due tick"
                );
            })
            .await
    }

    /// C2 (zipline#45): clearing the AuthAgent slot is guarded — the handle
    /// of a dead admin connection only clears the slot while it is still the
    /// registered agent; a newer agent registered afterwards is left alone.
    #[tokio::test]
    async fn test_clear_auth_agent_if_only_clears_matching_handle() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let link_id = add_adapter_peer(&asm);
                let peer = asm.peer_table.get(link_id).unwrap();

                let (agent1, _rx1) = tokio::sync::mpsc::unbounded_channel();
                let (agent2, _rx2) = tokio::sync::mpsc::unbounded_channel();

                // agent1 registers, then its admin connection dies: cleared.
                peer.link_state_machine.set_auth_agent(agent1.clone());
                assert!(peer.link_state_machine.test_has_auth_agent());
                assert!(peer.link_state_machine.clear_auth_agent_if(&agent1));
                assert!(!peer.link_state_machine.test_has_auth_agent());

                // agent1 re-registers, then agent2 replaces it. agent1's
                // stale cleanup must NOT clobber agent2.
                peer.link_state_machine.set_auth_agent(agent1.clone());
                peer.link_state_machine.set_auth_agent(agent2.clone());
                assert!(!peer.link_state_machine.clear_auth_agent_if(&agent1));
                assert!(
                    peer.link_state_machine.test_has_auth_agent(),
                    "stale bridge cleanup clobbered the newer agent"
                );
            })
            .await
    }

    /// With `auto_connect = false` (zipline#28), a dropped AdapterToNode
    /// tether must NOT auto-restart: `complete_close` leaves it Inactive
    /// and no holddown timer re-fires `Start`. The next `startLink` RPC is
    /// the only way back up.
    #[tokio::test(start_paused = true)]
    async fn test_no_restart_after_close_when_auto_connect_disabled() {
        LocalSet::new()
            .run_until(async {
                let mut builder = TestAssemblyBuilder::new();
                builder.self_noise_keypair = Some(crate::km_noise::NoiseKeypair::generate());
                builder.certx = Some(crate::km_cert_exchange::KmCertExchange::new(None, None));
                let mut cfg = <crate::config::Config as std::default::Default>::default();
                cfg.auto_connect = false;
                builder.config = Some(rcu::RcuBox::new(cfg));
                let asm = Arc::new(create_assembly(builder));
                let link_id = add_adapter_peer(&asm);

                // The link is closing (e.g. auth failed); the close completes.
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.link_state_machine.test_set_state(LinkState::Closing);
                }
                asm.process_link_state_event(link_id, LinkEvent::CloseDone)
                    .unwrap();
                assert_eq!(
                    asm.peer_table
                        .get(link_id)
                        .unwrap()
                        .link_state_machine
                        .get_state(),
                    LinkState::Inactive
                );

                // Advance well past the restart holddown: still Inactive.
                tokio::time::sleep(config::DEFAULT_LINK_RESTART_HOLDDOWN + Duration::from_secs(1))
                    .await;
                assert_eq!(
                    asm.peer_table
                        .get(link_id)
                        .unwrap()
                        .link_state_machine
                        .get_state(),
                    LinkState::Inactive,
                    "auto_connect=false link must wait for startLink, not self-restart"
                );
            })
            .await
    }

    /// With `auto_connect = false`, a manually started link that fails
    /// BEFORE authentication (here: the Helloing timeout in
    /// `process_timeout`, which records no `AuthFailureReason`) ends up
    /// permanently Inactive — terminal, since no restart is coming. The
    /// terminal state must carry a recorded failure reason: ph-cli's
    /// `connect` poll classifies a teardown state *without* a
    /// `Last auth failure:` line as Pending (restart forthcoming) and
    /// would otherwise wait forever on a link that will never recover.
    #[tokio::test(start_paused = true)]
    async fn test_manual_mode_pre_auth_failure_is_terminal_not_pending() {
        LocalSet::new()
            .run_until(async {
                let mut builder = TestAssemblyBuilder::new();
                let mut cfg = <crate::config::Config as std::default::Default>::default();
                cfg.auto_connect = false;
                builder.config = Some(rcu::RcuBox::new(cfg));
                let asm = Arc::new(create_assembly(builder));
                let link_id = add_adapter_peer(&asm);

                // A manually started attempt is stuck in Helloing; its
                // timeout fires (process_timeout gives up on the link).
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.link_state_machine.test_set_state(LinkState::Helloing);
                }
                let logical_clock = asm
                    .peer_table
                    .get(link_id)
                    .unwrap()
                    .link_state_machine
                    .test_logical_clock();
                asm.process_link_state_event(link_id, LinkEvent::Timeout { logical_clock })
                    .unwrap();
                assert_eq!(
                    asm.peer_table
                        .get(link_id)
                        .unwrap()
                        .link_state_machine
                        .get_state(),
                    LinkState::Closing,
                    "test precondition: the Helloing timeout initiates the close"
                );

                // The terminate handshake completes and the close finishes.
                asm.process_link_state_event(link_id, LinkEvent::CloseDone)
                    .unwrap();

                let peer = asm.peer_table.get(link_id).unwrap();
                assert_eq!(peer.link_state_machine.get_state(), LinkState::Inactive);
                assert!(
                    peer.link_state_machine.get_last_auth_failure().is_some(),
                    "terminal idle after a pre-auth failure must carry a recorded \
                     failure reason, or ph-cli connect classifies the permanently \
                     Inactive link as Pending and hangs until its deadline"
                );
            })
            .await
    }

    /// Companion: with the default config (`auto_connect = true`) the
    /// holddown restart still happens — today's behaviour is preserved.
    #[tokio::test(start_paused = true)]
    async fn test_restart_after_close_with_default_auto_connect() {
        LocalSet::new()
            .run_until(async {
                let mut builder = TestAssemblyBuilder::new();
                builder.self_noise_keypair = Some(crate::km_noise::NoiseKeypair::generate());
                builder.certx = Some(crate::km_cert_exchange::KmCertExchange::new(None, None));
                let asm = Arc::new(create_assembly(builder));
                let link_id = add_adapter_peer(&asm);

                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.link_state_machine.test_set_state(LinkState::Closing);
                }
                asm.process_link_state_event(link_id, LinkEvent::CloseDone)
                    .unwrap();
                assert_eq!(
                    asm.peer_table
                        .get(link_id)
                        .unwrap()
                        .link_state_machine
                        .get_state(),
                    LinkState::Inactive
                );

                tokio::time::sleep(config::DEFAULT_LINK_RESTART_HOLDDOWN + Duration::from_secs(1))
                    .await;
                assert_eq!(
                    asm.peer_table
                        .get(link_id)
                        .unwrap()
                        .link_state_machine
                        .get_state(),
                    LinkState::Keying,
                    "default config must keep the automatic holddown restart"
                );
            })
            .await
    }

    /// WaitForUserAuth with an agent that never replies must fail with
    /// `AuthFailureReason::InteractionTimeout` once
    /// `OIDC_USER_INTERACTION_TIMEOUT` (300 s) elapses. The Error state is
    /// transient — the same callback initiates the close — so the state
    /// assertion accepts the close already being underway.
    #[tokio::test(start_paused = true)]
    async fn test_wait_for_user_auth_times_out_with_interaction_timeout() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let link_id = add_adapter_peer(&asm);

                // Agent that accepts requests but never answers them.
                let (agent_tx, _agent_rx) = tokio::sync::mpsc::unbounded_channel();
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.link_state_machine
                        .test_set_state(LinkState::WaitForInitAuth);
                    peer.link_state_machine.test_set_oidc_idps(vec![test_idp()]);
                    peer.link_state_machine.set_auth_agent(agent_tx);
                }

                asm.process_link_state_event(
                    link_id,
                    LinkEvent::ReceivedInitAuth((false, Some(test_challenge_payload()))),
                )
                .unwrap();

                assert_eq!(
                    asm.peer_table
                        .get(link_id)
                        .unwrap()
                        .link_state_machine
                        .get_state(),
                    LinkState::WaitForUserAuth
                );

                tokio::time::sleep(
                    config::OIDC_USER_INTERACTION_TIMEOUT + Duration::from_millis(100),
                )
                .await;

                let peer = asm.peer_table.get(link_id).unwrap();
                let state = peer.link_state_machine.get_state();
                assert!(
                    matches!(state, LinkState::Error | LinkState::Closing),
                    "expected Error (or the close it initiates), got {state:?}"
                );
                assert_eq!(
                    peer.link_state_machine.get_last_auth_failure(),
                    Some(AuthFailureReason::InteractionTimeout)
                );
            })
            .await
    }

    /// An advertised IdP with no registered agent and no bootstrap key must
    /// fail authentication with `AuthFailureReason::NoAgent`.
    #[tokio::test(start_paused = true)]
    async fn test_no_agent_with_idp_and_no_bootstrap_fails_with_no_agent() {
        LocalSet::new()
            .run_until(async {
                // Default config: no bootstrap key.
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let link_id = add_adapter_peer(&asm);
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.link_state_machine
                        .test_set_state(LinkState::WaitForInitAuth);
                    peer.link_state_machine.test_set_oidc_idps(vec![test_idp()]);
                    // no auth agent registered
                }

                asm.process_link_state_event(
                    link_id,
                    LinkEvent::ReceivedInitAuth((true, Some(test_challenge_payload()))),
                )
                .unwrap();

                let peer = asm.peer_table.get(link_id).unwrap();
                let state = peer.link_state_machine.get_state();
                assert!(
                    matches!(state, LinkState::Error | LinkState::Closing),
                    "expected Error (or the close it initiates), got {state:?}"
                );
                assert_eq!(
                    peer.link_state_machine.get_last_auth_failure(),
                    Some(AuthFailureReason::NoAgent)
                );
            })
            .await
    }

    /// `LinkEvent::Start` on an Inactive link begins a fresh authentication
    /// attempt, so it must clear the previous attempt's recorded failure:
    /// the CLI treats a teardown state that carries a `Last auth failure`
    /// line as that attempt's terminal outcome, so a stale reason surviving
    /// into a restarted link would be misread as a new failure.
    #[tokio::test(start_paused = true)]
    async fn test_start_clears_previous_auth_failure() {
        LocalSet::new()
            .run_until(async {
                // process_start (AdapterToNode) keys the link, which needs a
                // noise keypair and a certificate exchange on the assembly.
                let mut builder = TestAssemblyBuilder::new();
                builder.self_noise_keypair = Some(crate::km_noise::NoiseKeypair::generate());
                builder.certx = Some(crate::km_cert_exchange::KmCertExchange::new(None, None));
                let asm = Arc::new(create_assembly(builder));
                let link_id = add_adapter_peer(&asm);

                // A previous attempt failed and the auto-close completed.
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.link_state_machine
                        .test_set_state(LinkState::WaitForUserAuth);
                }
                asm.process_link_state_event(
                    link_id,
                    LinkEvent::AuthenticationFailure(AuthFailureReason::UserDeclined),
                )
                .unwrap();
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    assert_eq!(
                        peer.link_state_machine.get_last_auth_failure(),
                        Some(AuthFailureReason::UserDeclined)
                    );
                    // Model the close completing (Closing -> Inactive).
                    peer.link_state_machine.test_set_state(LinkState::Inactive);
                }

                // A fresh Start (manual restart or the automatic holddown
                // restart) begins a new attempt: the stale reason must go.
                asm.process_link_state_event(link_id, LinkEvent::Start)
                    .unwrap();
                let peer = asm.peer_table.get(link_id).unwrap();
                assert_eq!(peer.link_state_machine.get_state(), LinkState::Keying);
                assert_eq!(
                    peer.link_state_machine.get_last_auth_failure(),
                    None,
                    "stale auth failure survived into the new attempt"
                );
            })
            .await
    }

    /// A `Start` begins a fresh ZDP-R session, so it must reset the link's
    /// sender and receiver.
    ///
    /// An adapter keeps one peer table entry (and so one ZDP-R session) per
    /// link for the life of the process, but the node it re-docks with
    /// allocates a brand new link -- and so a brand new sender -- for every
    /// dock attempt, restarting its sequence numbers at 0.  An adapter that
    /// carried the previous attempt's receive window into the restart would
    /// classify every packet of the new session as an already-seen
    /// duplicate: dropped without processing but still acknowledged, so the
    /// node never retransmits and the link never gets past Helloing.
    #[tokio::test(start_paused = true)]
    async fn test_start_resets_zdpr_session() {
        LocalSet::new()
            .run_until(async {
                // process_start (AdapterToNode) keys the link, which needs a
                // noise keypair and a certificate exchange on the assembly.
                let mut builder = TestAssemblyBuilder::new();
                builder.self_noise_keypair = Some(crate::km_noise::NoiseKeypair::generate());
                builder.certx = Some(crate::km_cert_exchange::KmCertExchange::new(None, None));
                let asm = Arc::new(create_assembly(builder));
                let link_id = add_adapter_peer(&asm);

                // A previous dock attempt received the peer's first two
                // management packets, then the link was torn down.
                let generation_before = {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    let mut recv = peer.zdpr_recv.lock().unwrap();
                    assert!(recv.should_process_packet(0));
                    recv.process_packet(0);
                    recv.process_packet(1);
                    assert!(
                        !recv.should_process_packet(0),
                        "test precondition: sequence number 0 is now a duplicate"
                    );
                    drop(recv);
                    peer.link_state_machine.test_set_state(LinkState::Inactive);
                    peer.zdpr_generation()
                };

                asm.process_link_state_event(link_id, LinkEvent::Start)
                    .unwrap();

                let peer = asm.peer_table.get(link_id).unwrap();
                assert_eq!(peer.link_state_machine.get_state(), LinkState::Keying);
                assert!(
                    peer.zdpr_recv.lock().unwrap().should_process_packet(0),
                    "stale receive window survived into the new session: the \
                     peer's restarted sequence numbers would be discarded as \
                     duplicates"
                );
                assert_ne!(
                    peer.zdpr_generation(),
                    generation_before,
                    "the new session must be distinguishable from the old one"
                );
            })
            .await
    }

    /// zipline#83 RED: a grant that differs from the non-empty configured
    /// `--zpr-addr` must be refused — the FSM parks in Error (or the close it
    /// initiates) instead of ACTIVE, the recorded failure is
    /// `GrantedAddressMismatch` carrying both address sets, its rendered text
    /// names the remedy (remove the `--zpr-addr` argument / `zpr_addr` config
    /// line), and main's fatal-error watcher is signalled so the process
    /// exits non-zero.
    #[tokio::test(start_paused = true)]
    async fn test_grant_address_mismatch_refuses_to_run() {
        LocalSet::new()
            .run_until(async {
                let configured: IpAddr = "fd00:1:1::1".parse().unwrap();
                let granted: IpAddr = "fd5a:5052:adda:1::42".parse().unwrap();

                let mut builder = TestAssemblyBuilder::new();
                let mut cfg = <crate::config::Config as std::default::Default>::default();
                cfg.zpr_addr = vec![configured];
                builder.config = Some(rcu::RcuBox::new(cfg));
                let asm = Arc::new(create_assembly(builder));
                let link_id = add_adapter_peer(&asm);
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.link_state_machine
                        .test_set_state(LinkState::RegisterAA);
                }

                asm.process_link_state_event(
                    link_id,
                    LinkEvent::ReceivedGrantZprAddressRequest(Ok(vec![
                        zpr_utils::net_defs::IpAddress::new_from_std(&granted),
                    ])),
                )
                .unwrap();

                let peer = asm.peer_table.get(link_id).unwrap();
                let state = peer.link_state_machine.get_state();
                assert!(
                    matches!(state, LinkState::Error | LinkState::Closing),
                    "a mismatched grant must not become ACTIVE; \
                     expected Error (or the close it initiates), got {state:?}"
                );

                let reason = peer.link_state_machine.get_last_auth_failure();
                match &reason {
                    Some(AuthFailureReason::GrantedAddressMismatch {
                        requested,
                        granted: g,
                    }) => {
                        assert_eq!(requested, &vec![configured]);
                        assert_eq!(g, &vec![granted]);
                    }
                    other => panic!("expected GrantedAddressMismatch, got {other:?}"),
                }

                // The local ZPR address set must NOT have been replaced by
                // the refused grant.
                assert_eq!(
                    asm.get_local_zpr_addrs_std(),
                    vec![configured],
                    "a refused grant must not overwrite the configured address"
                );

                // The fatal signal main exits on, with the remedy in the text.
                let fatal = asm
                    .get_fatal_error()
                    .expect("a mismatched grant must signal a fatal error so main exits non-zero");
                assert!(
                    fatal.contains("--zpr-addr") && fatal.contains("zpr_addr"),
                    "the fatal error must carry the remedy (remove the \
                     --zpr-addr argument / zpr_addr config line); got: {fatal}"
                );
                assert!(
                    fatal.contains("fd00:1:1::1") && fatal.contains("fd5a:5052:adda:1::42"),
                    "the fatal error must name both addresses; got: {fatal}"
                );
            })
            .await
    }

    /// zipline#83 companion (GREEN lock-in): an adapter with NO configured
    /// address accepts the dynamic grant — the TUN gets the granted address,
    /// the local ZPR address set becomes the granted set, the link goes
    /// ACTIVE, and no fatal error is signalled.
    #[tokio::test(start_paused = true)]
    async fn test_grant_with_no_configured_address_is_accepted() {
        LocalSet::new()
            .run_until(async {
                let granted: IpAddr = "fd5a:5052:adda:1::42".parse().unwrap();

                // Default config: zpr_addr is empty (no --zpr-addr).
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                assert!(
                    asm.get_local_zpr_addrs_std().is_empty(),
                    "test precondition: no configured ZPR address"
                );
                let link_id = add_adapter_peer(&asm);
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.link_state_machine
                        .test_set_state(LinkState::RegisterAA);
                }

                asm.process_link_state_event(
                    link_id,
                    LinkEvent::ReceivedGrantZprAddressRequest(Ok(vec![
                        zpr_utils::net_defs::IpAddress::new_from_std(&granted),
                    ])),
                )
                .unwrap();

                let peer = asm.peer_table.get(link_id).unwrap();
                assert_eq!(
                    peer.link_state_machine.get_state(),
                    LinkState::Active,
                    "a dynamic grant with no configured address must go ACTIVE"
                );
                assert_eq!(
                    asm.get_local_zpr_addrs_std(),
                    vec![granted],
                    "the granted address must become the local ZPR address set"
                );
                assert_eq!(peer.link_state_machine.get_last_auth_failure(), None);
                assert_eq!(asm.get_fatal_error(), None);
            })
            .await
    }

    /// zipline#83 review fix (PR #27) RED: an adapter started with NO
    /// `--zpr-addr` accepts its first dynamic grant — and on a later
    /// reconnect must accept a DIFFERENT dynamic grant too. The demand the
    /// mismatch check enforces is the *startup* configuration (empty here),
    /// not whatever the fabric happened to grant last time:
    /// `set_local_zpr_addrs` writes each grant into `config.zpr_addr` and
    /// teardown never restores the original empty value, so before the fix
    /// this reconnect mistook the previous dynamic address for an
    /// operator-configured demand and exited on a mismatch it was
    /// explicitly configured to accept.
    #[tokio::test(start_paused = true)]
    async fn test_reconnect_after_dynamic_grant_accepts_different_dynamic_address() {
        LocalSet::new()
            .run_until(async {
                let first: IpAddr = "fd5a:5052:adda:1::42".parse().unwrap();
                let second: IpAddr = "fd5a:5052:adda:1::43".parse().unwrap();

                // Default config: zpr_addr is empty (no --zpr-addr).
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                assert!(
                    asm.get_local_zpr_addrs_std().is_empty(),
                    "test precondition: no configured ZPR address"
                );
                let link_id = add_adapter_peer(&asm);
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.link_state_machine
                        .test_set_state(LinkState::RegisterAA);
                }

                // First connection: dynamic grant accepted.
                asm.process_link_state_event(
                    link_id,
                    LinkEvent::ReceivedGrantZprAddressRequest(Ok(vec![
                        zpr_utils::net_defs::IpAddress::new_from_std(&first),
                    ])),
                )
                .unwrap();
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    assert_eq!(
                        peer.link_state_machine.get_state(),
                        LinkState::Active,
                        "the first dynamic grant must go ACTIVE"
                    );
                }
                assert_eq!(asm.get_local_zpr_addrs_std(), vec![first]);

                // Reconnect: back through address registration. The fabric
                // assigns a different dynamic address this time.
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.link_state_machine
                        .test_set_state(LinkState::RegisterAA);
                }
                asm.process_link_state_event(
                    link_id,
                    LinkEvent::ReceivedGrantZprAddressRequest(Ok(vec![
                        zpr_utils::net_defs::IpAddress::new_from_std(&second),
                    ])),
                )
                .unwrap();

                let peer = asm.peer_table.get(link_id).unwrap();
                assert_eq!(
                    peer.link_state_machine.get_state(),
                    LinkState::Active,
                    "an adapter with no configured --zpr-addr must accept a \
                     different dynamic grant on reconnect"
                );
                assert_eq!(
                    asm.get_local_zpr_addrs_std(),
                    vec![second],
                    "the new grant must become the local ZPR address set"
                );
                assert_eq!(
                    peer.link_state_machine.get_last_auth_failure(),
                    None,
                    "a fabric-assigned address is not a mismatch when nothing \
                     was demanded"
                );
                assert_eq!(
                    asm.get_fatal_error(),
                    None,
                    "no fatal exit: the adapter was configured to accept \
                     fabric-assigned addresses"
                );
            })
            .await
    }

    /// zipline#83 companion: a grant matching the configured address is the
    /// normal path and must stay unchanged — ACTIVE, no failure, no fatal.
    #[tokio::test(start_paused = true)]
    async fn test_grant_matching_configured_address_stays_active() {
        LocalSet::new()
            .run_until(async {
                let configured: IpAddr = "fd00:1:1::1".parse().unwrap();

                let mut builder = TestAssemblyBuilder::new();
                let mut cfg = <crate::config::Config as std::default::Default>::default();
                cfg.zpr_addr = vec![configured];
                builder.config = Some(rcu::RcuBox::new(cfg));
                let asm = Arc::new(create_assembly(builder));
                let link_id = add_adapter_peer(&asm);
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.link_state_machine
                        .test_set_state(LinkState::RegisterAA);
                }

                asm.process_link_state_event(
                    link_id,
                    LinkEvent::ReceivedGrantZprAddressRequest(Ok(vec![
                        zpr_utils::net_defs::IpAddress::new_from_std(&configured),
                    ])),
                )
                .unwrap();

                let peer = asm.peer_table.get(link_id).unwrap();
                assert_eq!(peer.link_state_machine.get_state(), LinkState::Active);
                assert_eq!(peer.link_state_machine.get_last_auth_failure(), None);
                assert_eq!(asm.get_fatal_error(), None);
                assert_eq!(asm.get_local_zpr_addrs_std(), vec![configured]);
            })
            .await
    }

    /// A failed grant carries the node's ResponseCode; the link must record
    /// the corresponding `AuthFailureReason`.
    #[tokio::test(start_paused = true)]
    async fn test_grant_failure_code_maps_to_reason() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));

                for (code, expect_policy_denied, expect_unavailable) in [
                    (ResponseCode::PolicyDenied, true, false),
                    (ResponseCode::AuthFailed, false, false),
                    (ResponseCode::AuthUnavailable, false, true),
                ] {
                    let link_id = add_adapter_peer(&asm);
                    {
                        let peer = asm.peer_table.get(link_id).unwrap();
                        peer.link_state_machine
                            .test_set_state(LinkState::RegisterAA);
                    }

                    asm.process_link_state_event(
                        link_id,
                        LinkEvent::ReceivedGrantZprAddressRequest(Err(code)),
                    )
                    .unwrap();

                    let peer = asm.peer_table.get(link_id).unwrap();
                    let reason = peer.link_state_machine.get_last_auth_failure();
                    if expect_policy_denied {
                        assert_eq!(reason, Some(AuthFailureReason::PolicyDenied));
                    } else if expect_unavailable {
                        assert_eq!(reason, Some(AuthFailureReason::AuthUnavailable));
                    } else {
                        assert!(
                            matches!(reason, Some(AuthFailureReason::VisaServiceRejected(_))),
                            "expected VisaServiceRejected, got {reason:?}"
                        );
                    }
                }
            })
            .await
    }

    /// zipline#88 RED: an adapter accepting a *dynamic* grant (no configured
    /// address) must install an on-link route for the whole ZPR internal
    /// network (`fd5a:5052::/32`) on its TUN at activation, so traffic to
    /// and from fabric-assigned (dynamic-pool) addresses has a route.
    #[tokio::test(start_paused = true)]
    async fn test_dynamic_grant_installs_internal_net_route() {
        LocalSet::new()
            .run_until(async {
                let granted: IpAddr = "fd5a:5052:adda:1::42".parse().unwrap();

                let (tun_ctl, routes) = crate::assembly::test::RecordingTunCtl::new(false);
                let mut builder = TestAssemblyBuilder::new();
                builder.tun_ctl = Some(Box::new(tun_ctl));
                let asm = Arc::new(create_assembly(builder));
                let link_id = add_adapter_peer(&asm);
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.link_state_machine
                        .test_set_state(LinkState::RegisterAA);
                }

                asm.process_link_state_event(
                    link_id,
                    LinkEvent::ReceivedGrantZprAddressRequest(Ok(vec![
                        zpr_utils::net_defs::IpAddress::new_from_std(&granted),
                    ])),
                )
                .unwrap();

                let peer = asm.peer_table.get(link_id).unwrap();
                assert_eq!(peer.link_state_machine.get_state(), LinkState::Active);
                assert!(
                    routes
                        .lock()
                        .unwrap()
                        .contains(&(IpAddr::V6(ZPR_INTERNAL_NETWORK), ZPRNET_PREFIX_LEN)),
                    "activation on a dynamic grant must install the ZPR \
                     internal-network route {ZPR_INTERNAL_NETWORK}/{ZPRNET_PREFIX_LEN} \
                     on the TUN; recorded routes: {:?}",
                    routes.lock().unwrap()
                );
            })
            .await
    }

    /// zipline#88 RED: the statically-addressed activation path (grant
    /// matching the configured demand) must install the same internal-network
    /// route — this is the peer side of the return path: a static adapter
    /// with only its own deployment-provisioned routes has no route back to
    /// a dynamically-addressed peer, so its replies are dropped.
    #[tokio::test(start_paused = true)]
    async fn test_static_grant_installs_internal_net_route() {
        LocalSet::new()
            .run_until(async {
                let configured: IpAddr = "fd00:1:2::1".parse().unwrap();

                let (tun_ctl, routes) = crate::assembly::test::RecordingTunCtl::new(false);
                let mut builder = TestAssemblyBuilder::new();
                let mut cfg = <crate::config::Config as std::default::Default>::default();
                cfg.zpr_addr = vec![configured];
                builder.config = Some(rcu::RcuBox::new(cfg));
                builder.tun_ctl = Some(Box::new(tun_ctl));
                let asm = Arc::new(create_assembly(builder));
                let link_id = add_adapter_peer(&asm);
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.link_state_machine
                        .test_set_state(LinkState::RegisterAA);
                }

                asm.process_link_state_event(
                    link_id,
                    LinkEvent::ReceivedGrantZprAddressRequest(Ok(vec![
                        zpr_utils::net_defs::IpAddress::new_from_std(&configured),
                    ])),
                )
                .unwrap();

                let peer = asm.peer_table.get(link_id).unwrap();
                assert_eq!(peer.link_state_machine.get_state(), LinkState::Active);
                assert!(
                    routes
                        .lock()
                        .unwrap()
                        .contains(&(IpAddr::V6(ZPR_INTERNAL_NETWORK), ZPRNET_PREFIX_LEN)),
                    "activation on the static-address path must install the ZPR \
                     internal-network route {ZPR_INTERNAL_NETWORK}/{ZPRNET_PREFIX_LEN} \
                     on the TUN; recorded routes: {:?}",
                    routes.lock().unwrap()
                );
            })
            .await
    }

    /// zipline#88 (Q2, fail-fast leg): on a *dynamic* grant the adapter's
    /// reachability rides entirely on fabric-installed state — nothing was
    /// provisioned out of band — so a failed route install means the link
    /// cannot do its job and must fail activation ASAP, exactly like a
    /// failed `add_address`.
    #[tokio::test(start_paused = true)]
    async fn test_dynamic_grant_route_install_failure_is_fatal() {
        LocalSet::new()
            .run_until(async {
                let granted: IpAddr = "fd5a:5052:adda:1::42".parse().unwrap();

                let (tun_ctl, _routes) = crate::assembly::test::RecordingTunCtl::new(true);
                let mut builder = TestAssemblyBuilder::new();
                builder.tun_ctl = Some(Box::new(tun_ctl));
                let asm = Arc::new(create_assembly(builder));
                let link_id = add_adapter_peer(&asm);
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.link_state_machine
                        .test_set_state(LinkState::RegisterAA);
                }

                asm.process_link_state_event(
                    link_id,
                    LinkEvent::ReceivedGrantZprAddressRequest(Ok(vec![
                        zpr_utils::net_defs::IpAddress::new_from_std(&granted),
                    ])),
                )
                .unwrap();

                let peer = asm.peer_table.get(link_id).unwrap();
                let state = peer.link_state_machine.get_state();
                assert!(
                    matches!(state, LinkState::Error | LinkState::Closing),
                    "a failed internal-net route install on a dynamic grant \
                     must fail the activation (like a failed add_address); \
                     expected Error (or the close it initiates), got {state:?}"
                );
            })
            .await
    }

    /// zipline#88 (Q2, warn-and-continue leg): on the static-address path
    /// the deployment provisioned the TUN's addressing and routes out of
    /// band (and functioned that way before this route existed), so a failed
    /// route install is a warning, not a reason to refuse a link that may
    /// work.
    #[tokio::test(start_paused = true)]
    async fn test_static_grant_route_install_failure_warns_and_continues() {
        LocalSet::new()
            .run_until(async {
                let configured: IpAddr = "fd00:1:2::1".parse().unwrap();

                let (tun_ctl, _routes) = crate::assembly::test::RecordingTunCtl::new(true);
                let mut builder = TestAssemblyBuilder::new();
                let mut cfg = <crate::config::Config as std::default::Default>::default();
                cfg.zpr_addr = vec![configured];
                builder.config = Some(rcu::RcuBox::new(cfg));
                builder.tun_ctl = Some(Box::new(tun_ctl));
                let asm = Arc::new(create_assembly(builder));
                let link_id = add_adapter_peer(&asm);
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.link_state_machine
                        .test_set_state(LinkState::RegisterAA);
                }

                asm.process_link_state_event(
                    link_id,
                    LinkEvent::ReceivedGrantZprAddressRequest(Ok(vec![
                        zpr_utils::net_defs::IpAddress::new_from_std(&configured),
                    ])),
                )
                .unwrap();

                let peer = asm.peer_table.get(link_id).unwrap();
                assert_eq!(
                    peer.link_state_machine.get_state(),
                    LinkState::Active,
                    "a statically-provisioned adapter must activate even when \
                     the internal-net route install fails (warn and continue)"
                );
                assert_eq!(asm.get_fatal_error(), None);
            })
            .await
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_test() {
        LocalSet::new()
            .run_until(async {
                let sm = Arc::new(Mutex::new(LinkStateMachine::new(1)));
                let (tx, rx) = oneshot::channel();

                set_timeout(&sm, Duration::from_secs(5), tx);

                tokio::time::sleep(Duration::from_secs(4)).await;

                assert!(rx.is_empty());

                tokio::time::sleep(Duration::from_secs(2)).await;

                assert!(rx.await.is_ok());
            })
            .await
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_explicit_cancel_test() {
        LocalSet::new()
            .run_until(async {
                let sm = Arc::new(Mutex::new(LinkStateMachine::new(1)));
                let (tx, rx) = oneshot::channel();

                set_timeout(&sm, Duration::from_secs(5), tx);

                tokio::time::sleep(Duration::from_secs(4)).await;

                sm.lock().unwrap().cancel_timeout();

                tokio::time::sleep(Duration::from_secs(2)).await;

                assert!(rx.await.is_err());
            })
            .await
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_implicit_cancel_test() {
        LocalSet::new()
            .run_until(async {
                let sm = Arc::new(Mutex::new(LinkStateMachine::new(1)));
                let (tx, rx) = oneshot::channel();

                set_timeout(&sm, Duration::from_secs(5), tx);

                tokio::time::sleep(Duration::from_secs(4)).await;

                sm.lock().unwrap().set_state(LinkState::Keying);

                tokio::time::sleep(Duration::from_secs(2)).await;

                assert!(rx.await.is_err());
            })
            .await
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_reschedule_test() {
        LocalSet::new()
            .run_until(async {
                let sm = Arc::new(Mutex::new(LinkStateMachine::new(1)));
                let (tx1, rx1) = oneshot::channel();
                let (tx2, rx2) = oneshot::channel();

                set_timeout(&sm, Duration::from_secs(5), tx1);

                tokio::time::sleep(Duration::from_secs(4)).await;

                set_timeout(&sm, Duration::from_secs(5), tx2);

                tokio::time::sleep(Duration::from_secs(4)).await;

                assert!(rx1.await.is_err());
                assert!(rx2.is_empty());

                tokio::time::sleep(Duration::from_secs(2)).await;

                assert!(rx2.await.is_ok());
            })
            .await
    }

    fn set_timeout(sm: &Arc<Mutex<LinkStateMachine>>, duration: Duration, tx: oneshot::Sender<()>) {
        let sm_cb = sm.clone();
        sm.lock()
            .unwrap()
            .set_timeout_callback(duration, move |lc| {
                if sm_cb.lock().unwrap().logical_clock != lc {
                    return;
                }
                tx.send(()).unwrap();
            });
    }
}
