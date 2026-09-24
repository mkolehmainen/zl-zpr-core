use crate::adapter_tables;
use crate::address_pool::AddressPool;
use crate::capture_worker::CaptureWorker;
use crate::counters::*;
use crate::flow_control::FlowControl;
use crate::km_cert_exchange::KmCertExchange;
use crate::km_multiplexor::KmState;
use crate::km_noise;
use crate::link_state::{LinkEvent, LinkStateError, LinkType};
use crate::mgmt;
use crate::mgmt_processor_worker;
use crate::peer_table;
use crate::peer_table::PeerInsertError;
use crate::prelude::*;
use crate::queues::*;
use crate::special_peers::SpecialPeerName;
use crate::tun_ctl::TunCtl;
use crate::visa_table;
use crate::zdp::TerminateReason;
use crate::zdpr_worker;
use km_noise::NoiseKeypair;
use rcu;
use std::collections::HashMap;
use std::fmt::{Error, Formatter};
use std::net::IpAddr;
use std::num::NonZero;
use std::result::Result;
use std::sync::{Arc, Mutex};
use tracing_subscriber::filter::targets::Targets;
#[allow(unused_imports)]
use tracing_subscriber::{Layer, Registry, filter, fmt, reload};
use x25519_dalek::ReusableSecret;
use zpr::vsapi_types::{AuthServicesList, ConnectRequest};
use zpr_utils::net_defs::{IpAddress, ScopedIpAddr};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PhMode {
    Node,
    Adapter,
}

/// The build-identity string reported by this assembly, e.g. on the
/// mgmt-channel version TLV: `<pkg-version> (<git describe>)` (zipline#64).
pub const VERSION: &'static str = build_info::BUILD_VERSION;

/// Interface to full assembly of all stages.
///
/// This is the "public interface" that all stages of the system use to talk
/// to each other (via queues), and to shared resources (e.g. the buffer stack).
///
/// All queues and shared resources here should be bounded, so that
/// backpressure can flow from any processing stage all the way back to the
/// kernel network ingest queues, and that service time of any packet
/// transiting the system is not permitted to grow indefinitely under
/// pressure.
///
/// The intention is that there are no hidden unbounded queues in the system
/// (such as a mutex held over a blocking operation).  If a resource is
/// highly contended resulting in a bottleneck, that should result in some
/// visible queue becoming full.

pub struct Assembly {
    pub ph_mode: PhMode,
    pub topology_config: config::TopologyConfig,

    pub mgmt_substrate_egress: MgmtSubstrateEgress,
    pub actor_output_requeue: ActorOutputRequeue,

    pub vsconn: Option<libnode::vsconn::VSConnHandle>, // present only on nodes
    pub vs_auth_services: std::sync::RwLock<AuthServicesList>, // present only on nodes, may be empty, managed by visa service
    pub deferred_vs_connect: Mutex<Option<(LinkId, IpAddress, ConnectRequest)>>, // present only on nodes, the VS adapter's connect request and self-granted address, held until the node has VSAPI access

    pub visa_table: std::sync::RwLock<visa_table::VisaTable>, // Only for nodes

    // Used to intercept packets that are unencrypted but still have ZDP headers
    pub capture_queue: Capture,
    pub capture_worker: CaptureWorker,
    pub flow_control: FlowControl,

    pub counters: Counters,

    pub tun_ctl: Box<dyn TunCtl + Send>,

    pub peer_table: peer_table::PeerTable,

    // Adapter tables
    pub elt: adapter_tables::EndpointLookupTable,
    pub dlt: adapter_tables::DockLookupTable,

    pub mgmt_dispatch_factory: MgmtDispatchFactory,
    pub mgmt_hairpin_dispatch: MgmtHairpinDispatch,
    pub adapter_manager_factory: AdapterManagerFactory,
    pub km_state: KmState,

    pub self_noise_keypair: Option<NoiseKeypair>,
    pub a2a_dh_keypair: ReusableSecret,
    pub certx: Option<KmCertExchange>,
    pub system_start_time: std::time::Instant,
    pub address_pool: std::sync::Mutex<Option<AddressPool>>, // Nodes only (and required for nodes)

    /// Note that zpr addressed in config are not our real ZPR addresses until we are granted a ZPR address.
    /// If there is a static ZPR address present in the configuration it is set here in main.
    /// Various get_ and set_ functions are defined for this below.
    pub config: rcu::RcuBox<config::Config>,
    /// The operator-configured ZPR address demand as it stood at startup
    /// (`--zpr-addr` / `zpr_addr`), frozen at construction (zipline#83).
    /// Empty means "accept whatever the fabric assigns". This is what the
    /// granted-address mismatch check compares against — `config.zpr_addr`
    /// cannot be, because [`Self::set_local_zpr_addrs`] overwrites it with
    /// each dynamic grant and teardown never restores the startup value, so
    /// after a reconnect it would mistake the previous dynamic address for
    /// a configured demand.
    pub configured_zpr_addr_demand: Vec<IpAddr>,
    /// A fatal, unrecoverable error signalled from a worker (zipline#83:
    /// the granted-ZPR-address mismatch). Set via
    /// [`Self::signal_fatal_error`]; main watches [`Self::fatal_notify`] and
    /// exits non-zero with this message on stderr.
    pub fatal_error: Mutex<Option<String>>,
    /// Wakes main's fatal-error watcher (see [`Self::signal_fatal_error`]).
    pub fatal_notify: tokio::sync::Notify,
    pub logging: Mutex<HashMap<String, String>>,
    pub reload_handle:
        reload::Handle<filter::Filtered<fmt::Layer<Registry>, Targets, Registry>, Registry>,
}

impl Assembly {
    pub fn get_uptime(&self) -> std::time::Duration {
        std::time::Instant::now().duration_since(self.system_start_time)
    }

    /// Graceful shutdown routine.  Not guaranteed to be called
    pub async fn shutdown(self: &Arc<Self>) {
        match self.ph_mode {
            PhMode::Node => self.shutdown_node().await,
            PhMode::Adapter => self.shutdown_adapter().await,
        }
    }

    // The node quickly sends Terminate Indications
    async fn shutdown_node(self: &Arc<Self>) {
        if matches!(self.ph_mode, PhMode::Node) {
            let mut join_set = tokio::task::JoinSet::new();

            let vs_peer = self
                .peer_table
                .lookup_special_peer(SpecialPeerName::VisaServiceAdapter);

            self.peer_table.for_each(|(peer_id, peer)| {
                if Some(peer_id) != vs_peer && !peer.is_internal() {
                    // This should be a short block and must be blocked on,
                    // otherwise the messages won't get sent
                    let spawn_self = self.clone();
                    join_set.spawn_local(async move { spawn_self.reset_peer(peer_id.get()).await });
                }
            });

            join_set.join_all().await;

            if let Some(vs_peer) = vs_peer {
                self.reset_peer(vs_peer.get()).await;
            }
        }
    }

    // The adapter sends a more policy Terminate Request.
    async fn shutdown_adapter(self: &Arc<Self>) {
        let mut join_set = tokio::task::JoinSet::new();

        self.peer_table.for_each(|(peer_id, peer)| {
            if peer.is_internal() {
                return;
            }

            if let Err(e) = peer
                .link_state_machine
                .process_event(self, LinkEvent::Close(TerminateReason::Shutdown))
            {
                error!(target: PEER_MGMT, "Failed to nicely close peer {}: {e}", self.formatted_link_id(peer_id.get()));
                // So try harder...
                let spawn_self = self.clone();
                join_set.spawn_local(async move { spawn_self.reset_peer(peer_id.get()).await });
            }
        });
        join_set.join_all().await;

        let mut npeers = self.peer_table.len() - 1; // - 1 accounts for local actor
        info!(
            target: PEER_MGMT,
            "Waiting for {} peer{} to disconnect...",
            npeers,
            if npeers == 1 { "" } else { "s" }
        );
        while npeers > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            npeers = self.peer_table.len() - 1; // - 1 accounts for local actor
        }
    }

    /// Disconnect all non-internal, non-vs adapters.
    /// Used in a node context when (for example) we loose all state with the visa service.
    ///
    /// Does not remove visas related to the adapter/peer.
    pub async fn disconnect_adapters(self: &Arc<Self>) {
        if matches!(self.ph_mode, PhMode::Node) {
            let mut join_set = tokio::task::JoinSet::new();
            let vs_peer = self
                .peer_table
                .lookup_special_peer(SpecialPeerName::VisaServiceAdapter);
            self.peer_table.for_each(|(peer_id, peer)| {
                if Some(peer_id) != vs_peer && !peer.is_internal() {
                    // This should be a short block and must be blocked on,
                    // otherwise the messages won't get sent
                    let spawn_self = self.clone();
                    join_set.spawn_local(async move { spawn_self.reset_peer(peer_id.get()).await });
                }
            });
            join_set.join_all().await;
        }
    }

    #[allow(dead_code)]
    pub fn is_link_ready(&self, id: LinkId) -> bool {
        match self.peer_table.get(id) {
            Some(peer) => peer.link_state_machine.is_ready(),
            None => false,
        }
    }

    /// Update the local ZPR addresses of this node or adapter. Though presumably
    /// this is called only on an adapter as a nodes addresses are currently set
    /// through configuration or command line args.
    pub fn set_local_zpr_addrs<T>(&self, addrs: impl IntoIterator<Item = T>)
    where
        T: Into<IpAddr>,
    {
        let addrs: Vec<IpAddr> = addrs.into_iter().map(|a| a.into()).collect();
        self.config
            .update(move |cfg| {
                Some(config::Config {
                    zpr_addr: addrs.clone(),
                    ..cfg.clone()
                })
            })
            .unwrap();
    }

    /// Get a copy of the local ZPR addresses. May be empty on an adapter until we
    /// have been granted a ZPR address.
    pub fn get_local_zpr_addrs_std(&self) -> Vec<IpAddr> {
        self.config.get().zpr_addr.clone()
    }

    /// Record `msg` as a fatal, unrecoverable error and wake main's watcher
    /// (see main.rs): the process exits non-zero with the message on stderr
    /// (zipline#83). The first message wins — a later signal keeps the
    /// original text but still notifies, so main wakes regardless of
    /// ordering.
    pub fn signal_fatal_error(&self, msg: String) {
        {
            let mut fatal = self.fatal_error.lock().unwrap();
            if fatal.is_none() {
                *fatal = Some(msg);
            }
        }
        self.fatal_notify.notify_one();
    }

    /// The recorded fatal error, if any (see [`Self::signal_fatal_error`]).
    pub fn get_fatal_error(&self) -> Option<String> {
        self.fatal_error.lock().unwrap().clone()
    }

    /// Node only: the "dock address" is the first local ZPR address.
    ///
    /// In unlikely event that the node has no local ZPR addresses, this returns the
    /// all zeros IPv6 addr.
    ///
    /// TODO: In the future we may want to keep track of the nodes dock address
    /// in a more static way to avoid taking the read lock since we need this
    /// value on every visa request.
    pub fn get_local_dock_addr(&self) -> IpAddr {
        let lza = &self.config.get().zpr_addr;
        if lza.is_empty() {
            std::net::Ipv6Addr::UNSPECIFIED.into()
        } else {
            lza[0]
        }
    }

    /// Returns the local ZPR addresses which we believe we own but which are
    /// *not* actually configured on the TUN device.  An empty vector means the
    /// TUN device agrees with us.
    ///
    /// ph does not always own the addressing of its TUN device: on Linux an
    /// IPv6 ZPR address cannot be set at device-creation time, so a node's
    /// address is configured out of band and `zpr_addr` merely asserts what is
    /// expected to be there.  When the two disagree nothing fails directly --
    /// the node instead binds services to an address it does not have and
    /// emits packets from a source address it has not claimed -- so callers
    /// use this to turn that silent misconfiguration into a loud one.
    ///
    /// This deliberately reads the *current* address set via
    /// [`Self::get_local_zpr_addrs_std`] rather than the startup
    /// configuration, so it remains correct for an address that is assigned or
    /// reassigned at run time (as an adapter's is today, via
    /// [`Self::set_local_zpr_addrs`]).  Re-run it after any such change.
    ///
    /// Addresses the platform cannot inspect are reported as present: a check
    /// that cannot see the truth must not manufacture a failure.  The same
    /// applies to an unexpected error, which is logged and skipped.
    pub fn local_zpr_addrs_missing_from_tun(&self) -> Vec<IpAddr> {
        self.get_local_zpr_addrs_std()
            .into_iter()
            .filter(|addr| match self.tun_ctl.has_address(*addr) {
                Ok(present) => !present,
                Err(e) if e.kind() == std::io::ErrorKind::Unsupported => false,
                Err(e) => {
                    warn!(target: NET_OS, "cannot determine whether {addr} is configured on the TUN device: {e}");
                    false
                }
            })
            .collect()
    }

    pub fn process_link_state_event(
        self: &Arc<Self>,
        id: LinkId,
        event: LinkEvent,
    ) -> Result<(), LinkStateError> {
        let Some(peer) = self.peer_table.get(id) else {
            return Err(LinkStateError::NotFound(id));
        };
        peer.link_state_machine.process_event(self, event)
    }

    fn add_peer(
        self: &Arc<Self>,
        link_type: LinkType,
        peer_addr: &SubstrateAddr,
        interface_addr: &ScopedIpAddr,
    ) -> Result<NonZero<LinkId>, PeerInsertError> {
        let entry = self.peer_table.vacant_entry()?;

        let worker_config = mgmt_processor_worker::Config {
            link_id: entry.key(),
        };

        let peer_state =
            peer_table::PeerState::new(entry.key(), link_type, *peer_addr, *interface_addr, |q| {
                mgmt_processor_worker::launch(worker_config, self.clone(), q)
            });

        let link_id = entry.insert(peer_state);

        tokio::task::spawn_local(zdpr_worker::launch(self.clone(), link_id.get()));

        Ok(link_id)
    }

    /// Caled from `LinkStateWrapper::complete_close`.`
    /// Also drops visas related to the peer.
    pub fn drop_peer(self: &Arc<Self>, link_id: LinkId) {
        let vs_link_id = self
            .peer_table
            .lookup_special_peer(SpecialPeerName::VisaServiceAdapter);
        if vs_link_id.is_some() && link_id == vs_link_id.unwrap().get() {
            debug!(target: PEER_MGMT, "Removing peer {} [VISA SERVICE]", self.formatted_link_id(link_id));
        } else {
            debug!(target: PEER_MGMT, "Removing peer {}", self.formatted_link_id(link_id));
        }
        if self.ph_mode == PhMode::Node {
            // Revoke visas under the write lock, but hold the withdrawn
            // entries until the lock is released: the send path takes the
            // peer's `zdpr_send` mutex, which must never nest under the
            // visa-table lock (and `unbind_stream` itself re-acquires the
            // visa-table lock, which is why it is not usable here).
            let withdrawn = self
                .visa_table
                .write()
                .unwrap()
                .revoke_for_link(link_id, &self.peer_table);

            // Withdraw each revoked stream from the *surviving* peers so
            // they drop their egress bindings and re-request visas instead
            // of blackholing traffic on dead streams (zipline#21). The
            // dying link's own entries are skipped — that peer is gone.
            self.withdraw_streams(withdrawn, Some(link_id));
        }
        self.peer_table.remove(link_id);
        info!(target: PEER_MGMT, "Removed peer {}", self.formatted_link_id(link_id));
    }

    /// Withdraw the given forwarding entries from the peers still bound to
    /// them by sending each one a `StreamIdWithdrawal` — "the stream id YOU
    /// send with has been withdrawn" — because `entry.1` is the tether id
    /// the receiving adapter holds in its *outbound* ELT, not an id in its
    /// inbound DLT (which is what UnbindEgressStreamIndication's handler
    /// removes from). Shared by `drop_peer` (zipline#21) and
    /// `visa_mgmt::handle_revocation` (zipline#85).
    ///
    /// `excluded_link` names a dying link whose own entries must be skipped
    /// (that peer is gone) — `drop_peer` passes it. Entries whose link has
    /// already left the peer table are skipped as well.
    ///
    /// Lock ordering (zipline#9): call this only AFTER releasing the
    /// visa-table write lock — the send path takes the peer's `zdpr_send`
    /// mutex, which must never nest under it.
    ///
    /// Note the expiry path (`VisaTable::handle_expirations`) deliberately
    /// does not notify: both ends share the visa expiry and eject on their
    /// own clocks, and a peer that sends early gets UnknownStreamId and
    /// re-requests.
    pub(crate) fn withdraw_streams(
        &self,
        withdrawn: Vec<ForwardingEntry>,
        excluded_link: Option<LinkId>,
    ) {
        for entry in withdrawn {
            if Some(entry.0) == excluded_link || self.peer_table.get(entry.0).is_none() {
                continue;
            }
            mgmt::requests::send_stream_id_withdrawal(self, entry.0, entry.1).enqueue();
        }
    }

    /// Part of graceful shutdown (or administrative link shutdown).
    ///
    /// Reset peer at given link.
    ///
    /// Calls down to `LinkStateWrapper::reset` which will ultimately end up calling back
    /// here to [Assembly::drop_peer].
    pub async fn reset_peer(self: &Arc<Self>, link_id: LinkId) {
        let vs_link_id = self
            .peer_table
            .lookup_special_peer(SpecialPeerName::VisaServiceAdapter);
        if vs_link_id.is_some() && link_id == vs_link_id.unwrap().get() {
            if let Some(vsconn) = self.vsconn.as_ref() {
                if let Err(e) = vsconn.stop(true).await {
                    error!(target: PEER_MGMT, "stop command to VSConn failed: {e}");
                } else {
                    // Let VSConn runloop process/send the command.
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            }
        }
        if let Some(peer) = self.peer_table.get(link_id) {
            peer.link_state_machine.reset(self).await;
        }
    }

    /// Add a tether to the peer table.
    ///
    /// `auto_start` controls whether the link starts (fires
    /// `LinkEvent::Start`, Inactive -> Keying) immediately. Adapters started
    /// with `--auto-connect=false` pass `false` (zipline#28): the peer is
    /// still created — so ph-cli has a link to target — but it idles in
    /// Inactive until a `startLink` RPC wakes it. Everything else passes
    /// `true`, today's behaviour.
    pub fn start_tether(
        self: &Arc<Self>,
        adapter_addr: &SubstrateAddr,
        interface_addr: &ScopedIpAddr,
        link_type: LinkType,
        auto_start: bool,
    ) -> Result<NonZero<LinkId>, PeerInsertError> {
        assert!(matches!(
            link_type,
            LinkType::NodeToAdapter | LinkType::AdapterToNode
        ));
        debug!(target: PEER_MGMT, "Starting tether with {adapter_addr} connected to {interface_addr}");
        let peer_id = self.add_peer(link_type, adapter_addr, interface_addr)?;

        let Some(peer) = self.peer_table.get(peer_id.get()) else {
            // Peer is gone already
            return Ok(peer_id);
        };

        if !auto_start {
            info!(target: PEER_MGMT, "Tether with {adapter_addr} created idle (auto-connect off).  Assigned ID {}", self.formatted_link_id(peer_id.get()));
            return Ok(peer_id);
        }

        if let Err(e) = peer
            .link_state_machine
            .process_event(self, LinkEvent::Start)
        {
            error!(target: PEER_MGMT, "{} failed to start with error {e}.  Resetting", self.formatted_link_id(peer_id.get()));
            peer.link_state_machine
                .process_event(self, LinkEvent::Error)
                .expect("This shouldn't error!");
            return Err(PeerInsertError::FailedToStart(e.to_string()));
        } else {
            info!(target: PEER_MGMT, "Successfully started tether with {adapter_addr}.  Assigned ID {}", self.formatted_link_id(peer_id.get()));
        }

        return Ok(peer_id);
    }

    /// Temporary? function to find a link based on the actor address
    pub fn find_egress_link(&self, actor_addr: IpAddress) -> Option<NonZero<LinkId>> {
        // First check the local actor addresses to see if it's a locally-destined packet
        if self
            .config
            .get()
            .zpr_addr
            .iter()
            .any(|addr| IpAddress::new_from_std(addr) == actor_addr)
        {
            return Some(NonZero::new(LOCAL_ACTOR_LINK_ID).unwrap());
        }

        // Check peer actor addresses to see if one of them matches
        self.peer_table
            .find(|(_id, peer)| {
                peer.link_state_machine
                    .get_actor_addresses()
                    .iter()
                    .any(|addr| *addr == actor_addr)
            })
            .map(|(id, _peer)| id)
    }

    // Formats link IDs for display purposes
    pub fn format_link_id(&self, link_id: LinkId, f: &mut Formatter<'_>) -> Result<(), Error> {
        match link_id {
            0 => f.write_str("unknown link")?,
            1 => f.write_str("adapter link")?,
            2 => f.write_str("dock link")?,
            _ => write!(f, "link {}", link_id)?,
        }
        Ok(())
    }

    /// Returns a formatted string for the given link ID
    pub fn formatted_link_id(&self, link_id: LinkId) -> impl std::fmt::Display {
        std::fmt::from_fn(move |f| self.format_link_id(link_id, f))
    }
}

#[cfg(test)]
pub mod test {

    use super::*;
    use crate::config::TopologyConfig;
    use crate::packet_queue;
    use crate::two_way_queue;
    use tokio::sync::mpsc;

    #[allow(dead_code)]
    #[derive(Default)]
    pub struct TestAssemblyBuilder {
        pub ph_mode: Option<PhMode>,
        pub topology_config: Option<TopologyConfig>,
        pub local_zpr_addresses: Option<Vec<IpAddr>>,
        pub mgmt_substrate_egress: Option<MgmtSubstrateEgress>,
        pub actor_output_requeue: Option<ActorOutputRequeue>,
        pub vsconn: Option<Option<libnode::vsconn::VSConnHandle>>,
        pub visa_table: Option<visa_table::VisaTable>,
        pub capture_queue: Option<Capture>,
        pub capture_worker: Option<CaptureWorker>,
        pub flow_control: Option<FlowControl>,
        pub counters: Option<Counters>,
        pub tun_ctl: Option<Box<dyn TunCtl + Send>>,
        pub peer_table: Option<peer_table::PeerTable>,
        pub elt: Option<adapter_tables::EndpointLookupTable>,
        pub dlt: Option<adapter_tables::DockLookupTable>,
        pub mgmt_dispatch_factory: Option<MgmtDispatchFactory>,
        pub mgmt_hairpin_dispatch: Option<MgmtHairpinDispatch>,
        pub adapter_manager_factory: Option<AdapterManagerFactory>,
        pub km_state: Option<KmState>,
        pub self_noise_keypair: Option<crate::km_noise::NoiseKeypair>,
        pub certx: Option<crate::km_cert_exchange::KmCertExchange>,
        pub system_start_time: Option<std::time::Instant>,
        pub config: Option<rcu::RcuBox<config::Config>>,
        pub logging: Option<Mutex<HashMap<String, String>>>,
        pub reload_handle: Option<
            reload::Handle<filter::Filtered<fmt::Layer<Registry>, Targets, Registry>, Registry>,
        >,
    }

    #[allow(dead_code)]
    struct DummyTunCtlImpl;
    impl TunCtl for DummyTunCtlImpl {
        fn set_carrier(&self, _carrier: bool) -> std::io::Result<()> {
            Ok(())
        }
        fn add_address(&self, _addr: IpAddr, _prefix_len: u8) -> std::io::Result<()> {
            Ok(())
        }
        fn clear_address(&self, _addr: IpAddr, _prefix_len: u8) -> std::io::Result<()> {
            Ok(())
        }
        fn has_address(&self, _addr: IpAddr) -> std::io::Result<bool> {
            Ok(true)
        }
        fn add_route(&self, _dest: IpAddr, _prefix_len: u8) -> std::io::Result<()> {
            Ok(())
        }
        fn route_owner_conflict(
            &self,
            _dest: IpAddr,
            _prefix_len: u8,
        ) -> std::io::Result<Option<String>> {
            Ok(None)
        }
    }

    /// A `TunCtl` which reports exactly the addresses it was constructed with,
    /// so tests can model a TUN device that disagrees with our configuration.
    struct FakeTunCtl {
        addresses: Vec<IpAddr>,
    }

    impl TunCtl for FakeTunCtl {
        fn set_carrier(&self, _carrier: bool) -> std::io::Result<()> {
            Ok(())
        }
        fn add_address(&self, _addr: IpAddr, _prefix_len: u8) -> std::io::Result<()> {
            Ok(())
        }
        fn clear_address(&self, _addr: IpAddr, _prefix_len: u8) -> std::io::Result<()> {
            Ok(())
        }
        fn has_address(&self, addr: IpAddr) -> std::io::Result<bool> {
            Ok(self.addresses.contains(&addr))
        }
        fn add_route(&self, _dest: IpAddr, _prefix_len: u8) -> std::io::Result<()> {
            Ok(())
        }
        fn route_owner_conflict(
            &self,
            _dest: IpAddr,
            _prefix_len: u8,
        ) -> std::io::Result<Option<String>> {
            Ok(None)
        }
    }

    /// A `TunCtl` recording every `add_route` call, so tests can assert the
    /// link-activation route install (zipline#88). With `fail_routes` set,
    /// `add_route` fails instead, modelling a TUN whose routing table cannot
    /// be updated — the fail-fast/warn-and-continue split's test double.
    /// With `conflict` set, `route_owner_conflict` reports that interface
    /// as the live owner of the queried route (zipline#101).
    pub struct RecordingTunCtl {
        pub routes: Arc<std::sync::Mutex<Vec<(IpAddr, u8)>>>,
        pub fail_routes: bool,
        pub conflict: Option<String>,
    }

    impl RecordingTunCtl {
        /// A recording instance plus the shared log the test asserts on.
        pub fn new(fail_routes: bool) -> (Self, Arc<std::sync::Mutex<Vec<(IpAddr, u8)>>>) {
            let routes = Arc::new(std::sync::Mutex::new(Vec::new()));
            (
                Self {
                    routes: routes.clone(),
                    fail_routes,
                    conflict: None,
                },
                routes,
            )
        }

        /// A recording instance whose `route_owner_conflict` names
        /// `owner_if` as the conflicting live owner (zipline#101).
        pub fn with_conflict(owner_if: &str) -> (Self, Arc<std::sync::Mutex<Vec<(IpAddr, u8)>>>) {
            let (mut tun_ctl, routes) = Self::new(false);
            tun_ctl.conflict = Some(owner_if.to_string());
            (tun_ctl, routes)
        }
    }

    impl TunCtl for RecordingTunCtl {
        fn set_carrier(&self, _carrier: bool) -> std::io::Result<()> {
            Ok(())
        }
        fn add_address(&self, _addr: IpAddr, _prefix_len: u8) -> std::io::Result<()> {
            Ok(())
        }
        fn clear_address(&self, _addr: IpAddr, _prefix_len: u8) -> std::io::Result<()> {
            Ok(())
        }
        fn has_address(&self, _addr: IpAddr) -> std::io::Result<bool> {
            Ok(true)
        }
        fn add_route(&self, dest: IpAddr, prefix_len: u8) -> std::io::Result<()> {
            if self.fail_routes {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "RecordingTunCtl: add_route deliberately failing",
                ));
            }
            self.routes.lock().unwrap().push((dest, prefix_len));
            Ok(())
        }
        fn route_owner_conflict(
            &self,
            _dest: IpAddr,
            _prefix_len: u8,
        ) -> std::io::Result<Option<String>> {
            Ok(self.conflict.clone())
        }
    }

    /// Builds a test assembly whose local ZPR addresses are `zpr_addr` and
    /// whose TUN device carries `on_tun`.
    fn assembly_with_addrs(zpr_addr: &[&str], on_tun: &[&str]) -> Assembly {
        let parse = |v: &[&str]| -> Vec<IpAddr> { v.iter().map(|a| a.parse().unwrap()).collect() };
        let config = config::Config {
            zpr_addr: parse(zpr_addr),
            ..Default::default()
        };
        create_assembly(TestAssemblyBuilder {
            ph_mode: Some(PhMode::Node),
            config: Some(rcu::RcuBox::new(config)),
            tun_ctl: Some(Box::new(FakeTunCtl {
                addresses: parse(on_tun),
            })),
            ..Default::default()
        })
    }

    /// Regression test for a node configured with `fd5a:5052:90de::1` while its
    /// TUN device actually carried `fd5a:5052:90de::2`.  The node bound its VSS
    /// listener to an address it did not have and sourced visa-service traffic
    /// from an address it had not claimed, which its own bind check then denied
    /// -- with no indication of why.
    #[test]
    fn detects_local_zpr_addr_absent_from_tun() {
        let asm = assembly_with_addrs(&["fd5a:5052:90de::1"], &["fd5a:5052:90de::2"]);
        assert_eq!(
            asm.local_zpr_addrs_missing_from_tun(),
            vec!["fd5a:5052:90de::1".parse::<IpAddr>().unwrap()]
        );
    }

    /// A TUN device carrying the configured address (among others) is not a
    /// mismatch.
    #[test]
    fn accepts_local_zpr_addr_present_on_tun() {
        let asm = assembly_with_addrs(&["fd5a:5052:90de::1"], &["fd5a:5052:90de::1", "fe80::1"]);
        assert!(asm.local_zpr_addrs_missing_from_tun().is_empty());
    }

    /// Every configured address must be present, not just the first.
    #[test]
    fn detects_partially_configured_local_zpr_addrs() {
        let asm = assembly_with_addrs(
            &["fd5a:5052:90de::1", "fd5a:5052:90de::7"],
            &["fd5a:5052:90de::1"],
        );
        assert_eq!(
            asm.local_zpr_addrs_missing_from_tun(),
            vec!["fd5a:5052:90de::7".parse::<IpAddr>().unwrap()]
        );
    }

    /// An adapter which has not yet been granted an address has nothing to
    /// check, and must not be reported as misconfigured.
    #[test]
    fn no_local_zpr_addrs_is_not_a_mismatch() {
        let asm = assembly_with_addrs(&[], &["fd5a:5052:90de::2"]);
        assert!(asm.local_zpr_addrs_missing_from_tun().is_empty());
    }

    impl TestAssemblyBuilder {
        pub fn new() -> Self {
            Self::default()
        }
    }

    /// Test assembly able to key an AdapterToNode link: `process_start`
    /// hands the link to the key manager, which needs a noise keypair and a
    /// certificate exchange.
    fn keyable_adapter_assembly() -> Arc<Assembly> {
        let mut builder = TestAssemblyBuilder::new();
        builder.self_noise_keypair = Some(crate::km_noise::NoiseKeypair::generate());
        builder.certx = Some(crate::km_cert_exchange::KmCertExchange::new(None, None));
        Arc::new(create_assembly(builder))
    }

    fn tether_addrs() -> (SubstrateAddr, ScopedIpAddr) {
        (
            SubstrateAddr::from(([127, 0, 0, 1], 9000)),
            ScopedIpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2).into()),
        )
    }

    /// `start_tether` with `auto_start = false` (zipline#28: adapter started
    /// with `--auto-connect=false`) must create the tether peer — so ph-cli
    /// has a link to target — but leave it Inactive: no keying, no auth
    /// attempt. The `LinkEvent::Start` that the `startLink` RPC fires must
    /// then wake it into Keying, exactly like a restarted link.
    #[tokio::test]
    async fn test_start_tether_without_auto_start_idles_until_start_event() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let asm = keyable_adapter_assembly();
                // Mirror main.rs adapter startup: local actor peer first, so
                // the tether lands at DOCK_LINK_ID.
                assert_eq!(
                    asm.peer_table.insert_internal_peer().get(),
                    zpr::packet_info::LOCAL_ACTOR_LINK_ID
                );
                let (peer_sa, if_addr) = tether_addrs();
                let dsid = asm
                    .start_tether(&peer_sa, &if_addr, LinkType::AdapterToNode, false)
                    .unwrap();
                assert_eq!(dsid.get(), zpr::packet_info::DOCK_LINK_ID);

                let peer = asm.peer_table.get(dsid.get()).unwrap();
                assert_eq!(
                    peer.link_state_machine.get_state(),
                    crate::link_state::LinkState::Inactive,
                    "idle-mode tether must stay Inactive at startup"
                );

                // What admin_worker::start_link fires on `ph-cli connect`.
                asm.process_link_state_event(dsid.get(), LinkEvent::Start)
                    .unwrap();
                assert_eq!(
                    asm.peer_table
                        .get(dsid.get())
                        .unwrap()
                        .link_state_machine
                        .get_state(),
                    crate::link_state::LinkState::Keying,
                    "startLink must wake the idle tether"
                );
            })
            .await
    }

    /// `auto_start = true` is today's behaviour: the tether starts keying
    /// immediately.
    #[tokio::test]
    async fn test_start_tether_with_auto_start_keys_immediately() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let asm = keyable_adapter_assembly();
                let (peer_sa, if_addr) = tether_addrs();
                let dsid = asm
                    .start_tether(&peer_sa, &if_addr, LinkType::AdapterToNode, true)
                    .unwrap();
                assert_eq!(
                    asm.peer_table
                        .get(dsid.get())
                        .unwrap()
                        .link_state_machine
                        .get_state(),
                    crate::link_state::LinkState::Keying
                );
            })
            .await
    }

    pub fn create_assembly(builder: TestAssemblyBuilder) -> Assembly {
        let ph_mode = builder.ph_mode.unwrap_or(PhMode::Adapter);
        let topology_config = builder.topology_config.unwrap_or_default();
        let mgmt_substrate_egress = builder
            .mgmt_substrate_egress
            .unwrap_or_else(|| MgmtSubstrateEgress::new(packet_queue::packet_queue(1).0));
        let actor_output_requeue = builder
            .actor_output_requeue
            .unwrap_or_else(|| ActorOutputRequeue::new(Vec::new()));
        let vsconn = builder.vsconn.unwrap_or(None);
        let visa_table = std::sync::RwLock::new(
            builder
                .visa_table
                .unwrap_or_else(|| visa_table::VisaTable::new()),
        );
        let capture_queue = builder.capture_queue.unwrap_or_else(|| {
            let (cq_inq, _cq_outq) = std::os::unix::net::UnixDatagram::pair().unwrap();
            Capture::new(cq_inq)
        });
        let capture_worker = builder
            .capture_worker
            .unwrap_or_else(|| CaptureWorker::new());
        let flow_control = builder.flow_control.unwrap_or_else(|| FlowControl::new());
        let counters = builder.counters.unwrap_or_default();
        let tun_ctl = builder.tun_ctl.unwrap_or_else(|| Box::new(DummyTunCtlImpl));
        let peer_table = builder
            .peer_table
            .unwrap_or_else(|| peer_table::PeerTable::new());
        let elt = builder
            .elt
            .unwrap_or_else(|| adapter_tables::EndpointLookupTable::new());
        let dlt = builder
            .dlt
            .unwrap_or_else(|| adapter_tables::DockLookupTable::new());
        let mgmt_dispatch_factory = builder.mgmt_dispatch_factory.unwrap_or_else(|| {
            let (md_inq_factory, _md_outq) = two_way_queue::two_way_queue(1);
            MgmtDispatchFactory::new(md_inq_factory)
        });
        let mgmt_hairpin_dispatch = builder.mgmt_hairpin_dispatch.unwrap_or_else(|| {
            let (mhd_inq, _mhd_outq) = mpsc::channel(1);
            MgmtHairpinDispatch::new(mhd_inq)
        });
        let adapter_manager_factory = builder.adapter_manager_factory.unwrap_or_else(|| {
            let (am_inq_factory, _am_outq) = two_way_queue::two_way_queue(1);
            AdapterManagerFactory::new(am_inq_factory)
        });
        let km_state = builder.km_state.unwrap_or_else(|| {
            let (km_sig_tx, _km_sig_rx) = mpsc::channel(1);
            let (km_tx, _km_rx) = mpsc::channel(1);
            KmState::new(km_tx, km_sig_tx)
        });
        let config = builder.config.unwrap_or_else(|| {
            let config = <config::Config as std::default::Default>::default();
            rcu::RcuBox::new(config)
        });
        let configured_zpr_addr_demand = config.get().zpr_addr.clone();
        let logging = builder
            .logging
            .unwrap_or_else(|| Mutex::new(HashMap::default()));
        let reload_handle = builder.reload_handle.unwrap_or_else(|| {
            let (_reload_layer, reload_handle) =
                reload::Layer::new(fmt::layer().with_filter(Targets::new()));
            reload_handle
        });

        Assembly {
            ph_mode,
            topology_config,
            mgmt_substrate_egress,
            actor_output_requeue,
            vsconn,
            visa_table,
            vs_auth_services: std::sync::RwLock::new(AuthServicesList::default()),
            deferred_vs_connect: Mutex::new(None),
            capture_queue,
            capture_worker,
            flow_control,
            counters,
            tun_ctl,
            peer_table,
            elt,
            dlt,
            mgmt_dispatch_factory,
            mgmt_hairpin_dispatch,
            adapter_manager_factory,
            km_state,
            self_noise_keypair: builder.self_noise_keypair,
            a2a_dh_keypair: ReusableSecret::random(),
            certx: builder.certx,
            system_start_time: std::time::Instant::now(),
            address_pool: std::sync::Mutex::new(None),
            configured_zpr_addr_demand,
            config,
            fatal_error: Mutex::new(None),
            fatal_notify: tokio::sync::Notify::new(),
            logging,
            reload_handle,
        }
    }

    mod drop_peer_notify {
        //! Tests for zipline#21: revoking visas for a dying link must
        //! withdraw the streams from *surviving* peers by sending them an
        //! `UnbindEgressStreamIndication`; expiry deliberately does not.

        use super::*;
        use crate::forwarding_tables::PftPep;
        use crate::packet_queue;
        use crate::peer_table::test::create_dummy_peer_state;
        use crate::visa_table::VisaTable;
        use crate::visa_table::tests::new_vsapi_visa_tcp_default;
        use crate::zdp;
        use chrono::{DateTime, Utc};
        use std::net::Ipv4Addr;
        use zpr_utils::net_defs;

        /// Build a Node-mode assembly whose mgmt substrate egress queue we
        /// can read back, plus two dummy peers, and one visa (id >=
        /// MIN_VISA_ID) with forwarding entries on both links.
        ///
        /// Returns (asm, egress queue receiver, link_a, link_b, tether_a, tether_b).
        fn setup_two_link_visa() -> (
            Arc<Assembly>,
            packet_queue::Receiver<{ config::PACKET_BUFFER_SIZE }>,
            LinkId,
            LinkId,
            StreamId,
            StreamId,
        ) {
            let (egress_tx, egress_rx) = packet_queue::packet_queue(8);

            let mut builder = TestAssemblyBuilder::new();
            builder.ph_mode = Some(PhMode::Node);
            builder.visa_table = Some(VisaTable::new());
            builder.mgmt_substrate_egress = Some(MgmtSubstrateEgress::new(egress_tx));
            let asm = Arc::new(create_assembly(builder));

            let entry_a = asm.peer_table.vacant_entry().unwrap();
            let key_a = entry_a.key();
            let link_a = entry_a
                .insert(create_dummy_peer_state(
                    key_a,
                    LinkType::Internal,
                    SubstrateAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443),
                    net_defs::ScopedIpAddr::V4(Ipv4Addr::new(1, 2, 3, 5)),
                ))
                .get();

            let entry_b = asm.peer_table.vacant_entry().unwrap();
            let key_b = entry_b.key();
            let link_b = entry_b
                .insert(create_dummy_peer_state(
                    key_b,
                    LinkType::Internal,
                    SubstrateAddr::new(IpAddr::V4(Ipv4Addr::new(2, 2, 3, 4)), 443),
                    net_defs::ScopedIpAddr::V4(Ipv4Addr::new(2, 2, 3, 5)),
                ))
                .get();

            let visa_id = 3000;
            let mut visa_table = asm.visa_table.write().unwrap();
            let v = new_vsapi_visa_tcp_default(visa_id as u64, DateTime::<Utc>::MAX_UTC.into());
            let _ = visa_table.insert_visa(v);

            let peer_a = asm.peer_table.get(link_a).unwrap();
            let tether_a = peer_a
                .pft
                .insert(PftPep {
                    next_hop: ForwardingEntry(link_a, 1),
                    visa_id,
                })
                .unwrap();
            visa_table
                .link_forwarding_entry(visa_id, ForwardingEntry(link_a, tether_a))
                .unwrap();

            let peer_b = asm.peer_table.get(link_b).unwrap();
            let tether_b = peer_b
                .pft
                .insert(PftPep {
                    next_hop: ForwardingEntry(link_b, 1),
                    visa_id,
                })
                .unwrap();
            visa_table
                .link_forwarding_entry(visa_id, ForwardingEntry(link_b, tether_b))
                .unwrap();

            drop(visa_table);
            drop(peer_a);
            drop(peer_b);

            (asm, egress_rx, link_a, link_b, tether_a, tether_b)
        }

        fn try_recv_packet(
            rx: &mut packet_queue::Receiver<{ config::PACKET_BUFFER_SIZE }>,
        ) -> Option<crate::packet::Packet> {
            let buf = vec![0u8; config::PACKET_BUFFER_SIZE].into_boxed_slice();
            match rx.try_recv(buf) {
                Ok(pkt) => Some(pkt),
                Err(packet_queue::TryRecvError::Empty(_)) => None,
                Err(err) => panic!("unexpected queue error: {err:?}"),
            }
        }

        /// Dropping a peer must send `StreamIdWithdrawal` for each withdrawn
        /// forwarding entry on a *surviving* link — naming the stream id
        /// (PFT tether id) that surviving peer sends with — and nothing for
        /// entries on the dying link itself. StreamIdWithdrawal (not
        /// UnbindEgressStreamIndication) because the id lives in the
        /// receiving adapter's *outbound* ELT, keyed by tether id, not in
        /// its inbound DLT (zipline#21).
        #[tokio::test]
        async fn test_drop_peer_sends_stream_id_withdrawal_to_surviving_peer() {
            let (asm, mut egress_rx, link_a, link_b, _tether_a, tether_b) = setup_two_link_visa();

            asm.drop_peer(link_a);

            let pkt = try_recv_packet(&mut egress_rx)
                .expect("expected a StreamIdWithdrawal for the surviving peer");
            assert_eq!(pkt.metadata().egress_link_id, link_b);

            let (base_hdr, rest) = zdp::ZdpBaseHeader::ref_from_prefix(pkt.body()).unwrap();
            let packet_type = base_hdr.packet_type;
            assert_eq!(packet_type, zdp::ZdpPacketType::StreamIdWithdrawal);

            let (_mgmt_hdr, rest) = zdp::ZdpMgmtHeader::ref_from_prefix(rest).unwrap();
            let (per_flow_hdr, _rest) = zdp::ZdpPerFlowHeader::ref_from_prefix(rest).unwrap();
            let stream_id: u32 = per_flow_hdr.stream_id.into();
            assert_eq!(stream_id, tether_b);

            // Exactly one indication: the entry on the dying link must NOT
            // produce a send (that peer is gone).
            assert!(
                try_recv_packet(&mut egress_rx).is_none(),
                "no indication may be sent for the dying link's own entry"
            );
        }

        /// VS-pushed revocation (`visa_mgmt::handle_revocation`) must send
        /// `StreamIdWithdrawal` to every peer holding a forwarding entry for
        /// the revoked visa — one per live-link entry, each naming that
        /// link's tether id — so bound peers drop their egress bindings and
        /// re-request visas instead of blackholing traffic (zipline#85).
        #[tokio::test]
        async fn test_handle_revocation_sends_stream_id_withdrawal_to_bound_peers() {
            let (asm, mut egress_rx, link_a, link_b, tether_a, tether_b) = setup_two_link_visa();

            // setup_two_link_visa inserts the visa with id 3000.
            crate::visa_mgmt::handle_revocation(&asm, 3000).unwrap();

            let mut got = Vec::new();
            while let Some(pkt) = try_recv_packet(&mut egress_rx) {
                let egress_link = pkt.metadata().egress_link_id;
                let (base_hdr, rest) = zdp::ZdpBaseHeader::ref_from_prefix(pkt.body()).unwrap();
                assert_eq!(
                    base_hdr.packet_type,
                    zdp::ZdpPacketType::StreamIdWithdrawal,
                    "only StreamIdWithdrawal may be enqueued by handle_revocation"
                );
                let (_mgmt_hdr, rest) = zdp::ZdpMgmtHeader::ref_from_prefix(rest).unwrap();
                let (per_flow_hdr, _rest) = zdp::ZdpPerFlowHeader::ref_from_prefix(rest).unwrap();
                let stream_id: u32 = per_flow_hdr.stream_id.into();
                got.push((egress_link, stream_id));
            }
            got.sort_unstable();

            let mut expected = vec![(link_a, tether_a), (link_b, tether_b)];
            expected.sort_unstable();
            assert_eq!(
                got, expected,
                "exactly one StreamIdWithdrawal per live-link forwarding entry, \
                 each naming that link's tether id"
            );
        }

        /// Visa expiry must NOT notify peers: both ends hold the same expiry
        /// and eject on their own clocks; an early-sending peer gets
        /// UnknownStreamId and re-requests, unlike the revocation case.
        #[tokio::test]
        async fn test_handle_expirations_does_not_notify_peers() {
            let (egress_tx, mut egress_rx) = packet_queue::packet_queue(8);

            let mut builder = TestAssemblyBuilder::new();
            builder.ph_mode = Some(PhMode::Node);
            builder.visa_table = Some(VisaTable::new());
            builder.mgmt_substrate_egress = Some(MgmtSubstrateEgress::new(egress_tx));
            let asm = Arc::new(create_assembly(builder));

            let entry = asm.peer_table.vacant_entry().unwrap();
            let key = entry.key();
            let link_id = entry
                .insert(create_dummy_peer_state(
                    key,
                    LinkType::Internal,
                    SubstrateAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443),
                    net_defs::ScopedIpAddr::V4(Ipv4Addr::new(1, 2, 3, 5)),
                ))
                .get();

            let visa_id = 3000;
            let mut visa_table = asm.visa_table.write().unwrap();
            // Already expired
            let v = new_vsapi_visa_tcp_default(visa_id as u64, DateTime::<Utc>::MIN_UTC.into());
            let _ = visa_table.insert_visa(v);

            let peer = asm.peer_table.get(link_id).unwrap();
            let tether_id = peer
                .pft
                .insert(PftPep {
                    next_hop: ForwardingEntry(link_id, 1),
                    visa_id,
                })
                .unwrap();
            visa_table
                .link_forwarding_entry(visa_id, ForwardingEntry(link_id, tether_id))
                .unwrap();

            visa_table.handle_expirations(&asm.peer_table);
            assert!(!visa_table.table.contains_key(&visa_id));
            assert_eq!(peer.pft.len(), 0);
            drop(visa_table);

            assert!(
                try_recv_packet(&mut egress_rx).is_none(),
                "expiry must not emit any unbind indication"
            );
        }
    }
}
