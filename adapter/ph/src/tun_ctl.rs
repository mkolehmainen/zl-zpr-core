use crate::sys::ZprTun;
use std::io::Result;
use std::net::IpAddr;
use std::sync::Arc;

/// This interface provides shared access to the TUN device for controlling
/// its state.  Its API is limited to restrict coupling of the full system
/// with the TUN device.
pub trait TunCtl: Sync {
    /// Inform the kernel's networking layer whether a carrier is present.
    /// (I.e. whether we are passing packets.)  This is reflected on the
    /// interface itself and is used by the kernel to make routing decisions.
    fn set_carrier(&self, carrier: bool) -> Result<()>;

    /// Adds an IP address of the TUN device.
    fn add_address(&self, addr: IpAddr, prefix_len: u8) -> Result<()>;

    /// Clear an IP address from the TUN device.  Does not error if address is not set to begin with.
    fn clear_address(&self, addr: IpAddr, prefix_len: u8) -> Result<()>;

    /// Reports whether `addr` is currently configured on the TUN device.
    ///
    /// Returns an `Unsupported` error for addresses the platform cannot
    /// inspect (currently IPv4 on both Linux and macOS), which callers must
    /// distinguish from a definite "not present".
    fn has_address(&self, addr: IpAddr) -> Result<bool>;

    /// Ensure `dest/prefix_len` is routed on-link via the TUN device.
    ///
    /// Idempotent: installing a route that is already present is not an
    /// error. Used on link activation to give every adapter a return route
    /// covering the whole ZPR internal network, so replies to peers on
    /// fabric-assigned (dynamic-pool) addresses have somewhere to go
    /// (zipline#88).
    fn add_route(&self, dest: IpAddr, prefix_len: u8) -> Result<()>;

    /// Report the name of another **live** interface that already carries
    /// the route for `dest/prefix_len`, if any (zipline#101).
    ///
    /// Only one adapter per host can own the ZPR internal network: a
    /// second adapter whose route loses to another interface docks,
    /// activates, and then silently receives no traffic. `Ok(None)` means
    /// the route is absent, on our own TUN, or (Linux) only on a
    /// `linkdown` interface; `Ok(Some(ifname))` names the conflicting
    /// owner. `Err` means the routing table could not be queried at all —
    /// callers must treat that as "unknown", not as a conflict.
    fn route_owner_conflict(&self, dest: IpAddr, prefix_len: u8) -> Result<Option<String>>;
}

/// Canonical implementation of the `TunCtl` interface, just a thin wrapper
/// around a reference to a `ZprTun` struct.
pub struct TunCtlImpl {
    tun: Arc<ZprTun>,
}

impl TunCtlImpl {
    pub fn new(tun: Arc<ZprTun>) -> Self {
        Self { tun }
    }
}

impl TunCtl for TunCtlImpl {
    fn set_carrier(&self, carrier: bool) -> Result<()> {
        self.tun.set_carrier(carrier)
    }
    fn add_address(&self, addr: IpAddr, prefix_len: u8) -> Result<()> {
        self.tun.add_address(addr, prefix_len)
    }
    fn clear_address(&self, addr: IpAddr, prefix_len: u8) -> Result<()> {
        self.tun.clear_address(addr, prefix_len)
    }
    fn has_address(&self, addr: IpAddr) -> Result<bool> {
        self.tun.has_address(addr)
    }
    fn add_route(&self, dest: IpAddr, prefix_len: u8) -> Result<()> {
        self.tun.add_route(dest, prefix_len)
    }
    fn route_owner_conflict(&self, dest: IpAddr, prefix_len: u8) -> Result<Option<String>> {
        self.tun.route_owner_conflict(dest, prefix_len)
    }
}
