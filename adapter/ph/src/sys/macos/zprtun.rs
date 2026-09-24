use std::net::IpAddr;
use std::os::fd::{AsFd, BorrowedFd};

// TODO: This logging is used to debug the use of local commands for TUN address management. Remove once we use syscalls.
use tracing::*;

use crate::logging::targets::NET_OS;
use crate::sys::macos::tun;
use crate::sys::macos_route::{self, ExistingRouteAction, RouteCmdResult};
use crate::zprtun::ZprTunError;
use std::process::Command;

const COMMAND_IFCONFIG: &str = "/sbin/ifconfig";
const COMMAND_ROUTE: &str = "/sbin/route";

pub struct ZprTun {
    inner: tun::Tun,
    mtx: std::sync::Mutex<()>,
}

impl From<tun::TunError> for ZprTunError {
    fn from(e: tun::TunError) -> Self {
        ZprTunError::PlatformError(e.to_string())
    }
}

impl ZprTun {
    fn new(inner: tun::Tun) -> Self {
        ZprTun {
            inner,
            mtx: std::sync::Mutex::new(()),
        }
    }

    /// Create a new TUN device.
    /// If `ifname` is `None`, the kernel will automatically assign a name.
    /// On macOS if the name is specificed, it must be of the form `utun[0-9]+`.
    pub fn new_mq(
        ifname: Option<String>,
        concurrency: usize,
        address: Option<IpAddr>,
    ) -> std::result::Result<Vec<Self>, ZprTunError> {
        if concurrency != 1 {
            return Err(ZprTunError::PlatformError(String::from(
                "on macos concurrency (queues) must be 1",
            )));
        }
        let addr = address.ok_or_else(|| {
            ZprTunError::PlatformError(String::from("address is required on macos"))
            // TODO: Temporary
        })?;
        let mut bldr = tun::Tun::builder(addr.into());
        if let Some(name) = ifname {
            bldr.with_tun_name(&name);
        }
        let dev = tun::Tun::create(&bldr)?;
        Ok(vec![ZprTun::new(dev)])
    }

    /// A NOP on mac.
    pub fn set_carrier(&self, _carrier: bool) -> std::io::Result<()> {
        Ok(())
    }

    pub fn add_address(&self, addr: IpAddr, prefix_len: u8) -> std::io::Result<()> {
        let mtx = self
            .mtx
            .lock()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Mutex lock failed"))?;

        if self.has_address(addr)? {
            return Ok(());
        }

        let mut c = Command::new(COMMAND_IFCONFIG);
        c.arg(self.inner.get_name());
        match addr {
            IpAddr::V4(_ipv4) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "add_address with IPv4 is not supported on macOS",
                ));
            }
            IpAddr::V6(ipv6) => {
                c.arg("inet6")
                    .arg(format!("{}/{}", ipv6.to_string(), prefix_len));
            }
        }
        c.arg("alias");
        debug!(target: NET_OS, "{:?}", c);
        let output = c.output()?;
        if !output.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "{COMMAND_IFCONFIG} failed to set address on {}: {}",
                    self.inner.get_name(),
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }
        drop(mtx);
        Ok(())
    }

    /// Ensure `dest/prefix_len` is routed on-link via this TUN device.
    ///
    /// Idempotent, with verification: macOS `route add` has no `replace`
    /// mode, and a prefix already in the table comes back as "File exists"
    /// whether the existing route targets this TUN or somewhere else. On
    /// that error the existing route is inspected with `route -n get`; if it
    /// already runs via this interface the call succeeds, otherwise the
    /// stale route is deleted and ours installed — mirroring the Linux
    /// side's `ip -6 route replace` semantics.
    pub fn add_route(&self, dest: IpAddr, prefix_len: u8) -> std::io::Result<()> {
        if dest.is_ipv4() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "add_route with IPv4 is not supported on macOS",
            ));
        }
        let mtx = self
            .mtx
            .lock()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Mutex lock failed"))?;
        let output = self.route_add(dest, prefix_len)?;
        // /sbin/route exits 0 even when the add failed with "File exists"
        // (observed on a real Mac, zipline#100), so classification reads
        // stderr regardless of the exit status.
        match macos_route::classify_route_cmd(
            output.status.success(),
            &String::from_utf8_lossy(&output.stderr),
        ) {
            RouteCmdResult::Ok => {}
            RouteCmdResult::Failed(stderr) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!(
                        "{COMMAND_ROUTE} failed to install route {}/{} on {}: {}",
                        dest,
                        prefix_len,
                        self.inner.get_name(),
                        stderr
                    ),
                ));
            }
            // The prefix is already routed — but "File exists" does not say
            // via what. Verify before treating this as idempotent success.
            RouteCmdResult::Exists => match self.existing_route_target(dest, prefix_len)? {
                ExistingRouteAction::AlreadyOurs => {}
                ExistingRouteAction::Replace => {
                    debug!(
                        target: NET_OS,
                        "route {}/{} exists but not via {}; replacing",
                        dest,
                        prefix_len,
                        self.inner.get_name()
                    );
                    self.route_delete(dest, prefix_len)?;
                    let output = self.route_add(dest, prefix_len)?;
                    // An `Exists` here, right after deleting the stale
                    // route, is unexpected: treat anything non-clean as a
                    // failure.
                    match macos_route::classify_route_cmd(
                        output.status.success(),
                        &String::from_utf8_lossy(&output.stderr),
                    ) {
                        RouteCmdResult::Ok => {}
                        RouteCmdResult::Exists | RouteCmdResult::Failed(_) => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!(
                                    "{COMMAND_ROUTE} failed to reinstall route {}/{} on {} after \
                                     deleting the stale route: {}",
                                    dest,
                                    prefix_len,
                                    self.inner.get_name(),
                                    String::from_utf8_lossy(&output.stderr)
                                ),
                            ));
                        }
                    }
                }
            },
        }
        drop(mtx);
        Ok(())
    }

    /// Run `route -n add` for `dest/prefix_len` via this TUN, returning the
    /// raw output for the caller to interpret.
    fn route_add(&self, dest: IpAddr, prefix_len: u8) -> std::io::Result<std::process::Output> {
        let mut c = Command::new(COMMAND_ROUTE);
        c.arg("-n")
            .arg("add")
            .arg("-inet6")
            .arg(format!("{}/{}", dest, prefix_len))
            .arg("-interface")
            .arg(self.inner.get_name());
        debug!(target: NET_OS, "{:?}", c);
        c.output()
    }

    /// Inspect the route currently installed for `dest/prefix_len` and
    /// decide whether it already targets this TUN. A `route -n get` that
    /// fails or names another interface demands a replace — an
    /// uninspectable route is never assumed to be ours.
    fn existing_route_target(
        &self,
        dest: IpAddr,
        prefix_len: u8,
    ) -> std::io::Result<ExistingRouteAction> {
        let mut c = Command::new(COMMAND_ROUTE);
        c.arg("-n")
            .arg("get")
            .arg("-inet6")
            .arg(format!("{}/{}", dest, prefix_len));
        debug!(target: NET_OS, "{:?}", c);
        let output = c.output()?;
        if !output.status.success() {
            return Ok(ExistingRouteAction::Replace);
        }
        Ok(macos_route::existing_route_action(
            &String::from_utf8_lossy(&output.stdout),
            self.inner.get_name(),
        ))
    }

    /// Delete whatever route is installed for `dest/prefix_len`.
    ///
    /// Idempotent: the contract is "the route is gone afterwards". On any
    /// non-clean `route delete` result — including exit 0 with error text,
    /// which macOS produces for "not in table" (zipline#100) — the routing
    /// table is probed with `route -n get`; if the route is gone the delete
    /// succeeded for our purposes (logged at warn), otherwise it failed.
    fn route_delete(&self, dest: IpAddr, prefix_len: u8) -> std::io::Result<()> {
        let mut c = Command::new(COMMAND_ROUTE);
        c.arg("-n")
            .arg("delete")
            .arg("-inet6")
            .arg(format!("{}/{}", dest, prefix_len));
        debug!(target: NET_OS, "{:?}", c);
        let output = c.output()?;
        match macos_route::classify_route_cmd(
            output.status.success(),
            &String::from_utf8_lossy(&output.stderr),
        ) {
            RouteCmdResult::Ok => Ok(()),
            RouteCmdResult::Exists | RouteCmdResult::Failed(_) => {
                let delete_stderr = String::from_utf8_lossy(&output.stderr).into_owned();
                // Probe whether the route is still in the table: an absent
                // route means the contract is met whatever the delete said.
                let mut c = Command::new(COMMAND_ROUTE);
                c.arg("-n")
                    .arg("get")
                    .arg("-inet6")
                    .arg(format!("{}/{}", dest, prefix_len));
                debug!(target: NET_OS, "{:?}", c);
                let get = c.output()?;
                let get_output = format!(
                    "{}{}",
                    String::from_utf8_lossy(&get.stdout),
                    String::from_utf8_lossy(&get.stderr)
                );
                if macos_route::route_gone(get.status.success(), &get_output) {
                    warn!(
                        target: NET_OS,
                        "route delete {}/{} reported an error but the route is gone; \
                         treating as success (stderr: {})",
                        dest,
                        prefix_len,
                        delete_stderr.trim()
                    );
                    Ok(())
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!(
                            "{COMMAND_ROUTE} failed to delete route {}/{} and it is still \
                             in the table: delete stderr: {}; route get output: {}",
                            dest,
                            prefix_len,
                            delete_stderr.trim(),
                            get_output.trim()
                        ),
                    ))
                }
            }
        }
    }

    pub fn clear_address(&self, addr: IpAddr, prefix_len: u8) -> std::io::Result<()> {
        if !self.has_address(addr)? {
            return Ok(());
        }

        let mut c = Command::new(COMMAND_IFCONFIG);
        c.arg(self.inner.get_name());
        match addr {
            IpAddr::V4(_ipv4) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "clear_address with IPv4 is not supported on macOS",
                ));
            }
            IpAddr::V6(ipv6) => {
                c.arg("inet6")
                    .arg(format!("{}/{}", ipv6.to_string(), prefix_len));
            }
        }
        c.arg("-alias"); // <-- note the MINUS here
        debug!(target: NET_OS, "{:?}", c);
        let output = c.output()?;
        if !output.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "{COMMAND_IFCONFIG} failed to clear addresses {} on {}: {}",
                    addr,
                    self.inner.get_name(),
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }
        Ok(())
    }

    /// Reports whether `addr` is currently configured on this TUN device.
    ///
    /// Does not take the device mutex, so it is safe to call either with or
    /// without it held.
    pub fn has_address(&self, addr: IpAddr) -> std::io::Result<bool> {
        if addr.is_ipv4() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "has_address with IPv4 is not supported on macos",
            ));
        }
        let mut c = Command::new(COMMAND_IFCONFIG);
        c.arg(self.inner.get_name());
        debug!(target: NET_OS, "{:?}", c);
        let output = c.output()?;

        // If interface is there, the output will be something like:
        //
        // utun2: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 2000
        //         inet6 fe80::e9b0:1972:d221:2196%utun2 prefixlen 64 scopeid 0x11
        //         nd6 options=201<PERFORMNUD,DAD>
        if !output.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "{COMMAND_IFCONFIG} failed to show addresses for {}: {}",
                    self.inner.get_name(),
                    String::from_utf8_lossy(&output.stderr)
                ),
            ));
        }
        // Just look for the pattern "inet6 <addr>" + "%" in the output.
        let out_str = String::from_utf8_lossy(&output.stdout);
        Ok(out_str.contains(&format!("inet6 {}%", addr)))
    }
}

impl AsFd for ZprTun {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }
}
