//! Common interface for the TUN devices.
//!
//! The actual TUN implementation is platform specific and can be found in `sys/<platform>/zprtun.rs`.
//!
//!
//!
use crate::sys::TunPi;

#[allow(dead_code)]
pub const DEFAULT_TUN_MTU: u16 = 1400;

/// The MTU a newly created TUN device gets: the explicitly requested value,
/// or [`DEFAULT_TUN_MTU`] when none was requested.
///
/// PR #66 review (P2): the default must apply unconditionally — before
/// zipline#161 the macOS creation path applied it only when a create-time
/// address was supplied, and once creation stopped taking an address the
/// device would have been left at the kernel default (2000 for a utun),
/// above the 1400 overlay MTU. Platform-neutral so the rule is one place
/// and unit-tested from any host; currently only the macOS builder sets an
/// MTU at creation (Linux relies on external configuration, Wintun has its
/// own ring defaults).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn effective_tun_mtu(requested: Option<u16>) -> u16 {
    requested.unwrap_or(DEFAULT_TUN_MTU)
}

/// Error type used by some ZprTun functions across platform implementations.
#[derive(thiserror::Error, Debug)]
pub enum ZprTunError {
    #[error("{0}")]
    IoError(#[from] std::io::Error),

    #[error("platform error from TUN device: {0}")]
    PlatformError(String),
}

/// TRUE if the platform TUN implementation supports per-packet packet info.
pub const TUN_HAS_PI: bool = TunPi::PI_SIZE > 0;

#[cfg(test)]
mod tests {
    use super::*;

    /// PR #66 review (P2): the TUN MTU must not depend on an address being
    /// supplied at creation — an unspecified MTU gets `DEFAULT_TUN_MTU`,
    /// not the kernel default (2000 for a macOS utun, above the overlay's
    /// 1400).
    #[test]
    fn unspecified_mtu_defaults_to_overlay_mtu() {
        assert_eq!(effective_tun_mtu(None), DEFAULT_TUN_MTU);
    }

    #[test]
    fn explicit_mtu_wins() {
        assert_eq!(effective_tun_mtu(Some(1500)), 1500);
    }
}
