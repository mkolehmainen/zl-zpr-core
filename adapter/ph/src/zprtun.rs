//! Common interface for the TUN devices.
//!
//! The actual TUN implementation is platform specific and can be found in `sys/<platform>/zprtun.rs`.
//!
//!
//!
use crate::sys::TunPi;

#[allow(dead_code)]
pub const DEFAULT_TUN_MTU: u16 = 1400;

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
