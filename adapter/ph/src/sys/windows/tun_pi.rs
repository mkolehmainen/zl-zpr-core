//! Per-packet packet info, Windows arm: Wintun frames carry no packet-info
//! header at all, so `PI_SIZE` is 0 and `TUN_HAS_PI` is false (plan C3).
//! The conversions exist to satisfy the shared `TunPi` interface; with a
//! zero-size impl they never move any bytes.

use crate::sys::TunPi;

/// Zero-size packet info: Wintun rings carry bare IP packets.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TunPiImpl {}

impl From<TunPiImpl> for TunPi {
    fn from(_pi: TunPiImpl) -> TunPi {
        TunPi {
            strip: false,
            proto: 0,
        }
    }
}

impl From<TunPi> for TunPiImpl {
    fn from(_pi: TunPi) -> TunPiImpl {
        TunPiImpl {}
    }
}
