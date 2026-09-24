#[cfg(target_os = "linux")]
pub(crate) mod linux;
#[cfg(target_os = "linux")]
pub use self::linux::TunPiImpl;
#[cfg(target_os = "linux")]
pub use self::linux::ZprTun;

#[cfg(target_os = "macos")]
pub(crate) mod macos;
#[cfg(target_os = "macos")]
pub use self::macos::TunPiImpl;
#[cfg(target_os = "macos")]
pub use self::macos::ZprTun;

// Pure decision logic for the macOS route path. Compiled on every OS so it
// stays unit-testable from Linux builds; only macOS code calls it at runtime.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) mod macos_route;

// Pure parsing/decision logic for the ZPR internal-network route-owner
// check (zipline#101): the Linux `ip -6 route show` parser and the
// platform-neutral conflict decision. Compiled on every OS, same pattern
// and reason as `macos_route` above; the Linux parser half is dead code on
// macOS.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) mod linux_route;

pub(crate) mod posix;
pub use self::posix::notify;

use bytes::buf;

/// per-packet packet info
#[derive(Clone, Copy)]
pub struct TunPi {
    // the inbound packet was truncated (ignored outbound)
    pub strip: bool,
    /// Ethertype of packet
    pub proto: u16,
}

impl TunPi {
    /// The size of a per-packet packet info structure.
    pub const PI_SIZE: usize = std::mem::size_of::<TunPiImpl>();

    /// Read per-packet packet info from a `Buf`.
    pub fn read_pi<B: buf::Buf>(buf: &mut B) -> TunPi {
        let mut os_pi = std::mem::MaybeUninit::<TunPiImpl>::uninit();
        let slice = os_pi.as_mut_ptr();
        buf.copy_to_slice(unsafe {
            /* SAFETY: we immediately initialize */
            std::slice::from_raw_parts_mut(slice as *mut u8, TunPi::PI_SIZE)
        });
        unsafe {
            /* SAFETY: was just initialized */
            os_pi.assume_init()
        }
        .into()
    }

    /// Write per-packet packet info into a `BufMut`.
    pub fn write_pi<B: buf::BufMut>(buf: &mut B, pi: TunPi) {
        let os_pi: TunPiImpl = pi.into();
        buf.put(unsafe {
            /* SAFETY: we are reading exactly the structure */
            std::slice::from_raw_parts((&os_pi as *const _) as *const u8, TunPi::PI_SIZE)
        });
    }
}
