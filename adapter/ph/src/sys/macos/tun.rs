use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::{ioctl_readwrite, ioctl_write_ptr};
use std::ffi::CStr;
use std::mem;
use std::net::IpAddr;
use std::os::fd::AsFd;
use std::os::unix::io::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;
use thiserror::Error;

use libc::{
    self, AF_INET, AF_INET6, AF_SYS_CONTROL, AF_SYSTEM, IFNAMSIZ, PF_SYSTEM, SOCK_DGRAM,
    SYSPROTO_CONTROL, UTUN_OPT_IFNAME, c_char, c_uint, c_void, ctl_info, ifreq, sockaddr,
    socklen_t,
};

// Not in libc. Copied from netinet6/nd6.h
const IPV6_MMTU: u16 = 1280; // Minimum MTU for IPv6
const IPV4_MMTU: u16 = 576; // Minimum MTU for IPv4

/// Special macOS controller name for creating tun devices. (see net/if_utun.h)
pub const UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control";

ioctl_readwrite!(ctliocginfo, b'N', 3, ctl_info); // Convert kernel controller name to kernel controller ID
ioctl_write_ptr!(siocsifmtu, b'i', 52, ifreq); // set ifnet MTU

#[derive(Debug, Error)]
pub enum TunError {
    #[error("TUN device name is too long")]
    NameTooLong,

    #[error("TUN device name is invalid (expect 'utun<N>')")]
    InvalidName,

    #[error("Failed to parse TUN interface name: {0}")]
    ParseError(#[from] std::num::ParseIntError),

    #[error("I/O Error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("Invalid MTU size (must be >= 1280 for IPv6)")]
    InvalidIpv6Mtu,

    #[error("Invalid MTU size (must be >= 576 for IPv4)")]
    InvalidIpv4Mtu,
}

/// Basic TUN device on macOS.
pub struct Tun {
    tun_fd: OwnedFd,
    ctl_fd: OwnedFd,
    name: String,
}

// This is the way ZPR accesses the tun device.
impl AsFd for Tun {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.tun_fd.as_fd()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum IPV {
    V4,
    V6,
}

impl From<IpAddr> for IPV {
    fn from(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(_) => IPV::V4,
            IpAddr::V6(_) => IPV::V6,
        }
    }
}

impl Tun {
    /// Create a build to aid in configuring the tun.
    pub fn builder(ipv: IPV) -> Builder {
        Builder::new(ipv)
    }

    /// Create and configure the TUN device.
    pub fn create(config: &Builder) -> Result<Self, TunError> {
        // The id is one plus the number after the "utun" prefix.
        // If we pass the kernel id=0 it will assign the next available id.
        let id = if let Some(tun_name) = config.name.as_ref() {
            if tun_name.len() > IFNAMSIZ {
                return Err(TunError::NameTooLong);
            }
            if !tun_name.starts_with("utun") {
                return Err(TunError::InvalidName);
            }
            tun_name[4..].parse::<u32>()? + 1_u32
        } else {
            0_u32
        };

        let mut tundev = unsafe {
            let fd = OwnedFd::from_raw_fd(libc::socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL));
            let mut info = ctl_info {
                ctl_id: 0,
                ctl_name: {
                    let mut buffer = [0; 96];
                    for (i, o) in UTUN_CONTROL_NAME.as_bytes().iter().zip(buffer.iter_mut()) {
                        *o = *i as _;
                    }
                    buffer
                },
            };

            // Obtain a ctl_id for utun controller
            if let Err(err) = ctliocginfo(fd.as_raw_fd(), &mut info as *mut _ as *mut _) {
                return Err(std::io::Error::from(err).into());
            }

            let addr = libc::sockaddr_ctl {
                sc_id: info.ctl_id,
                sc_len: mem::size_of::<libc::sockaddr_ctl>() as _,
                sc_family: AF_SYSTEM as _,
                ss_sysaddr: AF_SYS_CONTROL as _,
                sc_unit: id as c_uint,
                sc_reserved: [0; 5],
            };

            // This 'connect' call will request creation of the TUN device
            let address = &addr as *const libc::sockaddr_ctl as *const sockaddr;
            if libc::connect(
                fd.as_raw_fd(),
                address,
                mem::size_of_val(&addr) as socklen_t,
            ) < 0
            {
                return Err(std::io::Error::last_os_error().into());
            }

            // Now query for the name of the TUN device
            let mut tun_name = [0u8; 64];
            let mut name_len: socklen_t = 64;
            let optval = &mut tun_name as *mut _ as *mut c_void;
            let optlen = &mut name_len as *mut socklen_t;
            if libc::getsockopt(
                fd.as_raw_fd(),
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                optval,
                optlen,
            ) < 0
            {
                return Err(std::io::Error::last_os_error().into());
            }

            let tun_name_str: String = CStr::from_ptr(tun_name.as_ptr() as *const c_char)
                .to_string_lossy()
                .into();

            let ctl_sock;
            if config.is_ipv6() {
                ctl_sock = libc::socket(AF_INET6, SOCK_DGRAM, 0);
            } else {
                ctl_sock = libc::socket(AF_INET, SOCK_DGRAM, 0);
            }
            if ctl_sock < 0 {
                return Err(std::io::Error::last_os_error().into());
            }

            Tun {
                tun_fd: fd,
                ctl_fd: OwnedFd::from_raw_fd(ctl_sock),
                name: tun_name_str,
            }
        };
        tundev.configure(config)?;

        // TODO: Set interface UP? Not required? Seems like kernel sets it to UP already.

        Ok(tundev)
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    // Post create configuration based on the builder.
    fn configure(&mut self, config: &Builder) -> Result<(), TunError> {
        // Set to non-blocking
        if let Err(err) = Tun::set_raw_fd_nonblocking(self.tun_fd.as_raw_fd()) {
            return Err(TunError::IOError(std::io::Error::from(err)));
        }

        // The device is created unaddressed (zipline#161) — addressing
        // happens later through `ZprTun::add_address` — so only an
        // explicitly requested MTU is set here.
        if let Some(mtu) = config.mtu {
            if config.is_ipv6() && mtu < IPV6_MMTU {
                return Err(TunError::InvalidIpv6Mtu);
            }
            if !config.is_ipv6() && mtu < IPV4_MMTU {
                return Err(TunError::InvalidIpv4Mtu);
            }
            self.set_mtu(mtu)?;
        }
        Ok(())
    }

    /// Prepare a new `ifreq` request for kernel control socket.  Fills in the name field.
    unsafe fn request_v4(&self) -> Result<libc::ifreq, TunError> {
        let mut req: libc::ifreq = unsafe { mem::zeroed() };
        unsafe {
            ptr::copy_nonoverlapping(
                self.name.as_ptr() as *const c_char,
                req.ifr_name.as_mut_ptr(),
                self.name.len(),
            )
        };
        Ok(req)
    }

    pub fn set_mtu(&mut self, value: u16) -> Result<(), TunError> {
        unsafe {
            let mut req = self.request_v4()?;
            req.ifr_ifru.ifru_mtu = value as i32;
            if let Err(err) = siocsifmtu(self.ctl_fd.as_raw_fd(), &req) {
                return Err(std::io::Error::from(err).into());
            }
            Ok(())
        }
    }

    fn set_raw_fd_nonblocking(fd: RawFd) -> nix::Result<()> {
        // Get the current file status flags
        let flags = fcntl(fd, FcntlArg::F_GETFL)?;

        // Add the O_NONBLOCK flag to the existing flags
        let mut new_flags = OFlag::from_bits_truncate(flags);
        new_flags.insert(OFlag::O_NONBLOCK);

        // Set the new flags
        fcntl(fd, FcntlArg::F_SETFL(new_flags))?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct Builder {
    name: Option<String>,
    mtu: Option<u16>,
    ipv: IPV,
}

impl Builder {
    /// Create a new builder, which is used to configure the TUN device.
    /// You must choose either IPv4 or IPv6.
    fn new(ipv: IPV) -> Builder {
        Builder {
            name: None,
            mtu: None,
            ipv,
        }
    }

    pub fn is_ipv6(&self) -> bool {
        self.ipv == IPV::V6
    }

    /// Tun name is optional. If provided must be of format "utun<N>" where N is a number.
    #[allow(dead_code)]
    pub fn with_tun_name(&mut self, name: &str) -> &mut Self {
        self.name = Some(name.into());
        self
    }

    /// Will use a default setting if not supplied.
    #[allow(dead_code)]
    pub fn with_mtu(&mut self, mtu: u16) -> &mut Self {
        self.mtu = Some(mtu);
        self
    }
}
