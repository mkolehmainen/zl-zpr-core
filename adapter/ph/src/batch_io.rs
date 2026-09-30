//! Batch I/O operations.
//!
//! These vary both by operating system and feature set.
//!
//! All these operations assume a file descriptor which has been set
//! non-blocking, and they perform non-blocking I/O operations.

use bytes::BufMut;
use libc;
#[cfg(unix)]
use nix::sys::socket::{self, AddressFamily, SockaddrLike, SockaddrStorage};
use std::io::Result;
#[cfg(unix)]
use std::net::Ipv4Addr;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::fd::{AsFd, AsRawFd};
use zpr_utils::net_defs::ScopedIpAddr;
#[cfg(unix)]
use zpr_utils::net_defs::ScopedIpv6Addr;

use crate::sys::wait::AsWaitSource;
use crate::sys::wait::WaitHandle;

/// Flags for socket send operations, as a platform-neutral newtype over the
/// OS flag bits (unix: the `MSG_*` bits of `sendmsg(2)`'s `flags` argument).
///
/// The constructors for flags that exist only on some platforms are no-ops
/// elsewhere, so callers need no `#[cfg]` of their own.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SendFlags(libc::c_int);

impl SendFlags {
    /// No flags.
    pub const fn none() -> Self {
        Self(0)
    }

    /// `MSG_CONFIRM`: tell the link layer that forward progress happened
    /// (suppresses unicast ARP/NDP re-validation). Linux only; a no-op
    /// elsewhere.
    #[cfg(target_os = "linux")]
    pub const fn confirm() -> Self {
        Self(libc::MSG_CONFIRM)
    }

    /// `MSG_CONFIRM` does not exist on this platform; no flags.
    #[cfg(not(target_os = "linux"))]
    pub const fn confirm() -> Self {
        Self(0)
    }

    /// `MSG_DONTWAIT`: this send completes immediately instead of blocking.
    /// Linux only (elsewhere the sockets are already non-blocking, or the
    /// platform has no such flag); a no-op off Linux.
    ///
    /// Not yet called: the unix engines apply `MSG_DONTWAIT` internally
    /// (zipline#117), so this constructor exists for the Windows engine
    /// (zipline#131) and for callers that need it explicitly.
    #[allow(dead_code)]
    #[cfg(target_os = "linux")]
    pub const fn dontwait() -> Self {
        Self(libc::MSG_DONTWAIT)
    }

    /// `MSG_DONTWAIT` is not used on this platform; no flags.
    #[allow(dead_code)]
    #[cfg(not(target_os = "linux"))]
    pub const fn dontwait() -> Self {
        Self(0)
    }

    /// The raw OS flag bits.
    ///
    /// Consumed by the unix engines only; the Windows engine (zipline#131)
    /// has no sendmsg-style flags argument.
    #[cfg_attr(windows, allow(dead_code))]
    fn bits(self) -> libc::c_int {
        self.0
    }
}

impl std::ops::BitOr for SendFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

pub struct ReceivedPacket {
    #[allow(dead_code)]
    pub size: usize,
    pub truncated: bool,
    pub source: Option<SocketAddr>,
    pub destination: Option<ScopedIpAddr>,
}

#[cfg(unix)]
fn sockaddr_to_socket_addr(sa: SockaddrStorage) -> Option<SocketAddr> {
    match sa.family()? {
        AddressFamily::Inet => Some(SocketAddr::V4((*sa.as_sockaddr_in().unwrap()).into())),
        AddressFamily::Inet6 => Some(SocketAddr::V6((*sa.as_sockaddr_in6().unwrap()).into())),
        _ => None,
    }
}

#[cfg(unix)]
fn errno_to_error(errno: nix::errno::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(errno as i32)
}

#[cfg(unix)]
fn pktinfo_from_ipv4addr(addr: &Ipv4Addr) -> libc::in_pktinfo {
    libc::in_pktinfo {
        ipi_ifindex: 0,
        ipi_spec_dst: libc::in_addr {
            s_addr: addr.to_bits().to_be(),
        },
        ipi_addr: libc::in_addr { s_addr: 0 },
    }
}

#[cfg(unix)]
fn pktinfo_from_scoped_ipv6addr(addr: &ScopedIpv6Addr) -> libc::in6_pktinfo {
    libc::in6_pktinfo {
        ipi6_addr: libc::in6_addr {
            s6_addr: addr.ip().octets(),
        },
        ipi6_ifindex: addr.scope_id(),
    }
}

/// Enable the reception of packet info on a socket.  Required for
/// `try_recv_buf_from_to_batch()` to return the destination address.
/// Unix only: the Windows engine has no pktinfo path (plan D5) — an
/// end-user adapter is single-homed for our purposes.
#[cfg(unix)]
pub fn set_recv_packet_info(fd: &impl AsFd, enable: bool) -> std::io::Result<()> {
    match socket::getsockname::<SockaddrStorage>(fd.as_fd().as_raw_fd())?.family() {
        Some(AddressFamily::Inet) => {
            socket::setsockopt(fd, socket::sockopt::Ipv4PacketInfo, &enable).map_err(errno_to_error)
        }
        Some(AddressFamily::Inet6) => {
            socket::setsockopt(fd, socket::sockopt::Ipv6RecvPacketInfo, &enable)
                .map_err(errno_to_error)
        }
        _ => Ok(()),
    }
}

trait BatchIoImpl {
    fn engine_name(&self) -> &'static str;

    fn try_write_batch<'a>(
        &mut self,
        handle: WaitHandle<'_>,
        bufs: &mut dyn Iterator<Item = &'a [u8]>,
        results: &mut Vec<Result<usize>>,
    ) -> Result<usize>;

    fn try_read_buf_batch<'a>(
        &mut self,
        handle: WaitHandle<'_>,
        bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
        results: &mut Vec<Result<usize>>,
    ) -> Result<usize>;

    fn try_send_to_batch<'a>(
        &mut self,
        handle: WaitHandle<'_>,
        bufs: &mut dyn Iterator<Item = (&'a [u8], SocketAddr, SendFlags)>,
        results: &mut Vec<Result<usize>>,
    ) -> Result<usize>;

    fn try_send_to_from_batch<'a>(
        &mut self,
        handle: WaitHandle<'_>,
        bufs: &mut dyn Iterator<Item = (&'a [u8], SocketAddr, Option<ScopedIpAddr>, SendFlags)>,
        results: &mut Vec<Result<usize>>,
    ) -> Result<usize>;

    fn try_recv_buf_from_batch<'a>(
        &mut self,
        handle: WaitHandle<'_>,
        bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
        results: &mut Vec<Result<ReceivedPacket>>,
    ) -> Result<usize>;

    fn try_recv_buf_from_to_batch<'a>(
        &mut self,
        handle: WaitHandle<'_>,
        bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
        results: &mut Vec<Result<ReceivedPacket>>,
    ) -> Result<usize>;
}

#[cfg(all(target_os = "linux", feature = "io-uring"))]
mod io_uring {
    //! io_uring(7)-based implementation.  Only available for Linux.

    use super::{BatchIoImpl, ReceivedPacket, SendFlags, sockaddr_to_socket_addr};
    use crate::sys::wait::WaitHandle;
    use bytes::BufMut;
    use io_uring::{IoUring, Probe, cqueue, opcode, squeue, types};
    use libc;
    use nix::sys::socket::{SockaddrLike, SockaddrStorage};
    use std::io::Result;
    use std::mem::MaybeUninit;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::os::fd::{AsRawFd, BorrowedFd};
    use std::ptr::NonNull;
    use zpr_utils::net_defs::{ScopedIpAddr, ScopedIpv6Addr};

    const MAX_ENTRIES: usize = 1024;

    /// This is a very basic on-stack vector/slab.
    struct Slab<T> {
        allocated: usize,
        storage: [MaybeUninit<T>; MAX_ENTRIES],
    }

    impl<T> Slab<T> {
        fn new() -> Self {
            Self {
                allocated: 0,
                storage: [const { MaybeUninit::uninit() }; MAX_ENTRIES],
            }
        }

        fn get(&self, idx: usize) -> &T {
            assert!(idx < self.allocated);
            // SAFETY: we've written to all entries which have been allocated
            unsafe { self.storage[idx].assume_init_ref() }
        }

        fn get_mut(&mut self, idx: usize) -> &mut T {
            assert!(idx < self.allocated);
            // SAFETY: we've written to all entries which have been allocated
            unsafe { self.storage[idx].assume_init_mut() }
        }

        fn push(&mut self, val: T) -> &mut T {
            assert!(self.allocated < self.storage.len());
            let idx = self.allocated;
            self.allocated += 1;
            self.storage[idx].write(val)
        }
    }

    impl<T> Drop for Slab<T> {
        fn drop(&mut self) {
            for i in 0..self.allocated {
                // SAFETY: we've written to all entries which have been allocated
                unsafe {
                    self.storage[i].assume_init_drop();
                }
            }
        }
    }

    /// Rounds of re-cancel + bounded wait before declaring the kernel is
    /// never going to complete a straggler.  Every operation we submit
    /// either completes immediately (`MSG_DONTWAIT`) or is paired with a
    /// cancel, so more than a handful of rounds already indicates something
    /// is deeply wrong; ~5 s puts it beyond doubt.
    const MAX_REAP_ROUNDS: u32 = 5000;

    /// Round accounting for the straggler-reap loop (zipline#117 review).
    ///
    /// A "round" is one guard timeout's worth of waiting (`REAP_TIMEOUT`).
    /// The loop may wake many times within a single round -- e.g. when a
    /// re-cancel promptly completes with `-ENOENT` while its operation is
    /// still pending -- and those wakeups must not count against
    /// `MAX_REAP_ROUNDS`, or the documented ~5 s bound would burn out in
    /// far less time and panic in the very cancel-miss condition this path
    /// exists to tolerate.  A new round starts (re-cancels plus a fresh
    /// guard timeout) only once the previous round's timeout CQE has been
    /// reaped, so rounds advance at timeout cadence and at most one guard
    /// timeout is ever outstanding.
    struct ReapGuard {
        rounds: u32,
        timeout_outstanding: bool,
    }

    impl ReapGuard {
        fn new() -> Self {
            Self {
                rounds: 0,
                timeout_outstanding: false,
            }
        }

        /// Completed (timeout-gated) rounds so far.
        fn rounds(&self) -> u32 {
            self.rounds
        }

        /// Record a reaped guard-timeout CQE, ending the current round.
        fn timeout_reaped(&mut self) {
            debug_assert!(self.timeout_outstanding);
            self.timeout_outstanding = false;
        }

        /// Called when operations remain unaccounted for after draining the
        /// completion queue.  Returns whether a new round should be
        /// submitted (re-cancels plus a fresh guard timeout); `false` means
        /// the current round's timeout is still pending and the caller
        /// should only wait.
        fn try_start_round(&mut self) -> bool {
            if self.timeout_outstanding {
                return false;
            }
            self.rounds += 1;
            self.timeout_outstanding = true;
            true
        }
    }

    trait BatchOp<Item, State, Res> {
        fn new() -> Self;

        /// Whether operations built by `build_op` can remain pending in the
        /// kernel when the fd is not ready, and so must each be paired with
        /// a cancel request.  Operations which complete immediately no
        /// matter what (e.g. socket operations carrying `MSG_DONTWAIT`)
        /// return false.
        fn needs_cancel(&self) -> bool;

        fn build_op(&mut self, fd: types::Fd, item: Item, idx: usize) -> (squeue::Entry, State);
        fn process_result(&self, idx: usize, state: State, amt: usize) -> Res;
    }

    // std::cmp::max() is not const
    const fn const_u32_max(x: u32, y: u32) -> u32 {
        if x > y { x } else { y }
    }

    const PKTINFO_CMSG_SPACE_NEEDED: usize = const_u32_max(
        // SAFETY: these const functions are erroneously marked unsafe
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in_pktinfo>() as u32) },
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in6_pktinfo>() as u32) },
    ) as usize;

    struct TryWriteBatchOp {}

    impl BatchOp<&[u8], (), usize> for TryWriteBatchOp {
        fn new() -> Self {
            Self {}
        }

        fn needs_cancel(&self) -> bool {
            // Writes (to the actor TUN) cannot be made unconditionally
            // immediate: O_NONBLOCK is ignored by io_uring and RWF_NOWAIT is
            // not supported by TUN devices.
            true
        }

        fn build_op(&mut self, fd: types::Fd, buf: &[u8], _idx: usize) -> (squeue::Entry, ()) {
            (
                opcode::Write::new(fd, buf.as_ptr(), buf.len() as u32).build(),
                (),
            )
        }

        fn process_result(&self, _idx: usize, (): (), amt: usize) -> usize {
            amt
        }
    }

    struct TryReadBufBatchOp<'a> {
        phantom: std::marker::PhantomData<&'a mut dyn BufMut>,
    }

    impl<'a> BatchOp<&'a mut dyn BufMut, &'a mut dyn BufMut, usize> for TryReadBufBatchOp<'a> {
        fn new() -> Self {
            Self {
                phantom: std::marker::PhantomData,
            }
        }

        fn needs_cancel(&self) -> bool {
            // Reads (from the actor TUN) cannot be made unconditionally
            // immediate: O_NONBLOCK is ignored by io_uring and RWF_NOWAIT is
            // not supported by TUN devices.
            true
        }

        fn build_op(
            &mut self,
            fd: types::Fd,
            buf: &'a mut dyn BufMut,
            _idx: usize,
        ) -> (squeue::Entry, &'a mut dyn BufMut) {
            let chunk = buf.chunk_mut();
            (
                opcode::Read::new(fd, chunk.as_mut_ptr(), chunk.len() as u32).build(),
                buf,
            )
        }

        fn process_result(&self, _idx: usize, buf: &'a mut dyn BufMut, amt: usize) -> usize {
            // SAFETY: We know we've written the given number of bytes in the BufMut.
            unsafe { buf.advance_mut(amt) };
            amt
        }
    }

    struct TrySendToBatchOp {
        iovec_slab: Slab<libc::iovec>,
        sockaddr_slab: Slab<SockaddrStorage>,
        msghdr_slab: Slab<libc::msghdr>,
    }

    impl BatchOp<(&[u8], SocketAddr, libc::c_int), (), usize> for TrySendToBatchOp {
        fn new() -> Self {
            Self {
                iovec_slab: Slab::new(),
                sockaddr_slab: Slab::new(),
                msghdr_slab: Slab::new(),
            }
        }

        fn needs_cancel(&self) -> bool {
            // MSG_DONTWAIT makes the send complete immediately.
            false
        }

        fn build_op(
            &mut self,
            fd: types::Fd,
            (buf, addr, flags): (&[u8], SocketAddr, libc::c_int),
            _idx: usize,
        ) -> (squeue::Entry, ()) {
            let iovec_ref = self.iovec_slab.push(slice_as_iovec(buf));
            let sockaddr_ref = self.sockaddr_slab.push(SockaddrStorage::from(addr));

            let msghdr_ref = self.msghdr_slab.push(libc::msghdr {
                msg_name: sockaddr_ref as *mut _ as *mut libc::c_void,
                msg_namelen: sockaddr_ref.len(),
                msg_iov: iovec_ref,
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            });

            (
                opcode::SendMsg::new(fd, msghdr_ref as *const _)
                    // MSG_DONTWAIT: complete immediately (with -EAGAIN if the
                    // socket is not ready) instead of arming internal poll,
                    // so no pending operation is left for a cancel to miss
                    // (zipline#117).
                    .flags(flags as u32 | libc::MSG_DONTWAIT as u32)
                    .build(),
                (),
            )
        }

        fn process_result(&self, _idx: usize, (): (), amt: usize) -> usize {
            amt
        }
    }

    struct TrySendToFromBatchOp {
        iovec_slab: Slab<libc::iovec>,
        sockaddr_slab: Slab<SockaddrStorage>,
        cmsg_slab: Slab<[u8; PKTINFO_CMSG_SPACE_NEEDED]>,
        msghdr_slab: Slab<libc::msghdr>,
    }

    impl BatchOp<(&[u8], SocketAddr, Option<ScopedIpAddr>, libc::c_int), (), usize>
        for TrySendToFromBatchOp
    {
        fn new() -> Self {
            Self {
                iovec_slab: Slab::new(),
                sockaddr_slab: Slab::new(),
                cmsg_slab: Slab::new(),
                msghdr_slab: Slab::new(),
            }
        }

        fn needs_cancel(&self) -> bool {
            // MSG_DONTWAIT makes the send complete immediately.
            false
        }

        fn build_op(
            &mut self,
            fd: types::Fd,
            (buf, dst_addr, src_addr, flags): (
                &[u8],
                SocketAddr,
                Option<ScopedIpAddr>,
                libc::c_int,
            ),
            _idx: usize,
        ) -> (squeue::Entry, ()) {
            let iovec_ref = self.iovec_slab.push(slice_as_iovec(buf));
            let sockaddr_ref = self.sockaddr_slab.push(SockaddrStorage::from(dst_addr));

            let cmsg_ref = self.cmsg_slab.push([0u8; PKTINFO_CMSG_SPACE_NEEDED]);

            let msghdr_ref = self.msghdr_slab.push(libc::msghdr {
                msg_name: sockaddr_ref as *mut _ as *mut libc::c_void,
                msg_namelen: sockaddr_ref.len(),
                msg_iov: iovec_ref,
                msg_iovlen: 1,
                msg_control: cmsg_ref as *mut _ as *mut libc::c_void,
                msg_controllen: std::mem::size_of_val(cmsg_ref),
                msg_flags: 0,
            });

            match src_addr {
                None => {
                    msghdr_ref.msg_controllen = 0;
                }

                Some(src_addr) => {
                    // SAFETY: we have enough space in cmsg_ref for a cmsg header
                    let cmsg_ptr =
                        unsafe { NonNull::new(libc::CMSG_FIRSTHDR(msghdr_ref)).unwrap_unchecked() };
                    // SAFETY: we have enough space in cmsg_ref for our cmsg
                    let cmsg_len = unsafe { scoped_ip_addr_to_cmsg(cmsg_ptr, src_addr) };
                    msghdr_ref.msg_controllen = cmsg_len;
                }
            }

            (
                opcode::SendMsg::new(fd, msghdr_ref as *const _)
                    // MSG_DONTWAIT: see TrySendToBatchOp (zipline#117).
                    .flags(flags as u32 | libc::MSG_DONTWAIT as u32)
                    .build(),
                (),
            )
        }

        fn process_result(&self, _idx: usize, (): (), amt: usize) -> usize {
            amt
        }
    }

    struct TryRecvBufFromBatchOp<'a> {
        iovec_slab: Slab<libc::iovec>,
        sockaddr_slab: [MaybeUninit<SockaddrStorage>; MAX_ENTRIES],
        msghdr_slab: Slab<libc::msghdr>,
        phantom: std::marker::PhantomData<&'a mut dyn BufMut>,
    }

    impl<'a> BatchOp<&'a mut dyn BufMut, &'a mut dyn BufMut, ReceivedPacket>
        for TryRecvBufFromBatchOp<'a>
    {
        fn new() -> Self {
            Self {
                iovec_slab: Slab::new(),
                sockaddr_slab: [MaybeUninit::uninit(); MAX_ENTRIES],
                msghdr_slab: Slab::new(),
                phantom: std::marker::PhantomData,
            }
        }

        fn needs_cancel(&self) -> bool {
            // MSG_DONTWAIT makes the receive complete immediately.
            false
        }

        fn build_op(
            &mut self,
            fd: types::Fd,
            buf: &'a mut dyn BufMut,
            idx: usize,
        ) -> (squeue::Entry, &'a mut dyn BufMut) {
            let iovec_ref = self.iovec_slab.push(buf_mut_as_iovec(buf));
            let sockaddr_ref = &mut self.sockaddr_slab[idx];
            let msghdr_ref = self.msghdr_slab.push(libc::msghdr {
                msg_name: sockaddr_ref.as_mut_ptr() as *mut libc::c_void,
                msg_namelen: std::mem::size_of_val(sockaddr_ref) as u32,
                msg_iov: iovec_ref,
                msg_iovlen: 1,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            });

            (
                opcode::RecvMsg::new(fd, msghdr_ref as *mut _)
                    // MSG_DONTWAIT: complete immediately (with -EAGAIN if the
                    // socket is empty) instead of arming internal poll, so no
                    // pending operation is left for a cancel to miss
                    // (zipline#117).
                    .flags(libc::MSG_DONTWAIT as u32)
                    .build(),
                buf,
            )
        }

        fn process_result(
            &self,
            idx: usize,
            buf: &'a mut dyn BufMut,
            size: usize,
        ) -> ReceivedPacket {
            // SAFETY: We know we've written the given number of bytes in the BufMut.
            unsafe {
                buf.advance_mut(size);
            }
            let truncated = (self.msghdr_slab.get(idx).msg_flags & libc::MSG_TRUNC) != 0;
            // SAFETY: We know the sockaddr is now filled.
            let source = sockaddr_to_socket_addr(unsafe { self.sockaddr_slab[idx].assume_init() });
            ReceivedPacket {
                size,
                truncated,
                source,
                destination: None,
            }
        }
    }

    struct TryRecvBufFromToBatchOp<'a> {
        iovec_slab: Slab<libc::iovec>,
        sockaddr_slab: [MaybeUninit<SockaddrStorage>; MAX_ENTRIES],
        cmsg_slab: [[u8; PKTINFO_CMSG_SPACE_NEEDED]; MAX_ENTRIES],
        msghdr_slab: Slab<libc::msghdr>,
        phantom: std::marker::PhantomData<&'a mut dyn BufMut>,
    }

    impl<'a> BatchOp<&'a mut dyn BufMut, &'a mut dyn BufMut, ReceivedPacket>
        for TryRecvBufFromToBatchOp<'a>
    {
        fn new() -> Self {
            Self {
                iovec_slab: Slab::new(),
                sockaddr_slab: [MaybeUninit::uninit(); MAX_ENTRIES],
                cmsg_slab: [[0u8; PKTINFO_CMSG_SPACE_NEEDED]; MAX_ENTRIES],
                msghdr_slab: Slab::new(),
                phantom: std::marker::PhantomData,
            }
        }

        fn needs_cancel(&self) -> bool {
            // MSG_DONTWAIT makes the receive complete immediately.
            false
        }

        fn build_op(
            &mut self,
            fd: types::Fd,
            buf: &'a mut dyn BufMut,
            idx: usize,
        ) -> (squeue::Entry, &'a mut dyn BufMut) {
            let iovec_ref = self.iovec_slab.push(buf_mut_as_iovec(buf));
            let sockaddr_ref = &mut self.sockaddr_slab[idx];
            let cmsg_ref = &mut self.cmsg_slab[idx];
            let msghdr_ref = self.msghdr_slab.push(libc::msghdr {
                msg_name: sockaddr_ref.as_mut_ptr() as *mut libc::c_void,
                msg_namelen: std::mem::size_of_val(sockaddr_ref) as u32,
                msg_iov: iovec_ref,
                msg_iovlen: 1,
                msg_control: cmsg_ref.as_mut_ptr() as *mut libc::c_void,
                msg_controllen: std::mem::size_of_val(cmsg_ref),
                msg_flags: 0,
            });

            (
                opcode::RecvMsg::new(fd, msghdr_ref as *mut _)
                    // MSG_DONTWAIT: see TryRecvBufFromBatchOp (zipline#117).
                    .flags(libc::MSG_DONTWAIT as u32)
                    .build(),
                buf,
            )
        }

        fn process_result(
            &self,
            idx: usize,
            buf: &'a mut dyn BufMut,
            size: usize,
        ) -> ReceivedPacket {
            // SAFETY: We know we've written the given number of bytes in the BufMut.
            unsafe {
                buf.advance_mut(size);
            }
            let truncated = (self.msghdr_slab.get(idx).msg_flags & libc::MSG_TRUNC) != 0;
            // SAFETY: We know the sockaddr is now filled.
            let source = sockaddr_to_socket_addr(unsafe { self.sockaddr_slab[idx].assume_init() });
            // SAFETY: We know the cmsgs are valid.
            let destination = unsafe { cmsg_iter(self.msghdr_slab.get(idx)) }
                .find_map(|cmsg| unsafe { cmsg_to_scoped_ip_addr(cmsg.as_ptr()) });
            ReceivedPacket {
                size,
                truncated,
                source,
                destination,
            }
        }
    }

    pub struct BatchIo {
        io_uring: IoUring<squeue::Entry, cqueue::Entry>,
    }

    // NOTE: Limit io_uring features used to those available in 5.10 or later.
    // (= oldest LTS release with EOL > end of 2025)

    impl BatchIo {
        pub const ENGINE_NAME: &'static str = "io_uring";

        pub const MAX_ENTRIES: usize = MAX_ENTRIES;

        const REQUIRED_OPCODES: &[u8] = &[
            opcode::AsyncCancel::CODE,
            opcode::Timeout::CODE,
            opcode::Write::CODE,
            opcode::Read::CODE,
            opcode::SendMsg::CODE,
            opcode::RecvMsg::CODE,
        ];

        pub fn detect_support() -> bool {
            let Ok(io_uring) = IoUring::new(1) else {
                return false;
            };

            let mut probe = Probe::new();
            if io_uring.submitter().register_probe(&mut probe).is_err() {
                return false;
            }

            Self::REQUIRED_OPCODES
                .iter()
                .all(|&op| probe.is_supported(op))
        }

        pub fn new(entries: usize) -> Result<Self> {
            assert!(entries <= MAX_ENTRIES);

            let io_uring = IoUring::<squeue::Entry, cqueue::Entry>::builder()
                .dontfork()
                .build((2 * entries) as u32)?;

            Ok(Self { io_uring })
        }

        fn do_batch_op<Item, State, Res>(
            &mut self,
            mut batch_op: impl BatchOp<Item, State, Res>,
            fd: BorrowedFd<'_>,
            items: &mut dyn Iterator<Item = Item>,
            results: &mut Vec<Result<Res>>,
        ) -> Result<usize> {
            /// `user_data` of cancel requests, which carry no result.
            const CANCEL_USER_DATA: u64 = 0;
            /// `user_data` of reap-bounding timeouts, which carry no result.
            const TIMEOUT_USER_DATA: u64 = u64::MAX;
            /// Bound of each straggler wait.
            const REAP_TIMEOUT: types::Timespec = types::Timespec::new().nsec(1_000_000);

            let fd = types::Fd(fd.as_raw_fd());

            // Whether each operation must be paired with a cancel request
            // (see `BatchOp::needs_cancel`).  Socket operations carry
            // MSG_DONTWAIT and complete immediately instead, which sidesteps
            // the cancel-miss stall (zipline#117) and halves their SQE usage.
            let needs_cancel = batch_op.needs_cancel();
            let entries_per_op = if needs_cancel { 2 } else { 1 };

            let mut submitted = 0;

            let mut squeue = self.io_uring.submission();

            // The SQ has room for `capacity / entries_per_op` operations, but
            // every per-operation slab (`state_slab`, the socket ops'
            // sockaddr/cmsg slabs, `op_seen`) holds only MAX_ENTRIES.  With
            // needs_cancel the two limits coincide (capacity = 2 * entries,
            // entries <= MAX_ENTRIES); without it (MSG_DONTWAIT socket ops,
            // one SQE each) the ring alone would admit up to 2 * MAX_ENTRIES
            // operations and the (MAX_ENTRIES + 1)-th `Slab::push` would
            // panic.  Clamp to the slab capacity so an over-long backlog
            // comes back as a partial batch instead (zipline#117 review).
            let max_to_submit =
                ((squeue.capacity() - squeue.len()) / entries_per_op).min(MAX_ENTRIES);

            let mut state_slab = Slab::new();

            // Enter the operations into the submission queue.
            while let Some(item) = items.next() {
                if submitted >= max_to_submit {
                    break;
                }

                // Attach a unique identifier to each item in the batch.
                // Needed for canceling the operations, and for identifying their results.
                let user_data = (submitted as u64) + 1;

                // Build the operation entry, and stow any state we need for processing the result.
                let (entry, state) = batch_op.build_op(fd, item, submitted);
                state_slab.push(Some(state));

                // NOTE: ideally we'd use LINK and O_NONBLOCK, but:
                // (a) since all reads from a TUN are "short", LINK treats them as failures,
                // (b) O_NONBLOCK is ignored by io_uring, and
                // (c) RWF_NOWAIT is not supported by TUN devices.
                //
                // So instead (for TUN operations -- socket operations use
                // MSG_DONTWAIT and complete immediately) we must manually
                // cancel all requests which weren't immediately fulfilled
                // (since they otherwise will run asynchronously).  This means
                // we must live with the (rare) possibility that reads after
                // the first which would have blocked actually complete
                // (since we are racing with the TUN device).
                //
                // (Note, even if (b) and (c) were solved, HARDLINK puts us in the same situation.)
                //
                // (Note also that, batch cancellation (which is supported
                // only on newer kernels anyway) only cancels the first item
                // of a linked chain!)

                if needs_cancel {
                    let entries = [
                        entry.user_data(user_data),
                        opcode::AsyncCancel::new(user_data)
                            .build()
                            .user_data(CANCEL_USER_DATA),
                    ];

                    // SAFETY: the buf ptrs are valid for our entire body, and we
                    // are waiting on completion before we exit.
                    unsafe { squeue.push_multiple(&entries) }.unwrap();
                } else {
                    // SAFETY: as above.
                    unsafe { squeue.push(&entry.user_data(user_data)) }.unwrap();
                }
                submitted += 1;
            }

            drop(squeue);

            // Submit the operations.
            //
            // A cancel can return -ENOENT while its operation is still
            // pending in the kernel (e.g. the operation was awoken by a
            // datagram which a sibling operation then consumed, and re-armed
            // its poll).  The old `submit_and_wait(2 * submitted)` here then
            // blocked until unrelated traffic completed the operation --
            // observed as ~600 ms fastpath stalls (zipline#117).
            //
            // So instead: submit without waiting, then reap completions,
            // re-cancelling stragglers with a bounded wait per round until
            // every operation is accounted for.  We must never return with
            // operations in flight (their SQEs point into caller-owned
            // buffers), and with the re-cancel loop the wait for that is
            // bounded; if a straggler never completes we panic explicitly
            // rather than hang.
            self.io_uring.submit()?;

            let results_base = results.len();
            results.reserve(submitted);

            // Number of operation results reaped (identified by user_data 1..=submitted).
            let mut ops_seen = 0usize;
            let mut op_seen = [false; MAX_ENTRIES];
            // Cancels and timeouts submitted vs. reaped: their completions
            // must be drained too, or they would be misread as operation
            // results of a later batch.
            let mut aux_expected = if needs_cancel { submitted } else { 0 };
            let mut aux_seen = 0usize;

            let mut reap_guard = ReapGuard::new();

            loop {
                // Read results from the completion queue.
                for entry in self.io_uring.completion() {
                    let user_data = entry.user_data();

                    if user_data == TIMEOUT_USER_DATA {
                        // The current round's guard timeout has fired (or
                        // was cancelled); only now may the next round start.
                        reap_guard.timeout_reaped();
                        aux_seen += 1;
                        continue;
                    }

                    if user_data == CANCEL_USER_DATA {
                        aux_seen += 1;
                        continue;
                    }

                    // Grab the unique identifier of the operation.
                    let idx = (user_data - 1) as usize;
                    assert!(idx < submitted && !op_seen[idx]);
                    op_seen[idx] = true;
                    ops_seen += 1;

                    let result = entry.result();

                    if result == -libc::ECANCELED {
                        // This operation was cancelled.  Don't append to `results`,
                        // under the assumption that the remainder of operations were
                        // cancelled as well.
                        //
                        // Note though that, because io_uring processing is racing
                        // against the rest of the system, and we are unable to use
                        // linking to stop processing at the first error for the reasons
                        // above, we may see successful operations after cancelled ones.
                        // So we must `continue` here, and not `break`.
                        // Filling in the gaps in the `results` vector is handled below.

                        continue;
                    }

                    if idx >= results.len() - results_base {
                        // Note that results may come out of order (cancellation, and
                        // completion itself, are asynchronous).  So, fill skipped-over
                        // results with EWOULDBLOCK.

                        results.resize_with(results_base + idx + 1, || {
                            Err(std::io::Error::from_raw_os_error(libc::EWOULDBLOCK))
                        });
                    }

                    // Translate the result.
                    results[results_base + idx] = if result < 0 {
                        Err(std::io::Error::from_raw_os_error(-result))
                    } else {
                        Ok(batch_op.process_result(
                            idx,
                            state_slab.get_mut(idx).take().unwrap(),
                            result as usize,
                        ))
                    };
                }

                if ops_seen == submitted && aux_seen == aux_expected {
                    break;
                }

                // Some operations (or cancels/timeouts) are still in flight:
                // either a cancel missed (-ENOENT with the operation still
                // pending), or -- for socket operations, as defense-in-depth
                // -- an operation did not complete immediately despite
                // MSG_DONTWAIT.  Re-cancel every unaccounted-for operation
                // and wait again, bounded by a timeout so this loop can never
                // block waiting for traffic.
                //
                // A round is gated on its guard timeout's CQE (see
                // `ReapGuard`): a wakeup caused by anything else -- e.g. a
                // re-cancel promptly completing with -ENOENT while its
                // operation is still pending -- neither consumes a round nor
                // submits more work, so MAX_REAP_ROUNDS really bounds the
                // wait at ~MAX_REAP_ROUNDS * REAP_TIMEOUT and at most one
                // guard timeout is outstanding at a time.
                if reap_guard.try_start_round() {
                    assert!(
                        reap_guard.rounds() <= MAX_REAP_ROUNDS,
                        "io_uring batch operation never completed: \
                         {} of {} operations (and {} of {} cancels/timeouts) reaped \
                         after {} re-cancel rounds",
                        ops_seen,
                        submitted,
                        aux_seen,
                        aux_expected,
                        reap_guard.rounds() - 1,
                    );

                    let mut squeue = self.io_uring.submission();
                    for (idx, seen) in op_seen.iter().enumerate().take(submitted) {
                        if !seen {
                            let cancel = opcode::AsyncCancel::new((idx as u64) + 1)
                                .build()
                                .user_data(CANCEL_USER_DATA);
                            // SAFETY: cancel entries reference no caller memory.
                            unsafe { squeue.push(&cancel) }.unwrap();
                            aux_expected += 1;
                        }
                    }
                    let timeout = opcode::Timeout::new(&REAP_TIMEOUT)
                        .build()
                        .user_data(TIMEOUT_USER_DATA);
                    // SAFETY: REAP_TIMEOUT is 'static.
                    unsafe { squeue.push(&timeout) }.unwrap();
                    aux_expected += 1;
                    drop(squeue);
                }

                self.io_uring.submit_and_wait(1)?;
            }

            Ok(results.len() - results_base)
        }
    }

    impl BatchIoImpl for BatchIo {
        fn engine_name(&self) -> &'static str {
            Self::ENGINE_NAME
        }

        fn try_write_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = &'a [u8]>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            self.do_batch_op(TryWriteBatchOp::new(), handle.as_fd(), bufs, results)
        }

        fn try_read_buf_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            self.do_batch_op(TryReadBufBatchOp::new(), handle.as_fd(), bufs, results)
        }

        fn try_send_to_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = (&'a [u8], SocketAddr, SendFlags)>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            self.do_batch_op(
                TrySendToBatchOp::new(),
                handle.as_fd(),
                &mut bufs.map(|(buf, addr, flags)| (buf, addr, flags.bits())),
                results,
            )
        }

        fn try_send_to_from_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = (&'a [u8], SocketAddr, Option<ScopedIpAddr>, SendFlags)>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            self.do_batch_op(
                TrySendToFromBatchOp::new(),
                handle.as_fd(),
                &mut bufs.map(|(buf, dst, src, flags)| (buf, dst, src, flags.bits())),
                results,
            )
        }

        fn try_recv_buf_from_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
            results: &mut Vec<Result<ReceivedPacket>>,
        ) -> Result<usize> {
            self.do_batch_op(TryRecvBufFromBatchOp::new(), handle.as_fd(), bufs, results)
        }

        fn try_recv_buf_from_to_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
            results: &mut Vec<Result<ReceivedPacket>>,
        ) -> Result<usize> {
            self.do_batch_op(
                TryRecvBufFromToBatchOp::new(),
                handle.as_fd(),
                bufs,
                results,
            )
        }
    }

    fn slice_as_iovec(buf: &[u8]) -> libc::iovec {
        libc::iovec {
            iov_base: buf.as_ptr() as *mut u8 as *mut _,
            iov_len: buf.len(),
        }
    }

    #[cfg(test)]
    mod reap_guard_tests {
        use super::*;

        #[test]
        fn test_prompt_cancel_completions_do_not_burn_reap_rounds() {
            // zipline#117 review (PR #43): if a straggler operation stays
            // pending while each re-cancel promptly completes with -ENOENT,
            // submit_and_wait(1) is satisfied by the cancel CQE rather than
            // the 1 ms guard timeout.  Such wakeups must not consume reap
            // rounds (or MAX_REAP_ROUNDS burns out in far less than the
            // documented ~5 s and the loop panics in the very cancel-miss
            // condition it tolerates), and must not enqueue additional
            // guard timeouts.  A round may only advance once the previous
            // round's timeout CQE has been reaped.
            let mut guard = ReapGuard::new();

            assert!(guard.try_start_round(), "first round must start");
            assert_eq!(guard.rounds(), 1);

            // Many wakeups within the round (prompt -ENOENT cancel
            // completions), no timeout CQE reaped: no new round, no new
            // timeout submission.
            for _ in 0..10 * MAX_REAP_ROUNDS {
                assert!(
                    !guard.try_start_round(),
                    "a wakeup without a reaped guard-timeout CQE must not \
                     start a new round (or submit another timeout)"
                );
            }
            assert_eq!(
                guard.rounds(),
                1,
                "wakeups without timeout CQEs must not consume reap rounds"
            );

            // Only a reaped guard-timeout CQE lets the next round start,
            // so rounds advance at REAP_TIMEOUT cadence and MAX_REAP_ROUNDS
            // really bounds the wait at ~MAX_REAP_ROUNDS * REAP_TIMEOUT.
            guard.timeout_reaped();
            assert!(guard.try_start_round());
            assert_eq!(guard.rounds(), 2);
        }
    }

    fn buf_mut_as_iovec(buf: &mut dyn BufMut) -> libc::iovec {
        let chunk = buf.chunk_mut();
        libc::iovec {
            iov_base: chunk.as_mut_ptr() as *mut _,
            iov_len: chunk.len(),
        }
    }

    /// SAFETY: `msg` be initialized, and its cmsgs must outlive the returned iterator
    unsafe fn cmsg_iter(msg: &libc::msghdr) -> CmsgIterator<'_> {
        CmsgIterator(msg, std::ptr::null())
    }

    struct CmsgIterator<'a>(&'a libc::msghdr, *const libc::cmsghdr);

    impl Iterator for CmsgIterator<'_> {
        type Item = NonNull<libc::cmsghdr>;

        fn next(&mut self) -> Option<Self::Item> {
            let next;
            if self.1.is_null() {
                // SAFETY: we were constructed with a valid `msghdr`
                next = unsafe { libc::CMSG_FIRSTHDR(self.0) };
            } else {
                // SAFETY: we were constructed with a valid `msghdr`, and the `cmsghdr` is nonnull and came from a previous call
                next = unsafe { libc::CMSG_NXTHDR(self.0, self.1) };
            }

            self.1 = next;

            NonNull::new(next)
        }
    }

    /// SAFETY: `cmsg` has enough space for an `in_pktinfo` or `in6_pktinfo` message
    unsafe fn scoped_ip_addr_to_cmsg(cmsg: NonNull<libc::cmsghdr>, addr: ScopedIpAddr) -> usize {
        let in_pktinfo;
        let in6_pktinfo;
        let pktinfo_ptr;
        let pktinfo_len;

        match &addr {
            ScopedIpAddr::V4(addr) => {
                in_pktinfo = super::pktinfo_from_ipv4addr(addr);
                pktinfo_ptr = &in_pktinfo as *const _ as *const u8;
                pktinfo_len = std::mem::size_of_val(&in_pktinfo);
            }

            ScopedIpAddr::V6(addr) => {
                in6_pktinfo = super::pktinfo_from_scoped_ipv6addr(addr);
                pktinfo_ptr = &in6_pktinfo as *const _ as *const u8;
                pktinfo_len = std::mem::size_of_val(&in6_pktinfo);
            }
        }

        // SAFETY: we were called with a valid `cmsg` with enough space
        unsafe {
            cmsg.write(libc::cmsghdr {
                cmsg_len: libc::CMSG_LEN(pktinfo_len as u32) as usize,
                cmsg_level: libc::IPPROTO_IP,
                cmsg_type: libc::IP_PKTINFO,
            });
            libc::CMSG_DATA(cmsg.as_ptr()).copy_from(pktinfo_ptr, pktinfo_len); // note unaligned (*u8) copy!
            return libc::CMSG_SPACE(pktinfo_len as u32) as usize;
        }
    }

    /// SAFETY: `cmsg` must point to a valid `cmsghdr`
    unsafe fn cmsg_to_scoped_ip_addr(cmsg: *const libc::cmsghdr) -> Option<ScopedIpAddr> {
        // SAFETY: `cmsg` points to a valid cmsg
        let cmsg_ref = unsafe { cmsg.as_ref()? };
        match (cmsg_ref.cmsg_level, cmsg_ref.cmsg_type) {
            (libc::IPPROTO_IP, libc::IP_PKTINFO) => {
                // SAFETY: we know the pointed-to cmsg is valid and of the correct type
                let info = unsafe {
                    (libc::CMSG_DATA(cmsg) as *const libc::in_pktinfo)
                        .as_ref()
                        .unwrap_unchecked()
                };
                Some(ScopedIpAddr::V4(Ipv4Addr::from(u32::from_be(
                    info.ipi_addr.s_addr,
                ))))
            }

            (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
                // SAFETY: we know the pointed-to cmsg is valid and of the correct type
                let info = unsafe {
                    (libc::CMSG_DATA(cmsg) as *const libc::in6_pktinfo)
                        .as_ref()
                        .unwrap_unchecked()
                };
                Some(ScopedIpAddr::V6(ScopedIpv6Addr::new(
                    Ipv6Addr::from(info.ipi6_addr.s6_addr),
                    info.ipi6_ifindex,
                )))
            }

            _ => None,
        }
    }
}

#[cfg(unix)]
mod posix_unbatched {
    //! Unbatched implementation using POSIX primitives.

    use super::*;
    use crate::sys::wait::WaitHandle;
    use bytes::BufMut;
    use nix::cmsg_space;
    use nix::sys::socket::{
        self, ControlMessageOwned, MsgFlags, SockaddrStorage, sockaddr_storage,
    };
    use nix::unistd;
    use std::io::{IoSlice, IoSliceMut, Result};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::os::fd::{AsRawFd, BorrowedFd};
    use zpr_ext::std::mem::slice_assume_init_mut;
    use zpr_utils::net_defs::{ScopedIpAddr, ScopedIpv6Addr};

    pub struct BatchIo {
        cmsg_buffer: Vec<u8>,
    }

    macro_rules! scoped_ip_addr_to_cmsg (
        ($cmsg_id:ident : $addr:expr) => {
            let in_pktinfo;
            let in6_pktinfo;
            let $cmsg_id;
            match $addr {
                zpr_utils::net_defs::ScopedIpAddr::V4(addr) => {
                    in_pktinfo = super::pktinfo_from_ipv4addr(addr);
                    $cmsg_id = nix::sys::socket::ControlMessage::Ipv4PacketInfo(&in_pktinfo);
                },

                zpr_utils::net_defs::ScopedIpAddr::V6(addr) => {
                    in6_pktinfo = super::pktinfo_from_scoped_ipv6addr(addr);
                    $cmsg_id = nix::sys::socket::ControlMessage::Ipv6PacketInfo(&in6_pktinfo);
                },
            }
        }
    );

    impl BatchIo {
        pub const ENGINE_NAME: &'static str = "posix_unbatched";

        pub const MAX_ENTRIES: usize = 1024;

        pub fn detect_support() -> bool {
            // theoretically always available
            true
        }

        pub fn new(_entries: usize) -> Result<Self> {
            Ok(Self {
                cmsg_buffer: cmsg_space!(sockaddr_storage),
            })
        }

        fn do_batch_op<'a, Item, Res>(
            mut op: impl FnMut(BorrowedFd<'a>, Item) -> Result<Res>,
            fd: BorrowedFd<'a>,
            items: &mut dyn Iterator<Item = Item>,
            results: &'a mut Vec<Result<Res>>,
        ) -> Result<usize> {
            let mut completed = 0;
            while let Some(item) = items.next() {
                let res = op(fd, item);
                if let Err(err) = res {
                    // emulate behavior of sendmmsg(2)

                    if completed == 0 {
                        return Err(err);
                    }

                    break;
                }
                results.push(res);
                completed += 1;
            }

            Ok(completed)
        }
    }

    impl BatchIoImpl for BatchIo {
        fn engine_name(&self) -> &'static str {
            Self::ENGINE_NAME
        }

        fn try_write_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = &'a [u8]>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            Self::do_batch_op(
                |fd, buf| unistd::write(fd, buf).map_err(errno_to_error),
                handle.as_fd(),
                bufs,
                results,
            )
        }

        fn try_read_buf_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            Self::do_batch_op(
                |fd, buf| {
                    // SAFETY: We will only be writing to the chunk.
                    let chunk =
                        unsafe { slice_assume_init_mut(buf.chunk_mut().as_uninit_slice_mut()) };
                    let amt = unistd::read(fd.as_raw_fd(), chunk).map_err(errno_to_error)?;
                    // SAFETY: We know we've written the given number of bytes in the BufMut.
                    unsafe { buf.advance_mut(amt as usize) };
                    Ok(amt)
                },
                handle.as_fd(),
                bufs,
                results,
            )
        }

        fn try_send_to_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = (&'a [u8], SocketAddr, SendFlags)>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            Self::do_batch_op(
                |fd, (buf, addr, flags): (_, _, SendFlags)| {
                    socket::sendto(
                        fd.as_raw_fd(),
                        buf,
                        &SockaddrStorage::from(addr),
                        MsgFlags::from_bits_retain(flags.bits()),
                    )
                    .map_err(errno_to_error)
                },
                handle.as_fd(),
                bufs,
                results,
            )
        }

        fn try_send_to_from_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = (&'a [u8], SocketAddr, Option<ScopedIpAddr>, SendFlags)>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            Self::do_batch_op(
                |fd, (buf, dst, src, flags): (_, _, _, SendFlags)| match src {
                    Some(src) => {
                        scoped_ip_addr_to_cmsg!(cmsg: &src);
                        socket::sendmsg(
                            fd.as_raw_fd(),
                            &[IoSlice::new(buf)],
                            &[cmsg],
                            MsgFlags::from_bits_retain(flags.bits()),
                            Some(&SockaddrStorage::from(dst)),
                        )
                        .map_err(errno_to_error)
                    }

                    None => socket::sendto(
                        fd.as_raw_fd(),
                        buf,
                        &SockaddrStorage::from(dst),
                        MsgFlags::from_bits_retain(flags.bits()),
                    )
                    .map_err(errno_to_error),
                },
                handle.as_fd(),
                bufs,
                results,
            )
        }

        fn try_recv_buf_from_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
            results: &mut Vec<Result<ReceivedPacket>>,
        ) -> Result<usize> {
            Self::do_batch_op(
                |fd, buf| {
                    // SAFETY: We will only be writing to the chunk.
                    let chunk =
                        unsafe { slice_assume_init_mut(buf.chunk_mut().as_uninit_slice_mut()) };
                    let mut io_slice = IoSliceMut::new(chunk);
                    // NOTE: nix's `recvfrom` weirdly is missing the `flags` argument,
                    // so we're forced to use `recvmsg` here
                    let recvmsg = socket::recvmsg(
                        fd.as_raw_fd(),
                        std::slice::from_mut(&mut io_slice),
                        None,
                        MsgFlags::empty(),
                    )
                    .map_err(errno_to_error)?;
                    let size = recvmsg.bytes;
                    let truncated = recvmsg.flags.contains(socket::MsgFlags::MSG_TRUNC);
                    let source = recvmsg.address.and_then(sockaddr_to_socket_addr);
                    // SAFETY: We know we've written the given number of bytes in the BufMut.
                    unsafe { buf.advance_mut(size) };
                    Ok(ReceivedPacket {
                        size,
                        truncated,
                        source,
                        destination: None,
                    })
                },
                handle.as_fd(),
                bufs,
                results,
            )
        }

        fn try_recv_buf_from_to_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
            results: &mut Vec<Result<ReceivedPacket>>,
        ) -> Result<usize> {
            Self::do_batch_op(
                |fd, buf| {
                    // SAFETY: We will only be writing to the chunk.
                    let chunk =
                        unsafe { slice_assume_init_mut(buf.chunk_mut().as_uninit_slice_mut()) };
                    let mut io_slice = IoSliceMut::new(chunk);
                    let recvmsg = socket::recvmsg(
                        fd.as_raw_fd(),
                        std::slice::from_mut(&mut io_slice),
                        Some(&mut self.cmsg_buffer),
                        MsgFlags::empty(),
                    )
                    .map_err(errno_to_error)?;
                    let size = recvmsg.bytes;
                    let truncated = recvmsg.flags.contains(socket::MsgFlags::MSG_TRUNC);
                    let source = recvmsg.address.and_then(sockaddr_to_socket_addr);
                    let destination = recvmsg
                        .cmsgs()
                        .expect("cmsgs sizing error")
                        .find_map(cmsg_to_scoped_ip_addr);
                    // SAFETY: We know we've written the given number of bytes in the BufMut.
                    unsafe { buf.advance_mut(size) };
                    Ok(ReceivedPacket {
                        size,
                        truncated,
                        source,
                        destination,
                    })
                },
                handle.as_fd(),
                bufs,
                results,
            )
        }
    }

    fn cmsg_to_scoped_ip_addr(cmsg: ControlMessageOwned) -> Option<ScopedIpAddr> {
        match cmsg {
            ControlMessageOwned::Ipv4PacketInfo(info) => Some(ScopedIpAddr::V4(Ipv4Addr::from(
                u32::from_be(info.ipi_addr.s_addr),
            ))),

            ControlMessageOwned::Ipv6PacketInfo(info) => Some(ScopedIpAddr::V6(
                ScopedIpv6Addr::new(Ipv6Addr::from(info.ipi6_addr.s6_addr), info.ipi6_ifindex),
            )),

            _ => None,
        }
    }
}

/// Startup check behind the Windows substrate bind (zipline#131 PR #52
/// review round 1): the Windows socket half has no per-datagram
/// destination info (no `WSARecvMsg`/`IP_PKTINFO`, plan D5's single-homed
/// ceiling), so a wildcard-bound socket would record the unspecified
/// address as every received packet's interface address and trip the
/// fastpath's `!src_intf.ip().is_unspecified()` assertion on the first
/// response of a new link. Reject the configuration up front with an
/// error that names the fix.
///
/// Portable (and unit tested) on every OS; only the Windows startup path
/// calls it. Note the adapter case is unaffected: a wildcard `self_addr`
/// with a `node_addr` is rebound to the OS-chosen concrete address before
/// this check runs.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn windows_substrate_bind_check(bound: SocketAddr) -> Result<()> {
    if bound.ip().is_unspecified() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "the Windows datapath cannot use a wildcard substrate bind \
                 ({bound}): without per-datagram destination info every \
                 received packet would carry the unspecified address as its \
                 interface address; set self_addr to a concrete local address"
            ),
        ));
    }
    Ok(())
}

/// The socket half of the Windows engine (plan D5): unbatched non-blocking
/// `send`/`recv`/`send_to`/`recv_from` on a `std::net::UdpSocket`.
///
/// std-only, so it compiles — and its unit tests run — on every OS; only
/// the `windows_unbatched` engine calls it at runtime. No
/// `WSARecvMsg`/`IP_PKTINFO`: an end-user adapter is single-homed for our
/// purposes, so the receive path reports the socket's own bound address as
/// the destination, and the send path ignores the caller-chosen source
/// address. Ceiling stated once here for the whole half: multi-homed hosts
/// and address change while running are not handled on Windows.
///
/// Batch semantics mirror `posix_unbatched::do_batch_op` (which emulates
/// `sendmmsg(2)`): the first item's failure is returned as the batch error;
/// a later item's failure ends the batch early with the successes so far.
#[cfg_attr(not(windows), allow(dead_code))]
mod std_udp {
    use super::{ReceivedPacket, SendFlags};
    use bytes::BufMut;
    use std::io::Result;
    use std::net::{SocketAddr, UdpSocket};
    use zpr_ext::std::mem::slice_assume_init_mut;
    use zpr_utils::net_defs::{ScopedIpAddr, ScopedIpv6Addr};

    /// `posix_unbatched::do_batch_op`'s loop shape, on a socket instead of
    /// an fd.
    fn do_batch_op<Item, Res>(
        mut op: impl FnMut(&UdpSocket, Item) -> Result<Res>,
        socket: &UdpSocket,
        items: &mut dyn Iterator<Item = Item>,
        results: &mut Vec<Result<Res>>,
    ) -> Result<usize> {
        let mut completed = 0;
        for item in items {
            let res = op(socket, item);
            if let Err(err) = res {
                // emulate behavior of sendmmsg(2)
                if completed == 0 {
                    return Err(err);
                }
                break;
            }
            results.push(res);
            completed += 1;
        }
        Ok(completed)
    }

    /// Connected-mode send (the `try_write_batch` leg).
    pub fn send_batch<'a>(
        socket: &UdpSocket,
        bufs: &mut dyn Iterator<Item = &'a [u8]>,
        results: &mut Vec<Result<usize>>,
    ) -> Result<usize> {
        do_batch_op(|socket, buf| socket.send(buf), socket, bufs, results)
    }

    /// Connected-mode receive (the `try_read_buf_batch` leg).
    pub fn recv_batch<'a>(
        socket: &UdpSocket,
        bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
        results: &mut Vec<Result<usize>>,
    ) -> Result<usize> {
        do_batch_op(
            |socket, buf| {
                // SAFETY: We will only be writing to the chunk.
                let chunk = unsafe { slice_assume_init_mut(buf.chunk_mut().as_uninit_slice_mut()) };
                let amt = socket.recv(chunk)?;
                // SAFETY: We know we've written the given number of bytes in the BufMut.
                unsafe { buf.advance_mut(amt) };
                Ok(amt)
            },
            socket,
            bufs,
            results,
        )
    }

    /// Unconnected send to explicit destinations. `SendFlags` carries no
    /// Windows flag bits (`std::net` exposes none), so it is accepted and
    /// ignored.
    pub fn send_to_batch<'a>(
        socket: &UdpSocket,
        bufs: &mut dyn Iterator<Item = (&'a [u8], SocketAddr, SendFlags)>,
        results: &mut Vec<Result<usize>>,
    ) -> Result<usize> {
        do_batch_op(
            |socket, (buf, addr, _flags)| socket.send_to(buf, addr),
            socket,
            bufs,
            results,
        )
    }

    /// Send with a caller-chosen source address: no pktinfo on this half
    /// (plan D5), so the source is ignored and the OS picks as it would for
    /// a plain `send_to` — correct for a single-homed host, the stated
    /// ceiling above.
    pub fn send_to_from_batch<'a>(
        socket: &UdpSocket,
        bufs: &mut dyn Iterator<Item = (&'a [u8], SocketAddr, Option<ScopedIpAddr>, SendFlags)>,
        results: &mut Vec<Result<usize>>,
    ) -> Result<usize> {
        do_batch_op(
            |socket, (buf, dst, _src, _flags)| socket.send_to(buf, dst),
            socket,
            bufs,
            results,
        )
    }

    /// Receive with peer addresses. With `with_dest`, the destination is
    /// the socket's own bound address (no pktinfo — single-homed ceiling
    /// above), resolved once per batch.
    pub fn recv_from_batch<'a>(
        socket: &UdpSocket,
        bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
        results: &mut Vec<Result<ReceivedPacket>>,
        with_dest: bool,
    ) -> Result<usize> {
        let destination = if with_dest {
            Some(local_scoped_addr(socket)?)
        } else {
            None
        };
        do_batch_op(
            |socket, buf| {
                // SAFETY: We will only be writing to the chunk.
                let chunk = unsafe { slice_assume_init_mut(buf.chunk_mut().as_uninit_slice_mut()) };
                match socket.recv_from(chunk) {
                    Ok((size, source)) => {
                        // SAFETY: We know we've written the given number of bytes in the BufMut.
                        unsafe { buf.advance_mut(size) };
                        Ok(ReceivedPacket {
                            size,
                            truncated: false,
                            source: Some(source),
                            destination,
                        })
                    }
                    // Windows reports an oversized datagram as WSAEMSGSIZE
                    // (10040) — the buffer holds the truncated head and the
                    // rest is discarded. Map it to `truncated`, which the
                    // fastpath drops and counts, the same as MSG_TRUNC on
                    // unix. (The peer address is lost with the error; the
                    // truncated path never reads it.)
                    #[cfg(windows)]
                    Err(err) if err.raw_os_error() == Some(10040) => {
                        let size = chunk.len();
                        // SAFETY: WSAEMSGSIZE fills the whole buffer before
                        // failing; it is all initialized.
                        unsafe { buf.advance_mut(size) };
                        Ok(ReceivedPacket {
                            size,
                            truncated: true,
                            source: None,
                            destination,
                        })
                    }
                    Err(err) => Err(err),
                }
            },
            socket,
            bufs,
            results,
        )
    }

    /// The socket's bound address as the `ScopedIpAddr` the fastpath
    /// expects for a packet's destination. A wildcard-bound socket has no
    /// usable destination to report (see `windows_substrate_bind_check`,
    /// the startup rejection this backstops), so it is refused rather
    /// than fabricating the unspecified address the fastpath asserts
    /// against.
    fn local_scoped_addr(socket: &UdpSocket) -> Result<ScopedIpAddr> {
        let local = socket.local_addr()?;
        if local.ip().is_unspecified() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "cannot report a destination for a wildcard-bound \
                     socket ({local}); bind to a concrete local address"
                ),
            ));
        }
        Ok(match local {
            SocketAddr::V4(a) => ScopedIpAddr::V4(*a.ip()),
            SocketAddr::V6(a) => ScopedIpAddr::V6(ScopedIpv6Addr::new(*a.ip(), a.scope_id())),
        })
    }
}

#[cfg(windows)]
mod windows_unbatched {
    //! Unbatched implementation for Windows (plan D5, zipline#131).
    //!
    //! Socket side: the `std_udp` half (non-blocking `std::net::UdpSocket`,
    //! no pktinfo — see `std_udp`'s module docs for the stated ceiling).
    //! TUN side: the Wintun ring, via `ZprTun::try_receive` /
    //! `ZprTun::send` (`WintunReceivePacket` / `WintunAllocateSendPacket` +
    //! `WintunSendPacket`), which half an operation targets is carried by
    //! the [`WaitTarget`] inside the `WaitHandle`: `read`/`write` reach the
    //! TUN ring, `send_to`/`recv_from` reach the socket.

    use super::{BatchIoImpl, ReceivedPacket, SendFlags, std_udp};
    use crate::sys::wait::{WaitHandle, WaitTarget};
    use bytes::BufMut;
    use std::io::Result;
    use std::net::SocketAddr;
    use zpr_utils::net_defs::ScopedIpAddr;

    pub struct BatchIo {}

    impl BatchIo {
        pub const ENGINE_NAME: &'static str = "windows_unbatched";

        pub const MAX_ENTRIES: usize = 1024;

        pub fn detect_support() -> bool {
            // std sockets and the Wintun ring are always available.
            true
        }

        pub fn new(_entries: usize) -> Result<Self> {
            Ok(Self {})
        }
    }

    /// The socket an I/O op targets; a TUN handle here is a caller bug.
    fn expect_socket<'a>(handle: WaitHandle<'a>, op: &str) -> &'a std::net::UdpSocket {
        match handle.target() {
            WaitTarget::Socket(socket) => socket,
            _ => panic!("windows_unbatched: {op} targets the substrate socket"),
        }
    }

    /// The TUN an I/O op targets; a socket handle here is a caller bug.
    fn expect_tun<'a>(handle: WaitHandle<'a>, op: &str) -> &'a crate::sys::ZprTun {
        match handle.target() {
            WaitTarget::Tun(tun) => tun,
            _ => panic!("windows_unbatched: {op} targets the TUN"),
        }
    }

    /// `std_udp::do_batch_op`'s loop shape for the TUN ring legs.
    fn do_tun_batch_op<Item, Res>(
        mut op: impl FnMut(&crate::sys::ZprTun, Item) -> Result<Res>,
        tun: &crate::sys::ZprTun,
        items: &mut dyn Iterator<Item = Item>,
        results: &mut Vec<Result<Res>>,
    ) -> Result<usize> {
        let mut completed = 0;
        for item in items {
            let res = op(tun, item);
            if let Err(err) = res {
                // emulate behavior of sendmmsg(2), as the other engines do
                if completed == 0 {
                    return Err(err);
                }
                break;
            }
            results.push(res);
            completed += 1;
        }
        Ok(completed)
    }

    impl BatchIoImpl for BatchIo {
        fn engine_name(&self) -> &'static str {
            Self::ENGINE_NAME
        }

        /// TUN egress: commit each packet to the Wintun send ring.
        fn try_write_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = &'a [u8]>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            let tun = expect_tun(handle, "try_write_batch");
            do_tun_batch_op(
                |tun, buf: &[u8]| tun.send(buf).map(|()| buf.len()),
                tun,
                bufs,
                results,
            )
        }

        /// TUN ingress: drain the Wintun receive ring. An empty ring ends
        /// the batch (`WouldBlock` first, per the sendmmsg(2) emulation all
        /// engines share); the fastpath re-arms on the read-wait event.
        fn try_read_buf_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            let tun = expect_tun(handle, "try_read_buf_batch");
            do_tun_batch_op(
                |tun, buf: &mut dyn BufMut| match tun.try_receive()? {
                    Some(packet) => {
                        let body = packet.bytes();
                        // An oversized frame cannot arrive: the ring frame
                        // limit (u16) is far under the packet buffer size.
                        buf.put_slice(body);
                        Ok(body.len())
                    }
                    None => Err(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "Wintun receive ring empty",
                    )),
                },
                tun,
                bufs,
                results,
            )
        }

        fn try_send_to_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = (&'a [u8], SocketAddr, SendFlags)>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            std_udp::send_to_batch(expect_socket(handle, "try_send_to_batch"), bufs, results)
        }

        fn try_send_to_from_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = (&'a [u8], SocketAddr, Option<ScopedIpAddr>, SendFlags)>,
            results: &mut Vec<Result<usize>>,
        ) -> Result<usize> {
            std_udp::send_to_from_batch(
                expect_socket(handle, "try_send_to_from_batch"),
                bufs,
                results,
            )
        }

        fn try_recv_buf_from_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
            results: &mut Vec<Result<ReceivedPacket>>,
        ) -> Result<usize> {
            std_udp::recv_from_batch(
                expect_socket(handle, "try_recv_buf_from_batch"),
                bufs,
                results,
                false,
            )
        }

        fn try_recv_buf_from_to_batch<'a>(
            &mut self,
            handle: WaitHandle<'_>,
            bufs: &mut dyn Iterator<Item = &'a mut dyn BufMut>,
            results: &mut Vec<Result<ReceivedPacket>>,
        ) -> Result<usize> {
            std_udp::recv_from_batch(
                expect_socket(handle, "try_recv_buf_from_to_batch"),
                bufs,
                results,
                true,
            )
        }
    }
}

// The engine registration macro: consumed by every arm of ENGINES.
macro_rules! bio {
    ($m:tt) => {
        BatchIoEngine {
            engine_name: $m::BatchIo::ENGINE_NAME,
            max_entries: $m::BatchIo::MAX_ENTRIES,
            factory: |e| $m::BatchIo::new(e).map(|bio| Box::new(bio) as Box<dyn BatchIoImpl>),
            detect_support: $m::BatchIo::detect_support,
        }
    };
}

const ENGINES: &[BatchIoEngine] = &[
    #[cfg(all(target_os = "linux", feature = "io-uring"))]
    bio!(io_uring),
    #[cfg(unix)]
    bio!(posix_unbatched),
    #[cfg(windows)]
    bio!(windows_unbatched),
];

/// List of available engine names.  Does not include automatic selection.
pub fn engine_names() -> impl Iterator<Item = &'static str> {
    ENGINES.iter().map(|e| e.engine_name)
}

/// "Engine" name which indicates an engine should be selected automatically
/// (as by `auto_select_engine()`).
pub const AUTO_ENGINE_NAME: &'static str = "auto";

/// Select an engine by name (as listed by `engine_names()`).
/// Supplying `AUTO_ENGINE_NAME` will use automatic selection
/// (as by `auto_select_engine()`).
pub fn select_engine_by_name(name: &str) -> Option<&'static BatchIoEngine> {
    if name == AUTO_ENGINE_NAME {
        Some(auto_select_engine())
    } else {
        ENGINES.iter().find(|e| e.engine_name == name)
    }
}

/// Select the best engine which is available on the current system.
pub fn auto_select_engine() -> &'static BatchIoEngine {
    ENGINES
        .iter()
        .find(|e| e.detect_support())
        .expect("no supported I/O engines!")
}

/// Represents an available batch I/O engine which may be instantiated.
pub struct BatchIoEngine {
    engine_name: &'static str,
    max_entries: usize,
    factory: fn(usize) -> Result<Box<dyn BatchIoImpl>>,
    detect_support: fn() -> bool,
}

impl BatchIoEngine {
    /// The name of this I/O engine.
    pub fn engine_name(&self) -> &'static str {
        self.engine_name
    }

    /// The maximum number of entries per batch this I/O engine supports.
    #[allow(dead_code)]
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Instantiate this batch I/O engine,
    /// supporting the supplied number of entries per batch.
    pub fn instantiate(&self, entries: usize) -> Result<BatchIo> {
        Ok(BatchIo((self.factory)(entries)?))
    }

    /// Detect whether this engine is supported by the host environment.
    pub fn detect_support(&self) -> bool {
        (self.detect_support)()
    }
}

pub struct BatchIo(Box<dyn BatchIoImpl>);

impl BatchIo {
    #[allow(dead_code)]
    pub fn engine_name(&self) -> &'static str {
        self.0.engine_name()
    }

    pub fn try_write_batch<'a>(
        &mut self,
        fd: impl AsWaitSource,
        bufs: impl IntoIterator<Item = &'a [u8]>,
        results: &mut Vec<Result<usize>>,
    ) -> Result<usize> {
        self.0
            .try_write_batch(fd.as_wait_handle(), &mut bufs.into_iter(), results)
    }

    pub fn try_read_buf_batch<'a, B>(
        &mut self,
        fd: impl AsWaitSource,
        bufs: impl IntoIterator<Item = &'a mut B>,
        results: &mut Vec<Result<usize>>,
    ) -> Result<usize>
    where
        B: BufMut + 'a,
    {
        self.0.try_read_buf_batch(
            fd.as_wait_handle(),
            &mut bufs.into_iter().map(|b| b as &mut dyn BufMut),
            results,
        )
    }

    #[allow(dead_code)]
    pub fn try_send_to_batch<'a>(
        &mut self,
        fd: impl AsWaitSource,
        bufs: impl IntoIterator<Item = (&'a [u8], SocketAddr, SendFlags)>,
        results: &mut Vec<Result<usize>>,
    ) -> Result<usize> {
        self.0
            .try_send_to_batch(fd.as_wait_handle(), &mut bufs.into_iter(), results)
    }

    pub fn try_send_to_from_batch<'a>(
        &mut self,
        fd: impl AsWaitSource,
        bufs: impl IntoIterator<Item = (&'a [u8], SocketAddr, Option<ScopedIpAddr>, SendFlags)>,
        results: &mut Vec<Result<usize>>,
    ) -> Result<usize> {
        self.0
            .try_send_to_from_batch(fd.as_wait_handle(), &mut bufs.into_iter(), results)
    }

    #[allow(dead_code)]
    pub fn try_recv_buf_from_batch<'a, B>(
        &mut self,
        fd: impl AsWaitSource,
        bufs: impl IntoIterator<Item = &'a mut B>,
        results: &mut Vec<Result<ReceivedPacket>>,
    ) -> Result<usize>
    where
        B: BufMut + 'a,
    {
        self.0.try_recv_buf_from_batch(
            fd.as_wait_handle(),
            &mut bufs.into_iter().map(|b| b as &mut dyn BufMut),
            results,
        )
    }

    pub fn try_recv_buf_from_to_batch<'a, B>(
        &mut self,
        fd: impl AsWaitSource,
        bufs: impl IntoIterator<Item = &'a mut B>,
        results: &mut Vec<Result<ReceivedPacket>>,
    ) -> Result<usize>
    where
        B: BufMut + 'a,
    {
        self.0.try_recv_buf_from_to_batch(
            fd.as_wait_handle(),
            &mut bufs.into_iter().map(|b| b as &mut dyn BufMut),
            results,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BufMut;
    use std::io::Result;
    use std::net::UdpSocket;
    use std::time::Duration;

    #[test]
    fn test_write() {
        for engine in ENGINES {
            // FIXME: we need to test EAGAIN behavior... possibly by first filling queue, then draining a few

            let (inq, outq) = connected_udp_pair().unwrap();
            inq.set_nonblocking(true).unwrap();
            outq.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();

            let nmsgs = 16;

            let mut bio = engine.instantiate(2 * nmsgs).unwrap();

            let mut msgs = Vec::new();

            for i in 0..nmsgs {
                msgs.push(format!("This is message {i}"));
            }

            let mut results = Vec::new();

            let n = bio.try_write_batch(&inq, msgs.iter().map(|msg| msg.as_bytes()), &mut results);
            assert!(n.unwrap() >= nmsgs);

            for i in 0..nmsgs {
                assert_eq!(*results[i].as_ref().unwrap(), msgs[i].len());
            }

            let mut buf = [0u8; 256];
            for i in 0..nmsgs {
                let msg_size = outq.recv(&mut buf).unwrap();
                assert_eq!(msgs[i].as_bytes(), &buf[..msg_size]);
            }
        }
    }

    #[test]
    fn test_read() {
        for engine in ENGINES {
            let (inq, outq) = connected_udp_pair().unwrap();
            inq.set_nonblocking(true).unwrap();
            outq.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();

            let nmsgs = 16;

            let mut bio = engine.instantiate(2 * nmsgs).unwrap();

            let mut msgs = Vec::new();

            for i in 0..nmsgs {
                msgs.push(format!("This is message {i}"));
            }

            for msg in &msgs {
                let _ = inq.send(msg.as_bytes()).unwrap();
            }

            let mut bufs = vec![Vec::with_capacity(64); 2 * nmsgs];
            let mut results = Vec::new();

            let n = bio.try_read_buf_batch(&outq, bufs.iter_mut(), &mut results);
            assert!(n.unwrap() >= nmsgs);

            for i in 0..nmsgs {
                assert_eq!(*results[i].as_ref().unwrap(), msgs[i].len());
                assert_eq!(bufs[i].as_slice(), msgs[i].as_bytes());
            }
        }
    }

    #[test]
    fn test_send() {
        for engine in ENGINES {
            // FIXME: we need to test EAGAIN behavior... possibly by first filling queue, then draining a few

            let inq = udp_socket().unwrap();
            let outq = udp_socket().unwrap();
            inq.set_nonblocking(true).unwrap();
            outq.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();

            let nmsgs = 16;

            let mut bio = engine.instantiate(2 * nmsgs).unwrap();

            let mut msgs = Vec::new();

            for i in 0..nmsgs {
                msgs.push(format!("This is message {i}"));
            }

            let mut results = Vec::new();

            let dest = outq.local_addr().unwrap();

            let n = bio.try_send_to_batch(
                &inq,
                msgs.iter()
                    .map(|msg| (msg.as_bytes(), dest, SendFlags::none())),
                &mut results,
            );
            assert!(n.unwrap() >= nmsgs);

            for i in 0..nmsgs {
                assert_eq!(*results[i].as_ref().unwrap(), msgs[i].len());
            }

            let mut buf = [0u8; 256];
            for i in 0..nmsgs {
                let msg_size = outq.recv(&mut buf).unwrap();
                assert_eq!(msgs[i].as_bytes(), &buf[..msg_size]);
            }
        }
    }

    #[test]
    fn test_recv() {
        for engine in ENGINES {
            let inq = udp_socket().unwrap();
            let outq = udp_socket().unwrap();
            inq.set_nonblocking(true).unwrap();
            outq.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            inq.connect(outq.local_addr().unwrap()).unwrap();

            let nmsgs = 16;

            let mut bio = engine.instantiate(2 * nmsgs).unwrap();

            let mut msgs = Vec::new();

            for i in 0..nmsgs {
                msgs.push(format!("This is message {i}"));
            }

            for msg in &msgs {
                let _ = inq.send(msg.as_bytes()).unwrap();
            }

            let mut bufs = vec![Vec::with_capacity(64); 2 * nmsgs];
            let mut results = Vec::new();

            let n = bio.try_recv_buf_from_batch(&outq, bufs.iter_mut(), &mut results);
            assert!(n.unwrap() >= nmsgs);

            let sender = inq.local_addr().unwrap();

            for i in 0..nmsgs {
                let res = results[i].as_ref().unwrap();
                assert_eq!(res.size, msgs[i].len());
                assert!(!res.truncated);
                assert_eq!(res.source, Some(sender));
                assert_eq!(bufs[i].as_slice(), msgs[i].as_bytes());
            }
        }
    }

    #[test]
    fn test_oversize_recv() {
        for engine in ENGINES {
            let inq = udp_socket().unwrap();
            let outq = udp_socket().unwrap();
            inq.set_nonblocking(true).unwrap();
            outq.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            inq.connect(outq.local_addr().unwrap()).unwrap();

            let mut bio = engine.instantiate(1).unwrap();

            let msg = [123u8; 128];

            let _ = inq.send(&[123u8; 128]).unwrap();

            let limit = 64;
            let mut buf = Vec::with_capacity(64).limit(limit);
            let mut results = Vec::new();

            let n = bio.try_recv_buf_from_batch(&outq, std::iter::once(&mut buf), &mut results);
            assert!(n.unwrap() == 1);

            let res = results[0].as_ref().unwrap();
            assert_eq!(res.size, limit);
            assert!(res.truncated);
            assert_eq!(buf.get_ref().len(), limit);
            assert_eq!(buf.get_ref().as_slice(), &msg[..limit]);
        }
    }

    #[test]
    fn test_recv_to() {
        for engine in ENGINES {
            let inq = udp_socket().unwrap();
            let outq = udp_socket().unwrap();
            inq.set_nonblocking(true).unwrap();
            outq.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            set_recv_packet_info(&outq, true).unwrap();
            inq.connect(outq.local_addr().unwrap()).unwrap();

            let mut bio = engine.instantiate(1).unwrap();

            let msg = "Hello".as_bytes();

            let _ = inq.send(msg).unwrap();

            let mut buf = Vec::with_capacity(64);
            let mut results = Vec::new();

            let n = bio.try_recv_buf_from_to_batch(&outq, std::iter::once(&mut buf), &mut results);
            assert!(n.unwrap() == 1);

            let res = results[0].as_ref().unwrap();
            assert_eq!(res.size, msg.len());
            assert!(!res.truncated);
            assert_eq!(res.source, Some(inq.local_addr().unwrap()));
            // NOTE: we don't have any way of testing the scope ID functionality as a unit test
            assert_eq!(
                res.destination.map(|sa| sa.ip()),
                Some(outq.local_addr().unwrap().ip())
            );
            assert_eq!(buf.as_slice(), msg);
        }
    }

    #[test]
    fn test_oversize_recv_to() {
        for engine in ENGINES {
            let inq = udp_socket().unwrap();
            let outq = udp_socket().unwrap();
            inq.set_nonblocking(true).unwrap();
            outq.set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            inq.connect(outq.local_addr().unwrap()).unwrap();

            let mut bio = engine.instantiate(1).unwrap();

            let msg = [123u8; 128];

            let _ = inq.send(&[123u8; 128]).unwrap();

            let limit = 64;
            let mut buf = Vec::with_capacity(64).limit(limit);
            let mut results = Vec::new();

            let n = bio.try_recv_buf_from_to_batch(&outq, std::iter::once(&mut buf), &mut results);
            assert!(n.unwrap() == 1);

            let res = results[0].as_ref().unwrap();
            assert_eq!(res.size, limit);
            assert!(res.truncated);
            assert_eq!(buf.get_ref().len(), limit);
            assert_eq!(buf.get_ref().as_slice(), &msg[..limit]);
        }
    }

    // NOTE: we don't have any way of really testing the "send_from" functionality as a unit test

    #[test]
    fn test_send_backlog_over_slab_capacity() {
        // zipline#117 review (PR #43): with MSG_DONTWAIT socket operations
        // (needs_cancel == false) each operation occupies a single SQE, so
        // the submission limit derived from the ring capacity (2 * entries)
        // can exceed MAX_ENTRIES -- but the state slab, the per-op sockaddr
        // slabs and `op_seen` all hold only MAX_ENTRIES.  A backlog larger
        // than MAX_ENTRIES must come back as a partial batch (like the old
        // `/ 2` limit produced), not panic on the (MAX_ENTRIES + 1)-th push.
        for engine in ENGINES {
            let inq = udp_socket().unwrap();
            let outq = udp_socket().unwrap();
            inq.set_nonblocking(true).unwrap();
            let dest = outq.local_addr().unwrap();

            let max = engine.max_entries();
            let nmsgs = max + max / 2;

            // Instantiate at the engine's advertised maximum, the
            // configuration under which the limit overshoots the slabs.
            let mut bio = engine.instantiate(max).unwrap();

            let msg = [42u8; 8];
            let mut results = Vec::new();

            let n = bio
                .try_send_to_batch(
                    &inq,
                    (0..nmsgs).map(|_| (&msg[..], dest, SendFlags::none())),
                    &mut results,
                )
                .unwrap();

            assert!(
                n >= 1 && n <= nmsgs,
                "[{}] expected a (possibly partial) batch, got {n} of {nmsgs}",
                engine.engine_name()
            );

            if engine.engine_name() == "io_uring" {
                // The io_uring engine must clamp the batch to its slab
                // capacity and return the remainder to the caller.
                assert_eq!(
                    n, max,
                    "[io_uring] a backlog over the slab capacity must return \
                     a partial batch of exactly the slab capacity"
                );
            }
        }
    }

    #[test]
    fn test_recv_stress_no_stall() {
        // zipline#117: a batch receive on an empty or partly-filled socket
        // must never block the calling thread waiting for traffic that has
        // not arrived.
        //
        // On the io_uring engine, each batch op was paired with an
        // AsyncCancel and the engine waited for every completion, relying on
        // each cancel finding its op.  A cancel can return -ENOENT while its
        // op is still pending (e.g. the op was woken by a datagram that a
        // sibling op then consumed, and re-armed its poll), leaving
        // submit_and_wait() blocked until the next unrelated datagram
        // completes the op -- observed as ~600 ms fastpath stalls in the
        // netns integration tier.
        //
        // Reproduce: the sender sends sequenced datagrams one at a time at
        // randomized sub-millisecond offsets while the receiver busy-loops
        // 64-op batch receives on the otherwise empty socket, so datagrams
        // keep arriving inside the submit/cancel window.  The receiver acks
        // each newly-seen datagram; the sender sends the next only on an
        // ack, or after GAP if the ack never comes (i.e. the receiver is
        // blocked inside a batch call).  A stalled call is thus always
        // unblocked by a later datagram, its duration is measured, and no
        // datagram can paper over a preceding one's stall.  Any batch call
        // taking STALL or longer fails the test, as does any datagram that
        // is never returned.

        const BATCH: usize = 64;
        const NDATAGRAMS: u64 = 1000;
        const STALL: Duration = Duration::from_millis(50);
        const GAP: Duration = Duration::from_millis(100);
        const HEARTBEAT: u64 = u64::MAX;

        // Iterate posix_unbatched (the control engine) first, so an io_uring
        // failure does not mask its result.
        for engine in ENGINES.iter().rev() {
            let engine_name = engine.engine_name();

            let inq = udp_socket().unwrap();
            let outq = udp_socket().unwrap();
            inq.set_nonblocking(true).unwrap();
            outq.set_nonblocking(true).unwrap();
            inq.connect(outq.local_addr().unwrap()).unwrap();

            let mut bio = engine.instantiate(BATCH).unwrap();

            let (ack_tx, ack_rx) = std::sync::mpsc::channel::<()>();
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

            let sender_stop = stop.clone();
            let sender = std::thread::spawn(move || {
                let mut rng = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .subsec_nanos() as u64
                    | 1;

                let mut seq = 0u64;
                while seq < NDATAGRAMS {
                    // One datagram at a randomized sub-millisecond offset, to
                    // land it at an arbitrary point of the receiver's batch
                    // calls; then wait for its ack before the next, so that a
                    // stall shows up as a >= GAP batch call instead of being
                    // cut short by the following datagram.
                    std::thread::sleep(Duration::from_micros(xorshift(&mut rng) % 700));
                    inq.send(&seq.to_le_bytes()).unwrap();
                    seq += 1;
                    let _ = ack_rx.recv_timeout(GAP);
                }

                // Keep the receiver unblockable while it drains the last
                // bursts: a stalled batch call only returns when the next
                // datagram arrives.
                while !sender_stop.load(std::sync::atomic::Ordering::Relaxed) {
                    inq.send(&HEARTBEAT.to_le_bytes()).unwrap();
                    std::thread::sleep(GAP);
                }
            });

            let mut seen = vec![false; NDATAGRAMS as usize];
            let mut nseen = 0usize;
            let mut max_elapsed = Duration::ZERO;
            let mut bufs = vec![Vec::with_capacity(64); BATCH];
            let mut results = Vec::new();
            let deadline = std::time::Instant::now() + Duration::from_secs(120);

            while nseen < NDATAGRAMS as usize {
                assert!(
                    std::time::Instant::now() < deadline,
                    "[{engine_name}] lost datagram(s): only {nseen} of {NDATAGRAMS} received"
                );

                bufs.iter_mut().for_each(|b| b.clear());
                results.clear();

                let start = std::time::Instant::now();
                match bio.try_recv_buf_from_batch(&outq, bufs.iter_mut(), &mut results) {
                    Ok(_) => (),
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => (),
                    Err(err) => panic!("[{engine_name}] batch receive failed: {err}"),
                }
                let elapsed = start.elapsed();
                max_elapsed = max_elapsed.max(elapsed);

                assert!(
                    elapsed < STALL,
                    "[{engine_name}] batch receive blocked for {elapsed:?} (>= {STALL:?}) \
                     after {nseen} of {NDATAGRAMS} datagrams: an operation was left in \
                     flight and the engine waited for traffic that had not arrived"
                );

                for (buf, result) in bufs.iter().zip(results.drain(..)) {
                    let Ok(packet) = result else { continue };
                    assert_eq!(packet.size, 8, "[{engine_name}] short datagram");
                    let seq = u64::from_le_bytes(buf[..8].try_into().unwrap());
                    if seq == HEARTBEAT || seq as usize >= seen.len() {
                        continue;
                    }
                    if !seen[seq as usize] {
                        seen[seq as usize] = true;
                        nseen += 1;
                        let _ = ack_tx.send(());
                    }
                }
            }

            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            sender.join().unwrap();

            println!(
                "engine {engine_name}: received all {NDATAGRAMS} datagrams, \
                 max batch call {max_elapsed:?}"
            );
        }
    }

    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    /// The Windows engine's socket half (`std_udp`, plan D5) is std-only,
    /// so it compiles and runs on every OS: send a batch from one localhost
    /// socket to another, receive it back, and check payloads and peer
    /// addresses (zipline#131 step 1).
    #[test]
    fn test_windows_socket_half_send_to_recv_from_to() {
        let sender = udp_socket().unwrap();
        let receiver = udp_socket().unwrap();
        sender.set_nonblocking(true).unwrap();
        receiver.set_nonblocking(true).unwrap();

        let dest = receiver.local_addr().unwrap();
        let nmsgs = 16;
        let msgs: Vec<String> = (0..nmsgs).map(|i| format!("This is message {i}")).collect();

        // Send the batch.
        let mut send_results = Vec::new();
        let n = std_udp::send_to_batch(
            &sender,
            &mut msgs
                .iter()
                .map(|msg| (msg.as_bytes(), dest, SendFlags::none())),
            &mut send_results,
        )
        .unwrap();
        assert_eq!(n, nmsgs);
        for (i, res) in send_results.iter().enumerate() {
            assert_eq!(*res.as_ref().unwrap(), msgs[i].len());
        }

        // Receive it back, with the destination (the receiver's own bound
        // address: the socket half has no pktinfo, plan D5).
        let mut bufs = vec![Vec::with_capacity(64); nmsgs];
        let mut recv_results = Vec::new();
        let mut nrecv = 0;
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while nrecv < nmsgs {
            assert!(
                std::time::Instant::now() < deadline,
                "datagrams lost: got {nrecv} of {nmsgs}"
            );
            match std_udp::recv_from_batch(
                &receiver,
                &mut bufs[nrecv..].iter_mut().map(|b| b as &mut dyn BufMut),
                &mut recv_results,
                true,
            ) {
                Ok(n) => nrecv += n,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(err) => panic!("batch receive failed: {err}"),
            }
        }

        let sender_addr = sender.local_addr().unwrap();
        let expect_dest = match receiver.local_addr().unwrap() {
            std::net::SocketAddr::V4(a) => ScopedIpAddr::V4(*a.ip()),
            std::net::SocketAddr::V6(a) => ScopedIpAddr::V6(
                zpr_utils::net_defs::ScopedIpv6Addr::new(*a.ip(), a.scope_id()),
            ),
        };
        for (i, res) in recv_results.iter().enumerate() {
            let packet = res.as_ref().unwrap();
            assert_eq!(packet.size, msgs[i].len());
            assert!(!packet.truncated);
            assert_eq!(packet.source, Some(sender_addr), "wrong peer address");
            assert_eq!(
                packet.destination,
                Some(expect_dest),
                "destination must be the receiver's bound address"
            );
            assert_eq!(bufs[i].as_slice(), msgs[i].as_bytes());
        }
    }

    /// The socket half's connected-mode `send`/`recv` legs (the shape the
    /// generic engine tests use `try_write_batch`/`try_read_buf_batch` in),
    /// portable for the same reason as above.
    #[test]
    fn test_windows_socket_half_send_recv_connected() {
        let (inq, outq) = connected_udp_pair().unwrap();
        inq.set_nonblocking(true).unwrap();
        outq.set_nonblocking(true).unwrap();

        let nmsgs = 16;
        let msgs: Vec<String> = (0..nmsgs).map(|i| format!("This is message {i}")).collect();

        let mut send_results = Vec::new();
        let n = std_udp::send_batch(
            &inq,
            &mut msgs.iter().map(|msg| msg.as_bytes()),
            &mut send_results,
        )
        .unwrap();
        assert_eq!(n, nmsgs);

        let mut bufs = vec![Vec::with_capacity(64); nmsgs];
        let mut recv_results = Vec::new();
        let mut nrecv = 0;
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while nrecv < nmsgs {
            assert!(
                std::time::Instant::now() < deadline,
                "datagrams lost: got {nrecv} of {nmsgs}"
            );
            match std_udp::recv_batch(
                &outq,
                &mut bufs[nrecv..].iter_mut().map(|b| b as &mut dyn BufMut),
                &mut recv_results,
            ) {
                Ok(n) => nrecv += n,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(err) => panic!("batch receive failed: {err}"),
            }
        }

        for (i, res) in recv_results.iter().enumerate() {
            assert_eq!(*res.as_ref().unwrap(), msgs[i].len());
            assert_eq!(bufs[i].as_slice(), msgs[i].as_bytes());
        }
    }

    /// zipline#131 PR #52 review round 1 (thread 1): the startup-time
    /// wildcard rejection behind the Windows substrate bind, portable so
    /// it is unit tested on every OS.
    #[test]
    fn test_windows_substrate_bind_check() {
        use std::net::{Ipv4Addr, Ipv6Addr};

        // Concrete addresses pass.
        for addr in [
            SocketAddr::from((Ipv4Addr::LOCALHOST, 7000)),
            SocketAddr::from((Ipv6Addr::LOCALHOST, 7000)),
        ] {
            windows_substrate_bind_check(addr).unwrap();
        }

        // Wildcard addresses are rejected with a clear config error that
        // names the offending address and the config key.
        for addr in [
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 7000)),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 7000)),
        ] {
            let err = windows_substrate_bind_check(addr).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
            let msg = err.to_string();
            assert!(msg.contains("wildcard"), "unhelpful error: {msg}");
            assert!(msg.contains("self_addr"), "unhelpful error: {msg}");
            assert!(
                msg.contains(&addr.to_string()),
                "error must name the address: {msg}"
            );
        }
    }

    /// zipline#131 PR #52 review round 1 (thread 1): the socket half has
    /// no per-datagram destination info (no pktinfo, plan D5), so a
    /// wildcard-bound socket would record the unspecified address as
    /// every received packet's destination — that value flows into
    /// `PeerState::interface_addr` and trips the fastpath's
    /// `!src_intf.ip().is_unspecified()` assertion on the first response.
    /// The `with_dest` receive leg must refuse to fabricate an
    /// unspecified destination, as a backstop behind the startup check.
    #[test]
    fn test_wildcard_bind_recv_with_dest_rejected() {
        let receiver = UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        receiver.set_nonblocking(true).unwrap();
        let sender = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = receiver.local_addr().unwrap().port();
        sender
            .send_to(b"hello", (std::net::Ipv4Addr::LOCALHOST, port))
            .unwrap();

        let mut bufs = vec![Vec::with_capacity(64); 1];
        let mut results: Vec<Result<ReceivedPacket>> = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let err = loop {
            assert!(std::time::Instant::now() < deadline, "datagram lost");
            match std_udp::recv_from_batch(
                &receiver,
                &mut bufs.iter_mut().map(|b| b as &mut dyn BufMut),
                &mut results,
                true,
            ) {
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(err) => break err,
                Ok(_) => {
                    let dest = results[0].as_ref().unwrap().destination;
                    panic!("wildcard-bound receive must fail, got destination {dest:?}");
                }
            }
        };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        let msg = err.to_string();
        assert!(msg.contains("wildcard"), "unhelpful error: {msg}");
    }

    /// Two localhost UDP sockets connected to each other: a portable
    /// stand-in for a datagram socketpair, so the TUN-side `read`/`write`
    /// batch calls can be exercised without AF_UNIX (zipline#129).
    fn connected_udp_pair() -> Result<(UdpSocket, UdpSocket)> {
        let a = udp_socket()?;
        let b = udp_socket()?;
        a.connect(b.local_addr()?)?;
        b.connect(a.local_addr()?)?;
        Ok((a, b))
    }

    fn udp_socket() -> Result<UdpSocket> {
        UdpSocket::bind(std::net::SocketAddrV6::new(
            std::net::Ipv6Addr::LOCALHOST,
            0,
            0,
            0,
        ))
    }
}
