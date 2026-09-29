//! Waiting for readiness on multiple OS objects.
//!
//! This is the platform seam for the fastpath's readiness wait (master plan
//! `docs/plans/2026-09-28-windows.md`, task C1; umbrella zipline#126). On
//! unix a [`WaitHandle`] wraps a [`BorrowedFd`] and [`WaitSet::wait`] is
//! `poll(2)`; a future Windows arm (zipline#130) wraps a HANDLE and waits
//! with `WaitForMultipleObjects`. Only the unix arm exists today; like
//! `sys::posix::notify`, the module is deliberately not `cfg`-gated —
//! gating is zipline#130's job.

use nix::poll;
use std::io::Result;
use std::ops::BitOr;
use std::os::fd::BorrowedFd;
use std::time::Duration;

/// An opaque handle to an OS object whose readiness can be awaited in a
/// [`WaitSet`].
///
/// On unix this wraps a [`BorrowedFd`]; it carries the same lifetime, so a
/// `WaitHandle` can never outlive the object it watches.
#[derive(Clone, Copy, Debug)]
pub struct WaitHandle<'a>(BorrowedFd<'a>);

impl<'a> WaitHandle<'a> {
    /// The underlying file descriptor (unix arm only).
    pub(crate) fn as_fd(&self) -> BorrowedFd<'a> {
        self.0
    }
}

impl<'a> From<BorrowedFd<'a>> for WaitHandle<'a> {
    fn from(fd: BorrowedFd<'a>) -> Self {
        Self(fd)
    }
}

/// Something whose readiness can be awaited in a [`WaitSet`].
pub trait Waitable {
    /// The handle to register with a [`WaitSet`].
    fn handle(&self) -> WaitHandle<'_>;
}

/// The kind(s) of readiness a [`WaitSet`] entry is interested in.
///
/// `NONE` registers the entry without asking for any events (mirroring an
/// empty `PollFlags`, which the fastpath uses to park a source it currently
/// has no buffers for).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interest(u8);

impl Interest {
    /// No events. The entry occupies a slot but cannot become ready.
    pub const NONE: Self = Self(0);
    /// Readable (unix: `POLLIN`).
    pub const READ: Self = Self(1);
    /// Writable (unix: `POLLOUT`).
    pub const WRITE: Self = Self(2);

    /// The unix `poll(2)` events these interests correspond to.
    fn poll_flags(self) -> poll::PollFlags {
        let mut flags = poll::PollFlags::empty();
        if self.0 & Self::READ.0 != 0 {
            flags |= poll::PollFlags::POLLIN;
        }
        if self.0 & Self::WRITE.0 != 0 {
            flags |= poll::PollFlags::POLLOUT;
        }
        flags
    }
}

impl BitOr for Interest {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// Which entries of a [`WaitSet`] became ready, by the index `push` returned.
///
/// Owned (no borrow of the `WaitSet`), so the set can be dropped — releasing
/// its borrows of the watched objects — before the results are acted on.
#[derive(Clone, Copy, Debug, Default)]
pub struct Ready {
    readable: u32,
    writable: u32,
}

impl Ready {
    /// Whether the entry at `index` reported readable (unix: `POLLIN`).
    pub fn is_readable(&self, index: usize) -> bool {
        self.readable & (1 << index) != 0
    }

    /// Whether the entry at `index` reported writable (unix: `POLLOUT`).
    pub fn is_writable(&self, index: usize) -> bool {
        self.writable & (1 << index) != 0
    }
}

/// A set of [`WaitHandle`]s to wait on simultaneously.
///
/// Entries are registered with [`push`](Self::push), which returns the index
/// [`wait`](Self::wait)'s [`Ready`] result reports that entry under. A set is
/// cheap to build and is typically rebuilt for every wait, because interests
/// change between iterations (see `fastpath_worker`).
///
/// At most 32 entries per set (the `Ready` bitmask width); `push` panics
/// beyond that. The unix arm's `wait` is exactly the `nix::poll::poll` call
/// the fastpath previously made inline.
pub struct WaitSet<'a> {
    entries: Vec<poll::PollFd<'a>>,
}

/// Maximum number of entries in a `WaitSet` (width of the `Ready` bitmasks).
const MAX_ENTRIES: usize = 32;

impl<'a> WaitSet<'a> {
    /// Create an empty wait set with room for `capacity` entries.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
        }
    }

    /// Register `handle` with the given `interest`. Returns the index this
    /// entry is reported under in [`Ready`].
    ///
    /// Panics if the set already holds [`MAX_ENTRIES`] entries.
    pub fn push(&mut self, handle: WaitHandle<'a>, interest: Interest) -> usize {
        let index = self.entries.len();
        assert!(index < MAX_ENTRIES, "WaitSet overflow");
        self.entries
            .push(poll::PollFd::new(handle.as_fd(), interest.poll_flags()));
        index
    }

    /// Block until at least one entry is ready or `timeout` elapses
    /// (`None` = wait forever), and report which entries are ready.
    ///
    /// A timeout expiry reports an empty [`Ready`]. Interruption by a signal
    /// surfaces as an error of kind [`std::io::ErrorKind::Interrupted`],
    /// exactly as the inline `poll(2)` call did; callers retry.
    pub fn wait(&mut self, timeout: Option<Duration>) -> Result<Ready> {
        let timeout = match timeout {
            None => poll::PollTimeout::NONE,
            Some(duration) => poll::PollTimeout::try_from(duration)
                .expect("WaitSet timeout exceeds the platform maximum"),
        };

        let _n = poll::poll(&mut self.entries, timeout)
            .map_err(|err| std::io::Error::from_raw_os_error(err as i32))?;

        let mut ready = Ready::default();
        for (index, pfd) in self.entries.iter().enumerate() {
            let revents = pfd.revents().unwrap();
            if revents.contains(poll::PollFlags::POLLIN) {
                ready.readable |= 1 << index;
            }
            if revents.contains(poll::PollFlags::POLLOUT) {
                ready.writable |= 1 << index;
            }
        }
        Ok(ready)
    }
}

#[cfg(test)]
mod tests {
    use super::{Interest, WaitSet};
    use crate::sys::notify::Notify;
    use crate::sys::wait::Waitable;
    use std::time::Duration;

    /// Two `Notify`s in a `WaitSet`; post one; `wait` reports exactly that
    /// one ready. (zipline#128 acceptance test.)
    #[test]
    fn waitset_reports_only_posted_notify() {
        let notify1 = Notify::new().unwrap();
        let notify2 = Notify::new().unwrap();

        let mut wait_set = WaitSet::with_capacity(2);
        let idx1 = wait_set.push(notify1.handle(), Interest::READ);
        let idx2 = wait_set.push(notify2.handle(), Interest::READ);

        notify1.post();

        let ready = wait_set.wait(Some(Duration::from_secs(5))).unwrap();
        assert!(ready.is_readable(idx1));
        assert!(!ready.is_readable(idx2));
    }
}
