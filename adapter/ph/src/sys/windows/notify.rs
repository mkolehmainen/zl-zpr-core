//! Notification of events via a Windows Event object (zipline#130).
//!
//! Same API as the posix arm (`sys/posix/notify.rs`), which signals through
//! a non-blocking pipe watched by `poll(2)`. Here the underlying object is
//! a **manual-reset** Event (`CreateEventW`): `post` is `SetEvent`,
//! `consume` reads-and-clears with `ResetEvent`, and the Event handle is
//! the [`Waitable`] a [`WaitSet`](crate::sys::wait::WaitSet) watches with
//! `WaitForMultipleObjects` (plan D3).
//!
//! Manual-reset matters: an auto-reset Event is consumed by the *wait*, so
//! a wait that reports several ready sources would eat the notification
//! before `consume` ran. With manual-reset the Event stays signaled until
//! `consume` resets it — exactly the posix arm's level-triggered semantics
//! (a pending byte keeps re-triggering `poll` until read).
//!
//! Memory ordering: `SetEvent`/`ResetEvent`/`WaitFor*` are kernel calls and
//! full synchronization points, matching the pipe write/read the posix arm
//! relies on.

use crate::sys::wait::{WaitHandle, Waitable};
use std::io::Result;
use std::sync::atomic::{AtomicBool, Ordering};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::Threading::{CreateEventW, ResetEvent, SetEvent};

/// A synchronization object used to post notifications.
///
/// A `Notify` object either has a notification, or does not. Posting a
/// notification causes the `Notify` to have a notification. Consuming the
/// notification causes the `Notify` to have no notification.
///
/// The primary benefit of a `Notify` (over e.g. an `AtomicBool`) is that
/// the presence of notifications can be awaited in a `WaitSet`.
pub struct Notify {
    /// Manual-reset Event handle; signaled while a notification is pending.
    event: HANDLE,
    /// Mirror of the Event's signaled state, so `consume` can report
    /// whether a notification was pending without a syscall race: the
    /// flag is flipped before the Event on `post` and after it on
    /// `consume`, and the Event is the authoritative wakeup.
    pending: AtomicBool,
}

// SAFETY: an Event handle may be signaled/waited from any thread, and the
// AtomicBool is Sync by construction. The posix arm is Send + Sync the same
// way (fds are thread-safe); the fastpath shares a Notify across threads.
unsafe impl Send for Notify {}
unsafe impl Sync for Notify {}

impl Notify {
    pub fn new() -> Result<Self> {
        // SAFETY: no security attributes, manual-reset, initially
        // unsignaled, unnamed. The returned handle is owned by this
        // Notify and closed in Drop.
        let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if event.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            event,
            pending: AtomicBool::new(false),
        })
    }

    /// Post a notification.
    ///
    /// This is a memory synchronization operation.
    pub fn post(&self) {
        self.pending.store(true, Ordering::Release);
        // SAFETY: self.event is a live Event handle owned by this Notify.
        if unsafe { SetEvent(self.event) } == 0 {
            panic!("SetEvent failed: {}", std::io::Error::last_os_error());
        }
    }

    /// Consume any outstanding notification.
    ///
    /// This is a memory synchronization operation.
    ///
    /// Returns `true` if there was a notification, `false` otherwise.
    pub fn consume(&self) -> bool {
        // Reset first, then read the flag: a `post` racing this consume
        // either lands before the ResetEvent (its notification is the one
        // being consumed) or after it (the Event is signaled again and the
        // next wait wakes). The swap(false) after the reset can only steal
        // a `true` from a post whose SetEvent also preceded the reset, so
        // no wakeup is ever lost.
        // SAFETY: self.event is a live Event handle owned by this Notify.
        if unsafe { ResetEvent(self.event) } == 0 {
            panic!("ResetEvent failed: {}", std::io::Error::last_os_error());
        }
        self.pending.swap(false, Ordering::AcqRel)
    }

    /// Wait for a notification to be present, and consume it.
    #[allow(dead_code)]
    pub fn wait_and_consume(&self) {
        use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
        use windows_sys::Win32::System::Threading::{INFINITE, WaitForSingleObject};
        loop {
            // SAFETY: self.event is a live Event handle owned by this Notify.
            let rc = unsafe { WaitForSingleObject(self.event, INFINITE) };
            if rc != WAIT_OBJECT_0 {
                panic!(
                    "WaitForSingleObject failed ({rc}): {}",
                    std::io::Error::last_os_error()
                );
            }
            if self.consume() {
                break;
            }
        }
    }
}

impl Drop for Notify {
    fn drop(&mut self) {
        // SAFETY: self.event is a live Event handle owned by this Notify;
        // nothing can wait on it once drop runs (it requires &mut/ownership).
        unsafe { CloseHandle(self.event) };
    }
}

/// A `Notify`'s readiness (a pending notification) can be awaited in a
/// `WaitSet` alongside other waitables.
impl Waitable for Notify {
    fn handle(&self) -> WaitHandle<'_> {
        WaitHandle::from_event(self.event)
    }
}
