//! Windows platform arm of `sys/` (zipline#130, master plan
//! `docs/plans/2026-09-28-windows.md` task C3).
//!
//! Mirrors `linux.rs`/`macos.rs`: the OS-specific `ZprTun` and `TunPiImpl`,
//! plus the Windows implementations of the modules `sys/posix` provides on
//! unix — `notify` (a manual-reset Event) and `control` (a named pipe with
//! an explicit DACL).

pub mod control;
pub mod notify;
pub mod substrate;
pub mod tun_pi;
pub mod zprtun;

pub use tun_pi::TunPiImpl;
pub use zprtun::ZprTun;
