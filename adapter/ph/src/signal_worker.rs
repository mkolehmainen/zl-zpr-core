//! Worker which handles OS shutdown and diagnostic signals: Unix signals,
//! or Windows console control events (plan D10).

use crate::counters::*;
use crate::prelude::*;
use tokio::task::spawn_local;

/// Unix: SIGINT (graceful; a second one exits immediately), SIGTERM
/// (graceful), SIGUSR1 (print counters).
#[cfg(unix)]
pub async fn launch(asm: Arc<Assembly>) {
    use tokio::signal::unix::{SignalKind, signal};

    let mut usr1_stream = signal(SignalKind::user_defined1()).unwrap();
    let mut term_stream = signal(SignalKind::terminate()).unwrap();
    let mut int_stream = signal(SignalKind::interrupt()).unwrap();

    let mut int_received = false;

    loop {
        tokio::select! {
            _ = usr1_stream.recv() => emit_counts(&asm.counters, asm.get_uptime()),

            _ = int_stream.recv() => {
                // Treat a single SIGINT as a UI request to shut down cleanly;
                // any subsequent SIGINTs as a forced shutdown.
                if int_received {
                    // There's no way to unregister a signal handler with
                    // Tokio, so instead, report SIGINT as the shutdown
                    // reason via exit code (as if we hadn't registered a handler).
                    std::process::exit(128 + SignalKind::interrupt().as_raw_value());
                } else {
                    info!(target: STARTUP, "Got SIGINT; attempting graceful shutdown. Send again to terminate immediately.");
                    int_received = true;
                    drop(spawn_local(do_clean_shutdown(asm.clone())));
                }
            }

            _ = term_stream.recv() => {
                // Attempt a graceful shutdown on SIGTERM.  Unlike SIGINT,
                // we don't change behavior on repeated signals: SIGKILL
                // is the appropriate follow-up to force shutdown.
                info!(target: STARTUP, "Got SIGTERM; attempting graceful shutdown. Send SIGKILL to terminate immediately.");
                drop(spawn_local(do_clean_shutdown(asm.clone())));
            }
        }
    }
}

/// Windows console control events, mapped onto the Unix roles:
/// Ctrl-C is SIGINT (graceful; a second one exits immediately),
/// closing the console window or system shutdown is SIGTERM (graceful),
/// Ctrl-Break is SIGUSR1 (print counters).
#[cfg(windows)]
pub async fn launch(asm: Arc<Assembly>) {
    use tokio::signal::windows::{ctrl_break, ctrl_c, ctrl_close, ctrl_shutdown};

    /// The exit status Windows gives a process killed by Ctrl-C
    /// (STATUS_CONTROL_C_EXIT), the counterpart of Unix's 128 + SIGINT.
    const STATUS_CONTROL_C_EXIT: i32 = 0xC000013A_u32 as i32;

    let mut break_stream = ctrl_break().unwrap();
    let mut c_stream = ctrl_c().unwrap();
    let mut close_stream = ctrl_close().unwrap();
    let mut shutdown_stream = ctrl_shutdown().unwrap();

    let mut c_received = false;

    loop {
        tokio::select! {
            _ = break_stream.recv() => emit_counts(&asm.counters, asm.get_uptime()),

            _ = c_stream.recv() => {
                if c_received {
                    std::process::exit(STATUS_CONTROL_C_EXIT);
                } else {
                    info!(target: STARTUP, "Got Ctrl-C; attempting graceful shutdown. Press Ctrl-C again to terminate immediately.");
                    c_received = true;
                    drop(spawn_local(do_clean_shutdown(asm.clone())));
                }
            }

            // Windows terminates the process a few seconds after these
            // events regardless, so graceful shutdown is best-effort.
            _ = close_stream.recv() => {
                info!(target: STARTUP, "Console closing; attempting graceful shutdown.");
                drop(spawn_local(do_clean_shutdown(asm.clone())));
            }

            _ = shutdown_stream.recv() => {
                info!(target: STARTUP, "System shutting down; attempting graceful shutdown.");
                drop(spawn_local(do_clean_shutdown(asm.clone())));
            }
        }
    }
}

/// Print every counter to stdout.
fn emit_counts(counters: &Counters, uptime: std::time::Duration) {
    println!("{:>42}\n", "*** Counters ***");
    println!(
        "{:>34}: {}.{} s",
        "Uptime",
        uptime.as_secs(),
        uptime.subsec_millis()
    );
    println!("\n");
    println!("{:>42}\n", "*** Management Counters ***");
    for (key, ref value) in &counters.management {
        println!("{:>34}: {}", key.name(), value.get_count());
    }
    for (i, fastpath) in counters.fastpaths.lock().unwrap().iter().enumerate() {
        println!("\n");
        let message = format!("*** Fastpath #{} Counters ***", i);
        println!("{:>42}\n", message);
        for (key, ref value) in fastpath {
            println!("{:>34}: {}", key.name(), value.get_count());
        }
    }
}

/// Shut the assembly down, print the counters, and exit successfully.
async fn do_clean_shutdown(asm: Arc<Assembly>) -> ! {
    asm.shutdown().await;
    emit_counts(&asm.counters, asm.get_uptime());
    std::process::exit(0);
}
