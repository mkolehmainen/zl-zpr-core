use clap::{Args, Parser, Subcommand};
use std::path::{Path, PathBuf};

use admin_api::{capture_socket_path, choose_socket_path, control_socket_path};

#[derive(Parser, Debug)]
#[command(version, about = "This program controls the RPC calls to the ZPR Packet Handler\nRun without a command to enter CLI mode", long_about = None)]
pub struct CmdlineArgs {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Path to the Packet Handler's management socket. Default: the per-user
    /// socket for your uid when a server answers there, else the shared
    /// socket (zipline#39).
    #[arg(long, short = 'p')]
    pub socket: Option<PathBuf>,

    /// Path to the Packet Handler's capture socket, only necessary when performing Capture commands
    #[arg(long, short = 'c')]
    pub cap_socket: Option<PathBuf>,
}

/// Resolve the control and capture socket paths for this invocation
/// (zipline#39). Explicit `-p`/`-c` short-circuit. Otherwise the control
/// socket is searched: per-uid path for the caller's euid first, then the
/// shared path; when neither answers the error names both. A candidate is
/// selected by a probe connect, not by pathname existence — a stale socket
/// file left by a dead ph must not shadow a live server at the other path.
/// The capture socket follows the resolved control socket's directory when
/// the control socket also came from the default search; with an explicit
/// `-p` the derived capture candidates are searched by liveness first and
/// colocation is only the last-resort fallback.
pub fn resolve_sockets(
    explicit_control: Option<PathBuf>,
    explicit_capture: Option<PathBuf>,
) -> Result<(PathBuf, PathBuf), String> {
    resolve_sockets_with(
        explicit_control,
        explicit_capture,
        nix::unistd::geteuid().as_raw(),
        admin_api::socket_is_live,
    )
}

/// Testable core of [resolve_sockets]: euid and liveness predicate injected.
pub fn resolve_sockets_with<F>(
    explicit_control: Option<PathBuf>,
    explicit_capture: Option<PathBuf>,
    euid: u32,
    exists: F,
) -> Result<(PathBuf, PathBuf), String>
where
    F: Fn(&Path) -> bool,
{
    let explicit_control_given = explicit_control.is_some();
    let control = choose_socket_path(
        explicit_control,
        control_socket_path(Some(euid)),
        control_socket_path(None),
        &exists,
    )?;
    let capture = match explicit_capture {
        Some(path) => path,
        // Explicit -p, no -c: the control path says nothing about where ph
        // derived its capture socket (ph given only --control-path keeps
        // capture at the derived default). Search the derived candidates by
        // liveness first; colocation beside the explicit control path is
        // only the last-resort guess (ph configured with both explicit
        // paths side by side), never an error — commands that do not touch
        // the capture socket must still run (zipline#39 review).
        None if explicit_control_given => {
            let per_uid = capture_socket_path(Some(euid));
            let shared = capture_socket_path(None);
            if exists(&per_uid) {
                per_uid
            } else if exists(&shared) {
                shared
            } else {
                colocated_capture(&control)
            }
        }
        // Control came from the default search: capture.sock beside it
        // belongs to the same adapter by construction.
        None => colocated_capture(&control),
    };
    Ok((control, capture))
}

// The capture socket beside a control socket: `<dir>/capture.sock`.
fn colocated_capture(control: &Path) -> PathBuf {
    match control.parent() {
        Some(dir) => dir.join("capture.sock"),
        None => capture_socket_path(None),
    }
}

#[derive(Parser, Debug)]
#[command(multicall = true)]
pub struct CliCommand {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Echo,
    /// Display or reset counters
    Counters {
        #[arg(long, short = 'r')]
        /// Reset counters
        reset: bool,
    },
    #[command(arg_required_else_help = true)]
    /// Connect to the Packet Handler for periodic counter updates
    Watch {
        #[arg(required = true)]
        /// How frequently to receive updates
        interval: u64,
    },
    #[command(arg_required_else_help = true)]
    /// Start performance sampling (currently not functional)
    PerfSample {
        #[arg(required = true)]
        /// How long the sampling should run
        duration: u64,

        #[arg(required = true)]
        /// How frequently packets should be injected
        frequency: u64,
    },
    /// Set up or tear down packet captures
    Capture(CaptureArgs),
    /// Change link state
    Link(LinkArgs),
    /// Change the log level of a node or adapter
    /// Format: logging [<level>=<target>]*
    /// There must be at least level, target pair
    /// The options for targets are:
    ///     all, capture, datapath, flow_mgmt, link_state,
    ///     mgmt_events, net_os, peer_mgmt, reporting, rpc,
    ///     startup, visa_mgmt, zdp
    /// The options for levels are:
    ///     OFF, ERROR, WARN, INFO, DEBUG, TRACE
    Logging {
        #[arg(required = true, value_delimiter = ' ', num_args = 1.., value_parser = parse_key_val, verbatim_doc_comment)]
        logs: Vec<(String, String)>,
    },
    /// Exit the CLI
    Quit,
    /// Gets the address of an adapter's node
    Addr,
    /// Connect (start) a link, performing interactive authentication when the
    /// packet handler requests it
    #[command(arg_required_else_help = true)]
    Connect {
        #[arg(required = true)]
        /// Link id to connect
        id: u32,
        /// Print authentication URLs instead of opening a browser
        #[arg(long)]
        no_browser: bool,
    },
    /// Register as the authentication agent for a link and run until
    /// interrupted
    #[command(arg_required_else_help = true)]
    AuthAgent {
        #[arg(required = true)]
        /// Link id to serve as authentication agent for
        id: u32,
        /// Print authentication URLs instead of opening a browser
        #[arg(long)]
        no_browser: bool,
    },
    /// Debug: run the OIDC relying-party login flow standalone and print the
    /// resulting id_token to stdout
    #[command(hide = true, arg_required_else_help = true)]
    OidcLogin {
        /// OIDC issuer URL
        #[arg(long)]
        issuer: String,
        /// OAuth client id
        #[arg(long)]
        client_id: String,
        /// OAuth client secret (confidential clients only)
        #[arg(long)]
        client_secret: Option<String>,
        /// Scopes to request (comma-separated)
        #[arg(long, value_delimiter = ',', default_value = "openid")]
        scopes: Vec<String>,
        /// Nonce to bind into the id_token
        #[arg(long)]
        nonce: String,
        /// Print the authorization URL instead of opening a browser
        #[arg(long)]
        no_browser: bool,
    },
}

#[derive(Debug, Args)]
#[command(flatten_help = true)]
pub struct CaptureArgs {
    #[command(subcommand)]
    pub command: CaptureCommands,
}

#[derive(Debug, Subcommand)]
pub enum CaptureCommands {
    /// Set a capture file
    SetFile {
        #[arg(required = true)]
        file_path: String,
    },
    /// Close a capture file
    CloseFile,
    /// Set a BPF to filter captured packets
    SetProgram {
        #[arg(required = true, default_value = "link[0] == 1 or link[0] == 0")]
        program: String,
    },
    /// Delete any set BPF
    DeleteProgram,
    /// Flush any outstanding packets to the capture file
    FlushFile,
    #[command(arg_required_else_help = true)]
    /// Create a temporary packet capture
    Sequence {
        file_path: String,
        /// Duration in seconds
        duration: u64,
        #[arg(default_value = "link[0] == 1 or link[0] == 0")]
        program: String,
    },
}

#[derive(Debug, Args)]
#[command(flatten_help = true)]
pub struct LinkArgs {
    #[command(subcommand)]
    pub command: LinkCommands,
}

#[derive(Debug, Subcommand)]
pub enum LinkCommands {
    /// Show a link's status
    Show { id: Option<u32> },
    /// Configure a link
    Configure { id: u32 },
    /// Start a link
    Start { id: u32 },
    /// Stop a link
    Stop { id: u32 },
    /// Reset a link.  It will require a configure before starting again
    Reset { id: u32 },
}

fn parse_key_val(s: &str) -> Result<(String, String), String> {
    let key_val: Vec<&str> = s.split("=").collect();
    match key_val.len() {
        2 => {
            return Ok((key_val[0].to_string(), key_val[1].to_uppercase()));
        }
        1 => {
            return Ok(("all".to_string(), key_val[0].to_uppercase()));
        }
        _ => Err(format!("Invalid key-value pair")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `auth-agent <id> --no-browser` must parse, setting the flag
    /// (zipline#20).
    #[test]
    fn auth_agent_accepts_no_browser_flag() {
        let parsed = CmdlineArgs::try_parse_from(["ph-cli", "auth-agent", "1", "--no-browser"]);
        match parsed {
            Ok(CmdlineArgs {
                command: Some(Commands::AuthAgent { id, no_browser }),
                ..
            }) => {
                assert_eq!(id, 1);
                assert!(no_browser);
            }
            other => panic!("auth-agent should accept --no-browser: {other:?}"),
        }
    }

    /// Without the flag, `auth-agent <id>` still parses with the flag
    /// defaulting off.
    #[test]
    fn auth_agent_parses_without_no_browser_flag() {
        let parsed = CmdlineArgs::try_parse_from(["ph-cli", "auth-agent", "1"]);
        match parsed {
            Ok(CmdlineArgs {
                command: Some(Commands::AuthAgent { id, no_browser }),
                ..
            }) => {
                assert_eq!(id, 1);
                assert!(!no_browser, "--no-browser must default off");
            }
            other => panic!("auth-agent without --no-browser should parse: {other:?}"),
        }
    }

    /// An explicit `-p`/`-c` short-circuits the socket search entirely, even
    /// when the paths do not exist (zipline#39).
    #[test]
    fn explicit_sockets_short_circuit() {
        let (control, capture) = resolve_sockets_with(
            Some(PathBuf::from("/x/control.sock")),
            Some(PathBuf::from("/y/capture.sock")),
            1000,
            |_: &Path| false,
        )
        .unwrap();
        assert_eq!(control, PathBuf::from("/x/control.sock"));
        assert_eq!(capture, PathBuf::from("/y/capture.sock"));
    }

    /// Default search prefers the per-uid socket for the caller's euid — the
    /// path a sudo-started ph created for us — and the capture socket follows
    /// the same directory (zipline#39).
    #[test]
    fn per_uid_socket_preferred() {
        let per_uid = control_socket_path(Some(1000));
        let (control, capture) =
            resolve_sockets_with(None, None, 1000, |p: &Path| p == per_uid.as_path()).unwrap();
        assert_eq!(control, per_uid);
        assert_eq!(capture, per_uid.parent().unwrap().join("capture.sock"));
    }

    /// When there is no per-uid socket the shared path is used (systemd-run
    /// ph), capture following along (zipline#39).
    #[test]
    fn shared_socket_fallback() {
        let shared = control_socket_path(None);
        let (control, capture) =
            resolve_sockets_with(None, None, 1000, |p: &Path| p == shared.as_path()).unwrap();
        assert_eq!(control, shared);
        assert_eq!(capture, shared.parent().unwrap().join("capture.sock"));
    }

    /// With no socket anywhere the error names both paths tried (zipline#39).
    #[test]
    fn missing_sockets_error_names_paths() {
        let err = resolve_sockets_with(None, None, 1000, |_: &Path| false)
            .expect_err("no socket exists, resolution must fail");
        let per_uid = control_socket_path(Some(1000));
        let shared = control_socket_path(None);
        assert!(
            err.contains(per_uid.to_str().unwrap()),
            "error must name the per-uid path: {err}"
        );
        assert!(
            err.contains(shared.to_str().unwrap()),
            "error must name the shared path: {err}"
        );
    }

    /// An explicit `-c` wins even when `-p` is defaulted (zipline#39).
    #[test]
    fn explicit_capture_with_defaulted_control() {
        let shared = control_socket_path(None);
        let (control, capture) = resolve_sockets_with(
            None,
            Some(PathBuf::from("/y/capture.sock")),
            1000,
            |p: &Path| p == shared.as_path(),
        )
        .unwrap();
        assert_eq!(control, shared);
        assert_eq!(capture, PathBuf::from("/y/capture.sock"));
    }

    /// ph started with only `--control-path /tmp/control.sock` keeps its
    /// capture path derived (per-uid for a sudo start). `ph-cli -p` with no
    /// `-c` must find that live derived capture socket instead of assuming
    /// `/tmp/capture.sock` (zipline#39 review).
    #[test]
    fn explicit_control_searches_capture_per_uid() {
        let cap = capture_socket_path(Some(1000));
        let (control, capture) = resolve_sockets_with(
            Some(PathBuf::from("/x/control.sock")),
            None,
            1000,
            |p: &Path| p == cap.as_path(),
        )
        .unwrap();
        assert_eq!(control, PathBuf::from("/x/control.sock"));
        assert_eq!(
            capture, cap,
            "capture must be searched independently when -p is explicit"
        );
    }

    /// Same as above with the derived capture socket at the shared path
    /// (systemd-started ph given only an explicit control path).
    #[test]
    fn explicit_control_searches_capture_shared() {
        let cap = capture_socket_path(None);
        let (control, capture) = resolve_sockets_with(
            Some(PathBuf::from("/x/control.sock")),
            None,
            1000,
            |p: &Path| p == cap.as_path(),
        )
        .unwrap();
        assert_eq!(control, PathBuf::from("/x/control.sock"));
        assert_eq!(
            capture, cap,
            "capture must fall back to the shared derived path"
        );
    }

    /// Explicit `-p` with no live derived capture socket anywhere: fall back
    /// to the colocation guess (ph configured with both paths explicit puts
    /// them side by side), never a hard error — commands that do not touch
    /// the capture socket must still run (zipline#39 review).
    #[test]
    fn explicit_control_capture_colocation_fallback() {
        let (control, capture) = resolve_sockets_with(
            Some(PathBuf::from("/x/control.sock")),
            None,
            1000,
            |_: &Path| false,
        )
        .unwrap();
        assert_eq!(control, PathBuf::from("/x/control.sock"));
        assert_eq!(capture, PathBuf::from("/x/capture.sock"));
    }
}
