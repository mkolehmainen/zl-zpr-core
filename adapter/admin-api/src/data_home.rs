use std::env;
use std::path::PathBuf;

// Return the path to the data home directory. A place we can stash things like
// unix domain sockets. Default is '/var/run/zpr'.
#[cfg(unix)]
pub fn get_data_home() -> PathBuf {
    let mut dh = match env::var("XDG_DATA_HOME") {
        Ok(val) => PathBuf::from(val),
        Err(_) => match env::var("HOME") {
            Ok(val) => {
                let mut pb = PathBuf::from(val);
                pb.push(".local/share");
                // Now we will only take this if user already has a .local/share dir.
                if pb.exists() {
                    pb
                } else {
                    PathBuf::from("/var/run")
                }
            }
            Err(_) => PathBuf::from("/var/run"),
        },
    };
    dh.push("zpr");
    dh
}

// Return the path to the data home directory on Windows: `%ProgramData%\zpr`,
// falling back to `C:\ProgramData\zpr` when the variable is unset (plan D9).
// The control channel itself is a named pipe, not a file under here.
#[cfg(windows)]
pub fn get_data_home() -> PathBuf {
    let base = env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join("zpr")
}
