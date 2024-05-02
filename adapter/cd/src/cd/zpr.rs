use std::fs;
use std::io::{BufReader, Error, ErrorKind, Read};

use std::time::Instant;

use std::sync::{Arc, Mutex};

use serde::Deserialize;

#[derive(Debug, Clone)]
pub enum ConfigState {
    Connecting,
    Connected(Instant),
    Disconnecting,
    Disconnected,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Configuration {
    #[serde(skip)]
    path_name: String,

    profile: Profile,
    dock: Dock,
    adapter: Adapter,
    // TODO: credentials: Credentials,
}

#[derive(Debug, Clone, Deserialize)]
struct Profile {
    name: String,
}

#[derive(Debug, Clone, Deserialize)]
struct Dock {
    host_or_ip: String,
    startup_port: u16,
}

#[derive(Debug, Clone, Deserialize)]
struct Adapter {
    private_key: Option<String>,
}

pub fn load_configuration(path: &str) -> Result<Configuration, std::io::Error> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut toml_text = String::new();
    let len = reader.read_to_string(&mut toml_text)?;
    if len == 0 {
        return Err(Error::new(
            ErrorKind::Other,
            format!("Empty configuration file: {}", path),
        ));
    }
    let mut c: Configuration = match toml::from_str(&toml_text) {
        Ok(c) => c,
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other,
                format!("Error parsing configuration file {}: {}", path, e),
            ))
        }
    };
    c.path_name = path.to_string();
    Ok(c)
}

#[derive(Debug, Clone)]
pub struct Zpr {
    shared: Arc<Shared>,
}

#[derive(Debug)]
struct Shared {
    configurations: Mutex<Vec<(Configuration, ConfigState)>>,
}

impl Configuration {
    pub fn get_name(&self) -> &str {
        self.profile.name.as_str()
    }    
}

impl Zpr {
    pub fn new() -> Zpr {
        Zpr {
            shared: Arc::new(Shared {
                configurations: Mutex::new(Vec::new()),
            }),
        }
    }

    // If a configuration exists with the same path, we overrite the existing one but only if it is disconnected.
    pub fn add_configuration(&self, c: Configuration) -> Result<(), std::io::Error> {
        let mut found = false;
        let mut state = self.shared.configurations.lock().unwrap();
        for (conf, state) in &*state {
            // XXX <------- RUST WTF IS THIS "&*" ?
            if conf.path_name == c.path_name {
                found = true;
                if !matches!(state, ConfigState::Disconnected) {
                    return Err(Error::new(
                        ErrorKind::Other,
                        "Configuration already exists and is not disconnected",
                    ));
                }
            }
        }
        if found {
            // Remove the existing configuration
            state.retain(|(conf, _)| conf.path_name != c.path_name);
        }

        // Name must be unique
        for (conf, state) in &*state {
            // XXX <------- RUST WTF IS THIS "&*" ?
            if conf.profile.name == c.profile.name {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("Configuration with name {} already exists", c.profile.name),
                ));
            }
        }

        state.push((c, ConfigState::Disconnected));
        Ok(())
    }

    // Mock up status function.  This returns a vector of (CONFIG_NAME, ENDPOINT, STATUS)
    pub fn get_status(&self) -> Vec<(String, String, String)> {
        let mut status = Vec::new();
        let state = self.shared.configurations.lock().unwrap();
        for (conf, state) in &*state {
            let s = match state {
                ConfigState::Connecting => String::from("connecting"),
                ConfigState::Connected(ctime) => {
                    let now = Instant::now();
                    let elapsed = now.duration_since(*ctime);
                    format!("connected {}s", elapsed.as_secs())
                }
                ConfigState::Disconnecting => String::from("disconnecting"),
                ConfigState::Disconnected => String::from("disconnected"),
            };
            status.push((conf.profile.name.clone(), conf.dock.host_or_ip.clone(), s));
        }
        status
    }


    pub fn get_configuration_state(&self, name: &str) -> Option<ConfigState> {
        let state = self.shared.configurations.lock().unwrap();
        for (conf, s) in &*state {
            if conf.profile.name == name {
                return Some(s.clone());
            }
        }
        None
    }

    // Not sure if this will be how things work later, but for now allowing the 
    // command server to just set the status.
    pub fn set_status(&self, name: &str, status: ConfigState) -> Result<(), std::io::Error> {
        let mut found = false;
        let mut state = self.shared.configurations.lock().unwrap();
        for (conf, _) in &*state {
            if conf.profile.name == name {
                found = true;
            }
        }
        if !found {
            return Err(Error::new(
                ErrorKind::Other,
                format!("Configuration with name {} not found", name),
            ));
        }
        for (conf, s) in &mut *state {
            if conf.profile.name == name {
                *s = status.clone();
            }
        }
        Ok(())
    }

    pub fn has_configuration(&self, name: &str) -> bool {
        let state = self.shared.configurations.lock().unwrap();
        for (conf, _) in &*state {
            if conf.profile.name == name {
                return true;
            }
        }
        false
    }

}
