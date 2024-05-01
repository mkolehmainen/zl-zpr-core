

use std::fs;
use std::io::{BufReader, Error, ErrorKind, Read};

use std::time::Instant;

use std::sync::{Arc, Mutex};


use serde::Deserialize;




#[derive(Debug)]
enum ConfigState {
    Connecting,
    Connected(Instant),
    Disconnecting,
    Disconnected,
}



#[derive(Debug, Clone, Deserialize)]
pub struct Configuration {

    #[serde(skip)]
    path_name: String,
    dock: Dock,
    adapter: Adapter,
    // TODO: credentials: Credentials,
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
        return Err(Error::new(ErrorKind::Other, format!("Empty configuration file: {}", path)));
    }
    let mut c: Configuration = match toml::from_str(&toml_text) {
        Ok(c) => c,
        Err(e) => {
            return Err(Error::new(ErrorKind::Other, format!("Error parsing configuration file {}: {}", path, e)))
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

impl Zpr {

    pub fn new() -> Zpr {
        Zpr {
            shared: Arc::new(Shared {
                configurations: Mutex::new(Vec::new()),
            }),
        }
    }

    pub fn add_configuration(&self, c: Configuration) -> Result<(), std::io::Error>{
        // If a configuration exists with the same path, we overrite the existing one but only if it is disconnected.
        let mut found = false;
        let mut state = self.shared.configurations.lock().unwrap();
        for (conf, state) in &*state { // XXX <------- RUST WTF IS THIS "&*" ?
            if conf.path_name == c.path_name {
                found = true;
                if ! matches!(state, ConfigState::Disconnected) {
                    return Err(Error::new(ErrorKind::Other, "Configuration already exists and is not disconnected"));
                }
            }
        }
        if found {
            // Remove the existing configuration
            state.retain(|(conf, _)| conf.path_name != c.path_name);
        } 
        state.push((c, ConfigState::Disconnected));
        Ok(())
    }

    pub fn get_status(&self) -> Vec<(String, String)> {
        let mut status = Vec::new();
        let state = self.shared.configurations.lock().unwrap();
        for (conf, state) in &*state {
            let s = match state {
                ConfigState::Connecting => String::from("connecting"),
                ConfigState::Connected(ctime) => {
                    let now = Instant::now();
                    let elapsed = now.duration_since(*ctime);
                    format!("connected {}s", elapsed.as_secs())
                },
                ConfigState::Disconnecting => String::from("disconnecting"),
                ConfigState::Disconnected => String::from("disconnected"),
            };
            status.push((conf.dock.host_or_ip.clone(), s));
        }
        status
    }
}

