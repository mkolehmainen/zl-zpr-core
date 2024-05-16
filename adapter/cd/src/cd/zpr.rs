use std::{
    collections::HashMap, 
    fs, 
    io::{
        BufReader, Cursor, Error, ErrorKind, Read, SeekFrom, Write, Seek
    }, 
    sync::{Arc, Mutex}, 
    time::{Instant, SystemTime},
    net::Ipv6Addr,
};

use byteorder::{BigEndian, WriteBytesExt, ReadBytesExt}; 
use base64::prelude::*;

use serde::Deserialize;

use tokio::{
    net::TcpStream,
    io::AsyncWriteExt,
};

use ring::signature;
use tracing::{error, info};


const NOISE_KEY_LEN: usize = 32;
const HMAC_SHA256_LEN: usize = 256;
const START_ME_UP_MIN_MSG_LEN: usize = 32 + NOISE_KEY_LEN + HMAC_SHA256_LEN; // <core message> + <noise key> + <hmac>
const START_ME_UP_NONCE_LEN: usize = 8;
const START_ME_UP_STATUS_OK: u8 = 0x0;
const SIG_TYPE_RSA_PKCS1_SHA256: u8 = 0x1;

const START_ME_UP_RESP_OFFSET_WG_PORT: usize = 2;
const START_ME_UP_RESP_OFFSET_IP_ADDR: usize = 4;
const START_ME_UP_RESP_OFFSET_NETMASK: usize = 20;
const START_ME_UP_RESP_OFFSET_SIGTYPE: usize = 21;
const START_ME_UP_RESP_OFFSET_KEYLEN: usize = 22;
const START_ME_UP_RESP_OFFSET_NONCE: usize = 24;
const START_ME_UP_RESP_OFFSET_DATA: usize = 32;



#[derive(Debug, Clone, PartialEq)]
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
    certificate: String, // path to node key file in DER format (TODO: ability to just use a PEM cert here!!)
}

#[derive(Debug, Clone, Deserialize)]
struct Adapter {
    private_key: Option<String>, // base64 noise key
    public_key: Option<String>,  // base64 noise key (TODO: should be able to derive from private key)
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


struct StartMyUpResponse {
    wg_port: u16,
    local_wg_addr: Ipv6Addr,
    ipv6_mask: u8,
    noise_key: [u8; NOISE_KEY_LEN],
}



// Zpr is the "shared state" for the control daemon. Not quite sure yet what will be in
// here.  For now is holding state information about configurations.
// 
// This pattern on an Arc and then a Mutex is copied from the tokio "best practice" as
// illustrated in the redis example.
#[derive(Debug, Clone)]
pub struct Zpr {
    shared: Arc<Shared>,
}

#[derive(Debug)]
struct Shared {
    state: Mutex<State>,    
}

#[derive(Debug)]
struct State {
    configurations: HashMap<String, (Configuration, ConfigState)>, // indexed by configuration.profile.name.
}

impl Configuration {
    pub fn get_name(&self) -> &str {
        self.profile.name.as_str()
    }    
}


impl Default for Zpr {
    fn default() -> Self {
        Zpr::new()
    }
}


impl Zpr {
    pub fn new() -> Zpr {
        Zpr {
            shared: Arc::new(Shared {
                state: Mutex::new(State {
                    configurations: HashMap::new(),                    
                }),
            }),
        }
    }

    // If a configuration exists with the same path, we overrite the existing one but only if it is disconnected.
    pub fn add_configuration(&self, c: Configuration) -> Result<(), std::io::Error> {
        let mut found = false;
        let mut found_name: String = String::new();
        let mut state = self.shared.state.lock().unwrap();            
        for (conf, state) in state.configurations.values() {
            if conf.path_name == c.path_name {
                found = true;
                found_name = conf.get_name().to_string();
                if !matches!(state, ConfigState::Disconnected) {
                    return Err(Error::new(
                        ErrorKind::Other,
                        "Configuration already exists and is not disconnected",
                    ));
                }
            }
        }
        if found {
            // If the names are the same, just writing our new config will overwrite the existing one.
            if found_name != c.profile.name {
                state.configurations.remove(&found_name);
            }
        } else {
            // The new path is not present, but also we require a unique name.
            if state.configurations.contains_key(c.get_name()) {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("Configuration with name {} already exists", c.profile.name),
                ));
            }
        }

        state.configurations.insert(c.get_name().to_string(), (c, ConfigState::Disconnected));
        Ok(())
    }

    // Mock up status function.  This returns a vector of (CONFIG_NAME, ENDPOINT, STATUS)
    pub fn get_status(&self) -> Vec<(String, String, String)> {
        let mut status = Vec::new();
        let state = self.shared.state.lock().unwrap();
        for (cname, (conf, state)) in &state.configurations {
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
            status.push((cname.clone(), conf.dock.host_or_ip.clone(), s));
        }
        status
    }


    pub fn get_configuration_state(&self, name: &str) -> Option<ConfigState> {
        let state = self.shared.state.lock().unwrap();
        let foo = state.configurations.get(name);
        if foo.is_none() {
            return None;
        }
        let (_, cs) = foo.unwrap();
        return Some(cs.clone());
    }


    // This public access to the status property is temporary.  As this is developed the status
    // value will depend on the outcome of operations or reactions to events.
    // 
    // For example, when `start_me_up` succeeds, the status moves to "connected".
    pub fn set_status(&self, name: &str, status: ConfigState) -> Result<(), std::io::Error> {
        let mut state = self.shared.state.lock().unwrap();
        let conf_state_tuple = state.configurations.get_mut(name).ok_or_else(|| {
            Error::new(
                ErrorKind::Other,
                format!("Configuration with name {} not found", name),
            )
        })?;
        (*conf_state_tuple).1 = status;
        Ok(())
    }

    pub fn has_configuration(&self, name: &str) -> bool {
        let state = self.shared.state.lock().unwrap();
        return state.configurations.contains_key(name);
    }

    // Perform the start-me-up protocol using the named configuration.
    pub async fn start_me_up(&self, name: &str) -> Result<(), std::io::Error> {
        let cc = match self.start_me_up_prepare(name) {
            Ok(c) => c,
            Err(e) => {
                return Err(e);
            }
        };

        // Do the start-me-up protocol here.
        match do_start_me_up(&cc).await {
            Err(e) => {
                // Set the state back to disconnected.
                let _ = self.set_status(name, ConfigState::Disconnected);
                return Err(e);
            },
            Ok(resp) => {
                // TODO: Figure out what todo with our new information.
                info!(config = name, dock_wg_port = resp.wg_port, local_wg_addr = format!("{:?}", resp.local_wg_addr), "start-me-up sucess");
                return self.set_status(name, ConfigState::Connected(Instant::now()));                
            },
        }
    }

    // Prepare for start-me-up by setting the state of the config to "connecting".
    // Returns a clone of the configuration.
    fn start_me_up_prepare(&self, name: &str) -> Result<Configuration, std::io::Error> {
        let mut state = self.shared.state.lock().unwrap();
        let conf_state_tuple = state.configurations.get_mut(name).ok_or_else(|| {
            Error::new(
                ErrorKind::Other,
                format!("Configuration with name {} not found", name),
            )
        })?;
        let (_, conf_state) = conf_state_tuple;
        // In order to start the state must be in disconnected.
        if !matches!(conf_state, ConfigState::Disconnected) {
            return Err(Error::new(
                ErrorKind::Other,
                format!("Configuration {} is not disconnected", name),
            ));
        }
        (*conf_state_tuple).1 = ConfigState::Connecting;

        // Loose the MUT reference and get a read-only one:
        let conf_state_tuple = state.configurations.get(name).ok_or_else(|| {
            Error::new(
                ErrorKind::Other,
                format!("Configuration with name {} not found", name),
            )
        })?;
        let (conf, _) = conf_state_tuple;
        Ok(conf.clone())
    }
}


// Run the start-me-up protocol against the dock. All needed details are in the
// passed configuration.
async fn do_start_me_up(config: &Configuration) -> Result<StartMyUpResponse, std::io::Error> {
 
    let msg = create_start_me_up_msg(config)?;

    println!("starting connect to {}: {}", config.dock.host_or_ip, config.dock.startup_port);    
    let mut stream = TcpStream::connect(format!("{}:{}", config.dock.host_or_ip, config.dock.startup_port)).await?;

    stream.write_all(&msg).await?;
    stream.shutdown().await?; // shut down write side of the connection.

    // TODO: This assumes we get the entire response in a single read.
    let mut resp_buffer = vec![0; 1024];
    loop {
        stream.readable().await?;
        match stream.try_read(&mut resp_buffer) {
            Ok(n) => {
                resp_buffer.truncate(n);
                break;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    if resp_buffer.len() < 1 {
        return Err(Error::new(
            ErrorKind::Other,
            "start-me-up empty response",
        ))
    }
    if resp_buffer[0] != START_ME_UP_STATUS_OK { // status must be 0x0 to proceed
        return Err(Error::new(
            ErrorKind::Other,
            format!("start-me-up returns non-zero status: {}", resp_buffer[0]),
        ))
    }
    if resp_buffer.len() < START_ME_UP_MIN_MSG_LEN {
        return Err(Error::new(
            ErrorKind::Other,
            "Dock response too short",
        ))
    }


    let mut rdr = Cursor::new(&resp_buffer);

    rdr.seek(SeekFrom::Start(START_ME_UP_RESP_OFFSET_WG_PORT as u64))?;
    let wg_port = ReadBytesExt::read_u16::<BigEndian>(&mut rdr)?;    

    // read IPv6
    rdr.seek(SeekFrom::Start(START_ME_UP_RESP_OFFSET_IP_ADDR as u64))?;    
    let mut ip6 = [0u16; 8];
    for i in 0..8 {
        ip6[i] = ReadBytesExt::read_u16::<BigEndian>(&mut rdr)?;
    }
    let ip6_addr = Ipv6Addr::new(ip6[0], ip6[1], ip6[2], ip6[3], ip6[4], ip6[5], ip6[6], ip6[7]);
    let ipv6_mask = resp_buffer[START_ME_UP_RESP_OFFSET_NETMASK];

    let sig_type = resp_buffer[START_ME_UP_RESP_OFFSET_SIGTYPE];
    if sig_type != SIG_TYPE_RSA_PKCS1_SHA256 {
        return Err(Error::new(
            ErrorKind::Other,
            format!("Unsupported signature type: {}", sig_type),
        ));
    }
    
    rdr.seek(SeekFrom::Start(START_ME_UP_RESP_OFFSET_KEYLEN as u64))?;
    let key_len = ReadBytesExt::read_u16::<BigEndian>(&mut rdr)?;    
    if key_len as usize != NOISE_KEY_LEN {
        return Err(Error::new(
            ErrorKind::Other,
            format!("Invalid key length {}", key_len),
        ))
    }

    let mut nonce = [0u8; START_ME_UP_NONCE_LEN];
    for i in 0..START_ME_UP_NONCE_LEN {
        nonce[i] = resp_buffer[START_ME_UP_RESP_OFFSET_NONCE+i];
    }

    // We already checked the length of the response above so there is no danger of 
    // exceeding the bounds of the buffer here.  From here on we assume a NOISE key,
    // and a 256 byte HMAC.

    let mut noise_key = [0u8; NOISE_KEY_LEN];
    for i in 0..NOISE_KEY_LEN {
        noise_key[i] = resp_buffer[START_ME_UP_RESP_OFFSET_DATA+i];
    }
    // Next we should have hmac    
    let mut hmac = [0u8; HMAC_SHA256_LEN];
    for i in 0..HMAC_SHA256_LEN {
        hmac[i] = resp_buffer[START_ME_UP_RESP_OFFSET_DATA + NOISE_KEY_LEN + i];
    }

    // Hmac is over CONCAT( address, nonce, key ) and uses the ZPR node_key rsa key.
    let mut checkbuf = Vec::new();
    checkbuf.extend_from_slice(&ip6_addr.octets());
    checkbuf.extend_from_slice(&nonce);
    checkbuf.extend_from_slice(&noise_key);

    // The path in the config file is relative to the config file path itself... unless it starts with /
    // which Path::join takes care of magically.
    let der_path = std::path::Path::new(&config.path_name).parent().unwrap().join(&config.dock.certificate);
    let public_key = 
        signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, 
                                          read_file(der_path.as_path())?);
    public_key.verify(&checkbuf, &hmac)
        .map_err(|e| std::io::Error::new(ErrorKind::Other, format!("hmac verify error: {:?}", e)))?;                                      

    let resp = StartMyUpResponse {
        wg_port: wg_port,
        local_wg_addr: ip6_addr,
        ipv6_mask: ipv6_mask,
        noise_key: noise_key,
    };

    Ok(resp)
}

fn read_file(path: &std::path::Path) -> Result<Vec<u8>, std::io::Error> {
    let mut file = std::fs::File::open(path)?;
    let mut contents: Vec<u8> = Vec::new();
    file.read_to_end(&mut contents)?;
    Ok(contents)
}

// Create the start-me-up message payload.
fn create_start_me_up_msg(config: &Configuration) -> Result<Vec<u8>, std::io::Error> {

    let kbuf: Vec<u8>;

    if let Some(key) = config.adapter.public_key.as_ref() {
        kbuf = match BASE64_STANDARD.decode(key) {
            Ok(k) => k,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("Error decoding public key: {}", e),
                ))
            }
        }
    } else {
        kbuf = Vec::new();
    }

    if kbuf.len() > std::u16::MAX as usize {
        return Err(Error::new(
            ErrorKind::Other,
            "Public key too long",
        ))
    }
    let key_len:u16 = kbuf.len() as u16;
    let mut msgbuf = Cursor::new(vec![0; 12+key_len as usize]);
    let _ = std::io::Write::write(&mut msgbuf, &[0x01, 0x00]); // transport_type, signature_type
    let _ = WriteBytesExt::write_u16::<BigEndian>(&mut msgbuf, key_len); // message length    
    let timestamp = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => panic!("SystemTime before UNIX EPOCH!"),
    };
    let _ = WriteBytesExt::write_u64::<BigEndian>(&mut msgbuf, timestamp);    
    if key_len > 0 {
        let _ = std::io::Write::write(&mut msgbuf, &kbuf);
    }
    Ok(msgbuf.into_inner())
}


#[cfg(test)]
mod test {
    use super::*;
    use std::env;    
    use std::time::{SystemTime, UNIX_EPOCH};
    use rand::Rng;


    struct TempTomlFile {
        path: String,
    }

    impl Drop for TempTomlFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    impl TempTomlFile {
        fn new(contents: &str) -> TempTomlFile {
            let mut rng = rand::thread_rng();
            let tstamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
            let dir = env::temp_dir();
            let num: u32 = rng.gen();
            let path = dir.join(format!("org_zpr_cd_test_{}_{}.toml", num, tstamp));
            fs::write(&path, contents).expect("Unable to write file");
            TempTomlFile {
                path: path.to_str().unwrap().to_string(),
            }
        }

        fn get_path(&self) -> &str {
            self.path.as_str()
        }
    }

    

    #[test]    
    fn test_load_configuration() {
        let toml_txt = r#"
            [profile]
            name = "test"
            [dock]
            host_or_ip = "localhost"
            startup_port = 2242
            certificate = "missing"
            [adapter]
            #blank
        "#;
        let tmpfile = TempTomlFile::new(toml_txt);
        let c = load_configuration(tmpfile.get_path());
        if let Err(e) = c {
            panic!("Error loading configuration: {}", e);
        }
        assert!(c.is_ok());
        let c = c.unwrap();
        assert_eq!(c.profile.name, "test");
        assert_eq!(c.get_name(), "test");
        assert_eq!(c.dock.host_or_ip, "localhost");
        assert_eq!(c.dock.startup_port, 2242);
        assert_eq!(c.adapter.private_key, None);
    }

    #[test]
    fn test_add_configuration() {
        let toml_txt = r#"
            [profile]
            name = "test"
            [dock]
            host_or_ip = "localhost"
            startup_port = 2242
            certificate = "missing"
            [adapter]
            #blank
        "#;
        let tmpfile = TempTomlFile::new(toml_txt);
        let c = load_configuration(tmpfile.get_path());
        assert!(c.is_ok());

        let conf = c.unwrap();
        let zpr = Zpr::new();

        let mut stats = zpr.get_status();
        assert_eq!(stats.len(), 0);

        let r = zpr.add_configuration(conf);
        if let Err(e) = r {
            panic!("Error adding configuration to Zpr: {}", e);
        }
        assert!(r.is_ok());

        stats = zpr.get_status();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].0, "test");
        assert_eq!(stats[0].1, "localhost");        
        assert_eq!(stats[0].2, "disconnected");                
    }

    #[test]
    fn test_cannot_have_duplicate_name() {
        let toml_txt = r#"
            [profile]
            name = "test"
            [dock]
            host_or_ip = "localhost"
            startup_port = 2242
            certificate = "missing"
            [adapter]
            #blank
        "#;
        let tmpfile1 = TempTomlFile::new(toml_txt);
        let c = load_configuration(tmpfile1.get_path());
        assert!(c.is_ok());
        let conf = c.unwrap();

        let zpr = Zpr::new();

        let r = zpr.add_configuration(conf);
        if let Err(e) = r {
            panic!("Error adding configuration to Zpr: {}", e);
        }
        assert!(r.is_ok());


        let toml_txt = r#"
            [profile]
            name = "test"
            [dock]
            host_or_ip = "anotherlocalhost"
            startup_port = 2243
            certificate = "missing"
            [adapter]
            #blank
        "#;
        let tmpfile2 = TempTomlFile::new(toml_txt);
        let c = load_configuration(tmpfile2.get_path());
        assert!(c.is_ok());
        let conf2 = c.unwrap();
        let r = zpr.add_configuration(conf2);
        assert!(r.is_err());
        let e = r.unwrap_err();
        assert!( e.to_string().contains("Configuration with name test already exists"));
    }

    #[test]
    fn test_empty_zpr_no_crash() {
        let zpr = Zpr::new();
        let stats = zpr.get_status();
        assert_eq!(stats.len(), 0);
        assert!(zpr.get_configuration_state("foo").is_none());
        let r = zpr.set_status("foo", ConfigState::Disconnected);
        assert!(r.is_err());
        let e = r.unwrap_err();
        assert!( e.to_string().contains("Configuration with name foo not found"));
    }

    #[test]
    fn test_set_state() {
        let toml_txt = r#"
            [profile]
            name = "test"
            [dock]
            host_or_ip = "localhost"
            startup_port = 2242
            certificate = "missing"
            [adapter]
            #blank
        "#;
        let tmpfile = TempTomlFile::new(toml_txt);
        let c = load_configuration(tmpfile.get_path());
        assert!(c.is_ok());
        let conf = c.unwrap();
        let zpr = Zpr::new();
        let r = zpr.add_configuration(conf);
        assert!(r.is_ok());

        let state = zpr.get_configuration_state("test");
        assert!(state.is_some());
        assert_eq!(state.unwrap(), ConfigState::Disconnected);

        let r = zpr.set_status("test", ConfigState::Connecting);
        assert!(r.is_ok());
        let state = zpr.get_configuration_state("test");
        assert!(state.is_some());
        assert_eq!(state.unwrap(), ConfigState::Connecting);

        let r = zpr.set_status("test", ConfigState::Connected(Instant::now()));
        assert!(r.is_ok());
        let state = zpr.get_configuration_state("test");
        assert!(state.is_some());
        assert!(matches!(state.unwrap(), ConfigState::Connected(_)));
    }
}

