
use std::net::Ipv6Addr;
use std::io::{Error, ErrorKind, Cursor, SeekFrom, Read, Seek};
use std::time::SystemTime;
use byteorder::{BigEndian, WriteBytesExt, ReadBytesExt}; 
use base64::prelude::*;
use ring::signature;
use tracing::info;


use crate::cd::zpr::Configuration;

use tokio::{
    net::TcpStream,
    io::AsyncWriteExt,
};


const NOISE_KEY_LEN: usize = 32;
const HMAC_SHA256_LEN: usize = 256;
const START_ME_UP_MIN_MSG_LEN: usize = 32 + NOISE_KEY_LEN + HMAC_SHA256_LEN; // <core message> + <noise key> + <hmac>
const START_ME_UP_NONCE_LEN: usize = 8;

const START_ME_UP_STATUS_OK: u8 = 0x0;

// The only signature type we support.
const SIG_TYPE_RSA_PKCS1_SHA256: u8 = 0x1;

// Therse are offsets into the start-me-up response message.
const OFFSET_WG_PORT: usize = 2;
const OFFSET_IP_ADDR: usize = 4;
const OFFSET_NETMASK: usize = 20;
const OFFSET_SIGTYPE: usize = 21;
const OFFSET_KEYLEN: usize = 22;
const OFFSET_NONCE: usize = 24;
const OFFSET_DATA: usize = 32;


pub struct StartMeUpResponse {
    pub wg_port: u16,
    pub local_wg_addr: Ipv6Addr,  // the dock side is .1 (TODO: we could compute that before returning)
    pub ipv6_mask: u8,
    pub noise_key: [u8; NOISE_KEY_LEN],
}


// Run the start-me-up protocol against the dock. All needed details are in the
// passed configuration.
pub async fn do_start_me_up(config: &Configuration) -> Result<StartMeUpResponse, std::io::Error> {
 
    let msg = create_start_me_up_msg(config)?;

    info!("starting connect to dock {}: {}", config.get_dock_host(), config.get_dock_startup_port());
    let mut stream = TcpStream::connect(format!("{}:{}", config.get_dock_host(), config.get_dock_startup_port())).await?;

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

    rdr.seek(SeekFrom::Start(OFFSET_WG_PORT as u64))?;
    let wg_port = ReadBytesExt::read_u16::<BigEndian>(&mut rdr)?;    

    // read IPv6
    rdr.seek(SeekFrom::Start(OFFSET_IP_ADDR as u64))?;    
    let mut ip6 = [0u16; 8];
    for i in 0..8 {
        ip6[i] = ReadBytesExt::read_u16::<BigEndian>(&mut rdr)?;
    }
    let ip6_addr = Ipv6Addr::new(ip6[0], ip6[1], ip6[2], ip6[3], ip6[4], ip6[5], ip6[6], ip6[7]);
    let ipv6_mask = resp_buffer[OFFSET_NETMASK];

    let sig_type = resp_buffer[OFFSET_SIGTYPE];
    if sig_type != SIG_TYPE_RSA_PKCS1_SHA256 {
        return Err(Error::new(
            ErrorKind::Other,
            format!("Unsupported signature type: {}", sig_type),
        ));
    }
    
    rdr.seek(SeekFrom::Start(OFFSET_KEYLEN as u64))?;
    let key_len = ReadBytesExt::read_u16::<BigEndian>(&mut rdr)?;    
    if key_len as usize != NOISE_KEY_LEN {
        return Err(Error::new(
            ErrorKind::Other,
            format!("Invalid key length {}", key_len),
        ))
    }

    let mut nonce = [0u8; START_ME_UP_NONCE_LEN];
    for i in 0..START_ME_UP_NONCE_LEN {
        nonce[i] = resp_buffer[OFFSET_NONCE+i];
    }

    // We already checked the length of the response above so there is no danger of 
    // exceeding the bounds of the buffer here.  From here on we assume a NOISE key,
    // and a 256 byte HMAC.

    let mut noise_key = [0u8; NOISE_KEY_LEN];
    for i in 0..NOISE_KEY_LEN {
        noise_key[i] = resp_buffer[OFFSET_DATA+i];
    }
    // Next we should have hmac    
    let mut hmac = [0u8; HMAC_SHA256_LEN];
    for i in 0..HMAC_SHA256_LEN {
        hmac[i] = resp_buffer[OFFSET_DATA + NOISE_KEY_LEN + i];
    }

    // Hmac is over CONCAT( address, nonce, key ) and uses the ZPR node_key rsa key.
    let mut checkbuf = Vec::new();
    checkbuf.extend_from_slice(&ip6_addr.octets());
    checkbuf.extend_from_slice(&nonce);
    checkbuf.extend_from_slice(&noise_key);

    // The path in the config file is relative to the config file path itself... unless it starts with /
    // which Path::join takes care of magically.
    let der_path = std::path::Path::new(&config.get_path()).parent().unwrap().join(&config.get_dock_certificate());
    let public_key = 
        signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, 
                                          read_file(der_path.as_path())?);
    public_key.verify(&checkbuf, &hmac)
        .map_err(|e| std::io::Error::new(ErrorKind::Other, format!("hmac verify error: {:?}", e)))?;                                      

    let resp = StartMeUpResponse {
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

    if let Some(key) = config.get_adapter_public_key().as_ref() {
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
