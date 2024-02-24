use std::collections::HashMap;
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use openssl::rsa::{Padding, Rsa};
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct P100Response {
    pub error_code: i32,
    pub result: Option<P100Result>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct P100Result {
    pub key: Option<String>,
    pub response: Option<String>,
    pub token: Option<String>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct P100DeviceInfo {
    pub error_code: i32,
    pub result: P100DeviceInfoData
}

#[derive(Debug, Serialize, Deserialize)]
pub struct P100DeviceInfoData {
    pub device_id: String,
    pub fw_ver: String,
    pub hw_ver: String,
    #[serde(rename = "type")]
    pub device_type: String,
    pub model: String,
    pub mac: String,
    pub hw_id: String,
    pub fw_id: String,
    pub oem_id: String,
    pub specs: String,
    pub device_on: bool,
    pub on_time: i32,
    pub overheated: bool,
    pub nickname: String,
    pub location: String,
    pub avatar: String,
    pub longitude: usize,
    pub latitude: usize,
    pub has_set_location_info: bool,
    pub ip: String,
    pub ssid: String,
    pub signal_level: i32,
    pub rssi: i32,
    pub region: String,
    pub time_diff: i32,
    pub lang: String,
    pub default_states: P100State
}

#[derive(Debug, Serialize, Deserialize)]
pub struct P100State {
    #[serde(rename = "type")]
    pub state_type: String,
    pub state: HashMap<String, String>
}

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_secs() * 1000
}

pub fn sha_digest(data: &str) -> String {
    sha1_smol::Sha1::from(data).digest().to_string()
}

pub fn mime_encode(data: &[u8]) -> Result<String, Box<dyn Error>> {
    let encoded_string = base64::encode(data);
    let mut encoded_vec = encoded_string.as_bytes().to_vec();
    let mut count = 0;
    for i in (76..encoded_vec.len()).step_by(76) {
        encoded_vec.insert(i + count, b'\r');
        encoded_vec.insert(i + count + 1, b'\n');
        count += 1;
    }
    Ok(std::str::from_utf8(&encoded_vec)?.to_string())
}

pub fn generate_rsa_keys() -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let rsa = Rsa::generate(1024)?;
    let private_key: Vec<u8> = rsa.private_key_to_pem()?;
    let public_key: Vec<u8> = rsa.public_key_to_pem()?;
    log::debug!("Private key : {}", String::from_utf8(private_key.clone())?);
    log::debug!("Public key : {}", String::from_utf8(public_key.clone())?);
    Ok((private_key, public_key))
}

pub fn rsa_decrypt(rsa: &[u8], cipher_payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let rsa = Rsa::private_key_from_pem(rsa)?;
    let mut plain_payload: Vec<u8> = vec![0; rsa.size() as usize];
    rsa.private_decrypt(cipher_payload, &mut plain_payload, Padding::PKCS1)?;
    Ok(plain_payload)
}
