use std::error::Error;
use std::fmt::{Display, Formatter};
use openssl::symm::{Cipher, encrypt};
use crate::plugin_error::PluginError;
use crate::utils;

#[derive(Debug, Clone)]
pub struct Aes128Keychain {
    key: Vec<u8>,
    iv: Vec<u8>
}

impl Display for Aes128Keychain {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Aes128Keychain [ KEY '{}'; IV '{}' ]", hex::encode(self.key()), hex::encode(self.iv()))
    }
}

impl Aes128Keychain {

    pub fn empty() -> Self {
        Aes128Keychain {
            key: Vec::new(),
            iv: Vec::new()
        }
    }

    pub fn new(key: &[u8], iv: &[u8]) -> Result<Self, Box<dyn Error>> {
        let kc = Aes128Keychain {
            key: key.to_vec(),
            iv: iv.to_vec()
        };
        kc.is_valid()?;
        Ok(kc)
    }

    pub fn is_valid(&self) -> Result<(), Box<dyn Error>> {
        if self.key.len() == 16 && self.iv.len() == 16 {
            Ok(())
        } else {
            Err(Box::new(PluginError("Keychain is invalid".to_string())))
        }
    }

    pub fn key(&self) -> &[u8] {
        self.key.as_slice()
    }

    pub fn iv(&self) -> &[u8] {
        self.iv.as_slice()
    }

}

pub fn enc(keychain: &Aes128Keychain, payload: &str) -> Result<String, Box<dyn Error>> {
    let pad = (0..16 - payload.len() % 16).map(|_| 4u8).collect::<Vec<u8>>();
    let buf = [ payload.as_bytes(), &pad ].concat();
    Ok(utils::mime_encode(
        &encrypt(
            Cipher::aes_128_cbc(),
            keychain.key(),
            Some(keychain.iv()),
            buf.as_slice()
        )?)?
        .replace("\r\n", ""))
}

pub fn dec(keychain: &Aes128Keychain, payload: &str) -> Result<String, Box<dyn Error>> {
    keychain.is_valid()?;
    Ok(String::from(std::str::from_utf8(
        openssl::symm::decrypt(
            openssl::symm::Cipher::aes_128_cbc(),
            keychain.key(),
            Some(keychain.iv()),
            base64::decode(payload)?.as_slice()
        )?.as_slice()
    )?))
}