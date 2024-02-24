use std::error::Error;
use serde_json::{json, Value};
use uuid::Uuid;
use crate::aes128::{Aes128Keychain, dec, enc};
use crate::plugin_error::PluginError;
use crate::utils;

#[derive(Debug, Clone)]
pub struct P100 {
    address: String,
    keychain: Aes128Keychain,
    cookies: String,
    token: String,
    terminal_uuid: Uuid
}

impl P100 {

    pub fn new(address: &str) -> Self {
        P100 {
            address: String::from(address),
            keychain: Aes128Keychain::empty(),
            cookies: String::new(),
            token: String::new(),
            terminal_uuid: Uuid::new_v4()
        }
    }

    fn cipher_payload(&self, json: Value) -> Result<String, Box<dyn Error>> {
        self.keychain.is_valid()?;
        let json_str = serde_json::to_string(&json)?;
        let pl = enc(&self.keychain, json_str.as_str())?;
        log::debug!("PAYLOAD : {}", &pl);
        Ok(pl)
    }

    fn decipher_response(&self, response: &str) -> Result<utils::P100Response, Box<dyn Error>> {
        let response_json: utils::P100Response = serde_json::from_str(response)?;
        let plain_res_str = dec(&self.keychain, response_json.result.unwrap().response.expect("Result does not contain response").as_str())?;
        Ok(serde_json::from_str(&plain_res_str)?)
    }

    fn decipher_device_info(&self, response: &str) -> Result<utils::P100DeviceInfo, Box<dyn Error>> {
        let response_json: utils::P100Response = serde_json::from_str(response)?;
        let plain_res_str = dec(&self.keychain, response_json.result.unwrap().response.expect("Result does not contain response").as_str())?;
        Ok(serde_json::from_str(&plain_res_str)?)
    }

    pub fn handshake(&mut self) -> Result<(), Box<dyn Error>> {
        let (rsa, rsa_pub) = utils::generate_rsa_keys()?;

        let res = ureq::post(format!("http://{}/app", self.address).as_str())
            .send_string(
                &serde_json::to_string_pretty(&json!({
                    "method": "handshake",
                    "params": {
                        "key": std::str::from_utf8(rsa_pub.as_slice())?,
                        "requestTimeMils": utils::now_ms()
                    }
                }))?
            )?;

        let cookies = res.header("Set-Cookie").unwrap().to_string();
        self.cookies = String::from_utf8(cookies.as_bytes()[0..cookies.len() - 13].to_vec())?;
        log::debug!("COOKIES : {}", self.cookies);

        let hs_res: utils::P100Response = res.into_json()?;

        // Decipher AES key and IV
        let cipher_key = base64::decode(&hs_res.result.unwrap().key.expect("Result does not contain key"))?;
        let plain_key = utils::rsa_decrypt(rsa.as_slice(), cipher_key.as_slice())?;
        let (key, iv) = (&plain_key[0..16], &plain_key[16..32]);
        // Create keychain
        self.keychain = Aes128Keychain::new(key, iv)?;
        log::debug!("{}", &self.keychain);

        Ok(())
    }

    pub fn login(&mut self, email: &str, password: &str) -> Result<(), Box<dyn Error>> {
        self.keychain.is_valid()?;

        let res = ureq::post(format!("http://{}/app", self.address).as_str())
            .set("Cookie", &self.cookies)
            .send_string(
                &serde_json::to_string_pretty(&json!({
                    "method": "securePassthrough",
                    "params": {
                        "request": self.cipher_payload(json!({
                            "method": "login_device",
                            "params": {
                                "username": utils::mime_encode(utils::sha_digest(email).as_bytes())?,
                                "password": utils::mime_encode(password.as_bytes())?
                            },
                            "requestTimeMils": utils::now_ms(),
                        }))?
                    }
                }))?
            )?
            .into_string()?;

        let res = self.decipher_response(&res)?;
        if res.error_code != 0 {
            return Err(Box::new(PluginError("Failed to shake hands.".to_string())));
        }
        // Decode token
        self.token = res.result.unwrap().token.expect("Result does not contain token");

        Ok(())
    }

    pub fn turn(&self, on: bool) -> Result<(), Box<dyn Error>> {
        self.keychain.is_valid()?;

        let res = ureq::post(format!("http://{}/app?token={}", self.address, self.token).as_str())
            .set("Cookie", &self.cookies)
            .send_string(
                &serde_json::to_string_pretty(&json!({
                    "method": "securePassthrough",
                    "params": {
                        "request": self.cipher_payload(json!({
                            "method": "set_device_info",
                            "params": {
                                "device_on": on
                            },
                            "requestTimeMils": utils::now_ms(),
                            "terminalUUID": self.terminal_uuid.to_string()
                        }))?
                    }
                }))?
            )?
            .into_string()?;

        if self.decipher_response(&res)?.error_code != 0 {
            return Err(Box::new(PluginError("Failed to log in.".to_string())));
        }

        Ok(())
    }

    pub fn turn_on(&self) -> Result<(), Box<dyn Error>> {
        self.turn(true)
    }

    pub fn turn_off(&self) -> Result<(), Box<dyn Error>> {
        self.turn(false)
    }

    pub fn get_device_info(&self) -> Result<bool, Box<dyn Error>> {
        self.keychain.is_valid()?;

        let res = ureq::post(format!("http://{}/app?token={}", self.address, self.token).as_str())
            .set("Cookie", &self.cookies)
            .send_string(
                &serde_json::to_string_pretty(&json!({
                    "method": "securePassthrough",
                    "params": {
                        "request": self.cipher_payload(json!({
                            "method": "get_device_info",
                            "requestTimeMils": utils::now_ms(),
                        }))?
                    }
                }))?
            )?
            .into_string()?;

        let res = self.decipher_device_info(&res)?;
        if res.error_code != 0 {
            return Err(Box::new(PluginError("Failed to get device info.".to_string())));
        }

        Ok(res.result.device_on)
    }

}