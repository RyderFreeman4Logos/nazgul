use crate::keypair::KeyPair;
use crate::traits::LocalByteConvertible;
use rand::rngs::OsRng;
use std::string::String;
use std::string::ToString;
use std::vec::Vec;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct WasmKeyPair(KeyPair);

#[wasm_bindgen]
impl WasmKeyPair {
    #[wasm_bindgen]
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let keypair = KeyPair::generate(&mut csprng);
        Self(keypair)
    }

    #[wasm_bindgen(js_name = fromSecretBytes)]
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<WasmKeyPair, JsValue> {
        KeyPair::from_bytes(bytes)
            .map(WasmKeyPair)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    #[wasm_bindgen(js_name = toSecretBytes)]
    pub fn to_secret_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    #[wasm_bindgen(js_name = getPublicBytes)]
    pub fn get_public_bytes(&self) -> Vec<u8> {
        self.0.public().to_bytes().to_vec()
    }

    #[wasm_bindgen(js_name = toSecretBase58)]
    pub fn to_secret_base58(&self) -> String {
        self.0.to_base58()
    }

    #[wasm_bindgen(js_name = getPublicBase58)]
    pub fn get_public_base58(&self) -> String {
        self.0.public().to_base58()
    }

    #[wasm_bindgen(js_name = fromSecretBase58)]
    pub fn from_secret_base58(s: &str) -> Result<WasmKeyPair, JsValue> {
        KeyPair::from_base58(s.to_string())
            .map(WasmKeyPair)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }
}

#[wasm_bindgen]
pub fn hello() -> String {
    "Hello from Nazgul!".to_string()
}
