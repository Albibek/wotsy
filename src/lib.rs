#![feature(custom_attribute)]
// Standard boilerplate
extern crate console_error_panic_hook;
extern crate wasm_bindgen;
extern crate wee_alloc;

extern crate aes;
extern crate base64;
extern crate block_modes;
extern crate itoa;
extern crate rand_core;
extern crate scrypt;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

// Debugging
pub use console_error_panic_hook::set_once as set_panic_hook;

use wasm_bindgen::prelude::*;

use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;
use aes::Aes256;
use block_modes::block_padding::Padding;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, BlockModeIv, Cbc};

use scrypt::{scrypt, ScryptParams};

use base64::URL_SAFE_NO_PAD;

use rand_core::block::{BlockRng, BlockRngCore};
use rand_core::RngCore;

//#[global_allocator]
//static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;
// Imports
#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);

    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);

    #[wasm_bindgen(js_namespace = Math)]
    fn random() -> f64;

    fn set_key(k: &str);

    fn efetch(url: &str, data: &[u8]);

    type HTMLDocument;
    static document: HTMLDocument;

    #[wasm_bindgen(method, js_name = getElementById)]
    fn get(this: &HTMLDocument, id: &str) -> HTMLElement;
    #[wasm_bindgen(method, structural, indexing_getter)]
    fn hget(this: &HTMLDocument, prop: &str) -> Element;

    type Element;
    #[wasm_bindgen(method, structural, indexing_getter)]
    fn child(this: &Element, prop: &str) -> Element;

    #[wasm_bindgen(method, structural, indexing_getter)]
    fn get(this: &Element, prop: &str) -> String;

    #[wasm_bindgen(method, setter = innerHTML)]
    fn set_inner_html(this: &Element, html: &str);

    type HTMLElement;

    //#[wasm_bindgen(method, getter)]
    //fn style(this: &HTMLElement) -> CSS2Properties;
    #[wasm_bindgen(method, setter = innerHTML)]
    fn h_set_inner_html(this: &HTMLElement, html: &str);

    #[wasm_bindgen(method, structural, indexing_getter)]
    fn get(this: &HTMLElement, prop: &str) -> String;

    #[wasm_bindgen(method, structural, indexing_getter)]
    fn get_list(this: &HTMLElement, id: &str) -> Box<[JsValue]>;

    #[wasm_bindgen(method, structural, indexing_setter)]
    fn set_list(this: &HTMLElement, id: &str, list: Box<[JsValue]>);

}

static URL: &str = "http://127.0.0.1:9999";

#[wasm_bindgen]
pub fn init() {
    set_panic_hook();
    log("HI");
}

#[derive(Serialize, Deserialize, Debug)]
struct Secret {
    iv: String,
    payload: String,
}

#[wasm_bindgen]
pub fn encrypt() {
    let o = document.get("secret").get("value");
    let mut secret = o.clone().into_bytes();

    let mut rng = BlockRng::new(JSRngCore);
    //   let params = ScryptParams::new(14, 8, 1).unwrap();
    let mut key = [0u8; 32];
    let mut iv_arr = [0u8; 16];
    //  let mut salt = [0u8; 8];
    // rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut iv_arr);

    let key = GenericArray::from_slice(&key);
    let iv = GenericArray::from_slice(&iv_arr);

    let len = secret.len();
    let mut cipher = Aes256Cbc::new_fixkey(&key, &iv);

    log(&String::from_utf8_lossy(&secret));
    log(&encode_bytes(&secret));
    log(&format!("{:?}", len));

    secret.resize(len + 16, 0);

    let mut padded = {
        //let padded_msg = Pkcs7::pad(&mut secret, len, 16).unwrap();
        Pkcs7::pad(&mut secret, len, 16).unwrap()
    };

    set_key(&encode_bytes(&key));
    cipher.encrypt_nopad(&mut padded).unwrap();

    let secret = Secret {
        iv: encode_bytes(&iv_arr),
        payload: encode_bytes(&padded),
    };
    let data = serde_json::to_string(&secret).unwrap();
    efetch("/create", &data.into_bytes());
}

#[wasm_bindgen]
pub fn links(response: &str) {
    let hash = &document.hget("window").child("location").get("hash");
    let href = format!("{}/s/{}{}", URL, response, hash);
    document
        .get("link_card")
        .h_set_inner_html(&format!("<a href=\"{}\">{}</a>", href, href));
    let o = document.get("links").set_list("classList", Box::new([]));
    let form_classes = document.get("secret_form").get_list("classList");
    let mut form_classes: Vec<JsValue> = form_classes.into();
    form_classes.push("uk-hidden".into());

    document
        .get("secret_form")
        .set_list("classList", form_classes.into());

    log("RESP");
    log(&format!("{:?}", o));
    //
}

#[wasm_bindgen]
pub fn decrypt() {
    let hash = &document.hget("window").child("location").get("hash");
    if !hash.starts_with("#") || hash.len() < 1 {
        return;
    }

    let key = &hash[1..];
    log("HASH");
    log(hash);

    //let mut cipher = Aes256Cbc::new_fixkey(&key, &iv);

    //cipher.decrypt_nopad(&mut padded).unwrap();
    //let res = Pkcs7::unpad(&mut pggadded).unwrap();

    //log(&encode_bytes(&res));
}

fn decode_bytes(data: &str) -> Vec<u8> {
    return base64::decode_config(&data, URL_SAFE_NO_PAD).unwrap();
}

fn encode_bytes(data: &[u8]) -> String {
    return base64::encode_config(&data, URL_SAFE_NO_PAD);
}

fn format_bytes(out: &[u8]) -> String {
    //let mut print_res = String::new();
    //out.iter().map(|b| itoa::fmt(&mut print_res, *b)).last();
    //return print_res;
    return base64::encode(&out);
}

struct JSRngCore;
impl BlockRngCore for JSRngCore {
    type Item = u32;
    type Results = [u32; 1];
    fn generate(&mut self, results: &mut Self::Results) {
        results[0] = (random() * ::std::u32::MAX as f64).floor() as u32;
    }
}
