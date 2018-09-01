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
//extern crate scrypt;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

// Debugging
pub use console_error_panic_hook::set_once as set_panic_hook;

use wasm_bindgen::prelude::*;

use aes::block_cipher_trait::generic_array::GenericArray;
use aes::Aes256;
use block_modes::block_padding::Padding;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, BlockModeIv, Cbc};

//use scrypt::{scrypt, ScryptParams};

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

    fn efetch(url: &str, method: &str, data: &[u8], fu: usize);

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

    #[wasm_bindgen(method, structural, indexing_setter)]
    fn set_str(this: &Element, prop: &str, value: &str);

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

static BASEURL: &str = "http://127.0.0.1:9999";
static DATAURL: &str = "/s/";

#[wasm_bindgen]
pub fn init() {
    set_panic_hook();
    let hash = &document.hget("window").child("location").get("hash");

    if hash.len() == 0 || hash == "#" {
        visible("secret_form", true);
    } else {
        visible("decrypted", true);
        let mut url = String::new();
        url.push_str(DATAURL);
        hash[1..].split(":").next().map(|id| url.push_str(id));

        efetch(&url, "GET", &[], 1);
    }
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

    secret.resize(len + 16, 0);

    let mut padded = {
        //let padded_msg = Pkcs7::pad(&mut secret, len, 16).unwrap();
        Pkcs7::pad(&mut secret, len, 16).unwrap()
    };

    set_hash(&encode_bytes(&key));
    cipher.encrypt_nopad(&mut padded).unwrap();

    let secret = Secret {
        iv: encode_bytes(&iv_arr),
        payload: encode_bytes(&padded),
    };
    let data = serde_json::to_string(&secret).unwrap();
    efetch("/create", "POST", &data.into_bytes(), 0);
}

pub fn set_hash(value: &str) {
    document
        .hget("window")
        .child("location")
        .set_str("hash", value);
}

#[wasm_bindgen]
pub fn links(response: String) {
    // FIXME sanitize input
    let hash: &str = &document.hget("window").child("location").get("hash");
    let mut href = String::new();
    href.push_str(BASEURL);
    href.push_str("#");
    href.push_str(&response);
    href.push_str(":");

    href.push_str(&hash[1..]);

    let mut inner = String::new();
    inner.push_str("<a href=\"");
    inner.push_str(&href);
    inner.push_str("\">");
    inner.push_str(&href);
    inner.push_str("</a>");

    document.get("link_card").h_set_inner_html(&inner);
    visible("secret_form", false);
    visible("link", true);
    set_hash("");
}

pub fn visible(id: &str, visible: bool) {
    let classes = document.get(id).get_list("classList");
    let mut classes: Vec<JsValue> = classes.into();
    if visible {
        let class_js: JsValue = "uk-hidden".into();
        let pos: Option<usize> = classes.iter().position(|class| class == &class_js);
        if let Some(pos) = pos {
            classes.swap_remove(pos);
        }
    } else {
        classes.push("uk-hidden".into());
    }
    document.get(id).set_list("classList", classes.into());
}

#[wasm_bindgen]
pub fn decrypt(data: String) {
    let hash = &document.hget("window").child("location").get("hash");
    if !hash.starts_with("#") || hash.len() < 1 {
        return;
    }

    let key = decode_bytes(&hash[1..].split(":").skip(1).next().unwrap());
    log(hash);
    let secret: Secret = serde_json::from_str(&data).unwrap();
    log(&data);
    log(&secret.payload);
    let iv = decode_bytes(&secret.iv);
    let mut data = decode_bytes(&secret.payload);

    let key = GenericArray::from_slice(&key);
    let iv = GenericArray::from_slice(&iv);

    let mut cipher = Aes256Cbc::new_fixkey(&key, &iv);

    cipher.decrypt_nopad(&mut data).unwrap();
    let res = Pkcs7::unpad(&mut data).unwrap();
    let res = String::from_utf8_lossy(res);

    document.get("decrypted_secret").h_set_inner_html(&res);
}

fn decode_bytes(data: &str) -> Vec<u8> {
    return base64::decode_config(&data, URL_SAFE_NO_PAD).unwrap();
}

fn encode_bytes(data: &[u8]) -> String {
    return base64::encode_config(&data, URL_SAFE_NO_PAD);
}

struct JSRngCore;
impl BlockRngCore for JSRngCore {
    type Item = u32;
    type Results = [u32; 1];
    fn generate(&mut self, results: &mut Self::Results) {
        results[0] = (random() * ::std::u32::MAX as f64).floor() as u32;
    }
}
