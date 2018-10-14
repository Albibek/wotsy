#![feature(custom_attribute)]
// Standard boilerplate
extern crate console_error_panic_hook;
extern crate js_sys;
extern crate wasm_bindgen;
extern crate web_sys;
extern crate wee_alloc;

extern crate aes;
extern crate base64;
extern crate block_modes;
extern crate itoa;
extern crate rand_core;
//extern crate scrypt;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

// Debugging
pub use console_error_panic_hook::set_once as set_panic_hook;

use js_sys::{Math, Object};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use aes::block_cipher_trait::generic_array::GenericArray;
use aes::Aes256;
use block_modes::block_padding::Padding;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, BlockModeIv, Cbc};

//use scrypt::{scrypt, ScryptParams};

use base64::URL_SAFE_NO_PAD;

use rand_core::block::{BlockRng, BlockRngCore};
use rand_core::RngCore;

use web_sys::{window, HtmlAnchorElement, HtmlTextAreaElement, Node, RequestInit, Response};

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

// Imports
//#[wasm_bindgen]
//extern "C" {
//fn efetch(url: &str, method: &str, data: &[u8], fu: usize);
//}

static DATAURL: &str = "/s/";
lazy_static! {
    static ref WIN: web_sys::Window = window().expect("should have window");
    static ref DOC: web_sys::Document = WIN.document().expect("window should have document");
}

/*
 function efetch(url, method, data, id) {
            params = {
                method: method,
            };
            if (method == "POST") {
                params.body = data
            };
            fetch(url,params)
            .then((response) => response.text(), (reason) => alert(reason))
            .then((text)=>callbacks[id](text), (reason) => alert(reason));
        }
 */
fn efetch(url: &str, method: &str, data: Option<&str>, fu: usize) {
    let mut init = RequestInit::new();
    init.method(method);
    if method == "POST" {
        if let Some(data) = data {
            init.body(Some(&JsValue::from_str(data)));
        }
    }

    let success = Closure::wrap(Box::new(move |response: JsValue| {
        let response_text = Closure::wrap(Box::new(move |result: JsValue| {
            match fu {
                0 => links(result.as_string().unwrap()),
                1 => decrypt(result.as_string().unwrap()),
                _ => log("bad index"),
            };
            //           log(&format!("OK RESPONSE! {:?}", &result.as_string().unwrap()));
        }) as Box<FnMut(JsValue)>);
        response
            .dyn_into::<Response>()
            .unwrap()
            .text()
            .unwrap()
            .then(&response_text);
        response_text.forget();
    }) as Box<FnMut(JsValue)>);

    let failure = Closure::wrap(Box::new(move |result| {
        // TODO beatiful error
        log(&format!("FAIL RESPONSE! {:?}", result));
    }) as Box<FnMut(JsValue)>);

    WIN.fetch_with_str_and_init(url, &init)
        .then2(&success, &failure);
    success.forget();
    failure.forget();
}

#[allow(unused)]
fn log(m: &str) {
    web_sys::console::log_1(&JsValue::from_str(m));
}

#[wasm_bindgen]
pub fn init() {
    set_panic_hook();
    let hash = WIN.location().hash().unwrap();

    if hash.len() == 0 || hash == "#" {
        visible("secret_form", true);
    } else {
        visible("decrypted", true);
        let mut url = String::new();
        url.push_str(DATAURL);
        hash[1..].split(":").next().map(|id| url.push_str(id));

        efetch(&url, "GET", None, 1);
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Secret {
    iv: String,
    payload: String,
}

#[wasm_bindgen]
pub fn encrypt() {
    let mut secret = DOC
        .get_element_by_id("secret")
        .unwrap()
        .dyn_into::<HtmlTextAreaElement>()
        .unwrap()
        .value()
        .into_bytes();

    let mut rng = BlockRng::new(JSRngCore);
    // TODO password protection for secret
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

    let mut padded = Pkcs7::pad(&mut secret, len, 16).unwrap();

    WIN.location().set_hash(&encode_bytes(&key)).unwrap();
    cipher.encrypt_nopad(&mut padded).unwrap();

    let secret = Secret {
        iv: encode_bytes(&iv_arr),
        payload: encode_bytes(&padded),
    };
    let data = serde_json::to_string(&secret).unwrap();
    efetch("/create", "POST", Some(&data), 0);
}

#[wasm_bindgen]
pub fn links(response: String) {
    // FIXME sanitize input
    let location = WIN.location();
    let hash = location.hash().unwrap();
    let mut href = String::new();
    let url = web_sys::Url::new(&DOC.url().unwrap()).unwrap();
    url.set_hash("");

    href.push_str(&url.href());
    href.push_str("#");
    href.push_str(&response);
    href.push_str(":");
    href.push_str(&hash[1..]);

    let anchor = DOC.create_element("a").unwrap();
    anchor.set_attribute("href", &href).unwrap();
    let anchor = anchor.dyn_into::<HtmlAnchorElement>().unwrap();
    anchor.set_text(&href).unwrap();

    let link_card = DOC.get_element_by_id("link_card").unwrap();
    AsRef::<Node>::as_ref(&link_card)
        .append_child(anchor.as_ref())
        .unwrap();
    visible("secret_form", false);
    visible("link", true);
    location.set_hash("").unwrap();
}

pub fn visible(id: &str, visible: bool) {
    let element = DOC.get_element_by_id(id).unwrap();

    let classes = element.class_list();

    if visible && classes.contains("uk-hidden") {
        classes.remove_1("uk-hidden").unwrap();
    } else if !visible && !classes.contains("uk-hidden") {
        classes.add_1("uk-hidden").unwrap();
    }
}

#[wasm_bindgen]
pub fn decrypt(data: String) {
    let location = WIN.location();
    let hash = location.hash().unwrap();

    if !hash.starts_with("#") || hash.len() < 1 {
        return;
    }

    // TODO beautiful error
    let key = decode_bytes(&hash[1..].split(":").skip(1).next().expect("bad link data"));
    let secret: Secret = serde_json::from_str(&data).unwrap();
    let iv = decode_bytes(&secret.iv);
    let mut data = decode_bytes(&secret.payload);

    let key = GenericArray::from_slice(&key);
    let iv = GenericArray::from_slice(&iv);

    let mut cipher = Aes256Cbc::new_fixkey(&key, &iv);

    cipher.decrypt_nopad(&mut data).unwrap();
    let res = Pkcs7::unpad(&mut data).unwrap();
    let res = String::from_utf8_lossy(res);

    DOC.get_element_by_id("decrypted_secret")
        .unwrap()
        .dyn_into::<Node>()
        .unwrap()
        .set_text_content(Some(&res));
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
        results[0] = (Math::random() * ::std::u32::MAX as f64).floor() as u32;
    }
}
