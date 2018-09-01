//#![deny(warnings)]
extern crate futures;
extern crate hyper;
extern crate hyper_staticfile;
extern crate pretty_env_logger;
#[macro_use]
extern crate log;
extern crate rand;
extern crate tokio_fs;
extern crate tokio_io;

extern crate base64;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

use futures::{future, Future, Stream};

use hyper::header::{HeaderValue, CONTENT_TYPE};
use hyper::service::service_fn;
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use hyper_staticfile::ResolveResult;

use rand::{thread_rng, Rng};
use std::io::{self, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static NOTFOUND: &[u8] = b"Not Found";
static STATIC: &str = "/pkg/";
static DATA_URL: &str = "/s/";
static DATA_DIR: &str = "data/";
static TIMEOUT: Duration = Duration::from_secs(60 * 60 * 24 * 7);

fn main() {
    //pretty_env_logger::init_custom_env("RUST_LOG=debug");
    pretty_env_logger::init();

    let addr = "127.0.0.1:9999".parse().unwrap();

    let server = Server::bind(&addr)
        .serve(|| service_fn(response))
        .map_err(|e| eprintln!("server error: {}", e));

    println!("Listening on http://{}", addr);

    hyper::rt::run(server);
}

#[derive(Serialize, Deserialize, Debug)]
struct Secret {
    iv: String,
    payload: String,
    #[serde(default)]
    timeout: u64,
}

type ResponseFuture = Box<Future<Item = Response<Body>, Error = io::Error> + Send>;

fn response(mut req: Request<Body>) -> ResponseFuture {
    let path = req.uri().path().to_string();
    let serve_static = path == "/" || path.starts_with(STATIC) || path == "/index.html";

    warn!("request {:?}", req);
    match (req.method().clone(), path) {
        (Method::GET, ref path) if serve_static => {
            let mut path = path.clone();
            if path == "/" {
                let uri = req.uri_mut();
                *uri = "/index.html".parse().unwrap();
                path = "/index.html".to_string(); // TODO. A little bit of needless alloc, but whatever
            }
            {
                req.headers_mut().remove("if-modified-since");
            }
            warn!("changed request {:?}", req);
            let resolve_future = hyper_staticfile::resolve("", &req);
            let future = resolve_future.map(move |result| match result {
                ResolveResult::Found(_, _) => {
                    let mime = if path.ends_with(".wasm") {
                        HeaderValue::from_str("application/wasm").unwrap()
                    } else if path.ends_with(".js") {
                        HeaderValue::from_str("application/javascript").unwrap()
                    } else if path.ends_with(".html") {
                        HeaderValue::from_str("text/html").unwrap()
                    } else if path.ends_with(".css") {
                        HeaderValue::from_str("text/css").unwrap()
                    } else {
                        HeaderValue::from_str("text/plain").unwrap()
                    };
                    let mut response = hyper_staticfile::ResponseBuilder::new()
                        .cache_headers(Some(1))
                        .build(&req, result)
                        .unwrap();

                    response.headers_mut().insert(CONTENT_TYPE, mime);
                    response
                }
                _ => Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(NOTFOUND.into())
                    .unwrap(),
            });
            Box::new(future)
        }

        (Method::GET, ref path) if path.starts_with(DATA_URL) => {
            // FIXME: retrieve data
            Box::new(future::ok(
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(NOTFOUND.into())
                    .unwrap(),
            ))
        }
        (Method::GET, _) => Box::new(future::ok(
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(NOTFOUND.into())
                .unwrap(),
        )),
        (Method::POST, ref path) if path == "/create" => {
            let future = req
                .into_body()
                .concat2()
                .and_then(move |body| {
                    let mut secret: Secret = serde_json::from_slice(&body).unwrap();
                    let mut id = [0u8; 24];
                    thread_rng().fill(&mut id);
                    let id = base64::encode_config(&id, base64::URL_SAFE_NO_PAD);
                    secret.timeout = (SystemTime::now() + TIMEOUT)
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let data = serde_json::to_vec(&secret).unwrap();
                    let mut filename = String::new();
                    filename.push_str(DATA_DIR);
                    // TODO encode to id filename directly
                    filename.push_str(&id);
                    filename.push_str(".secret");
                    warn!("F: {:?}", filename);
                    let mut file = std::fs::File::create(filename).unwrap();
                    file.write(&data).unwrap();
                    // body
                    future::ok(id)
                })
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::Other))
                .and_then(|id| {
                    future::ok(
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(id.into())
                            .unwrap(),
                    )
                });
            Box::new(future)
        }
        e => {
            warn!("got error {:?}", e);
            Box::new(future::ok(
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty())
                    .unwrap(),
            ))
        }
    }
}
