#!/bin/bash
set -ex
cargo +nightly build --target wasm32-unknown-unknown --release
wasm-bindgen --out-dir pkg --browser --no-modules target/wasm32-unknown-unknown/release/wotsy.wasm
