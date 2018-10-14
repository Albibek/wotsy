#!/bin/bash
set -e
cargo build -p wotsy_server --release
env RUST_LOG=debug wotsy_server/target/release/wotsy_server
