#!/bin/bash
set -e
pushd wotsy_server
cargo build --release
popd
env RUST_LOG=debug wotsy_server/target/release/wotsy_server
