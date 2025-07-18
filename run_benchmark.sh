#!/bin/bash

# This script builds and runs the custom benchmark for the falcon512_rs library.

# Ensure the script stops if any command fails
set -e

echo "🚀 Building and running benchmark for falcon512_rs..."

# The command to run a specific example in release mode with our custom features.
#
# --package falcon512_rs : Specifies which package to build (useful in a workspace).
# --example custom_bench : Tells Cargo to build and run the file in `examples/custom_bench.rs`.
# --release              : Crucial for performance. Compiles with full optimizations.
# --features bench       : Enables the `bench` feature to track memory allocations.
# -- -q                   : (Optional) The '-q' is passed to the final binary to make it less verbose.
#                          You can remove this if your program doesn't use it.
cargo run \
    --package falcon512_rs \
    --example benchmark \
    --release \
    --features bench

echo "✅ Benchmark finished."
