#!/bin/bash

set -e

echo "🚀 Building and running benchmark for falcon512_rs..."

cargo run \
    --package falcon512_rs \
    --example benchmark \
    --release \
    --features bench

echo "✅ Benchmark finished."
