#!/bin/bash

set -e

# Deterministic, CPU-load-agnostic benchmark: exact instruction count under valgrind/callgrind.
# This is the metric to track when optimizing - it is reproducible regardless of machine load.
# Requires `valgrind` and a matching `iai-callgrind-runner` on $PATH.
#
# Pin a fixed baseline target-cpu so the counts also reproduce across *machines*, overriding the
# `target-cpu=native` in .cargo/config.toml (RUSTFLAGS replaces build.rustflags for this one
# command). `cargo build --release` and the wall-clock bench below keep native for max performance.
#
# After the first run, each metric is printed with its delta vs the previous run.
echo "🔬 Deterministic instruction-count benchmark (valgrind/callgrind, portable x86-64 codegen)..."
RUSTFLAGS="-C target-cpu=x86-64" cargo bench --bench instr_count

echo ""
echo "⏱️  Wall-clock reference benchmark (jemalloc, native codegen; load-dependent, ns/cycles/peak-mem)..."
cargo bench --bench wall_clock_benchmark --features bench

echo "✅ Benchmark finished."
