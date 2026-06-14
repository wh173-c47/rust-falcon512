//! Deterministic, CPU-load-agnostic benchmark for Falcon-512 `verify`.
//!
//! Unlike a wall-clock benchmark (`benches/benchmark.rs`, Criterion), this runs the workload
//! once under valgrind/callgrind and reports the **exact instruction count** plus a cache/cycle
//! model. The numbers are a pure function of the code path taken - independent of CPU frequency,
//! background load, allocator state, or which machine runs them.
//!
//! Run with:
//!   cargo bench --bench instr_count
//!
//! Requires `valgrind` and `iai-callgrind-runner` (matching the pinned `iai-callgrind` version)
//! on `$PATH`. On the first run every metric shows `+inf%` (no baseline yet); subsequent runs
//! print the delta against the previous run - that delta is the optimization signal.

use falcon512_rs::falcon512::verify;
use iai_callgrind::{black_box, main};

#[path = "shared/mod.rs"]
mod shared;

/// Full `verify` on NIST KAT #0 (short 73-byte nonce‖message: 0 absorb permutations).
#[inline(never)]
fn verify_kat_0() {
    let ok = verify(
        black_box(shared::KAT0_NONCE_MSG),
        black_box(shared::KAT0_SIG),
        black_box(&shared::KAT0_PK),
    );
    assert!(black_box(ok), "KAT0 must verify");
}

/// Full `verify` on NIST KAT #99 (large 3340-byte nonce‖message: exercises the SHAKE absorb path).
#[inline(never)]
fn verify_kat_99() {
    let ok = verify(
        black_box(shared::KAT99_NONCE_MSG),
        black_box(shared::KAT99_SIG),
        black_box(&shared::KAT99_PK),
    );
    assert!(black_box(ok), "KAT99 must verify");
}

main!(verify_kat_0, verify_kat_99);
