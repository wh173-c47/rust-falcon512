# Falcon512 Rust

This crate provides an efficient implementation of key cryptographic primitives for the Falcon512 signature scheme, as well as supporting modular arithmetic and encoding/decoding routines. The code is tailored for use in lattice-based cryptography and digital signatures, with a focus on performances.
Implementation allows to be run on Solana (tested despite current max transaction size limit) and potentially other Rust compatible chains (untested).

> **Verification is a public-input operation.** Falcon `verify` hashes `nonce ‖ message` (both public, transmitted with the signature), so it uses the **variable-time** `hash_to_point` - the rejection sampler the reference verifier uses - rather than the constant-time oversampling + sorting network. This produces the identical challenge polynomial at a fraction of the cost (see [`OPTIMIZATION_NOTES.md`](./OPTIMIZATION_NOTES.md)). There is no secret on the verify path; constant-time hashing matters only for *signing*, which this crate does not (yet) implement.

## Features

- **Keccak/SHAKE256 permutation core**: Efficiently processes the state for SHAKE-based hash functions.
- **Montgomery modular arithmetic**: Constant-time multiplication, addition, subtraction, and utility functions for cryptographic fields.
- **Number Theoretic Transform (NTT)**: Fast polynomial transforms for use in lattice-based cryptography.
- **Signature verification and encoding**: Utilities for signature checking and public key handling, including NTT format conversion.
- **To be implemented**:
  - `keygen`
  - `sign`

## Highlights

### Cryptographic Hashing

- `process_block(shake_ctx: &mut [u64; 26])`
    - Runs the Keccak permutation on a SHAKE256 context, mutating the state in-place.
- `shake_inject(shake_ctx: &mut [u64; 26], input: &[u8])`
    - Absorbs input bytes into the SHAKE256 context. Not intended for consecutive calls.
- `shake_flip(shake_ctx: &mut [u64; 26])`
    - Switches the SHAKE256 context to output mode, after which extraction can occur.
- `shake_extract(shake_ctx: &mut [u64; 26]) -> [u64; SHAKE_EXTRACT_OUT_CAPACITY_WORDS]`
    - Extracts ("squeezes") the full constant-time oversample (11 permutations). Kept as the A/B reference.
- `shake_extract_vartime(shake_ctx: &mut [u64; 26]) -> [u64; SHAKE_VARTIME_WORDS]`
    - Squeezes only the 9 rate blocks the variable-time sampler needs (the production verify path).

### Modular Arithmetic (Montgomery)

- `mq_montymul(a: u16, b: u16) -> u16`
    - Performs constant-time Montgomery modular multiplication with the field modulus `Q`.
- `mq_add(a: u16, b: u16) -> u16`
    - Modular addition: returns `(a + b) mod Q`.
- `mq_sub(a: u16, b: u16) -> u16`
    - Modular subtraction: returns `(a - b) mod Q`.

### Number Theoretic Transform

- `mq_ntt(p: &mut [u16; N])`
    - In-place radix-8 (3-stage-merged) Cooley-Tukey NTT with Montgomery multiplication and deferred reduction. Used for fast polynomial operations in Falcon.
- `mq_intt(p: &mut [u16; N])`
    - In-place radix-8 inverse NTT (Montgomery, deferred reduction). Used for fast polynomial operations in Falcon.

### Encoding, Decoding, and Verification

- `mq_decode(x: &mut [u16; N], input: &[u8; FALCON_PK_SIZE], offset: usize) -> usize`
    - Decodes a Falcon public key from a byte slice into polynomial coefficients.
- `pk_to_ntt_fmt(pk: &[u8; FALCON_PK_SIZE]) -> [u16; N]`
    - Converts and validates a public key, returning it in NTT format (panics on invalid input).
- `verify(nonce_msg: &[u8], sig: &[u8], pk_ntt_fmt: &[u16; N]) -> bool`
    - Verifies a Falcon signature for the given nonce + message and public key.

## Usage

Include the crate in your `Cargo.toml`:

```toml
[dependencies]
falcon512_rs = "0.1"
```

Example for signature verification:

```rust
let pk_ntt = pk_to_ntt_fmt(&pk);
let valid = verify(&nonce_msg, &sig, &pk_ntt);

assert!(valid);
```

## Benchmarks

The primary benchmark is **deterministic and CPU-load-agnostic**: it counts the exact number of
instructions executed by `verify` under valgrind/callgrind (via `iai-callgrind`).
Unlike wall-clock timing, the result is independent of CPU
frequency, background load, and the host - so it can tell a 2% optimization from noise, and an
optimization is judged by its instruction delta. See [`OPTIMIZATION_NOTES.md`](./OPTIMIZATION_NOTES.md).

```sh
./run_benchmark.sh                                       # deterministic (portable) + wall-clock (native)
RUSTFLAGS="-C target-cpu=x86-64" cargo bench --bench instr_count   # deterministic, reproducible across machines
cargo bench --bench wall_clock_benchmark --features bench  # jemalloc wall-clock (ns / cycles / peak memory)
cargo bench --bench benchmark                            # Criterion wall-clock (ns / ops-sec)
```

`.cargo/config.toml` sets `target-cpu=native`, so `cargo build --release` and the wall-clock benches
get the full native ISA (~+10%). The deterministic bench is the exception: `run_benchmark.sh` pins it
to a fixed baseline `x86-64` (`RUSTFLAGS`) so its instruction counts reproduce on any host - the
numbers below are those portable counts. (A bare `cargo bench --bench instr_count`, without the
`RUSTFLAGS` pin, would instead use native and report lower, machine-specific counts.)

All benchmark dependencies (`iai-callgrind`, `criterion`, `jemallocator`, `num-format`) are
`[dev-dependencies]` - none are compiled into a normal `cargo build`. The wall-clock harness body is
additionally gated behind the `bench` feature.

Deterministic instruction counts for `verify` (portable `x86-64` codegen) - ~−64% / −45% versus the
original constant-time implementation (see [`OPTIMIZATION_NOTES.md`](./OPTIMIZATION_NOTES.md)):

| NIST KAT | Instructions | Estimated cycles |
|----------|-------------:|-----------------:|
| #0  (73-byte message) | 117,649 | 166,825 |
| #99 (3340-byte message) | 253,983 | 367,699 |

With `target-cpu=native` (the default release build) these drop further to 98,568 and 220,814
instructions respectively.

On the first run every metric shows `+inf%` (no baseline); subsequent runs print the delta against
the previous run - that delta is the optimization signal.

Two wall-clock benchmarks (both under `benches/`) are retained for human-facing numbers only - the
Criterion `benchmark` (ns / ops-sec) and the jemalloc `wall_clock_benchmark` (ns / CPU cycles / peak
memory):

*run on an Intel(R) Core(TM) i5-10210U CPU @ 1.60GHz*
```
--- Running Falcon512 Benchmarks ---
📊 Falcon512 Verify NIST Test vector 0
Bench: 100,000 runs, 1204.019 ms total
Avg per call:
  - Time: 0.012040 ms (83055.18 ops/sec)
  - CPU Cycles: 66,842
  - Memory: bytes peak usage 3,604,480

📊 Falcon512 Verify NIST Test vector 99
Bench: 100,000 runs, 2589.878 ms total
Avg per call:
  - Time: 0.025899 ms (38611.86 ops/sec)
  - CPU Cycles: 96,986
  - Memory: bytes peak usage 3,616,768

```

> **Wall-clock disclaimer:** the ns / ops-sec / `rdtsc`-cycle numbers vary significantly with CPU
> architecture, system load, and hardware. They are reference-only. For tracking optimizations, use
> the deterministic instruction count above.

---

## Security Notes

- This is a **verification-only** crate, and `verify` operates entirely on public data (`nonce ‖ message`, signature, public key). The hash-to-point is therefore variable-time *by design* - see the note at the top. The modular-arithmetic primitives (`mq_montymul`/`mq_add`/`mq_sub`) are branchless; the rejection sampler and decoders are not constant-time and must not be reused on secret inputs (e.g. a future signing path). Always audit for your specific target and platform.
- Never use these primitives without understanding the Falcon signature scheme and its parameterization.
- This crate assumes valid inputs and panics on malformed data where appropriate.
- This code use unchecked maths and unsafe pointer accesses & updates (on bounded indexes).

## License

This code is released under the MIT License. See [LICENSE](./LICENSE) for details.

## References

- [Falcon: Fast-Fourier Lattice-based Compact Signatures over NTRU](https://falcon-sign.info/)
- [Keccak Team: SHA-3 and SHAKE Functions](https://keccak.team/)

---
For questions, bug reports, or contributions, please open an issue or pull request!

> This code is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.
