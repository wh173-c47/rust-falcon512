# Falcon512 Rust

This crate provides an efficient, constant-time implementation of key cryptographic primitives for the Falcon512 signature scheme, as well as supporting modular arithmetic and encoding/decoding routines. The code is tailored for use in lattice-based cryptography and digital signatures, with a focus on performances.
Implementation allows to be run on Solana (tested despite current max transaction size limit) and potentially other Rust compatible chains (untested).

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
    - Extracts ("squeezes") output from the SHAKE256 context in 8-byte chunks.

### Modular Arithmetic (Montgomery)

- `mq_montymul(a: u16, b: u16) -> u16`
    - Performs constant-time Montgomery modular multiplication with the field modulus `Q`.
- `mq_add(a: u16, b: u16) -> u16`
    - Modular addition: returns `(a + b) mod Q`.
- `mq_sub(a: u16, b: u16) -> u16`
    - Modular subtraction: returns `(a - b) mod Q`.

### Number Theoretic Transform

- `mq_ntt(p: &mut [u16; N])`
    - Performs an in-place Cooley-Tukey Radix-2 NTT utilizing Montgomery multiplication for speed and security. Used for fast polynomial operations in Falcon.
- `mq_intt(p: &mut [u16; N])`
    - Performs an in-place Cooley-Tukey Radix-2 inverse NTT utilizing Montgomery multiplication for speed and security. Used for fast polynomial operations in Falcon.

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

This crate includes a built-in benchmark suite to measure the performance of Falcon512 signature verification and related primitives.

You can run the benchmarks using the provided script:

```sh
./run_benchmark.sh
```

Example output (ran on a i5-10210U CPU @ 1.60GHz × 8):

```
--- Running Falcon512 Benchmarks ---
📊 Falcon512 Verify NIST Test vector 0
Bench: 100,000 runs, 2521.899 ms total
Avg per call:
  - Time: 0.025219 ms (39652.66 ops/sec)
  - CPU Cycles: 86,299
  - Memory: bytes peak usage 3,604,480

📊 Falcon512 Verify NIST Test vector 99
Bench: 100,000 runs, 3593.758 ms total
Avg per call:
  - Time: 0.035938 ms (27826.02 ops/sec)
  - CPU Cycles: 109,238
  - Memory: bytes peak usage 3,616,768
```

> **Benchmark Disclaimer:**  
> Benchmark results may vary significantly depending on your CPU architecture, system load, compiler optimizations, and hardware configuration. These benchmarks are provided for reference only and may not reflect real-world performance in all environments.

---

## Security Notes

- All cryptographic routines are implemented to be constant-time, but you should always audit and test for your specific target and platform.
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
