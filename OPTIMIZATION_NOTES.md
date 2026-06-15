# Falcon-512 (Rust) - `verify` optimization notes

A log of how `verify` was optimized and, just as importantly, what was tried and **reverted**. NIST
/ FN-DSA behaviour is preserved throughout: SHAKE256 is untouched, and the challenge polynomial `c`,
the public-key NTT format, and every KAT distance are unchanged - the 10 known-answer distances are
the correctness oracle for every change here.

The recurring theme is that the binding cost on a modern CPU is **whether LLVM can keep work in
registers and auto-vectorize it**, which is frequently the opposite of what a naive instruction count
or a register-machine intuition predicts. Several "obvious" wins regress; the section on reverts is
the interesting part.

---

## How performance is measured

Wall-clock timing (and `rdtsc` cycles) depends on CPU frequency scaling, background load, and the
allocator - it can't tell a 2% win from noise. The optimization signal is instead a **deterministic
instruction count under valgrind/callgrind**, via `iai-callgrind` (`benches/instr_count.rs`):

```sh
cargo bench --bench instr_count
```

The reported *Instructions / L1 / L2 / RAM / Estimated Cycles* are a pure function of the executed
code path. After the first run iai prints each metric's **delta vs the previous run** - that delta is
the signal. (Caveat: callgrind models cache but **not** branch prediction, so a change that only
trades a predictable branch for branchless code is invisible here; such changes are judged on the
wall-clock bench instead.)

`.cargo/config.toml` enables `target-cpu=native`, so `cargo build --release` and the wall-clock
benches use the full host ISA (~10% fewer instructions from auto-vectorization). The deterministic
bench is the exception: `run_benchmark.sh` pins it to a fixed baseline `x86-64` so its counts
reproduce on any host. Both sets of numbers are reported below.

---

## Results (`verify`, instructions)

Portable (`x86-64`) counts - the reproducible metric:

| stage | KAT 0 | Δ vs baseline | KAT 99 | Δ vs baseline |
|-------|------:|--------:|-------:|---------:|
| baseline (constant-time hash-to-point, 11 permutations) | 327,957 | - | 464,280 | - |
| variable-time hash-to-point, 9 permutations, `% q` sampler | 180,076 | −45.1% | 316,410 | −31.8% |
| deferred-reduction (lazy) NTT butterflies | 171,114 | −47.8% | 307,448 | −33.8% |
| radix-8 stage-merged NTT (forward + inverse) | 118,073 | −64.0% | 254,407 | −45.2% |
| **fused subtract-c0 + normalize tail** | **117,649** | **−64.1%** | **253,983** | **−45.3%** |

For reference, the same final build with `target-cpu=native`: **KAT 0 = 98,568** (cycles 153,143),
**KAT 99 = 220,814** (cycles 340,063).

KAT 99 moves less in % because its 3340-byte message spends a large fraction of its time in the SHAKE
*absorb* permutations, which none of these changes touch.

---

## Optimizations applied

### Variable-time hash-to-point
The verifier hashes `nonce ‖ message`, which is entirely **public** - there is no secret to protect,
so the constant-time oversampling + sorting-network compaction (`hash_to_point_ct`) is wasted work.
`hash_to_point_vartime` instead streams the squeezed XOF and collects the first `N` accepted draws in
stream order. This deletes the oversample buffer and the whole conditional-move compaction network.
The output is bit-identical to the constant-time challenge - proven by
`tests::hash_to_point_ab::ct_and_vartime_produce_identical_challenge` and by the KAT distances.

### Fewer SHAKE permutations
The variable-time sampler needs only ~546 draws to accept 512 coefficients (rejection ≈ 6.24%). Nine
Keccak rate blocks give 612 draws ⇒ E[accepted] ≈ 574, σ ≈ 6 - a short fill is a ~10σ event.
`shake_extract_vartime` squeezes a fixed 9 blocks instead of the 11 the constant-time oversample
required, dropping 2 of the most expensive operations in the function. Each block is a full 17-word
rate, copied whole-word.

### Direct `% q` in the sampler
The per-draw reducer used a ~20-instruction **branchless** reduction (four subtract rounds + a
sentinel) because it served the constant-time path. The variable-time sampler is already branchy, so
it collapses to `if t < 5q { t % q }`. LLVM lowers the constant `% 12289` to a ~4-instruction
multiply-by-reciprocal, and the reject branch is ~94% not-taken - a real win on both instructions and
cycles. (≈ −15 instructions on each of ~550 draws.)

### Deferred-reduction (lazy) NTT butterflies
`q = 12289` leaves headroom up to `5q < 2^16` in a `u16`. Because each Montgomery twiddle product is
already `< q`, a butterfly's sum and its `q`-biased difference (`u + Q − v`, ≡ `u − v mod q`, kept
non-negative) can be written back **without a per-butterfly conditional reduction**; values grow by
at most `q` per level and are folded back with a single `% q` pass only when they approach the `u16`
ceiling. This removes the branchless conditional reductions from the hot path. The bound schedule is
machine-checked by z3 (`z3/lazy_ntt_bounds.py`): it proves, over the exact REDC bit arithmetic, that
every stored value stays `< 2^16` and that the single conditional inside `mq_montymul` still lands the
product in `[0, q)` for operands up to `4q`.

### Radix-8 stage-merged NTT (the big one)
The largest single win. A radix-2 NTT makes **9 passes** over the 512-element array (each pass = 512
loads + 512 stores); the multiply count is fixed but the memory traffic is not. The transform is
re-expressed as a **radix-8** transform: nine stages collapse into **3 passes**, each loading a group
of 8 coefficients once, running all three butterfly levels (12 sub-butterflies, 7 twiddles) entirely
in registers, and storing 8 once - cutting load/store traffic ~3× and keeping every intermediate
register-resident. Twiddles are read from `GMB`/`IGMB` at the same offsets the radix-2 stages use, so
the output ordering - and therefore the public-key NTT format - is unchanged.

Forward and inverse differ in their growth:
- **Forward** is clean in `u16`: each level adds at most `q` (the multiply output is `< q`), so a
  group's values stay `< 4q` across the three levels; one `% q` pass between radix-8 passes resets
  them. Every Montgomery operand stays `< 3q < 5q`, which the z3 proof already covers.
- **Inverse** sums grow *multiplicatively*, so the two level-1 outer sums are folded back to `< 2q`
  (`% 2q`) inside the butterfly; that keeps every stored output `< 4q < 2^16` and every Montgomery
  operand `< 4q`.

Result: forward radix-8 alone was −18.3% (native); adding the inverse took the session total to −36%
(native) / the cumulative figures in the table.

---

## Tried, measured, reverted (the CPU-specific lessons)
- **SIMD-vectorizing the NTT butterflies**: **no win**, reverted. The pointwise Montgomery mul
  auto-vectorizes to 0.375 instr/call, so the radix-8 butterflies *can* be vectorized by recasting
  them structure-of-arrays (element-wise loops over the group runs). But that splits the 3-level
  butterfly into separate passes that round-trip the intermediates through memory - erasing the
  advantage the scalar butterfly gets from holding all 8 elements register-resident across the 3
  levels. A register-resident variant (16 groups at a time through local YMM-sized arrays, kept in
  registers across the levels) lands flat on the instruction count and within wall-clock noise. A
  hand-written AVX2 path would do the *same* lane loads/stores, so it cannot beat the scalar version
  either. The transform is at its register-resident optimum for this size: the cost of moving data
  in/out of lanes offsets the vectorized arithmetic. (Callgrind counts a 16-wide op as ~1
  instruction, a SIMD-throughput blind spot - but the wall-clock bench shows nothing hidden there.)
- **Fusing two pure-map tail passes is fine; fusing into the reduction loop is not.** Combining
  `subtract-c0 + normalize` (two element-wise maps) into one pass is a small win and is kept. But
  folding the whole tail (`1/N scale → −c0 → center → square`) into the **distance** loop measured
  **+5.1% / +2.9%**: the distance step carries a `s += z²` reduction dependency, and folding the
  maps into it (plus interleaving the branchless Montgomery reduction) serializes work that was
  parallel and blocks vectorization.
- **Folding the final `1/N` scaling into the `s2` reduce / into the last inverse pass**: same trap -
  injecting `mq_montymul` (with its conditional) into an otherwise 16-wide auto-vectorized map pass
  de-vectorizes it. The scaling stays a separate, vectorizable pass.
- **Streaming squeeze** (interleave the squeeze with sampling, stop at exactly 512): **+0.4%**. For
  these vectors 512 isn't reached within 8 blocks (no permutation saved), and the two-phase form - a
  tight `copy_nonoverlapping` into a contiguous buffer, then a flat sampling loop - vectorizes better
  than the interleaved stream.
- **Making the two NTT directions use the same loop form**: regressed **either** way (slices for the
  forward: +6.3%; raw pointers for the inverse: +2.1%). `split_at_mut` *proves* the two halves
  disjoint and unlocks vectorization where raw `*mut` can't; the best loop shape differs per direction.

The throughline: keep simple element-wise passes separate so they auto-vectorize, and don't reach for
`unsafe`/manual fusion as if it were free - on a real CPU the binding factor is whether the compiler
can prove non-aliasing and vectorize.

---

## Where the remaining cost is
After radix-8 the profile (KAT 0) is roughly: **SHAKE squeeze ~40%**, **Montgomery multiplies in the
NTT butterflies ~17%**, `comp_decode` ~12%, and assorted already-vectorized passes (pointwise,
scaling, reduces, normalize, distance). `verify` is at a strong optimum; the three big chunks are all
either NIST-frozen or already at their register-resident best.

- **SHAKE / Keccak (~40%)** is the floor: NIST-mandated, `process_block` is already a hand-unrolled
  Keccak-f1600 on `rotate_left`, dropping below 9 squeeze permutations is statistically unsafe, and a
  single sponge can't be lane-parallelized (wide AVX2 Keccak needs 4 independent sponges).
- **NTT butterfly multiplies (~17%)** are scalar, as covered above, vectorizing them does not
  pay: the data movement in/out of SIMD lanes offsets the arithmetic, so the register-resident scalar
  radix-8 is the optimum here.
- **`comp_decode` (~12%)** is tight, bit-accurate Golomb-Rice; its only obvious change (branchless
  conditional-negate of the sign) trades a 50/50 branch the deterministic metric can't even see, so
  it's judged not worth the bit-twiddling risk.
