# Falcon-512 (Rust) - Optimization Notes

NIST/FN-DSA behaviour is preserved throughout: SHAKE256 is untouched (no Poseidon/Pedersen swap),
the challenge polynomial `c`, the public-key NTT format, and every KAT distance are unchanged.

---

## How performance is measured (the agnostic metric)

Wall-clock timing (and `rdtsc` cycles) depends on CPU frequency scaling, background load, and the
allocator - it cannot tell a 2% win from noise. The replacement is **deterministic instruction
counting under valgrind/callgrind** via `iai-callgrind` (`benches/instr_count.rs`):

```sh
cargo bench --bench instr_count
```

The reported *Instructions* / *L1* / *L2* / *RAM* / *Estimated Cycles* are a pure function of the
executed code path - independent of machine load or host, and reproducible bit-for-bit. This is the
After the first run iai prints each metric's **delta vs the previous run**, so an optimization is judged by its instruction delta, not by a stopwatch.
The legacy Criterion wall-clock bench (`benches/benchmark.rs`) is kept for human-facing ns/ops-sec
numbers but is explicitly *not* the optimization signal.

> Counts below were taken with the default (portable) codegen - `target-cpu=native` left **off** so
> the numbers reproduce on any x86-64 host (see `.cargo/config.toml`). Enabling native lowers the
> absolute counts (auto-vectorization) but makes them machine-specific.

---

## Results (instructions, `verify`)

| stage | KAT 0 | Δ vs baseline | KAT 99 | Δ vs baseline |
|-------|------:|--------:|-------:|---------:|
| **baseline** (CT hash-to-point, 11 perms) | 327,957 | - | 464,280 | - |
| **+A** variable-time hash-to-point | 197,466 | −39.8% | 333,766 | −28.1% |
| **+B** 9 SHAKE permutations | 185,568 | −43.4% | 321,868 | −30.7% |
| **+C** vartime sampler via `% q` (Round 2) | 180,076 | −45.1% | 316,410 | −31.8% |
| **+D** lazy forward NTT (Round 2) | 173,994 | −46.9% | 310,328 | −33.2% |
| **+E** lazy inverse subtraction (Round 2) | **171,114** | **−47.8%** | **307,448** | **−33.8%** |

Estimated cycles track the same shape. KAT 99 starts higher and moves less in % because its
3340-byte message spends ~35% of the work in the SHAKE *absorb* permutations, which none of these
findings touch.

Reverted (measured regressions - see below): F7 INTT-tail fusion (+5%), streaming squeeze (+0.4%),
forward NTT as slices / inverse NTT as raw pointers (+6.3% / +2.1%), final-1/N-scaling fold
(de-vectorizes the `s2` reduce).

---

## Findings that ported (algorithmic, cost-model-independent)

### A - variable-time hash-to-point  ✅ biggest win
The verifier hashes `nonce ‖ message`, which is fully **public** - there is no secret to protect, so
the constant-time oversampling + sorting-network compaction (`hash_to_point_ct`) is wasted work; the
reference verifier itself uses the rejection sampler. The per-draw reducer
(`handle_hash_to_point_bytes_pair`) already maps each 16-bit draw to its value in `[0,q)` or the
`0xffff` rejection sentinel, so `hash_to_point_vartime` just collects the first `N` non-sentinel
draws in stream order. This deletes the `tt1` oversample buffer and the entire p-loop conditional-
move network. Output is **bit-identical** to the CT challenge - proved by
`tests::hash_to_point_ab::ct_and_vartime_produce_identical_challenge`
and by the 10 KAT distances still matching exactly through the production path.

### B - fewer SHAKE permutations  ✅
Vartime needs only ~546 draws to accept 512 coefficients (rejection ≈ 6.24%). Nine Keccak rate
blocks = 612 draws ⇒ E[accepted] ≈ 574, σ ≈ 6 - a short fill is a ~10σ event. `shake_extract_vartime`
squeezes a fixed 9 blocks instead of the 11 the CT oversample required, dropping 2 of the costliest
operations in the function (~5.6k instructions each). Every block is a full 17-word rate, so it is
copied whole-word (no trailing partial copy).

---

## Deeper, after a line-level callgrind profile

A per-line profile (`callgrind_annotate --auto=yes`) showed the remaining cost concentrated in two
places: the SHAKE permutation (irreducible - NIST) and the **Montgomery arithmetic in the NTT
(~29%)**, within which the *conditional reductions* alone were ~12.8% of the whole `verify`. Plus a
6% surprise in the hash-to-point reducer. Three wins followed, all output-identical (the 10 KAT
distances + the CT≡vartime A/B test gate every one).

### C - vartime hash-to-point via `% q`  ✅ (−2.9% / −1.7%)
`handle_hash_to_point_bytes_pair` does a 20-instruction **branchless** reduction (4 subtract rounds
+ a sentinel) on every draw - branchless because it serves the *constant-time* path. The vartime
sampler is already branchy (it accepts/rejects), so for it the whole thing collapses to
`if t < 5q { t % q }`. LLVM lowers the constant `% 12289` to a ~4-instruction multiply-by-reciprocal,
and the reject branch is ~94% not-taken (predictable - so this is a real cycle win, not a
branch-misprediction trick the Ir metric can't see). ~15 fewer instructions on each of ~550 draws.

### D - lazy forward NTT  ✅ (−3.4% / −1.9%)
q=12289 leaves headroom up to 5q < 2^16 in a `u16`. In the DIT forward butterfly the
twiddle product `v` is already in [0, q), so the sum and the **q-biased difference** `u + Q − v`
(≡ u−v mod q, kept non-negative) can be written back **without the per-butterfly conditional
reductions** - values grow by ≤ q per stage and are reduced (one `% q` pass) only after stages 4 and
8. This removes the `mq_add`/`mq_sub` conditionals from the hot loop (the forward NTT no longer calls
either). The bound schedule is **machine-checked by z3** (`z3/lazy_ntt_bounds.py`): it proves every
stored value stays < 2^16 and that the single conditional inside `mq_montymul` still lands in [0, q)
for operands up to 4q (pre-reduction value < 2q), reasoning over the exact REDC bit arithmetic.

### E - lazy inverse subtraction  ✅ (−1.7% / −0.9%)
The GS inverse butterfly's `low' = u+v` path grows *multiplicatively*, so it can't go fully lazy in
16 bits - but the difference feeding the Montgomery multiply can. `mq_sub(u,v)` is replaced by the
biased `u + Q − v` (< 2q, which keeps the multiply's single conditional valid, z3-checked), dropping
one conditional reduction per butterfly with **no** mid-pass (the `mq_add` low path stays in [0, q)).
After D+E, `mq_sub` has essentially vanished from the profile and `mq_add` is ~6× cheaper.

---

## Findings that REVERSED

### F7 / E1 - fusing the INTT tail  ❌ implemented, measured, reverted
Collapsing `1/N scale → −c0 → center → square` into one pass removed real per-loop and
dict-traffic overhead (−43.5k steps). In Rust it is a **pessimization (+5.1% / +2.9% instructions)**
and was reverted. Reason: the four tail passes are simple *map* loops with no loop-carried
dependency, so LLVM auto-vectorizes each into SIMD. The distance accumulation, by contrast, carries
a `s += z²` reduction dependency. Fusing the maps *into* the reduction loop - and interleaving the
branchless Montgomery reduction - serializes work that was parallel and blocks vectorization. The
separate-pass form is kept; see the comment in `verify_raw`. This is the headline example of "the
outcome is totally different on a real CPU."

### Streaming squeeze  ❌ tried, reverted (+0.4%)
Squeezing block-by-block and stopping the instant 512 coefficients are accepted,
to hit the ~8.03-permutation average instead of a fixed 9. Implemented as a fused
`hash_to_point_streaming` (squeeze + sample in one pass, no intermediate buffer). Measured **+0.4% /
+0.2% instructions** and reverted. Two reasons: (1) for these KAT vectors 512 is *not* reached within
8 blocks, so no permutation is actually saved; (2) the two-phase form - a tight `copy_nonoverlapping`
squeeze into a contiguous 153-word buffer, then a flat 4-lane sampling loop - vectorizes better than
the interleaved stream, whose per-block re-entry and labelled break inhibit it. The fixed-9
`shake_extract_vartime` + `hash_to_point_vartime` is kept.

### NTT loop form: raw pointers vs `split_at_mut` slices  ❌ both directions tried, reverted
The forward NTT uses raw pointers; the inverse uses `chunks_exact_mut().enumerate()` +
`split_at_mut`. Making them uniform regressed **either way**:
- inverse → raw pointers: **+2.1%** (raw `*mut` reintroduces possible aliasing, so LLVM can't
  vectorize the butterfly; `split_at_mut` *proves* the two halves disjoint and unlocks it),
- forward → slices: **+6.3%** (the forward butterfly multiplies the *read* half by the twiddle before
  the add/sub, and that shape codegens better as straight-line pointer arithmetic).

The asymmetry is the lesson: each NTT direction was already sitting at its own codegen optimum - the
existing mix (forward = raw pointer, inverse = slice) is *not* an inconsistency to clean up but a
tuned result. On a real CPU "make it uniform / make it `unsafe`" is not a free win; the binding factor
is whether the compiler can prove non-aliasing and vectorize, which differs per loop shape.

---

## Out of scope (would break NIST/format invariants)

- **Radix-4 / split-radix NTT.** Its classic benefit is *fewer multiplies* - which is real on a CPU
  (unlike post-F1b), so this is the one genuinely open avenue. But
  it reorders the transform, and the public key is supplied **already in radix-2 NTT format**
  (precomputed offchain); changing the layout would require regenerating every public key and KAT
  vector.
- **comp_decode de-Bruijn bit-scan (F3).** Real signatures have short Gaussian unary runs (~0–2
  bits), so the bit loop already terminates in 1–2 iterations; the perfect-hash adds complexity for
  no measurable gain. Deferred.

---

## Where the remaining cost is

A callgrind function breakdown (`callgrind_annotate target/iai/instr_count/callgrind.verify_kat_99.out`)
shows the floor is the **SHAKE/Keccak permutation**:

- KAT 99: `shake_inject` (absorb) ≈ 35% + `shake_extract_vartime` (squeeze) ≈ 12% ≈ **47%** SHAKE;
  the rest is the NTT pair, hash-to-point, and `comp_decode`.
- KAT 0 (short message, 0 absorb perms): the 9 squeeze permutations dominate.

`process_block` is already a hand-unrolled, pointer-based Keccak-f1600 using the `rotate_left`
intrinsic. Beyond it, the only lever is an AVX2/SIMD Keccak (machine-specific, `target-cpu=native`)
or moving the permutation off the critical path - neither of which is a NIST-preserving, portable
source change.
