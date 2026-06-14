use crate::{
    constants::{
        errors::E_INVALID_PUBLIC_KEY, FALCON_PK_SIZE, GMB, IGMB, LOGN, M, N, NONCE_LEN,
        OVER_SAMPLING, Q, R2, SIG_COMP_MAXSIZE,
    },
    shake256::{shake_extract_vartime, shake_flip, shake_inject},
    utils::{mq_add, mq_montymul, mq_sub, revert, sign_extend_u16_to_u32, swap_byte_pairs},
};

/// Handles a pair of bytes as a `u64` and converts it to a field element.
///
/// # Parameters
/// - `pair`: The input 64-bit value containing the byte pair to be processed.
///
/// # Returns
/// The resulting field element as `u16`.
#[inline(always)]
fn handle_hash_to_point_bytes_pair(pair: u64) -> u16 {
    let mut r = pair - (24578 & ((pair - 24578 >> 63) - 1));

    r = r - (24578 & (((r - 24578) >> 63) - 1));
    r = r - (12289 & (((r - 12289) >> 63) - 1));

    (r | ((pair - 61445) >> 63) - 1) as u16
}

/// A draw `t` (a 16-bit big-endian word) is rejected iff `t >= 5q = 61445`; otherwise it is
/// accepted as `t mod q`. `5q < 2^16`, so this fits a `u16`.
const REJECT_THRESHOLD: u16 = 5 * Q;

/// Variable-time hash-to-point for **verification** (Falcon `hash_to_point_vartime`).
///
/// The verifier hashes `nonce ‖ message`, which is fully public - there is no secret to
/// protect, so the constant-time oversampling + sorting-network compaction of
/// [`hash_to_point_ct`] is unnecessary work here. The reference verifier `Zf(verify)` itself
/// uses the variable-time rejection sampler.
///
/// [`handle_hash_to_point_bytes_pair`] already maps every 16-bit draw to either its reduced
/// value in `[0, q)` or the sentinel `0xffff` (raw draw `>= 5q = 61445`). Accepted values are
/// `< q < 0x8000`, so they can never collide with the sentinel. This streams the SIMD-reduced
/// XOF output and collects the first `N` non-sentinel coefficients **in stream order**, which is
/// exactly what the constant-time variant computes - bit-for-bit identical `c` - but without the
/// `tt1` oversampling buffer or the p-loop conditional-move network.
///
/// # Parameters
/// - `extracted`: The squeezed SHAKE256 stream, as a slice of `u64` (4 big-endian draws each).
/// - `x`: Output polynomial coefficients (as `[u16; N]`), filled with the `N` accepted draws.
///
/// # Panics (debug only)
/// The caller must squeeze enough draws to accept `N` coefficients; with the oversampled buffer
/// this is statistically guaranteed (see `shake_extract`). Reaching the end of `extracted`
/// before `N` acceptances would index out of bounds.
#[inline(always)]
pub fn hash_to_point_vartime(extracted: &[u64], x: &mut [u16; N]) {
    let x_ptr = x.as_mut_ptr();

    unsafe {
        let ex_ptr = extracted.as_ptr();
        let mut count = 0usize;
        let mut u = 0usize;

        loop {
            let swapped = swap_byte_pairs(*ex_ptr.add(u));

            // 4 big-endian draws per word, low lane first (stream order). Unlike the constant-time
            // path, the vartime sampler is already branchy, so accept/reduce directly: a draw
            // `t < 5q` is accepted as `t mod q` (LLVM lowers the constant `% Q` to a multiply-by-
            // reciprocal, ~4 instructions), and `t >= 5q` is simply skipped. This avoids the
            // 20-instruction branchless reduction + sentinel that `handle_hash_to_point_bytes_pair`
            // needs for constant-time. Identical challenge.
            let t0 = (swapped & 0xffff) as u16;
            if t0 < REJECT_THRESHOLD {
                *x_ptr.add(count) = t0 % Q;
                count += 1;
                if count == N {
                    break;
                }
            }
            let t1 = ((swapped >> 0x10) & 0xffff) as u16;
            if t1 < REJECT_THRESHOLD {
                *x_ptr.add(count) = t1 % Q;
                count += 1;
                if count == N {
                    break;
                }
            }
            let t2 = ((swapped >> 0x20) & 0xffff) as u16;
            if t2 < REJECT_THRESHOLD {
                *x_ptr.add(count) = t2 % Q;
                count += 1;
                if count == N {
                    break;
                }
            }
            let t3 = (swapped >> 0x30) as u16;
            if t3 < REJECT_THRESHOLD {
                *x_ptr.add(count) = t3 % Q;
                count += 1;
                if count == N {
                    break;
                }
            }

            u += 1;
        }
    }
}

/// Constant-time: produces a new point from a flipped shake256 context.
///
/// # Parameters
/// - `extracted`: The extracted state from SHAKE256, as a slice of `u64`.
/// - `x`: Output polynomial coefficients (as `[u16; N]`), to be filled.
/// - `tt1`: Temporary storage, as mutable `[u16; N]`.
///
/// # Details
/// Produces a new point from the extracted SHAKE256 state in constant time. Retained as the
/// reference for the variable-time path ([`hash_to_point_vartime`]); see the `hash_to_point`
/// A/B equivalence test.
#[inline(always)]
pub fn hash_to_point_ct(extracted: &[u64], x: &mut [u16; N], tt1: &mut [u16; N]) {
    let x_ptr = x.as_mut_ptr();
    let tt1_ptr = tt1.as_mut_ptr();

    unsafe {
        let ex_ptr = extracted.as_ptr();
        let mut u = 0usize;

        loop {
            let raw = *ex_ptr.add(u);
            let swapped = swap_byte_pairs(raw);

            let base = u << 2;
            let dest = x_ptr.add(base);

            *dest = handle_hash_to_point_bytes_pair(swapped & 0xffff);
            *dest.add(1) = handle_hash_to_point_bytes_pair((swapped >> 0x10) & 0xffff);
            *dest.add(2) = handle_hash_to_point_bytes_pair((swapped >> 0x20) & 0xffff);
            *dest.add(3) = handle_hash_to_point_bytes_pair(swapped >> 0x30);

            u += 1;

            if u == 0x80{
                break;

            }
        }

        let mut out_base = 0usize;

        loop {
            let raw = *ex_ptr.add(u);
            let swapped = swap_byte_pairs(raw);
            let dest = tt1_ptr.add(out_base);

            *dest = handle_hash_to_point_bytes_pair(swapped & 0xffff);
            *dest.add(1) = handle_hash_to_point_bytes_pair((swapped >> 0x10) & 0xffff);
            *dest.add(2) = handle_hash_to_point_bytes_pair((swapped >> 0x20) & 0xffff);
            *dest.add(3) = handle_hash_to_point_bytes_pair(swapped >> 0x30);

            u += 1;
            out_base += 4;

            if u == 0xB3 {
                break;
            }
        }

        let raw = *ex_ptr.add(0xB3);
        let swapped = swap_byte_pairs(raw) & 0xffff;
        let lane = swapped as u64;

        *tt1_ptr.add(out_base + 0xc) = handle_hash_to_point_bytes_pair(lane);
    }

    let mut p = 1;

    loop {
        let mut v: u16 = 0;
        let mut u: usize = 0;

        unsafe {
            // skip first round if u < p
            loop {
                // Update v (unsigned arithmetic, subtract mk)
                v -= (*x_ptr.add(u) >> 0xf) - 1;
                u += 1;

                if u == p {
                    break;
                }
            }

            // first loop for `u < _N`
            loop {
                let sv: u16 = *x_ptr.add(u);
                let j = u as u16 - v;
                // mk = (sv >> 15) - 1
                let mut mk = (sv >> 0xf) - 1;

                // update v (unsigned arithmetic, subtract mk)
                v -= mk;

                // adjust mk with new condition (same shift as before but in uint256)
                mk &= 0 - (((j & p as u16) + 0x1ff) >> 0x9);

                let xi = u - p;
                let dv = *x_ptr.add(xi);
                let mk_and_sv_xor_dv = mk & (sv ^ dv);

                *x_ptr.add(xi) = dv ^ mk_and_sv_xor_dv;
                *x_ptr.add(u) = sv ^ mk_and_sv_xor_dv;

                u += 1;

                if u == N {
                    break;
                }
            }

            // sec loop for `u >= _M || (u - p) >= _N`
            loop {
                let tt1i = u - N;
                let sv = *tt1_ptr.add(tt1i);
                let j = u as u16 - v;
                let mut mk = (sv >> 0xf) - 1;

                v -= mk;

                mk &= 0 - (((j & p as u16) + 0x1ff) >> 0x9);

                let xi = u - p;
                let dv = *x_ptr.add(xi);
                let mk_and_sv_xor_dv = mk & (sv ^ dv);

                *x_ptr.add(xi) = dv ^ mk_and_sv_xor_dv;
                *tt1_ptr.add(tt1i) = sv ^ mk_and_sv_xor_dv;

                u += 1;

                if u < M as usize && (u - p) < N {
                    continue;
                }

                break;
            }

            let next_p = p << 0x1;
            let next_p_lt_oversampling = next_p < OVER_SAMPLING as usize;

            if next_p_lt_oversampling {
                // sec loop for `u < _M`
                loop {
                    let u_sub_n = u - N;
                    let sv = *tt1_ptr.add(u_sub_n);
                    let j = u as u16 - v;
                    let mut mk = (sv >> 0xf) - 1;

                    v = v - mk;

                    mk &= 0 - (((j & p as u16) + 0x1ff) >> 0x9);

                    let dvi = u_sub_n - p;
                    let dv = *tt1_ptr.add(dvi);
                    let mk_and_sv_xor_dv = mk & (sv ^ dv);

                    *tt1_ptr.add(dvi) = dv ^ mk_and_sv_xor_dv;
                    *tt1_ptr.add(u_sub_n) = sv ^ mk_and_sv_xor_dv;

                    u += 1;

                    if u == M as usize {
                        break;
                    }
                }

                p = next_p;

                continue;
            }

            break;
        }
    }
}

/// Computes the Number Theoretic Transform (NTT) on a polynomial in-place.
///
/// This is a Rust implementation of the Cooley-Turkey Radix-2 NTT algorithm,
/// using the Montgomery multiplication for efficiency.
///
/// # Arguments
/// * `p` - A mutable slice representing the polynomial coefficients.
#[inline(always)]
pub fn mq_ntt(p: &mut [u16; N]) {
    let mut len = N;
    let mut step = 1;
    let mut stage: u32 = 0;

    unsafe {
        let ptr = p.as_mut_ptr();

        loop {
            let half = len >> 1;
            let mut base = 0usize;

            for block_idx in 0..step {
                let s = GMB[step + block_idx];
                let mut low_idx = base;
                let mut high_idx = base + half;

                for _ in 0..half {
                    let u = *ptr.add(low_idx);
                    // `v` is fully reduced into [0, q) by the Montgomery multiply.
                    let v = mq_montymul(*ptr.add(high_idx), s);

                    // Lazy butterfly (no per-butterfly conditional reduction): the sum and the
                    // q-biased difference (≡ u−v mod q, kept non-negative) are written back
                    // unreduced. Values grow by at most q per stage; reduced only after stages 4
                    // and 8 below. Bound-proven to stay < 5q < 2^16 so they fit `u16`, and the
                    // largest Montgomery input (< 4q) keeps the single conditional in `mq_montymul`
                    // valid (pre-reduction value < 2q). See `mq_ntt` notes / OPTIMIZATION_NOTES.md.
                    *ptr.add(low_idx) = u + v;
                    *ptr.add(high_idx) = u + Q - v;

                    low_idx += 1;
                    high_idx += 1;
                }

                base += len;
            }

            stage += 1;

            // Lazy-bound reset: bring values back to [0, q) before they would exceed u16 (after a
            // 4th consecutive lazy stage the bound is < 5q; another stage would overflow).
            if stage == 4 || stage == 8 {
                for i in 0..N {
                    *ptr.add(i) %= Q;
                }
            }

            len = half;
            step <<= 1;

            if step == N {
                break;
            }
        }
    }
}

/// Computes the Inverse Number Theoretic Transform (iNTT) on a polynomial in-place.
///
/// # Arguments
/// * `p` - A mutable slice representing the polynomial coefficients in NTT domain.
#[inline(always)]
pub fn mq_intt(p: &mut [u16; N]) {
    let mut step = 1;
    let mut blocks = N;

    loop {
        let half_blocks = blocks >> 1;
        let block_size = step << 1;

        for (blk_idx, chunk) in p.chunks_exact_mut(block_size).enumerate() {
            let s = IGMB[half_blocks + blk_idx];
            let (low, high) = chunk.split_at_mut(step);

            for j in 0..step {
                let u = low[j];
                let v = high[j];

                low[j] = mq_add(u, v);
                // Lazy difference: `u + Q - v` (≡ u − v mod q, in (0, 2q)) replaces the conditional
                // `mq_sub`. It stays < 2q, so the single conditional inside `mq_montymul` still
                // lands the product in [0, q) - one fewer reduction per butterfly, no mid-pass
                // needed (`mq_add` keeps the low path in [0, q)).
                high[j] = mq_montymul(u + Q - v, s);
            }
        }

        step = block_size;
        blocks = half_blocks;

        if blocks == 1 {
            break;
        }
    }

    // final scaling (× 0x80) for each lane
    p.iter_mut().for_each(|val| {
        *val = mq_montymul(*val, 0x80);
    });
}

/// Converts a polynomial's coefficients to Montgomery representation in-place.
///
/// This operation is required before performing NTT-based polynomial multiplication.
/// It multiplies every coefficient of the polynomial `p` by `R^2 mod Q` using
/// Montgomery multiplication.
///
/// # Arguments
/// * `p` - A mutable slice representing the polynomial to be converted.
#[inline(always)]
pub fn mq_poly_tomonty(p: &mut [u16; N]) {
    unsafe {
        let ptr = p.as_mut_ptr();

        for i in 0..N {
            *ptr.add(i) = mq_montymul(*ptr.add(i), R2);
        }
    }
}

/// Performs pointwise multiplication of two polynomials in NTT form.
///
/// This function takes two polynomials, `f` and `g`, which are already in
/// NTT and Montgomery representation, and computes their product `f[i] * g[i]`
/// for all `i`. The result is written back over the `f` polynomial.
///
/// # Arguments
/// * `f` - A mutable slice for the first polynomial, `f`. The result is stored here.
/// * `g` - An immutable slice for the second polynomial, `g`.
#[inline(always)]
pub fn mq_poly_montymul_ntt(f: &mut [u16; N], g: &[u16; N]) {
    unsafe {
        let f_ptr = f.as_mut_ptr();
        let g_ptr = g.as_ptr();

        for i in 0..N {
            *f_ptr.add(i) = mq_montymul(*f_ptr.add(i), *g_ptr.add(i));
        }
    }
}

/// sub polynomial g from polynomial f
/// result f-g is written over f
///
/// # Arguments
/// * `f` - A mutable slice for the first polynomial, `f`. The result is stored here.
/// * `g` - An immutable slice for the second polynomial, `g`.
#[inline(always)]
pub fn mq_poly_sub(f: &mut [u16; N], g: &[u16; N]) {
    unsafe {
        let f_ptr = f.as_mut_ptr();
        let g_ptr = g.as_ptr();

        for i in 0..N {
            *f_ptr.add(i) = mq_sub(*f_ptr.add(i), *g_ptr.add(i));
        }
    }
}

/// converts a pub key to NTT + Montgomery format
///
/// # Arguments
/// * `pubkey` - A mutable slice of the Falcon public key. The result is stored here.
#[inline(always)]
pub fn to_ntt_monty(pubkey: &mut [u16; N]) {
    mq_ntt(pubkey);
    mq_poly_tomonty(pubkey);
}

/// Computes the squared Euclidean distance between two vectors, with sign extension.
///
/// # Parameters
/// - `s1`: The first input vector, as `[u16; N]`.
/// - `s2`: The second input vector, as `[u16; N]`.
///
/// # Returns
/// The sum of squared, sign-extended coefficients as a `u32`.
///
/// # Safety
/// Uses unsafe pointer arithmetic for performance.
pub fn distance(s1: &[u16; N], s2: &[u16; N]) -> u32 {
    let mut s: u32 = 0;
    let mut ng: u32 = 0;

    unsafe {
        let s1_ptr = s1.as_ptr();
        let s2_ptr = s2.as_ptr();

        for i in 0..N {
            let z: u32 = sign_extend_u16_to_u32(*s1_ptr.add(i));

            s += z * z;
            ng |= s;

            let z: u32 = sign_extend_u16_to_u32(*s2_ptr.add(i));

            s += z * z;
            ng |= s;
        }
    }

    ng = 0 - (ng >> 0x1f);

    s | ng
}

/// Returns true if the given vector (2N coordinates, in two halves) is acceptable as a signature.
///
/// Compares the squared Euclidean norm of the concatenated vectors with an acceptance bound.
///
/// # Parameters
/// - `s1`: The first half of the signature vector, as `[u16; N]`.
/// - `s2`: The second half of the signature vector, as `[u16; N]`.
///
/// # Returns
/// `true` if the vector is considered "short" (acceptable as a signature), otherwise `false`.
pub fn is_short(s1: &[u16; N], s2: &[u16; N]) -> bool {
    distance(s1, s2) <= 34034726
}

/// Decodes the public key into an internal format.
///
/// # Parameters
/// - `x`: Output polynomial coefficients, as mutable `[u16; N]`.
/// - `input`: Serialized public key bytes, as `[u8; FALCON_PK_SIZE]`.
/// - `offset`: Offset into the input buffer to start decoding from.
///
/// # Returns
/// The number of bytes read from the input buffer.
pub fn mq_decode(x: &mut [u16; N], input: &[u8; FALCON_PK_SIZE], offset: usize) -> usize {
    let mut acc: u64 = 0;
    let mut in_offset = offset;
    let mut acc_len: u8 = 0;
    let mut u = 0;
    // ((_N * 14) + 7) >> 3
    let mut ret = 896;

    loop {
        // byte(0, input[in_offset])
        acc = (acc << 0x8) | (input[in_offset] as u64);

        in_offset += 1;
        acc_len += 8;

        if acc_len < 0xe {
            continue;
        }

        acc_len -= 0xe;

        let w: u16 = ((acc >> acc_len) & 0x3fff) as u16;

        if w < 12289 {
            x[u] = w;

            u += 1;

            if u == N {
                break;
            }

            continue;
        }

        ret = 0;

        break;
    }

    if (acc & (1 << acc_len) - 1) != 0 {
        ret = 0;
    }

    ret
}

/// Decodes a compressed vector from a byte buffer.
///
/// # Parameters
/// - `input`: The input byte buffer to decode from.
///
/// # Returns
/// A tuple containing:
///   - The decoded vector as `[u16; N]`
///   - The number of bytes read from the buffer.
pub fn comp_decode(input: &[u8]) -> ([u16; N], usize) {
    let in_max = input.len();
    let mut out = [0u16; N];
    let mut v = 0;
    let mut acc = 0;
    let mut acc_len = 0;
    let mut u = 0;
    let in_ptr = (*input).as_ptr();

    v = loop {
        if v < in_max {
            unsafe {
                acc = (acc << 0x8) | (*in_ptr.add(v) as u16);
            }
            v += 1;

            let b = acc >> acc_len;
            let mut m = b & 0x7f;
            let s = b & 0x80;

            v = loop {
                if acc_len == 0 {
                    if v < in_max {
                        unsafe {
                            acc = (acc << 0x8) | (*in_ptr.add(v) as u16);
                        }
                        v += 1;
                        acc_len = 8;
                    } else {
                        break 0;
                    }
                }

                acc_len -= 1;

                if (acc >> acc_len) & 1 != 0 {
                    break v;
                }

                m += 0x80;

                if m > 2047 {
                    break 0;
                }
            };

            if m == 0 && s != 0 {
                break 0;
            }

            // m | -m
            out[u] = if s == 0 { m } else { 0 - m };

            u += 1;

            if u == N {
                break v;
            }

            continue;
        }

        break 0;
    };

    (out, v)
}

/// Internal signature verification routine.
///
/// # Parameters
/// - `c0`: Mutable output buffer, as `[u16; N]`.
/// - `s2`: Second part of the signature, as `[u16; N]`.
/// - `h`: Hashed public key, as `[u16; N]`.
/// - `s1`: Mutable first part of the signature, as `[u16; N]`.
///
/// # Returns
/// `true` if the signature is valid, `false` otherwise.
pub fn verify_raw(c0: &mut [u16; N], s2: &[u16; N], h: &[u16; N], s1: &mut [u16; N]) -> bool {
    // reduce s2_ elements modulo q ([0..q-1] range).
    unsafe {
        let s1_ptr = s1.as_mut_ptr();
        let s2_ptr = s2.as_ptr();

        for i in 0..N {
            let ptr = s2_ptr.add(i);

            *s1_ptr.add(i) = *ptr + (Q & (0 - (*ptr >> 0xf)));
        }
    }

    // computes -s1_ = s2_*h_ - c0_ mod ph_i mod q (in s1_[]).
    //
    // NB: these tail passes are deliberately *not* fused. In Rust the separate map-style loops each
    // auto-vectorize; folding them into the distance loop (which carries the `s += z²` reduction
    // dependency) and interleaving the branchless Montgomery reduction defeats vectorization and
    // measures ~+5% instructions on a callgrind run.

    mq_ntt(s1);
    mq_poly_montymul_ntt(s1, h);
    mq_intt(s1);
    mq_poly_sub(s1, c0);

    // normalize -s1_ elements into th_e [-q/2..q/2] range.
    let q_shr_1 = Q >> 0x1;

    unsafe {
        let s1_ptr = s1.as_mut_ptr();

        for i in 0..N {
            let ptr = s1_ptr.add(i);

            *ptr = *ptr - (Q & (0 - (q_shr_1 - *ptr >> 0xf)));
        }
    }

    is_short(s1, s2)
}

/// Converts a serialized public key to NTT format, verifying structure.
///
/// # Parameters
/// - `pk`: Serialized public key bytes, as `[u8; FALCON_PK_SIZE]`.
///
/// # Returns
/// The decoded public key in NTT format as `[u16; N]`.
///
/// # Panics
/// Panics if the public key is invalid.
pub fn pk_to_ntt_fmt(pk: &[u8; FALCON_PK_SIZE]) -> [u16; N] {
    // 1st byte should have the form "0000nnnn"
    if (pk[0] >> 0x4) != 0 || pk[0] & 0xf != LOGN {
        revert(E_INVALID_PUBLIC_KEY);
    }

    let mut pk_ntt_fmt = [0u16; N];

    // decode public key
    // let sz1 = mq_decode2(ref pk_ntt_fmt, pk.span(), 1);
    let sz1 = mq_decode(&mut pk_ntt_fmt, pk, 1);

    if sz1 != FALCON_PK_SIZE - 1 {
        revert(E_INVALID_PUBLIC_KEY);
    }

    // pk_ntt_fmt now contains decoded public key

    to_ntt_monty(&mut pk_ntt_fmt);

    pk_ntt_fmt
}

/// Verifies that the given signature, message, and public key match.
///
/// # Parameters
/// - `nonce_msg`: Message (and nonce) bytes.
/// - `sig`: Signature bytes.
/// - `pk_ntt_fmt`: Public key in NTT format, as `[u16; N]`.
///
/// # Returns
/// `true` if the signature is valid, otherwise `false`.
///
/// # Panics
/// Panics if the public key is invalid.
/// Panics if the signature len is invalid.
/// Panics if fails decoding signature.
/// Panics if the nonce + message len is invalid (0 len message).
pub fn verify(nonce_msg: &[u8], sig: &[u8], pk_ntt_fmt: &[u16; N]) -> bool {
    let sig_len = sig.len();

    // sig must have a minimum length of 42 bytes
    // sig type must have the correct sig length in the pub key
    if sig_len < 1 || sig_len > SIG_COMP_MAXSIZE as usize || nonce_msg.len() == NONCE_LEN as usize {
        return false;
    }

    // sigLen (supplied arg) typical value is in the order of 650 to 660,
    // yielding cb_sig_proper in the order of 609 to 619
    let (decoded_sig, sz2) = comp_decode(&sig);

    if sz2 != sig_len {
        return false;
    }

    // decoded_sig now contains decoded signature

    let mut shake_ctx = [0u64; 26];

    shake_inject(&mut shake_ctx, &nonce_msg);
    shake_flip(&mut shake_ctx);

    // Squeeze only the 9 rate blocks the variable-time sampler needs (Finding B), not the 11 the
    // constant-time oversample required.
    let extracted = shake_extract_vartime(&mut shake_ctx);

    let mut hash_nonce_msg = [0u16; N];

    // Verification input is public - use the variable-time rejection sampler (Falcon's verify
    // path), not the constant-time sorting network. Produces the identical challenge `c`.
    hash_to_point_vartime(&extracted, &mut hash_nonce_msg);

    let mut s1 = [0u16; N];

    verify_raw(&mut hash_nonce_msg, &decoded_sig, pk_ntt_fmt, &mut s1)
}
