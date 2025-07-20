use crate::{
    constants::{
        errors::E_INVALID_PUBLIC_KEY,
        FALCON_PK_SIZE,
        OVER_SAMPLING,
        GMB,
        IGMB,
        LOGN,
        M,
        N,
        NONCE_LEN,
        Q,
        R2,
        SIG_COMP_MAXSIZE
    },
    shake256::{shake_inject, shake_flip, shake_extract },
    utils::{mq_add, mq_sub, mq_montymul, revert, sign_extend_u16_to_u32, swap_byte_pairs}
};

// TODO: see below if no branching worth vs early exited branching
#[inline(always)]
fn handle_hash_to_point_bytes_pair(pair: u64) -> u16 {
    let mut r = pair - (24578 & ((pair - 24578 >> 63) - 1));

    r = r - (24578 & (((r - 24578) >> 63) - 1));
    r = r - (12289 & (((r - 12289) >> 63) - 1));

    (r | ((pair - 61445) >> 63) - 1) as u16
}


// constant-time produces a new point from a flipped shake256 context
// TODO: optimize further
#[inline(always)]
pub fn hash_to_point_ct(
    extracted: &[u64],
    x: &mut [u16; N],
    tt1: &mut [u16; N]
) {
    unsafe {
        let ex_ptr = extracted.as_ptr();
        let x_ptr = x.as_mut_ptr();
        let t_ptr = tt1.as_mut_ptr();
        let mut u = 0usize;

        while u != 0x80 {
            let raw = *ex_ptr.add(u);
            let swapped = swap_byte_pairs(raw);

            let base = u << 2;
            let dest = x_ptr.add(base);

            *dest.add(0) = handle_hash_to_point_bytes_pair(swapped & 0xffff);
            *dest.add(1) = handle_hash_to_point_bytes_pair((swapped >> 0x10) & 0xffff);
            *dest.add(2) = handle_hash_to_point_bytes_pair((swapped >> 0x20) & 0xffff);
            *dest.add(3) = handle_hash_to_point_bytes_pair(swapped >> 0x30);

            u += 1;
        }

        let mut out_base = 0usize;

        while u != 0xB3 {
            let raw = *ex_ptr.add(u);
            let swapped = swap_byte_pairs(raw);
            let dest = t_ptr.add(out_base);

            *dest.add(0) = handle_hash_to_point_bytes_pair(swapped & 0xffff);
            *dest.add(1) = handle_hash_to_point_bytes_pair((swapped >> 0x10) & 0xffff);
            *dest.add(2) = handle_hash_to_point_bytes_pair((swapped >> 0x20) & 0xffff);
            *dest.add(3) = handle_hash_to_point_bytes_pair(swapped >> 0x30);

            u += 1;
            out_base += 4;
        }

        let raw = *ex_ptr.add(0xB3);
        let swapped = swap_byte_pairs(raw) & 0xFFFF;
        let lane = swapped as u64;

        *t_ptr.add(out_base + 0xC) = handle_hash_to_point_bytes_pair(lane);
    }

    let mut p = 1;

    loop {
        let mut v: u16 = 0;
        let mut u: usize = 0;

        // skip first round if u < p
        loop {
            // Update v (unsigned arithmetic, subtract mk)
            v -= (x[u] >> 0xf) - 1;
            u += 1;

            if u == p {
                break;
            }
        };

        // first loop for `u < _N`
        loop {
            let sv: u16 = x[u];
            let j = u as u16 - v;
            // mk = (sv >> 15) - 1 (but we work in uint256 now)
            // mk is 0xFFFFFFFFFFFFFFFF... for negative condition
            let mut mk = (sv >> 0xf) - 1;

            // update v (unsigned arithmetic, subtract mk)
            v -= mk;

            // adjust mk with new condition (same shift as before but in uint256)
            mk &= 0 - (((j & p as u16) + 0x1ff) >> 0x9);

            let xi = u - p;
            let dv = x[xi];
            let mk_and_sv_xor_dv = mk & (sv ^ dv);

            x[xi] = dv ^ mk_and_sv_xor_dv;
            x[u] = sv ^ mk_and_sv_xor_dv;

            u += 1;

            if u == N {
                break;
            }
        };

        // sec loop for `u >= _M || (u - p) >= _N`

        loop {
            let tt1i = u - N;
            let sv = tt1[tt1i];
            let j = u as u16 - v;
            let mut mk = (sv >> 0xf) - 1;

            v -= mk;

            mk &= 0 - (((j & p as u16) + 0x1ff) >> 0x9);

            let xi = u - p;
            let dv = x[xi];
            let mk_and_sv_xor_dv = mk & (sv ^ dv);

            x[xi] = dv ^ mk_and_sv_xor_dv;
            tt1[tt1i] = sv ^ mk_and_sv_xor_dv;

            u += 1;

            if u < M as usize && (u - p) < N {
                continue;
            }

            break;
        };

        // sec loop for `u < _M`
        loop {
            let u_sub_n = u - N;
            let sv = tt1[u_sub_n];
            let j = u as u16 - v;
            let mut mk = (sv >> 0xf) - 1;

            v = v - mk;

            mk &= 0 - (((j & p as u16) + 0x1ff) >> 0x9);

            let dvi = u_sub_n - p;
            let dv = tt1[dvi];
            let mk_and_sv_xor_dv = mk & (sv ^ dv);

            tt1[dvi] = dv ^ mk_and_sv_xor_dv;
            tt1[u_sub_n] = sv ^ mk_and_sv_xor_dv;

            u += 1;

            if u == M as usize {
                break;
            }
        };

        p = p << 0x1;

        if p < OVER_SAMPLING as usize {
            continue;
        };

        break;
    };
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

    unsafe {
        let ptr = p.as_mut_ptr();

        while step != N {
            let half = len >> 1;
            let block_size = len;
            let mut base = 0usize;

            for block_idx in 0..step {
                let s = GMB[step + block_idx];
                let mut low_idx  = base;
                let mut high_idx = base + half;

                for _ in 0..half {
                    let u = *ptr.add(low_idx);
                    let v = mq_montymul(*ptr.add(high_idx), s);

                    *ptr.add(low_idx) = mq_add(u, v);
                    *ptr.add(high_idx) = mq_sub(u, v);

                    low_idx  += 1;
                    high_idx += 1;
                }

                base += block_size;
            }

            len = half;
            step <<= 1;
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

    while blocks > 1 {
        let half_blocks = blocks >> 1;
        let block_size  = step << 1;

        for (blk_idx, chunk) in p.chunks_exact_mut(block_size).enumerate() {
            let s = IGMB[half_blocks + blk_idx];
            let (low, high) = chunk.split_at_mut(step);

            for j in 0..step {
                let u = low[j];
                let v = high[j];

                low[j]  = mq_add(u, v);
                high[j] = mq_montymul(mq_sub(u, v), s);
            }
        }

        step = block_size;
        blocks = half_blocks;
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
pub fn to_ntt_monty(
    pubkey: &mut [u16; N]
) {
    mq_ntt(pubkey);
    mq_poly_tomonty(pubkey);
}

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

/// returns true if given vector (2N coord, in two halves) is acceptable as signature
/// compares appropriate norm of the vector with acceptance bound
pub fn is_short(s1: &[u16; N], s2: &[u16; N]) -> bool {
    distance(s1, s2) <= 34034726
}

// decode the public key
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
    };

    if (acc & (1 << acc_len) - 1) != 0 {
        ret = 0;
    }

    ret
}

// from an in, an out and a max in len, returns the nb of bytes read from the buffer
pub fn comp_decode(
    input: &[u8]
) -> ([u16; N], usize) {
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

// internal signature verification
// returns true if valid else false
pub fn verify_raw(
    c0: &mut[u16; N],
    s2: &[u16; N],
    h: &[u16; N],
    s1: &mut [u16; N]
) -> bool {
    // reduce s2_ elements modulo q ([0..q-1] range).
    unsafe {
        let s1_ptr = s1.as_mut_ptr();
        let s2_ptr = s2.as_ptr();

        for i in 0..N {
            *s1_ptr.add(i) = *s2_ptr.add(i) + (Q & (0 - (*s2_ptr.add(i) >> 0xf)));
        }
    }

    // computes -s1_ = s2_*h_ - c0_ mod ph_i mod q (in s1_[]).

    mq_ntt(s1);
    mq_poly_montymul_ntt(s1, h);
    mq_intt(s1);
    mq_poly_sub(s1, c0);

    // normalize -s1_ elements into th_e [-q/2..q/2] range.
    let q_shr_1 = Q >> 0x1;

    unsafe {
        let s1_ptr = s1.as_mut_ptr();

        for i in 0..N {
            *s1_ptr.add(i) = *s1_ptr.add(i) - (Q & (0 - ((q_shr_1 - *s1_ptr.add(i) >> 0xf))));
        }
    }

    is_short(s1, s2)
}

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

// verify that the given sig, msg and pub key matches
pub fn verify(
    nonce_msg: &[u8],
    sig: &[u8],
    pk_ntt_fmt: &[u16; N]
) -> bool {
    let sig_len = sig.len();

    // sig must have a minimum length of 42 bytes
    // sig type must have the correct sig length in the pub key
    if
        sig_len < 1 ||
        sig_len  > SIG_COMP_MAXSIZE as usize ||
        nonce_msg.len() == NONCE_LEN as usize
    {
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

    let extracted = shake_extract(&mut shake_ctx);

    let mut tmp_buff = [0u16; N];
    let mut hash_nonce_msg = [0u16; N];

    hash_to_point_ct(&extracted, &mut hash_nonce_msg, &mut tmp_buff);

    verify_raw(
        &mut hash_nonce_msg,
        &decoded_sig,
        pk_ntt_fmt,
        &mut tmp_buff
    )
}
