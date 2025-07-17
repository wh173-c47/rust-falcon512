use crate::{
    constants::{
        errors::E_INVALID_PUBLIC_KEY,
        FALCON_PK_SIZE,
        GMB,
        IGMB,
        LOGN,
        M,
        N,
        NONCE_LEN,
        N_INV,
        Q,
        SIG_COMP_MAXSIZE
    },
    shake256::{hash_to_point_ct, shake_extract, shake_flip, shake_inject},
    utils::{addmod, mulmod, revert, sign_extend_u16_to_u32, submod}
};

/// compute NTT on a ring element
pub fn mq_ntt(input: &mut[u16; 512]) {
    let mut t: usize = N as usize;
    let mut m = 1;
    let end = t;

    loop {
        let ht: usize = (t >> 0x1) as usize;
        let mut j1 = 0;
        let mut i = 0;

        loop {
            let j2 = j1 + ht;
            let s = GMB[m + i];
            let mut j = j1;

            loop {
                let u = input[j];
                let jht = j + ht;
                let v = mulmod(input[jht], s, Q);

                input[j] = addmod(u, v, Q);
                input[jht] = submod(u, v, Q);

                j += 1;

                if j == j2 {
                    break;
                }
            };

            j1 += t;
            i += 1;

            if i == m {
                break;
            }
        };

        t = ht as usize;
        m = m << 0x1;

        if m == end {
            break;
        }
    };
}

/// compute inverse NTT on a ring element
/// writes result over `in`
pub fn mq_intt(input: &mut [u16; 512]) {
    let mut t = 1;
    let mut m: usize = N as usize;
    let end = m;

    loop {
        let hm = m >> 0x1;
        let dt = t << 0x1;
        let mut j1 = 0;
        let mut i = 0;

        loop {
            let j2 = j1 + t;
            let s = IGMB[hm + i];
            let mut j = j1;

            loop {
                let u = input[j];
                let jt = j + t;
                let v = input[jt];

                input[j] = addmod(u, v, Q);
                input[jt] = mulmod(submod(u, v, Q), s, Q);

                j += 1;

                if j == j2 {
                    break;
                }
            };

            j1 += dt;
            i += 1;

            if i == hm {
                break;
            }
        };

        t = dt;
        m = hm;

        if m == 1 {
            break;
        }
    };

    let mut m = 0;

    loop {
        input[m] = mulmod(input[m],  N_INV, Q);

        m += 1;

        if m == end {
            break;
        }
    };
}

// mul two polynomials together (NTT representation)
// result f*g is written over f
pub fn mq_poly_ntt(f: &mut [u16; 512], g: &[u16; 512]) {
    let mut i = 0;
    let end: usize = N as usize;

    loop {
        f[i] = mulmod(f[i], g[i], Q);

        i += 1;

        if i == end {
            break;
        }
    }
}

// sub polynomial g from polynomial f
// result f-g is written over f
pub fn mq_poly_sub(f: &mut [u16; 512], g: &[u16; 512]) {
    let mut i = 0;
    let end: usize = N as usize;

    loop {
        f[i] = submod(f[i], g[i], Q);

        i += 1;

        if i == end {
            break;
        }
    }
}

pub fn distance(s1: &[u16; 512], s2: &[u16; 512]) -> u32 {
    let mut s: u32 = 0;
    let mut ng: u32 = 0;
    let mut u = 0;
    let end = N as usize;

    loop {
        let z:  u32 = sign_extend_u16_to_u32(s1[u]);

        s += z * z;
        ng |= s;

        let z:  u32 = sign_extend_u16_to_u32(s2[u]);

        s += z * z;
        ng |= s;

        u += 1;

        if u == end {
            break;
        }
    };

    ng = 0 - (ng >> 0x1f);

    s | ng
}

/// returns true if given vector (2N coord, in two halves) is acceptable as signature
/// compares appropriate norm of the vector with acceptance bound
pub fn is_short(s1: &[u16; 512], s2: &[u16; 512]) -> bool {
    distance(s1, s2) <= 34034726
}

// decode the public key
pub fn mq_decode(x: &mut [u16; 512], input: &[u8; 897], offset: usize) -> u16 {
    let mut acc: u64 = 0;
    let mut in_offset = offset;
    let mut acc_len: u8 = 0;
    let mut u = 0;
    // ((_N * 14) + 7) >> 3
    let mut ret = 896;
    let end = N as usize;

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

            if u == end {
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
    input: &Vec<u8>
) -> ([u16; 512], usize) {
    let in_max = input.len();
    let mut out = [0u16; 512];
    let mut v = 0;
    let mut acc = 0;
    let mut acc_len = 0;
    let mut u = 0;

    v = loop {
        if v < in_max {
            acc = (acc << 0x8) | (input[v] as u16);
            v += 1;

            let b = acc >> acc_len;
            let mut m = b & 0x7f;
            let s = b & 0x80;

            v = loop {
                if acc_len == 0 {
                    if v < in_max {
                       acc = (acc << 0x8) | (input[v] as u16);
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

            if u == N as usize {
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
    c0: &mut[u16; 512],
    s2: &[u16; 512],
    h: &[u16; 512],
    s1: &mut [u16; 512]
) -> bool {
    let mut u = 0;
    let end = N as usize;

    // reduce s2_ elements modulo q ([0..q-1] range).
    loop {
        let w = s2[u];

        s1[u] = w + (Q & (0 - (w >> 0xf)));

        u += 1;

        if u == end {
            break;
        }
    };

    // computes -s1_ = s2_*h_ - c0_ mod ph_i mod q (in s1_[]).

    mq_ntt(s1);
    mq_poly_ntt(s1, h);
    mq_intt(s1);
    mq_poly_sub(s1, c0);

    // normalize -s1_ elements into th_e [-q/2..q/2] range.
    u = 0;

    let q_shr_1 = Q >> 0x1;

    loop {
        let w = s1[u];

        s1[u] = w - (Q & (0 - ((q_shr_1 - w) >> 0xf)));

        u += 1;

        if u == end {
            break;
        }
    };

    is_short(s1, s2)
}

pub fn pk_to_ntt_fmt(pk: &[u8; 897]) -> [u16; 512] {
    // 1st byte should have the form "0000nnnn"
    if (pk[0] >> 0x4) != 0 || pk[0] & 0xf != LOGN {
        revert(E_INVALID_PUBLIC_KEY);
    }

    let mut pk_ntt_fmt = [0u16; 512];

    // decode public key
    // let sz1 = mq_decode2(ref pk_ntt_fmt, pk.span(), 1);
    let sz1 = mq_decode(&mut pk_ntt_fmt, pk, 1);

    if sz1 != FALCON_PK_SIZE - 1 {
        revert(E_INVALID_PUBLIC_KEY);
    }

    // pk_ntt_fmt now contains decoded public key

    mq_ntt(&mut pk_ntt_fmt);

    pk_ntt_fmt
}

// verify that the given sig, msg and pub key matches
pub fn verify(
    nonce_msg: Vec<u8>,
    sig: Vec<u8>,
    pk_ntt_fmt: &[u16; 512]
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

    let extracted = shake_extract(&mut shake_ctx, M * 2);

    let mut tmp_buff = [0u16; 512];
    let mut hash_nonce_msg = [0u16; 512];

    hash_to_point_ct(&extracted, &mut hash_nonce_msg, &mut tmp_buff);

    verify_raw(
        &mut hash_nonce_msg,
        &decoded_sig,
        pk_ntt_fmt,
        &mut tmp_buff
    )
}
