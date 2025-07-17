use crate::{constants::{M, M16, M32, M8, N, N_ROUNDS, OVER_SAMPLING, SHAKE256_RATE, SHAKE_ROUND_CONSTANTS}, utils::{rol, swap_byte_pairs}};

/// processes the provided shake256 state
/// result is written over shake context
#[inline(always)]
pub fn process_block(
    shake_ctx: &mut [u64; 26]
) {
    shake_ctx[1] = !shake_ctx[1];
    shake_ctx[2] = !shake_ctx[2];
    shake_ctx[8] = !shake_ctx[8];
    shake_ctx[12] = !shake_ctx[12];
    shake_ctx[17] = !shake_ctx[17];
    shake_ctx[20] = !shake_ctx[20];

    let mut j: u8 = 0;

    loop {
        let  xor_0_1 = shake_ctx[1] ^ shake_ctx[6] ^ shake_ctx[11] ^ shake_ctx[16] ^ shake_ctx[21];
        let xor_2_3 = shake_ctx[4] ^ shake_ctx[9] ^ shake_ctx[14] ^ shake_ctx[19] ^ shake_ctx[24];
        let xor_4_5 = shake_ctx[3] ^ shake_ctx[8] ^ shake_ctx[13] ^ shake_ctx[18] ^ shake_ctx[23];
        let xor_6_7  = shake_ctx[0] ^ shake_ctx[5] ^ shake_ctx[10] ^ shake_ctx[15] ^ shake_ctx[20];
        let xor_8_9 = shake_ctx[2] ^ shake_ctx[7] ^ shake_ctx[12] ^ shake_ctx[17] ^ shake_ctx[22];

        // shl 1 | shr 63
        let t_0 = rol(1, xor_0_1) ^ xor_2_3;
        let t_2 = rol(1, xor_4_5) ^ xor_0_1;
        let t_4 = rol(1, xor_6_7) ^ xor_4_5;
        let t_1 = rol(1, xor_8_9) ^ xor_6_7;
        let t_3 = rol(1, xor_2_3) ^ xor_8_9;

        shake_ctx[0] = shake_ctx[0] ^ t_0;

        // processes rol ops

        let mut tmp = shake_ctx[5] ^ t_0;
        // shl 36 | shr 28
        shake_ctx[5] = rol(36, tmp);

        tmp = shake_ctx[10] ^ t_0;
        // shl 3 | shr 61
        shake_ctx[10] = rol(3, tmp);

        tmp = shake_ctx[15] ^ t_0;
        // shl 41 | shr 23
        shake_ctx[15] = rol(41, tmp);

        tmp = shake_ctx[20] ^ t_0;
        // shl 18 | shr 46
        shake_ctx[20] = rol(18, tmp);

        tmp = shake_ctx[1] ^ t_1;
        // shl 1 | shr 63
        shake_ctx[1] = rol(1, tmp);

        tmp = shake_ctx[6] ^ t_1;
        // shl 44 | shr 20
        shake_ctx[6] = rol(44, tmp);

        tmp = shake_ctx[11] ^ t_1;
        // shl 10 | shr 54
        shake_ctx[11] = rol(10, tmp);

        tmp = shake_ctx[16] ^ t_1;
        // shl 45 | shr 19
        shake_ctx[16] = rol(45, tmp);

        tmp = shake_ctx[21] ^ t_1;
        // shl 2 | shr 62
        shake_ctx[21] = rol(2, tmp);

        tmp = shake_ctx[2] ^ t_2;
        // shl 62 | shr 2
        shake_ctx[2] = rol(62, tmp);

        tmp = shake_ctx[7] ^ t_2;
        // shl 6 | shr 58
        shake_ctx[7] = rol(6, tmp);

        tmp = shake_ctx[12] ^ t_2;
        // shl 43 | shr 21
        shake_ctx[12] = rol(43, tmp);

        tmp = shake_ctx[17] ^ t_2;
        // shl 15 | shr 49
        shake_ctx[17] = rol(15, tmp);

        tmp = shake_ctx[22] ^ t_2;
        // shl 61 | shr 3
        shake_ctx[22] = rol(61, tmp);

        tmp = shake_ctx[3] ^ t_3;
        // shl 28 | shr 36
        shake_ctx[3] = rol(28, tmp);

        tmp = shake_ctx[8] ^ t_3;
        // shl 55 | shr 9
        shake_ctx[8] = rol(55, tmp);

        tmp = shake_ctx[13] ^ t_3;
        // shl 25 | shr 39
        shake_ctx[13] = rol(25, tmp);

        tmp = shake_ctx[18] ^ t_3;
        // shl 21 | shr 43
        shake_ctx[18] = rol(21, tmp);

        tmp = shake_ctx[23] ^ t_3;
        // shl 56 | shr 8
        shake_ctx[23] = rol(56, tmp);

        tmp = shake_ctx[4] ^ t_4;
        // shl 27 | shr 37
        shake_ctx[4] = rol(27, tmp);

        tmp = shake_ctx[9] ^ t_4;
        // shl 20 | shr 44
        shake_ctx[9] = rol(20, tmp);

        tmp = shake_ctx[14] ^ t_4;
        // shl 39 | shr 25
        shake_ctx[14] = rol(39, tmp);

        tmp = shake_ctx[19] ^ t_4;
        // shl 8 | shr 56
        shake_ctx[19] = rol(8, tmp);

        tmp = shake_ctx[24] ^ t_4;
        // shl 14 | shr 50
        shake_ctx[24] = rol(14, tmp);

        let mut c_0 = shake_ctx[0] ^ (shake_ctx[6] | shake_ctx[12]);
        let mut c_1 = shake_ctx[6] ^ (!shake_ctx[12] | shake_ctx[18]);
        let mut c_2 = shake_ctx[12] ^ (shake_ctx[18] & shake_ctx[24]);
        let mut c_3 = shake_ctx[18] ^ (shake_ctx[24] | shake_ctx[0]);
        let mut c_4 = shake_ctx[24] ^ (shake_ctx[0] & shake_ctx[6]);

        shake_ctx[0] = c_0;
        shake_ctx[6] = c_1;
        shake_ctx[12] = c_2;
        shake_ctx[18] = c_3;
        shake_ctx[24] = c_4;

        c_0 = shake_ctx[3] ^ (shake_ctx[9] | shake_ctx[10]);
        c_1 = shake_ctx[9] ^ (shake_ctx[10] & shake_ctx[16]);
        c_2 = shake_ctx[10] ^ (shake_ctx[16] | !shake_ctx[22]);
        c_3 = shake_ctx[16] ^ (shake_ctx[22] | shake_ctx[3]);
        c_4 = shake_ctx[22] ^ (shake_ctx[3] & shake_ctx[9]);

        shake_ctx[3] = c_0;
        shake_ctx[9] = c_1;
        shake_ctx[10] = c_2;
        shake_ctx[16] = c_3;
        shake_ctx[22] = c_4;

        tmp = !shake_ctx[19];

        c_0 = shake_ctx[1] ^ (shake_ctx[7] | shake_ctx[13]);
        c_1 = shake_ctx[7] ^ (shake_ctx[13] & shake_ctx[19]);
        c_2 = shake_ctx[13] ^ (tmp & shake_ctx[20]);
        c_3 = tmp ^ (shake_ctx[20] | shake_ctx[1]);
        c_4 = shake_ctx[20] ^ (shake_ctx[1] & shake_ctx[7]);

        shake_ctx[1] = c_0;
        shake_ctx[7] = c_1;
        shake_ctx[13] = c_2;
        shake_ctx[19] = c_3;
        shake_ctx[20] = c_4;

        tmp = !shake_ctx[17];

        c_0 = shake_ctx[4] ^ (shake_ctx[5] & shake_ctx[11]);
        c_1 = shake_ctx[5] ^ (shake_ctx[11] | shake_ctx[17]);
        c_2 = shake_ctx[11] ^ (tmp | shake_ctx[23]);
        c_3 = tmp ^ (shake_ctx[23] & shake_ctx[4]);
        c_4 = shake_ctx[23] ^ (shake_ctx[4] | shake_ctx[5]);

        shake_ctx[4] = c_0;
        shake_ctx[5] = c_1;
        shake_ctx[11] = c_2;
        shake_ctx[17] = c_3;
        shake_ctx[23] = c_4;

        tmp = !shake_ctx[8];

        c_0 = shake_ctx[2] ^ (tmp & shake_ctx[14]);
        c_1 = tmp ^ (shake_ctx[14] | shake_ctx[15]);
        c_2 = shake_ctx[14] ^ (shake_ctx[15] & shake_ctx[21]);
        c_3 = shake_ctx[15] ^ (shake_ctx[21] | shake_ctx[2]);
        c_4 = shake_ctx[21] ^ (shake_ctx[2] & shake_ctx[8]);

        shake_ctx[2] = c_0;
        shake_ctx[8] = c_1;
        shake_ctx[14] = c_2;
        shake_ctx[15] = c_3;
        shake_ctx[21] = c_4;

        let j_usize: usize = j as usize;

        shake_ctx[0] = shake_ctx[0] ^ SHAKE_ROUND_CONSTANTS[j_usize];

        let xor_0_1 = shake_ctx[6] ^ shake_ctx[9] ^ shake_ctx[7] ^ shake_ctx[5] ^ shake_ctx[8];
        let xor_2_3 = shake_ctx[24] ^ shake_ctx[22] ^ shake_ctx[20] ^ shake_ctx[23] ^ shake_ctx[21];
        let xor_4_5 = shake_ctx[18] ^ shake_ctx[16] ^ shake_ctx[19] ^ shake_ctx[17] ^ shake_ctx[15];
        let xor_6_7 = shake_ctx[0] ^ shake_ctx[3] ^ shake_ctx[1] ^ shake_ctx[4] ^ shake_ctx[2];
        let xor_8_9 = shake_ctx[12] ^ shake_ctx[10] ^ shake_ctx[13] ^ shake_ctx[11] ^ shake_ctx[14];

        // shl 1 | shr 63
        let t_0 = rol(1, xor_0_1) ^ xor_2_3;
        let t_2 = rol(1, xor_4_5) ^ xor_0_1;
        let t_4 = rol(1, xor_6_7) ^ xor_4_5;
        let t_1 = rol(1, xor_8_9) ^ xor_6_7;
        let t_3 = rol(1, xor_2_3) ^ xor_8_9;

        shake_ctx[0] = shake_ctx[0] ^ t_0;

        tmp = shake_ctx[3] ^ t_0;
        // shl 36 | shr 28

        shake_ctx[3] = rol(36, tmp);

        tmp = shake_ctx[1] ^ t_0;
        // shl 3 | shr 61

        shake_ctx[1] = rol(3, tmp);

        tmp = shake_ctx[4] ^ t_0;
        // shl 41 | shr 23
        shake_ctx[4] = rol(41, tmp);

        tmp = shake_ctx[2] ^ t_0;
        // shl 18 | shr 46
        shake_ctx[2] = rol(18, tmp);

        tmp = shake_ctx[6] ^ t_1;
        // shl 1 | shr 63
        shake_ctx[6] = rol(1, tmp);

        tmp = shake_ctx[9] ^ t_1;
        // shl 44 | shr 20
        shake_ctx[9] = rol(44, tmp);

        tmp = shake_ctx[7] ^ t_1;
        // shl 10 | shr 54
        shake_ctx[7] = rol(10, tmp);

        tmp = shake_ctx[5] ^ t_1;
        // shl 45 | shr 19
        shake_ctx[5] = rol(45, tmp);

        tmp = shake_ctx[8] ^ t_1;
        // shl 2 | shr 62
        shake_ctx[8] = rol(2, tmp);

        tmp = shake_ctx[12] ^ t_2;
        // shl 62 | shr 2
        shake_ctx[12] = rol(62, tmp);

        tmp = shake_ctx[10] ^ t_2;
        // shl 6 | shr 58
        shake_ctx[10] = rol(6, tmp);

        tmp = shake_ctx[13] ^ t_2;
        // shl 43 | shr 21
        shake_ctx[13] = rol(43, tmp);

        tmp = shake_ctx[11] ^ t_2;
        // shl 15 | shr 49
        shake_ctx[11] = rol(15, tmp);

        tmp = shake_ctx[14] ^ t_2;
        // shl 61 | shr 3
        shake_ctx[14] = rol(61, tmp);

        tmp = shake_ctx[18] ^ t_3;
        // shl 28 | shr 36
        shake_ctx[18] = rol(28, tmp);

        tmp = shake_ctx[16] ^ t_3;
        // shl 55 | shr 9
        shake_ctx[16] = rol(55, tmp);

        tmp = shake_ctx[19] ^ t_3;
        // shl 25 | shr 39
        shake_ctx[19] = rol(25, tmp);

        tmp = shake_ctx[17] ^ t_3;
        // shl 21 | shr 43
        shake_ctx[17] = rol(21, tmp);

        tmp = shake_ctx[15] ^ t_3;
        // shl 56 | shr 8
        shake_ctx[15] = rol(56, tmp);

        tmp = shake_ctx[24] ^ t_4;
        // shl 27 | shr 37
        shake_ctx[24] = rol(27, tmp);

        tmp = shake_ctx[22] ^ t_4;
        // shl 20 | shr 44
        shake_ctx[22] = rol(20, tmp);

        tmp = shake_ctx[20] ^ t_4;
        // shl 39 | shr 25
        shake_ctx[20] = rol(39, tmp);

        tmp = shake_ctx[23] ^ t_4;
        // shl 8 | shr 56
        shake_ctx[23] = rol(8, tmp);

        tmp = shake_ctx[21] ^ t_4;
        // shl 14 | shr 50
        shake_ctx[21] = rol(14, tmp);

        c_0 = shake_ctx[0] ^ (shake_ctx[9] | shake_ctx[13]);
        c_1 = shake_ctx[9] ^ (!shake_ctx[13] | shake_ctx[17]);
        c_2 = shake_ctx[13] ^ (shake_ctx[17] & shake_ctx[21]);
        c_3 = shake_ctx[17] ^ (shake_ctx[21] | shake_ctx[0]);
        c_4 = shake_ctx[21] ^ (shake_ctx[0] & shake_ctx[9]);

        shake_ctx[0] = c_0;
        shake_ctx[9] = c_1;
        shake_ctx[13] = c_2;
        shake_ctx[17] = c_3;
        shake_ctx[21] = c_4;

        c_0 = shake_ctx[18] ^ (shake_ctx[22] | shake_ctx[1]);
        c_1 = shake_ctx[22] ^ (shake_ctx[1] & shake_ctx[5]);
        c_2 = shake_ctx[1] ^ (shake_ctx[5] | !shake_ctx[14]);
        c_3 = shake_ctx[5] ^ (shake_ctx[14] | shake_ctx[18]);
        c_4 = shake_ctx[14] ^ (shake_ctx[18] & shake_ctx[22]);

        shake_ctx[18] = c_0;
        shake_ctx[22] = c_1;
        shake_ctx[1] = c_2;
        shake_ctx[5] = c_3;
        shake_ctx[14] = c_4;

        tmp = !shake_ctx[23];

        c_0 = shake_ctx[6] ^ (shake_ctx[10] | shake_ctx[19]);
        c_1 = shake_ctx[10] ^ (shake_ctx[19] & shake_ctx[23]);
        c_2 = shake_ctx[19] ^ (tmp & shake_ctx[2]);
        c_3 = tmp ^ (shake_ctx[2] | shake_ctx[6]);
        c_4 = shake_ctx[2] ^ (shake_ctx[6] & shake_ctx[10]);

        shake_ctx[6] = c_0;
        shake_ctx[10] = c_1;
        shake_ctx[19] = c_2;
        shake_ctx[23] = c_3;
        shake_ctx[2] = c_4;

        tmp = !shake_ctx[11];

        c_0 = shake_ctx[24] ^ (shake_ctx[3] & shake_ctx[7]);
        c_1 = shake_ctx[3] ^ (shake_ctx[7] | shake_ctx[11]);
        c_2 = shake_ctx[7] ^ (tmp | shake_ctx[15]);
        c_3 = tmp ^ (shake_ctx[15] & shake_ctx[24]);
        c_4 = shake_ctx[15] ^ (shake_ctx[24] | shake_ctx[3]);

        shake_ctx[24] = c_0;
        shake_ctx[3] = c_1;
        shake_ctx[7] = c_2;
        shake_ctx[11] = c_3;
        shake_ctx[15] = c_4;

        tmp = !shake_ctx[16];

        c_0 = shake_ctx[12] ^ (tmp & shake_ctx[20]);
        c_1 = tmp ^ (shake_ctx[20] | shake_ctx[4]);
        c_2 = shake_ctx[20] ^ (shake_ctx[4] & shake_ctx[8]);
        c_3 = shake_ctx[4] ^ (shake_ctx[8] | shake_ctx[12]);
        c_4 = shake_ctx[8] ^ (shake_ctx[12] & shake_ctx[16]);

        shake_ctx[12] = c_0;
        shake_ctx[16] = c_1;
        shake_ctx[20] = c_2;
        shake_ctx[4] = c_3;
        shake_ctx[8] = c_4;
        shake_ctx[0] = shake_ctx[0] ^ SHAKE_ROUND_CONSTANTS[j_usize + 1];

        tmp = shake_ctx[5];

        shake_ctx[5] = shake_ctx[18];
        shake_ctx[18] = shake_ctx[11];
        shake_ctx[11] = shake_ctx[10];
        shake_ctx[10] = shake_ctx[6];
        shake_ctx[6] = shake_ctx[22];
        shake_ctx[22] = shake_ctx[20];
        shake_ctx[20] = shake_ctx[12];
        shake_ctx[12] = shake_ctx[19];
        shake_ctx[19] = shake_ctx[15];
        shake_ctx[15] = shake_ctx[24];
        shake_ctx[24] = shake_ctx[8];
        shake_ctx[8] = tmp;

        tmp = shake_ctx[1];

        shake_ctx[1] = shake_ctx[9];
        shake_ctx[9] = shake_ctx[14];
        shake_ctx[14] = shake_ctx[2];
        shake_ctx[2] = shake_ctx[13];
        shake_ctx[13] = shake_ctx[23];
        shake_ctx[23] = shake_ctx[4];
        shake_ctx[4] = shake_ctx[21];
        shake_ctx[21] = shake_ctx[16];
        shake_ctx[16] = shake_ctx[3];
        shake_ctx[3] = shake_ctx[17];
        shake_ctx[17] = shake_ctx[7];
        shake_ctx[7] = tmp;

        j += 2;

        if j == N_ROUNDS {
            break;
        }
    };

    shake_ctx[1] = !shake_ctx[1];
    shake_ctx[2] = !shake_ctx[2];
    shake_ctx[8] = !shake_ctx[8];
    shake_ctx[12] = !shake_ctx[12];
    shake_ctx[17] = !shake_ctx[17];
    shake_ctx[20] = !shake_ctx[20];
}

/// inject bytes data into the shake context
/// does not support consecutive calls
pub fn shake_inject(
    shake_ctx: &mut [u64; 26],
    input: &Vec<u8>
) {
    let mut in_len = input.len();
    let mut o: usize = 7;
    let rate = SHAKE256_RATE as usize;

    while in_len >= rate {
        let mut i: u8 = 0;

        loop  {
            let mut packed: u64 = (input[o] as u64) |
                ((input[o - 1] as u64) << 0x8) |
                (input[o - 2] as u64) << 0x10 |
                (input[o - 3] as u64) << 0x18 |
                (input[o - 4] as u64) << 0x20 |
                (input[o - 5] as u64) << 0x28 |
                (input[o - 6] as u64) << 0x30 |
                (input[o - 7] as u64) << 0x38;

            packed = (packed >> 0x8 & M8) | (packed & M8) << 0x8;
            packed = (packed >> 0x10 & M16) | (packed & M16) << 0x10;
            packed = (packed >> 0x20 & M32) | (packed & M32) << 0x20;

            let shake_o: usize = ((0x7 + i) >> 0x3) as usize;

            shake_ctx[shake_o] = shake_ctx[shake_o] ^ packed;

            i += 8;
            o += 8;

            if i == SHAKE256_RATE {
                break;
            }
        };

        in_len -= rate;

        process_block(shake_ctx);
    };

    if in_len > 0 {
        let msg_o = input.len() - in_len;
        let mut i = 0;

        loop {
            let o: usize = (i >> 0x3) as usize;

            shake_ctx[o] ^= (input[msg_o + i] as u64) << (i << 0x3 & 0x3f);

            i += 1;

            if i == in_len {
                break;
            }
        }
    }

    shake_ctx[25] =  in_len as u64;
}

/// flips shake256 state to output mode
/// after this call:
/// shake256_inject() can no longer be called on context
/// shake256_extract() can be called
pub fn shake_flip(shake_ctx: &mut [u64; 26]) {
    let last: u16 = shake_ctx[25] as u16;
    let o1: usize = (last >> 0x3) as usize;

    shake_ctx[o1] ^= 0x1f << ((last & 0x7) << 0x3);

    let rate_sub_1 = SHAKE256_RATE - 1;
    let o2: usize = (rate_sub_1 >> 0x3) as usize;

    shake_ctx[o2] ^= 0x80 << ((rate_sub_1 & 7) << 0x3);
    shake_ctx[25] = SHAKE256_RATE as u64;
}

/// extracts bytes from shake256 context ("squeeze" op, 8 bytes chunks)
/// context must have been flipped to output mode
pub fn shake_extract(
    shake_ctx: &mut [u64; 26],
    len: u16
) -> Vec<u64> {
    let mut dptr: u16 = shake_ctx[25] as u16;
    let mut out: Vec<u64> = vec![];
    let mut out_len = len;

    loop {
        if dptr == SHAKE256_RATE as u16 {
            process_block(shake_ctx);

            dptr = 0;
        }

        // below eq, benchmark it
        let mut clen: u16 = (SHAKE256_RATE as u16) - dptr;

        if clen > out_len {
            clen = out_len;
        }

        // clen = min(out_len, clen);

        // extracts bytes in chunks of 8 where possible
        loop {
            out.push(shake_ctx[(dptr as usize) >> 0x3]);

            dptr += 8;
            out_len -= 8;
            clen -= 8;

            if clen < 8 {
                break;
            }
        };

        // extract remaining bytes
        if clen > 0 {
            let mut packed = 0;
            let mut i: u16 = 0;

            loop {
                packed = packed |
                    ((shake_ctx[(dptr as usize) >> 0x3]) >> ((dptr & 7) << 0x3) & 0xff) << (i << 0x3);

                dptr += 1;
                i += 1;

                if i == clen {
                    break;
                }
            };

            out.push(packed);
            out_len -= clen;
        }

        if out_len == 0 {
            break;
        }
    };

    shake_ctx[25] = dptr as u64;

    out
}

// TODO: see below if no branching worth vs early exited branching
#[inline(always)]
fn handle_hash_to_point_bytes_pair(pair: u64) -> u16 {
    let mut res: u16 = pair as u16;

    if pair < 12289 {
        return res;
    }

    if res < 61445 {
        if res  < 24578 {
            res -= 12289;

            return res;
        }

        if res < 36867 {
            res -= 24578;

            return res;
        }

        if res < 49156 {
            res -= 36867;

            return res;
        }

        res -= 49156;

        return res;
    }

    0xffff
}


#[inline(always)]
pub fn handle_hash_to_point_chunk(
    chunk: u64,
    out: &mut [u16; 512],
    index: usize
) {
    let swapped = swap_byte_pairs(chunk);

    out[index] = handle_hash_to_point_bytes_pair(swapped & 0xffff);
    out[index + 1] = handle_hash_to_point_bytes_pair(swapped >> 0x10 & 0xffff);
    out[index + 2] = handle_hash_to_point_bytes_pair(swapped >> 0x20 & 0xffff);
    out[index + 3] = handle_hash_to_point_bytes_pair(swapped >> 0x30);
}

// constant-time produces a new point from a flipped shake256 context
// TODO: optimize further
pub fn hash_to_point_ct(
    extracted: &Vec<u64>,
    x: &mut [u16; 512],
    tt1: &mut [u16; 512]
) {
    let mut u = 0;

    // handling `x` len 512, unrolled x32 => 16 runs
    loop {
        let index: usize = u << 0x2;

        handle_hash_to_point_chunk(extracted[u], x, index);
        handle_hash_to_point_chunk(extracted[u + 1], x, index + 0x4);
        handle_hash_to_point_chunk(extracted[u + 2], x, index + 0x8);
        handle_hash_to_point_chunk(extracted[u + 3], x, index + 0xc);
        handle_hash_to_point_chunk(extracted[u + 4], x, index + 0x10);
        handle_hash_to_point_chunk(extracted[u + 5], x, index + 0x14);
        handle_hash_to_point_chunk(extracted[u + 6], x, index + 0x18);
        handle_hash_to_point_chunk(extracted[u + 7], x, index + 0x1c);

        u += 8;

        if u == 0x80 {
            break;
        }
    };

    let mut out_index = 0;

    // handling `tt1` OVERSAMPLING - 13 unrolled x32 => 6 runs
    loop {
        handle_hash_to_point_chunk(extracted[u], tt1, out_index);
        handle_hash_to_point_chunk(extracted[u + 1], tt1, out_index + 0x4);
        handle_hash_to_point_chunk(extracted[u + 2], tt1, out_index + 0x8);
        handle_hash_to_point_chunk(extracted[u + 3], tt1, out_index + 0xc);
        handle_hash_to_point_chunk(extracted[u + 4], tt1, out_index + 0x10);
        handle_hash_to_point_chunk(extracted[u + 5], tt1, out_index + 0x14);
        handle_hash_to_point_chunk(extracted[u + 6], tt1, out_index + 0x18);
        handle_hash_to_point_chunk(extracted[u + 7], tt1, out_index + 0x1c);

        u += 8;
        out_index += 32;

        if u == 0xb0 {
            break;
        }
    };

    // handles remaining 13 items
    handle_hash_to_point_chunk(extracted[0xb0], tt1, out_index);
    handle_hash_to_point_chunk(extracted[0xb1], tt1, out_index + 0x4);
    handle_hash_to_point_chunk(extracted[0xb2], tt1, out_index + 0x8);

    let swapped = swap_byte_pairs(extracted[0xb3]);

    tt1[out_index + 0xc] = handle_hash_to_point_bytes_pair(swapped & 0xffff);

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

            // Update v (unsigned arithmetic, subtract mk)
            v -= mk;

            // Adjust mk with new condition (same shift as before but in uint256)
            mk &= 0 - (((j & p as u16) + 0x1ff) >> 0x9);

            let xi = u - p;
            let dv = x[xi];
            let mk_and_sv_xor_dv = mk & (sv ^ dv);

            x[xi] = dv ^ mk_and_sv_xor_dv;
            x[u] = sv ^ mk_and_sv_xor_dv;

            u += 1;

            if u == N as usize {
                break;
            }
        };

        // sec loop for `u >= _M || (u - p) >= _N`

        loop {
            let tt1i = u - N as usize;
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

            if u < M as usize && (u - p) < N as usize {
                continue;
            }

            break;
        };

        // sec loop for `u < _M`
        loop {
            let u_sub_n = u - N as usize;
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
