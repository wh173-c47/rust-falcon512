use crate::{constants::{N_ROUNDS, SHAKE256_RATE, SHAKE_ROUND_CONSTANTS}, utils::rol};
use num::integer::div_rem;

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
        let xor_0_1 = shake_ctx[1] ^ shake_ctx[6] ^ shake_ctx[11] ^ shake_ctx[16] ^ shake_ctx[21];
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

/// packs and swap chunks (LE)
#[inline(always)]
fn pack_and_swap_chunk(input: &[u8], offset: usize) -> u64 {
    (input[offset]) as u64
        | ((input[offset + 1] as u64) << 0x8)
        | ((input[offset + 2] as u64) << 0x10)
        | ((input[offset + 3] as u64) << 0x18)
        | ((input[offset + 4] as u64) << 0x20)
        | ((input[offset + 5] as u64) << 0x28)
        | ((input[offset + 6] as u64) << 0x30)
        | ((input[offset + 7] as u64) << 0x38)
}

/// absorbs one full 136-byte block into the Keccak state using direct field access.
#[inline(always)]
fn absorb_full_block(shake_ctx: &mut [u64; 26], input_block: &[u8]) {
    shake_ctx[0] = shake_ctx[0] ^ pack_and_swap_chunk(input_block, 0x0);
    shake_ctx[1] = shake_ctx[1] ^ pack_and_swap_chunk(input_block, 0x8);
    shake_ctx[2] = shake_ctx[2] ^ pack_and_swap_chunk(input_block, 0x10);
    shake_ctx[3] = shake_ctx[3] ^ pack_and_swap_chunk(input_block, 0x18);
    shake_ctx[4] = shake_ctx[4] ^ pack_and_swap_chunk(input_block, 0x20);
    shake_ctx[5] = shake_ctx[5] ^ pack_and_swap_chunk(input_block, 0x28);
    shake_ctx[6] = shake_ctx[6] ^ pack_and_swap_chunk(input_block, 0x30);
    shake_ctx[7] = shake_ctx[7] ^ pack_and_swap_chunk(input_block, 0x38);
    shake_ctx[8] = shake_ctx[8] ^ pack_and_swap_chunk(input_block, 0x40);
    shake_ctx[9] = shake_ctx[9] ^ pack_and_swap_chunk(input_block, 0x48);
    shake_ctx[10] = shake_ctx[10] ^ pack_and_swap_chunk(input_block, 0x50);
    shake_ctx[11] = shake_ctx[11] ^ pack_and_swap_chunk(input_block, 0x58);
    shake_ctx[12] = shake_ctx[12] ^ pack_and_swap_chunk(input_block, 0x60);
    shake_ctx[13] = shake_ctx[13] ^ pack_and_swap_chunk(input_block, 0x68);
    shake_ctx[14] = shake_ctx[14] ^ pack_and_swap_chunk(input_block, 0x70);
    shake_ctx[15] = shake_ctx[15] ^ pack_and_swap_chunk(input_block, 0x78);
    shake_ctx[16] = shake_ctx[16] ^ pack_and_swap_chunk(input_block, 0x80);
}

/// inject bytes data into the shake context
/// does not support consecutive calls
pub fn shake_inject(
    shake_ctx: &mut [u64; 26],
    input: &[u8]
) {
    let mut in_len = input.len();
    let mut offset: usize = 0;
    let rate_usize = SHAKE256_RATE as usize;
    let full_runs = in_len / rate_usize;
    let loop_end = full_runs * rate_usize;

    // processes full blocks using the fast, unrolled path
    while offset != loop_end {
        let next_block = offset + rate_usize;
        let input_block = &input[offset..next_block];

        absorb_full_block(shake_ctx, input_block);
        process_block(shake_ctx);

        offset = next_block;
    };

    in_len -= loop_end;

    if in_len != 0 {
        // The remainder always starts filling the state from lane 0.
        let (full_words_in_remainder, final_bytes) = div_rem(in_len, 8);

        let mut i = 0;
        while i != full_words_in_remainder {
            // CORRECTED: The destination index is `i`, starting from 0.
            let data_chunk = pack_and_swap_chunk(input, offset + i * 8);
            shake_ctx[i] ^= data_chunk;
            i += 1;
        };

        let remainder_offset = offset + (full_words_in_remainder * 8);

        i = 0;
        while i != final_bytes {
            // CORRECTED: The destination index for the final bytes is the lane
            // immediately after the last full word. This is `full_words_in_remainder`.
            let lane_index = full_words_in_remainder;
            shake_ctx[lane_index] ^= (input[remainder_offset + i] as u64) << (i * 8);
            i += 1;
        };
    }

    shake_ctx[25] = in_len as u64;
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
    len: usize,
) -> Vec<u64> {
    let out_capacity_words = (len + 7) / 8;
    let mut out: Vec<u64> = Vec::with_capacity(out_capacity_words);
    let rate_usize = SHAKE256_RATE as usize;

    let (full_runs, remainder_bytes) = div_rem(len, rate_usize);

    for _ in 0..full_runs {
        process_block(shake_ctx);
        // squeeze full block
        out.extend_from_slice(&shake_ctx[..17]);
    }

    if remainder_bytes > 0 {
        process_block(shake_ctx);

        let (remainder_words, partial_word_bytes) = div_rem(remainder_bytes, 8);

        if remainder_words > 0 {
            out.extend_from_slice(&shake_ctx[..remainder_words]);
        }

        if partial_word_bytes > 0 {
            let word_to_unpack = shake_ctx[remainder_words];
            let mut packed = 0u64;

            for i in 0..partial_word_bytes {
                packed |= ((word_to_unpack >> (i * 8)) & 0xFF) << (i * 8);
            }

            out.push(packed);
        }
    }

    shake_ctx[25] = 0x0;

    out
}
