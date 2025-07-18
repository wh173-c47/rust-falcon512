use crate::{constants::{SHAKE256_RATE, SHAKE_ROUND_CONSTANTS}};

#[inline(always)]
fn theta_rho_step_1(shake_ctx: &mut [u64; 26]) {
    let xor_0_1 = shake_ctx[1] ^ shake_ctx[6] ^ shake_ctx[11] ^ shake_ctx[16] ^ shake_ctx[21];
    let xor_2_3 = shake_ctx[4] ^ shake_ctx[9] ^ shake_ctx[14] ^ shake_ctx[19] ^ shake_ctx[24];
    let xor_4_5 = shake_ctx[3] ^ shake_ctx[8] ^ shake_ctx[13] ^ shake_ctx[18] ^ shake_ctx[23];
    let xor_6_7 = shake_ctx[0] ^ shake_ctx[5] ^ shake_ctx[10] ^ shake_ctx[15] ^ shake_ctx[20];
    let xor_8_9 = shake_ctx[2] ^ shake_ctx[7] ^ shake_ctx[12] ^ shake_ctx[17] ^ shake_ctx[22];

    let t_0 = xor_0_1.rotate_left(1) ^ xor_2_3;
    let t_1 = xor_8_9.rotate_left(1) ^ xor_6_7;
    let t_2 = xor_4_5.rotate_left(1) ^ xor_0_1;
    let t_3 = xor_2_3.rotate_left(1) ^ xor_8_9;
    let t_4 = xor_6_7.rotate_left(1) ^ xor_4_5;

    shake_ctx[0] ^= t_0;
    shake_ctx[1] = (shake_ctx[1] ^ t_1).rotate_left(1);
    shake_ctx[2] = (shake_ctx[2] ^ t_2).rotate_left(62);
    shake_ctx[3] = (shake_ctx[3] ^ t_3).rotate_left(28);
    shake_ctx[4] = (shake_ctx[4] ^ t_4).rotate_left(27);
    shake_ctx[5] = (shake_ctx[5] ^ t_0).rotate_left(36);
    shake_ctx[6] = (shake_ctx[6] ^ t_1).rotate_left(44);
    shake_ctx[7] = (shake_ctx[7] ^ t_2).rotate_left(6);
    shake_ctx[8] = (shake_ctx[8] ^ t_3).rotate_left(55);
    shake_ctx[9] = (shake_ctx[9] ^ t_4).rotate_left(20);
    shake_ctx[10] = (shake_ctx[10] ^ t_0).rotate_left(3);
    shake_ctx[11] = (shake_ctx[11] ^ t_1).rotate_left(10);
    shake_ctx[12] = (shake_ctx[12] ^ t_2).rotate_left(43);
    shake_ctx[13] = (shake_ctx[13] ^ t_3).rotate_left(25);
    shake_ctx[14] = (shake_ctx[14] ^ t_4).rotate_left(39);
    shake_ctx[15] = (shake_ctx[15] ^ t_0).rotate_left(41);
    shake_ctx[16] = (shake_ctx[16] ^ t_1).rotate_left(45);
    shake_ctx[17] = (shake_ctx[17] ^ t_2).rotate_left(15);
    shake_ctx[18] = (shake_ctx[18] ^ t_3).rotate_left(21);
    shake_ctx[19] = (shake_ctx[19] ^ t_4).rotate_left(8);
    shake_ctx[20] = (shake_ctx[20] ^ t_0).rotate_left(18);
    shake_ctx[21] = (shake_ctx[21] ^ t_1).rotate_left(2);
    shake_ctx[22] = (shake_ctx[22] ^ t_2).rotate_left(61);
    shake_ctx[23] = (shake_ctx[23] ^ t_3).rotate_left(56);
    shake_ctx[24] = (shake_ctx[24] ^ t_4).rotate_left(14);
}

#[inline(always)]
fn chi_iota_step_1(shake_ctx: &mut [u64; 26], round_constant: u64) {
    let mut c_0 = shake_ctx[0] ^ (shake_ctx[6] | shake_ctx[12]);
    let mut c_1 = shake_ctx[6] ^ (!shake_ctx[12] | shake_ctx[18]);
    let mut c_2 = shake_ctx[12] ^ (shake_ctx[18] & shake_ctx[24]);
    let mut c_3 = shake_ctx[18] ^ (shake_ctx[24] | shake_ctx[0]);
    let mut c_4 = shake_ctx[24] ^ (shake_ctx[0] & shake_ctx[6]);

    shake_ctx[0] = c_0; shake_ctx[6] = c_1; shake_ctx[12] = c_2; shake_ctx[18] = c_3; shake_ctx[24] = c_4;

    c_0 = shake_ctx[3] ^ (shake_ctx[9] | shake_ctx[10]);
    c_1 = shake_ctx[9] ^ (shake_ctx[10] & shake_ctx[16]);
    c_2 = shake_ctx[10] ^ (shake_ctx[16] | !shake_ctx[22]);
    c_3 = shake_ctx[16] ^ (shake_ctx[22] | shake_ctx[3]);
    c_4 = shake_ctx[22] ^ (shake_ctx[3] & shake_ctx[9]);
    shake_ctx[3] = c_0; shake_ctx[9] = c_1; shake_ctx[10] = c_2; shake_ctx[16] = c_3; shake_ctx[22] = c_4;

    let tmp = !shake_ctx[19];

    c_0 = shake_ctx[1] ^ (shake_ctx[7] | shake_ctx[13]);
    c_1 = shake_ctx[7] ^ (shake_ctx[13] & shake_ctx[19]);
    c_2 = shake_ctx[13] ^ (tmp & shake_ctx[20]);
    c_3 = tmp ^ (shake_ctx[20] | shake_ctx[1]);
    c_4 = shake_ctx[20] ^ (shake_ctx[1] & shake_ctx[7]);
    shake_ctx[1] = c_0; shake_ctx[7] = c_1; shake_ctx[13] = c_2; shake_ctx[19] = c_3; shake_ctx[20] = c_4;

    let tmp = !shake_ctx[17];

    c_0 = shake_ctx[4] ^ (shake_ctx[5] & shake_ctx[11]);
    c_1 = shake_ctx[5] ^ (shake_ctx[11] | shake_ctx[17]);
    c_2 = shake_ctx[11] ^ (tmp | shake_ctx[23]);
    c_3 = tmp ^ (shake_ctx[23] & shake_ctx[4]);
    c_4 = shake_ctx[23] ^ (shake_ctx[4] | shake_ctx[5]);
    shake_ctx[4] = c_0; shake_ctx[5] = c_1; shake_ctx[11] = c_2; shake_ctx[17] = c_3; shake_ctx[23] = c_4;

    let tmp = !shake_ctx[8];

    c_0 = shake_ctx[2] ^ (tmp & shake_ctx[14]);
    c_1 = tmp ^ (shake_ctx[14] | shake_ctx[15]);
    c_2 = shake_ctx[14] ^ (shake_ctx[15] & shake_ctx[21]);
    c_3 = shake_ctx[15] ^ (shake_ctx[21] | shake_ctx[2]);
    c_4 = shake_ctx[21] ^ (shake_ctx[2] & shake_ctx[8]);
    shake_ctx[2] = c_0; shake_ctx[8] = c_1; shake_ctx[14] = c_2; shake_ctx[15] = c_3; shake_ctx[21] = c_4;

    shake_ctx[0] ^= round_constant;
}

#[inline(always)]
fn theta_rho_step_2(shake_ctx: &mut [u64; 26]) {
    let xor_0_1 = shake_ctx[6] ^ shake_ctx[9] ^ shake_ctx[7] ^ shake_ctx[5] ^ shake_ctx[8];
    let xor_2_3 = shake_ctx[24] ^ shake_ctx[22] ^ shake_ctx[20] ^ shake_ctx[23] ^ shake_ctx[21];
    let xor_4_5 = shake_ctx[18] ^ shake_ctx[16] ^ shake_ctx[19] ^ shake_ctx[17] ^ shake_ctx[15];
    let xor_6_7 = shake_ctx[0] ^ shake_ctx[3] ^ shake_ctx[1] ^ shake_ctx[4] ^ shake_ctx[2];
    let xor_8_9 = shake_ctx[12] ^ shake_ctx[10] ^ shake_ctx[13] ^ shake_ctx[11] ^ shake_ctx[14];

    let t_0 = xor_0_1.rotate_left(1) ^ xor_2_3;
    let t_1 = xor_8_9.rotate_left(1) ^ xor_6_7;
    let t_2 = xor_4_5.rotate_left(1) ^ xor_0_1;
    let t_3 = xor_2_3.rotate_left(1) ^ xor_8_9;
    let t_4 = xor_6_7.rotate_left(1) ^ xor_4_5;

    shake_ctx[0] ^= t_0;

    shake_ctx[3] = (shake_ctx[3] ^ t_0).rotate_left(36);
    shake_ctx[1] = (shake_ctx[1] ^ t_0).rotate_left(3);
    shake_ctx[4] = (shake_ctx[4] ^ t_0).rotate_left(41);
    shake_ctx[2] = (shake_ctx[2] ^ t_0).rotate_left(18);
    shake_ctx[6] = (shake_ctx[6] ^ t_1).rotate_left(1);
    shake_ctx[9] = (shake_ctx[9] ^ t_1).rotate_left(44);
    shake_ctx[7] = (shake_ctx[7] ^ t_1).rotate_left(10);
    shake_ctx[5] = (shake_ctx[5] ^ t_1).rotate_left(45);
    shake_ctx[8] = (shake_ctx[8] ^ t_1).rotate_left(2);
    shake_ctx[12] = (shake_ctx[12] ^ t_2).rotate_left(62);
    shake_ctx[10] = (shake_ctx[10] ^ t_2).rotate_left(6);
    shake_ctx[13] = (shake_ctx[13] ^ t_2).rotate_left(43);
    shake_ctx[11] = (shake_ctx[11] ^ t_2).rotate_left(15);
    shake_ctx[14] = (shake_ctx[14] ^ t_2).rotate_left(61);
    shake_ctx[18] = (shake_ctx[18] ^ t_3).rotate_left(28);
    shake_ctx[16] = (shake_ctx[16] ^ t_3).rotate_left(55);
    shake_ctx[19] = (shake_ctx[19] ^ t_3).rotate_left(25);
    shake_ctx[17] = (shake_ctx[17] ^ t_3).rotate_left(21);
    shake_ctx[15] = (shake_ctx[15] ^ t_3).rotate_left(56);
    shake_ctx[24] = (shake_ctx[24] ^ t_4).rotate_left(27);
    shake_ctx[22] = (shake_ctx[22] ^ t_4).rotate_left(20);
    shake_ctx[20] = (shake_ctx[20] ^ t_4).rotate_left(39);
    shake_ctx[23] = (shake_ctx[23] ^ t_4).rotate_left(8);
    shake_ctx[21] = (shake_ctx[21] ^ t_4).rotate_left(14);
}

#[inline(always)]
fn chi_iota_pi_step_2(shake_ctx: &mut [u64; 26], round_constant: u64) {
    let mut c_0 = shake_ctx[0] ^ (shake_ctx[9] | shake_ctx[13]);
    let mut c_1 = shake_ctx[9] ^ (!shake_ctx[13] | shake_ctx[17]);
    let mut c_2 = shake_ctx[13] ^ (shake_ctx[17] & shake_ctx[21]);
    let mut c_3 = shake_ctx[17] ^ (shake_ctx[21] | shake_ctx[0]);
    let mut c_4 = shake_ctx[21] ^ (shake_ctx[0] & shake_ctx[9]);

    shake_ctx[0] = c_0; shake_ctx[9] = c_1; shake_ctx[13] = c_2; shake_ctx[17] = c_3; shake_ctx[21] = c_4;

    c_0 = shake_ctx[18] ^ (shake_ctx[22] | shake_ctx[1]);
    c_1 = shake_ctx[22] ^ (shake_ctx[1] & shake_ctx[5]);
    c_2 = shake_ctx[1] ^ (shake_ctx[5] | !shake_ctx[14]);
    c_3 = shake_ctx[5] ^ (shake_ctx[14] | shake_ctx[18]);
    c_4 = shake_ctx[14] ^ (shake_ctx[18] & shake_ctx[22]);
    shake_ctx[18] = c_0; shake_ctx[22] = c_1; shake_ctx[1] = c_2; shake_ctx[5] = c_3; shake_ctx[14] = c_4;

    let tmp = !shake_ctx[23];

    c_0 = shake_ctx[6] ^ (shake_ctx[10] | shake_ctx[19]);
    c_1 = shake_ctx[10] ^ (shake_ctx[19] & shake_ctx[23]);
    c_2 = shake_ctx[19] ^ (tmp & shake_ctx[2]);
    c_3 = tmp ^ (shake_ctx[2] | shake_ctx[6]);
    c_4 = shake_ctx[2] ^ (shake_ctx[6] & shake_ctx[10]);
    shake_ctx[6] = c_0; shake_ctx[10] = c_1; shake_ctx[19] = c_2; shake_ctx[23] = c_3; shake_ctx[2] = c_4;

    let tmp = !shake_ctx[11];

    c_0 = shake_ctx[24] ^ (shake_ctx[3] & shake_ctx[7]);
    c_1 = shake_ctx[3] ^ (shake_ctx[7] | shake_ctx[11]);
    c_2 = shake_ctx[7] ^ (tmp | shake_ctx[15]);
    c_3 = tmp ^ (shake_ctx[15] & shake_ctx[24]);
    c_4 = shake_ctx[15] ^ (shake_ctx[24] | shake_ctx[3]);
    shake_ctx[24] = c_0; shake_ctx[3] = c_1; shake_ctx[7] = c_2; shake_ctx[11] = c_3; shake_ctx[15] = c_4;

    let tmp = !shake_ctx[16];

    c_0 = shake_ctx[12] ^ (tmp & shake_ctx[20]);
    c_1 = tmp ^ (shake_ctx[20] | shake_ctx[4]);
    c_2 = shake_ctx[20] ^ (shake_ctx[4] & shake_ctx[8]);
    c_3 = shake_ctx[4] ^ (shake_ctx[8] | shake_ctx[12]);
    c_4 = shake_ctx[8] ^ (shake_ctx[12] & shake_ctx[16]);
    shake_ctx[12] = c_0; shake_ctx[16] = c_1; shake_ctx[20] = c_2; shake_ctx[4] = c_3; shake_ctx[8] = c_4;

    shake_ctx[0] ^= round_constant;

    let tmp = shake_ctx[5];

    shake_ctx[5] = shake_ctx[18]; shake_ctx[18] = shake_ctx[11]; shake_ctx[11] = shake_ctx[10];
    shake_ctx[10] = shake_ctx[6]; shake_ctx[6] = shake_ctx[22]; shake_ctx[22] = shake_ctx[20];
    shake_ctx[20] = shake_ctx[12]; shake_ctx[12] = shake_ctx[19]; shake_ctx[19] = shake_ctx[15];
    shake_ctx[15] = shake_ctx[24]; shake_ctx[24] = shake_ctx[8]; shake_ctx[8] = tmp;

    let tmp = shake_ctx[1];

    shake_ctx[1] = shake_ctx[9]; shake_ctx[9] = shake_ctx[14]; shake_ctx[14] = shake_ctx[2];
    shake_ctx[2] = shake_ctx[13]; shake_ctx[13] = shake_ctx[23]; shake_ctx[23] = shake_ctx[4];
    shake_ctx[4] = shake_ctx[21]; shake_ctx[21] = shake_ctx[16]; shake_ctx[16] = shake_ctx[3];
    shake_ctx[3] = shake_ctx[17]; shake_ctx[17] = shake_ctx[7]; shake_ctx[7] = tmp;
}

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

    // unrolling rounds
    theta_rho_step_1(shake_ctx);
    chi_iota_step_1(shake_ctx, SHAKE_ROUND_CONSTANTS[0x0]);
    theta_rho_step_2(shake_ctx);
    chi_iota_pi_step_2(shake_ctx, SHAKE_ROUND_CONSTANTS[0x1]);

    theta_rho_step_1(shake_ctx);
    chi_iota_step_1(shake_ctx, SHAKE_ROUND_CONSTANTS[0x2]);
    theta_rho_step_2(shake_ctx);
    chi_iota_pi_step_2(shake_ctx, SHAKE_ROUND_CONSTANTS[0x3]);

    theta_rho_step_1(shake_ctx);
    chi_iota_step_1(shake_ctx, SHAKE_ROUND_CONSTANTS[0x4]);
    theta_rho_step_2(shake_ctx);
    chi_iota_pi_step_2(shake_ctx, SHAKE_ROUND_CONSTANTS[0x5]);

    theta_rho_step_1(shake_ctx);
    chi_iota_step_1(shake_ctx, SHAKE_ROUND_CONSTANTS[0x6]);
    theta_rho_step_2(shake_ctx);
    chi_iota_pi_step_2(shake_ctx, SHAKE_ROUND_CONSTANTS[0x7]);

    theta_rho_step_1(shake_ctx);
    chi_iota_step_1(shake_ctx, SHAKE_ROUND_CONSTANTS[0x8]);
    theta_rho_step_2(shake_ctx);
    chi_iota_pi_step_2(shake_ctx, SHAKE_ROUND_CONSTANTS[0x9]);

    theta_rho_step_1(shake_ctx);
    chi_iota_step_1(shake_ctx, SHAKE_ROUND_CONSTANTS[0xa]);
    theta_rho_step_2(shake_ctx);
    chi_iota_pi_step_2(shake_ctx, SHAKE_ROUND_CONSTANTS[0xb]);

    theta_rho_step_1(shake_ctx);
    chi_iota_step_1(shake_ctx, SHAKE_ROUND_CONSTANTS[0xc]);
    theta_rho_step_2(shake_ctx);
    chi_iota_pi_step_2(shake_ctx, SHAKE_ROUND_CONSTANTS[0xd]);

    theta_rho_step_1(shake_ctx);
    chi_iota_step_1(shake_ctx, SHAKE_ROUND_CONSTANTS[0xe]);
    theta_rho_step_2(shake_ctx);
    chi_iota_pi_step_2(shake_ctx, SHAKE_ROUND_CONSTANTS[0xf]);

    theta_rho_step_1(shake_ctx);
    chi_iota_step_1(shake_ctx, SHAKE_ROUND_CONSTANTS[0x10]);
    theta_rho_step_2(shake_ctx);
    chi_iota_pi_step_2(shake_ctx, SHAKE_ROUND_CONSTANTS[0x11]);

    theta_rho_step_1(shake_ctx);
    chi_iota_step_1(shake_ctx, SHAKE_ROUND_CONSTANTS[0x12]);
    theta_rho_step_2(shake_ctx);
    chi_iota_pi_step_2(shake_ctx, SHAKE_ROUND_CONSTANTS[0x13]);

    theta_rho_step_1(shake_ctx);
    chi_iota_step_1(shake_ctx, SHAKE_ROUND_CONSTANTS[0x14]);
    theta_rho_step_2(shake_ctx);
    chi_iota_pi_step_2(shake_ctx, SHAKE_ROUND_CONSTANTS[0x15]);

    theta_rho_step_1(shake_ctx);
    chi_iota_step_1(shake_ctx, SHAKE_ROUND_CONSTANTS[0x16]);
    theta_rho_step_2(shake_ctx);
    chi_iota_pi_step_2(shake_ctx, SHAKE_ROUND_CONSTANTS[0x17]);

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
    u64::from_le_bytes(input[offset..offset+8].try_into().unwrap())
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
        let full_words_in_remainder = in_len / 0x8;
        let final_bytes = in_len & 0x7;

        let mut i = 0;

        while i != full_words_in_remainder {
            let data_chunk = pack_and_swap_chunk(input, offset + i * 8);

            shake_ctx[i] ^= data_chunk;

            i += 1;
        };

        let remainder_offset = offset + (full_words_in_remainder * 8);

        i = 0;
        while i != final_bytes {
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

    shake_ctx[o2] ^= 0x80 << ((rate_sub_1 & 0x7) << 0x3);
    shake_ctx[25] = SHAKE256_RATE as u64;
}

// (shake_extract_len + 7) / 8
const OUT_CAPACITY_WORDS: usize = 180;

/// extracts bytes from shake256 context ("squeeze" op, 8 bytes chunks)
/// context must have been flipped to output mode
pub fn shake_extract(
    shake_ctx: &mut [u64; 26]
) -> [u64; OUT_CAPACITY_WORDS] {
    // M << 1
    let len = 1434;

    let mut out = [0u64; OUT_CAPACITY_WORDS];
    let mut words_written = 0;

    let rate_usize = SHAKE256_RATE as usize;
    let full_runs = len / rate_usize;
    let remainder_bytes = len % rate_usize;

    for _ in 0..full_runs {
        process_block(shake_ctx);

        let dest_slice = &mut out[words_written..words_written + 17];

        dest_slice.copy_from_slice(&shake_ctx[..17]);

        words_written += 17;
    }

    if remainder_bytes > 0 {
        process_block(shake_ctx);

        let remainder_words = remainder_bytes / 0x8;
        let partial_word_bytes = remainder_bytes & 0x7;

        if remainder_words > 0 {
            let dest_slice = &mut out[words_written..words_written + remainder_words];
            dest_slice.copy_from_slice(&shake_ctx[..remainder_words]);
            words_written += remainder_words;
        }

        if partial_word_bytes > 0 {
            let src_bytes = shake_ctx[remainder_words].to_le_bytes();
            let mut packed_bytes = [0u8; 8];

            packed_bytes[..partial_word_bytes].copy_from_slice(&src_bytes[..partial_word_bytes]);
            out[words_written] = u64::from_le_bytes(packed_bytes);
        }
    }

    shake_ctx[25] = 0x0;

    out
}