use crate::constants::{M8, R_M8, Q, Q0I, };

#[inline(always)]
pub fn mq_montymul(a: u16, b: u16) -> u16 {
    let res: u32 = (a as u32) * (b as u32);
    let m = res as u16 * Q0I;
    let t = (res + (m as u32) * Q as u32) >> 16;

    if t < Q as u32 { // <-- Potential branch
        t as u16
    } else {
        (t - Q as u32) as u16
    }
}

/// Performs modular addition: `(a + b) mod Q`.
#[inline(always)]
pub fn mq_add(a: u16, b: u16) -> u16 {
    let c = a as u32 + b as u32;

    (c - if c >= Q as u32 { Q as u32} else { 0 }) as u16
}

/// Performs modular subtraction: `(a - b) mod Q`.
#[inline(always)]
pub fn mq_sub(a: u16, b: u16) -> u16 {
    let c = (a as i32) - (b as i32);

    (c + if c < 0 { Q as i32 } else { 0 }) as u16
}

#[inline(always)]
pub fn rol(r: u64, x: u64) -> u64 {
    (x << r) | (x >> (64 - r))
}

/// swaps byte pairs u64 wide `x`
#[inline(always)]
pub fn swap_byte_pairs(x: u64) -> u64 {
    (x & R_M8) >> 0x8 | (x & M8) << 0x8
}

/// returns extended sign (if any) of a 16-bit value to 32-bit
#[inline(always)]
pub fn sign_extend_u16_to_u32(x: u16) -> u32 {
    (x as i16) as i32 as u32
}

pub fn revert(reason: &str) {
    panic!("Reverted: {}", reason);
}
