use crate::constants::{M8, R_M8};

// TODO: Optimize ops, probl benchmark Monty repr

#[inline(always)]
pub fn mulmod(x: u16, y: u16, m: u16) -> u16 {
    ((x as u32 * y as u32) % m as u32) as u16
}

#[inline(always)]
pub fn addmod(x: u16, y: u16, m: u16) -> u16 {
    ((x as u32 + y as u32) % m as u32) as u16
}

#[inline(always)]
pub fn submod(x: u16, y: u16, m: u16) -> u16 {
    ((m as u32 + x as u32 - y as u32) % m as u32) as u16
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
    if x < 32768_u16 {
        // positive, unchanged
        x.into()
    } else {
        // manually sign-extend to 32-bit
        x as u32 | 0xFFFF0000
    }
}

pub fn revert(reason: &str) {
    panic!("Reverted: {}", reason);
}
