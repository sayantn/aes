use core::ops::{BitAnd, BitOr, BitXor, Not};
use core::{mem, slice};

#[inline(always)]
const fn rep(x: u8) -> u128 {
    u128::from_ne_bytes([x; 16])
}

#[inline(always)]
const fn ror1(x: u128) -> u128 {
    ((x & rep(0xfe)) >> 1) | ((x & rep(0x01)) << 7)
}

#[inline(always)]
const fn swap2(x: u128) -> u128 {
    ((x & rep(0xcc)) >> 2) | ((x & rep(0x33)) << 2)
}

#[inline(always)]
const fn step_a(a: u128, b: u128, mask: u128) -> u128 {
    let x = a & b;
    x ^ ((x & mask) >> 1) ^ ((((a << 1) & b) ^ ((b << 1) & a)) & mask)
}

#[inline(always)]
const fn step_b(a: u128, mask: u128) -> u128 {
    let x = a & mask;
    (x | (x >> 1)) ^ ((a << 1) & mask)
}

#[allow(clippy::cast_possible_truncation)]
const fn sub_word(x: u32) -> u32 {
    // Check if rustc is enough to optimize this
    subbytes(x as u128) as u32
}

const fn subbytes(x: u128) -> u128 {
    let y = ror1(x);
    let x = (x & rep(0xdd)) ^ (y & rep(0x57));
    let y = ror1(y);
    let x = x ^ (y & rep(0x1c));
    let y = ror1(y);
    let x = x ^ (y & rep(0x4a));
    let y = ror1(y);
    let x = x ^ (y & rep(0x42));
    let y = ror1(y);
    let x = x ^ (y & rep(0x64));
    let y = ror1(y);
    let x = x ^ (y & rep(0xe0));

    let a1 = x ^ ((x & rep(0xf0)) >> 4);
    let a2 = swap2(x);
    let a3 = step_a(x, a1, rep(0xaa));
    let a4 = step_a(a1, a2, rep(0xaa));
    let a5 = (a3 & rep(0xcc)) >> 2;
    let a3 = a3 ^ (((a4 << 2) ^ a4) & rep(0xcc));
    let a4 = step_b(a5, rep(0x22));
    let a3 = a3 ^ a4;
    let a5 = step_b(a3, rep(0xa0));
    let a4 = a5 & rep(0xc0);
    let a6 = a4 >> 2;
    let a4 = a4 ^ ((a5 << 2) & rep(0xc0));
    let a5 = step_b(a6, rep(0x20));
    let a4 = a4 | a5;
    let a3 = (a3 ^ (a4 >> 4)) & rep(0x0f);
    let a2 = a3 ^ ((a3 & rep(0x0c)) >> 2);
    let a4 = step_a(a2, a3, rep(0x0a));
    let a5 = step_b(a4, rep(0x08));
    let a4 = (a4 ^ (a5 >> 2)) & rep(0x03);
    let a4 = a4 ^ ((a4 & rep(0x02)) >> 1);
    let a4 = a4 | (a4 << 2);
    let a3 = step_a(a2, a4, rep(0x0a));
    let a3 = a3 | (a3 << 4);
    let a2 = swap2(a1);
    let x = step_a(a1, a3, rep(0xaa));
    let a4 = step_a(a2, a3, rep(0xaa));
    let a5 = (x & rep(0xcc)) >> 2;
    let x = x ^ (((a4 << 2) ^ a4) & rep(0xcc));
    let a4 = step_b(a5, rep(0x22));
    let x = x ^ a4;

    let y = ror1(x);
    let x = (x & rep(0x39)) ^ (y & rep(0x3f));
    let y = ((y & rep(0xfc)) >> 2) | ((y & rep(0x03)) << 6);
    let x = x ^ (y & rep(0x97));
    let y = ror1(y);
    let x = x ^ (y & rep(0x9b));
    let y = ror1(y);
    let x = x ^ (y & rep(0x3c));
    let y = ror1(y);
    let x = x ^ (y & rep(0xdd));
    let y = ror1(y);
    let x = x ^ (y & rep(0x72));

    x ^ rep(0x63)
}

const fn invsubbytes(x: u128) -> u128 {
    let x = x ^ rep(0x63);
    let y = ror1(x);
    let x = (x & rep(0xfd)) ^ (y & rep(0x5e));
    let y = ror1(y);
    let x = x ^ (y & rep(0xf3));
    let y = ror1(y);
    let x = x ^ (y & rep(0xf5));
    let y = ror1(y);
    let x = x ^ (y & rep(0x78));
    let y = ror1(y);
    let x = x ^ (y & rep(0x77));
    let y = ror1(y);
    let x = x ^ (y & rep(0x15));
    let y = ror1(y);
    let x = x ^ (y & rep(0xa5));

    let a1 = x ^ ((x & rep(0xf0)) >> 4);
    let a2 = swap2(x);
    let a3 = step_a(x, a1, rep(0xaa));
    let a4 = step_a(a1, a2, rep(0xaa));
    let a5 = (a3 & rep(0xcc)) >> 2;
    let a3 = a3 ^ (((a4 << 2) ^ a4) & rep(0xcc));
    let a4 = step_b(a5, rep(0x22));
    let a3 = a3 ^ a4;
    let a5 = step_b(a3, rep(0xa0));
    let a4 = a5 & rep(0xc0);
    let a6 = a4 >> 2;
    let a4 = a4 ^ ((a5 << 2) & rep(0xc0));
    let a5 = step_b(a6, rep(0x20));
    let a4 = a4 | a5;
    let a3 = (a3 ^ (a4 >> 4)) & rep(0x0f);
    let a2 = a3 ^ ((a3 & rep(0x0c)) >> 2);
    let a4 = step_a(a2, a3, rep(0x0a));
    let a5 = step_b(a4, rep(0x08));
    let a4 = (a4 ^ (a5 >> 2)) & rep(0x03);
    let a4 = a4 ^ ((a4 & rep(0x02)) >> 1);
    let a4 = a4 | (a4 << 2);
    let a3 = step_a(a2, a4, rep(0x0a));
    let a3 = a3 | (a3 << 4);
    let a2 = swap2(a1);
    let x = step_a(a1, a3, rep(0xaa));
    let a4 = step_a(a2, a3, rep(0xaa));
    let a5 = (x & rep(0xcc)) >> 2;
    let x = x ^ (((a4 << 2) ^ a4) & rep(0xcc));
    let a4 = step_b(a5, rep(0x22));
    let x = x ^ a4;

    let y = ror1(x);
    let x = (x & rep(0xb5)) ^ (y & rep(0x40));
    let y = ror1(y);
    let x = x ^ (y & rep(0x80));
    let y = ror1(y);
    let x = x ^ (y & rep(0x16));
    let y = ror1(y);
    let x = x ^ (y & rep(0xeb));
    let y = ror1(y);
    let x = x ^ (y & rep(0x97));
    let y = ror1(y);
    let x = x ^ (y & rep(0xfb));
    let y = ror1(y);

    x ^ (y & rep(0x7d))
}

const fn shiftrows(state: [u8; 16]) -> u128 {
    u128::from_ne_bytes([
        state[0], state[5], state[10], state[15], state[4], state[9], state[14], state[3],
        state[8], state[13], state[2], state[7], state[12], state[1], state[6], state[11],
    ])
}

const fn invshiftrows(state: [u8; 16]) -> u128 {
    u128::from_ne_bytes([
        state[0], state[13], state[10], state[7], state[4], state[1], state[14], state[11],
        state[8], state[5], state[2], state[15], state[12], state[9], state[6], state[3],
    ])
}

#[inline(always)]
const fn xtime(a: u128) -> u128 {
    let b = a & rep(0x80);
    let a = a ^ b;
    let b = b.wrapping_sub(b >> 7) & rep(0x1b);
    b ^ (a << 1)
}

#[inline(always)]
const fn swap16(x: u128) -> u128 {
    ((x & 0xffff_0000_ffff_0000_ffff_0000_ffff_0000) >> 16)
        | ((x & 0x0000_ffff_0000_ffff_0000_ffff_0000_ffff) << 16)
}

#[inline(always)]
const fn swap8(x: u128) -> u128 {
    ((x & 0xff00_ff00_ff00_ff00_ff00_ff00_ff00_ff00) >> 8)
        | ((x & 0x00ff_00ff_00ff_00ff_00ff_00ff_00ff_00ff) << 8)
}

#[inline(always)]
const fn ror8_32(x: u128) -> u128 {
    if cfg!(target_endian = "big") {
        ((x & 0x00ff_ffff_00ff_ffff_00ff_ffff_00ff_ffff) << 8)
            | ((x & 0xff00_0000_ff00_0000_ff00_0000_ff00_0000) >> 24)
    } else {
        ((x & 0xffff_ff00_ffff_ff00_ffff_ff00_ffff_ff00) >> 8)
            ^ ((x & 0x0000_00ff_0000_00ff_0000_00ff_0000_00ff) << 24)
    }
}

fn mixcolumns(state: u128) -> u128 {
    let s = state ^ swap16(state);
    let s = s ^ swap8(s) ^ state;
    let t = xtime(state);

    s ^ t ^ ror8_32(t)
}

fn invmixcolumns(state: u128) -> u128 {
    let s = state ^ swap16(state);
    let s = s ^ swap8(s) ^ state;

    let t = xtime(state);
    let s = s ^ t ^ ror8_32(t);
    let t = xtime(t);
    let t = t ^ swap16(t);
    let s = s ^ t;
    let t = xtime(t);

    s ^ t ^ swap8(t)
}

#[derive(Copy, Clone)]
#[repr(transparent)]
#[must_use]
pub struct AesBlock(u128);

impl BitAnd for AesBlock {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl BitOr for AesBlock {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitXor for AesBlock {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl Not for AesBlock {
    type Output = Self;

    #[inline]
    fn not(self) -> Self::Output {
        Self(!self.0)
    }
}

impl AesBlock {
    #[inline]
    pub const fn new(value: [u8; 16]) -> Self {
        Self(u128::from_ne_bytes(value))
    }

    #[inline]
    pub fn store_to(self, dst: &mut [u8]) {
        assert!(dst.len() >= 16);
        dst[..16].copy_from_slice(&self.0.to_ne_bytes());
    }

    #[inline]
    pub fn zero() -> Self {
        Self(0)
    }

    #[inline]
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Performs one round of AES encryption function (`ShiftRows`->`SubBytes`->`MixColumns`->`AddRoundKey`)
    #[inline]
    pub fn enc(self, round_key: Self) -> Self {
        Self(subbytes(shiftrows(self.0.to_ne_bytes()))).mc() ^ round_key
    }

    /// Performs one round of AES decryption function (`InvShiftRows`->`InvSubBytes`->`InvMixColumns`->`AddRoundKey`)
    #[inline]
    pub fn dec(self, round_key: Self) -> Self {
        Self(invsubbytes(invshiftrows(self.0.to_ne_bytes()))).imc() ^ round_key
    }

    /// Performs one round of AES encryption function without `MixColumns` (`ShiftRows`->`SubBytes`->`AddRoundKey`)
    #[inline]
    pub fn enc_last(self, round_key: Self) -> Self {
        Self(subbytes(shiftrows(self.0.to_ne_bytes()))) ^ round_key
    }

    /// Performs one round of AES decryption function without `InvMixColumns` (`InvShiftRows`->`InvSubBytes`->`AddRoundKey`)
    #[inline]
    pub fn dec_last(self, round_key: Self) -> Self {
        Self(invsubbytes(invshiftrows(self.0.to_ne_bytes()))) ^ round_key
    }

    /// Performs the `MixColumns` operation
    #[inline]
    pub fn mc(self) -> Self {
        Self(mixcolumns(self.0))
    }

    /// Performs the `InvMixColumns` operation
    #[inline]
    pub fn imc(self) -> Self {
        Self(invmixcolumns(self.0))
    }
}

const RCON: [u32; 10] = if cfg!(target_endian = "big") {
    [
        0x0100_0000,
        0x0200_0000,
        0x0400_0000,
        0x0800_0000,
        0x1000_0000,
        0x2000_0000,
        0x4000_0000,
        0x8000_0000,
        0x1b00_0000,
        0x3600_0000,
    ]
} else {
    [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
};

const fn ror8(a: u32) -> u32 {
    if cfg!(target_endian = "big") {
        a.rotate_left(8)
    } else {
        a.rotate_right(8)
    }
}

pub(super) fn keygen_128(key: [u8; 16]) -> [AesBlock; 11] {
    let mut expanded_keys: [AesBlock; 11] = unsafe { mem::zeroed() };
    let columns = unsafe { slice::from_raw_parts_mut(expanded_keys.as_mut_ptr().cast(), 44) };

    for (i, chunk) in key.chunks_exact(4).enumerate() {
        columns[i] = u32::from_ne_bytes(chunk.try_into().unwrap());
    }

    for i in (0..40).step_by(4) {
        columns[i + 4] = columns[i + 0] ^ ror8(sub_word(columns[i + 3])) ^ RCON[i / 4];
        columns[i + 5] = columns[i + 1] ^ columns[i + 4];
        columns[i + 6] = columns[i + 2] ^ columns[i + 5];
        columns[i + 7] = columns[i + 3] ^ columns[i + 6];
    }

    expanded_keys
}

pub(super) fn keygen_192(key: [u8; 24]) -> [AesBlock; 13] {
    let mut expanded_keys: [AesBlock; 13] = unsafe { mem::zeroed() };
    let columns = unsafe { slice::from_raw_parts_mut(expanded_keys.as_mut_ptr().cast(), 52) };

    for (i, chunk) in key.chunks_exact(4).enumerate() {
        columns[i] = u32::from_ne_bytes(chunk.try_into().unwrap());
    }

    for i in (0..42).step_by(6) {
        columns[i + 6] = columns[i + 0] ^ ror8(sub_word(columns[i + 5])) ^ RCON[i / 6];
        columns[i + 7] = columns[i + 1] ^ columns[i + 6];
        columns[i + 8] = columns[i + 2] ^ columns[i + 7];
        columns[i + 9] = columns[i + 3] ^ columns[i + 8];
        columns[i + 10] = columns[i + 4] ^ columns[i + 9];
        columns[i + 11] = columns[i + 5] ^ columns[i + 10];
    }

    columns[48] = columns[42] ^ ror8(sub_word(columns[47])) ^ RCON[7];
    columns[49] = columns[43] ^ columns[48];
    columns[50] = columns[44] ^ columns[49];
    columns[51] = columns[45] ^ columns[50];

    expanded_keys
}

pub(super) fn keygen_256(key: [u8; 32]) -> [AesBlock; 15] {
    let mut expanded_keys: [AesBlock; 15] = unsafe { mem::zeroed() };
    let columns = unsafe { slice::from_raw_parts_mut(expanded_keys.as_mut_ptr().cast(), 60) };

    for (i, chunk) in key.chunks_exact(4).enumerate() {
        columns[i] = u32::from_ne_bytes(chunk.try_into().unwrap());
    }

    for i in (0..48).step_by(8) {
        columns[i + 8] = columns[i + 0] ^ ror8(sub_word(columns[i + 7])) ^ RCON[i / 8];
        columns[i + 9] = columns[i + 1] ^ columns[i + 8];
        columns[i + 10] = columns[i + 2] ^ columns[i + 9];
        columns[i + 11] = columns[i + 3] ^ columns[i + 10];
        columns[i + 12] = columns[i + 4] ^ sub_word(columns[i + 11]);
        columns[i + 13] = columns[i + 5] ^ columns[i + 12];
        columns[i + 14] = columns[i + 6] ^ columns[i + 13];
        columns[i + 15] = columns[i + 7] ^ columns[i + 14];
    }

    columns[56] = columns[48] ^ ror8(sub_word(columns[55])) ^ RCON[6];
    columns[57] = columns[49] ^ columns[56];
    columns[58] = columns[50] ^ columns[57];
    columns[59] = columns[51] ^ columns[58];

    expanded_keys
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subbytes() {
        let x = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let r = subbytes(u128::from_ne_bytes(x)).to_ne_bytes();
        let e = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
            0xab, 0x76,
        ];
        assert_eq!(r, e);
    }

    #[test]
    fn test_invsubbytes() {
        let x = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let r = invsubbytes(u128::from_ne_bytes(x)).to_ne_bytes();
        let e = [
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3,
            0xd7, 0xfb,
        ];
        assert_eq!(r, e);
    }
}
