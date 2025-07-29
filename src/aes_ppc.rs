#![allow(unused)]

#[cfg(target_arch = "powerpc")]
use core::arch::powerpc::*;
#[cfg(target_arch = "powerpc64")]
use core::arch::powerpc64::*;
use core::intrinsics::simd::*;
use core::ops::{BitAnd, BitOr, BitXor, Not};
use core::{mem, slice};

use crate::common::array_from_slice;

#[allow(improper_ctypes)]
extern "unadjusted" {
    #[link_name = "llvm.ppc.altivec.crypto.vcipher"]
    fn vcipher(a: vector_unsigned_long, b: vector_unsigned_long) -> vector_unsigned_long;
    #[link_name = "llvm.ppc.altivec.crypto.vcipherlast"]
    fn vcipherlast(a: vector_unsigned_long, b: vector_unsigned_long) -> vector_unsigned_long;
    #[link_name = "llvm.ppc.altivec.crypto.vncipher"]
    fn vncipher(a: vector_unsigned_long, b: vector_unsigned_long) -> vector_unsigned_long;
    #[link_name = "llvm.ppc.altivec.crypto.vncipherlast"]
    fn vncipherlast(a: vector_unsigned_long, b: vector_unsigned_long) -> vector_unsigned_long;
    #[link_name = "llvm.ppc.altivec.crypto.vsbox"]
    fn vsbox(a: vector_unsigned_long) -> vector_unsigned_long;
}

#[derive(Copy, Clone)]
#[repr(transparent)]
#[must_use]
pub struct AesBlock(vector_unsigned_long);

impl From<[u8; 16]> for AesBlock {
    #[inline]
    fn from(value: [u8; 16]) -> Self {
        Self::new(value)
    }
}

impl BitAnd for AesBlock {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(unsafe { simd_and(self.0, rhs.0) })
    }
}

impl BitOr for AesBlock {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(unsafe { simd_or(self.0, rhs.0) })
    }
}

impl BitXor for AesBlock {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(unsafe { simd_xor(self.0, rhs.0) })
    }
}

impl Not for AesBlock {
    type Output = Self;

    #[inline]
    fn not(self) -> Self::Output {
        self ^ [0xff; 16].into()
    }
}

impl AesBlock {
    #[inline]
    pub const fn new(value: [u8; 16]) -> Self {
        unsafe { mem::transmute(u128::from_be_bytes(value)) }
    }

    #[inline]
    pub fn store_to(self, dst: &mut [u8]) {
        assert!(dst.len() >= 16);
        unsafe {
            *dst.as_mut_ptr().cast() = mem::transmute::<_, u128>(self).to_be_bytes();
        }
    }

    #[inline]
    pub fn zero() -> Self {
        [0; 16].into()
    }

    #[inline]
    #[must_use]
    pub fn is_zero(self) -> bool {
        0_u64 == unsafe { simd_reduce_or(self.0) }
    }

    /// Performs one round of AES encryption function (`ShiftRows`->`SubBytes`->`MixColumns`->`AddRoundKey`)
    #[inline]
    pub fn enc(self, round_key: Self) -> Self {
        Self(unsafe { vcipher(self.0, round_key.0) })
    }

    /// Performs one round of AES decryption function (`InvShiftRows`->`InvSubBytes`->`InvMixColumns`->`AddRoundKey`)
    #[inline]
    pub fn dec(self, round_key: Self) -> Self {
        Self(unsafe { vncipher(self.0, Self::zero().0) }) ^ round_key
    }

    /// Performs one round of AES encryption function without `MixColumns` (`ShiftRows`->`SubBytes`->`AddRoundKey`)
    #[inline]
    pub fn enc_last(self, round_key: Self) -> Self {
        Self(unsafe { vcipherlast(self.0, round_key.0) })
    }

    /// Performs one round of AES decryption function without `InvMixColumn`s (`InvShiftRows`->`InvSubBytes`->`AddRoundKey`)
    #[inline]
    pub fn dec_last(self, round_key: Self) -> Self {
        Self(unsafe { vncipherlast(self.0, round_key.0) })
    }

    /// Performs the `MixColumns` operation
    #[inline]
    pub fn mc(self) -> Self {
        self.dec_last(Self::zero()).enc(Self::zero())
    }

    /// Performs the `InvMixColumn`s operation
    #[inline]
    pub fn imc(self) -> Self {
        self.enc_last(Self::zero()).dec(Self::zero())
    }
}

#[inline(always)]
fn sub_word(input: u32) -> u32 {
    unsafe {
        let input = mem::transmute([input; 4]);

        // AES single round encryption (with a round key of all zeros)
        let sub_input = vsbox(input);

        vec_extract::<_, 0>(mem::transmute::<_, vector_unsigned_int>(sub_input))
    }
}

const RCON: [u32; 10] = [
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
];

#[inline(always)]
const fn f(a: usize) -> usize {
    if cfg!(target_endian = "big") {
        a
    } else {
        a ^ 3
    }
}

pub(super) fn keygen_128(key: [u8; 16]) -> [AesBlock; 11] {
    let mut expanded_keys = [AesBlock::zero(); 11];

    let keys_ptr: *mut u32 = expanded_keys.as_mut_ptr().cast();
    let columns = unsafe { slice::from_raw_parts_mut(keys_ptr, 44) };

    for (i, chunk) in key.chunks_exact(4).enumerate() {
        columns[f(i)] = u32::from_be_bytes(chunk.try_into().unwrap());
    }

    for i in (0..40).step_by(4) {
        columns[f(i + 4)] =
            columns[f(i + 0)] ^ sub_word(columns[f(i + 3)]).rotate_left(8) ^ RCON[i / 4];
        columns[f(i + 5)] = columns[f(i + 1)] ^ columns[f(i + 4)];
        columns[f(i + 6)] = columns[f(i + 2)] ^ columns[f(i + 5)];
        columns[f(i + 7)] = columns[f(i + 3)] ^ columns[f(i + 6)];
    }

    expanded_keys
}

pub(super) fn keygen_192(key: [u8; 24]) -> [AesBlock; 13] {
    let mut expanded_keys = [AesBlock::zero(); 13];

    let keys_ptr: *mut u32 = expanded_keys.as_mut_ptr().cast();
    let columns = unsafe { slice::from_raw_parts_mut(keys_ptr, 52) };

    for (i, chunk) in key.chunks_exact(4).enumerate() {
        columns[f(i)] = u32::from_be_bytes(chunk.try_into().unwrap());
    }

    for i in (0..42).step_by(6) {
        columns[f(i + 6)] =
            columns[f(i + 0)] ^ sub_word(columns[f(i + 5)]).rotate_left(8) ^ RCON[i / 6];
        columns[f(i + 7)] = columns[f(i + 1)] ^ columns[f(i + 6)];
        columns[f(i + 8)] = columns[f(i + 2)] ^ columns[f(i + 7)];
        columns[f(i + 9)] = columns[f(i + 3)] ^ columns[f(i + 8)];
        columns[f(i + 10)] = columns[f(i + 4)] ^ columns[f(i + 9)];
        columns[f(i + 11)] = columns[f(i + 5)] ^ columns[f(i + 10)];
    }

    columns[f(48)] = columns[f(42)] ^ sub_word(columns[f(47)]).rotate_left(8) ^ RCON[7];
    columns[f(49)] = columns[f(43)] ^ columns[f(48)];
    columns[f(50)] = columns[f(44)] ^ columns[f(49)];
    columns[f(51)] = columns[f(45)] ^ columns[f(50)];

    expanded_keys
}

pub(super) fn keygen_256(key: [u8; 32]) -> [AesBlock; 15] {
    let mut expanded_keys = [AesBlock::zero(); 15];

    let keys_ptr: *mut u32 = expanded_keys.as_mut_ptr().cast();
    let columns = unsafe { slice::from_raw_parts_mut(keys_ptr, 60) };

    for (i, chunk) in key.chunks_exact(4).enumerate() {
        columns[f(i)] = u32::from_be_bytes(chunk.try_into().unwrap());
    }

    for i in (0..48).step_by(8) {
        columns[f(i + 8)] =
            columns[f(i + 0)] ^ sub_word(columns[f(i + 7)]).rotate_left(8) ^ RCON[i / 8];
        columns[f(i + 9)] = columns[f(i + 1)] ^ columns[f(i + 8)];
        columns[f(i + 10)] = columns[f(i + 2)] ^ columns[f(i + 9)];
        columns[f(i + 11)] = columns[f(i + 3)] ^ columns[f(i + 10)];
        columns[f(i + 12)] = columns[f(i + 4)] ^ sub_word(columns[f(i + 11)]);
        columns[f(i + 13)] = columns[f(i + 5)] ^ columns[f(i + 12)];
        columns[f(i + 14)] = columns[f(i + 6)] ^ columns[f(i + 13)];
        columns[f(i + 15)] = columns[f(i + 7)] ^ columns[f(i + 14)];
    }

    columns[f(56)] = columns[f(48)] ^ sub_word(columns[f(55)]).rotate_left(8) ^ RCON[6];
    columns[f(57)] = columns[f(49)] ^ columns[f(56)];
    columns[f(58)] = columns[f(50)] ^ columns[f(57)];
    columns[f(59)] = columns[f(51)] ^ columns[f(58)];

    expanded_keys
}
