use crate::common::array_from_slice;
use core::arch::riscv64::*;
use core::mem;
use core::ops::{BitAnd, BitOr, BitXor, Not};

#[derive(Copy, Clone)]
#[repr(C, align(16))]
#[must_use]
pub struct AesBlock(u64, u64);

impl BitAnd for AesBlock {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0, self.1 & rhs.1)
    }
}

impl BitOr for AesBlock {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0, self.1 | rhs.1)
    }
}

impl BitXor for AesBlock {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0, self.1 ^ rhs.1)
    }
}

impl Not for AesBlock {
    type Output = Self;

    #[inline]
    fn not(self) -> Self::Output {
        Self(!self.0, !self.1)
    }
}

impl AesBlock {
    #[inline]
    pub const fn new(value: [u8; 16]) -> Self {
        unsafe { mem::transmute(value) }
    }

    #[inline]
    pub const fn to_bytes(self) -> [u8; 16] {
        unsafe { mem::transmute(self) }
    }

    #[inline]
    #[must_use]
    pub fn is_zero(self) -> bool {
        (self.0 | self.1) == 0
    }

    /// Performs one round of AES encryption function (`ShiftRows`->`SubBytes`->`MixColumns`->`AddRoundKey`)
    #[inline]
    pub fn enc(self, round_key: Self) -> Self {
        unsafe {
            Self(
                aes64esm(self.0, self.1) ^ round_key.0,
                aes64esm(self.1, self.0) ^ round_key.1,
            )
        }
    }

    /// Performs one round of AES decryption function (`InvShiftRows`->`InvSubBytes`->`InvMixColumns`->`AddRoundKey`)
    #[inline]
    pub fn dec(self, round_key: Self) -> Self {
        unsafe {
            Self(
                aes64dsm(self.0, self.1) ^ round_key.0,
                aes64dsm(self.1, self.0) ^ round_key.1,
            )
        }
    }

    /// Performs one round of AES encryption function without `MixColumns` (`ShiftRows`->`SubBytes`->`AddRoundKey`)
    #[inline]
    pub fn enc_last(self, round_key: Self) -> Self {
        unsafe {
            Self(
                aes64es(self.0, self.1) ^ round_key.0,
                aes64es(self.1, self.0) ^ round_key.1,
            )
        }
    }

    /// Performs one round of AES decryption function without `InvMixColumns` (`InvShiftRows`->`InvSubBytes`->`AddRoundKey`)
    #[inline]
    pub fn dec_last(self, round_key: Self) -> Self {
        unsafe {
            Self(
                aes64ds(self.0, self.1) ^ round_key.0,
                aes64ds(self.1, self.0) ^ round_key.1,
            )
        }
    }

    /// Performs the `MixColumns` operation
    #[inline]
    pub fn mc(self) -> Self {
        unsafe {
            let (tmp0, tmp1) = (aes64ds(self.0, self.1), aes64ds(self.1, self.0));
            Self(aes64esm(tmp0, tmp1), aes64esm(tmp1, tmp0))
        }
    }

    /// Performs the `InvMixColumns` operation
    #[inline]
    pub fn imc(self) -> Self {
        unsafe { Self(aes64im(self.0), aes64im(self.1)) }
    }
}

#[inline(always)]
fn keyexp_128<const RNUM: u8>(prev: AesBlock) -> AesBlock {
    keyexp_256_1::<RNUM>(prev, prev)
}

#[inline(always)]
fn keyexp_192<const RNUM: u8>((a, b, c): (u64, u64, u64)) -> (u64, u64, u64) {
    unsafe {
        let a = aes64ks2(aes64ks1i::<RNUM>(c), a);
        let b = aes64ks2(a, b);
        (a, b, aes64ks2(b, c))
    }
}

#[inline(always)]
fn keyexp_256_1<const RNUM: u8>(prev0: AesBlock, prev1: AesBlock) -> AesBlock {
    unsafe {
        let tmp = aes64ks2(aes64ks1i(prev1.1, RNUM), prev0.0);
        AesBlock(tmp, aes64ks2(tmp, prev0.1))
    }
}

#[inline(always)]
fn keyexp_256_2(prev0: AesBlock, prev1: AesBlock) -> AesBlock {
    keyexp_256_1::<10>(prev0, prev1)
}

pub(super) fn keygen_128(key: [u8; 16]) -> [AesBlock; 11] {
    let key0 = AesBlock::from(key);
    let key1 = keyexp_128::<0>(key0);
    let key2 = keyexp_128::<1>(key1);
    let key3 = keyexp_128::<2>(key2);
    let key4 = keyexp_128::<3>(key3);
    let key5 = keyexp_128::<4>(key4);
    let key6 = keyexp_128::<5>(key5);
    let key7 = keyexp_128::<6>(key6);
    let key8 = keyexp_128::<7>(key7);
    let key9 = keyexp_128::<8>(key8);
    let key10 = keyexp_128::<9>(key9);

    [
        key0, key1, key2, key3, key4, key5, key6, key7, key8, key9, key10,
    ]
}

#[allow(clippy::cast_possible_truncation)]
pub(super) fn keygen_192(key: [u8; 24]) -> [AesBlock; 13] {
    let state0 = (
        u64::from_le_bytes(array_from_slice(&key, 0)),
        u64::from_le_bytes(array_from_slice(&key, 8)),
        u64::from_le_bytes(array_from_slice(&key, 16)),
    );

    let state1 = keyexp_192::<0>(state0);
    let state2 = keyexp_192::<1>(state1);
    let state3 = keyexp_192::<2>(state2);
    let state4 = keyexp_192::<3>(state3);
    let state5 = keyexp_192::<4>(state4);
    let state6 = keyexp_192::<5>(state5);
    let state7 = keyexp_192::<6>(state6);
    let state24 = unsafe { aes64ks2(aes64ks1i(state7.2, 7), state7.0) };
    let state25 = unsafe { aes64ks2(state24, state7.1) };

    unsafe {
        mem::transmute((
            state0, state1, state2, state3, state4, state5, state6, state7, state24, state25,
        ))
    }
}

pub(super) fn keygen_256(key: [u8; 32]) -> [AesBlock; 15] {
    let key0 = AesBlock::from(array_from_slice(&key, 0));
    let key1 = AesBlock::from(array_from_slice(&key, 16));

    let key2 = keyexp_256_1::<0>(key0, key1);
    let key3 = keyexp_256_2(key1, key2);
    let key4 = keyexp_256_1::<1>(key2, key3);
    let key5 = keyexp_256_2(key3, key4);
    let key6 = keyexp_256_1::<2>(key4, key5);
    let key7 = keyexp_256_2(key5, key6);
    let key8 = keyexp_256_1::<3>(key6, key7);
    let key9 = keyexp_256_2(key7, key8);
    let key10 = keyexp_256_1::<4>(key8, key9);
    let key11 = keyexp_256_2(key9, key10);
    let key12 = keyexp_256_1::<5>(key10, key11);
    let key13 = keyexp_256_2(key11, key12);
    let key14 = keyexp_256_1::<6>(key12, key13);

    [
        key0, key1, key2, key3, key4, key5, key6, key7, key8, key9, key10, key11, key12, key13,
        key14,
    ]
}
