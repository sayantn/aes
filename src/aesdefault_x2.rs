use core::mem;
use core::ops::{BitAnd, BitOr, BitXor, Not};

use crate::{common::array_from_slice, AesBlock};

#[derive(Copy, Clone)]
#[repr(C, align(32))]
#[must_use]
pub struct AesBlockX2(AesBlock, AesBlock);

impl From<(AesBlock, AesBlock)> for AesBlockX2 {
    #[inline]
    fn from((hi, lo): (AesBlock, AesBlock)) -> Self {
        Self(hi, lo)
    }
}

impl From<AesBlock> for AesBlockX2 {
    #[inline]
    fn from(value: AesBlock) -> Self {
        Self(value, value)
    }
}

impl From<AesBlockX2> for (AesBlock, AesBlock) {
    #[inline]
    fn from(value: AesBlockX2) -> Self {
        (value.0, value.1)
    }
}

impl BitAnd for AesBlockX2 {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0, self.1 & rhs.1)
    }
}

impl BitOr for AesBlockX2 {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0, self.1 | rhs.1)
    }
}

impl BitXor for AesBlockX2 {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0, self.1 ^ rhs.1)
    }
}

impl Not for AesBlockX2 {
    type Output = Self;

    #[inline]
    fn not(self) -> Self::Output {
        Self(!self.0, !self.1)
    }
}

impl AesBlockX2 {
    #[inline]
    pub const fn new(value: [u8; 32]) -> Self {
        Self(
            AesBlock::new(array_from_slice(&value, 0)),
            AesBlock::new(array_from_slice(&value, 16)),
        )
    }

    #[inline]
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        unsafe { mem::transmute([self.0.to_bytes(), self.1.to_bytes()]) }
    }

    #[inline]
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.0.is_zero() & self.1.is_zero()
    }

    /// Performs one round of AES encryption function (`ShiftRows`->`SubBytes`->`MixColumns`->`AddRoundKey`)
    #[inline]
    pub fn enc(self, round_key: Self) -> Self {
        Self(self.0.enc(round_key.0), self.1.enc(round_key.1))
    }

    /// Performs one round of AES decryption function (`InvShiftRows`->`InvSubBytes`->`InvMixColumns`->`AddRoundKey`)
    #[inline]
    pub fn dec(self, round_key: Self) -> Self {
        Self(self.0.dec(round_key.0), self.1.dec(round_key.1))
    }

    /// Performs one round of AES encryption function without `MixColumns` (`ShiftRows`->`SubBytes`->`AddRoundKey`)
    #[inline]
    pub fn enc_last(self, round_key: Self) -> Self {
        Self(self.0.enc_last(round_key.0), self.1.enc_last(round_key.1))
    }

    /// Performs one round of AES decryption function without `InvMixColumns` (`InvShiftRows`->`InvSubBytes`->`AddRoundKey`)
    #[inline]
    pub fn dec_last(self, round_key: Self) -> Self {
        Self(self.0.dec_last(round_key.0), self.1.dec_last(round_key.1))
    }

    /// Performs the `MixColumns` operation
    #[inline]
    pub fn mc(self) -> Self {
        Self(self.0.mc(), self.1.mc())
    }

    /// Performs the `InvMixColumns` operation
    #[inline]
    pub fn imc(self) -> Self {
        Self(self.0.imc(), self.1.imc())
    }
}
