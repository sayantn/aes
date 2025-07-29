#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
use core::ops::{BitAnd, BitOr, BitXor, Not};

use crate::aes::AesBlock;

#[derive(Copy, Clone)]
#[repr(transparent)]
#[must_use]
pub struct AesBlockX2(pub(super) __m256i);

impl From<[u8; 32]> for AesBlockX2 {
    #[inline]
    fn from(value: [u8; 32]) -> Self {
        Self(unsafe { _mm256_loadu_si256(value.as_ptr().cast()) })
    }
}

impl From<(AesBlock, AesBlock)> for AesBlockX2 {
    #[inline]
    fn from(value: (AesBlock, AesBlock)) -> Self {
        Self(unsafe { _mm256_setr_m128i(value.0 .0, value.1 .0) })
    }
}

impl From<AesBlock> for AesBlockX2 {
    #[inline]
    fn from(value: AesBlock) -> Self {
        Self(unsafe { _mm256_broadcastsi128_si256(value.0) })
    }
}

impl From<AesBlockX2> for (AesBlock, AesBlock) {
    #[inline]
    fn from(value: AesBlockX2) -> Self {
        unsafe {
            (
                AesBlock(_mm256_extracti128_si256::<0>(value.0)),
                AesBlock(_mm256_extracti128_si256::<1>(value.0)),
            )
        }
    }
}

impl BitAnd for AesBlockX2 {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(unsafe { _mm256_and_si256(self.0, rhs.0) })
    }
}
impl BitOr for AesBlockX2 {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(unsafe { _mm256_or_si256(self.0, rhs.0) })
    }
}

impl BitXor for AesBlockX2 {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(unsafe { _mm256_xor_si256(self.0, rhs.0) })
    }
}

impl Not for AesBlockX2 {
    type Output = Self;

    #[inline]
    fn not(self) -> Self::Output {
        Self(unsafe { _mm256_xor_si256(self.0, _mm256_set1_epi64x(-1)) })
    }
}

impl AesBlockX2 {
    #[inline]
    pub const fn new(value: [u8; 32]) -> Self {
        unsafe { core::mem::transmute(value) }
    }

    #[inline]
    pub fn store_to(self, dst: &mut [u8]) {
        assert!(dst.len() >= 32);
        unsafe { _mm256_storeu_si256(dst.as_mut_ptr().cast(), self.0) };
    }

    #[inline]
    pub fn zero() -> Self {
        Self(unsafe { _mm256_setzero_si256() })
    }

    #[inline]
    #[must_use]
    pub fn is_zero(self) -> bool {
        unsafe { _mm256_testz_si256(self.0, self.0) == 1 }
    }

    /// Performs one round of AES encryption function (`ShiftRows`->`SubBytes`->`MixColumns`->`AddRoundKey`)
    #[inline]
    pub fn enc(self, round_key: Self) -> Self {
        Self(unsafe { _mm256_aesenc_epi128(self.0, round_key.0) })
    }

    /// Performs one round of AES decryption function (`InvShiftRows`->`InvSubBytes`->`InvMixColumn`s->`AddRoundKey`)
    #[inline]
    pub fn dec(self, round_key: Self) -> Self {
        Self(unsafe { _mm256_aesdec_epi128(self.0, round_key.0) })
    }

    /// Performs one round of AES encryption function without `MixColumns` (`ShiftRows`->`SubBytes`->`AddRoundKey`)
    #[inline]
    pub fn enc_last(self, round_key: Self) -> Self {
        Self(unsafe { _mm256_aesenclast_epi128(self.0, round_key.0) })
    }

    /// Performs one round of AES decryption function without `InvMixColumn`s (`InvShiftRows`->`InvSubBytes`->`AddRoundKey`)
    #[inline]
    pub fn dec_last(self, round_key: Self) -> Self {
        Self(unsafe { _mm256_aesdeclast_epi128(self.0, round_key.0) })
    }
}
