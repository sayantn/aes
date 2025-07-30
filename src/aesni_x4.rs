#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
use core::ops::{BitAnd, BitOr, BitXor, Not};

use crate::{AesBlock, AesBlockX2};

#[derive(Copy, Clone)]
#[repr(transparent)]
#[must_use]
pub struct AesBlockX4(__m512i);

impl From<(AesBlock, AesBlock, AesBlock, AesBlock)> for AesBlockX4 {
    #[inline]
    #[allow(clippy::many_single_char_names)]
    fn from((a, b, c, d): (AesBlock, AesBlock, AesBlock, AesBlock)) -> Self {
        unsafe {
            let p = _mm256_inserti128_si256::<1>(_mm256_castsi128_si256(a.0), b.0);
            let q = _mm256_inserti128_si256::<1>(_mm256_castsi128_si256(c.0), d.0);

            Self(_mm512_inserti64x4::<1>(_mm512_castsi256_si512(p), q))
        }
    }
}

impl From<AesBlock> for AesBlockX4 {
    #[inline]
    fn from(value: AesBlock) -> Self {
        Self(unsafe { _mm512_broadcast_i32x4(value.0) })
    }
}

impl From<AesBlockX4> for (AesBlock, AesBlock, AesBlock, AesBlock) {
    #[inline]
    fn from(value: AesBlockX4) -> Self {
        unsafe {
            (
                AesBlock(_mm512_extracti32x4_epi32::<0>(value.0)),
                AesBlock(_mm512_extracti32x4_epi32::<1>(value.0)),
                AesBlock(_mm512_extracti32x4_epi32::<2>(value.0)),
                AesBlock(_mm512_extracti32x4_epi32::<3>(value.0)),
            )
        }
    }
}

impl From<(AesBlockX2, AesBlockX2)> for AesBlockX4 {
    #[inline]
    fn from(value: (AesBlockX2, AesBlockX2)) -> Self {
        Self(unsafe { _mm512_inserti64x4::<1>(_mm512_castsi256_si512(value.0 .0), value.1 .0) })
    }
}

impl From<AesBlockX2> for AesBlockX4 {
    #[inline]
    fn from(value: AesBlockX2) -> Self {
        Self(unsafe { _mm512_broadcast_i64x4(value.0) })
    }
}

impl From<AesBlockX4> for (AesBlockX2, AesBlockX2) {
    #[inline]
    fn from(value: AesBlockX4) -> Self {
        unsafe {
            (
                AesBlockX2(_mm512_extracti64x4_epi64::<0>(value.0)),
                AesBlockX2(_mm512_extracti64x4_epi64::<1>(value.0)),
            )
        }
    }
}

impl BitAnd for AesBlockX4 {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(unsafe { _mm512_and_si512(self.0, rhs.0) })
    }
}

impl BitOr for AesBlockX4 {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(unsafe { _mm512_or_si512(self.0, rhs.0) })
    }
}

impl BitXor for AesBlockX4 {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(unsafe { _mm512_xor_si512(self.0, rhs.0) })
    }
}

impl Not for AesBlockX4 {
    type Output = Self;

    #[inline]
    fn not(self) -> Self::Output {
        Self(unsafe { _mm512_xor_si512(self.0, _mm512_set1_epi64(-1)) })
    }
}

impl AesBlockX4 {
    #[inline]
    pub const fn new(value: [u8; 64]) -> Self {
        unsafe { core::mem::transmute(value) }
    }

    #[inline]
    pub fn store_to(self, dst: &mut [u8]) {
        assert!(dst.len() >= 64);
        unsafe { _mm512_storeu_si512(dst.as_mut_ptr().cast(), self.0) };
    }

    #[inline]
    pub fn zero() -> Self {
        Self(unsafe { _mm512_setzero_si512() })
    }

    #[inline]
    #[must_use]
    pub fn is_zero(self) -> bool {
        unsafe { _mm512_test_epi64_mask(self.0, self.0) == 0 }
    }

    /// Performs one round of AES encryption function (`ShiftRows`->`SubBytes`->`MixColumns`->`AddRoundKey`)
    #[inline]
    pub fn enc(self, round_key: Self) -> Self {
        Self(unsafe { _mm512_aesenc_epi128(self.0, round_key.0) })
    }

    /// Performs one round of AES decryption function (`InvShiftRows`->`InvSubBytes`->`InvMixColumns`->`AddRoundKey`)
    #[inline]
    pub fn dec(self, round_key: Self) -> Self {
        Self(unsafe { _mm512_aesdec_epi128(self.0, round_key.0) })
    }

    /// Performs one round of AES encryption function without `MixColumns` (`ShiftRows`->`SubBytes`->`AddRoundKey`)
    #[inline]
    pub fn enc_last(self, round_key: Self) -> Self {
        Self(unsafe { _mm512_aesenclast_epi128(self.0, round_key.0) })
    }

    /// Performs one round of AES decryption function without `InvMixColumns` (`InvShiftRows`->`InvSubBytes`->`AddRoundKey`)
    #[inline]
    pub fn dec_last(self, round_key: Self) -> Self {
        Self(unsafe { _mm512_aesdeclast_epi128(self.0, round_key.0) })
    }
}
