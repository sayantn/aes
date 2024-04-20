#[cfg(target_arch = "x86")]
use std::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

use crate::aes_x86::AesBlock;
use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not};

#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct AesBlockX2(pub(super) __m256i);

impl PartialEq for AesBlockX2 {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        (*self ^ *other).is_zero()
    }
}

impl Eq for AesBlockX2 {}

impl From<[u8; 32]> for AesBlockX2 {
    #[inline]
    fn from(value: [u8; 32]) -> Self {
        Self(unsafe { _mm256_loadu_si256(value.as_ptr().cast()) })
    }
}

impl From<(AesBlock, AesBlock)> for AesBlockX2 {
    #[inline]
    fn from((lo, hi): (AesBlock, AesBlock)) -> Self {
        Self(unsafe { _mm256_setr_m128i(lo.0, hi.0) })
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

impl BitAndAssign for AesBlockX2 {
    #[inline]
    fn bitand_assign(&mut self, rhs: Self) {
        *self = *self & rhs;
    }
}

impl BitOr for AesBlockX2 {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(unsafe { _mm256_or_si256(self.0, rhs.0) })
    }
}

impl BitOrAssign for AesBlockX2 {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
    }
}

impl BitXor for AesBlockX2 {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(unsafe { _mm256_xor_si256(self.0, rhs.0) })
    }
}

impl BitXorAssign for AesBlockX2 {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
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
    pub fn store_to(self, dst: &mut [u8]) {
        assert!(dst.len() >= 32);
        unsafe { _mm256_storeu_si256(dst.as_mut_ptr().cast(), self.0) };
    }

    #[inline]
    pub fn zero() -> Self {
        Self(unsafe { _mm256_setzero_si256() })
    }

    #[inline]
    pub fn is_zero(self) -> bool {
        unsafe { _mm256_testz_si256(self.0, self.0) == 1 }
    }

    /// Shifts the AES block by [N] bytes to the right. [N] must be non-negative
    #[inline]
    pub fn shr<const N: i32>(self) -> Self {
        assert!(N >= 0);
        // this is NOT a mistake. Intel CPUs are Little-Endian
        Self(unsafe { _mm256_bslli_epi128::<N>(self.0) })
    }

    /// Shifts the AES block by [N] bytes to the left. [N] must be non-negative
    #[inline]
    pub fn shl<const N: i32>(self) -> Self {
        assert!(N >= 0);
        // this is NOT a mistake. Intel CPUs are Little-Endian
        Self(unsafe { _mm256_bsrli_epi128::<N>(self.0) })
    }

    /// Performs one round of AES encryption function (ShiftRows->SubBytes->MixColumns->AddRoundKey)
    #[inline]
    pub fn enc(self, round_key: Self) -> Self {
        Self(unsafe { _mm256_aesenc_epi128(self.0, round_key.0) })
    }

    /// Performs one round of AES decryption function (InvShiftRows->InvSubBytes->InvMixColumns->AddRoundKey)
    #[inline]
    pub fn dec(self, round_key: Self) -> Self {
        Self(unsafe { _mm256_aesdec_epi128(self.0, round_key.0) })
    }

    /// Performs one round of AES encryption function without MixColumns (ShiftRows->SubBytes->AddRoundKey)
    #[inline]
    pub fn enc_last(self, round_key: Self) -> Self {
        Self(unsafe { _mm256_aesenclast_epi128(self.0, round_key.0) })
    }

    /// Performs one round of AES decryption function without InvMixColumns (InvShiftRows->InvSubBytes->AddRoundKey)
    #[inline]
    pub fn dec_last(self, round_key: Self) -> Self {
        Self(unsafe { _mm256_aesdeclast_epi128(self.0, round_key.0) })
    }
}
