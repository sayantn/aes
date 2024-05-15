use crate::{AesBlock, AesBlockX2};
use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not};

#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(C, align(32))]
pub struct AesBlockX4(AesBlockX2, AesBlockX2);

impl From<[u8; 64]> for AesBlockX4 {
    #[inline]
    fn from(value: [u8; 64]) -> Self {
        Self::new(value)
    }
}

impl From<(AesBlock, AesBlock, AesBlock, AesBlock)> for AesBlockX4 {
    #[inline]
    fn from(value: (AesBlock, AesBlock, AesBlock, AesBlock)) -> Self {
        Self((value.0, value.1).into(), (value.2, value.3).into())
    }
}

impl From<(AesBlockX2, AesBlockX2)> for AesBlockX4 {
    #[inline]
    fn from((hi, lo): (AesBlockX2, AesBlockX2)) -> Self {
        Self(hi, lo)
    }
}

impl From<AesBlock> for AesBlockX4 {
    #[inline]
    fn from(value: AesBlock) -> Self {
        Self(value.into(), value.into())
    }
}

impl From<AesBlockX2> for AesBlockX4 {
    #[inline]
    fn from(value: AesBlockX2) -> Self {
        Self(value, value)
    }
}

impl From<AesBlockX4> for (AesBlock, AesBlock, AesBlock, AesBlock) {
    #[inline]
    fn from(value: AesBlockX4) -> Self {
        let (a, b) = value.0.into();
        let (c, d) = value.1.into();
        (a, b, c, d)
    }
}

impl From<AesBlockX4> for (AesBlockX2, AesBlockX2) {
    #[inline]
    fn from(value: AesBlockX4) -> Self {
        (value.0, value.1)
    }
}

impl BitAnd for AesBlockX4 {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0, self.1 & rhs.1)
    }
}

impl BitAndAssign for AesBlockX4 {
    #[inline]
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
        self.1 &= rhs.1;
    }
}

impl BitOr for AesBlockX4 {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0, self.1 | rhs.1)
    }
}

impl BitOrAssign for AesBlockX4 {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
        self.1 |= rhs.1;
    }
}

impl BitXor for AesBlockX4 {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0, self.1 ^ rhs.1)
    }
}

impl BitXorAssign for AesBlockX4 {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
        self.1 ^= rhs.1;
    }
}

impl Not for AesBlockX4 {
    type Output = Self;

    #[inline]
    fn not(self) -> Self::Output {
        Self(!self.0, !self.1)
    }
}

impl AesBlockX4 {
    #[inline]
    pub const fn new(value: [u8; 64]) -> Self {
        Self(
            AesBlockX2::new(unsafe { *(value.as_ptr() as *const _) }),
            AesBlockX2::new(unsafe { *(value.as_ptr().add(32) as *const _) }),
        )
    }

    #[inline]
    pub fn store_to(self, dst: &mut [u8]) {
        assert!(dst.len() >= 64);
        self.0.store_to(&mut dst[..32]);
        self.1.store_to(&mut dst[32..]);
    }

    #[inline]
    pub fn zero() -> Self {
        Self(AesBlockX2::zero(), AesBlockX2::zero())
    }

    #[inline]
    pub fn is_zero(self) -> bool {
        self.0.is_zero() & self.1.is_zero()
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
    #[inline(always)]
    pub(crate) fn aese(self, round_key: Self) -> Self {
        Self(self.0.aese(round_key.0), self.1.aese(round_key.1))
    }

    /// Performs one round of AES encryption function (ShiftRows->SubBytes->MixColumns->AddRoundKey)
    #[inline]
    pub fn enc(self, round_key: Self) -> Self {
        Self(self.0.enc(round_key.0), self.1.enc(round_key.1))
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
    #[inline(always)]
    pub(crate) fn aesd(self, round_key: Self) -> Self {
        Self(self.0.aesd(round_key.0), self.1.aesd(round_key.1))
    }

    /// Performs one round of AES decryption function (InvShiftRows->InvSubBytes->InvMixColumns->AddRoundKey)
    #[inline]
    pub fn dec(self, round_key: Self) -> Self {
        Self(self.0.dec(round_key.0), self.1.dec(round_key.1))
    }

    /// Performs one round of AES encryption function without MixColumns (ShiftRows->SubBytes->AddRoundKey)
    #[inline]
    pub fn enc_last(self, round_key: Self) -> Self {
        Self(self.0.enc_last(round_key.0), self.1.enc_last(round_key.1))
    }

    /// Performs one round of AES decryption function without InvMixColumns (InvShiftRows->InvSubBytes->AddRoundKey)
    #[inline]
    pub fn dec_last(self, round_key: Self) -> Self {
        Self(self.0.dec_last(round_key.0), self.1.dec_last(round_key.1))
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
    #[inline(always)]
    pub(crate) fn mc(self) -> Self {
        Self(self.0.mc(), self.1.mc())
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
    #[inline(always)]
    pub(crate) fn imc(self) -> Self {
        Self(self.0.imc(), self.1.imc())
    }
}
