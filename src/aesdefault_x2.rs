use crate::AesBlock;
use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not};

#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(align(32))]
pub struct AesBlockX2(AesBlock, AesBlock);

impl From<[u8; 32]> for AesBlockX2 {
    #[inline]
    fn from(value: [u8; 32]) -> Self {
        Self(
            AesBlock::try_from(&value[..16]).unwrap(),
            AesBlock::try_from(&value[16..]).unwrap(),
        )
    }
}

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

impl BitAndAssign for AesBlockX2 {
    #[inline]
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
        self.1 &= rhs.1;
    }
}

impl BitOr for AesBlockX2 {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0, self.1 | rhs.1)
    }
}

impl BitOrAssign for AesBlockX2 {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
        self.1 |= rhs.1;
    }
}

impl BitXor for AesBlockX2 {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0, self.1 ^ rhs.1)
    }
}

impl BitXorAssign for AesBlockX2 {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
        self.1 ^= rhs.1;
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
    pub fn store_to(self, dst: &mut [u8]) {
        assert!(dst.len() >= 32);
        self.0.store_to(&mut dst[..16]);
        self.1.store_to(&mut dst[16..]);
    }

    #[inline]
    pub fn zero() -> Self {
        Self(AesBlock::zero(), AesBlock::zero())
    }

    #[inline]
    pub fn is_zero(self) -> bool {
        self.0.is_zero() & self.1.is_zero()
    }

    /// Shifts the AES blocks by `N` bytes to the right. `N` must be non-negative
    #[inline]
    pub fn shr<const N: i32>(self) -> Self {
        assert!(N >= 0);
        Self(self.0.shr::<N>(), self.1.shr::<N>())
    }

    /// Shifts the AES blocks by `N` bytes to the left. `N` must be non-negative
    #[inline]
    pub fn shl<const N: i32>(self) -> Self {
        assert!(N >= 0);
        Self(self.0.shl::<N>(), self.1.shl::<N>())
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
    #[inline(always)]
    pub(crate) fn pre_enc(self, round_key: Self) -> Self {
        Self(self.0.pre_enc(round_key.0), self.1.pre_enc(round_key.1))
    }

    /// Performs one round of AES encryption function (ShiftRows->SubBytes->MixColumns->AddRoundKey)
    #[inline]
    pub fn enc(self, round_key: Self) -> Self {
        Self(self.0.enc(round_key.0), self.1.enc(round_key.1))
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
    #[inline(always)]
    pub(crate) fn pre_dec(self, round_key: Self) -> Self {
        Self(self.0.pre_dec(round_key.0), self.1.pre_dec(round_key.1))
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
}
