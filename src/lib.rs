#![doc = include_str!("../README.md")]
#![no_std]
#![cfg_attr(
    all(
        feature = "nightly",
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "vaes"
    ),
    feature(stdarch_x86_avx512)
)]
#![cfg_attr(
    all(
        feature = "nightly",
        target_arch = "arm",
        target_feature = "v8",
        target_feature = "aes"
    ),
    feature(stdarch_arm_neon_intrinsics)
)]
#![cfg_attr(
    all(
        feature = "nightly",
        any(target_arch = "riscv32", target_arch = "riscv64"),
        target_feature = "zkne",
        target_feature = "zknd"
    ),
    feature(link_llvm_intrinsics, abi_unadjusted)
)]
#![allow(
    internal_features,
    clippy::identity_op,
    clippy::inline_always,
    clippy::similar_names,
    clippy::doc_markdown,
    clippy::missing_panics_doc,
    clippy::wildcard_imports
)]

use core::fmt::{self, Binary, Debug, Display, Formatter, LowerHex, UpperHex};
use core::ops::{BitAndAssign, BitOrAssign, BitXorAssign};

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "sse4.1",
        target_feature = "aes",
    ))] {
        mod aes_x86;
        pub use aes_x86::AesBlock;
        use aes_x86::*;
    } else if #[cfg(all(
        any(
            target_arch = "aarch64",
            target_arch = "arm64ec",
            all(feature = "nightly", target_arch = "arm", target_feature = "v8")
        ),
        target_feature = "aes"
    ))] {
        mod aes_arm;
        pub use aes_arm::AesBlock;
        use aes_arm::*;
    } else if #[cfg(all(
        feature = "nightly",
        target_arch = "riscv64",
        target_feature = "zkne",
        target_feature = "zknd"
    ))] {
        mod aes_riscv64;
        pub use aes_riscv64::AesBlock;
        use aes_riscv64::*;
    } else if #[cfg(all(
        feature = "nightly",
        target_arch = "riscv32",
        target_feature = "zkne",
        target_feature = "zknd"
    ))] {
        mod aes_riscv32;
        pub use aes_riscv32::AesBlock;
        use aes_riscv32::*;
    } else if #[cfg(feature = "constant-time")]{
        mod aes_bitslice;
        pub use aes_bitslice::AesBlock;
        use aes_bitslice::*;
    } else {
        mod aes_table_based;
        pub use aes_table_based::AesBlock;
        use aes_table_based::*;
    }
}

cfg_if! {
    if #[cfg(all(
        feature = "nightly",
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "vaes"
    ))] {
        mod aesni_x2;
        pub use aesni_x2::AesBlockX2;
    } else {
        mod aesdefault_x2;
        pub use aesdefault_x2::AesBlockX2;
    }
}

cfg_if! {
    if #[cfg(all(
        feature = "nightly",
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "avx512f",
        target_feature = "vaes"
    ))] {
        mod aesni_x4;
        pub use aesni_x4::AesBlockX4;
    } else {
        mod aesdefault_x4;
        pub use aesdefault_x4::AesBlockX4;
    }
}

#[cfg(test)]
mod tests;

#[inline(always)]
fn try_from_slice<const N: usize, T: From<[u8; N]>>(value: &[u8]) -> Result<T, usize> {
    if value.len() >= N {
        Ok(array_from_slice(value, 0).into())
    } else {
        Err(value.len())
    }
}

#[allow(unused)]
#[inline(always)]
const fn array_from_slice<const N: usize>(value: &[u8], offset: usize) -> [u8; N] {
    debug_assert!(value.len() - offset >= N);
    unsafe { *value.as_ptr().add(offset).cast() }
}

impl Default for AesBlock {
    #[inline]
    fn default() -> Self {
        Self::zero()
    }
}

impl From<&[u8; 16]> for AesBlock {
    #[inline]
    fn from(value: &[u8; 16]) -> Self {
        (*value).into()
    }
}

impl TryFrom<&[u8]> for AesBlock {
    type Error = usize;

    #[inline]
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        try_from_slice(value)
    }
}

impl From<AesBlock> for [u8; 16] {
    #[inline]
    fn from(value: AesBlock) -> Self {
        let mut dst = [0; 16];
        value.store_to(&mut dst);
        dst
    }
}

impl From<u128> for AesBlock {
    #[inline]
    fn from(value: u128) -> Self {
        value.to_be_bytes().into()
    }
}

impl From<AesBlock> for u128 {
    #[inline]
    fn from(value: AesBlock) -> Self {
        u128::from_be_bytes(value.into())
    }
}

impl BitAndAssign for AesBlock {
    #[inline]
    fn bitand_assign(&mut self, rhs: Self) {
        *self = *self & rhs;
    }
}

impl BitOrAssign for AesBlock {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
    }
}

impl BitXorAssign for AesBlock {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}

impl Debug for AesBlock {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl Display for AesBlock {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "{self:X}")
        } else {
            write!(f, "{self:x}")
        }
    }
}

impl Binary for AesBlock {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            f.write_str("0b")?;
        }
        for digit in <[u8; 16]>::from(*self) {
            write!(f, "{digit:>08b}")?;
        }
        Ok(())
    }
}

impl LowerHex for AesBlock {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            f.write_str("0x")?;
        }
        for x in <[u8; 16]>::from(*self) {
            write!(f, "{x:>02x}")?;
        }
        Ok(())
    }
}

impl UpperHex for AesBlock {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            f.write_str("0X")?;
        }
        for x in <[u8; 16]>::from(*self) {
            write!(f, "{x:>02X}")?;
        }
        Ok(())
    }
}

impl Default for AesBlockX2 {
    #[inline]
    fn default() -> Self {
        Self::zero()
    }
}

impl From<&[u8; 32]> for AesBlockX2 {
    #[inline]
    fn from(value: &[u8; 32]) -> Self {
        (*value).into()
    }
}

impl TryFrom<&[u8]> for AesBlockX2 {
    type Error = usize;

    #[inline]
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        try_from_slice(value)
    }
}

impl From<AesBlockX2> for [u8; 32] {
    #[inline]
    fn from(value: AesBlockX2) -> Self {
        let mut dst = [0; 32];
        value.store_to(&mut dst);
        dst
    }
}

impl BitAndAssign for AesBlockX2 {
    #[inline]
    fn bitand_assign(&mut self, rhs: Self) {
        *self = *self & rhs;
    }
}

impl BitOrAssign for AesBlockX2 {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
    }
}

impl BitXorAssign for AesBlockX2 {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}

impl Debug for AesBlockX2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        <(AesBlock, AesBlock)>::from(*self).fmt(f)
    }
}

impl Default for AesBlockX4 {
    #[inline]
    fn default() -> Self {
        Self::zero()
    }
}

impl From<&[u8; 64]> for AesBlockX4 {
    #[inline]
    fn from(value: &[u8; 64]) -> Self {
        (*value).into()
    }
}

impl TryFrom<&[u8]> for AesBlockX4 {
    type Error = usize;

    #[inline]
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        try_from_slice(value)
    }
}

impl From<AesBlockX4> for [u8; 64] {
    #[inline]
    fn from(value: AesBlockX4) -> Self {
        let mut dst = [0; 64];
        value.store_to(&mut dst);
        dst
    }
}

impl BitAndAssign for AesBlockX4 {
    #[inline]
    fn bitand_assign(&mut self, rhs: Self) {
        *self = *self & rhs;
    }
}

impl BitOrAssign for AesBlockX4 {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
    }
}

impl BitXorAssign for AesBlockX4 {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}

impl Debug for AesBlockX4 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        <(AesBlock, AesBlock, AesBlock, AesBlock)>::from(*self).fmt(f)
    }
}

mod private {
    pub trait Sealed {}
}

pub trait AesEncrypt<const KEY_LEN: usize>:
    From<[u8; KEY_LEN]> + private::Sealed + Debug + Clone
{
    type Decrypter: AesDecrypt<KEY_LEN, Encrypter = Self>;

    fn decrypter(&self) -> Self::Decrypter;

    fn encrypt_block(&self, plaintext: AesBlock) -> AesBlock;

    fn encrypt_2_blocks(&self, plaintext: AesBlockX2) -> AesBlockX2;

    fn encrypt_4_blocks(&self, plaintext: AesBlockX4) -> AesBlockX4;
}

pub trait AesDecrypt<const KEY_LEN: usize>:
    From<[u8; KEY_LEN]> + private::Sealed + Debug + Clone
{
    type Encrypter: AesEncrypt<KEY_LEN, Decrypter = Self>;

    fn encrypter(&self) -> Self::Encrypter;

    fn decrypt_block(&self, plaintext: AesBlock) -> AesBlock;

    fn decrypt_2_blocks(&self, ciphertext: AesBlockX2) -> AesBlockX2;

    fn decrypt_4_blocks(&self, ciphertext: AesBlockX4) -> AesBlockX4;
}

#[derive(Clone, Debug)]
pub struct Aes128Enc {
    round_keys: [AesBlock; 11],
}

impl private::Sealed for Aes128Enc {}

impl From<[u8; 16]> for Aes128Enc {
    fn from(value: [u8; 16]) -> Self {
        Aes128Enc {
            round_keys: keygen_128(value),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Aes128Dec {
    round_keys: [AesBlock; 11],
}

impl private::Sealed for Aes128Dec {}

impl From<[u8; 16]> for Aes128Dec {
    fn from(value: [u8; 16]) -> Self {
        Aes128Enc::from(value).decrypter()
    }
}

#[derive(Clone, Debug)]
pub struct Aes192Enc {
    round_keys: [AesBlock; 13],
}

impl private::Sealed for Aes192Enc {}

impl From<[u8; 24]> for Aes192Enc {
    fn from(value: [u8; 24]) -> Self {
        Aes192Enc {
            round_keys: keygen_192(value),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Aes192Dec {
    round_keys: [AesBlock; 13],
}

impl private::Sealed for Aes192Dec {}

impl From<[u8; 24]> for Aes192Dec {
    fn from(value: [u8; 24]) -> Self {
        Aes192Enc::from(value).decrypter()
    }
}

#[derive(Clone, Debug)]
pub struct Aes256Enc {
    round_keys: [AesBlock; 15],
}

impl private::Sealed for Aes256Enc {}

impl From<[u8; 32]> for Aes256Enc {
    fn from(value: [u8; 32]) -> Self {
        Aes256Enc {
            round_keys: keygen_256(value),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Aes256Dec {
    round_keys: [AesBlock; 15],
}

impl private::Sealed for Aes256Dec {}

impl From<[u8; 32]> for Aes256Dec {
    fn from(value: [u8; 32]) -> Self {
        Aes256Enc::from(value).decrypter()
    }
}

#[inline(always)]
fn dec_round_keys<const N: usize>(enc_round_keys: &[AesBlock; N]) -> [AesBlock; N] {
    let mut drk = [AesBlock::zero(); N];
    drk[0] = enc_round_keys[N - 1];
    for i in 1..(N - 1) {
        drk[i] = enc_round_keys[N - 1 - i].imc();
    }
    drk[N - 1] = enc_round_keys[0];
    drk
}

#[inline(always)]
fn enc_round_keys<const N: usize>(dec_round_keys: &[AesBlock; N]) -> [AesBlock; N] {
    let mut rk = [AesBlock::zero(); N];
    rk[0] = dec_round_keys[N - 1];
    for i in 1..(N - 1) {
        rk[i] = dec_round_keys[N - 1 - i].mc();
    }
    rk[N - 1] = dec_round_keys[0];
    rk
}

cfg_if! {
    if #[cfg(any(
        all(
            any(
                target_arch = "aarch64",
                target_arch = "arm64ec",
                all(feature = "nightly", target_arch = "arm", target_feature = "v8")
            ),
            target_feature = "aes",
        ), all(
                feature = "nightly",
                target_arch = "riscv32",
                target_feature = "zkne",
                target_feature = "zknd"
        )))] {
        macro_rules! aes_intr {
            ($($name:ident),*) => {$(
                impl $name {
                    #[inline(always)]
                    fn pre_enc(self, round_key:Self) -> Self {
                        let (a, b) = self.into();
                        let (rk0, rk1) = round_key.into();
                        (a.pre_enc(rk0), b.pre_enc(rk1)).into()
                    }

                    #[inline(always)]
                    fn pre_enc_last(self, round_key:Self) -> Self {
                        let (a, b) = self.into();
                        let (rk0, rk1) = round_key.into();
                        (a.pre_enc_last(rk0), b.pre_enc_last(rk1)).into()
                    }

                    #[inline(always)]
                    fn pre_dec(self, round_key:Self) -> Self {
                        let (a, b) = self.into();
                        let (rk0, rk1) = round_key.into();
                        (a.pre_dec(rk0), b.pre_dec(rk1)).into()
                    }

                    #[inline(always)]
                    fn pre_dec_last(self, round_key:Self) -> Self {
                        let (a, b) = self.into();
                        let (rk0, rk1) = round_key.into();
                        (a.pre_dec_last(rk0), b.pre_dec_last(rk1)).into()
                    }
                }
            )*};
        }

        aes_intr!(AesBlockX2, AesBlockX4);

        macro_rules! impl_aes {
            (enc: $round_keys: expr, $plaintext: expr, $max:literal) => {{
                let mut acc = $plaintext;
                for i in 0..($max - 1) {
                    acc = acc.pre_enc($round_keys[i].into());
                }
                acc.pre_enc_last($round_keys[$max - 1].into()) ^ $round_keys[$max].into()
            }};
            (dec: $round_keys: expr, $ciphertext: expr, $max:literal) => {{
                let mut acc = $ciphertext;
                for i in 0..($max - 1) {
                    acc = acc.pre_dec($round_keys[i].into());
                }
                acc.pre_dec_last($round_keys[$max - 1].into()) ^ $round_keys[$max].into()
            }};
        }
    } else {
        macro_rules! impl_aes {
            (enc: $round_keys: expr, $plaintext: expr, $max:literal) => {{
                let mut acc = $plaintext ^ $round_keys[0].into();
                for i in 1..$max {
                    acc = acc.enc($round_keys[i].into());
                }
                acc.enc_last($round_keys[$max].into())
            }};
            (dec: $round_keys: expr, $ciphertext: expr, $max:literal) => {{
                let mut acc = $ciphertext ^ $round_keys[0].into();
                for i in 1..$max {
                    acc = acc.dec($round_keys[i].into());
                }
                acc.dec_last($round_keys[$max].into())
            }};
        }
}
}

impl AesEncrypt<16> for Aes128Enc {
    type Decrypter = Aes128Dec;

    fn decrypter(&self) -> Self::Decrypter {
        Aes128Dec {
            round_keys: dec_round_keys(&self.round_keys),
        }
    }

    #[inline]
    fn encrypt_block(&self, plaintext: AesBlock) -> AesBlock {
        impl_aes!(enc: self.round_keys, plaintext, 10)
    }

    #[inline]
    fn encrypt_2_blocks(&self, plaintext: AesBlockX2) -> AesBlockX2 {
        impl_aes!(enc: self.round_keys, plaintext, 10)
    }

    #[inline]
    fn encrypt_4_blocks(&self, plaintext: AesBlockX4) -> AesBlockX4 {
        impl_aes!(enc: self.round_keys, plaintext, 10)
    }
}

impl AesDecrypt<16> for Aes128Dec {
    type Encrypter = Aes128Enc;

    fn encrypter(&self) -> Self::Encrypter {
        Aes128Enc {
            round_keys: enc_round_keys(&self.round_keys),
        }
    }

    #[inline]
    fn decrypt_block(&self, ciphertext: AesBlock) -> AesBlock {
        impl_aes!(dec: self.round_keys, ciphertext, 10)
    }

    #[inline]
    fn decrypt_2_blocks(&self, ciphertext: AesBlockX2) -> AesBlockX2 {
        impl_aes!(dec: self.round_keys, ciphertext, 10)
    }

    #[inline]
    fn decrypt_4_blocks(&self, ciphertext: AesBlockX4) -> AesBlockX4 {
        impl_aes!(dec: self.round_keys, ciphertext, 10)
    }
}

impl AesEncrypt<24> for Aes192Enc {
    type Decrypter = Aes192Dec;

    fn decrypter(&self) -> Self::Decrypter {
        Aes192Dec {
            round_keys: dec_round_keys(&self.round_keys),
        }
    }

    #[inline]
    fn encrypt_block(&self, plaintext: AesBlock) -> AesBlock {
        impl_aes!(enc: self.round_keys, plaintext, 12)
    }

    #[inline]
    fn encrypt_2_blocks(&self, plaintext: AesBlockX2) -> AesBlockX2 {
        impl_aes!(enc: self.round_keys, plaintext, 12)
    }

    #[inline]
    fn encrypt_4_blocks(&self, plaintext: AesBlockX4) -> AesBlockX4 {
        impl_aes!(enc: self.round_keys, plaintext, 12)
    }
}

impl AesDecrypt<24> for Aes192Dec {
    type Encrypter = Aes192Enc;

    fn encrypter(&self) -> Self::Encrypter {
        Aes192Enc {
            round_keys: enc_round_keys(&self.round_keys),
        }
    }

    #[inline]
    fn decrypt_block(&self, ciphertext: AesBlock) -> AesBlock {
        impl_aes!(dec: self.round_keys, ciphertext, 12)
    }

    #[inline]
    fn decrypt_2_blocks(&self, ciphertext: AesBlockX2) -> AesBlockX2 {
        impl_aes!(dec: self.round_keys, ciphertext, 12)
    }

    #[inline]
    fn decrypt_4_blocks(&self, ciphertext: AesBlockX4) -> AesBlockX4 {
        impl_aes!(dec: self.round_keys, ciphertext, 12)
    }
}

impl AesEncrypt<32> for Aes256Enc {
    type Decrypter = Aes256Dec;

    fn decrypter(&self) -> Self::Decrypter {
        Aes256Dec {
            round_keys: dec_round_keys(&self.round_keys),
        }
    }

    #[inline]
    fn encrypt_block(&self, plaintext: AesBlock) -> AesBlock {
        impl_aes!(enc: self.round_keys, plaintext, 14)
    }

    #[inline]
    fn encrypt_2_blocks(&self, plaintext: AesBlockX2) -> AesBlockX2 {
        impl_aes!(enc: self.round_keys, plaintext, 14)
    }

    #[inline]
    fn encrypt_4_blocks(&self, plaintext: AesBlockX4) -> AesBlockX4 {
        impl_aes!(enc: self.round_keys, plaintext, 14)
    }
}

impl AesDecrypt<32> for Aes256Dec {
    type Encrypter = Aes256Enc;

    fn encrypter(&self) -> Self::Encrypter {
        Aes256Enc {
            round_keys: enc_round_keys(&self.round_keys),
        }
    }

    #[inline]
    fn decrypt_block(&self, ciphertext: AesBlock) -> AesBlock {
        impl_aes!(dec: self.round_keys, ciphertext, 14)
    }

    #[inline]
    fn decrypt_2_blocks(&self, ciphertext: AesBlockX2) -> AesBlockX2 {
        impl_aes!(dec: self.round_keys, ciphertext, 14)
    }

    #[inline]
    fn decrypt_4_blocks(&self, ciphertext: AesBlockX4) -> AesBlockX4 {
        impl_aes!(dec: self.round_keys, ciphertext, 14)
    }
}
