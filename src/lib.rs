//! This crate provides a platform-agnostic api for the [AES function](https://doi.org/10.6028/NIST.FIPS.197-upd1)
//!
//! All you have to do is compile it with correct `target_cpu` attributes, and this crate would
//! guarantee that you are getting the best possible performance, while hiding from you the ugly
//! details. For typical Rust applications, if you are not cross-compiling, you can just use
//! `target-cpu=native` in the `RUSTFLAGS` environment variable.
//!
//! # Implementations (as of date) and requirements
//!
//!  -  `AES-NI (with Vector AES for 2- and 4-blocks)` => requires a Nightly compiler (for avx512),
//!     enabling the `vaes` feature, and compiling for x86(64) with `avx512vl` and `vaes` target_features enabled.
//!
//!  -  `AES-NI (with Vector AES for 4-blocks)` => requires a Nightly compiler (for avx512),
//!     enabling the `vaes` feature, and compiling for x86(64) with `avx512f` and `vaes` target_features enabled.
//!
//!  -  `AES-NI` => requires compiling for x86(64) with `sse4.1` and `aes` target_features enabled.
//!
//!  -  `AES-AArch64` => requires compiling for AArch64 with `aes` target_feature enabled.
//!
//!  -  `Software Implementation` (Fallback, using the reference implementation of AES as provided by
//!     Rijmen and Daemen, available on [their website](https://web.archive.org/web/20050828204927/http://www.iaik.tu-graz.ac.at/research/krypto/AES/old/%7Erijmen/rijndael/) )
//!
//! It is important to remember that the target_cpu attribute sets all the available target_feature
//! attributes, so you are guaranteed to get the best performance available in your target cpu.
//!
//! No matter which implementation is selected, all the functions are guaranteed to have exactly the same signature, with
//! the exact same behaviour
//!
//! This crate also implements 2- and 4- block versions of normal AES functions, using [`AesBlockX2`]
//! and [`AesBlockX4`]. These behave exactly as if you were doing the same operation on 2 (or 4)
//! [`AesBlock`]s. These are provided to use hardware acceleration using x86(64)'s `VAES` instruction
//! set or, in the future, ARM's `SVE2-AES` instructions.

#![cfg_attr(
    all(
        feature = "vaes",
        any(target_arch = "x86", target_arch = "x86_64"),
        any(target_feature = "avx512f", target_feature = "avx512vl"),
        target_feature = "vaes"
    ),
    feature(stdarch_x86_avx512)
)]

use cfg_if::cfg_if;
use std::fmt::{Binary, Debug, Display, Formatter, LowerHex, UpperHex};

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
        target_arch = "aarch64",
        target_feature = "aes"
    ))] {
        mod aes_aarch64;
        pub use aes_aarch64::AesBlock;
        use aes_aarch64::*;
    } else {
        mod aes_default;
        pub use aes_default::AesBlock;
        use aes_default::*;
    }
}

cfg_if! {
    if #[cfg(all(
        feature = "vaes",
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "avx512vl",
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
        feature = "vaes",
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
fn slice_as_array<const N: usize>(value: &[u8]) -> Result<[u8; N], usize> {
    if value.len() >= N {
        Ok(unsafe { *(value.as_ptr() as *const _) })
    } else {
        Err(value.len())
    }
}

impl AesBlock {
    #[inline]
    pub const fn new(value: [u8; 16]) -> Self {
        unsafe { std::mem::transmute(value) }
    }
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
        slice_as_array::<16>(value).map(AesBlock::from)
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

impl Debug for AesBlock {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

impl Display for AesBlock {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            write!(f, "{self:X}")
        } else {
            write!(f, "{self:x}")
        }
    }
}

impl Binary for AesBlock {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            f.write_str("0b")?;
        }
        for digit in <[u8; 16]>::from(*self) {
            write!(f, "{:>08b}", digit)?;
        }
        Ok(())
    }
}

impl LowerHex for AesBlock {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
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
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if f.alternate() {
            f.write_str("0X")?;
        }
        for x in <[u8; 16]>::from(*self) {
            write!(f, "{x:>02X}")?;
        }
        Ok(())
    }
}

impl AesBlockX2 {
    #[inline]
    pub const fn new(value: [u8; 32]) -> Self {
        unsafe { std::mem::transmute(value) }
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
        slice_as_array::<32>(value).map(AesBlockX2::from)
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

impl Debug for AesBlockX2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        <(AesBlock, AesBlock)>::from(*self).fmt(f)
    }
}

impl AesBlockX4 {
    #[inline]
    pub const fn new(value: [u8; 64]) -> Self {
        unsafe { std::mem::transmute(value) }
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
        slice_as_array::<64>(value).map(AesBlockX4::from)
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

impl Debug for AesBlockX4 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        <(AesBlock, AesBlock, AesBlock, AesBlock)>::from(*self).fmt(f)
    }
}

mod private {
    pub trait Sealed {}
}

pub trait AesEncrypt<const KEY_LEN: usize>: From<[u8; KEY_LEN]> + private::Sealed {
    type Decrypter: AesDecrypt<KEY_LEN>;

    fn decrypter(&self) -> Self::Decrypter;

    fn encrypt_block(&self, plaintext: AesBlock) -> AesBlock;

    fn encrypt_2_blocks(&self, plaintext: AesBlockX2) -> AesBlockX2;

    fn encrypt_4_blocks(&self, plaintext: AesBlockX4) -> AesBlockX4;
}

pub trait AesDecrypt<const KEY_LEN: usize>: From<[u8; KEY_LEN]> + private::Sealed {
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
fn decryption_round_keys<const N: usize>(round_keys: &[AesBlock; N]) -> [AesBlock; N] {
    let mut drk = [AesBlock::zero(); N];
    drk[0] = round_keys[N - 1];
    for i in 1..(N - 1) {
        drk[i] = round_keys[N - 1 - i].imc();
    }
    drk[N - 1] = round_keys[0];
    drk
}

cfg_if! {
if #[cfg(all(
    target_arch = "aarch64",
    target_feature = "aes"
))] {
    macro_rules! impl_aes {
        (enc: $round_keys: expr, $plaintext: expr, $max:literal) => {{
            let mut acc = $plaintext;
            for i in 0..($max - 1) {
                acc = acc.aese($round_keys[i].into()).mc();
            }
            acc.aese($round_keys[$max - 1].into()) ^ $round_keys[$max].into()
        }};
        (dec: $round_keys: expr, $ciphertext: expr, $max:literal) => {{
            let mut acc = $ciphertext;
            for i in 0..($max - 1) {
                acc = acc.aesd($round_keys[i].into()).imc();
            }
            acc.aesd($round_keys[$max - 1].into()) ^ $round_keys[$max].into()
        }};
    }
}else{
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
            round_keys: decryption_round_keys(&self.round_keys),
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
            round_keys: decryption_round_keys(&self.round_keys),
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
            round_keys: decryption_round_keys(&self.round_keys),
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
