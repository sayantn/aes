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
        target_feature = "aes",
        target_endian = "little" // https://github.com/rust-lang/stdarch/issues/1484
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

use cfg_if::cfg_if;
use core::fmt::{self, Binary, Debug, Display, Formatter, LowerHex, UpperHex};
use core::ops::{BitAndAssign, BitOrAssign, BitXorAssign};

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
        target_feature = "aes",
        target_endian = "little" // https://github.com/rust-lang/stdarch/issues/1484
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

macro_rules! impl_common_ops {
    ($($name:ty, $key_len:literal),*) => {$(
    impl Default for $name {
        #[inline]
        fn default() -> Self {
            Self::zero()
        }
    }

    impl From<&[u8; $key_len]> for $name {
        #[inline]
        fn from(value: &[u8; $key_len]) -> Self {
            (*value).into()
        }
    }

    impl TryFrom<&[u8]> for $name {
        type Error = usize;

        #[inline]
        fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
            try_from_slice(value)
        }
    }

    impl From<$name> for [u8; $key_len] {
        #[inline]
        fn from(value: $name) -> Self {
            let mut dst = [0; $key_len];
            value.store_to(&mut dst);
            dst
        }
    }

    impl BitAndAssign for $name {
        #[inline]
        fn bitand_assign(&mut self, rhs: Self) {
            *self = *self & rhs;
        }
    }

    impl BitOrAssign for $name {
        #[inline]
        fn bitor_assign(&mut self, rhs: Self) {
            *self = *self | rhs;
        }
    }

    impl BitXorAssign for $name {
        #[inline]
        fn bitxor_assign(&mut self, rhs: Self) {
            *self = *self ^ rhs;
        }
    }
    )*};
}

impl_common_ops!(AesBlock, 16, AesBlockX2, 32, AesBlockX4, 64);

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

impl Debug for AesBlockX2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        <(AesBlock, AesBlock)>::from(*self).fmt(f)
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
        macro_rules! impl_pre_encdec {
            ($($name:ident),*) => {$(
                impl $name {
                    fn pre_enc(self, round_key: Self) -> Self {
                        let (a, b) = self.into();
                        let (rk_a, rk_b) = round_key.into();
                        (a.pre_enc(rk_a), b.pre_enc(rk_b)).into()
                    }

                    fn pre_dec(self, round_key: Self) -> Self {
                        let (a, b) = self.into();
                        let (rk_a, rk_b) = round_key.into();
                        (a.pre_dec(rk_a), b.pre_dec(rk_b)).into()
                    }
                }
            )*};
        }

        impl_pre_encdec!(AesBlockX2, AesBlockX4);

        macro_rules! declare_chain {
            ($($name:ty),*) => {$(
                impl $name {
                    /// Computes `(self ^ keys[0]).enc(keys[1])...enc(keys[key.len() - 1])` in the most optimized way
                    pub fn chain_enc(self, keys: &[$name]) -> $name {
                        assert_ne!(keys.len(), 0);

                        let mut acc = self;
                        for &key in &keys[..keys.len() - 1] {
                            acc = acc.pre_enc(key);
                        }
                        acc ^ keys[keys.len() - 1]
                    }

                    /// Computes `(self ^ keys[0]).dec(keys[1])...dec(keys[key.len() - 1])` in the most optimized way
                    pub fn chain_dec(self, keys: &[$name]) -> $name {
                        assert_ne!(keys.len(), 0);

                        let mut acc = self;
                        for &key in &keys[..keys.len() - 1] {
                            acc = acc.pre_dec(key);
                        }
                        acc ^ keys[keys.len() - 1]
                    }
                }
            )*};
        }
    } else {
        macro_rules! declare_chain {
            ($($name:ty),*) => {$(
                impl $name {
                    /// Computes `(self ^ keys[0]).enc(keys[1])...enc(keys[key.len() - 1])` in the most optimized way
                    pub fn chain_enc(self, keys: &[$name]) -> $name {
                        assert_ne!(keys.len(), 0);

                        let mut acc = self ^ keys[0];
                        for &key in &keys[1..] {
                            acc = acc.enc(key);
                        }
                        acc
                    }

                    /// Computes `(self ^ keys[0]).dec(keys[1])...dec(keys[key.len() - 1])` in the most optimized way
                    pub fn chain_dec(self, keys: &[$name]) -> $name {
                        assert_ne!(keys.len(), 0);

                        let mut acc = self ^ keys[0];
                        for &key in &keys[1..] {
                            acc = acc.dec(key);
                        }
                        acc
                    }
                }
            )*};
        }
    }
}

declare_chain!(AesBlock, AesBlockX2, AesBlockX4);

macro_rules! implement_aes {
    ($enc_name:ident, $dec_name:ident, $key_len:literal, $nr:literal, $keygen:ident) => {
        #[derive(Debug, Clone)]
        pub struct $enc_name {
            round_keys: [AesBlock; { $nr + 1 }],
        }

        impl private::Sealed for $enc_name {}

        impl From<[u8; $key_len]> for $enc_name {
            fn from(value: [u8; $key_len]) -> Self {
                $enc_name {
                    round_keys: $keygen(value),
                }
            }
        }

        #[derive(Debug, Clone)]
        pub struct $dec_name {
            round_keys: [AesBlock; { $nr + 1 }],
        }

        impl private::Sealed for $dec_name {}

        impl From<[u8; $key_len]> for $dec_name {
            fn from(value: [u8; $key_len]) -> Self {
                $enc_name::from(value).decrypter()
            }
        }

        impl AesEncrypt<$key_len> for $enc_name {
            type Decrypter = $dec_name;

            fn decrypter(&self) -> Self::Decrypter {
                $dec_name {
                    round_keys: dec_round_keys(&self.round_keys),
                }
            }

            fn encrypt_block(&self, plaintext: AesBlock) -> AesBlock {
                plaintext
                    .chain_enc(&self.round_keys[..$nr])
                    .enc_last(self.round_keys[$nr])
            }

            fn encrypt_2_blocks(&self, plaintext: AesBlockX2) -> AesBlockX2 {
                let round_keys = self.round_keys.map(Into::into);
                plaintext
                    .chain_enc(&round_keys[..$nr])
                    .enc_last(round_keys[$nr])
            }

            fn encrypt_4_blocks(&self, plaintext: AesBlockX4) -> AesBlockX4 {
                let round_keys = self.round_keys.map(Into::into);
                plaintext
                    .chain_enc(&round_keys[..$nr])
                    .enc_last(round_keys[$nr])
            }
        }

        impl AesDecrypt<$key_len> for $dec_name {
            type Encrypter = $enc_name;

            fn encrypter(&self) -> Self::Encrypter {
                $enc_name {
                    round_keys: enc_round_keys(&self.round_keys),
                }
            }

            fn decrypt_block(&self, ciphertext: AesBlock) -> AesBlock {
                ciphertext
                    .chain_dec(&self.round_keys[..$nr])
                    .dec_last(self.round_keys[$nr])
            }

            fn decrypt_2_blocks(&self, ciphertext: AesBlockX2) -> AesBlockX2 {
                let round_keys = self.round_keys.map(Into::into);
                ciphertext
                    .chain_dec(&round_keys[..$nr])
                    .dec_last(round_keys[$nr])
            }

            fn decrypt_4_blocks(&self, ciphertext: AesBlockX4) -> AesBlockX4 {
                let round_keys = self.round_keys.map(Into::into);
                ciphertext
                    .chain_dec(&round_keys[..$nr])
                    .dec_last(round_keys[$nr])
            }
        }
    };
}

implement_aes!(Aes128Enc, Aes128Dec, 16, 10, keygen_128);
implement_aes!(Aes192Enc, Aes192Dec, 24, 12, keygen_192);
implement_aes!(Aes256Enc, Aes256Dec, 32, 14, keygen_256);
