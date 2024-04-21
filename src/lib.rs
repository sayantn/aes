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
use std::array::TryFromSliceError;
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

#[inline(never)]
pub fn z(value: (AesBlock, AesBlock)) -> AesBlockX2 {
    AesBlockX2::from(value).enc(value.0.into())
}

impl Default for AesBlock {
    fn default() -> Self {
        Self::zero()
    }
}

impl TryFrom<&[u8]> for AesBlock {
    type Error = TryFromSliceError;

    #[inline]
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        <[u8; 16]>::try_from(value).map(AesBlock::from)
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

impl TryFrom<&[u8]> for AesBlockX2 {
    type Error = TryFromSliceError;

    #[inline]
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        <[u8; 32]>::try_from(value).map(Self::from)
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
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        <(AesBlock, AesBlock)>::from(*self).fmt(f)
    }
}

impl TryFrom<&[u8]> for AesBlockX4 {
    type Error = TryFromSliceError;

    #[inline]
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        <[u8; 64]>::try_from(value).map(Self::from)
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

#[derive(Clone, Debug)]
pub struct Aes128Enc {
    round_keys: [AesBlock; 11],
}

#[derive(Clone, Debug)]
pub struct Aes128Dec {
    round_keys: [AesBlock; 11],
}

impl From<[u8; 16]> for Aes128Enc {
    fn from(value: [u8; 16]) -> Self {
        Aes128Enc {
            round_keys: keygen_128(value),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Aes192Enc {
    round_keys: [AesBlock; 13],
}

#[derive(Clone, Debug)]
pub struct Aes192Dec {
    round_keys: [AesBlock; 13],
}

impl From<[u8; 24]> for Aes192Enc {
    fn from(value: [u8; 24]) -> Self {
        Aes192Enc {
            round_keys: keygen_192(value),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Aes256Enc {
    round_keys: [AesBlock; 15],
}

#[derive(Clone, Debug)]
pub struct Aes256Dec {
    round_keys: [AesBlock; 15],
}

impl From<[u8; 32]> for Aes256Enc {
    fn from(value: [u8; 32]) -> Self {
        Aes256Enc {
            round_keys: keygen_256(value),
        }
    }
}

impl Aes128Enc {
    pub fn decrypter(&self) -> Aes128Dec {
        Aes128Dec {
            round_keys: [
                self.round_keys[10],
                self.round_keys[9].imc(),
                self.round_keys[8].imc(),
                self.round_keys[7].imc(),
                self.round_keys[6].imc(),
                self.round_keys[5].imc(),
                self.round_keys[4].imc(),
                self.round_keys[3].imc(),
                self.round_keys[2].imc(),
                self.round_keys[1].imc(),
                self.round_keys[0],
            ],
        }
    }
}

impl Aes192Enc {
    pub fn decrypter(&self) -> Aes192Dec {
        Aes192Dec {
            round_keys: [
                self.round_keys[12],
                self.round_keys[11].imc(),
                self.round_keys[10].imc(),
                self.round_keys[9].imc(),
                self.round_keys[8].imc(),
                self.round_keys[7].imc(),
                self.round_keys[6].imc(),
                self.round_keys[5].imc(),
                self.round_keys[4].imc(),
                self.round_keys[3].imc(),
                self.round_keys[2].imc(),
                self.round_keys[1].imc(),
                self.round_keys[0],
            ],
        }
    }
}

impl Aes256Enc {
    pub fn decrypter(&self) -> Aes256Dec {
        Aes256Dec {
            round_keys: [
                self.round_keys[14],
                self.round_keys[13].imc(),
                self.round_keys[12].imc(),
                self.round_keys[11].imc(),
                self.round_keys[10].imc(),
                self.round_keys[9].imc(),
                self.round_keys[8].imc(),
                self.round_keys[7].imc(),
                self.round_keys[6].imc(),
                self.round_keys[5].imc(),
                self.round_keys[4].imc(),
                self.round_keys[3].imc(),
                self.round_keys[2].imc(),
                self.round_keys[1].imc(),
                self.round_keys[0],
            ],
        }
    }
}

cfg_if! {
    if #[cfg(all(
        target_arch = "aarch64",
        target_feature = "aes"
    ))] {
        impl Aes128Enc {
            #[inline]
            pub fn encrypt_2_blocks(&self, plaintext: AesBlockX2) -> AesBlockX2 {
                let (a, b) = plaintext.into();
                (self.encrypt_block(a), self.encrypt_block(b)).into()
            }

            #[inline]
            pub fn encrypt_4_blocks(&self, plaintext: AesBlockX4) -> AesBlockX4 {
                let (a, b) = plaintext.into();
                (self.encrypt_2_blocks(a), self.encrypt_2_blocks(b)).into()
            }
        }

        impl Aes128Dec {
            #[inline]
            pub fn decrypt_2_blocks(&self, ciphertext: AesBlockX2) -> AesBlockX2 {
                let (a, b) = ciphertext.into();
                (self.decrypt_block(a), self.decrypt_block(b)).into()
            }

            #[inline]
            pub fn decrypt_4_blocks(&self, ciphertext: AesBlockX4) -> AesBlockX4 {
                let (a, b) = ciphertext.into();
                (self.decrypt_2_blocks(a), self.decrypt_2_blocks(b)).into()
            }
        }


        impl Aes192Enc {
            #[inline]
            pub fn encrypt_2_blocks(&self, plaintext: AesBlockX2) -> AesBlockX2 {
                let (a, b) = plaintext.into();
                (self.encrypt_block(a), self.encrypt_block(b)).into()
            }

            #[inline]
            pub fn encrypt_4_blocks(&self, plaintext: AesBlockX4) -> AesBlockX4 {
                let (a, b) = plaintext.into();
                (self.encrypt_2_blocks(a), self.encrypt_2_blocks(b)).into()
            }
        }

        impl Aes192Dec {
            #[inline]
            pub fn decrypt_2_blocks(&self, ciphertext: AesBlockX2) -> AesBlockX2 {
                let (a, b) = ciphertext.into();
                (self.decrypt_block(a), self.decrypt_block(b)).into()
            }

            #[inline]
            pub fn decrypt_4_blocks(&self, ciphertext: AesBlockX4) -> AesBlockX4 {
                let (a, b) = ciphertext.into();
                (self.decrypt_2_blocks(a), self.decrypt_2_blocks(b)).into()
            }
        }


        impl Aes256Enc {
            #[inline]
            pub fn encrypt_2_blocks(&self, plaintext: AesBlockX2) -> AesBlockX2 {
                let (a, b) = plaintext.into();
                (self.encrypt_block(a), self.encrypt_block(b)).into()
            }

            #[inline]
            pub fn encrypt_4_blocks(&self, plaintext: AesBlockX4) -> AesBlockX4 {
                let (a, b) = plaintext.into();
                (self.encrypt_2_blocks(a), self.encrypt_2_blocks(b)).into()
            }
        }

        impl Aes256Dec {
            #[inline]
            pub fn decrypt_2_blocks(&self, ciphertext: AesBlockX2) -> AesBlockX2 {
                let (a, b) = ciphertext.into();
                (self.decrypt_block(a), self.decrypt_block(b)).into()
            }

            #[inline]
            pub fn decrypt_4_blocks(&self, ciphertext: AesBlockX4) -> AesBlockX4 {
                let (a, b) = ciphertext.into();
                (self.decrypt_2_blocks(a), self.decrypt_2_blocks(b)).into()
            }
        }
    }else{
        impl Aes128Enc {
            #[inline]
            pub fn encrypt_block(&self, plaintext: AesBlock) -> AesBlock {
                let acc = plaintext ^ self.round_keys[0];
                let acc = acc.enc(self.round_keys[1]);
                let acc = acc.enc(self.round_keys[2]);
                let acc = acc.enc(self.round_keys[3]);
                let acc = acc.enc(self.round_keys[4]);
                let acc = acc.enc(self.round_keys[5]);
                let acc = acc.enc(self.round_keys[6]);
                let acc = acc.enc(self.round_keys[7]);
                let acc = acc.enc(self.round_keys[8]);
                let acc = acc.enc(self.round_keys[9]);
                acc.enc_last(self.round_keys[10])
            }

            #[inline]
            pub fn encrypt_2_blocks(&self, plaintext: AesBlockX2) -> AesBlockX2 {
                let acc = plaintext ^ self.round_keys[0].into();
                let acc = acc.enc(self.round_keys[1].into());
                let acc = acc.enc(self.round_keys[2].into());
                let acc = acc.enc(self.round_keys[3].into());
                let acc = acc.enc(self.round_keys[4].into());
                let acc = acc.enc(self.round_keys[5].into());
                let acc = acc.enc(self.round_keys[6].into());
                let acc = acc.enc(self.round_keys[7].into());
                let acc = acc.enc(self.round_keys[8].into());
                let acc = acc.enc(self.round_keys[9].into());
                acc.enc_last(self.round_keys[10].into())
            }

            #[inline]
            pub fn encrypt_4_blocks(&self, plaintext: AesBlockX4) -> AesBlockX4 {
                let acc = plaintext ^ self.round_keys[0].into();
                let acc = acc.enc(self.round_keys[1].into());
                let acc = acc.enc(self.round_keys[2].into());
                let acc = acc.enc(self.round_keys[3].into());
                let acc = acc.enc(self.round_keys[4].into());
                let acc = acc.enc(self.round_keys[5].into());
                let acc = acc.enc(self.round_keys[6].into());
                let acc = acc.enc(self.round_keys[7].into());
                let acc = acc.enc(self.round_keys[8].into());
                let acc = acc.enc(self.round_keys[9].into());
                acc.enc_last(self.round_keys[10].into())
            }
        }

        impl Aes128Dec {
            #[inline]
            pub fn decrypt_block(&self, ciphertext: AesBlock) -> AesBlock {
                let acc = ciphertext ^ self.round_keys[0];
                let acc = acc.dec(self.round_keys[1]);
                let acc = acc.dec(self.round_keys[2]);
                let acc = acc.dec(self.round_keys[3]);
                let acc = acc.dec(self.round_keys[4]);
                let acc = acc.dec(self.round_keys[5]);
                let acc = acc.dec(self.round_keys[6]);
                let acc = acc.dec(self.round_keys[7]);
                let acc = acc.dec(self.round_keys[8]);
                let acc = acc.dec(self.round_keys[9]);
                acc.dec_last(self.round_keys[10])
            }

            #[inline]
            pub fn decrypt_2_blocks(&self, ciphertext: AesBlockX2) -> AesBlockX2 {
                let acc = ciphertext ^ self.round_keys[0].into();
                let acc = acc.dec(self.round_keys[1].into());
                let acc = acc.dec(self.round_keys[2].into());
                let acc = acc.dec(self.round_keys[3].into());
                let acc = acc.dec(self.round_keys[4].into());
                let acc = acc.dec(self.round_keys[5].into());
                let acc = acc.dec(self.round_keys[6].into());
                let acc = acc.dec(self.round_keys[7].into());
                let acc = acc.dec(self.round_keys[8].into());
                let acc = acc.dec(self.round_keys[9].into());
                acc.dec_last(self.round_keys[10].into())
            }

            #[inline]
            pub fn decrypt_4_blocks(&self, ciphertext: AesBlockX4) -> AesBlockX4 {
                let acc = ciphertext ^ self.round_keys[0].into();
                let acc = acc.dec(self.round_keys[1].into());
                let acc = acc.dec(self.round_keys[2].into());
                let acc = acc.dec(self.round_keys[3].into());
                let acc = acc.dec(self.round_keys[4].into());
                let acc = acc.dec(self.round_keys[5].into());
                let acc = acc.dec(self.round_keys[6].into());
                let acc = acc.dec(self.round_keys[7].into());
                let acc = acc.dec(self.round_keys[8].into());
                let acc = acc.dec(self.round_keys[9].into());
                acc.dec_last(self.round_keys[10].into())
            }
        }

        impl Aes192Enc {
            #[inline]
            pub fn encrypt_block(&self, plaintext: AesBlock) -> AesBlock {
                let acc = plaintext ^ self.round_keys[0];
                let acc = acc.enc(self.round_keys[1]);
                let acc = acc.enc(self.round_keys[2]);
                let acc = acc.enc(self.round_keys[3]);
                let acc = acc.enc(self.round_keys[4]);
                let acc = acc.enc(self.round_keys[5]);
                let acc = acc.enc(self.round_keys[6]);
                let acc = acc.enc(self.round_keys[7]);
                let acc = acc.enc(self.round_keys[8]);
                let acc = acc.enc(self.round_keys[9]);
                let acc = acc.enc(self.round_keys[10]);
                let acc = acc.enc(self.round_keys[11]);
                acc.enc_last(self.round_keys[12])
            }

            #[inline]
            pub fn encrypt_2_blocks(&self, plaintext: AesBlockX2) -> AesBlockX2 {
                let acc = plaintext ^ self.round_keys[0].into();
                let acc = acc.enc(self.round_keys[1].into());
                let acc = acc.enc(self.round_keys[2].into());
                let acc = acc.enc(self.round_keys[3].into());
                let acc = acc.enc(self.round_keys[4].into());
                let acc = acc.enc(self.round_keys[5].into());
                let acc = acc.enc(self.round_keys[6].into());
                let acc = acc.enc(self.round_keys[7].into());
                let acc = acc.enc(self.round_keys[8].into());
                let acc = acc.enc(self.round_keys[9].into());
                let acc = acc.enc(self.round_keys[10].into());
                let acc = acc.enc(self.round_keys[11].into());
                acc.enc_last(self.round_keys[12].into())
            }

            #[inline]
            pub fn encrypt_4_blocks(&self, plaintext: AesBlockX4) -> AesBlockX4 {
                let acc = plaintext ^ self.round_keys[0].into();
                let acc = acc.enc(self.round_keys[1].into());
                let acc = acc.enc(self.round_keys[2].into());
                let acc = acc.enc(self.round_keys[3].into());
                let acc = acc.enc(self.round_keys[4].into());
                let acc = acc.enc(self.round_keys[5].into());
                let acc = acc.enc(self.round_keys[6].into());
                let acc = acc.enc(self.round_keys[7].into());
                let acc = acc.enc(self.round_keys[8].into());
                let acc = acc.enc(self.round_keys[9].into());
                let acc = acc.enc(self.round_keys[10].into());
                let acc = acc.enc(self.round_keys[11].into());
                acc.enc_last(self.round_keys[12].into())
            }
        }

        impl Aes192Dec {
            #[inline]
            pub fn decrypt_block(&self, ciphertext: AesBlock) -> AesBlock {
                let acc = ciphertext ^ self.round_keys[0];
                let acc = acc.dec(self.round_keys[1]);
                let acc = acc.dec(self.round_keys[2]);
                let acc = acc.dec(self.round_keys[3]);
                let acc = acc.dec(self.round_keys[4]);
                let acc = acc.dec(self.round_keys[5]);
                let acc = acc.dec(self.round_keys[6]);
                let acc = acc.dec(self.round_keys[7]);
                let acc = acc.dec(self.round_keys[8]);
                let acc = acc.dec(self.round_keys[9]);
                let acc = acc.dec(self.round_keys[10]);
                let acc = acc.dec(self.round_keys[11]);
                acc.dec_last(self.round_keys[12])
            }

            #[inline]
            pub fn decrypt_2_blocks(&self, ciphertext: AesBlockX2) -> AesBlockX2 {
                let acc = ciphertext ^ self.round_keys[0].into();
                let acc = acc.dec(self.round_keys[1].into());
                let acc = acc.dec(self.round_keys[2].into());
                let acc = acc.dec(self.round_keys[3].into());
                let acc = acc.dec(self.round_keys[4].into());
                let acc = acc.dec(self.round_keys[5].into());
                let acc = acc.dec(self.round_keys[6].into());
                let acc = acc.dec(self.round_keys[7].into());
                let acc = acc.dec(self.round_keys[8].into());
                let acc = acc.dec(self.round_keys[9].into());
                let acc = acc.dec(self.round_keys[10].into());
                let acc = acc.dec(self.round_keys[11].into());
                acc.dec_last(self.round_keys[12].into())
            }

            #[inline]
            pub fn decrypt_4_blocks(&self, ciphertext: AesBlockX4) -> AesBlockX4 {
                let acc = ciphertext ^ self.round_keys[0].into();
                let acc = acc.dec(self.round_keys[1].into());
                let acc = acc.dec(self.round_keys[2].into());
                let acc = acc.dec(self.round_keys[3].into());
                let acc = acc.dec(self.round_keys[4].into());
                let acc = acc.dec(self.round_keys[5].into());
                let acc = acc.dec(self.round_keys[6].into());
                let acc = acc.dec(self.round_keys[7].into());
                let acc = acc.dec(self.round_keys[8].into());
                let acc = acc.dec(self.round_keys[9].into());
                let acc = acc.dec(self.round_keys[10].into());
                let acc = acc.dec(self.round_keys[11].into());
                acc.dec_last(self.round_keys[12].into())
            }
        }

        impl Aes256Enc {
            #[inline]
            pub fn encrypt_block(&self, plaintext: AesBlock) -> AesBlock {
                let acc = plaintext ^ self.round_keys[0];
                let acc = acc.enc(self.round_keys[1]);
                let acc = acc.enc(self.round_keys[2]);
                let acc = acc.enc(self.round_keys[3]);
                let acc = acc.enc(self.round_keys[4]);
                let acc = acc.enc(self.round_keys[5]);
                let acc = acc.enc(self.round_keys[6]);
                let acc = acc.enc(self.round_keys[7]);
                let acc = acc.enc(self.round_keys[8]);
                let acc = acc.enc(self.round_keys[9]);
                let acc = acc.enc(self.round_keys[10]);
                let acc = acc.enc(self.round_keys[11]);
                let acc = acc.enc(self.round_keys[12]);
                let acc = acc.enc(self.round_keys[13]);
                acc.enc_last(self.round_keys[14])
            }

            #[inline]
            pub fn encrypt_2_blocks(&self, plaintext: AesBlockX2) -> AesBlockX2 {
                let acc = plaintext ^ self.round_keys[0].into();
                let acc = acc.enc(self.round_keys[1].into());
                let acc = acc.enc(self.round_keys[2].into());
                let acc = acc.enc(self.round_keys[3].into());
                let acc = acc.enc(self.round_keys[4].into());
                let acc = acc.enc(self.round_keys[5].into());
                let acc = acc.enc(self.round_keys[6].into());
                let acc = acc.enc(self.round_keys[7].into());
                let acc = acc.enc(self.round_keys[8].into());
                let acc = acc.enc(self.round_keys[9].into());
                let acc = acc.enc(self.round_keys[10].into());
                let acc = acc.enc(self.round_keys[11].into());
                let acc = acc.enc(self.round_keys[12].into());
                let acc = acc.enc(self.round_keys[13].into());
                acc.enc_last(self.round_keys[14].into())
            }

            #[inline]
            pub fn encrypt_4_blocks(&self, plaintext: AesBlockX4) -> AesBlockX4 {
                let acc = plaintext ^ self.round_keys[0].into();
                let acc = acc.enc(self.round_keys[1].into());
                let acc = acc.enc(self.round_keys[2].into());
                let acc = acc.enc(self.round_keys[3].into());
                let acc = acc.enc(self.round_keys[4].into());
                let acc = acc.enc(self.round_keys[5].into());
                let acc = acc.enc(self.round_keys[6].into());
                let acc = acc.enc(self.round_keys[7].into());
                let acc = acc.enc(self.round_keys[8].into());
                let acc = acc.enc(self.round_keys[9].into());
                let acc = acc.enc(self.round_keys[10].into());
                let acc = acc.enc(self.round_keys[11].into());
                let acc = acc.enc(self.round_keys[12].into());
                let acc = acc.enc(self.round_keys[13].into());
                acc.enc_last(self.round_keys[14].into())
            }
        }

        impl Aes256Dec {
            #[inline]
            pub fn decrypt_block(&self, ciphertext: AesBlock) -> AesBlock {
                let acc = ciphertext ^ self.round_keys[0];
                let acc = acc.dec(self.round_keys[1]);
                let acc = acc.dec(self.round_keys[2]);
                let acc = acc.dec(self.round_keys[3]);
                let acc = acc.dec(self.round_keys[4]);
                let acc = acc.dec(self.round_keys[5]);
                let acc = acc.dec(self.round_keys[6]);
                let acc = acc.dec(self.round_keys[7]);
                let acc = acc.dec(self.round_keys[8]);
                let acc = acc.dec(self.round_keys[9]);
                let acc = acc.dec(self.round_keys[10]);
                let acc = acc.dec(self.round_keys[11]);
                let acc = acc.dec(self.round_keys[12]);
                let acc = acc.dec(self.round_keys[13]);
                acc.dec_last(self.round_keys[14])
            }

            #[inline]
            pub fn decrypt_2_blocks(&self, ciphertext: AesBlockX2) -> AesBlockX2 {
                let acc = ciphertext ^ self.round_keys[0].into();
                let acc = acc.dec(self.round_keys[1].into());
                let acc = acc.dec(self.round_keys[2].into());
                let acc = acc.dec(self.round_keys[3].into());
                let acc = acc.dec(self.round_keys[4].into());
                let acc = acc.dec(self.round_keys[5].into());
                let acc = acc.dec(self.round_keys[6].into());
                let acc = acc.dec(self.round_keys[7].into());
                let acc = acc.dec(self.round_keys[8].into());
                let acc = acc.dec(self.round_keys[9].into());
                let acc = acc.dec(self.round_keys[10].into());
                let acc = acc.dec(self.round_keys[11].into());
                let acc = acc.dec(self.round_keys[12].into());
                let acc = acc.dec(self.round_keys[13].into());
                acc.dec_last(self.round_keys[14].into())
            }

            #[inline]
            pub fn decrypt_4_blocks(&self, ciphertext: AesBlockX4) -> AesBlockX4 {
                let acc = ciphertext ^ self.round_keys[0].into();
                let acc = acc.dec(self.round_keys[1].into());
                let acc = acc.dec(self.round_keys[2].into());
                let acc = acc.dec(self.round_keys[3].into());
                let acc = acc.dec(self.round_keys[4].into());
                let acc = acc.dec(self.round_keys[5].into());
                let acc = acc.dec(self.round_keys[6].into());
                let acc = acc.dec(self.round_keys[7].into());
                let acc = acc.dec(self.round_keys[8].into());
                let acc = acc.dec(self.round_keys[9].into());
                let acc = acc.dec(self.round_keys[10].into());
                let acc = acc.dec(self.round_keys[11].into());
                let acc = acc.dec(self.round_keys[12].into());
                let acc = acc.dec(self.round_keys[13].into());
                acc.dec_last(self.round_keys[14].into())
            }
        }
    }
}

/// Testing AES with the official NIST test vectors
#[cfg(test)]
mod tests {
    use crate::*;
    use hex::FromHex;
    use lazy_static::lazy_static;
    use pretty_assertions::assert_eq;

    #[test]
    fn expansion_of_128_bit_key() {
        let key = <[u8; 16]>::from_hex("2b7e151628aed2a6abf7158809cf4f3c").unwrap();

        let expanded = keygen_128(key);
        assert_eq!(expanded[0], 0x2b7e151628aed2a6abf7158809cf4f3c_u128.into());
        assert_eq!(expanded[1], 0xa0fafe1788542cb123a339392a6c7605_u128.into());
        assert_eq!(expanded[2], 0xf2c295f27a96b9435935807a7359f67f_u128.into());
        assert_eq!(expanded[3], 0x3d80477d4716fe3e1e237e446d7a883b_u128.into());
        assert_eq!(expanded[4], 0xef44a541a8525b7fb671253bdb0bad00_u128.into());
        assert_eq!(expanded[5], 0xd4d1c6f87c839d87caf2b8bc11f915bc_u128.into());
        assert_eq!(expanded[6], 0x6d88a37a110b3efddbf98641ca0093fd_u128.into());
        assert_eq!(expanded[7], 0x4e54f70e5f5fc9f384a64fb24ea6dc4f_u128.into());
        assert_eq!(expanded[8], 0xead27321b58dbad2312bf5607f8d292f_u128.into());
        assert_eq!(expanded[9], 0xac7766f319fadc2128d12941575c006e_u128.into());
        assert_eq!(expanded[10], 0xd014f9a8c9ee2589e13f0cc8b6630ca6_u128.into());
    }

    #[test]
    fn expansion_of_192_bit_key() {
        let key = <[u8; 24]>::from_hex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b").unwrap();

        let expanded = keygen_192(key);
        assert_eq!(expanded[0], 0x8e73b0f7da0e6452c810f32b809079e5_u128.into());
        assert_eq!(expanded[1], 0x62f8ead2522c6b7bfe0c91f72402f5a5_u128.into());
        assert_eq!(expanded[2], 0xec12068e6c827f6b0e7a95b95c56fec2_u128.into());
        assert_eq!(expanded[3], 0x4db7b4bd69b5411885a74796e92538fd_u128.into());
        assert_eq!(expanded[4], 0xe75fad44bb095386485af05721efb14f_u128.into());
        assert_eq!(expanded[5], 0xa448f6d94d6dce24aa326360113b30e6_u128.into());
        assert_eq!(expanded[6], 0xa25e7ed583b1cf9a27f939436a94f767_u128.into());
        assert_eq!(expanded[7], 0xc0a69407d19da4e1ec1786eb6fa64971_u128.into());
        assert_eq!(expanded[8], 0x485f703222cb8755e26d135233f0b7b3_u128.into());
        assert_eq!(expanded[9], 0x40beeb282f18a2596747d26b458c553e_u128.into());
        assert_eq!(expanded[10], 0xa7e1466c9411f1df821f750aad07d753_u128.into());
        assert_eq!(expanded[11], 0xca4005388fcc5006282d166abc3ce7b5_u128.into());
        assert_eq!(expanded[12], 0xe98ba06f448c773c8ecc720401002202_u128.into());
    }

    #[test]
    fn expansion_of_256_bit_key() {
        let key = <[u8; 32]>::from_hex(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        )
        .unwrap();

        let expanded = keygen_256(key);
        assert_eq!(expanded[0], 0x603deb1015ca71be2b73aef0857d7781_u128.into());
        assert_eq!(expanded[1], 0x1f352c073b6108d72d9810a30914dff4_u128.into());
        assert_eq!(expanded[2], 0x9ba354118e6925afa51a8b5f2067fcde_u128.into());
        assert_eq!(expanded[3], 0xa8b09c1a93d194cdbe49846eb75d5b9a_u128.into());
        assert_eq!(expanded[4], 0xd59aecb85bf3c917fee94248de8ebe96_u128.into());
        assert_eq!(expanded[5], 0xb5a9328a2678a647983122292f6c79b3_u128.into());
        assert_eq!(expanded[6], 0x812c81addadf48ba24360af2fab8b464_u128.into());
        assert_eq!(expanded[7], 0x98c5bfc9bebd198e268c3ba709e04214_u128.into());
        assert_eq!(expanded[8], 0x68007bacb2df331696e939e46c518d80_u128.into());
        assert_eq!(expanded[9], 0xc814e20476a9fb8a5025c02d59c58239_u128.into());
        assert_eq!(expanded[10], 0xde1369676ccc5a71fa2563959674ee15_u128.into());
        assert_eq!(expanded[11], 0x5886ca5d2e2f31d77e0af1fa27cf73c3_u128.into());
        assert_eq!(expanded[12], 0x749c47ab18501ddae2757e4f7401905a_u128.into());
        assert_eq!(expanded[13], 0xcafaaae3e4d59b349adf6acebd10190d_u128.into());
        assert_eq!(expanded[14], 0xfe4890d1e6188d0b046df344706c631e_u128.into());
    }

    macro_rules! aes_test {
        (enc: $enc:ident, $vectors:ident) => {
            assert_eq!($enc.encrypt_block($vectors[0].0), $vectors[0].1);
            assert_eq!($enc.encrypt_block($vectors[1].0), $vectors[1].1);

            assert_eq!(
                $enc.encrypt_2_blocks(AesBlockX2::from(($vectors[0].0, $vectors[1].0))),
                AesBlockX2::from(($vectors[0].1, $vectors[1].1))
            );

            assert_eq!($enc.encrypt_block($vectors[2].0), $vectors[2].1);
            assert_eq!($enc.encrypt_block($vectors[3].0), $vectors[3].1);

            assert_eq!(
                $enc.encrypt_2_blocks(AesBlockX2::from(($vectors[2].0, $vectors[3].0))),
                AesBlockX2::from(($vectors[2].1, $vectors[3].1))
            );

            assert_eq!(
                $enc.encrypt_4_blocks(AesBlockX4::from((
                    $vectors[0].0,
                    $vectors[1].0,
                    $vectors[2].0,
                    $vectors[3].0
                ))),
                AesBlockX4::from(($vectors[0].1, $vectors[1].1, $vectors[2].1, $vectors[3].1))
            );
        };
        (dec: $enc:ident, $vectors:ident) => {
            assert_eq!($enc.decrypt_block($vectors[0].1), $vectors[0].0);
            assert_eq!($enc.decrypt_block($vectors[1].1), $vectors[1].0);

            assert_eq!(
                $enc.decrypt_2_blocks(AesBlockX2::from(($vectors[0].1, $vectors[1].1))),
                AesBlockX2::from(($vectors[0].0, $vectors[1].0))
            );

            assert_eq!($enc.decrypt_block($vectors[2].1), $vectors[2].0);
            assert_eq!($enc.decrypt_block($vectors[3].1), $vectors[3].0);

            assert_eq!(
                $enc.decrypt_2_blocks(AesBlockX2::from(($vectors[2].1, $vectors[3].1))),
                AesBlockX2::from(($vectors[2].0, $vectors[3].0))
            );

            assert_eq!(
                $enc.decrypt_4_blocks(AesBlockX4::from((
                    $vectors[0].1,
                    $vectors[1].1,
                    $vectors[2].1,
                    $vectors[3].1
                ))),
                AesBlockX4::from(($vectors[0].0, $vectors[1].0, $vectors[2].0, $vectors[3].0))
            );
        };
    }

    // these are of form (plaintext, ciphertext) pairs
    lazy_static! {
        static ref AES_128_VECTORS: [(AesBlock, AesBlock); 5] = [
            (
                0x6bc1bee22e409f96e93d7e117393172a.into(),
                0x3ad77bb40d7a3660a89ecaf32466ef97.into()
            ),
            (
                0xae2d8a571e03ac9c9eb76fac45af8e51.into(),
                0xf5d3d58503b9699de785895a96fdbaaf.into()
            ),
            (
                0x30c81c46a35ce411e5fbc1191a0a52ef.into(),
                0x43b1cd7f598ece23881b00e3ed030688.into()
            ),
            (
                0xf69f2445df4f9b17ad2b417be66c3710.into(),
                0x7b0c785e27e8ad3f8223207104725dd4.into()
            ),
            (
                0x3243f6a8885a308d313198a2e0370734.into(),
                0x3925841d02dc09fbdc118597196a0b32.into()
            ),
        ];
        static ref AES_192_VECTORS: [(AesBlock, AesBlock); 4] = [
            (
                0x6bc1bee22e409f96e93d7e117393172a.into(),
                0xbd334f1d6e45f25ff712a214571fa5cc.into()
            ),
            (
                0xae2d8a571e03ac9c9eb76fac45af8e51.into(),
                0x974104846d0ad3ad7734ecb3ecee4eef.into()
            ),
            (
                0x30c81c46a35ce411e5fbc1191a0a52ef.into(),
                0xef7afd2270e2e60adce0ba2face6444e.into()
            ),
            (
                0xf69f2445df4f9b17ad2b417be66c3710.into(),
                0x9a4b41ba738d6c72fb16691603c18e0e.into()
            )
        ];
        static ref AES_256_VECTORS: [(AesBlock, AesBlock); 4] = [
            (
                0x6bc1bee22e409f96e93d7e117393172a.into(),
                0xf3eed1bdb5d2a03c064b5a7e3db181f8.into()
            ),
            (
                0xae2d8a571e03ac9c9eb76fac45af8e51.into(),
                0x591ccb10d410ed26dc5ba74a31362870.into()
            ),
            (
                0x30c81c46a35ce411e5fbc1191a0a52ef.into(),
                0xb6ed21b99ca6f4f9f153e7b1beafed1d.into()
            ),
            (
                0xf69f2445df4f9b17ad2b417be66c3710.into(),
                0x23304b7a39f9f3ff067d8d8f9e24ecc7.into()
            )
        ];
    }

    #[test]
    fn aes_128_test() {
        let key = <[u8; 16]>::from_hex("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let enc = Aes128Enc::from(key);

        aes_test!(enc: enc, AES_128_VECTORS);

        let dec = enc.decrypter();

        aes_test!(dec: dec, AES_128_VECTORS);
    }

    #[test]
    fn aes_192_test() {
        let key = <[u8; 24]>::from_hex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b").unwrap();
        let enc = Aes192Enc::from(key);

        aes_test!(enc: enc, AES_192_VECTORS);

        let dec = enc.decrypter();

        aes_test!(dec: dec, AES_192_VECTORS);
    }

    #[test]
    fn aes_256_test() {
        let key = <[u8; 32]>::from_hex(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        )
        .unwrap();
        let enc = Aes256Enc::from(key);

        aes_test!(enc: enc, AES_256_VECTORS);

        let dec = enc.decrypter();

        aes_test!(dec: dec, AES_256_VECTORS);
    }
}
