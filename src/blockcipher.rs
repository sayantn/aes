use crate::*;
use cfg_if::cfg_if;
use core::fmt::Debug;

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

cfg_if! {
    if #[cfg(all(
        feature = "nightly",
        any(target_arch = "powerpc", target_arch = "powerpc64"),
        target_feature = "power8-crypto"
    ))] {
        #[inline(always)]
        fn dec_round_keys<const N: usize>(enc_round_keys: &[AesBlock; N]) -> [AesBlock; N] {
            *enc_round_keys
        }

        #[inline(always)]
        fn enc_round_keys<const N: usize>(dec_round_keys: &[AesBlock; N]) -> [AesBlock; N] {
            *dec_round_keys
        }
    } else {
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
    }
}

cfg_if! {
    if #[cfg(all(
            any(
                target_arch = "aarch64",
                target_arch = "arm64ec",
                all(feature = "nightly", target_arch = "arm", target_feature = "v8")
            ),
            target_feature = "aes",
        ))] {
        macro_rules! impl_aese_aesd {
            ($($name:ident),*) => {$(
                impl $name {
                    #[inline(always)]
                    fn aese(self, round_key: Self) -> Self {
                        let (a, b) = self.into();
                        let (rk_a, rk_b) = round_key.into();
                        (a.aese(rk_a), b.aese(rk_b)).into()
                    }

                    #[inline(always)]
                    fn aesd(self, round_key: Self) -> Self {
                        let (a, b) = self.into();
                        let (rk_a, rk_b) = round_key.into();
                        (a.aesd(rk_a), b.aesd(rk_b)).into()
                    }
                }
            )*};
        }

        impl_aese_aesd!(AesBlockX2, AesBlockX4);

        macro_rules! declare_chain {
            ($($name:ty),*) => {$(
                impl $name {
                    /// Computes `(self ^ keys[0]).enc(keys[1])...enc(keys[keys.len() - 1])` in the most optimized way
                    ///
                    /// # Panics
                    /// If `keys.len() == 0`
                    #[inline]
                    pub fn chain_enc(self, keys: &[$name]) -> $name {
                        assert_ne!(keys.len(), 0);

                        let mut acc = self;
                        for &key in &keys[..keys.len() - 1] {
                            acc = acc.aese(key).mc();
                        }
                        acc ^ keys[keys.len() - 1]
                    }

                    /// Computes `(self ^ keys[0]).dec(keys[1])...dec(keys[keys.len() - 1])` in the most optimized way
                    ///
                    /// # Panics
                    /// If `keys.len() == 0`
                    #[inline]
                    pub fn chain_dec(self, keys: &[$name]) -> $name {
                        assert_ne!(keys.len(), 0);

                        let mut acc = self;
                        for &key in &keys[..keys.len() - 1] {
                            acc = acc.aesd(key).imc();
                        }
                        acc ^ keys[keys.len() - 1]
                    }

                    /// Computes `(self ^ keys[0]).enc(keys[1])...enc(keys[keys.len() - 2]).enc_last(keys[keys.len() - 1])` in the most optimized way
                    ///
                    /// # Panics
                    /// If `keys.len() < 2`
                    #[inline]
                    pub fn chain_enc_with_last(self, keys: &[$name]) -> $name {
                        assert!(keys.len() >= 2);

                        let mut acc = self;
                        for &key in &keys[..keys.len() - 2] {
                            acc = acc.aese(key).mc();
                        }
                        acc.aese(keys[keys.len() - 2]) ^ keys[keys.len() - 1]
                    }

                    /// Computes `(self ^ keys[0]).dec(keys[1])...dec(keys[keys.len() - 2]).dec_last(keys[keys.len() - 1])` in the most optimized way
                    ///
                    /// # Panics
                    /// If `keys.len() < 2`
                    #[inline]
                    pub fn chain_dec_with_last(self, keys: &[$name]) -> $name {
                        assert!(keys.len() >= 2);

                        let mut acc = self;
                        for &key in &keys[..keys.len() - 2] {
                            acc = acc.aesd(key).imc();
                        }
                        acc.aesd(keys[keys.len() - 2]) ^ keys[keys.len() - 1]
                    }
                }
            )*};
        }
    } else {
        macro_rules! declare_chain {
            ($($name:ty),*) => {$(
                impl $name {
                    /// Computes `(self ^ keys[0]).enc(keys[1])...enc(keys[keys.len() - 1])` in the most optimized way
                    ///
                    /// # Panics
                    /// If `keys.len() == 0`
                    #[inline]
                    pub fn chain_enc(self, keys: &[$name]) -> $name {
                        assert_ne!(keys.len(), 0);

                        let mut acc = self ^ keys[0];
                        for &key in &keys[1..] {
                            acc = acc.enc(key);
                        }
                        acc
                    }

                    /// Computes `(self ^ keys[0]).dec(keys[1])...dec(keys[keys.len() - 1])` in the most optimized way
                    ///
                    /// # Panics
                    /// If `keys.len() == 0`
                    #[inline]
                    pub fn chain_dec(self, keys: &[$name]) -> $name {
                        assert_ne!(keys.len(), 0);

                        let mut acc = self ^ keys[0];
                        for &key in &keys[1..] {
                            acc = acc.dec(key);
                        }
                        acc
                    }

                    /// Computes `(self ^ keys[0]).enc(keys[1])...enc(keys[keys.len() - 2]).enc_last(keys[keys.len() - 1])` in the most optimized way
                    ///
                    /// # Panics
                    /// If `keys.len() < 2`
                    #[inline]
                    pub fn chain_enc_with_last(self, keys: &[$name]) -> $name {
                        assert!(keys.len() >= 2);

                        let mut acc = self ^ keys[0];
                        for &key in &keys[1..keys.len() - 1] {
                            acc = acc.enc(key);
                        }
                        acc.enc_last(keys[keys.len() - 1])
                    }

                    /// Computes `(self ^ keys[0]).dec(keys[1])...dec(keys[keys.len() - 2]).dec_last(keys[keys.len() - 1])` in the most optimized way
                    ///
                    /// # Panics
                    /// If `keys.len() < 2`
                    #[inline]
                    pub fn chain_dec_with_last(self, keys: &[$name]) -> $name {
                        assert!(keys.len() >= 2);

                        let mut acc = self ^ keys[0];
                        for &key in &keys[1..keys.len() - 1] {
                            acc = acc.dec(key);
                        }
                        acc.dec_last(keys[keys.len() - 1])
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
            /// Returns an encrypter with the provided key
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
            /// Returns an decrypter with the provided key
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
                plaintext.chain_enc_with_last(&self.round_keys)
            }

            fn encrypt_2_blocks(&self, plaintext: AesBlockX2) -> AesBlockX2 {
                let round_keys = self.round_keys.map(Into::into);
                plaintext.chain_enc_with_last(&round_keys)
            }

            fn encrypt_4_blocks(&self, plaintext: AesBlockX4) -> AesBlockX4 {
                let round_keys = self.round_keys.map(Into::into);
                plaintext.chain_enc_with_last(&round_keys)
            }
        }

        impl AesDecrypt<$key_len> for $dec_name {
            type Encrypter = $enc_name;

            fn encrypter(&self) -> Self::Encrypter {
                $enc_name {
                    round_keys: enc_round_keys(&self.round_keys),
                }
            }

            cfg_if! {
                if #[cfg(all(
                    feature = "nightly",
                    any(target_arch = "powerpc", target_arch = "powerpc64"),
                    target_feature = "power8-crypto"
                ))] {
                    fn decrypt_block(&self, ciphertext: AesBlock) -> AesBlock {
                        let mut acc = ciphertext ^ self.round_keys[$nr];
                        for &drk in self.round_keys[1..$nr].iter().rev() {
                            acc = acc.dec2(drk);
                        }
                        acc.dec_last(self.round_keys[0])
                    }

                    fn decrypt_2_blocks(&self, ciphertext: AesBlockX2) -> AesBlockX2 {
                        let (a, b) = ciphertext.into();
                        (self.decrypt_block(a), self.decrypt_block(b)).into()
                    }

                    fn decrypt_4_blocks(&self, ciphertext: AesBlockX4) -> AesBlockX4 {
                        let (a, b) = ciphertext.into();
                        (self.decrypt_2_blocks(a), self.decrypt_2_blocks(b)).into()
                    }
                } else {
                    fn decrypt_block(&self, ciphertext: AesBlock) -> AesBlock {
                        ciphertext.chain_dec_with_last(&self.round_keys)
                    }

                    fn decrypt_2_blocks(&self, ciphertext: AesBlockX2) -> AesBlockX2 {
                        let round_keys = self.round_keys.map(Into::into);
                        ciphertext.chain_dec_with_last(&round_keys)
                    }

                    fn decrypt_4_blocks(&self, ciphertext: AesBlockX4) -> AesBlockX4 {
                        let round_keys = self.round_keys.map(Into::into);
                        ciphertext.chain_dec_with_last(&round_keys)
                    }
                }
            }
        }
    };
}

implement_aes!(Aes128Enc, Aes128Dec, 16, 10, keygen_128);
implement_aes!(Aes192Enc, Aes192Dec, 24, 12, keygen_192);
implement_aes!(Aes256Enc, Aes256Dec, 32, 14, keygen_256);
