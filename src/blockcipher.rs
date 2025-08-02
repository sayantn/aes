use crate::*;
use cfg_if::cfg_if;
use core::array;
use core::fmt::Debug;

mod private {
    pub trait Sealed {}
}

#[allow(unused)]
#[inline(always)]
fn transpose<T: Copy, const M: usize, const N: usize>(array: [[T; M]; N]) -> [[T; N]; M] {
    array::from_fn(|i| array::from_fn(|j| array[j][i]))
}

pub trait AesEncrypt<const KEY_LEN: usize>:
    From<[u8; KEY_LEN]> + private::Sealed + Debug + Clone
{
    type Decrypter: AesDecrypt<KEY_LEN, Encrypter = Self>;

    fn decrypter(&self) -> Self::Decrypter;

    fn encrypt_block(&self, plaintext: AesBlock) -> AesBlock;

    /// Encrypt two blocks, *using the same key*
    fn encrypt_2_blocks(&self, plaintext: AesBlockX2) -> AesBlockX2;

    /// Encrypt four blocks, *using the same key*
    fn encrypt_4_blocks(&self, plaintext: AesBlockX4) -> AesBlockX4;
}

pub trait AesDecrypt<const KEY_LEN: usize>:
    From<[u8; KEY_LEN]> + private::Sealed + Debug + Clone
{
    type Encrypter: AesEncrypt<KEY_LEN, Decrypter = Self>;

    fn encrypter(&self) -> Self::Encrypter;

    fn decrypt_block(&self, plaintext: AesBlock) -> AesBlock;

    /// Decrypt two blocks, *using the same key*
    fn decrypt_2_blocks(&self, ciphertext: AesBlockX2) -> AesBlockX2;

    /// Decrypt four blocks, *using the same key*
    fn decrypt_4_blocks(&self, ciphertext: AesBlockX4) -> AesBlockX4;
}

pub trait AesEncryptX2<const KEY_LEN: usize>:
    From<[[u8; KEY_LEN]; 2]> + private::Sealed + Debug + Clone
{
    type Decrypter: AesDecryptX2<KEY_LEN, Encrypter = Self>;

    fn decrypter(&self) -> Self::Decrypter;

    /// Encrypt two blocks, using the first key for the first block, and the second key for the second block
    fn encrypt_2_blocks(&self, plaintext: AesBlockX2) -> AesBlockX2;

    /// Encrypt four blocks, using the first key for the first two blocks, and the second key for the second two blocks
    fn encrypt_4_blocks(&self, plaintext: AesBlockX4) -> AesBlockX4;
}

pub trait AesDecryptX2<const KEY_LEN: usize>:
    From<[[u8; KEY_LEN]; 2]> + private::Sealed + Debug + Clone
{
    type Encrypter: AesEncryptX2<KEY_LEN, Decrypter = Self>;

    fn encrypter(&self) -> Self::Encrypter;

    /// Decrypt two blocks, using the first key for the first block, and the second key for the second block
    fn decrypt_2_blocks(&self, ciphertext: AesBlockX2) -> AesBlockX2;

    /// Decrypt four blocks, using the first key for the first two blocks, and the second key for the second two blocks
    fn decrypt_4_blocks(&self, ciphertext: AesBlockX4) -> AesBlockX4;
}

pub trait AesEncryptX4<const KEY_LEN: usize>:
    From<[[u8; KEY_LEN]; 4]> + private::Sealed + Debug + Clone
{
    type Decrypter: AesDecryptX4<KEY_LEN, Encrypter = Self>;

    fn decrypter(&self) -> Self::Decrypter;

    /// Encrypt four blocks, using the four keys for the four blocks respectively
    fn encrypt_4_blocks(&self, plaintext: AesBlockX4) -> AesBlockX4;
}

pub trait AesDecryptX4<const KEY_LEN: usize>:
    From<[[u8; KEY_LEN]; 4]> + private::Sealed + Debug + Clone
{
    type Encrypter: AesEncryptX4<KEY_LEN, Decrypter = Self>;

    fn encrypter(&self) -> Self::Encrypter;

    /// Decrypt four blocks, using the four keys for the four blocks respectively
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
                            acc = acc.raw_dec(drk);
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

cfg_if! {
    // Only interleave the keys if we have a decent enough X2 implementation
    if #[cfg(all(
        feature = "nightly",
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "vaes"
    ))] {

        #[inline(always)]
        fn dec_round_keys_x2<const N: usize>(enc_round_keys: &[AesBlockX2; N]) -> [AesBlockX2; N] {
            let mut drk = [AesBlockX2::zero(); N];
            drk[0] = enc_round_keys[N - 1];
            for i in 1..(N - 1) {
                drk[i] = enc_round_keys[N - 1 - i].imc();
            }
            drk[N - 1] = enc_round_keys[0];
            drk
        }

        #[inline(always)]
        fn enc_round_keys_x2<const N: usize>(dec_round_keys: &[AesBlockX2; N]) -> [AesBlockX2; N] {
            let mut rk = [AesBlockX2::zero(); N];
            rk[0] = dec_round_keys[N - 1];
            for i in 1..(N - 1) {
                rk[i] = dec_round_keys[N - 1 - i].mc();
            }
            rk[N - 1] = dec_round_keys[0];
            rk
        }

        macro_rules! implement_aes_x2 {
            ($enc_name:ident, $dec_name:ident, $key_len:literal, $nr:literal, $keygen:ident) => {

                #[derive(Debug, Clone)]
                pub struct $enc_name {
                    round_keys: [AesBlockX2; { $nr + 1 }],
                }

                impl private::Sealed for $enc_name {}

                impl From<[[u8; $key_len]; 2]> for $enc_name {
                    /// Returns an encrypter with the provided key
                    fn from(value: [[u8; $key_len]; 2]) -> Self {
                        $enc_name {
                            round_keys: transpose(value.map($keygen)).map(Into::into),
                        }
                    }
                }

                #[derive(Debug, Clone)]
                pub struct $dec_name {
                    round_keys: [AesBlockX2; { $nr + 1 }],
                }

                impl private::Sealed for $dec_name {}

                impl From<[[u8; $key_len]; 2]> for $dec_name {
                    /// Returns an decrypter with the provided key
                    fn from(value: [[u8; $key_len]; 2]) -> Self {
                        $enc_name::from(value).decrypter()
                    }
                }

                impl AesEncryptX2<$key_len> for $enc_name {
                    type Decrypter = $dec_name;

                    fn decrypter(&self) -> Self::Decrypter {
                        $dec_name {
                            round_keys: dec_round_keys_x2(&self.round_keys),
                        }
                    }

                    fn encrypt_2_blocks(&self, plaintext: AesBlockX2) -> AesBlockX2 {
                        plaintext.chain_enc_with_last(&self.round_keys)
                    }

                    fn encrypt_4_blocks(&self, plaintext: AesBlockX4) -> AesBlockX4 {
                        let round_keys = self.round_keys.map(Into::into);
                        plaintext.chain_enc_with_last(&round_keys)
                    }
                }

                impl AesDecryptX2<$key_len> for $dec_name {
                    type Encrypter = $enc_name;

                    fn encrypter(&self) -> Self::Encrypter {
                        $enc_name {
                            round_keys: enc_round_keys_x2(&self.round_keys),
                        }
                    }

                    fn decrypt_2_blocks(&self, ciphertext: AesBlockX2) -> AesBlockX2 {
                        ciphertext.chain_dec_with_last(&self.round_keys)
                    }

                    fn decrypt_4_blocks(&self, ciphertext: AesBlockX4) -> AesBlockX4 {
                        let round_keys = self.round_keys.map(Into::into);
                        ciphertext.chain_dec_with_last(&round_keys)
                    }
                }
            }
        }

        implement_aes_x2!(Aes128EncX2, Aes128DecX2, 16, 10, keygen_128);
        implement_aes_x2!(Aes192EncX2, Aes192DecX2, 24, 12, keygen_192);
        implement_aes_x2!(Aes256EncX2, Aes256DecX2, 32, 14, keygen_256);
    } else {
        // otherwise just use a tuple

        macro_rules! implement_aes_x2 {
            ($enc_name:ident, $dec_name:ident, $key_len:literal, $nr:literal, $base_enc:ident, $base_dec:ident) => {

                #[derive(Debug, Clone)]
                pub struct $enc_name {
                    inner: [$base_enc; 2],
                }

                impl private::Sealed for $enc_name {}

                impl From<[[u8; $key_len]; 2]> for $enc_name {
                    /// Returns an encrypter with the provided key
                    fn from(value: [[u8; $key_len]; 2]) -> Self {
                        $enc_name {
                            inner: value.map(Into::into),
                        }
                    }
                }

                #[derive(Debug, Clone)]
                pub struct $dec_name {
                    inner: [$base_dec; 2],
                }

                impl private::Sealed for $dec_name {}

                impl From<[[u8; $key_len]; 2]> for $dec_name {
                    /// Returns an decrypter with the provided key
                    fn from(value: [[u8; $key_len]; 2]) -> Self {
                        $dec_name {
                            inner: value.map(Into::into),
                        }
                    }
                }

                impl AesEncryptX2<$key_len> for $enc_name {
                    type Decrypter = $dec_name;

                    fn decrypter(&self) -> Self::Decrypter {
                        $dec_name {
                            inner: self.inner.each_ref().map($base_enc::decrypter),
                        }
                    }

                    fn encrypt_2_blocks(&self, plaintext: AesBlockX2) -> AesBlockX2 {
                        let (a, b) = plaintext.into();
                        (self.inner[0].encrypt_block(a), self.inner[1].encrypt_block(b)).into()
                    }

                    fn encrypt_4_blocks(&self, plaintext: AesBlockX4) -> AesBlockX4 {
                        let (a, b) = plaintext.into();
                        (self.inner[0].encrypt_2_blocks(a), self.inner[1].encrypt_2_blocks(b)).into()
                    }
                }

                impl AesDecryptX2<$key_len> for $dec_name {
                    type Encrypter = $enc_name;

                    fn encrypter(&self) -> Self::Encrypter {
                        $enc_name {
                            inner: self.inner.each_ref().map($base_dec::encrypter),
                        }
                    }

                    fn decrypt_2_blocks(&self, ciphertext: AesBlockX2) -> AesBlockX2 {
                        let (a, b) = ciphertext.into();
                        (self.inner[0].decrypt_block(a), self.inner[1].decrypt_block(b)).into()
                    }

                    fn decrypt_4_blocks(&self, ciphertext: AesBlockX4) -> AesBlockX4 {
                        let (a, b) = ciphertext.into();
                        (self.inner[0].decrypt_2_blocks(a), self.inner[1].decrypt_2_blocks(b)).into()
                    }
                }
            }
        }

        implement_aes_x2!(Aes128EncX2, Aes128DecX2, 16, 10, Aes128Enc, Aes128Dec);
        implement_aes_x2!(Aes192EncX2, Aes192DecX2, 24, 12, Aes192Enc, Aes192Dec);
        implement_aes_x2!(Aes256EncX2, Aes256DecX2, 32, 14, Aes256Enc, Aes256Dec);
    }
}

cfg_if! {
    // Only interleave the keys if we have a decent enough X4 implementation
    if #[cfg(all(
        feature = "nightly",
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "vaes",
        target_feature = "avx512f"
    ))] {

        #[inline(always)]
        fn dec_round_keys_x4<const N: usize>(enc_round_keys: &[AesBlockX4; N]) -> [AesBlockX4; N] {
            let mut drk = [AesBlockX4::zero(); N];
            drk[0] = enc_round_keys[N - 1];
            for i in 1..(N - 1) {
                drk[i] = enc_round_keys[N - 1 - i].imc();
            }
            drk[N - 1] = enc_round_keys[0];
            drk
        }

        #[inline(always)]
        fn enc_round_keys_x4<const N: usize>(dec_round_keys: &[AesBlockX4; N]) -> [AesBlockX4; N] {
            let mut rk = [AesBlockX4::zero(); N];
            rk[0] = dec_round_keys[N - 1];
            for i in 1..(N - 1) {
                rk[i] = dec_round_keys[N - 1 - i].mc();
            }
            rk[N - 1] = dec_round_keys[0];
            rk
        }

        macro_rules! implement_aes_x4 {
            ($enc_name:ident, $dec_name:ident, $key_len:literal, $nr:literal, $keygen:ident) => {

                #[derive(Debug, Clone)]
                pub struct $enc_name {
                    round_keys: [AesBlockX4; { $nr + 1 }],
                }

                impl private::Sealed for $enc_name {}

                impl From<[[u8; $key_len]; 4]> for $enc_name {
                    /// Returns an encrypter with the provided key
                    fn from(value: [[u8; $key_len]; 4]) -> Self {
                        $enc_name {
                            round_keys: transpose(value.map($keygen)).map(Into::into),
                        }
                    }
                }

                #[derive(Debug, Clone)]
                pub struct $dec_name {
                    round_keys: [AesBlockX4; { $nr + 1 }],
                }

                impl private::Sealed for $dec_name {}

                impl From<[[u8; $key_len]; 4]> for $dec_name {
                    /// Returns an decrypter with the provided key
                    fn from(value: [[u8; $key_len]; 4]) -> Self {
                        $enc_name::from(value).decrypter()
                    }
                }

                impl AesEncryptX4<$key_len> for $enc_name {
                    type Decrypter = $dec_name;

                    fn decrypter(&self) -> Self::Decrypter {
                        $dec_name {
                            round_keys: dec_round_keys_x4(&self.round_keys),
                        }
                    }

                    fn encrypt_4_blocks(&self, plaintext: AesBlockX4) -> AesBlockX4 {
                        plaintext.chain_enc_with_last(&self.round_keys)
                    }
                }

                impl AesDecryptX4<$key_len> for $dec_name {
                    type Encrypter = $enc_name;

                    fn encrypter(&self) -> Self::Encrypter {
                        $enc_name {
                            round_keys: enc_round_keys_x4(&self.round_keys),
                        }
                    }

                    fn decrypt_4_blocks(&self, ciphertext: AesBlockX4) -> AesBlockX4 {
                        ciphertext.chain_dec_with_last(&self.round_keys)
                    }
                }
            }
        }

        implement_aes_x4!(Aes128EncX4, Aes128DecX4, 16, 10, keygen_128);
        implement_aes_x4!(Aes192EncX4, Aes192DecX4, 24, 12, keygen_192);
        implement_aes_x4!(Aes256EncX4, Aes256DecX4, 32, 14, keygen_256);
    } else {
        // otherwise just use a tuple

        macro_rules! implement_aes_x4 {
            ($enc_name:ident, $dec_name:ident, $key_len:literal, $nr:literal, $base_enc:ident, $base_dec:ident) => {

                #[derive(Debug, Clone)]
                pub struct $enc_name {
                    inner: [$base_enc; 2],
                }

                impl private::Sealed for $enc_name {}

                impl From<[[u8; $key_len]; 4]> for $enc_name {
                    /// Returns an encrypter with the provided key
                    fn from(value: [[u8; $key_len]; 4]) -> Self {
                        let value: [[[u8; $key_len]; 2]; 2] = unsafe { core::mem::transmute(value) };
                        $enc_name {
                            inner: value.map(Into::into),
                        }
                    }
                }

                #[derive(Debug, Clone)]
                pub struct $dec_name {
                    inner: [$base_dec; 2],
                }

                impl private::Sealed for $dec_name {}

                impl From<[[u8; $key_len]; 4]> for $dec_name {
                    /// Returns an decrypter with the provided key
                    fn from(value: [[u8; $key_len]; 4]) -> Self {
                        let value: [[[u8; $key_len]; 2]; 2] = unsafe { core::mem::transmute(value) };
                        $dec_name {
                            inner: value.map(Into::into),
                        }
                    }
                }

                impl AesEncryptX4<$key_len> for $enc_name {
                    type Decrypter = $dec_name;

                    fn decrypter(&self) -> Self::Decrypter {
                        $dec_name {
                            inner: self.inner.each_ref().map($base_enc::decrypter),
                        }
                    }

                    fn encrypt_4_blocks(&self, plaintext: AesBlockX4) -> AesBlockX4 {
                        let (a, b) = plaintext.into();
                        (self.inner[0].encrypt_2_blocks(a), self.inner[1].encrypt_2_blocks(b)).into()
                    }
                }

                impl AesDecryptX4<$key_len> for $dec_name {
                    type Encrypter = $enc_name;

                    fn encrypter(&self) -> Self::Encrypter {
                        $enc_name {
                            inner: self.inner.each_ref().map($base_dec::encrypter),
                        }
                    }

                    fn decrypt_4_blocks(&self, ciphertext: AesBlockX4) -> AesBlockX4 {
                        let (a, b) = ciphertext.into();
                        (self.inner[0].decrypt_2_blocks(a), self.inner[1].decrypt_2_blocks(b)).into()
                    }
                }
            }
        }

        implement_aes_x4!(Aes128EncX4, Aes128DecX4, 16, 10, Aes128EncX2, Aes128DecX2);
        implement_aes_x4!(Aes192EncX4, Aes192DecX4, 24, 12, Aes192EncX2, Aes192DecX2);
        implement_aes_x4!(Aes256EncX4, Aes256DecX4, 32, 14, Aes256EncX2, Aes256DecX2);
    }
}
