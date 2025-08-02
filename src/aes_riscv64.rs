use crate::common::array_from_slice;
use core::arch::riscv64::*;
use core::mem;
use core::ops::{BitAnd, BitOr, BitXor, Not};

#[derive(Copy, Clone)]
#[repr(C, align(16))]
#[must_use]
pub struct AesBlock(u64, u64);

impl BitAnd for AesBlock {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0, self.1 & rhs.1)
    }
}

impl BitOr for AesBlock {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0, self.1 | rhs.1)
    }
}

impl BitXor for AesBlock {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0, self.1 ^ rhs.1)
    }
}

impl Not for AesBlock {
    type Output = Self;

    #[inline]
    fn not(self) -> Self::Output {
        Self(!self.0, !self.1)
    }
}

impl AesBlock {
    #[inline]
    pub const fn new(value: [u8; 16]) -> Self {
        unsafe { mem::transmute(value) }
    }

    #[inline]
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 16] {
        unsafe { mem::transmute(self) }
    }

    #[inline]
    #[must_use]
    pub fn is_zero(self) -> bool {
        (self.0 | self.1) == 0
    }

    /// Performs one round of AES encryption function (`ShiftRows`->`SubBytes`->`MixColumns`->`AddRoundKey`)
    #[inline]
    pub fn enc(self, round_key: Self) -> Self {
        unsafe {
            Self(
                aes64esm(self.0, self.1) ^ round_key.0,
                aes64esm(self.1, self.0) ^ round_key.1,
            )
        }
    }

    /// Performs one round of AES decryption function (`InvShiftRows`->`InvSubBytes`->`InvMixColumns`->`AddRoundKey`)
    #[inline]
    pub fn dec(self, round_key: Self) -> Self {
        unsafe {
            Self(
                aes64dsm(self.0, self.1) ^ round_key.0,
                aes64dsm(self.1, self.0) ^ round_key.1,
            )
        }
    }

    /// Performs one round of AES encryption function without `MixColumns` (`ShiftRows`->`SubBytes`->`AddRoundKey`)
    #[inline]
    pub fn enc_last(self, round_key: Self) -> Self {
        unsafe {
            Self(
                aes64es(self.0, self.1) ^ round_key.0,
                aes64es(self.1, self.0) ^ round_key.1,
            )
        }
    }

    /// Performs one round of AES decryption function without `InvMixColumns` (`InvShiftRows`->`InvSubBytes`->`AddRoundKey`)
    #[inline]
    pub fn dec_last(self, round_key: Self) -> Self {
        unsafe {
            Self(
                aes64ds(self.0, self.1) ^ round_key.0,
                aes64ds(self.1, self.0) ^ round_key.1,
            )
        }
    }

    /// Performs the `MixColumns` operation
    #[inline]
    pub fn mc(self) -> Self {
        unsafe {
            let (tmp0, tmp1) = (aes64ds(self.0, self.1), aes64ds(self.1, self.0));
            Self(aes64esm(tmp0, tmp1), aes64esm(tmp1, tmp0))
        }
    }

    /// Performs the `InvMixColumns` operation
    #[inline]
    pub fn imc(self) -> Self {
        unsafe { Self(aes64im(self.0), aes64im(self.1)) }
    }
}

#[inline(always)]
fn keyexp_128<const RNUM: u8>(a: u64, b: u64) -> (u64, u64) {
    keyexp_256_1::<RNUM>(a, b, b)
}

#[inline(always)]
fn keyexp_192<const RNUM: u8>(a: u64, b: u64, c: u64) -> (u64, u64, u64) {
    let (a, b) = keyexp_256_1::<RNUM>(a, b, c);
    (a, b, unsafe { aes64ks2(b, c) })
}

#[inline(always)]
fn keyexp_256_1<const RNUM: u8>(a: u64, b: u64, d: u64) -> (u64, u64) {
    let a = unsafe { aes64ks2(aes64ks1i(d, RNUM), a) };
    (a, unsafe { aes64ks2(a, b) })
}

#[inline(always)]
fn keyexp_256_2(a: u64, b: u64, d: u64) -> (u64, u64) {
    keyexp_256_1::<10>(a, b, d)
}

pub(super) fn keygen_128(key: [u8; 16]) -> [AesBlock; 11] {
    let (key0, key1) = (
        u64::from_ne_bytes(array_from_slice(&key, 0)),
        u64::from_ne_bytes(array_from_slice(&key, 8)),
    );
    let (key2, key3) = keyexp_128::<0>(key0, key1);
    let (key4, key5) = keyexp_128::<1>(key2, key3);
    let (key6, key7) = keyexp_128::<2>(key4, key5);
    let (key8, key9) = keyexp_128::<3>(key6, key7);
    let (key10, key11) = keyexp_128::<4>(key8, key9);
    let (key12, key13) = keyexp_128::<5>(key10, key11);
    let (key14, key15) = keyexp_128::<6>(key12, key13);
    let (key16, key17) = keyexp_128::<7>(key14, key15);
    let (key18, key19) = keyexp_128::<8>(key16, key17);
    let (key20, key21) = keyexp_128::<9>(key18, key19);

    unsafe {
        mem::transmute([
            key0, key1, key2, key3, key4, key5, key6, key7, key8, key9, key10, key11, key12, key13,
            key14, key15, key16, key17, key18, key19, key20, key21,
        ])
    }
}

#[allow(clippy::cast_possible_truncation)]
pub(super) fn keygen_192(key: [u8; 24]) -> [AesBlock; 13] {
    let (key0, key1, key2) = (
        u64::from_ne_bytes(array_from_slice(&key, 0)),
        u64::from_ne_bytes(array_from_slice(&key, 8)),
        u64::from_ne_bytes(array_from_slice(&key, 16)),
    );

    let (key3, key4, key5) = keyexp_192::<0>(key0, key1, key2);
    let (key6, key7, key8) = keyexp_192::<1>(key3, key4, key5);
    let (key9, key10, key11) = keyexp_192::<2>(key6, key7, key8);
    let (key12, key13, key14) = keyexp_192::<3>(key9, key10, key11);
    let (key15, key16, key17) = keyexp_192::<4>(key12, key13, key14);
    let (key18, key19, key20) = keyexp_192::<5>(key15, key16, key17);
    let (key21, key22, key23) = keyexp_192::<6>(key18, key19, key20);
    let (key24, key25) = keyexp_256_1::<7>(key21, key22, key23);

    unsafe {
        mem::transmute([
            key0, key1, key2, key3, key4, key5, key6, key7, key8, key9, key10, key11, key12, key13,
            key14, key15, key16, key17, key18, key19, key20, key21, key22, key23, key24, key25,
        ])
    }
}

pub(super) fn keygen_256(key: [u8; 32]) -> [AesBlock; 15] {
    let (key0, key1, key2, key3) = (
        u64::from_ne_bytes(array_from_slice(&key, 0)),
        u64::from_ne_bytes(array_from_slice(&key, 8)),
        u64::from_ne_bytes(array_from_slice(&key, 16)),
        u64::from_ne_bytes(array_from_slice(&key, 24)),
    );

    let (key4, key5) = keyexp_256_1::<0>(key0, key1, key3);
    let (key6, key7) = keyexp_256_2(key2, key3, key5);
    let (key8, key9) = keyexp_256_1::<1>(key4, key5, key7);
    let (key10, key11) = keyexp_256_2(key6, key7, key9);
    let (key12, key13) = keyexp_256_1::<2>(key8, key9, key11);
    let (key14, key15) = keyexp_256_2(key10, key11, key13);
    let (key16, key17) = keyexp_256_1::<3>(key12, key13, key15);
    let (key18, key19) = keyexp_256_2(key14, key15, key17);
    let (key20, key21) = keyexp_256_1::<4>(key16, key17, key19);
    let (key22, key23) = keyexp_256_2(key18, key19, key21);
    let (key24, key25) = keyexp_256_1::<5>(key20, key21, key23);
    let (key26, key27) = keyexp_256_2(key22, key23, key25);
    let (key28, key29) = keyexp_256_1::<6>(key24, key25, key27);

    unsafe {
        mem::transmute([
            key0, key1, key2, key3, key4, key5, key6, key7, key8, key9, key10, key11, key12, key13,
            key14, key15, key16, key17, key18, key19, key20, key21, key22, key23, key24, key25,
            key26, key27, key28, key29,
        ])
    }
}
