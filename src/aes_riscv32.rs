use core::arch::riscv32::*;
use core::ops::{BitAnd, BitOr, BitXor, Not};
use core::{mem, slice};

#[derive(Eq, PartialEq, Copy, Clone)]
#[repr(C, align(16))]
#[must_use]
pub struct AesBlock(u32, u32, u32, u32);

macro_rules! outer {
    (fn $inner:ident <- $name:ident) => {
        #[inline(always)]
        fn $inner(t0: u32, t1: u32, t2: u32, t3: u32, rk: u32) -> u32 {
            let mut value = rk;
            unsafe {
                value = $name(value, t0, 0);
                value = $name(value, t1, 1);
                value = $name(value, t2, 2);
                value = $name(value, t3, 3);
            }
            value
        }
    };
    (enc: $name:ident, $msg:ident, $rk:ident) => {{
        outer!(fn inner <- $name);
        AesBlock(
            inner($msg.0, $msg.1, $msg.2, $msg.3, $rk.0),
            inner($msg.1, $msg.2, $msg.3, $msg.0, $rk.1),
            inner($msg.2, $msg.3, $msg.0, $msg.1, $rk.2),
            inner($msg.3, $msg.0, $msg.1, $msg.2, $rk.3),
        )
    }};
    (dec: $name:ident, $msg:ident, $rk:ident) => {{
        outer!(fn inner <- $name);
        AesBlock(
            inner($msg.0, $msg.3, $msg.2, $msg.1, $rk.0),
            inner($msg.1, $msg.0, $msg.3, $msg.2, $rk.1),
            inner($msg.2, $msg.1, $msg.0, $msg.3, $rk.2),
            inner($msg.3, $msg.2, $msg.1, $msg.0, $rk.3),
        )
    }};
}

impl From<[u8; 16]> for AesBlock {
    #[inline]
    fn from(value: [u8; 16]) -> Self {
        Self::new(value)
    }
}

impl BitAnd for AesBlock {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(
            self.0 & rhs.0,
            self.1 & rhs.1,
            self.2 & rhs.2,
            self.3 & rhs.3,
        )
    }
}

impl BitOr for AesBlock {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(
            self.0 | rhs.0,
            self.1 | rhs.1,
            self.2 | rhs.2,
            self.3 | rhs.3,
        )
    }
}

impl BitXor for AesBlock {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(
            self.0 ^ rhs.0,
            self.1 ^ rhs.1,
            self.2 ^ rhs.2,
            self.3 ^ rhs.3,
        )
    }
}

impl Not for AesBlock {
    type Output = Self;

    #[inline]
    fn not(self) -> Self::Output {
        Self(!self.0, !self.1, !self.2, !self.3)
    }
}

impl AesBlock {
    #[inline]
    pub const fn new(value: [u8; 16]) -> Self {
        unsafe { mem::transmute(value) }
    }

    #[inline]
    pub fn store_to(self, dst: &mut [u8]) {
        assert!(dst.len() >= 16);
        unsafe {
            dst.as_mut_ptr().cast::<Self>().write_unaligned(self);
        }
    }

    #[inline]
    pub fn zero() -> Self {
        Self(0, 0, 0, 0)
    }

    #[inline]
    #[must_use]
    pub fn is_zero(self) -> bool {
        (self.0 | self.1 | self.2 | self.3) == 0
    }

    /// Performs one round of AES encryption function (`ShiftRows`->`SubBytes`->`MixColumns`->`AddRoundKey`)
    #[inline]
    pub fn enc(self, round_key: Self) -> Self {
        outer!(enc: aes32esmi, self, round_key)
    }

    /// Performs one round of AES encryption function without `MixColumns` (`ShiftRows`->`SubBytes`->`AddRoundKey`)
    #[inline]
    pub fn enc_last(self, round_key: Self) -> Self {
        outer!(enc: aes32esi, self, round_key)
    }

    /// Performs one round of AES decryption function (`InvShiftRows`->`InvSubBytes`->`InvMixColumn`s->`AddRoundKey`)
    #[inline]
    pub fn dec(self, round_key: Self) -> Self {
        outer!(dec: aes32dsmi, self, round_key)
    }

    /// Performs one round of AES decryption function without `InvMixColumn`s (`InvShiftRows`->`InvSubBytes`->`AddRoundKey`)
    #[inline]
    pub fn dec_last(self, round_key: Self) -> Self {
        outer!(dec: aes32dsi, self, round_key)
    }

    /// Performs the `MixColumns` operation
    #[inline]
    pub fn mc(self) -> Self {
        self.dec_last(Self::zero()).enc(Self::zero())
    }

    /// Performs the `InvMixColumn`s operation
    #[inline]
    pub fn imc(self) -> Self {
        self.enc_last(Self::zero()).dec(Self::zero())
    }
}

const RCON: [u32; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

#[inline(always)]
fn sub_word(xor: u32, word: u32) -> u32 {
    outer!(fn inner <- aes32esi);
    inner(word, word, word, word, xor)
}

pub(super) fn keygen_128(key: [u8; 16]) -> [AesBlock; 11] {
    let mut expanded_keys: [AesBlock; 11] = unsafe { mem::zeroed() };

    let keys_ptr: *mut u32 = expanded_keys.as_mut_ptr().cast();
    let columns = unsafe { slice::from_raw_parts_mut(keys_ptr, 44) };

    for (i, chunk) in key.chunks_exact(4).enumerate() {
        columns[i] = u32::from_ne_bytes(chunk.try_into().unwrap());
    }

    for i in (0..40).step_by(4) {
        columns[i + 4] = sub_word(
            columns[i + 0] ^ RCON[i / 4],
            (columns[i + 3]).rotate_right(8),
        );
        columns[i + 5] = columns[i + 1] ^ columns[i + 4];
        columns[i + 6] = columns[i + 2] ^ columns[i + 5];
        columns[i + 7] = columns[i + 3] ^ columns[i + 6];
    }

    expanded_keys
}

pub(super) fn keygen_192(key: [u8; 24]) -> [AesBlock; 13] {
    let mut expanded_keys: [AesBlock; 13] = unsafe { mem::zeroed() };

    let keys_ptr: *mut u32 = expanded_keys.as_mut_ptr().cast();
    let columns = unsafe { slice::from_raw_parts_mut(keys_ptr, 52) };

    for (i, chunk) in key.chunks_exact(4).enumerate() {
        columns[i] = u32::from_ne_bytes(chunk.try_into().unwrap());
    }

    for i in (0..42).step_by(6) {
        columns[i + 6] = sub_word(columns[i + 0] ^ RCON[i / 6], columns[i + 5].rotate_right(8));
        columns[i + 7] = columns[i + 1] ^ columns[i + 6];
        columns[i + 8] = columns[i + 2] ^ columns[i + 7];
        columns[i + 9] = columns[i + 3] ^ columns[i + 8];
        columns[i + 10] = columns[i + 4] ^ columns[i + 9];
        columns[i + 11] = columns[i + 5] ^ columns[i + 10];
    }

    columns[48] = sub_word(columns[42] ^ RCON[7], columns[47].rotate_right(8));
    columns[49] = columns[43] ^ columns[48];
    columns[50] = columns[44] ^ columns[49];
    columns[51] = columns[45] ^ columns[50];

    expanded_keys
}

pub(super) fn keygen_256(key: [u8; 32]) -> [AesBlock; 15] {
    let mut expanded_keys: [AesBlock; 15] = unsafe { mem::zeroed() };

    let keys_ptr: *mut u32 = expanded_keys.as_mut_ptr().cast();
    let columns = unsafe { slice::from_raw_parts_mut(keys_ptr, 60) };

    for (i, chunk) in key.chunks_exact(4).enumerate() {
        columns[i] = u32::from_ne_bytes(chunk.try_into().unwrap());
    }

    for i in (0..48).step_by(8) {
        columns[i + 8] = sub_word(columns[i + 0] ^ RCON[i / 8], columns[i + 7].rotate_right(8));
        columns[i + 9] = columns[i + 1] ^ columns[i + 8];
        columns[i + 10] = columns[i + 2] ^ columns[i + 9];
        columns[i + 11] = columns[i + 3] ^ columns[i + 10];
        columns[i + 12] = sub_word(columns[i + 4], columns[i + 11]);
        columns[i + 13] = columns[i + 5] ^ columns[i + 12];
        columns[i + 14] = columns[i + 6] ^ columns[i + 13];
        columns[i + 15] = columns[i + 7] ^ columns[i + 14];
    }

    columns[56] = sub_word(columns[48] ^ RCON[6], columns[55].rotate_right(8));
    columns[57] = columns[49] ^ columns[56];
    columns[58] = columns[50] ^ columns[57];
    columns[59] = columns[51] ^ columns[58];

    expanded_keys
}
