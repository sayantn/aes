#[cfg(not(target_arch = "arm"))]
use core::arch::aarch64::*;
#[cfg(target_arch = "arm")]
use core::arch::arm::*;
use core::ops::{BitAnd, BitOr, BitXor, Not};
use core::{mem, slice};

#[derive(Copy, Clone)]
#[repr(transparent)]
#[must_use]
pub struct AesBlock(uint8x16_t);

impl PartialEq for AesBlock {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        (*self ^ *other).is_zero()
    }
}

impl Eq for AesBlock {}

impl From<[u8; 16]> for AesBlock {
    #[inline]
    fn from(value: [u8; 16]) -> Self {
        Self(unsafe { vld1q_u8(value.as_ptr()) })
    }
}

impl BitAnd for AesBlock {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(unsafe { vandq_u8(self.0, rhs.0) })
    }
}

impl BitOr for AesBlock {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(unsafe { vorrq_u8(self.0, rhs.0) })
    }
}

impl BitXor for AesBlock {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(unsafe { veorq_u8(self.0, rhs.0) })
    }
}

impl Not for AesBlock {
    type Output = Self;

    #[inline]
    fn not(self) -> Self::Output {
        Self(unsafe { vmvnq_u8(self.0) })
    }
}

impl AesBlock {
    #[inline]
    pub const fn new(value: [u8; 16]) -> Self {
        // using transmute in simd is safe
        unsafe { mem::transmute(value) }
    }

    #[inline]
    pub fn store_to(self, dst: &mut [u8]) {
        assert!(dst.len() >= 16);
        unsafe { vst1q_u8(dst.as_mut_ptr(), self.0) };
    }

    #[inline]
    pub fn zero() -> Self {
        Self(unsafe { vdupq_n_u8(0) })
    }

    #[inline]
    #[must_use]
    pub fn is_zero(self) -> bool {
        #[cfg(not(target_arch = "arm"))]
        unsafe {
            let a = vreinterpretq_u64_u8(self.0);
            (vgetq_lane_u64::<0>(a) | vgetq_lane_u64::<1>(a)) == 0
        }
        #[cfg(target_arch = "arm")]
        unsafe {
            let a = vreinterpretq_u32_u8(self.0);
            (vgetq_lane_u32::<0>(a)
                | vgetq_lane_u32::<1>(a)
                | vgetq_lane_u32::<2>(a)
                | vgetq_lane_u32::<3>(a))
                == 0
        }
    }

    #[inline(always)]
    fn aese(self, round_key: Self) -> Self {
        Self(unsafe { vaeseq_u8(self.0, round_key.0) })
    }

    #[inline(always)]
    pub(crate) fn pre_enc(self, round_key: Self) -> Self {
        self.aese(round_key).mc()
    }

    /// Performs one round of AES encryption function (`ShiftRows`->`SubBytes`->`MixColumns`->`AddRoundKey`)
    #[inline]
    pub fn enc(self, round_key: Self) -> Self {
        self.pre_enc(Self::zero()) ^ round_key
    }

    #[inline(always)]
    fn aesd(self, round_key: Self) -> Self {
        Self(unsafe { vaesdq_u8(self.0, round_key.0) })
    }

    #[inline(always)]
    pub(crate) fn pre_dec(self, round_key: Self) -> Self {
        self.aesd(round_key).imc()
    }

    /// Performs one round of AES decryption function (`InvShiftRows`->`InvSubBytes`->`InvMixColumn`s->`AddRoundKey`)
    #[inline]
    pub fn dec(self, round_key: Self) -> Self {
        self.pre_dec(Self::zero()) ^ round_key
    }

    /// Performs one round of AES encryption function without `MixColumns` (`ShiftRows`->`SubBytes`->`AddRoundKey`)
    #[inline]
    pub fn enc_last(self, round_key: Self) -> Self {
        self.aese(Self::zero()) ^ round_key
    }

    /// Performs one round of AES decryption function without `InvMixColumn`s (`InvShiftRows`->`InvSubBytes`->`AddRoundKey`)
    #[inline]
    pub fn dec_last(self, round_key: Self) -> Self {
        self.aesd(Self::zero()) ^ round_key
    }

    /// Performs the `MixColumns` operation
    #[inline]
    pub fn mc(self) -> Self {
        Self(unsafe { vaesmcq_u8(self.0) })
    }

    /// Performs the `InvMixColumn`s operation
    #[inline]
    pub fn imc(self) -> Self {
        Self(unsafe { vaesimcq_u8(self.0) })
    }
}

#[inline(always)]
unsafe fn sub_word(input: u32) -> u32 {
    let input = vreinterpretq_u8_u32(vdupq_n_u32(input));

    // AES single round encryption (with a round key of all zeros)
    let sub_input = vaeseq_u8(input, vdupq_n_u8(0));

    vgetq_lane_u32::<0>(vreinterpretq_u32_u8(sub_input))
}

const RCON: [u32; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

pub(super) fn keygen_128(key: [u8; 16]) -> [AesBlock; 11] {
    unsafe {
        let mut expanded_keys: [AesBlock; 11] = mem::zeroed();

        let keys_ptr: *mut u32 = expanded_keys.as_mut_ptr().cast();
        let columns = slice::from_raw_parts_mut(keys_ptr, 44);

        for (i, chunk) in key.chunks_exact(4).enumerate() {
            columns[i] = u32::from_ne_bytes(chunk.try_into().unwrap());
        }

        for i in (0..40).step_by(4) {
            columns[i + 4] =
                columns[i + 0] ^ sub_word(columns[i + 3]).rotate_right(8) ^ RCON[i / 4];
            columns[i + 5] = columns[i + 1] ^ columns[i + 4];
            columns[i + 6] = columns[i + 2] ^ columns[i + 5];
            columns[i + 7] = columns[i + 3] ^ columns[i + 6];
        }

        expanded_keys
    }
}

pub(super) fn keygen_192(key: [u8; 24]) -> [AesBlock; 13] {
    unsafe {
        let mut expanded_keys: [AesBlock; 13] = mem::zeroed();

        let keys_ptr: *mut u32 = expanded_keys.as_mut_ptr().cast();
        let columns = slice::from_raw_parts_mut(keys_ptr, 52);

        for (i, chunk) in key.chunks_exact(4).enumerate() {
            columns[i] = u32::from_ne_bytes(chunk.try_into().unwrap());
        }

        for i in (0..42).step_by(6) {
            columns[i + 6] =
                columns[i + 0] ^ sub_word(columns[i + 5]).rotate_right(8) ^ RCON[i / 6];
            columns[i + 7] = columns[i + 1] ^ columns[i + 6];
            columns[i + 8] = columns[i + 2] ^ columns[i + 7];
            columns[i + 9] = columns[i + 3] ^ columns[i + 8];
            columns[i + 10] = columns[i + 4] ^ columns[i + 9];
            columns[i + 11] = columns[i + 5] ^ columns[i + 10];
        }

        columns[48] = columns[42] ^ sub_word(columns[47]).rotate_right(8) ^ RCON[7];
        columns[49] = columns[43] ^ columns[48];
        columns[50] = columns[44] ^ columns[49];
        columns[51] = columns[45] ^ columns[50];

        expanded_keys
    }
}

pub(super) fn keygen_256(key: [u8; 32]) -> [AesBlock; 15] {
    unsafe {
        let mut expanded_keys: [AesBlock; 15] = mem::zeroed();

        let keys_ptr: *mut u32 = expanded_keys.as_mut_ptr().cast();
        let columns = slice::from_raw_parts_mut(keys_ptr, 60);

        for (i, chunk) in key.chunks_exact(4).enumerate() {
            columns[i] = u32::from_ne_bytes(chunk.try_into().unwrap());
        }

        for i in (0..48).step_by(8) {
            columns[i + 8] =
                columns[i + 0] ^ sub_word(columns[i + 7]).rotate_right(8) ^ RCON[i / 8];
            columns[i + 9] = columns[i + 1] ^ columns[i + 8];
            columns[i + 10] = columns[i + 2] ^ columns[i + 9];
            columns[i + 11] = columns[i + 3] ^ columns[i + 10];
            columns[i + 12] = columns[i + 4] ^ sub_word(columns[i + 11]);
            columns[i + 13] = columns[i + 5] ^ columns[i + 12];
            columns[i + 14] = columns[i + 6] ^ columns[i + 13];
            columns[i + 15] = columns[i + 7] ^ columns[i + 14];
        }

        columns[56] = columns[48] ^ sub_word(columns[55]).rotate_right(8) ^ RCON[6];
        columns[57] = columns[49] ^ columns[56];
        columns[58] = columns[50] ^ columns[57];
        columns[59] = columns[51] ^ columns[58];

        expanded_keys
    }
}
