use crate::{Aes128Dec, Aes128Enc, Aes192Dec, Aes192Enc, Aes256Dec, Aes256Enc};
use cfg_if::cfg_if;
use std::arch::aarch64::*;
use std::mem;
use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not};

#[derive(Copy, Clone)]
#[repr(align(16))]
pub struct AesBlock(uint8x16_t);

impl PartialEq for AesBlock {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        unsafe {
            let result = vceqq_u64(vreinterpretq_u64_u8(self.0), vreinterpretq_u64_u8(other.0));
            vgetq_lane_u64::<0>(result) != 0 && vgetq_lane_u64::<1>(result) != 0
        }
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

impl BitAndAssign for AesBlock {
    #[inline]
    fn bitand_assign(&mut self, rhs: Self) {
        *self = *self & rhs;
    }
}

impl BitOr for AesBlock {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(unsafe { vornq_u8(self.0, rhs.0) })
    }
}

impl BitOrAssign for AesBlock {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
    }
}

impl BitXor for AesBlock {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(unsafe { veorq_u8(self.0, rhs.0) })
    }
}

impl BitXorAssign for AesBlock {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
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
    pub fn store_to(self, dst: &mut [u8]) {
        assert!(dst.len() >= 16);
        unsafe { vst1q_u8(dst.as_mut_ptr(), self.0) };
    }

    #[inline]
    pub fn zero() -> Self {
        Self(unsafe { vdupq_n_u8(0) })
    }

    #[inline]
    pub fn is_zero(self) -> bool {
        unsafe {
            let result = vceqzq_u64(vreinterpretq_u64_u8(self.0));
            vgetq_lane_u64::<0>(result) != 0 && vgetq_lane_u64::<1>(result) != 0
        }
    }

    /// Shifts the AES block by [N] bytes to the right. [N] must be non-negative
    ///
    ///
    /// ```
    /// # use aes::AesBlock;
    ///
    /// let array:[u8;16] = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
    ///
    /// let  aes_block = AesBlock::from(array).shr::<2>();
    /// let  integer = u128::from_be_bytes(array) >> 16;
    ///
    /// assert_eq!(<[u8;16]>::from(aes_block), integer.to_be_bytes());
    /// assert_eq!(integer, 0x0000000102030405060708090a0b0c0d);
    /// ```
    #[inline]
    pub fn shr<const N: i32>(self) -> Self {
        assert!(N >= 0);
        cfg_if! {
            if #[cfg(target_endian = "little")] {
                (u128::from_le_bytes(self.into()) << 8 * N).to_le_bytes().into()
            } else {
                (u128::from_be_bytes(self.into()) >> 8 * N).to_be_bytes().into()
            }
        }
    }

    /// Shifts the AES block by [N] bytes to the left. [N] must be non-negative
    ///
    /// ```
    /// # use aes::AesBlock;
    ///
    /// let array:[u8;16] = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
    ///
    /// let  aes_block = AesBlock::from(array).shl::<2>();
    /// let  integer = u128::from_be_bytes(array) << 16;
    ///
    /// assert_eq!(<[u8;16]>::from(aes_block), integer.to_be_bytes());
    /// assert_eq!(integer, 0x02030405060708090a0b0c0d0e0f0000);
    /// ```
    #[inline]
    pub fn shl<const N: i32>(self) -> Self {
        assert!(N >= 0);
        cfg_if! {
            if #[cfg(target_endian = "little")] {
                (u128::from_le_bytes(self.into()) >> 8 * N).to_le_bytes().into()
            } else {
                (u128::from_be_bytes(self.into()) << 8 * N).to_be_bytes().into()
            }
        }
    }

    fn pre_enc(self, round_key: Self) -> Self {
        Self(unsafe { vaeseq_u8(self.0, round_key.0) })
    }

    /// Performs one round of AES encryption function (ShiftRows->SubBytes->MixColumns->AddRoundKey)
    #[inline]
    pub fn enc(self, round_key: Self) -> Self {
        self.pre_enc(Self::zero()).mc() ^ round_key
    }

    fn pre_dec(self, round_key: Self) -> Self {
        Self(unsafe { vaesdq_u8(self.0, round_key.0) })
    }

    /// Performs one round of AES decryption function (InvShiftRows->InvSubBytes->InvMixColumns->AddRoundKey)
    #[inline]
    pub fn dec(self, round_key: Self) -> Self {
        self.pre_dec(Self::zero()).imc() ^ round_key
    }

    /// Performs one round of AES encryption function without MixColumns (ShiftRows->SubBytes->AddRoundKey)
    #[inline]
    pub fn enc_last(self, round_key: Self) -> Self {
        self.pre_enc(Self::zero()) ^ round_key
    }

    /// Performs one round of AES decryption function without InvMixColumns (InvShiftRows->InvSubBytes->AddRoundKey)
    #[inline]
    pub fn dec_last(self, round_key: Self) -> Self {
        self.pre_dec(Self::zero()) ^ round_key
    }

    /// Performs the MixColumns operation
    #[inline]
    pub fn mc(self) -> Self {
        Self(unsafe { vaesmcq_u8(self.0) })
    }

    /// Performs the InvMixColumns operation
    #[inline]
    pub fn imc(self) -> Self {
        Self(unsafe { vaesimcq_u8(self.0) })
    }
}

unsafe fn sub_word(input: u32) -> u32 {
    let input = vreinterpretq_u8_u32(vdupq_n_u32(input));

    // AES single round encryption (with a "round" key of all zeros)
    let sub_input = vaeseq_u8(input, vdupq_n_u8(0));

    vgetq_lane_u32::<0>(vreinterpretq_u32_u8(sub_input))
}

const RCON: [u32; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

pub(super) fn keygen_128(key: [u8; 16]) -> [AesBlock; 11] {
    unsafe {
        let mut expanded_keys: [AesBlock; 11] = mem::zeroed();

        let keys_ptr: *mut u32 = expanded_keys.as_mut_ptr().cast();
        let columns = std::slice::from_raw_parts_mut(keys_ptr, 44);

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
        let columns = std::slice::from_raw_parts_mut(keys_ptr, 52);

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
        let columns = std::slice::from_raw_parts_mut(keys_ptr, 60);

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

impl Aes128Enc {
    #[inline]
    pub fn encrypt_block(&self, plaintext: AesBlock) -> AesBlock {
        let acc = plaintext;
        let acc = acc.pre_enc(self.round_keys[0]).mc();
        let acc = acc.pre_enc(self.round_keys[1]).mc();
        let acc = acc.pre_enc(self.round_keys[2]).mc();
        let acc = acc.pre_enc(self.round_keys[3]).mc();
        let acc = acc.pre_enc(self.round_keys[4]).mc();
        let acc = acc.pre_enc(self.round_keys[5]).mc();
        let acc = acc.pre_enc(self.round_keys[6]).mc();
        let acc = acc.pre_enc(self.round_keys[7]).mc();
        let acc = acc.pre_enc(self.round_keys[8]).mc();
        acc.pre_enc(self.round_keys[9]) ^ self.round_keys[10]
    }
}

impl Aes128Dec {
    #[inline]
    pub fn decrypt_block(&self, ciphertext: AesBlock) -> AesBlock {
        let acc = ciphertext;
        let acc = acc.pre_dec(self.round_keys[0]).imc();
        let acc = acc.pre_dec(self.round_keys[1]).imc();
        let acc = acc.pre_dec(self.round_keys[2]).imc();
        let acc = acc.pre_dec(self.round_keys[3]).imc();
        let acc = acc.pre_dec(self.round_keys[4]).imc();
        let acc = acc.pre_dec(self.round_keys[5]).imc();
        let acc = acc.pre_dec(self.round_keys[6]).imc();
        let acc = acc.pre_dec(self.round_keys[7]).imc();
        let acc = acc.pre_dec(self.round_keys[8]).imc();
        acc.pre_dec(self.round_keys[9]) ^ self.round_keys[10]
    }
}

impl Aes192Enc {
    #[inline]
    pub fn encrypt_block(&self, plaintext: AesBlock) -> AesBlock {
        let acc = plaintext;
        let acc = acc.pre_enc(self.round_keys[0]).mc();
        let acc = acc.pre_enc(self.round_keys[1]).mc();
        let acc = acc.pre_enc(self.round_keys[2]).mc();
        let acc = acc.pre_enc(self.round_keys[3]).mc();
        let acc = acc.pre_enc(self.round_keys[4]).mc();
        let acc = acc.pre_enc(self.round_keys[5]).mc();
        let acc = acc.pre_enc(self.round_keys[6]).mc();
        let acc = acc.pre_enc(self.round_keys[7]).mc();
        let acc = acc.pre_enc(self.round_keys[8]).mc();
        let acc = acc.pre_enc(self.round_keys[9]).mc();
        let acc = acc.pre_enc(self.round_keys[10]).mc();
        acc.pre_enc(self.round_keys[11]) ^ self.round_keys[12]
    }
}

impl Aes192Dec {
    #[inline]
    pub fn decrypt_block(&self, ciphertext: AesBlock) -> AesBlock {
        let acc = ciphertext;
        let acc = acc.pre_dec(self.round_keys[0]).imc();
        let acc = acc.pre_dec(self.round_keys[1]).imc();
        let acc = acc.pre_dec(self.round_keys[2]).imc();
        let acc = acc.pre_dec(self.round_keys[3]).imc();
        let acc = acc.pre_dec(self.round_keys[4]).imc();
        let acc = acc.pre_dec(self.round_keys[5]).imc();
        let acc = acc.pre_dec(self.round_keys[6]).imc();
        let acc = acc.pre_dec(self.round_keys[7]).imc();
        let acc = acc.pre_dec(self.round_keys[8]).imc();
        let acc = acc.pre_dec(self.round_keys[9]).imc();
        let acc = acc.pre_dec(self.round_keys[10]).imc();
        acc.pre_dec(self.round_keys[11]) ^ self.round_keys[12]
    }
}

impl Aes256Enc {
    #[inline]
    pub fn encrypt_block(&self, plaintext: AesBlock) -> AesBlock {
        let acc = plaintext;
        let acc = acc.pre_enc(self.round_keys[0]).mc();
        let acc = acc.pre_enc(self.round_keys[1]).mc();
        let acc = acc.pre_enc(self.round_keys[2]).mc();
        let acc = acc.pre_enc(self.round_keys[3]).mc();
        let acc = acc.pre_enc(self.round_keys[4]).mc();
        let acc = acc.pre_enc(self.round_keys[5]).mc();
        let acc = acc.pre_enc(self.round_keys[6]).mc();
        let acc = acc.pre_enc(self.round_keys[7]).mc();
        let acc = acc.pre_enc(self.round_keys[8]).mc();
        let acc = acc.pre_enc(self.round_keys[9]).mc();
        let acc = acc.pre_enc(self.round_keys[10]).mc();
        let acc = acc.pre_enc(self.round_keys[11]).mc();
        let acc = acc.pre_enc(self.round_keys[12]).mc();
        acc.pre_enc(self.round_keys[13]) ^ self.round_keys[14]
    }
}

impl Aes256Dec {
    #[inline]
    pub fn decrypt_block(&self, ciphertext: AesBlock) -> AesBlock {
        let acc = ciphertext;
        let acc = acc.pre_dec(self.round_keys[0]).imc();
        let acc = acc.pre_dec(self.round_keys[1]).imc();
        let acc = acc.pre_dec(self.round_keys[2]).imc();
        let acc = acc.pre_dec(self.round_keys[3]).imc();
        let acc = acc.pre_dec(self.round_keys[4]).imc();
        let acc = acc.pre_dec(self.round_keys[5]).imc();
        let acc = acc.pre_dec(self.round_keys[6]).imc();
        let acc = acc.pre_dec(self.round_keys[7]).imc();
        let acc = acc.pre_dec(self.round_keys[8]).imc();
        let acc = acc.pre_dec(self.round_keys[9]).imc();
        let acc = acc.pre_dec(self.round_keys[10]).imc();
        let acc = acc.pre_dec(self.round_keys[11]).imc();
        let acc = acc.pre_dec(self.round_keys[12]).imc();
        acc.pre_dec(self.round_keys[13]) ^ self.round_keys[14]
    }
}
