use crate::common::array_from_slice;
#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;
use core::mem;
use core::ops::{BitAnd, BitOr, BitXor, Not};

#[derive(Copy, Clone)]
#[repr(transparent)]
#[must_use]
pub struct AesBlock(pub(super) __m128i);

impl BitAnd for AesBlock {
    type Output = Self;

    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(unsafe { _mm_and_si128(self.0, rhs.0) })
    }
}

impl BitOr for AesBlock {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(unsafe { _mm_or_si128(self.0, rhs.0) })
    }
}

impl BitXor for AesBlock {
    type Output = Self;

    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(unsafe { _mm_xor_si128(self.0, rhs.0) })
    }
}

impl Not for AesBlock {
    type Output = Self;

    #[inline]
    fn not(self) -> Self::Output {
        Self(unsafe { _mm_xor_si128(self.0, _mm_set1_epi64x(-1)) })
    }
}

impl AesBlock {
    #[inline]
    pub const fn new(value: [u8; 16]) -> Self {
        // using transmute in simd is safe
        unsafe { mem::transmute(value) }
    }

    #[inline]
    pub const fn to_bytes(self) -> [u8; 16] {
        unsafe { mem::transmute(self) }
    }

    #[inline]
    #[must_use]
    pub fn is_zero(self) -> bool {
        unsafe { _mm_testz_si128(self.0, self.0) == 1 }
    }

    /// Performs one round of AES encryption function (`ShiftRows`->`SubBytes`->`MixColumns`->`AddRoundKey`)
    #[inline]
    pub fn enc(self, round_key: Self) -> Self {
        Self(unsafe { _mm_aesenc_si128(self.0, round_key.0) })
    }

    /// Performs one round of AES decryption function (`InvShiftRows`->`InvSubBytes`->`InvMixColumns`->`AddRoundKey`)
    #[inline]
    pub fn dec(self, round_key: Self) -> Self {
        Self(unsafe { _mm_aesdec_si128(self.0, round_key.0) })
    }

    /// Performs one round of AES encryption function without `MixColumns` (`ShiftRows`->`SubBytes`->`AddRoundKey`)
    #[inline]
    pub fn enc_last(self, round_key: Self) -> Self {
        Self(unsafe { _mm_aesenclast_si128(self.0, round_key.0) })
    }

    /// Performs one round of AES decryption function without `InvMixColumns` (`InvShiftRows`->`InvSubBytes`->`AddRoundKey`)
    #[inline]
    pub fn dec_last(self, round_key: Self) -> Self {
        Self(unsafe { _mm_aesdeclast_si128(self.0, round_key.0) })
    }

    /// Performs the `MixColumns` operation
    #[inline]
    pub fn mc(self) -> Self {
        self.dec_last(Self::zero()).enc(Self::zero())
    }

    /// Performs the `InvMixColumns` operation
    #[inline]
    pub fn imc(self) -> Self {
        Self(unsafe { _mm_aesimc_si128(self.0) })
    }

    #[inline(always)]
    fn shl<const N: i32>(self) -> Self {
        Self(unsafe { _mm_bslli_si128::<N>(self.0) })
    }

    #[inline(always)]
    fn mix(self) -> Self {
        let temp = self ^ self.shl::<4>();
        temp ^ temp.shl::<8>()
    }

    #[inline(always)]
    fn keygenassist<const RCON: i32, const SHUFFLE: i32>(self) -> Self {
        Self(unsafe { _mm_shuffle_epi32::<SHUFFLE>(_mm_aeskeygenassist_si128::<RCON>(self.0)) })
    }
}

// The key expansion code is taken from the Intel whitepaper

fn keyexp_128<const RCON: i32>(prev_rkey: AesBlock) -> AesBlock {
    prev_rkey.mix() ^ prev_rkey.keygenassist::<RCON, 0xff>()
}

fn keyexp_192<const RCON1: i32, const RCON2: i32>(
    (state1, state2): &mut (AesBlock, AesBlock),
) -> (AesBlock, AesBlock, AesBlock) {
    #[inline(always)]
    fn fwd<const RCON: i32>(state1: &mut AesBlock, state2: &mut AesBlock) {
        *state1 = state1.mix() ^ state2.keygenassist::<RCON, 0x55>();
        *state2 ^= state2.shl::<4>() ^ AesBlock(unsafe { _mm_shuffle_epi32::<0xff>(state1.0) });
    }
    let prev_state = state2.0;

    fwd::<RCON1>(state1, state2);

    let key1 = unsafe { _mm_unpacklo_epi64(prev_state, state1.0) };
    let key2 = unsafe { _mm_alignr_epi8::<8>(state2.0, state1.0) };

    fwd::<RCON2>(state1, state2);

    (AesBlock(key1), AesBlock(key2), *state1)
}

fn keyexp_256_1<const RCON: i32>(prev0: AesBlock, prev1: AesBlock) -> AesBlock {
    prev0.mix() ^ prev1.keygenassist::<RCON, 0xff>()
}

fn keyexp_256_2(prev0: AesBlock, prev1: AesBlock) -> AesBlock {
    prev0.mix() ^ prev1.keygenassist::<0, 0xaa>()
}

pub(super) fn keygen_128(key: [u8; 16]) -> [AesBlock; 11] {
    let key0 = AesBlock::from(key);
    let key1 = keyexp_128::<0x01>(key0);
    let key2 = keyexp_128::<0x02>(key1);
    let key3 = keyexp_128::<0x04>(key2);
    let key4 = keyexp_128::<0x08>(key3);
    let key5 = keyexp_128::<0x10>(key4);
    let key6 = keyexp_128::<0x20>(key5);
    let key7 = keyexp_128::<0x40>(key6);
    let key8 = keyexp_128::<0x80>(key7);
    let key9 = keyexp_128::<0x1b>(key8);
    let key10 = keyexp_128::<0x36>(key9);

    [
        key0, key1, key2, key3, key4, key5, key6, key7, key8, key9, key10,
    ]
}

pub(super) fn keygen_192(key: [u8; 24]) -> [AesBlock; 13] {
    let key0 = AesBlock::from(array_from_slice(&key, 0));
    let mut key_block = [0; 16];
    key_block[..8].copy_from_slice(&key[16..]);
    key_block[8..].fill(0);

    let mut state = (key0, AesBlock::from(key_block));

    let (key1, key2, key3) = keyexp_192::<0x01, 0x02>(&mut state);
    let (key4, key5, key6) = keyexp_192::<0x04, 0x08>(&mut state);
    let (key7, key8, key9) = keyexp_192::<0x10, 0x20>(&mut state);
    let (key10, key11, key12) = keyexp_192::<0x40, 0x80>(&mut state);

    [
        key0, key1, key2, key3, key4, key5, key6, key7, key8, key9, key10, key11, key12,
    ]
}

pub(super) fn keygen_256(key: [u8; 32]) -> [AesBlock; 15] {
    let key0 = AesBlock::from(array_from_slice(&key, 0));
    let key1 = AesBlock::from(array_from_slice(&key, 16));

    let key2 = keyexp_256_1::<0x01>(key0, key1);
    let key3 = keyexp_256_2(key1, key2);
    let key4 = keyexp_256_1::<0x02>(key2, key3);
    let key5 = keyexp_256_2(key3, key4);
    let key6 = keyexp_256_1::<0x04>(key4, key5);
    let key7 = keyexp_256_2(key5, key6);
    let key8 = keyexp_256_1::<0x08>(key6, key7);
    let key9 = keyexp_256_2(key7, key8);
    let key10 = keyexp_256_1::<0x10>(key8, key9);
    let key11 = keyexp_256_2(key9, key10);
    let key12 = keyexp_256_1::<0x20>(key10, key11);
    let key13 = keyexp_256_2(key11, key12);
    let key14 = keyexp_256_1::<0x40>(key12, key13);

    [
        key0, key1, key2, key3, key4, key5, key6, key7, key8, key9, key10, key11, key12, key13,
        key14,
    ]
}
