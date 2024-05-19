use core::arch::asm;
use core::ops::{BitAnd, BitOr, BitXor, Not};
use core::{mem, slice};

macro_rules! _asm {
    (asm: $assembly:expr, $rs1:expr $(,$rs2:expr)?) => {{
        let value: u64;
        unsafe {
            asm!(
                $assembly,
                rd = lateout(reg) value,
                rs1 = in(reg) $rs1,
                $(rs2 = in(reg) $rs2, )?
                options(pure, nomem, nostack)
            );
        }
        value
    }};
    ($instruction:literal, $rs1:expr) => {
        _asm!(asm: concat!($instruction, " {rd},{rs1}"), $rs1)
    };
    ($instruction:literal, $rs1:expr, $rs2:expr) => {
        _asm!(asm: concat!($instruction, " {rd},{rs1},{rs2}"), $rs1, $rs2)
    };
}

#[inline(always)]
fn aes64esm(rs1: u64, rs2: u64) -> u64 {
    _asm!("aes64esm", rs1, rs2)
}

#[inline(always)]
fn aes64es(rs1: u64, rs2: u64) -> u64 {
    _asm!("aes64es", rs1, rs2)
}

#[inline(always)]
fn aes64dsm(rs1: u64, rs2: u64) -> u64 {
    _asm!("aes64dsm", rs1, rs2)
}

#[inline(always)]
fn aes64ds(rs1: u64, rs2: u64) -> u64 {
    _asm!("aes64ds", rs1, rs2)
}

#[inline(always)]
fn aes64im(rs1: u64) -> u64 {
    _asm!("aes64im", rs1)
}

#[inline(always)]
fn aes64ks1i(rs1: u64, rnum: u8) -> u64 {
    macro_rules! case {
        ($imm_0_until_10:expr) => {
            _asm!(asm: concat!("aes64ks1i {rd},{rs1},", $imm_0_until_10), rs1)
        }
    }
    match rnum {
        0 => case!(0),
        1 => case!(1),
        2 => case!(2),
        3 => case!(3),
        4 => case!(4),
        5 => case!(5),
        6 => case!(6),
        7 => case!(7),
        8 => case!(8),
        9 => case!(9),
        10 => case!(10),
        _ => unreachable!(),
    }
}

#[inline(always)]
fn aes64ks2(rs1: u64, rs2: u64) -> u64 {
    _asm!("aes64ks2", rs1, rs2)
}

#[derive(Copy, Clone, Eq, PartialEq)]
#[repr(C, align(16))]
pub struct AesBlock(u64, u64);

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
    pub fn store_to(self, dst: &mut [u8]) {
        assert!(dst.len() >= 16);
        unsafe {
            *dst.as_mut_ptr().cast::<[u8; 16]>() = mem::transmute(self);
        }
    }

    #[inline]
    pub fn zero() -> Self {
        Self(0, 0)
    }

    #[inline]
    pub fn is_zero(self) -> bool {
        (self.0 | self.1) == 0
    }

    /// Performs one round of AES encryption function (ShiftRows->SubBytes->MixColumns->AddRoundKey)
    #[inline]
    pub fn enc(self, round_key: Self) -> Self {
        Self(
            aes64esm(self.0, self.1) ^ round_key.0,
            aes64esm(self.1, self.0) ^ round_key.1,
        )
    }

    /// Performs one round of AES decryption function (InvShiftRows->InvSubBytes->InvMixColumns->AddRoundKey)
    #[inline]
    pub fn dec(self, round_key: Self) -> Self {
        Self(
            aes64dsm(self.0, self.1) ^ round_key.0,
            aes64dsm(self.1, self.0) ^ round_key.1,
        )
    }

    /// Performs one round of AES encryption function without MixColumns (ShiftRows->SubBytes->AddRoundKey)
    #[inline]
    pub fn enc_last(self, round_key: Self) -> Self {
        Self(
            aes64es(self.0, self.1) ^ round_key.0,
            aes64es(self.1, self.0) ^ round_key.1,
        )
    }

    /// Performs one round of AES decryption function without InvMixColumns (InvShiftRows->InvSubBytes->AddRoundKey)
    #[inline]
    pub fn dec_last(self, round_key: Self) -> Self {
        Self(
            aes64ds(self.0, self.1) ^ round_key.0,
            aes64ds(self.1, self.0) ^ round_key.1,
        )
    }

    /// Performs the MixColumns operation
    #[inline]
    pub fn mc(self) -> Self {
        let (tmp0, tmp1) = (aes64ds(self.0, self.1), aes64ds(self.1, self.0));
        Self(aes64esm(tmp0, tmp1), aes64esm(tmp1, tmp0))
    }

    /// Performs the InvMixColumns operation
    #[inline]
    pub fn imc(self) -> Self {
        Self(aes64im(self.0), aes64im(self.1))
    }
}

#[inline(always)]
fn keyexp_128(prev: AesBlock, rnum: u8) -> AesBlock {
    let tmp = aes64ks2(aes64ks1i(prev.1, rnum), prev.0);
    AesBlock(tmp, aes64ks2(tmp, prev.1))
}

#[inline(always)]
fn keyexp_256_1(prev0: AesBlock, prev1: AesBlock, rnum: u8) -> AesBlock {
    let tmp = aes64ks2(aes64ks1i(prev1.1, rnum), prev0.0);
    AesBlock(tmp, aes64ks2(tmp, prev0.1))
}

#[inline(always)]
fn keyexp_256_2(prev0: AesBlock, prev1: AesBlock) -> AesBlock {
    let tmp = aes64ks2(aes64ks1i(prev1.1, 10), prev0.0);
    AesBlock(tmp, aes64ks2(tmp, prev0.1))
}

pub(super) fn keygen_128(key: [u8; 16]) -> [AesBlock; 11] {
    let key0 = AesBlock::from(key);
    let key1 = keyexp_128(key0, 0);
    let key2 = keyexp_128(key1, 1);
    let key3 = keyexp_128(key2, 2);
    let key4 = keyexp_128(key3, 3);
    let key5 = keyexp_128(key4, 4);
    let key6 = keyexp_128(key5, 5);
    let key7 = keyexp_128(key6, 6);
    let key8 = keyexp_128(key7, 7);
    let key9 = keyexp_128(key8, 8);
    let key10 = keyexp_128(key9, 9);

    [
        key0, key1, key2, key3, key4, key5, key6, key7, key8, key9, key10,
    ]
}

pub(super) fn keygen_192(key: [u8; 24]) -> [AesBlock; 13] {
    let mut expanded_keys: [AesBlock; 13] = unsafe { mem::zeroed() };

    let keys_ptr: *mut u64 = expanded_keys.as_mut_ptr().cast();
    let columns = unsafe { slice::from_raw_parts_mut(keys_ptr, 26) };

    for (i, chunk) in key.chunks_exact(8).enumerate() {
        columns[i] = u64::from_ne_bytes(chunk.try_into().unwrap());
    }

    for i in (0..21).step_by(3) {
        columns[i + 3] = aes64ks2(aes64ks1i(columns[i + 2], (i / 3) as u8), columns[i + 0]);
        columns[i + 4] = aes64ks2(columns[i + 3], columns[i + 1]);
        columns[i + 5] = aes64ks2(columns[i + 4], columns[i + 2]);
    }

    columns[24] = aes64ks2(aes64ks1i(columns[23], 7), columns[21]);
    columns[25] = aes64ks2(columns[24], columns[22]);

    expanded_keys
}

pub(super) fn keygen_256(key: [u8; 32]) -> [AesBlock; 15] {
    let key0 = AesBlock::try_from(&key[..16]).unwrap();
    let key1 = AesBlock::try_from(&key[16..]).unwrap();

    let key2 = keyexp_256_1(key0, key1, 0);
    let key3 = keyexp_256_2(key1, key2);
    let key4 = keyexp_256_1(key2, key3, 1);
    let key5 = keyexp_256_2(key3, key4);
    let key6 = keyexp_256_1(key4, key5, 2);
    let key7 = keyexp_256_2(key5, key6);
    let key8 = keyexp_256_1(key6, key7, 3);
    let key9 = keyexp_256_2(key7, key8);
    let key10 = keyexp_256_1(key8, key9, 4);
    let key11 = keyexp_256_2(key9, key10);
    let key12 = keyexp_256_1(key10, key11, 5);
    let key13 = keyexp_256_2(key11, key12);
    let key14 = keyexp_256_1(key12, key13, 6);

    [
        key0, key1, key2, key3, key4, key5, key6, key7, key8, key9, key10, key11, key12, key13,
        key14,
    ]
}
