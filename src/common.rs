use crate::{AesBlock, AesBlockX2, AesBlockX4};
use core::fmt;
use core::fmt::{Binary, Debug, Display, Formatter, LowerHex, UpperHex};
use core::ops::{BitAndAssign, BitOrAssign, BitXorAssign};

#[allow(unused)]
#[inline(always)]
pub(crate) const fn array_from_slice<const N: usize>(value: &[u8], offset: usize) -> [u8; N] {
    debug_assert!(value.len() - offset >= N);
    unsafe { *value.as_ptr().add(offset).cast() }
}

impl PartialEq for AesBlock {
    fn eq(&self, other: &Self) -> bool {
        (*self ^ *other).is_zero()
    }
}

impl Eq for AesBlock {}

impl PartialEq for AesBlockX2 {
    fn eq(&self, other: &Self) -> bool {
        (*self ^ *other).is_zero()
    }
}

impl Eq for AesBlockX2 {}

impl PartialEq for AesBlockX4 {
    fn eq(&self, other: &Self) -> bool {
        (*self ^ *other).is_zero()
    }
}

impl Eq for AesBlockX4 {}

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
    impl From<[u8; $key_len]> for $name {
        #[inline]
        fn from(value: [u8; $key_len]) -> Self {
            Self::new(value)
        }
    }

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
            if value.len() >= $key_len {
                Ok(array_from_slice(value, 0).into())
            } else {
                Err(value.len())
            }
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
