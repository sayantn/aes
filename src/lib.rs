#![doc = include_str!("../README.md")]
#![no_std]
#![cfg_attr(
    all(
        feature = "nightly",
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "vaes"
    ),
    feature(stdarch_x86_avx512)
)]
#![cfg_attr(
    all(
        feature = "nightly",
        target_arch = "arm",
        target_feature = "v8",
        target_feature = "aes",
    ),
    feature(stdarch_arm_neon_intrinsics)
)]
#![cfg_attr(
    all(
        feature = "nightly",
        any(target_arch = "riscv32", target_arch = "riscv64"),
        target_feature = "zkne",
        target_feature = "zknd"
    ),
    feature(riscv_ext_intrinsics)
)]
#![cfg_attr(
    all(
        feature = "nightly",
        any(target_arch = "powerpc", target_arch = "powerpc64"),
        target_feature = "power8-crypto"
    ),
    feature(
        stdarch_powerpc,
        link_llvm_intrinsics,
        abi_unadjusted,
        simd_ffi,
        core_intrinsics
    )
)]
#![deny(warnings)]
#![allow(
    stable_features, // TODO: remove after 1.89 rolls out
    internal_features,
    clippy::identity_op,
    clippy::inline_always,
    clippy::similar_names,
    clippy::doc_markdown,
    clippy::wildcard_imports
)]

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "aes",
    ))] {
        #[path = "aes_x86.rs"]
        mod aes;
    } else if #[cfg(all(
        any(
            target_arch = "aarch64",
            target_arch = "arm64ec",
            all(feature = "nightly", target_arch = "arm", target_feature = "v8")
        ),
        target_feature = "aes",
    ))] {
        #[path = "aes_arm.rs"]
        mod aes;
    } else if #[cfg(all(
        feature = "nightly",
        target_arch = "riscv64",
        target_feature = "zkne",
        target_feature = "zknd"
    ))] {
        #[path = "aes_riscv64.rs"]
        mod aes;
    } else if #[cfg(all(
        feature = "nightly",
        target_arch = "riscv32",
        target_feature = "zkne",
        target_feature = "zknd"
    ))] {
        #[path = "aes_riscv32.rs"]
        mod aes;
    } else if #[cfg(all(
        feature = "nightly",
        any(target_arch = "powerpc", target_arch = "powerpc64"),
        target_feature = "power8-crypto"
    ))] {
        #[path = "aes_ppc.rs"]
        mod aes;
    } else if #[cfg(feature = "constant-time")] {
        #[path = "aes_bitslice.rs"]
        mod aes;
    } else {
        #[path = "aes_table_based.rs"]
        mod aes;
    }
}

cfg_if! {
    if #[cfg(all(
        feature = "nightly",
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "vaes"
    ))] {
        #[path = "aesni_x2.rs"]
        mod aesx2;
    } else {
        #[path = "aesdefault_x2.rs"]
        mod aesx2;
    }
}

cfg_if! {
    if #[cfg(all(
        feature = "nightly",
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "avx512f",
        target_feature = "vaes"
    ))] {
        #[path = "aesni_x4.rs"]
        mod aesx4;
    } else {
        #[path = "aesdefault_x4.rs"]
        mod aesx4;
    }
}

pub use aes::AesBlock;
pub use aesx2::AesBlockX2;
pub use aesx4::AesBlockX4;

use aes::*;

mod blockcipher;
mod common;
pub use blockcipher::*;

#[cfg(test)]
mod tests;
