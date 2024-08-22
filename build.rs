#![cfg_attr(
    all(feature = "nightly", target_arch = "arm", target_feature = "v8"),
    feature(stdarch_arm_feature_detection)
)]
#![cfg_attr(
    all(
        feature = "nightly",
        any(target_arch = "riscv64", target_arch = "riscv32")
    ),
    feature(stdarch_riscv_feature_detection)
)]
use std::arch::*;

fn select_impl() -> &'static str {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if is_x86_feature_detected!("aes") && is_x86_feature_detected!("sse4.1") {
        return "x86";
    }
    #[cfg(any(target_arch = "aarch64", target_arch = "arm64ec"))]
    if is_aarch64_feature_detected!("aes") {
        return "neon";
    }
    #[cfg(all(feature = "nightly", target_arch = "arm", target_feature = "v8"))]
    if is_arm_feature_detected!("aes") {
        return "arm-neon";
    }
    #[cfg(all(
        feature = "nightly",
        any(target_arch = "riscv64", target_arch = "riscv32")
    ))]
    if is_riscv_feature_detected!("zkne") && is_riscv_feature_detected!("zknd") {
        return "risc-v";
    }
    "software"
}

fn select_x2_impl() -> &'static str {
    #[cfg(all(feature = "nightly", any(target_arch = "x86", target_arch = "x86_64")))]
    if is_x86_feature_detected!("vaes") {
        return "vaes";
    }
    "tuple"
}

fn select_x4_impl() -> &'static str {
    #[cfg(all(feature = "nightly", any(target_arch = "x86", target_arch = "x86_64")))]
    if is_x86_feature_detected!("avx512f") {
        return "avx512f";
    }
    "tuple"
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    println!(
        "cargo:rustc-check-cfg=cfg(aes_impl, values(\"x86\", \"neon\", \"arm-neon\", \"risc-v\", \"software\"))"
    );
    println!("cargo:rustc-check-cfg=cfg(aes_x2_impl, values(\"vaes\", \"tuple\"))");
    println!("cargo:rustc-check-cfg=cfg(aes_x4_impl, values(\"avx512f\", \"tuple\"))");

    println!("cargo:rustc-cfg=aes_impl=\"{}\"", select_impl());
    println!("cargo:rustc-cfg=aes_x2_impl=\"{}\"", select_x2_impl());
    println!("cargo:rustc-cfg=aes_x4_impl=\"{}\"", select_x4_impl());
}
