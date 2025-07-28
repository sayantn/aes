[![Actions Status](https://github.com/sayantn/aes/actions/workflows/rust.yml/badge.svg)](https://github.com/sayantn/aes/actions)

This is a pure-Rust platform-agnostic [AES](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf) library, that
is focused on reusability and optimal performance.

This library guarantees the best performance on the `target_cpu` (if correctly specified). This currently has 7
implementations, among which it automatically decides the best (most performant) using Cargo's `target_feature` flags.

# The implementations and their requirements are:

- AES-NI (with Vector AES for 2- and 4- blocks) => requires a Nightly Compiler, the `nightly` feature to be enabled, and
  compiling for x86(64) with the `avx512f` and `vaes` target_feature flags set.
- AES-NI (with Vector AES for 2-blocks) => requires a Nightly Compiler, the `nightly` feature to be enabled, and
  compiling for x86(64) with the `vaes` target_feature flag set.
- AES-NI => requires compiling for x86(64) with the `sse4.1` and `aes` target_feature flags set.
- AES-Neon => requires compiling for AArch64 or ARM64EC or ARM-v8 with the `aes` target_feature flag set (
  ARM-v8 requires a Nightly compiler and the `nightly` feature to be enabled).
- AES-RV => Requires a Nightly compiler, the `nightly` feature to be enabled and compiling for RISC-V RV64 or RV32 with
  the `zkne` and `zknd` target-features enabled (performance considerably improves with the `unaligned-scalar-mem`
  target-feature enabled)
- Software AES => fallback implementation based on Rijmen and Daemen's `optimized` implementation (available
  on [their website](https://web.archive.org/web/20050828204927/http://www.iaik.tu-graz.ac.at/research/krypto/AES/old/%7Erijmen/rijndael/)).
- Constant-time Software AES => Much slower than Software AES, but is constant-time, which can be important in some
  scenarios. Enabled by the `constant-time` feature. It is worth noting that all the accelerated AES implementations are
  constant-time, so this only comes into play when no accelerated version is found.

If you are unsure about the target_feature flags to set, use `target_cpu=native` (if not cross-compiling) in
the `RUSTFLAGS` environment variable, and use the `nightly` feature only if you are using a nightly compiler.

# Warning

Using the wrong `target_feature` flags may lead to the binary crashing due to an "Unknown Instruction" error. This
library uses these flags to use the CPU intrinsics to maximize performance. If you are unsure what `target_feature`s are
supported on your CPU, use the command

````bash
    rustc --print cfg -C target-cpu=native
````

Using the `nightly` feature when not using a nightly compiler can lead to compile failures, so use this only if you
are using a nightly compiler.
