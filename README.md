This is a pure-Rust platform-agnostic AES library, that is focused on reusability and optimal performance.

This library guarantees the best performance on the `target_cpu` (if correctly specified). This currently has 5 implementations, among which it automatically decides the best (most performant) using Cargo's `target_feature` flags. 

# The implementations and their requirements are:
  -  AES-NI (with Vector AES for 2- and 4- blocks) => requires a Nightly Compiler, the `vaes` feature to be enabled, and compiling for x86(64) with the `avx512vl` and `vaes` target_feature flags set.
  -  AES-NI (with Vector AES for 4-blocks)         => requires a Nightly Compiler, the `vaes` feature to be enabled, and compiling for x86(64) with the `avx512f` and `vaes` target_feature flags set.
  -  AES-NI   => requires compiling for x86(64) with the `sse4.1` and `aes` target_feature flags set.
  -  AES-Neon => requires compiling for AArch64 with the `aes` target_feature flag set.
  -  Software AES => fallback implementation based on Rijmen and Daemen's `optimized` implementation (available on [their website](https://web.archive.org/web/20050828204927/http://www.iaik.tu-graz.ac.at/research/krypto/AES/old/%7Erijmen/rijndael/))

If you are unsure about the target_feature flags to set, use `target_cpu=native` (if not cross-compiling) in the `RUSTFLAGS` environment variable

# Warning
  Using the wrong `target_feature` flags may lead to the binary crashing due to an "Unknown Instruction" error. This library uses these flags to use the CPU intrinsics to maximize performance. If you are unsure what `target_feature`s are supported on your CPU, use the command

    rustc --print cfg -C target-cpu=native