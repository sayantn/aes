This is a pure-Rust platform-agnostic [AES](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf) library, that
is focused on reusability and optimal performance.

This library guarantees the best performance on the `target-cpu` (if correctly specified). This currently has 6
implementations, among which it automatically decides the best (most performant) using Cargo's `target-feature` flags.

# The implementations and their requirements are:

- AES-NI (with Vector AES for 2- and 4- blocks) => requires a Nightly Compiler, the `nightly` feature to be enabled, and
  compiling for x86(64) with the `avx512f` and `vaes` target-feature flags set.
- AES-NI (with Vector AES for 2-blocks) => requires a Nightly Compiler, the `nightly` feature to be enabled, and
  compiling for x86(64) with the `vaes` target-feature flag set. (although `vaes` is a AVX-512 feature, some AlderLake
  CPUs have `vaes` without AVX-512 support)
- AES-NI => requires compiling for x86(64) with the `sse4.1` and `aes` target-feature flags set.
- AES-Neon => requires compiling for AArch64 or ARM64EC or ARM-v8 with the `aes` target-feature flag set (ARM-v8
  requires a Nightly compiler and the `nightly` feature to be enabled) .
- AES-RV64 => requires a Nightly compiler, the `nightly` feature to be enabled, and compiling for RISC-V RV64 with
  the `zkne` and `zknd` target-feature flags set.
- Software AES => fallback implementation based on Rijmen and Daemen's `optimized` implementation (available
  on [their website](https://web.archive.org/web/20050828204927/http://www.iaik.tu-graz.ac.at/research/krypto/AES/old/%7Erijmen/rijndael/))

If you are unsure about the target-feature flags to set, use `target-cpu=native` (if not cross-compiling) in
the `RUSTFLAGS` environment variable, and use the `nightly` feature only if you are using a nightly compiler.

# Warning

Using the wrong `target-feature` flags may lead to the binary crashing due to an "Unknown Instruction" error. This
library uses these flags to use the CPU intrinsics to maximize performance. If you are unsure what `target-feature`s are
supported on your CPU, use the command

````bash
    rustc --print cfg -C target-cpu=native
````

Using the `nightly` feature when not using a nightly compiler can lead to compile failures, so use this only if you
are using a nightly compiler.
