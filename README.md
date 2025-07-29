[![Actions Status](https://github.com/sayantn/aes/actions/workflows/rust.yml/badge.svg)](https://github.com/sayantn/aes/actions)

A pure-Rust platform-agnostic [AES](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf) library, focused on reusability and optimal performance.

This library guarantees the best performance on the `target_cpu` (if correctly specified). This currently has quite a few
implementations, among which it automatically decides the best (most performant) using `rustc`'s `target_feature` flags.

# The implementations and their requirements

*Nightly-only* means a Nightly compiler is required, and the `nightly` crate feature must be enabled.

All the implementations are well-tested, but it is still possible for bugs to creep through, especially for the *Nightly-only* implementations, as those are on the bleeding edge of the compiler.
In case you discover a bug, please feel free to file an issue at [my repository](https://github.com/sayantn/aes).

## For Scalar AES (1 block at a time)

| Implementation                 | Architecture          | Target Feature  |                                                                                        |
| ------------------------------ | --------------------- | --------------- | -------------------------------------------------------------------------------------- |
| **AES-NI**                     | `x86`/`x86_64`        | `sse4.1`+`aes`  |                                                                                        |
| **AES-Neon**                   | `aarch64`/`arm64ec`   | `aes`           |                                                                                        |
|                                | `arm`                 | `v8`+`aes`      | *Nightly-only*                                                                         |
| **AES-RV**                     | `riscv32`/`riscv64`   | `zkne`+`zknd`   | *Nightly-only*                                                                         |
| **AES-PPC**                    | `powerpc`/`powerpc64` | `power8-crypto` | *Nightly-only*                                                                         |
| **Constant-time Software AES** | None                  | None            | Requires the `constant-time` crate feature                                             |
| **Table-based Software AES**   | None                  | None            | Based on Rijmen and Daemen's `optimized` implementation (available on their [website]) |

[website]: https://web.archive.org/web/20050828204927/http://www.iaik.tu-graz.ac.at/research/krypto/AES/old/%7Erijmen/rijndael

The **Constant-time Software AES** implementation guards against side-channel attacks, at the cost of some speed.
This will *only* be used if no accelerated AES implementation is found, **and** the `constant-time` crate feature is enabled (because all hardware-accelerated AES implementations are always constant-time).

## For X2 Vector AES (2 blocks in parallel)

| Implementation | Architecture   | Target Feature |                |
| -------------- | -------------- | -------------- | -------------- |
| **AES-NI**     | `x86`/`x86_64` | `vaes`         | *Nightly-only* |

## For X4 Vector AES (4 blocks in parallel)

| Implementation | Architecture   | Target Feature   |                |
| -------------- | -------------- | ---------------- | -------------- |
| **AES-NI**     | `x86`/`x86_64` | `vaes`+`avx512f` | *Nightly-only* |

For Vector AES, if no accelerated version is found, then a *tuple-based* implementation is used.
That is, if an `x86_64` machine has `vaes`, but not `avx512f`, then `AesBlockX4` will be represented as a wrapper over `(AesBlockX2, AesBlockX2)` (which still benefits from the X2 parallelism offered by `vaes`).

If you are unsure, use `target_cpu=native` (if not cross-compiling; otherwise you can use `target_cpu=<CPU of your target machine>` with the appropriate target triple) in
the `RUSTFLAGS` environment variable, and use the `nightly` feature **only** if you are using a nightly compiler.

# Minimum Supported Rust version

I typically don't maintain a strict MSRV. Normally, it would be the *latest stable* if the `nightly` crate feature is not enabled, otherwise it would be the *latest nightly* (by latest, I mean latest at the time of the release).

# Warning

Using the wrong `target_feature` flags may lead to the binary crashing due to an "Unknown Instruction" error. This
library uses these flags to use the CPU intrinsics to maximize performance. If you are unsure what `target_feature`s are
supported on your CPU, use the command

```bash
rustc --print cfg -C target-cpu=native
```

Using the `nightly` feature when not using a nightly compiler can lead to compile failures, so use this only if you
are using a nightly compiler.

This is a low-level crate, and is supposed to be used as a cryptographic primitive.
This crate only implements AES-ECB, which is **NOT** a secure cipher.
Rather, this crate should be used as a building block for implementing higher-level algorithms in a platform-independent and performant way.
