FROM ubuntu:25.10

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  ca-certificates \
  libc6-dev \
  libc6-dev-arm64-cross \
  qemu-user \
  make \
  file \
  curl \
  xz-utils

ENV VERSION="14.3.rel1"
ENV TOOLCHAIN="arm-gnu-toolchain-${VERSION}-x86_64-aarch64_be-none-linux-gnu"

# Download the aarch64_be gcc toolchain
RUN curl -L "https://developer.arm.com/-/media/Files/downloads/gnu/${VERSION}/binrel/${TOOLCHAIN}.tar.xz" -o "${TOOLCHAIN}.tar.xz"
RUN tar -xvf "${TOOLCHAIN}.tar.xz"
RUN mkdir /toolchains && mv "./${TOOLCHAIN}" /toolchains

ENV CARGO_TARGET_AARCH64_BE_UNKNOWN_LINUX_GNU_LINKER="/toolchains/${TOOLCHAIN}/bin/aarch64_be-none-linux-gnu-gcc"
ENV CARGO_TARGET_AARCH64_BE_UNKNOWN_LINUX_GNU_RUNNER="qemu-aarch64_be -cpu max -L /toolchains/${TOOLCHAIN}/aarch64_be-none-linux-gnu/libc"
