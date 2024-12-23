FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  ca-certificates \
  libc6-dev \
  qemu-user \
  wget \
  xz-utils \
  make \
  file

RUN wget https://github.com/riscv-collab/riscv-gnu-toolchain/releases/download/2024.12.16/riscv32-glibc-ubuntu-24.04-gcc-nightly-2024.12.16-nightly.tar.xz
RUN tar -xJf riscv32-glibc-ubuntu-24.04-gcc-nightly-2024.12.16-nightly.tar.xz

ENV EXTRA_ARGS="-Z build-std"

ENV CARGO_TARGET_RISCV32GC_UNKNOWN_LINUX_GNU_LINKER=/riscv/bin/riscv32-unknown-linux-gnu-gcc \
    CARGO_TARGET_RISCV32GC_UNKNOWN_LINUX_GNU_RUNNER="qemu-riscv32 -L /riscv/sysroot -cpu rv32,zk=true"
