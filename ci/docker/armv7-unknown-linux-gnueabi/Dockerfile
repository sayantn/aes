FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  ca-certificates \
  libc6-dev \
  gcc-arm-linux-gnueabi \
  libc6-dev-armel-cross \
  qemu-user \
  make \
  file

ENV CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABI_LINKER=arm-linux-gnueabi-gcc \
    CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABI_RUNNER="qemu-arm -L /usr/arm-linux-gnueabi"
