FROM ubuntu:25.10
RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  ca-certificates \
  libc6-dev \
  gcc-powerpc-linux-gnu \
  libc6-dev-powerpc-cross \
  qemu-user \
  make \
  file

ENV CARGO_TARGET_POWERPC_UNKNOWN_LINUX_GNU_LINKER=powerpc-linux-gnu-gcc \
    CARGO_TARGET_POWERPC_UNKNOWN_LINUX_GNU_RUNNER="qemu-ppc -L /usr/powerpc-linux-gnu"
