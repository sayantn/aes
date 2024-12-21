FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  ca-certificates \
  libc6-dev \
  gcc-powerpc64le-linux-gnu \
  libc6-dev-ppc64el-cross \
  qemu-user \
  make \
  file

ENV CARGO_TARGET_POWERPC64LE_UNKNOWN_LINUX_GNU_LINKER=powerpc64le-linux-gnu-gcc \
    CARGO_TARGET_POWERPC64LE_UNKNOWN_LINUX_GNU_RUNNER="qemu-ppc64le -L /usr/powerpc64le-linux-gnu -cpu power10"
