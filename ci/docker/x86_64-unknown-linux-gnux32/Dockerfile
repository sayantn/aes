FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  ca-certificates \
  libc6-dev \
  gcc-x86-64-linux-gnux32 \
  libc6-dev-x32-cross \
  wget \
  xz-utils \
  make \
  file

ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNUX32_LINKER=x86-64-linux-gnux32-gcc

RUN wget https://downloadmirror.intel.com/843185/sde-external-9.48.0-2024-11-25-lin.tar.xz
RUN tar -xJf sde-external-9.48.0-2024-11-25-lin.tar.xz
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNUX32_RUNNER="/sde-external-9.48.0-2024-11-25-lin/sde64 -future --"
