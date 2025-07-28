FROM ubuntu:25.10
RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  ca-certificates \
  libc6-dev  \
  wget \
  xz-utils \
  make \
  file

RUN wget https://downloadmirror.intel.com/859732/sde-external-9.58.0-2025-06-16-lin.tar.xz -O sde.tar.xz
RUN mkdir intel-sde
RUN tar -xJf sde.tar.xz --strip-components=1 -C intel-sde
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER="/intel-sde/sde64 -future --"
