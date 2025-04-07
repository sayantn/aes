#!/usr/bin/env sh

set -ex

if [ $# -lt 1 ]; then
    >&2 echo "Usage: $0 <TARGET> [<EXTRA-ARGS>]*"
    exit 1
fi

echo "Building docker container for ${1}"
docker build -t aes -f "ci/docker/${1}/Dockerfile" ci/
mkdir -p target
docker run \
  --rm \
  --user "$(id -u)":"$(id -g)" \
  --env CARGO_HOME=/cargo \
  --env CARGO_TARGET_DIR=/checkout/target \
  --env RUSTFLAGS \
  --volume "${HOME}/.cargo":/cargo \
  --volume "$(rustc --print sysroot)":/rust:ro \
  --volume "$(pwd)":/checkout:ro \
  --volume "$(pwd)"/target:/checkout/target \
  --init \
  --workdir /checkout \
  --privileged \
  aes \
  sh -c "HOME=/tmp PATH=\$PATH:/rust/bin exec cargo test --target ${1} $(shift 1; echo "$*") -- --nocapture"
