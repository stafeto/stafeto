#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
#
# Probe: fetch relibc and musl next to the repository (../third), apply the
# stafeto patches and build the two static libraries the probes link:
#   ../third/relibc/target/stafeto-libc.a and stafeto-include/
#   ../third/musl/out/lib/libc.a and out/include/
# Then: cargo xtask relibc; cargo xtask musl.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
THIRD=${THIRD:-$HERE/../../../third}
LLVM=${LLVM:-/opt/homebrew/opt/llvm/bin}
export PATH=$LLVM:$PATH
mkdir -p "$THIRD"
cd "$THIRD"
[ -d relibc ] || {
    git clone https://gitlab.redox-os.org/redox-os/relibc.git
    git -C relibc checkout 5f317a4edd6d12501e7e084dcaa00f54a7014201
    git -C relibc submodule update --init dlmalloc-rs openlibm
    git -C relibc apply "$HERE/relibc-stafeto.patch"
}
[ -d musl ] || {
    git clone https://git.musl-libc.org/git/musl
    git -C musl checkout c4e1bb3994c14ed5112c894d15a451bf00f0d501
    git -C musl apply "$HERE/musl-stafeto.patch"
}

# relibc: target_os = "linux" for the Linux C ABI, --cfg stafeto swaps the
# platform module (src/platform/stafeto) for the Linux system calls.
cd "$THIRD/relibc"
CC_aarch64_unknown_linux_gnu=clang \
CFLAGS_aarch64_unknown_linux_gnu="--target=aarch64-linux-gnu -mfix-cortex-a53-835769" \
AR_aarch64_unknown_linux_gnu=llvm-ar \
RUSTFLAGS="--cfg stafeto -C relocation-model=static -Z tls-model=local-exec -C target-feature=+fix-cortex-a53-835769" \
cargo +nightly-2026-05-24 rustc --release --target aarch64-unknown-linux-gnu \
    -Z build-std=core,alloc,compiler_builtins --lib -- --emit link=target/stafeto-librelibc.a
cp target/stafeto-librelibc.a target/stafeto-libc.a
NM=llvm-nm OBJCOPY=llvm-objcopy bash ./renamesyms.sh target/stafeto-libc.a target/aarch64-unknown-linux-gnu/release/deps/
NM=llvm-nm OBJCOPY=llvm-objcopy bash ./stripcore.sh target/stafeto-libc.a
H=target/stafeto-include
rm -rf $H && mkdir -p $H && cp -r include/* $H && cp openlibm/include/*.h openlibm/src/*.h $H
for d in src/header/*/; do
    header=$(basename "$d")
    case $header in _*) continue ;; esac
    [ -f "$d/cbindgen.toml" ] || continue
    out="$H/$(echo "$header" | sed 's/_/\//g').h"
    mkdir -p "$(dirname "$out")"
    cat "$d/cbindgen.toml" cbindgen.globdefs.toml | cbindgen "$d/mod.rs" --config=/dev/stdin --output "$out"
done

# musl: __syscallN call __stafeto_syscall instead of svc.
cd "$THIRD/musl"
./configure --target=aarch64-linux-musl CC=clang \
    CFLAGS="--target=aarch64-linux-gnu -mfix-cortex-a53-835769" \
    AR=llvm-ar RANLIB=llvm-ranlib --disable-shared --prefix="$PWD/out"
make -j8 install-headers install-libs
