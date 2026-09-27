#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

set -eu

tool_dir="${E2FSPROGS_BIN_DIR:-/opt/homebrew/opt/e2fsprogs/sbin}"
if [ ! -x "$tool_dir/mke2fs" ]; then
    tool_dir="$(dirname "$(command -v mke2fs)")"
fi

here="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
temp_dir="$(mktemp -d)"
trap 'rm -rf "$temp_dir"' EXIT HUP INT TERM
mkdir -p "$temp_dir/root/boot"
printf 'hello from ext4\n' > "$temp_dir/root/boot/hello.txt"
ln -s hello.txt "$temp_dir/root/boot/message"
truncate -s 4m "$here/ext4.img"
"$tool_dir/mke2fs" -q -F -t ext4 -b 1024 -d "$temp_dir/root" "$here/ext4.img"
"$tool_dir/e2fsck" -fn "$here/ext4.img"
