#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
#
# Runs stafeto in QEMU: the kernel Image and the boot image of the BusyBox
# ash shell, with the console on this terminal.
#
#   ./run.sh [--hvf] [--cpus N] [--memory SIZE] [-- extra qemu options]
#
# Ctrl-A X ends QEMU; `exit` at the shell prompt ends it too.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
accel=tcg
cpus=1
memory=512M

usage() {
    sed -n '8,12p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case $1 in
        --hvf) accel=hvf ;;
        --cpus)
            [ $# -ge 2 ] || usage 2
            cpus=$2
            shift
            ;;
        --cpus=*) cpus=${1#--cpus=} ;;
        --memory)
            [ $# -ge 2 ] || usage 2
            memory=$2
            shift
            ;;
        -h | --help) usage 0 ;;
        --)
            shift
            break
            ;;
        *)
            echo "run.sh: unknown option $1" >&2
            usage 2
            ;;
    esac
    shift
done

case $cpus in
    '' | *[!0-9]* | 0)
        echo "run.sh: --cpus takes a number from 1 to 8" >&2
        exit 2
        ;;
esac
[ "$cpus" -le 8 ] || {
    echo "run.sh: --cpus takes a number from 1 to 8" >&2
    exit 2
}

if ! command -v qemu-system-aarch64 >/dev/null 2>&1; then
    echo "run.sh: qemu-system-aarch64 is not installed." >&2
    case $(uname -s) in
        Darwin) echo "  Install it with: brew install qemu" >&2 ;;
        *)
            echo "  Debian and Ubuntu: sudo apt install qemu-system-arm" >&2
            echo "  Fedora: sudo dnf install qemu-system-aarch64" >&2
            echo "  Arch: sudo pacman -S qemu-system-aarch64" >&2
            ;;
    esac
    exit 1
fi

if [ "$accel" = hvf ]; then
    # Apple's GICv3 in the macOS kernel and the host's CPU model.
    machine=virt,gic-version=3
    accelerator=hvf,kernel-irqchip=on
    cpu=host
else
    machine=virt,gic-version=2
    accelerator=tcg
    cpu=cortex-a72
fi

exec qemu-system-aarch64 \
    -machine "$machine" -accel "$accelerator" -cpu "$cpu" -m "$memory" \
    -smp "$cpus" \
    -global virtio-mmio.force-legacy=false \
    -device virtio-rng-device,bus=virtio-mmio-bus.31 \
    -kernel "$here/Image" -initrd "$here/boot.img" \
    -nographic "$@"
