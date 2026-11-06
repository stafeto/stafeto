#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
#
# Runs stafeto in QEMU: the kernel Image and the boot image of this archive
# with a screen, a keyboard, the network and a disk for the packages. The
# console is on this terminal and the window of QEMU shows the screen.
#
#   ./run.sh [--hvf] [--cpus N] [--memory SIZE] [--nographic] [--fresh-store]
#            [--print] [-- extra qemu options]
#
#   --hvf          Apple silicon: the host's CPU through the Hypervisor framework
#   --cpus N       1 to 8 CPUs (1 by default)
#   --memory SIZE  RAM, for example 1024M or 2G
#   --nographic    no window (a game shows nothing then)
#   --fresh-store  a new empty disk store.img
#   --print        print the QEMU command, one argument per line, and stop
#
# Ctrl-A X ends QEMU; `poweroff` at the shell prompt ends it too.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
image=@IMAGE@
memory=@MEMORY@
store=$here/store.img
accel=tcg
cpus=1
window=yes
fresh=no
print=no

usage() {
    sed -n '8,19p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

need() {
    [ $# -ge 2 ] || usage 2
}

while [ $# -gt 0 ]; do
    case $1 in
        --hvf) accel=hvf ;;
        --cpus)
            need "$@"
            cpus=$2
            shift
            ;;
        --cpus=*) cpus=${1#--cpus=} ;;
        --memory)
            need "$@"
            memory=$2
            shift
            ;;
        --memory=*) memory=${1#--memory=} ;;
        --nographic) window=no ;;
        --fresh-store) fresh=yes ;;
        --print) print=yes ;;
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

# The memory in MiB, for the check below.
case $memory in
    *[Mm]) mib=${memory%?} ;;
    *[Gg]) mib=$((${memory%?} * 1024)) ;;
    *) mib= ;;
esac
case $mib in
    '' | *[!0-9]*)
        echo "run.sh: --memory takes a size such as 1024M or 2G" >&2
        exit 2
        ;;
esac
if [ "$image" = boot-full.img ] && [ "$mib" -lt 1024 ]; then
    echo "run.sh: the full image needs 1024M: on less its container leaves init 15837 free pages, under the 16384 it keeps" >&2
    exit 2
fi

if [ "$accel" = hvf ]; then
    # Apple's GICv3 in the macOS kernel and the host's CPU model.
    machine=virt,gic-version=3,highmem-ecam=off
    accelerator=hvf,kernel-irqchip=on
    cpu=host
else
    machine=virt,gic-version=2,highmem-ecam=off
    accelerator=tcg
    cpu=cortex-a72
fi

# A comma in a path ends a value in a QEMU option unless it is doubled.
store_option=$(printf '%s' "$store" | sed 's/,/,,/g')

# The machine of the images (cargo xtask image base|full): the entropy
# device, the screen, the keyboard, the network and the disk of the package
# service. A test compares this list with the one xtask builds.
command_line() {
    printf '%s\n' qemu-system-aarch64 \
        -machine "$machine" -accel "$accelerator" -cpu "$cpu" -m "$memory" \
        -smp "$cpus" \
        -global virtio-mmio.force-legacy=false \
        -device virtio-rng-device,bus=virtio-mmio-bus.31 \
        -nic none \
        -kernel "$here/Image" -initrd "$here/$image" \
        -device virtio-gpu-device,bus=virtio-mmio-bus.23,xres=640,yres=400 \
        -device virtio-keyboard-device,bus=virtio-mmio-bus.15 \
        -netdev user,id=n0 \
        -device virtio-net-device,netdev=n0,bus=virtio-mmio-bus.7,mac=52:54:00:12:34:56 \
        -drive "if=none,id=store,format=raw,file=$store_option,cache=writeback,werror=report,rerror=report" \
        -device virtio-blk-pci,drive=store,bus=pcie.0,addr=0x1,disable-legacy=on,disable-modern=off,vectors=0,num-queues=1,serial=stafeto-store
    if [ "$window" = yes ]; then
        printf '%s\n' -serial mon:stdio
    else
        printf '%s\n' -nographic
    fi
    for extra in "$@"; do
        printf '%s\n' "$extra"
    done
}

if [ "$print" = yes ]; then
    command_line "$@"
    exit 0
fi

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

# The disk is a sparse file of 512 MiB, made at the first run.
if [ "$fresh" = yes ]; then
    rm -f "$store"
fi
if [ ! -e "$store" ]; then
    dd if=/dev/zero of="$store" bs=1048576 count=0 seek=512 2>/dev/null
fi

# Read the arguments back, one per line, into the positional parameters.
oldifs=$IFS
IFS='
'
set -f
# shellcheck disable=SC2046
set -- $(command_line "$@")
set +f
IFS=$oldifs
shift
exec qemu-system-aarch64 "$@"
