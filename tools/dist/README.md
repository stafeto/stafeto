# stafeto @VERSION@ for QEMU (aarch64, `virt` machine): @FLAVOUR@

@RELEASE@ A POSIX system on its own capability microkernel, written in Rust
for AArch64. This archive boots the kernel in QEMU to a BusyBox `ash` shell
with a screen, a keyboard, the network and a disk.

@ABOUT@

## Run

You need `qemu-system-aarch64` (macOS: `brew install qemu`; Debian and
Ubuntu: `sudo apt install qemu-system-arm`).

    ./run.sh                 # QEMU's own emulation (TCG), 1 CPU, @MEMORY@
    ./run.sh --cpus 4        # 4 CPUs (1 to 8)
    ./run.sh --hvf           # Apple silicon Mac: the host's CPU through HVF
    ./run.sh --nographic     # no window: the console only
    ./run.sh --print         # print the QEMU command and stop

The console is this terminal; the window of QEMU shows the screen and takes
the keyboard. Wait for the prompt, then try `uname -a`, `pkg list`,
`pkg install doom` and, once it is installed, `doom -iwad /games/freedoom1.wad`.
`poweroff` at the prompt or Ctrl-A X ends the machine.

## The disk

`pkg install` keeps the packages on the disk `store.img`, a sparse file of
512 MiB that `run.sh` makes next to itself at the first run. What you install
stays there between runs. `./run.sh --fresh-store` starts with a new empty
disk. The index of the packages comes from `https://stafeto.github.io/packages/`
over the network of the machine (user-mode networking of QEMU).

## What is inside

| File | Content |
| --- | --- |
| `Image` | the kernel, in the arm64 Linux boot image format |
| `@IMAGE@` | the boot image: init, the services and the packages of the @FLAVOUR@ image |
| `run.sh` | starts QEMU with these files |
| `LICENSES/` | the licence texts of the kernel and, in `LICENSES/packages/<name>/`, the notices of every package of this image |

Next to this archive a release carries the kernel with its symbols, the
sources of the GPL packages with our build scripts and patches, an SBOM
(`.spdx.json`), the signed index of the packages and `SHA256SUMS`.

## Limits

- @LIMIT@
- The shell talks on the console of this terminal; the window of QEMU shows the
  screen and takes the keyboard.

## Licences

The kernel, services and tools are GPL-3.0-or-later; the libraries that
programs link are MIT, and the POSIX system layer is GPL-3.0-or-later with
the GCC Runtime Library Exception 3.1. The packages keep their own licences
(see `LICENSES/INDEX.txt`). Source: https://github.com/stafeto/stafeto
