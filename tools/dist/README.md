# stafeto @VERSION@ for QEMU (aarch64, `virt` machine)

A pre-release of stafeto: a POSIX system on its own capability microkernel,
written in Rust for AArch64. This archive boots the kernel in QEMU to a
BusyBox `ash` shell.

## Run

You need `qemu-system-aarch64` (macOS: `brew install qemu`; Debian and
Ubuntu: `sudo apt install qemu-system-arm`).

    ./run.sh                 # QEMU's own emulation (TCG), 1 CPU
    ./run.sh --cpus 4        # 4 CPUs (1 to 8)
    ./run.sh --hvf           # Apple silicon Mac: the host's CPU through HVF

Wait for the prompt, then try `uname -a`, `ls /bin`, `top`, `nano`, `htop`,
`bash`. `exit` at the prompt or Ctrl-A X ends the machine.

## What is inside

| File | Content |
| --- | --- |
| `Image` | the kernel, in the arm64 Linux boot image format |
| `boot.img` | the boot image: init, the services (UART, RAM files, pipes, terminal, clock, process, entropy) and the packages: BusyBox, GNU bash, GNU nano, htop, ncdu, ncurses and small ready-made utilities |
| `run.sh` | starts QEMU with these two files |
| `LICENSES/` | the licence texts of the kernel and of every package |

Next to this archive a release carries the kernel with its symbols, the
sources of the GPL packages with our build scripts and patches, an SBOM
(`.spdx.json`) and `SHA256SUMS`.

## Limits

- All files live in memory: what you create is gone when the machine stops.
  There is no disk, network or graphics yet.
- One user shell on the serial console; no installation of packages in the
  running system.
- A pre-release: the interfaces and the image layout can change before 0.2.0.

## Licences

The kernel, services and tools are GPL-3.0-or-later; the libraries that
programs link are MIT, and the POSIX system layer is GPL-3.0-or-later with
the GCC Runtime Library Exception 3.1. The packages keep their own licences
(see `LICENSES/INDEX.txt`). Source: https://github.com/stafeto/stafeto
