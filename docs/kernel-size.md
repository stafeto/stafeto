# Kernel size per source file

`cargo xtask kernel-size` builds the shipping kernel (the build that also boots under Apple Virtualization.framework) and prints where the bytes of its `.text` come from. It reports and never fails: no build or ci step checks the size. The record of the shipping image size is `kernel/size.txt` and `cargo xtask build` prints the difference from it.

```sh
cargo xtask kernel-size
```

The output has one row per source file, largest first (files of `kernel/`, `karch/`, `kboot/`, `kcore/` and the other workspace crates the kernel links), with the bytes, the share of `.text` and the boot-only part. The rows are followed by:

- `(alignment and literal pools)`: the bytes of `.text` that belong to no instruction line (padding between functions);
- `.text total`: the size of `.text` in the ELF file, and the sum of the boot-only column;
- `.rodata` and `.data`: the sizes of those sections (not split by file: about 12.7 KB of `.rodata` is message text);
- `padding (4 KiB pages)`: `kernel/kernel.ld` starts each section on a 4 KiB boundary, so the image is larger than the sum of its sections;
- `image`: the size of `target/stafeto.img`.

## The crates of the kernel

The kernel is four crates, and the path of each row names the crate:

- `kernel/`: the glue and the entry. Objects, IPC, processes, threads, memory, SMP, the system calls, the ITS driver (its sections are part of the protocol of `OBJ`), the entry of exceptions, the block of each CPU and the report of a panic.
- `karch/`: the AArch64 layer. Boot code (`head.S`), exception vectors (`vectors.S`), the MMU, the caches, the system registers, the GIC, the timer, the registers of a program. It knows no kernel object and holds nearly all hardware `unsafe`; the lint `clippy::undocumented_unsafe_blocks` is denied in the crate.
- `kboot/`: what the kernel reads once at boot: the device tree, the boot information and the memory map. `#![forbid(unsafe_code)]`; `cargo test -p kboot` runs its tests on the host, and the EFI boot loader links it too.
- `kcore/`: the portable logic, tested on the host.

`kernel` depends on `karch`, `kboot` and `kcore`; `karch` on `kcore` and `kboot`; `kcore` on `kboot`; `kboot` on nothing. The wcet bounds name functions with the crate path (`karch::gic::mask`, `kernel::arch::its::wait_once`); `tools/wcet/bounds.toml` keys a loop by its offset in the function, so a change in the inlining of a function moves it.

## Method

`llvm-objdump -d -l -C` names the source line of every instruction, and an instruction takes 4 bytes. Symbol sizes (`llvm-nm --size-sort`) would credit code that link-time optimization inlined to the symbol of its caller, so the line table decides:

- an instruction is credited to the file its line belongs to;
- an instruction of the library (`core`, `alloc`) that was inlined into a function is credited to the last workspace file seen in that function;
- a function with no workspace line (`fmt`, `memcpy`) forms the row `library`;
- assembly has no line table and forms the row `assembly (no line info)`.

The boot-only column counts the instructions of functions that run once while the kernel starts (the list `BOOT_ONLY` in `xtask/src/kernel_size.rs`: boot parameters, initialization of memory, interrupt controller, timer, scheduler, ITS, secondary CPUs, boot report). It is a lower bound: boot code inlined into a function that also runs later is counted in that function.

The tool needs `llvm-objdump` and `llvm-size` from the `llvm-tools` rustup component, which the repository already requires.
