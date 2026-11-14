# Kernel size per source file

`cargo xtask kernel-size` builds the shipping kernel (the build that also boots under Apple Virtualization.framework) and prints where the bytes of its `.text` come from. It reports and never fails: no build or ci step checks the size. The record of the shipping image size is `kernel/size.txt` and `cargo xtask build` prints the difference from it.

```sh
cargo xtask kernel-size
```

The output has one row per source file, largest first (files of `kernel/`, `kcore/` and the other workspace crates the kernel links), with the bytes, the share of `.text` and the boot-only part. The rows are followed by:

- `(alignment and literal pools)`: the bytes of `.text` that belong to no instruction line (padding between functions);
- `.text total`: the size of `.text` in the ELF file, and the sum of the boot-only column;
- `.rodata` and `.data`: the sizes of those sections (not split by file: about 12.7 KB of `.rodata` is message text);
- `padding (4 KiB pages)`: `kernel/kernel.ld` starts each section on a 4 KiB boundary, so the image is larger than the sum of its sections;
- `image`: the size of `target/stafeto.img`.

## Method

`llvm-objdump -d -l -C` names the source line of every instruction, and an instruction takes 4 bytes. Symbol sizes (`llvm-nm --size-sort`) would credit code that link-time optimization inlined to the symbol of its caller, so the line table decides:

- an instruction is credited to the file its line belongs to;
- an instruction of the library (`core`, `alloc`) that was inlined into a function is credited to the last workspace file seen in that function;
- a function with no workspace line (`fmt`, `memcpy`) forms the row `library`;
- assembly has no line table and forms the row `assembly (no line info)`.

The boot-only column counts the instructions of functions that run once while the kernel starts (the list `BOOT_ONLY` in `xtask/src/kernel_size.rs`: boot parameters, initialization of memory, interrupt controller, timer, scheduler, ITS, secondary CPUs, boot report). It is a lower bound: boot code inlined into a function that also runs later is counted in that function.

The tool needs `llvm-objdump` and `llvm-size` from the `llvm-tools` rustup component, which the repository already requires.
