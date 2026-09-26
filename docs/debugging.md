# Debugging

## The kernel is silent or crashes

1. Run QEMU with an exception log:

   ```
   qemu-system-aarch64 -M virt,gic-version=2 -cpu cortex-a72 -m 512M -nographic \
     -kernel target/stafeto.img -initrd target/boot.img \
     -d int,cpu_reset,guest_errors -D qemu.log
   ```

2. Find the first `Taking exception` in `qemu.log`. ESR, FAR, and ELR are
   next to it. The exception class is `(ESR >> 26) & 0x3f` (bits above 31
   are used for something else on newer processors). Common values:

   | Class | What happened |
   |---|---|
   | `0x00` | unknown instruction |
   | `0x15` | `svc` call from EL0 |
   | `0x20`, `0x24` | instruction or data fetch error at EL0 |
   | `0x21`, `0x25` | the same at EL1, i.e. in the kernel |
   | `0x26` | stack not aligned to 16 bytes |
   | `0x3c` | `brk` instruction |

   The kernel prints the same thing itself on an exception in the kernel:
   registers x0..x30, the exception class in words, for access faults the
   fault kind and page table level, then a call stack. In the stack, the
   panic-handling functions and `handle_exception` come first, followed by
   the address of the interrupted instruction (equal to ELR) and the
   functions that led to it.

3. The kernel detects an overflow of its own stack by itself: the
   exception entry sees that the frame does not fit on the stack, switches
   to the emergency stack, and prints the line `kernel stack overflow`
   with the stack pointer, followed by the usual report with the real ELR.
   The call stack runs from the emergency stack on into the kernel stack,
   so it shows the function that overflowed the stack.

4. A program fault at EL0 terminates only that process; the machine keeps
   running. The kernel prints a single line
   `process fault: <class> (EC 0x..) ESR=0x... FAR=0x... ELR=0x...`; the
   parent reads the same cause through `object_info`. `FAR` in it is taken
   from the processor only where it is valid: instruction and data fetch
   faults and a misaligned program counter (spec 7.9); it is 0 in other
   cases. The addresses in `ELR` and `FAR` here are addresses in the
   program.

   `init` exiting stops the machine. When `init` faults, the
   `process fault` line is followed by the program's registers (x0..x30,
   `sp_el0`, `elr`, `spsr`, `tpidr_el0`), then the panic
   `init terminated by a fault: ESR=0x... FAR=0x... ELR=0x...`; its call
   stack shows only kernel functions. Killing `init` with `process_kill`
   produces the panic `init terminated: Killed`. A normal `init` exit
   prints `init exited with code N` and shuts the machine down.

   An SError or FIQ taken at EL0 stops the machine. The report starts with
   the line `system error at EL0, thread 0x...`, followed by the
   program's registers and a panic naming the entry point: this is a
   system error (for example, an external error while the kernel writes
   to a device), and the program is not at fault. In a build with kernel
   tests, a fault that the running test does not expect likewise stops
   the machine, with a report starting with the line
   `program fault at EL0, thread 0x...`: an error in the test program is
   immediately visible.

5. If ELR and FAR keep repeating in a loop, the exception is happening
   inside the handler before it has printed anything.

6. If PC is near zero or garbage, `VBAR_EL1` has not been set yet.

7. Every build ends a run with PSCI `SYSTEM_OFF`, and QEMU exits with
   status 0: when `init` exits, at a panic, and at the end of the kernel
   tests, which print `TESTS DONE total=N failed=M` first. xtask judges a
   run of tests by that line and fails a run with a `KERNEL PANIC` line
   anywhere. A panic before the kernel has read the PSCI conduit from the
   device tree parks the processor instead, and the run ends at xtask's
   deadline.

## Address from a panic

A panic prints the call stack as addresses. lldb gives the function name
and line for an address:

```
lldb -b -o 'image lookup -a 0xffffffffc0001234' target/stafeto.elf
```

xtask places the ELF next to the image: `target/stafeto.elf` for a normal
build, `target/stafeto-ktest.elf` for a build with kernel tests,
`target/stafeto-ktest-icount.elf` for a build with kernel tests under
`-icount` (adds to the regular kernel tests the ones that need
instruction-counted time), and `target/stafeto-probe.elf` and
`target/stafeto-overflow.elf` for the fault probes (unknown instruction
and stack overflow) from `cargo xtask test`. The right file is named by
the `backtrace (look up: ...)` line itself in the panic output. With
`CARGO_TARGET_DIR` set, the images, the ELFs and the boot images are
there instead of under `target/`.

## Under HVF

`cargo xtask hvf` runs the boot checks, the test init and the kernel
tests under HVF on a Mac with Apple silicon, on two machines:
`-machine virt,gic-version=3 -accel hvf,kernel-irqchip=on -cpu host`, with
Apple's GICv3 in the macOS kernel, and
`-machine virt,gic-version=2 -accel hvf,kernel-irqchip=off -cpu host`,
with QEMU's GICv2. On any other host it prints why it skips and succeeds;
`cargo xtask ci` does not run it. To run one by hand, after
`cargo xtask test` has built the images (under `target/`, or
`CARGO_TARGET_DIR` when it is set):

~~~
qemu-system-aarch64 -machine virt,gic-version=3 -accel hvf,kernel-irqchip=on \
  -cpu host -m 512M -display none -serial stdio -monitor none \
  -kernel target/stafeto-ktest.img -initrd target/boot.img
~~~

What differs from QEMU's own emulation:

- The counter runs at 24 MHz. A fast round trip takes a few ticks, so
  times under HVF mean something only as averages over many turns. The
  PMU's cycle counter is emulated (`PMCCNTR_EL0` is `CNTVCT_EL0` times
  128, and every read traps): measure with the counter instead.
- An address with no device reads as 0, and a write to it vanishes: there
  is no external abort. The test init's
  `window_over_a_hole_faults_only_its_process` fails with
  `the child read the hole and did not fault`; xtask accepts this one
  failure and no other.
- QEMU emulates a device register from the syndrome of the access. An
  access that has none, a load or store pair or one with writeback,
  stops QEMU with `Assertion failed: (isv)` and status 134. Device
  registers are reached through `arch::mmio` and `rt::mmio`, one `ldr` or
  `str` each.
- `ID_AA64PFR0_EL1.GIC` reads 0 though the GICv3 system registers work;
  the kernel takes the GIC's version from the device tree.
- The processor has no AArch32 at EL0 and holds `SCTLR_EL1.ITD` and
  `SED` at 1; the kernel writes them 1 on every machine.

## Debugger

`cargo xtask gdb` starts QEMU stopped before the kernel starts: first a
small QEMU loader runs at the start of memory, and the kernel's first
instruction sits at address `0x40200000`. Then, in another terminal:

```
lldb target/stafeto.elf -o 'gdb-remote 1234'
```

While the MMU is off, code executes at physical addresses (the image is
placed at `0x40200000`), while symbols in the ELF are recorded at virtual
addresses (starting at `0xffffffffc0000000`). Set a breakpoint before the
MMU is enabled at the physical address: `breakpoint set -a 0x40200000`.
