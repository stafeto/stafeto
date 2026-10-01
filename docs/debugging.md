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
   running. The kernel writes a single line
   `process fault: <class> (EC 0x..) ESR=0x... FAR=0x... ELR=0x...` into
   its log, which shows it on the console at once while no device window
   covers the console's page, and otherwise leaves it to the console's
   driver (spec 3.2, 16.3); the parent reads the same cause through
   `object_info`. `FAR` in it is taken
   from the processor only where it is valid: instruction and data fetch
   faults and a misaligned program counter (spec 7.9); it is 0 in other
   cases. The addresses in `ELR` and `FAR` here are addresses in the
   program.

   Any end of `init` stops the machine with a panic: `init` lives for
   good. When `init` faults, the `process fault` line is followed by the
   program's registers (x0..x30, `sp_el0`, `elr`, `spsr`, `tpidr_el0`),
   both in the log as well, then the panic
   `init terminated by a fault: ESR=0x... FAR=0x... ELR=0x...`; its call
   stack shows only kernel functions. Killing `init` with `process_kill`
   produces the panic `init terminated: Killed`. A normal `init` exit
   produces the panic `init exited with code N`: the test init ends its
   run this way, and xtask takes that one panic, after `TESTS DONE` and
   with the expected code, as the end of the run.

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

7. A panic, and each report of an exception that ends in one, takes the
   console back from any driver and first prints the records of the
   kernel log that nobody showed or took, once: the last lines of
   programs and faults a driver did not get to show come before the
   report and the line `KERNEL PANIC`. A run ends with PSCI `SYSTEM_OFF`, after up to
   10 ms for the console's transmitter to go idle, and QEMU exits with
   status 0, at a panic, `init`'s end among them, and at the end of the
   kernel tests, which print `TESTS DONE total=N failed=M` first. The normal build does
   not end: `init` lives on with the UART driver and the shell, and xtask
   stops a boot on the shell's line
   `shell: connected to uart; type help for the commands`, and talks to
   the shell through a pipe on the console's input in its console
   dialog, which ends with five `crash uart`: four restarts of the driver
   and a broken one, after which the kernel prints the shell's line and
   then what is left of the kernel log, which init's worker shows; it
   stops a run of the image of `init`'s test
   table on init's line of the end of the test client there,
   `init: checker ended: ...`. xtask judges a run of tests by its
   `TESTS DONE` line and fails a run with a `KERNEL PANIC` line
   anywhere, except the one panic of `init`'s exit that ends a run of the
   test init. A panic before the kernel has read the PSCI conduit from
   the device tree parks the processor instead, and the run ends at
   xtask's deadline.

8. Until the kernel has read the device tree it knows no port and
   writes nothing to one (spec 3.2): what it says goes into its log, and
   the line `stafeto <version> booting` and anything after it come out
   once the port of the tree is known. A panic before that, such as
   `no device tree in x0` when the ELF is booted instead of the Image,
   stays in the log in RAM. Read it through QEMU's monitor: start QEMU
   with `-monitor tcp:127.0.0.1:4444,server=on,wait=off`, then
   `printf 'pmemsave 0x40200000 0x100000 ram.bin\n' | nc 127.0.0.1 4444`
   saves the kernel's image with its log into `ram.bin` in QEMU's
   working directory. xtask reads the records out of such a file
   (`xtask/src/ring.rs`) and does so in its check of the ELF boot.

## On Apple VZ

`cargo xtask vz` boots the image that ships with a boot image whose
`init` starts `services/virtio-console`, the driver of the Virtio PCI
console, under the console's name `uart`. VZ gives the machine no PL011,
so the kernel never has a port there: its boot report and its log reach
the terminal through the driver, as the PL011's driver shows them on
QEMU. A kernel panic shows nothing and powers the machine off; the
runner says `guest stopped: the kernel powered off (end of run or
panic)` on its output, and a VZ probe that sees it before its end fails
with a hint. The same kernel image shows the panic under HVF (`cargo
xtask run --hvf`, `cargo xtask hvf`), and an early panic also stays in
the log in RAM, which QEMU's monitor can save (item 8 above). VZ cannot
keep the log across a reset: at PSCI `SYSTEM_RESET` it starts the
machine again with RAM cleared. The runner keeps the guest's input open
when its own stdin ends; a receive of no bytes, the end of the host's
input, leaves the driver going with output alone.

The console is device 5 of bus 0, its INTA is SPI 0x25 (INTID 69,
level) through the tree's `interrupt-map`, and the driver checks the
function's ID before it writes there. `cargo xtask console-restart-vz`
crashes the driver: `init` resets the Virtio device (`device_status`
0, read back until 0) and clears the function's command word through
windows of its own before it lets the driver's DMA object go; VZ keeps
a device's DMA going with bus mastering off, so the reset is what stops
it. Init's `dma-watch` build then reads the old object for 300 ms while
xtask types, and says it stayed unchanged. A stop that does not settle
leaves the object with init for good and the driver broken. The new
instance resets the device again before it turns bus mastering on and
reports the command word it found, 0.

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

`cargo xtask run`, `test` and `hvf` also pass each panic frame to
`llvm-symbolizer` with that run's ELF and print its function and source
line. When the tool is unavailable, the original addresses stay in the
output and xtask prints how to enable symbolization.

## Under HVF

`cargo xtask hvf` runs the boot checks, the console dialog with the
shell, the test init and the kernel tests under HVF on a Mac with Apple
silicon, on two machines:
`-machine virt,gic-version=3 -accel hvf,kernel-irqchip=on -cpu host`, with
Apple's GICv3 in the macOS kernel, and
`-machine virt,gic-version=2 -accel hvf,kernel-irqchip=off -cpu host`,
with QEMU's GICv2. On any other host it prints why it skips and succeeds;
`cargo xtask ci` does not run it. `cargo xtask run --hvf` boots the
normal build on the first machine with the console on the terminal, and
fails with the reason on any other host. To run one by hand, after
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
