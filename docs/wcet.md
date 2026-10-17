# WCET inputs: block coverage and kernel stack depth

Two tools in xtask give the inputs of a worst-case execution time
analysis of the kernel. Neither changes the kernel.

## What is measured

`cargo xtask wcet coverage` runs the probes of the kernel group of `ci`
(the boots of the kernel and of its images, the kernel tests, the
init and service tests), the steps of the process service
(`process-steps`) and two probes that run under `-icount` (`entropy`,
`rtbench-short`) under a QEMU TCG plugin (tools/wcet/trace.c) that records
every translation block of the kernel that executes. From the kernel's ELF
file (`llvm-objdump`) it takes the functions, their basic blocks and the
call graph, and lists, for each entry path, the blocks of the functions the
path reaches that no probe executed:

| Entry path | Symbol |
| --- | --- |
| system calls | `kernel::syscall::dispatch` |
| entries from EL0 and interrupts | `handle_user_exception` |
| exceptions at EL1 | `handle_exception` |
| vector table | `exception_vectors` |

Every entry from EL0 ends in `sched::resume`, so the interrupt paths are in
the reach of `handle_user_exception`.

`cargo xtask wcet stack` builds the shipping kernel with
`-Z emit-stack-sizes` in `target/wcet-stack` (the flag is unstable; the
build sets `RUSTC_BOOTSTRAP=1` for this one build, so no image of a run
changes), reads the frame of every function from `.stack_sizes`, walks the
call graph from `exception_vectors`, `handle_user_exception`,
`handle_exception` and `kernel_main`, and sums the frames along the deepest
path. The sum plus 10 % must not exceed `kcore::layout::KERNEL_STACK_SIZE`,
the size of a kernel stack (64 KiB). The step `kernel stack depth` of the
host group of `ci` runs it and fails with the deepest path when the room is
gone.

## How to run

```
cargo xtask wcet coverage [--jobs N] [--all] [--skip PROBE]... [--from DIR]
cargo xtask wcet stack [--limit BYTES] [--elf FILE]
```

- `coverage` prints, for each kernel image that a probe booted, the number
  of functions and blocks in the reach of each entry path, the blocks that
  did not run and the share covered, then the functions with most missed
  blocks. The full list (function, address and offset of every block that
  did not run) is `target/wcet/coverage.txt`. The traces are
  `target/wcet/traces/<probe>/<kernel>.<pid>.trace`. A change does not fail
  `ci` on its coverage.
- `--all` runs every probe of the boot list that is not os-test, the guest
  probes of all groups included.
- `--skip PROBE` leaves a probe out of the run (or, with `--from`, out of the
  traces read); `--from DIR` reads the traces of an earlier run.
- `stack` prints the deepest stack against the limit and writes the paths,
  the recursions and the calls through a register to `target/wcet/stack.txt`.
  `--limit` replaces the limit of the check; `--elf` reads another ELF file
  that was built with `-Z emit-stack-sizes`.

The plugin needs a QEMU built with `--enable-plugins` that installs
`qemu-plugin.h` (the setup action of `ci` builds it so; Homebrew's QEMU
has it) and glib's headers found by `pkg-config`. `STAFETO_QEMU_INCLUDE`
names the directory of the header when it is not next to the QEMU on `PATH`.
The step `trace plugin` of the kernel group of `ci` boots a probe under the
plugin and checks that `kernel_main` is in the trace.

## Limits

- The unit of coverage is the translation block. A block is covered when
  its first instruction ran. An exception in the middle of a translation
  block counts the instructions after it as run.
- Blocks come from the branch instructions in the disassembly. A target
  of a `br` (the tables of a `match`) is not a leader, so the blocks
  after such a jump that nothing else branches to join the block before them
  and show as covered when it is.
- Each kernel image has its own addresses. The shipping kernel, the test
  kernels and their EL0 halves are reported one by one; there is no sum
  over images. The shipping kernel is the one the guest probes boot.
- The probes run under TCG. Boots under HVF are not traced.
- The call graph follows `bl` and tail calls (`b` to the start of another
  function). Calls and jumps through a register (`blr`, `br`) are listed
  and not followed; most `br` are the tables of a `match`. Recursion is
  listed too, and the depth counts each function of a cycle once
  (`dispatch` and `go_on` call each other once per system call).
- A frame is the size in `.stack_sizes`. Assembly has no entry there; its
  frame is the largest `sub sp, sp, #N` and the largest push `[sp, #-N]!`
  of its symbol. The paths of a panic count too.
- A second exception on top of the first is not summed: kernel code runs
  with interrupts masked, and the exceptions of the kernel itself stop the
  machine on the emergency stack (kernel.ld).
