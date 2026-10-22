# WCET inputs: block coverage, kernel stack depth and the computed bound

Three tools in xtask give the inputs of a worst-case execution time
analysis of the kernel and a first computed bound. None changes the kernel.

## What is measured

`cargo xtask wcet coverage` runs the probes of the kernel group of `ci`
(the boots of the kernel and of its images, the kernel tests, the
init and service tests), the steps of the process service
(`process-steps`) and two probes that run under `-icount` (`entropy`,
`rtbench-short`), the tests of the test init (`init tests 512M`, with and
without `icount`) and the kernel tests of the icount build (`kernel tests
icount`: the test kernel and the one with the EL0 tests are images of their own)
under a QEMU TCG plugin (tools/wcet/trace.c) that records
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
cargo xtask wcet coverage [--jobs N] [--all] [--skip PROBE]... [--from DIR] [--out DIR]
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
- `--out DIR` names the directory under `target/` for the traces and the
  report (`wcet` by default); runs to compare keep apart so.
- A probe that fails does not stop the others: its trace is kept and the run
  goes on.
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

## The computed bound

`cargo xtask wcet bound` computes, for each system call and for the interrupt
paths, the longest path in instructions from the control-flow graph of the
kernel's basic blocks and its call graph, and sets it against the longest
measure of the kernel tests under `-icount`.

### How the bound is computed

1. The kernel tests of the icount build run under the trace plugin
   (tools/wcet/trace.c). The plugin writes, for each translation block that
   ran, its address, its instructions and its executions (to within a factor
   of two when a run ends by a kill). The report checks that each translation
   block agrees with the disassembly: it lies in a function of the image and
   has no branch inside it. The cost of a basic block is its number of
   instructions in the disassembly, which the trace confirms for each block
   that ran; the plugin itself adds no instruction to the guest.
2. Each function of the image (`llvm-objdump`) gets a control-flow graph: its
   basic blocks, the edges of its branches, the calls in each block, and its
   exits (a return, a tail call). The targets of a `br` that is the jump of a
   `match` come from the table in the image (the section's bytes), read by the
   pattern the compiler emits: the address of the table, a load of an entry
   and an add to a base. A `br` to the address of a function is a tail call.
3. A block costs its instructions and the bound of every function it calls.
   At a branch the path takes the longer way. A loop costs (B - 1) times its
   longest pass from the header back to the header, plus the longest way from
   the header to where the path leaves the loop; B is the bound of the loop
   in tools/wcet/bounds.toml, the most times its header runs for one entry.
   Nested loops multiply. A loop with several ways in (a region the compiler
   made by jumping into its middle) costs B times the sum of its blocks, B
   being the most times any of its blocks runs.
4. A call of a function that never returns (a panic, a halt) ends its path,
   which is no path of the analysis. Functions that never return are found
   from the graph.
5. The copies and fills of the builtins (`memcpy`, `memmove`, `memset`) cost by
   the size the call site sets with `mov x2, #n`, or the size an annotation
   `[[copy]]` gives for the function; the loops of the builtins count only for
   a copy with no size.

### What one row means

For a system call the estimate is the longest path through `dispatch` between
its two counter reads (the interval the kernel measures with `CALL_TIMING`),
with the handlers priced at nothing, plus the longest path of the call's
handler, plus `calibration.counter_read` from the annotations. The frame of a
call is the same for every call: the path through `dispatch` that leaves the
section, flushes the commands the call posted (at most `OUTBOX` = 96) and
copies a message. The measure is the longest of the kernel tests for that
call. For a call that works in portions (`mem_create`, `mem_map`,
`mem_unmap`, `mem_protect`) the kernel polls for an interrupt between two
portions, so the estimate is the path of one portion, and the measure is the
longest of the rows that measure a portion (`memory portions`). The rows of
the interrupt paths name the test rows that measure them. The estimate of
the path from the interrupt of a device to its driver covers `irq::deliver` and
one turn that frees retired objects (`qsbr::reclaim`); it leaves out what
`sched::exit_loop` does on that path (`decide`, the acknowledge, `thread::run`,
the entry and exit of the exception), since the loop is priced at nothing. It is
above the measure because the worst batch of `reclaim` costs far more than the
batch of the test, so `ok` there means no more than that. A full model of the
path is a task of its own.

Next to the estimate the row prints `takes`, k_static: the most calls of
`kernel::obj::acquire`, the one function the kernel takes `OBJ` through (kept
out of line for this), on any path of the entry, with the loops at their bounds.
Every stretch between two polls for an interrupt takes `OBJ` once (docs/smp.md),
so `wcet bound` refuses the kernel when k_static is above 1. A system call has
the larger of the count of its handlers and that of `dispatch` (an arm of
`dispatch` that takes `OBJ` hands its section to a handler that takes none, and
a handler that takes it itself sits in an arm that does not); a long call also
has the count of `go_on`, where its next entry starts. A function that begins a
stretch of its own, which a poll for an interrupt precedes at each call
(`portions`, `make`, `process_create_second`), is left out of the count of its
callers and has a row of its own. A plus sign follows the count when the path as a whole is incomplete (a loop
without a bound or a call through a register on it, whether or not it takes
`OBJ`); when no such loop takes `OBJ` and no call is unresolved, the count is
exact all the same, and a loop that takes it is refused apart from the sign. A loop that takes `OBJ` and has
no bound is refused outright, since its count could be anything.

The estimate is a bound on what the code can do with the loop bounds of the
annotation file. The tests reach a small part of it: a call that posts one
command measures a few hundred instructions where the frame holds the path of
96. An estimate below its measure is an error of the analysis (a path or a
bound missing) or an incomplete trace, and the command prints it with the word
`BELOW THE MEASURE`. The report prints the margin of the tightest entry as the
calibration margin.

### How to run

```
cargo xtask wcet bound [--from OUT-DIR] [--out DIR] [--annotations FILE]
```

Without `--from` the command runs the kernel tests of the icount build under
the plugin (about a minute with the build), then analyses
`target/stafeto-ktest-icount.elf`. The traces and the lines of the tests stay
in `target/<out>/bound-traces` and `target/<out>/measured`, and `--from` reads
them again, which is what to use while editing the annotations (a few seconds).
The report is `target/<out>/bound.txt`: the table of estimates and measures,
the loops without a bound (each with its address, its size and the constants
it compares against), the calls through a register that nothing resolves, the
recursion, the loops with several ways in, the loops on the analysed paths with
their bounds, the bounds that no loop matched, and the longest functions.

The kernel group of `ci` runs it as the step `wcet bound`. The step prints the
table. It fails when the analysis breaks (an annotation names no function, a
call of the kernel has no `[[call]]` entry, the file does not parse), when an
entry takes `OBJ` more than once (k_static above 1, or a loop with no bound that
takes it), and when a `[[path]]` marked `complete = "yes"` is not complete: a loop
with no bound or a call through a register that nothing resolves lies on it, so
the portions of cleanup, the firing of timers, the interrupt of a device and the
portions of the long calls keep every bound. An estimate below a measure, and a
loop without a bound on the path of a system call, are printed and leave the
step green.

### The annotation file

tools/wcet/bounds.toml holds one table for each kind of fact, each with a
reason (`why`):

| Table | What it says |
| --- | --- |
| `[calibration]` | `counter_read`: instructions added to every estimate |
| `[dispatch]` | the function of the system call dispatch, and the one it restarts a long call in |
| `[[call]]` | a call by its `abi::Call` name, the functions that carry it out, `long` for a call that works in portions, `portions` for the test rows that measure it |
| `[[path]]` | a path no call starts (symbol, test rows that measure it); `plus` names more functions that the path runs after the symbol, such as a turn of the way out of the kernel, whose bounds add to its own; `complete = "yes"` makes an incomplete path a refusal |
| `[[stretch]]` | a function that begins a stretch of its own: the count of takes of `OBJ` leaves it out of its callers |
| `[[loop]]` | `function`, `at` (the offset of the header block from the function's start, or `*` for every loop of it), `bound` |
| `[atomic]` | the bound of a loop that is no more than a lock word's protocol or a compare-and-swap retry (at most six blocks, no call) |
| `[[free]]` | a prefix of function names priced at nothing: code of the test builds, the way out of the kernel |
| `[[copy]]` | the size of the copies of a function whose call sites set no constant |
| `[[indirect]]` | the targets of a call through a register, by the offset of the instruction |
| `[[noreturn]]`, `[[unreachable]]` | a function that never returns, a block that cannot run |

A loop on an analysed path with no bound is named in the report with the
constants it compares against and the functions it calls, which is the hint for
the bound. A bound that matches no loop is named too: after an edit of the
kernel the offsets move, and the report shows which annotations to renew.

### Limits

- Calls and jumps through a register are followed only where an annotation
  names the targets or the pattern of a `match` is read from the image. Other
  ones (the calls of `dyn` traits) are listed and count nothing; their
  functions are the formatting of panics, which are no paths of the analysis.
- A table that the pattern does not match gives no targets: the `br` is listed.
  A table is read up to the next table of the function or to the first entry
  that is no instruction of the function.
- Recursion is listed, and the second call of the cycle counts nothing. Once
  `dispatch` has been entered by `go_on` for another call, the nested call is
  an entry of its own, priced at nothing for the restart.
- A bound of a loop is a reading of the code with a reason, and the tool
  checks it against the tests only through the estimates: a bound that is too
  small shows as an estimate below a measure when a test reaches it.
- The analysis reads the first image of the icount build. The second image
  holds the EL0 tests with the same kernel code, and its measures count in the
  comparison.
- The paths of the interrupt and of the cleanup portion reach the loops over
  the queues of commands (`RING` = 1024 entries a queue) and the stages of the
  teardown. Their bounds multiply along the nesting, so these estimates are far
  above the tests.
- The count of takes follows the control-flow graph. A take, a poll for an
  interrupt and a second take in the same function count as two takes on one
  path unless the second is a function marked `[[stretch]]`.
- Time is the number of instructions. Memory, cache and lock waits of other
  CPUs add to it; B_N = B + (N - 1) * OBJ_HOLD_MAX (docs/smp.md) adds the holds
  of the others.
