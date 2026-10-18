# SMP

How the kernel uses several CPUs, the limits that keep its blocking time
bounded, and how to measure them.

## Model

- Each CPU owns its current thread, ready queue (64 levels), timers, cleanup
  queue, log ring, time accounting and active ASID. Interrupts, scheduling and
  the way out to EL0 take no lock.
- Another CPU's state changes by a command: a one-writer queue "CPU i to CPU j"
  and an SGI. A thread has at most one command in flight.
- The objects that CPUs share (channels, handle tables, mappings, processes,
  thread numbers, frames, ASIDs) are guarded by one ticket lock, `OBJ`, taken
  with interrupts masked for the links of the objects only. Copies of
  messages and the teardown of detached objects run outside it.
- Freed memory waits for a quiescent period (QSBR) of all CPUs.
- Scheduling is partitioned and fixed-priority: a thread has a CPU mask, by
  default its creator's CPU, and the kernel does not balance. A service on
  another CPU than its client runs at the client's level (a command lifts it).

## Limits

| Name | Value | Meaning |
| --- | --- | --- |
| `KERNEL_B_MAX` | 18 000 | longest non-preemptible portion of one CPU, instructions |
| `OBJ_HOLD_MAX` | 4 000 | longest hold of `OBJ`, instructions (icount) |
| `B4_MAX` | 32 000 | B + 3 * `OBJ_HOLD_MAX` |
| `S5_ICOUNT_MAX` | 3 063 | S5 on one CPU, instructions |
| `S5X_HVF_MAX` | 294 / 101 (GICv3), 340 / 216 (GICv2) | median of S5x on HVF, ticks of 16 ns: target in WFI / behind a lower thread; the guard of a regression |

`S5X_HVF_MAX` is the guard of a regression: it bounds the median, which a host
that preempts a vCPU leaves alone. The real-time limit of S5x bounds the longest
request, and the board (stage 7) gives it.

B_N = B + (N - 1) * `OBJ_HOLD_MAX`, S5_N = S5 + (N - 1) * `OBJ_HOLD_MAX`; `cargo
xtask kernel-test 512M icount` prints B_2, B_4, B_8 and fails B_4 above `B4_MAX`.
Under `-icount` QEMU runs the CPUs one after the other, so waits for a lock
and cross-CPU latencies there show the length of its time slice. Path lengths
come from the single-CPU tests, waits and latencies from HVF.

## Numbers (M4 host, HVF, 4 CPUs, median of 3 runs)

| Row | GICv3 | GICv2 |
| --- | --- | --- |
| S5x, target in WFI | 246 ticks | 310 ticks |
| S5x, target behind a lower thread | 94 ticks | 199 ticks |
| call to a service on another CPU | 347 ticks | 493 ticks |
| call to a service on this CPU | 12 ticks | 12 ticks |
| S5 on CPU 0 under a call storm of the others | 21 ticks | 23 ticks |
| local call under the storm | 111 ticks | 52 ticks |
| wait for `OBJ`, share of kernel time under the storm, 2 / 4 CPUs | 11.8 % / 23.2 % | 12.0 % / 21.5 % |

The storm is the worst case: three CPUs that do nothing but calls on one table.
The rule of the decision (finer locks when the wait is over 10 % of the
kernel time, or its longest is over (N - 1) holds) fires on the share under the
storm. The holds and waits on a host include the time a CPU the host
preempted spent holding or waiting for the lock, so the board (stage 7) decides.

## How to measure

- `cargo xtask smp-measure [tcg|hvf|hvf2] [RUNS]`: the test init on 2 and 4 CPUs
  with the kernel built with `smp-measure`, which counts for each CPU the kernel
  time of its entries from EL0, the longest entry, the waits for `OBJ` and the
  longest hold; prints the table and the verdict of the rule; writes
  `target/measure/smp-<mode>.txt`.
- `cargo xtask smp-probe [machine]`: the test init on 4 CPUs; on HVF it checks the
  median of S5x against `S5X_HVF_MAX`, runs the litmus tests MP (release and
  acquire) and SB (dmb) for up to 10^6 rounds (on HVF the forbidden outcomes
  are 0, and SB without dmb shows both threads reading 0 in 9 rounds of 10)
  and a lock torture of 250 ms (some 850 000 calls on HVF).
- `cargo xtask smp-window`: the test init on 4 CPUs with a kernel that holds
  a thread at a chosen point (`window-probe`): a receive or a send holds after
  its first look at a request for its entry, until another CPU makes the
  request, and a receive holds between its two sections, until the head of
  the queue moves. Then the kernels without the look under `OBJ` before a wait
  and without the second look at the head, each of which must fail.
- `ci` runs the test init, `smp 4 window` and `smp 4 asid` on 4 CPUs, and five
  guests on 4 CPUs beside their runs on one. `STAFETO_SMP=N` runs any probe on N
  CPUs; `STAFETO_MACHINE` names the machine of `posix-procs`.

## What programs see of the CPUs

- `object_info` CPU (kind 15, no handle and no lock) gives the CPUs up, the
  ticks of one CPU since it started, those it slept in `wfi` and those its
  entries from EL0 spent in the kernel, and the caller's CPU. The owner of
  a CPU counts the ticks of its entries when the entry polls (`Local::time`,
  3 instructions on the path of the null call) and its sleeps in `sleep`;
  the other CPUs read the words with one load each.
- `sysconf(_SC_NPROCESSORS_CONF)` and `_SC_NPROCESSORS_ONLN`, `sched_getaffinity`
  and the listing of `/sys/devices/system/cpu` (which BusyBox `nproc --all`
  and htop count) give the CPUs that are up. `/proc/stat` has a line `cpuN`
  for each CPU (user, system and idle from that call) and `/proc/cpuinfo` a
  record for each; the field `processor` of `/proc/<pid>/stat` is the CPU of
  the process's main thread.
- The process service puts the main thread of every new image (spawn, fork
  and exec) on the least busy CPU of the mask its page allows
  (`Page::cpus`, 0 for all); a process is busy when it ran since the last
  look or has no look yet. A thread starts on the CPU of its creator or, when
  the mask does not allow that, on the lowest CPU it names.
  `sched_setaffinity` writes the mask of its process: the kernel moves no
  thread, so the mask works for the threads made later and for the next exec
  (`taskset -c N command`).
- `cargo xtask cpus-dialog [N]` runs the dialog on N CPUs: `nproc`, the CPU
  lines, `taskset -p`, one loop per CPU on different CPUs, the busy time of
  each CPU, a command under `taskset -c` and htop with a meter for each CPU.
  `ci` runs it on 1 and on 4 CPUs.

## Not on several CPUs

- The kernel tests: their harness runs the tests on CPU 0 with the other CPUs
  outside the scheduler, and the first test that retires an ASID waits for them.
  The kernel on 4 CPUs is covered by the test init.
- The probes of the shell, `posix-sock`, `posix-ipc`, `posix-poll`, `posix-pty`
  steps and `posix-tty-control-steps`: with TCG on 4 CPUs the boot of `posix-sock` takes
  17 times as long (every invalidation of the TLB reaches all vCPUs), and the
  watchdogs of the services fire.
- `posix-procs`: 46 s on a quiet Mac and over its 60 s limit on the runners of ci with 4 CPUs
  (it passes on 4 CPUs under HVF and TCG when the limit is not reached).
- `posix-threads`: 2 x 10^5 handoffs outrun the time limit on TCG with more
  than one CPU.
