# Numeric process identity for Rust POSIX

> Replaced by the labels of the process service's sessions ([#72](https://github.com/stafeto/stafeto/pull/72)): kind 10 of `object_info`, `ProcessIdentity` and `process_identity` are gone; `getpid` and `getppid` read the record's snapshot taken at startup.

## Behavior

The GPL-3.0-or-later Rust C ABI exports getpid and getppid through
unistd.h. pid_t is a signed 32-bit integer. Both calls read the calling
process's native identity, allocate nothing and preserve errno. All
pthreads in a process observe the same PID and parent PID, independently
of their managed thread IDs or native handle numbers.

The native MIT ABI and rt expose ProcessIdentity and process_identity.
ObjectInfo PROCESS_IDENTITY (10) takes a process handle with no rights
required and returns ID/parent ID in x1/x2. Bad arguments, handles and
object kinds follow existing ObjectInfo validation. Registers past x2
are preserved. No new system-call number or global handle lookup exists.

## Namespace and lifetime

A boot-wide sequence reserves positive numbers from 1 to i32::MAX.
IDs are never reused during the same boot. The final number is valid;
after it, allocation stays LIMIT_REACHED without wrapping through zero.
The sequence is a pure kcore model, protected by a separate short kernel
lock during creation. Validation precedes allocation, and namespace
reservation precedes address-space acquisition.

A failed later creation retires its reserved number. Existing creation
rollback returns memory/quota as before. A number is not an address,
local handle, process-table slot or managed pthread ID. A process stores
its ID through ended-shell lifetime, even after address-space teardown.
Its existing parent link keeps the parent shell's immutable ID readable.
Init is root 1 with parent 0; kernel-test roots also have parent 0.

This reads the native process tree. The current kernel ends descendants
when their parent ends. POSIX orphan adoption and process lifecycle must
still be implemented; the query does not claim to provide that policy.
UID/GID, process-directed routing and sigqueue are subsequent work.

## Verification

Two host model tests check positive monotonic allocation, consumed-ID
retirement, the last valid number and permanent exhaustion. A native
ABI test checks ID/parent word encoding and the namespace boundary.

A kernel test builds a real root/child/grandchild tree, retains the leaf
independently of handle tables, ends the root and drains teardown. IDs
and parent links remain unchanged until the retained shells are released;
object counts return to baseline. Its tree checks distinguish all IDs.

A new EL0 init test checks root 1, six create/kill/recreate cycles,
increasing child IDs, correct parent ID, a copy with no rights and ended
shell identity. Existing argument tests include bad reserved values,
invalid/wrong-kind handles and preservation past x2. Unknown-kind
checks now use the first selector after PROCESS_IDENTITY.

C and standalone probes check pid_t/result types, stable identity in
main and a child pthread, errno preservation and calls from a signal
handler. The Rust pthread probe compares exported PID/PPID against a
direct native query. Signal handlers also query identity during nested
entry and ordinary delivery, including the resource-pressure path.

Two focused xtask commands run only the affected guest tables:
cargo xtask kernel-test and cargo xtask init-test. These also make
targeted mutation checks independent of the full CI suite.
Targeted kernel/EL0 init tests and C ABI probes passed. Apple VZ passed
the pthread/signal checks. Host and guest Clippy passed.
Ten mutations were caught: reused/wrapped/skipped-last IDs on the host;
constant IDs, lost parents and ended IDs by the real kernel tree;
handle-as-PID by init; swapped PID/PPID at guest stage 450; errno at C
exit 199. Sources were restored before the complete verification.
Full cargo xtask ci passed on 4b7c6a6: kcore 402, init 222, kernel
166/177, all POSIX/BusyBox probes and shipping hot-path checks.
Normal/VZ kernels are 154708/171076 bytes, four bytes above #61 and
below 204800. Thread/C ABI/standalone images are 626688/516096/532480.
Normal/icount IPC timings match #61. The icount IRQ driver measurement
is 675 ticks, previously 673; bind/ack/portion are unchanged. New call
latency and a fresh global blocking bound were not measured.

## Remaining requirements

Numeric identity is a prerequisite for truthful sigqueue addressing and
si_pid, and for future process loading/wait interfaces. Queued real-time
signals, sender credentials, process routing, SA_SIGINFO with interrupted
context, timed signal acceptance, POSIX orphan lifecycle and remaining
mandatory POSIX.1-2024 shell/utility support are still implementation
work. Rust POSIX remains GPL-3.0-or-later; no completion is claimed.
