# Rust POSIX thread capacity

## Published limit

PTHREAD_THREADS_MAX is 64, including the managed main thread.
limits.h also declares the POSIX minimum _POSIX_THREAD_THREADS_MAX as 64.
The managed registry derives its capacity from the public constant.
An ended joinable thread continues occupying a record until JOIN_ACK;
POSIX permits zombie threads to count against the thread limit.
Allocation/resource failure still returns EAGAIN before that maximum
when a process has insufficient quota or available kernel resources.

The Rust POSIX implementation remains GPL-3.0-or-later. The low-level
lib/abi resource constants retain that package's MIT license.

## Native resources

The kernel allows 128 non-ended threads per process. This accommodates
64 application threads and the existing heap, file and pthread owners.
The system thread-number table remains at 1024 entries.
Per-process mappings also grow from 64 to 128 so all separate stacks
fit alongside ELF segments, the loader stack and heap mappings.
Other kernel limits and teardown work-portion sizes stay fixed.

The 128-entry mapping table takes 4096 bytes. Its first mapping allocates
a dedicated page through PaidPages and records it in the process PageLog.
The mappings stage drains its counted memory-object references; the table
page remains charged and is returned with the process shell's page log.
Handle chunks and directories still use the existing 2048-byte block pool.
No new pool field or uncharged mapping allocation is introduced.

The pthread owner's stack grows from 32 to 64 KiB for its larger registry.
Thread-specific bindings take 64 KiB in static storage, up from 32 KiB.
Stack reservations now span 0x30000000..0x34000000, one MiB per slot;
the default mapped stack is still 64 KiB with a 4 KiB unmapped guard.
Message pages start at 0x2000000, one per application slot.
The C ABI/pthread probe process has an 8 MiB quota and 128 handle entries.
The temporary BusyBox bridge retains its own configuration.

## Guest checks

The C probe fills all 63 child records before joining them, observes
EAGAIN without changing its output ID or errno, joins every child and
creates another successfully. Headers and the minimum are checked at
compile time, through both Cargo and standalone Clang linking.
Its existing scandir exhaustion test has a larger pointer array to reach
real allocation failure under the larger quota and still verify cleanup.

The native Rust probe holds 63 children in kernel Receiving state,
one acknowledged child at a time. Each starts with NULL thread data,
sets its own binding and errno, waits, and verifies both after release.
Main retains its own binding and errno while all records are occupied.
An extra create must fail with EAGAIN and preserve its output value.
Heap allocation and RAM-file reading must succeed at that point.

Every child is released and joined with its expected result. The first
round warms paid pools and page tables, which persist by design.
The second round must restore both handle count and used quota exactly.
The earlier failed-create test now exhausts the 128-entry handle table,
so native creation still fails after mapping the stack and must undo it.
The capacity checks run in QEMU and Apple Virtualization.framework.

## Kernel checks

Existing mapping tests now require the advertised 128 entries and a
table that fits exactly one paid page. They cover the full limit,
slot reuse, references, busy ranges and complete draining.
The existing kernel probes derive their maximum-thread/mapping cases
from the ABI, exercising creation, limit recovery and teardown at 128.
The non-preemptible-path document records the larger fixed bounds;
its previous cycle figures remain historical measurements.
Full CI found the old ABI assertion; it now requires 128 mappings.
Close/Replies probes require eight fixed-size portions for two full
processes; their counts follow the enlarged crowd and retain interrupt checks.

Three deliberate mutations were rejected at guest stage 81: the old
pthread registry admitted only 31 live children, the old native-thread
limit only 60, and the old mapping limit only 60. Sources were restored.

## Measurements

Full CI on e5a86ff passed: init 221, kernel 165, icount 176.
The shipping kernel is 150608 bytes; C ABI and thread boot images are 303104.
On 512M/2G, stopping 128 ready threads costs 17965/17965 icount ticks;
first_map at the enlarged limits costs 16578/14490, unmap 3355/3355.
The printed field is stop_threads with threads=128, replacing stop_64.
These measured paths remain below the historical 20069-tick buffer case.
They do not establish a fresh B: 128 last-session senders, mapping-table
release and physical worst-case timing require further measurement.

## Remaining interfaces

This capacity step does not complete POSIX thread synchronization.
Mutexes, conditions, read/write locks, barriers, semaphores, complete
thread attributes, sysconf limits, ELF TLS, asynchronous cancellation,
signals, process/fork lifecycle, remaining interfaces, shell and utilities
remain part of the full mandatory POSIX.1-2024 implementation.
