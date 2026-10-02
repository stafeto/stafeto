# Rust POSIX mutex ownership

History: the mutex no longer goes through an owner thread: it waits by address in the layer (notes/m5a-transport.md). This note records the earlier design.

## Interfaces and layout

The GPL-3.0-or-later Rust C ABI adds pthread_mutex_init/destroy,
pthread_mutex_lock/trylock/unlock and mutex attribute init/destroy/gettype/settype.
pthread_mutex_t is 32 bytes, aligned to eight; attributes are 16 bytes,
aligned to eight. PTHREAD_MUTEX_INITIALIZER matches the Rust default.
NORMAL, ERRORCHECK, RECURSIVE and DEFAULT are exported; DEFAULT maps to NORMAL.
No object registry, per-mutex allocation or initialized-object limit is added.
Initialization requires exclusive access; destroyed objects can be initialized again.

ERRORCHECK self-lock reports EDEADLK. Recursive lock and trylock increment
an explicit count, up to UINT32_MAX, then report EAGAIN without changing it.
An intermediate recursive unlock keeps ownership. NORMAL self-lock blocks.
Busy trylock returns EBUSY; a foreign or unlocked unlock returns EPERM.
Destroying an owned object returns EBUSY, leaving its state unchanged.
Invalid types and invalidated objects return EINVAL; errno is preserved.
Additional diagnostics cover some otherwise undefined application operations.

## Serialization and waiting

The existing pthread owner manages lock counts and ownership in atomic fields
of each live object. Every application thread can park one request with the
mutex address, nonce and token; a blocked call retains the object until return.
An interrupted request retries the same nonce and replaces the old rejected token.

Final unlock chooses the highest effective native priority among waiters;
ties use the earliest nonce. It assigns ownership before waking that thread,
so another trylock cannot steal the unlocked interval. The chosen waiting
record is removed before caching and sending its successful LOCK answer.
A rejected reply retains ownership and the reply; retry returns that same result.
UNLOCK retries also retrieve the saved result without releasing twice.
The owner scans at most 64 application records; native priority queries are bounded.

These operations are not deferred cancellation points. Pending cancellation
survives the wait and acquisition, then is taken at a later cancellation point.
The default stalled behavior leaves a mutex held if its owner exits without
unlocking. Application cleanup handlers can release held locks during cancellation.
No priority inheritance or ceiling protection is claimed by this step.

## Publication

The application performs a Release publication RMW before its UNLOCK request.
The owner acquires the current publication using an Acquire RMW and records
new ownership with Release. Successful application acquisition uses an Acquire
RMW of that ownership, including when its pthread ID held an earlier cycle.
This carries ordinary protected writes through the owner to the next holder.
The successful-lock publication does not rely on IPC being a language-level fence.
Recursive partial unlock retains the same owner and reduces only its count.

## Checks

C checks run through Cargo and standalone Clang linking: layout/alignment,
static/dynamic initialization, all four types, attribute validation, foreign
unlock, busy try/destroy, recursive partial release, preserved errno and reuse.
129 simultaneously initialized and held objects verify no extra object limit.

The native Rust probe confirms six live AwaitingReply waiters and interrupts
each three times. One has pending deferred cancellation. Their priorities differ,
two tie, and an already waiting lowest-priority contender is raised before unlock.
The recorded protected sequence must follow the resulting priority/nonce order.
An active-section counter detects overlap; ordinary data carries a checked stamp.
The first handed-off holder waits inside its section while main checks EBUSY,
EPERM, remaining waiters and removal of the selected waiting record.
Committed LOCK, TRY, UNLOCK and DESTROY answers are deliberately interrupted.

The recursive probe injects the maximum count through a test-only helper;
lock and trylock must return EAGAIN and retain ownership. Two partial releases
verify exact count handling. A separate owner is cancelled while joining a live
target: its cleanup unlock must wake a mutex waiter, leaving that target joinable.
The final warmed quota and handle count must equal their baseline.
Test-only helpers are absent from the public sysroot library.
QEMU and Apple Virtualization.framework passed the native probe.
Four deliberate mutations were detected: exclusion (stage 92), recursive
partial release (103), waiter priority (96), and repeated UNLOCK (94).
Sources were restored before the ready implementation commit.

## Verification result

Full cargo xtask ci passed on 713da7b: init 221, kernel 165, icount 176.
License declarations and SPDX checks passed. No host-only tests were added.
The kernel is unchanged at 150608 bytes (Apple VZ 171072).
Mutex-operation latency and the new global blocking bound were not measured.

## Remaining work

This milestone adds process-private stalled mutex ownership. Timed/clock locks,
robust owner-death and consistency, process sharing and priority protocols remain.
Conditions, read/write locks, barriers, semaphores, attributes, sysconf, ELF TLS,
asynchronous cancellation, signals, process/fork lifecycle, other interfaces,
shell and utilities remain in the full mandatory POSIX.1-2024 roadmap.
Kernel limits are unchanged; a new global blocking bound is not established here.
