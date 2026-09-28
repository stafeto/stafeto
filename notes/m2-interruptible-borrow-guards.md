# Interruptible local borrow guards

## Problem and result

Local C ABI file scopes keep PosixFs and directory state on their thread.
Dispatch and numeric operations temporarily form exclusive Rust references.
A native handler could previously reenter while those references remained
live across IPC, creating a conflicting reference to the same state.
Masking native requests for the entire operation would also stop IPC wakeups.

The kernel now keeps an independent checked entry-deferral nesting counter.
ThreadUpcallControl 3 begins one level and 4 ends one. The application mask
remains independent. An enabled request still interrupts an existing IPC wait,
but native preparation waits until every protected reference has ended.
Rebinding and native return reject live deferrals. Underflow and overflow
leave the previous state intact; no deferral record needs allocation.

A request can arrive before the protected operation starts a new wait.
Blocking receive rejects this already pending request without consuming its
queue. Send rejects it before enqueuing or entering the synchronous fast path.
Transferred handles are consumed exactly as on the existing Interrupted path.
Nonblocking receive remains usable for polling. Closed channels and invalid
arguments keep their existing validation and handle-ownership rules.

## Library lifetime

The MIT rt::upcall::DeferredEntry guard owns one current-thread level.
Its PhantomData prevents Send and Sync. Drop may immediately invoke a pending
handler, so it must run after every protected exclusive reference ends.
The guard changes no application mask and requires no heap storage.

GPL-3.0-or-later Rust POSIX routes both local dispatch forms through one
helper. The guard exists before raw TLS pointers become references; its
callback result cannot borrow the local file references. All success and
error returns release those references before deferred delivery. The shared
process client and sole file worker retain their existing IPC ownership.
Console input preparation already returns an owned transport snapshot,
so actual input waiting and UART cancellation remain outside the file borrow.

TLS blocks now live in UnsafeCell. The restore object keeps a shared cell
reference until the old TLS register is installed, preserving both lifetime
and interior mutation by handlers. Short guards cover installation and
restoration; neither guard covers the user's complete scoped callback.
The errno offset and 48-byte TLS layout remain unchanged.

## Tests and failure detection

Three new host tests cover nested deferral, request wakeup, preparation,
rebinding/return rejection, independent mask changes, underflow and overflow.
The existing malformed-command test now uses operation 5. Seven upcall
model tests pass, with 400 tests in the complete kcore collection.

A managed guest worker checks two protected levels and coalesced requests.
Pending receive returns Interrupted, while nonblocking receive consumes an
existing notification. Pending inline and extended sends enqueue nothing.
A moved handle is consumed and the process's live handle count is restored.
Dropping the inner level keeps the handler deferred; the outer invokes it.
Masked requests stay pending and caller mask changes survive guard removal.

Two further workers block in actual receive and accepted send. The parent
requests native entry; IPC returns Interrupted before either handler runs.
The handler enters only after both guards are dropped. An interrupted
accepted send invalidates its reply token through the PeerClosed outcome.
A bounded completion wait detects stranded workers without relying on the
outer runner's timeout.

A probe-only hook requests entry with local references already live.
The handler observes the live-borrow flag before creating another reference;
a broken guard reports failure without deliberately invoking Rust alias UB.
After deferral ends it opens, reads and closes through the same local scope.
Stat and open return EINTR without changing caller output. getcwd succeeds
without a transport wait and still delivers after its local borrow ends.
Nested errno scopes preserve register restoration, errno and pending masks;
an outer guard retains a request through a complete nested TLS scope.

## Validation and remaining work

Targeted QEMU and Apple Virtualization.framework guest probes passed.
Host upcall tests and target Clippy passed. Seven mutations were caught:
early native entry faults at its refused return, lost wakeup and omitted
pending receive/send gates fail at 369, kept transfers at 342, changed mask
at 345, and missing local protection at 351. Sources were restored.
Full cargo xtask ci passed on 81af635: 400 kcore host tests, BusyBox,
221 init checks, 165/176 kernel checks and shipping hot-path verification.
Kernel images remain 154704/171072 bytes (normal/Apple VZ). Thread, C ABI
and standalone boot images are 540672/442368/454656 bytes. Normal IPC
round trip is 1761 ticks; test fast/slow/buffer/handles are 1936/2125/3034/4209.
A new total non-preemptible bound was not measured.
The POSIX implementation and probes remain GPL-3.0-or-later; rt and ABI
retain MIT. Signal actions, signal sets, queues, restart policy, nonlocal
exits and asynchronous cancellation remain library work. Full mandatory
POSIX.1-2024 shell and utility conformance remains the goal.
Local RAM RPCs do not gain committed-outcome retention in this change;
interruptions after service effects still need explicit outcome accounting.
