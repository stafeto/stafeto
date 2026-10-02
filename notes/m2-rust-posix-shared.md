# Shared Rust POSIX file state

History: the file worker is gone: the process files live under a lock of the layer and each thread performs its request itself (notes/m5a-transport.md). This note records the earlier design.

The GPL-3.0-or-later Rust C ABI now routes process file operations to one
private native worker. It owns PosixFs and the stable directory-stream registry.
Process threads share descriptors, their flags, backend offsets, the current
directory and DIR objects. Each calling thread retains its own errno.
This is a step toward the separate POSIX service required for BusyBox.

## Startup and thread scopes

Rust startup connects to RAM files and initializes the file owner using
its MANAGE process handle before passing that handle to the heap owner.
It does not require DUPLICATE rights. The file owner has a 32 KiB stack
and a message page at 0xb00000, separate from heap and client buffers.
Both owners publish initial state with release before thread_start;
the worker acquires that publication before reading its state.

tls::with_process installs independent errno and selects the shared owner.
Leaving a process scope leaves descriptors and streams alive, including
when a nested scope or another client thread ends. Local tls::with_files
continues to provide exclusive ownership for existing Rust guest probes.
tls::with_errno still has no file context. The private block uses its
padding at offset 20 for the mode and remains 48 bytes; errno stays at 16.
CRT now calls C main inside a process scope.

## Internal request lifetime

The original transport described below has been replaced by
[value messages](m2-rust-posix-messages.md); current requests own their payload
in message pages and the worker's receive buffer.


The transport sends an executor address and a pointer to a caller-stack
job in the same address space. The closure and result require Send.
UnsafeCell separates the worker-written fields from atomic publication.
The client publishes the closure with release; the worker acquires it,
takes and executes it once, publishes the result with release and replies.
The client acquires completion after the reply before taking the result.
It stays blocked throughout execution; no allocator or polling lock is used.

Unexpected IPC failure, malformed acknowledgment or absent completion ends
the process with status 125. Returning could recycle a stack still named
by an executing job. Worker death recovery and cancellation need a different
request lifetime model; fail-stop was the original stage's explicit policy.
The private channel is for trusted library calls, not external clients.
The separate service will need explicit methods and validated data messages,
without executable addresses or pointers into another address space.

## Operations and directory buffers

File and metadata entry points dispatch their existing Rust operations
through the owner. Directory calls use the same owner and registry.
Read data returns in a bounded owned buffer and is copied to the application's
destination by the calling thread; failures leave that destination untouched.
Returned stream and entry addresses are stable; clients synchronize use of the same
stream buffer through transfer or other application synchronization.
Independent stream buffers remain independent under the registry's UnsafeCell
storage. Selection and comparator callbacks still execute on the client,
after each directory request, so their existing reentry checks remain valid.

shared::cleanup closes streams and process descriptors after clients stop
using them. The worker remains alive until process exit. CRT does not wait
for quiescence on main return; kernel process teardown stops remaining threads
and closes process handles, disconnecting the RAM session.

## Validation

cargo xtask posix-shared boots a dedicated native guest program using the
existing RAM service table. Two clients use priority 30 within its process
ceiling. A shared descriptor and duplicate advance the same offset; one
thread closes the original and changes cwd, and the other observes both.
A directory opened in one thread is enumerated by the other, survives a
nested scope, and resumes at its service-owned position in the first thread.
Equal-priority clients both read bytes from the same open description;
aggregate character counts detect duplicated or lost reads.
The test also checks independent errno, descriptor reuse, scandir after
the cwd change, and quiescent cleanup.
Deliberately ignoring close fails at stage 18 when fstat still sees the fd.

cargo xtask posix-abi includes the new run after Cargo/Clang C programs
and the existing native errno/heap probe. Full cargo xtask ci includes it
and target Clippy for the new guest package. BusyBox retains the MIT bridge.

## Remaining work

Console reads now wait outside the owner; see
[the input milestone](m2-rust-posix-input.md). Future blocking file backends
still need deferred execution to avoid holding the owner.
Asynchronous backend requests, cancellation, signals, worker recovery,
cross-process sessions and fork/exec inheritance remain requirements.
ELF TLS and pthread interfaces still need implementation. This stage makes
current bounded RAM operations share one owner; it does not claim complete
POSIX thread support or hard real-time bounds.

Reference: [POSIX atomic file operations](https://pubs.opengroup.org/onlinepubs/9799919799/functions/V2_chap02.html).
