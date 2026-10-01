# Rust process allocation

The GPL-3.0-or-later Rust C ABI exports malloc, calloc, realloc, reallocarray,
free, aligned_alloc and posix_memalign. stdlib.h provides the declarations;
stddef.h defines max_align_t with the AArch64 16-byte fundamental alignment.
The experimental sysroot includes GPL and third-party license texts.
The license checker covers every POSIX Rust module and C header, and still
checks that BusyBox does not link a GPLv3 dependency.

## Allocator and ownership

posix-heap wraps linked_list_allocator 0.10.6 without its optional spinlock.
The upstream first-fit allocator splits and coalesces free blocks; its
original MIT and Apache notices are retained under docs/licenses.
Our wrapper stores requested size, allocation layout, alignment and prefix
in a private header preceding the returned payload. Arithmetic and Layout
checks reject impossible sizes before allocating or copying.

A private native thread owns the process heap. Clients send allocation
requests through one IPC channel and block until the reply. Serialization
allows one thread to free an allocation transferred by another, without
an allocator spinlock. Successful calls preserve the client's errno.
free preserves errno and accepts NULL; posix_memalign returns an error
number while preserving errno and its output pointer on failure.

## Startup and growth

Rust startup consumes its MANAGE process handle to initialize the worker
before calling C main. No DUPLICATE right is required from the loader.
Initialization requires exclusive startup and unused reserved ranges.
The worker uses a 16 KiB stack and a message page at 0xa00000; the contiguous
heap occupies 0x10000000 through 0x20000000 in the process address space.
Mappings grow in page multiples, with a minimum 64 KiB chunk and alignment
slack. Process page quotas and mapping limits can stop growth earlier.
Closing a memory handle leaves its mapping alive. Freed blocks are reused;
committed mappings remain until process exit.

The worker runs at the process ceiling, one above the main thread in the
init tables, and takes a client's priority on receive up to that ceiling. First-fit search, growth and large
zeroing or copying have no established worst-case bounds. This implementation
does not claim hard real-time allocation. Scheduling and latency analysis
remain separate requirements of the wider runtime.

## Allocation semantics

Zero-size allocation returns a distinct freeable pointer. realloc(p, 0)
keeps p as a freeable zero-size object; no bytes may be accessed through it.
Shrinking keeps the allocation in place and updates its requested size.
Growing allocates a replacement, copies the old requested bytes and then
frees the old block. Failure retains the original allocation and its data.
calloc and reallocarray check multiplication overflow. aligned_alloc
requires a power-of-two alignment and a size multiple; posix_memalign
requires an alignment that is also a multiple of pointer size.

## Validation

Four host tests cover alignment, distinct zero sizes, overflow, realloc
preservation and failure, deterministic fragmentation over 2000 operations,
and extension/coalescing across a committed-region boundary.
Disabling realloc's byte copy deliberately fails its preservation test;
restoring the copy passes all four host tests.

The C probe runs through both Cargo and standalone Clang/LLD linking.
It checks zeroing, alignment, overflow, errno, preserved outputs, growth,
quota exhaustion with live data retained, and reuse after failure.
The native thread probe transfers allocations in both directions, performs
overlapping allocation/free workloads, and checks distinct errno storage.
A completion notification replaces an iteration-count polling deadline.
RAM, Picolibc and BusyBox ash guest checks preserve the existing port path.
The full cargo xtask ci includes the new allocator tests and guest probes.

## Remaining work

scandir and C/POSIX alphasort now use process allocation and ordering;
see [m2-rust-posix-scan.md](m2-rust-posix-scan.md). The
[shared file owner](m2-rust-posix-shared.md) now serializes process state.
ELF TLS loading, blocking-I/O concurrency and cancellation,
environment inheritance, mmap, process lifecycle and the remaining POSIX
interfaces are pending. Heap-worker failure recovery is not implemented.
BusyBox retains its MIT bridge until the separate Rust POSIX service exists.
