# Rust POSIX retained file results

History: the file worker and its reply journal are gone (notes/m5a-transport.md). This note records the earlier design.

## Problem and result

An interrupted file-owner request could lose a completed read, write or open.
A native handler could then make another request before the original resumed.
Returning EINTR discarded the original result even though its effect persisted.

Each private transaction now has a unique checked, nonzero process-wide nonce.
Execute reserves a journal entry before performing any file operation. It stores
the complete encoded reply, including errors. A duplicate Execute returns the
stored reply without repeating the operation. Fetch recovers a committed reply;
an absent entry reports EINTR, without resending the original Execute.

The client copies reply bytes into its own stack before sending Ack. Ack removes
only the matching entry and succeeds again if that entry has already gone.
Interrupted Fetch/Ack calls retry their internal control request with the same
nonce. Independent journal entries retain all outstanding nested outcomes.
Positive read/write results still close their existing cancellation frame with
Point::end; error/zero results follow the existing deferred cancellation policy.

The owner copies every request before making any nested kernel/service call.
It accepts explicit values and never invokes caller-provided job addresses.
The private envelope adds 16 bytes: maximum write payload becomes 996 bytes;
read replies retain 1016 bytes. RAM-service messages and direct PosixFs are
unchanged. BusyBox continues using its separate temporary MIT bridge.
All new Rust POSIX code and tests are GPL-3.0-or-later.

## Storage and initialization

The journal uses the existing Rust posix_heap allocator with its own mappings.
It commits 64 KiB chunks in reserved 0x20000000..0x28000000 storage. This works
before malloc initialization and preserves the existing startup checks.
The file owner borrows the process capability, which startup keeps open for
the worker lifetime, normally by moving it into allocation::init.

Reservation failure returns ENOMEM before effects. Ack returns node storage
to this private allocator. Warm mappings remain reusable until process exit,
as for the ordinary heap. Address space, mappings, handles and memory quotas
remain finite resource limits; no fixed per-thread reply or nesting limit
replaces the dynamic journal. The worker has no native handler bound.

## Verification

Host codec tests cover Execute/Fetch/Ack round trips, nonzero identities,
versions, reserved fields, truncation, extra control bytes and full messages.
Existing full-payload tests now validate the complete envelope and verify
that modifying the original source cannot alter the serialized write.

The native pthread probe interrupts the first reply after a result commits.
Two nested handlers perform more operations on the same thread. Writes must
produce ABC with three one-byte results; reads must independently return A,
B and C while preserving the shared offset. Nested opens/close must preserve
the original live descriptor. An Ack is interrupted after removal, exercising
its repeated acknowledgement while ancestor replies remain retained.

The probe holds 80 results to force growth beyond one mapping, fetches them all,
and removes alternating entries twice while checking the remaining identities.
A repeated Execute must produce one write and advance its offset once.
Handle exhaustion refuses a new mapping while existing capacity remains usable.
After filling that capacity, a refused write must preserve both offset and byte.
Repeated calls check reuse against warmed process handle and memory baselines.

A gated owner keeps a write queued. The test observes the native Sending state,
interrupts that thread and releases the owner. The call must return EINTR and
leave the shared file offset unchanged, proving absence of effects before accept.
The gate is captured before reply so a resumed client cannot arm a stale Ack.

Three transport frames plus two trampolines exceed the boot thread's 16 KiB
stack. The nested probe therefore runs on a normal managed 64 KiB stack.
This does not establish alternate signal stacks or arbitrary nesting depth.

Restored-source QEMU, Apple VZ, standalone/C ABI, UART/native cancellation and
interruption, guest/host Clippy and license checks passed. Six mutations were
caught: missing Fetch, early release, Ack of a neighbor and non-idempotent Ack
at stage 251; duplicate effects at 269; missing deallocation at quota stage 257.
The input-cancellation baseline now warms the journal before measuring reuse.
The existing queued-file interruption check lets Fetch/Ack finish before
checking EINTR, preserving its unchanged-output and ended-thread assertions.
Full cargo xtask ci passed on 1df6f3f, including BusyBox and shipping hot paths.
Init: 221 per machine; kernel: 165 normally and 176 under icount.
Kernel images: 154704 bytes normally, 171072 for Apple VZ.
Pthread/C ABI/standalone boot images: 442368/393216/405504 bytes.

## Remaining full POSIX work

General signal delivery is still disabled. Dispositions, masks, queues,
receiver selection, process delivery, stop/kill, restart policy, alternate
stacks and context-changing returns remain work. Pending cancellation inside
a handler requires the standard's async-cancellation safety policy.

Pthread and clock reply/state lifetimes also need reentry-safe ownership.
Local file scopes must protect exclusive Rust borrows. Allocation and other
unsafe regions need controlled delivery. This journal is released by ordinary
Fetch/Ack and process exit; abandoned outcomes after future nonlocal returns
or asynchronous thread exit require an explicit reclamation protocol.
Full mandatory POSIX.1-2024, conforming shell and utilities remain the target.
These functional checks establish no worst-case latency or RTOS timing bound.
