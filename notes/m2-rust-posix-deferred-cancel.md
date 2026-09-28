# Deferred Rust pthread cancellation

## Interfaces

The GPL-3.0-or-later Rust C ABI adds pthread_cancel, pthread_setcancelstate,
pthread_setcanceltype, pthread_testcancel and paired pthread_cleanup_push/pop.
New threads start enabled/deferred, independently of their creator.
pthread functions return error codes directly and preserve errno.
Invalid state/type leaves the previous-value pointer unchanged.
Asynchronous cancellation is explicitly unsupported with ENOSYS for now;
its constant is declared, and the implementation does not pretend to provide it.

read, write and pthread_join are cancellation points in this checkpoint.
Other required points and complete POSIX.1-2024 conformance remain work.
Disabled requests remain pending, including across a disabled read.
Enabling deferred cancellation does not itself introduce a cancellation point.
The next explicit point takes an already pending request before its operation.

## Delivery

Each launch record owns pending/enabled state and an active-point generation.
Sequentially consistent publication checks pending after entering a point.
The pthread owner interrupts live IPC when the target has an enabled point.
A BadState result can mean the target has not entered IPC yet; the reserved
1 ms timer retries delivery. A successful interrupt records that generation,
so cleanup waits for the same operation are not repeatedly interrupted.
New owner requests do not postpone a timer that is already armed.

Rust I/O internals return and drop their resources before the C boundary
acts on cancellation. UART reads first await the tagged CancelRead response.
Native console channel/timer handles are released by ordinary Rust return.
A positive I/O result wins the race with cancellation after delivery;
its bytes survive, and cancellation can remain pending for the next point.
Accepted file operations run in the serialized owner before subsequent cleanup
requests; no callback borrows the canceled caller's stack.

## Join and cleanup

A canceled join performs JOIN_ABANDON before invoking user handlers.
The target stays joinable and retains its exit value, including when the first
JOIN reply was rejected after the target had already terminated.
A successful join closes its cancellation window before internal JOIN_ACK.
The pending request can be taken at the next point after acknowledgement.

Cleanup macros register live stack nodes with a checked 24-byte C layout.
Only that thread changes its list. Pop removes a node before calling it;
execute=0 discards it, and execute!=0 invokes the registered routine.
pthread_exit and accepted cancellation disable cancellation and drain handlers
in reverse registration order before publishing completion and sending EXIT.
PTHREAD_CANCELED is the cancellation result delivered to a joining thread.
Reusing a thread slot resets pending, enabled, generation and cleanup state.

## Guest checks

The C probe runs through Cargo and separately linked Clang with Rust libc.a.
It covers initial state, deferred enabling, invalid arguments, unsupported
asynchronous type, disabled pending requests and read/write before effects.
It checks LIFO cleanup, normal pop modes, explicit exit with pending requests,
independent errno and fresh state after a canceled launch record is reused.

The pthread guest cancels a live joiner and keeps it blocked in a handler.
Main joins the original target while that handler is still running, proving
claim release precedes handler completion. Another case cancels a retained
JOIN result; its disabled handler successfully joins that target itself.

The pre-IPC race uses a real low-priority target and a temporarily elevated
owner. Kernel BadState is counted before the target enters receive; the
production timer retry must then wake it and run cleanup. Probe-only owner
handles and cancellation injections are absent from the regular sysroot.

cargo xtask posix-cancel-input cancels an actual UART read before host input.
Its disabled handler reads a character and CR through the same session;
main then reads another character, preserving errno. Thread stacks, native
handles, timers and memory charges return to the warmed baseline.
cargo xtask posix-cancel-input-vz repeats this on Apple Virtio.
The normal input probe is included in cargo xtask posix-abi, test and ci;
ci also checks Clippy with the native input feature.

## Remaining requirements

Asynchronous cancellation needs execution redirection and protected runtime
regions. General ELF TLS, thread-specific destructors, signals, synchronization,
other cancellation points, and cleanup of returned resources from future
blocking open/directory operations remain required. The full mandatory
POSIX.1-2024 API, shell and utility target remains unchanged.

## Deliberate failures

Skipping wake retries stalls the confirmed pre-IPC race.
Retaining the join claim fails stage 16 while the canceled handler still runs.
Skipping handlers or ignoring disabled state fails the C probe with code 220.
Omitting UART cancellation acknowledgement fails input stage 32.
All five mutations were restored before the final verification.

Final cargo xtask ci passed on 8f096a7: init 221 per machine, kernel 165,
and 176 under icount. Normal kernel 154704 bytes; Apple VZ 171072 bytes.
Implementation: [#44](https://github.com/stafeto/stafeto/pull/44).
