# Task 3: fast-path rule and heavy portions

The condition that a waiting receiver outranks cleanup and ready threads
now lives in `kcore::sched::Scheduler::can_hand_off`, beside `pick` and
`hand_off`. The channel fast path uses that decision before it meets the
request. The pending-interrupt and testpoint checks remain in the kernel.
The host test covers cleanup one level below, at, and above the receiver
and a ready thread at the receiver's level. The existing 10,000-world
comparison between wake/pick and hand-off also checks the new condition.

The `icount` kernel has an in-tree teardown workload with 11 thread
buffers and 42 handles in transit. Nine threads hold four handles each
and two hold three, exactly filling the 64-unit Buffers portion. The
handles name the system resource, so the workload tests the size of the
portion without adding the cost of `CLIENT_GONE` wakeups. Its process
also holds 32 charged pages to exercise the Shell stage. A separate
fixture stops 64 ready threads in a single call.

The memory workload now measures the first `mem_create` entry while a
single free block of the allocator's largest order is available and all
other free blocks are held by the fixture. It returns those blocks after
the call. An EL0 test closes the last channel handle and then ends its
thread; the measured build records that `thread_exit` entry. The test
of a mapping whose target dies between portions also prints the entry
that abandons its change.

On QEMU 11.1.1 under `-icount`, the 512M machine measured Buffers 5,116,
Shell 15,030, stop of 64 threads 8,368, first high-order `mem_create`
11,368, thread exit after close 1,032, and abandoned change 279 ticks.
The 2G results were within 30 ticks of those. A 32-page Shell portion
took 58,634 ticks in the test build because each freed page was poisoned.
The Shell limit is now eight pages: its measured portion stays below the
20,069-tick blocking bound, while Buffers stays at 64 units. The
previous session-heavy Buffers fixture remains the bound; the in-tree
resource-handle fixture does not replace its 20,069-tick result.

## Verification

`hand_off_yields_to_cleanup_at_or_above_the_receiver` fails if cleanup
at the receiver's level is allowed through, or cleanup below it is
unnecessarily blocked. `hand_off_matches_wake_and_pick` fails if the
new condition allows a different scheduler state after a hand-off.

`teardown_portions_are_measured` checks that all 11 buffers and 42
handles fit one portion and that no process or thread stays allocated.
The existing `shell_goes_in_portions` now checks eight pages per portion
over nine portions. Restoring the 32-page limit fails its counts.

`thread_exit_after_channel_close_is_measured` fails if the close-and-exit
program does not complete or the measured `ThreadExit` slot stays zero.
The existing `dying_target_ends_the_map` checks that the abandoned change
returns BAD_STATE and keeps no mapping; it now records its time too.

`cargo xtask test` passed, including both 512M and 2G measured kernels.
The new lines appear in their `target/measure/` files. The ordinary
kernel test images and the HVF image keep their existing test contracts.
