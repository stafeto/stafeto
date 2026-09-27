# Task 1: kernel call timing

Part 1.4e records the worst EL0 entry and individual system call times.
The `KERNEL_STATS` result now has nine words. The ninth is the longest
interval from the saved EL0 exception frame to the scheduler's first poll
for a pending interrupt. The exception handler starts this interval and
the empty-stack exit loop ends it. The counter is the virtual timer used
for all other kernel times. The record includes the call, the scheduler
transition, and any work before the first poll.

`object_info(KERNEL_STATS, x2=0)` leaves the message buffer alone. Selector
one writes 29 little-endian words at its start, indexed by call number;
slot zero is zero. The KSTATS right is checked before the write. Other
selectors fail with INVALID_ARGS before handle lookup. The reader in `rt`
returns the same nine ordinary fields with a separate array of maxima.

The `measure` kernel feature collects call times. It is on in the
`icount` test build. The shipping build writes zero maxima into the
buffer, keeping the same query layout. The recorded interval ends as
`dispatch` returns, so time spent waiting for a reply is excluded. The
three calls that can abandon their stack record before entering the
scheduler. All other early returns remain within `dispatch_inner` and
are recorded by its caller.

The STATS reply from init grew from 96 to 104 bytes to carry the ninth
kernel word. The protocol description, parser, writer, and shell test
fixtures follow the new layout.

## Verification

`kernel_stats_travel_in_nine_words` checks the ABI round trip, including
the new ninth word. Changing its word order or count fails the test.

`proto_init::stats_reply_round_trips` checks the 104-byte layout and all
offsets. A stale 96-byte parser or missing ninth word fails it.

`kernel_call_maxima_use_the_buffer` checks preservation with selector
zero, denial before a buffer write, zero in slot zero, and a nonzero
entry-to-poll time. Removing the rights check or writing on the simple
stats query fails it.

`object_info_checks_its_arguments` checks that selector two is rejected
before handle lookup. The measured kernel test
`object_info_reports_what_the_kernel_counts` checks that the call's slot
becomes nonzero after an actual dispatch. Omitting the measured record
fails it.

`cargo xtask test` passed with 221 test-init tests and the measured
`icount` kernel. The ordinary null call costs 271 icount ticks versus
the earlier 253. The measured kernel's null call costs 277 ticks. That
rise led to the `measure` feature for per-call collection. The persistent
entry-to-poll count remains in both builds for interrupt diagnostics.

The nine-word STATS response changes the init protocol for every client
in this tree. Its request and other responses retain their layouts.
