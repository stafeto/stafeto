# Task 5: event ring and trace command

The `trace` kernel feature records syscall entry, thread switches and
interrupt acknowledgements in the existing log ring. Each event has a
distinct ABI kind, timestamp and short payload. The feature increases
the ring from 64 to 256 records. The shipping image leaves it off after
the HVF comparison below.

`object_info(LOG)` keeps the destructive text read at x2=0. At x2 equal
to a sequence number plus one, it reads up to 12 records, including
shown text and events, without moving the console cursor. It returns
the next sequence plus one in x4 and the overwritten count in x2.
`rt::sys::log_peek` exposes that contract. Init gives the shell a KSTATS
resource named `trace`; the shell's `trace` command prints event times
and payloads, and reports overwritten records. A command reads the ring
snapshot seen by its first batch, so printing events cannot make the
command chase its own output forever. The console driver still prints
text only, and overwritten events do not inflate its text-loss count.

The host ring tests cover a read after overwrite, repeated reads without
cursor movement, and separate event and console text loss. The test init
checks both LOG selectors and the registers each may change. The xtask
trace dialog boots the trace image, runs the shell command and requires
an event line and another prompt. `cargo xtask ci` passed.

On QEMU 11.1.1 HVF, 20 trace-test runs per GIC gave fast medians 10 ticks
(GICv3) and 11 ticks (GICv2), versus 6 for the ordinary test image.
Slow medians were 11 ticks on both, versus 6. The overhead exceeds the
ordinary-image budget, so event writing stays behind `trace`.
