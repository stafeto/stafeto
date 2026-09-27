# Task 2: durable machine measurements

Successful `cargo xtask test` and `cargo xtask hvf` runs now write files
under `target/measure/`. A machine's report is built from output that
already passed the boot, init, or kernel verdict. The writer first fills
a pending file in that directory and renames it over the final file.
A failed run does not publish a new report.

Each report names the source commit, machine, accelerator, QEMU version,
counter frequency, number of validated runs, and the kernel and boot
image sizes. The file keeps the measurement lines emitted by test init
and the kernel. On TCG this includes the normal build, log, IPC,
memory, timer, interrupt and device-window rows of spec 15.3. The
measured `icount` kernel also prints the maximum for each call number,
including zero for calls that the suite did not exercise. The test init
prints the nine KERNEL_STATS fields once before its verdict.

The round-trip measurement now also runs in the regular kernel test
image. This gives counter-tick samples under HVF without making the
tests whose timer moments require `-icount` run there. The `icount`
build keeps its original order: moving its round-trip test changed the
moment of a later timer test and made that test fail. The regular build
runs the round-trip test after its other EL0 tests.

`cargo xtask hvf` runs the regular kernel test image five times on each
GIC mode. Its report keeps each IPC line and summarizes the fast and
slow averages with minimum, median, and maximum. These are measurements
of the 1,000-round workload of the existing kernel test, in units of
CNTVCT_EL0 ticks. The per-round longest line remains in the file to
show intermittent pauses.

## Verification

`report_keeps_only_measurement_rows_and_sanitizes_machine_name` checks
the metadata and rows, the machine name used for the file, and the
sorting of three fast and slow samples. A swapped median or missing
measurement prefix fails it.

`cargo xtask test` passed after preserving the `icount` test order. It
wrote reports for 512M, 2G, GICv3, EL2 and EL2 GICv3. The 512M file
contains 28 call maximum lines, a KERNEL_STATS line, and the full TCG
measurement rows. The other files contain the rows their test runs make.

`cargo xtask hvf` passed with 220 accepted init tests and 164 kernel
tests on each GIC mode. Five round-trip samples per mode gave median
fast=7 and slow=8 ticks on this Mac and QEMU 11.1.1. The maximum of
individual rounds varied more than the five averages; the report keeps
both. The latest report names the commit of the tree used when it ran.

HVF does not run the long-call `icount` workloads. Their instruction
counts belong to the 512M and 2G TCG reports. The final part report
will compare those with the HVF counter times explicitly.
