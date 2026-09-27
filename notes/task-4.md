# Task 4: single-core locks and switch cost

The shipping AArch64 kernel now uses a one-core lock flag that needs no
exclusive-access instruction. Host builds and the `atomic-locks` feature
retain the atomic implementation. The scheduler reads the cleanup top and
nearest timer without taking their locks inside `decide`. Interrupts are
masked there, so neither queue can change between these reads and the
scheduler decision. A `baseline` test feature restores the original atomic
locks and locked reads for comparison.

`cargo xtask hvf` alternates 20 runs of each variant on each HVF GIC. On
QEMU 11.1.1, both GICv3 and GICv2 reported fast median 6 ticks against
baseline 7, and slow median 6 against baseline 8. Fast ranges were 6 to 6
and 7 to 7. Slow ranges were 6 to 7 and 8 to 8. The paired series and
their machine details are in `target/measure/hvf-gicv*.txt`.

The kernel test measures 1,000 control-loop turns and 1,000 FP register
save-and-load pairs with the same counter. Under HVF the control loop had
median 8 ticks on both GICs; FP pairs had median about 304 on GICv3 and
309 on GICv2. This probes eager FP preservation cost. The choice of lazy
FP for Cortex-A53 remains with the PinePhone work.

`xtask ci` disassembles the shipping ELF and rejects direct `memcpy` or
`memset` calls in `dispatch`, `alloc_zeroed`, emitted `alloc_table`
functions, relevant table-map functions, and the register-only prefix of
`channel::deliver`. `set_result` and some table allocators are inlined by
the release build, so the guard sees their emitted caller instructions.
The buffer and handle paths after the length check in `deliver` may call
memory helpers.

`fp_switch_cost_is_measured` fails if FP save/load is unexpectedly cheaper
than the matched control loop and reports both costs. The xtask parser test
fails if a helper call appears before the register-delivery boundary.
`cargo xtask ci` and `cargo xtask hvf` passed with the final changes.
