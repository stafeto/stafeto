# Parallel guest boots in xtask

Every guest boots on one core of the host, and the host has many. `cargo xtask test`, `ci` and `os-test` give their independent QEMU boots to a pool of threads (`xtask/src/jobs.rs`). `--jobs N` sets the size; the default is half the cores, and `--jobs 1` runs the boots one after the other in the old order.

## How it works

- A job keeps its output and the output of the commands it runs (`xtask/src/out.rs`). The pool prints each job whole, in the order of the list, with a line `== ok: name (seconds)` or `== FAILED: name (seconds): reason` after it. After a failure the pool starts no more jobs, and the error names every failed job.
- Everything the boots share is built once, before they start: relibc, BusyBox, the three kernel builds and the two test boot images. A lock (`BUILD_LOCK`) covers each cargo build of programs together with the copy of its result, so two builds never meet in the path that a package's builds share.
- Each os-test boot has its own image name and removes its image when it ends.
- The measurements that `write_measures` keeps carry the place of their job, so the files read in the same order whatever the pace of the jobs.
- Runs under HVF and VZ (`cargo xtask hvf`, `vz`) stay one after the other, since their numbers depend on the load of the host.

## Time of `cargo xtask ci`

Same machine (12 cores), warm cache, whole run:

| | time |
|---|---|
| before (serial) | 2 min 33 s |
| after (6 jobs) | 1 min 25 s |

## Runs under -icount

The numbers of a run under `-icount` count instructions. The lines `normal build ticks`, `log ticks`, `ipc round trip ticks`, `memory portions ticks`, `timer portions ticks`, `interrupt path ticks`, `device window ticks`, `upcall ticks`, `teardown portions ticks` and `B on` of a serial run and of a parallel run of `ci` are identical, and so are the `icount` lines of `target/measure/512m.txt` and `2g.txt` (53 lines each).

## rtbench on HVF and VZ at the same time

`cargo xtask rtbench --minutes 2` ran three times: serial A, serial B and concurrent. The table gives p50/p99/max in nanoseconds of the main rows.

HVF, p50/p99/max in ns:

| row | serial A | serial B | concurrent |
|---|---|---|---|
| s3_mutex_rival_30 | 41983/18116375/18116375 | 41983/18350079/20063833 | 41983/18118708/18118708 |
| s5_kill_busy_25 | 335/543/3250 | 375/2303/4458 | 375/543/2958 |
| s6_read_ready | 1343/2687/24208 | 1375/8959/4236916 | 1375/2623/10500 |
| s7_sleep_abs_1ms | 3583/7167/28084 | 3775/16895/6357667 | 3839/7551/476750 |
| s8_futex_pair | 503/751/38333 | 503/1055/2250 | 503/751/5708 |
| s9_service_round_trip | 295/423/7916 | 335/543/72000 | 335/375/6375 |
| s13_spawn_to_main | 50175/92159/4420458 | 55295/102399/139791 | 55295/94207/109250 |

VZ, p50/p99/max in ns:

| row | serial A | serial B | concurrent |
|---|---|---|---|
| s3_mutex_rival_30 | 41983/18142166/18142166 | 41983/18120083/18120083 | 41983/18118041/18118041 |
| s5_kill_busy_25 | 375/591/2708 | 375/639/12375 | 375/543/2708 |
| s6_read_ready | 1343/2687/7541 | 1343/2559/31583 | 1471/2687/17250 |
| s7_sleep_abs_1ms | 3583/7167/33250 | 3583/7295/29708 | 3839/7807/27792 |
| s8_futex_pair | 503/671/6625 | 503/671/1333 | 543/719/6791 |
| s9_service_round_trip | 295/375/10833 | 295/423/10541 | 335/375/11583 |
| s13_spawn_to_main | 53247/86015/833625 | 53247/94207/96083 | 55295/102399/857750 |

The two serial runs differ by up to 4 times in p99 and by up to 100 times in the maximum (`s6_read_ready` on HVF, `s7_sleep_abs_1ms` on HVF). The concurrent run stays inside that spread in p99 and in the maximum. The p50 of a few rows is 4 to 7 percent higher in the concurrent run (`s7_sleep_abs_1ms`, `s6_read_ready` on VZ), which is one or two counter ticks of 41.7 ns. `rtbench --minutes N` therefore runs HVF and VZ at the same time by default, and `--serial` restores the old order. A run that compares a change by its p50 uses `--serial`.
