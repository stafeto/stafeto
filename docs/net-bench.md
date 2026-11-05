# The measurement of HTTP on stafeto against Linux (`cargo xtask net-bench`)

A manual measurement on an Apple Silicon Mac (stage P7): ci has neither HVF nor VZ, so it builds the command and runs its host tests. The guests are the Linux guest of [linux-guest.md](linux-guest.md) and stafeto's image of the measurement (`boot-net-bench.img`), each on Apple VZ with four CPUs and 1 GiB, one guest at a time. The Linux guest is built on the Mac from pinned Alpine packages and never ships.

## What it needs

- `brew install vegeta wrk nginx iperf3` (vegeta 12.13.0 at a fixed rate, wrk 4.2.0 for the ceiling, Homebrew's nginx for the floor, iperf3 for the limit of the NAT). The versions go into the report.
- The Local Network permission for the terminal, as for `nginx-bench --machine vz`.
- No quiet Mac. Other work may run on it; the method below tolerates that and records it.

## The rows and the loads

| row | system | nginx workers |
|---|---|---|
| L1 | Linux 6.18 (Alpine 3.24), nginx 1.30.6 | 1 |
| L4 | the same | 4 |
| S4 | stafeto, `netd`, nginx 1.30.6 | 4 |

The fast path (F1) belongs to the next part of the stage.

| load | what |
|---|---|
| W1 | 900 files of 10 KiB (`/s/0000.bin` to `/s/0899.bin`, taken in turn), 64 long connections |
| W2 | 64 files of 256 KiB (`/l/00.bin` to `/l/63.bin`), 64 long connections |
| W3 | the files of W1, a new connection for each request (up to 64 at once) |

Both guests carry the same files and the same settings (`tools/nginx/nginx.conf`); `linux-guest check` proves it, and every guest the run starts passes the same fingerprints of `nginx -T`, of `/www` and of the versions before it is loaded. L1 differs from L4 in `worker_processes`, an allowed difference.

## The method

1. **Grid and walk.** One grid of absolute rates for all rows: 250, 500, 1 000, 1 500, 2 000, 3 000, 4 000, 6 000, 8 000, 12 000, 16 000, 24 000, 32 000, 48 000, 64 000, 96 000 a second (W2 and W3 start at 100: 100, 200, 300, 500, 700, 1 000, then the same). The walk goes from the bottom up, a step is a warm-up and a run of `--stage` seconds (default 10 and 60), and it ends at the first saturated step: below 95 % of the asked rate, p99 above 50 ms, an answer other than 200, or a line of nginx at crit. Before a guest's first step of a load, and when the guest sat idle for 45 s, one pass over the set at 2 000 a second (500 for W2) warms the open-file cache of nginx, so the low rates do not mix misses with hits.
2. **R\*.** The highest rate whose p99 is within 1 ms below the first saturation. Rates below R\* that fail 1 ms do not end the walk; they have a column of their own (the measure is not monotonic).
3. **Bisection.** Between the best rate L and the next point F of the grid, a probe at (L+F)/2, until (F-L)/L is at most 5 %.
4. **Correction for the lag of the load generator.** vegeta counts a latency from the moment a worker takes a request, and a pacer that fell behind sends the missed requests at once: its own stall is then in no latency. For each request the scheduled time is `t0 + seq/rate`, the lag is the time a worker took it against that, and the latency in every table is `lag + latency` (nearest-rank percentiles over all requests). The table of the report gives p99 as vegeta counts it and the p99 of the lag beside it.
5. **The floor of the Mac and the noise rule.** The same load on Homebrew's nginx on the loopback with the same settings and files, `--floor` seconds at a rate. It runs for a failing point of the walk and, in every round, at the three rates of the round. A step fails when p99 minus the p99 of the floor at that rate is above 1 ms and p99 minus the p99 of the lag is above 1 ms (a floor not taken counts as zero). A step with p99 above 1 ms that does not fail by this rule is noisy, and so is any step with a guest of VZ that came up beside the run. The marks "floor" (floor p99 above 0.5 ms), "generator" (p99 of lag above 0.5 ms) and "foreign guest" only describe a step. In the walk a noisy step is taken once more, and twice noisy leaves that rate undecided and the walk goes on; twice noisy in the bisection stops it with "at least L, above that the floor decides". A step that holds 1 ms is a pass whatever the marks.
6. **Rounds.** Confirmation and the runs at 50 and 80 % go in rounds, short and alternating. In round n the systems come in the order of a Latin square (round 1 L1, L4, S4; round 2 L4, S4, L1; round 3 S4, L1, L4), each started anew (and fingerprinted), so a slow drift of the Mac (load, temperature) falls on the systems alike. In a round, for each load of the system: the floor at its three rates, the ceiling by `wrk` (`-t2 -c64` and the criterion `-c100` (`-c200` for W2; 900 open files and 200 connections of one worker pass the 1 024 descriptors of a process), errors of connect; W3 with `Connection: close`), a confirmation run at R\*, and a run at 50 % and at 80 % of the R\* of the walk. R\* is confirmed by three passes in a row (p99 within 1 ms, one run per round); a run that fails, noisy or not, and a run that saturates (p99 above 50 ms from a single stall counts) steps R\* back by 5 % and counts anew, three steps at most, then R\* is "not confirmed" with all its numbers. The rounds go on for the open pairs up to 12 rounds, a limit of Mac time that the note does not have. A confirmation run is `--confirm` seconds (default 300) after `--confirm-warm`, stretched up to `--cap` seconds to reach 100 000 requests, since p99.9 is printed only from that many (below it the table has `-`).
7. **The CPUs of the guest.** `/proc/stat` per CPU before and after each confirmation run and each ceiling gives the idle share of each CPU and the CPU time per answer (Linux: everything but idle and iowait; stafeto: the same fields). A guest that prints fewer lines than CPUs leaves them unknown, and the table says so. "First limit": a CPU idle below 5 % at the ceiling is the guest's CPU; otherwise the NAT where the ceiling's transfer is above 80 % of the TCP limit of `iperf3`; otherwise the generator where a saturated step has a p99 of lag above 0.5 ms that is at least half of its p99; otherwise not determined.
8. **The limit of the NAT.** `iperf3` between the Mac and L4: TCP with one and four streams in both directions and UDP with 64-byte packets (packets a second sent), three repeats of each.
9. **The conditions.** For every step the Mac's one-minute load; for every guest the load and the other machines of VZ and QEMU at its start and end, its MAC and address, the fingerprints (`boots.tsv`).

The run promises no ratio between the rows; it gives numbers with the spread of their repeats. The rates of R\* are for this Mac on this day.

## The commands

```
cargo xtask net-bench run                      # nat, sweep and rounds for L1, L4, S4 and W1 to W3
cargo xtask net-bench run --systems s4,l4 --workloads w1 --phases sweep
cargo xtask net-bench run --quick --max-rate 2000   # a few minutes, to see that it works
cargo xtask net-bench run --resume target/net-bench/<time>
cargo xtask net-bench tables target/net-bench/<time>
```

`--stage`, `--warm`, `--confirm`, `--confirm-warm`, `--cap`, `--floor`, `--ceiling`, `--nat` set the seconds (the defaults are the full method: 10 and 60 for a step, 30 and 300 for a confirmation run); shorter values let the rounds be short on a busy Mac, and the report names the values used. `--rounds N` is the rounds that also take the ceilings and the 50 and 80 % runs.

A run keeps one file per step in `target/net-bench/<time>/results/`, the output of every tool and the console of every guest in `raw/` (`seconds-*.csv`, one line per second of a step; the files of results of vegeta stay there compressed), and the tables in `tables.md`. `--resume` replays the records: a finished step is not run again, a guest starts only for a step that is missing. A step in which the guest failed (a line at crit, a console that does not answer) is recorded as saturated with the reason, the guest is dropped, and the next step starts a new one. The tables are Table 1 (NAT), 2 and 2a (R\*, the numbers at R\*, the ratios), 4 (common rates), 5 (ceilings), 6 (the floor), 7 (conditions), 8 (W3 by rate) and the effect of the correction.

`tables` recomputes the walk and the bisection from the recorded steps under the present rule (where a rate the search asks for was never recorded it prints what the run recorded and says so) and reads the confirmation from the first run of each round: the highest rate with three passes in a row, else the rate with most passes, with "passes of runs" beside it. The retreat process itself cannot be replayed; a new run confirms.

Two properties of the method. The Latin square is cyclic: it balances the places of the systems in the rounds and leaves their predecessors unbalanced (S4 follows L4 in rounds 1 and 2); every guest starts anew, so the effect is small. The lag of a request is counted from the schedule that the least late request sets (`lags` in `nginx_bench.rs`), the note says the first request; the difference keeps the lag from going below zero.
