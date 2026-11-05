# The measurement of nginx (`cargo xtask nginx-bench`)

A manual measurement on an Apple Silicon Mac: ci can run neither HVF nor VZ,
so it only builds the four images and runs the host tests of the command.

## What it needs

- `brew install wrk vegeta` (wrk 4.2.0 for the ceiling and the connection
  errors, vegeta 12.13.0 for the latencies at a fixed rate); `brew install
  nginx` for the reference run on the Mac. vegeta counts a latency from the
  moment a worker takes the request, and when its pacer falls behind it
  sends the missed requests at once: a stall of vegeta itself is not in the
  latency. xtask computes each request's lag behind the schedule from its
  sequence number and gives its p99 and its longest for every stage.
- For VZ, the terminal needs the Local Network permission (System Settings,
  Privacy and Security) to reach the guest on the NAT.
- A quiet Mac: the load generator and the guest share its cores, and macOS
  cannot pin either. Note what else ran.

## The images

`boot-nginx-bench.img` (QEMU) and `boot-nginx-bench-vz.img` (VZ) are the shell
with the network service, nginx with the package's settings
(`tools/nginx/nginx.conf`, four workers, `listen 80 reuseport`), the variant
`/etc/nginx/exclusive.conf` with one listening socket, and the files
`/www/1k.bin`, `/www/10k.bin` and `/www/256k.bin`. Init's tables are the
network images': the shell's commands, and so nginx, have the quota of
`NET_COMMAND_QUOTA`, which holds the answers of 200 connections in flight
(a line `malloc(...) failed` of nginx marks a stage). The images `-nobuf` hold `netd.conf` with
`buffers 0`: every send goes by messages.

## The runs

```
cargo xtask nginx-bench --machine hvf               # QEMU HVF, 1 CPU, through a forwarded port
cargo xtask nginx-bench --machine hvf --cpus 2
cargo xtask nginx-bench --machine vz                # Apple VZ, the guest's address on the NAT
cargo xtask nginx-bench --machine vz --cpus 2
cargo xtask nginx-bench --machine hvf --no-buffers
cargo xtask nginx-bench --machine vz --no-buffers
cargo xtask nginx-bench --machine host              # Homebrew's nginx, a reference of the Mac
```

`--quick` runs only the files' check, the ceiling and one stage, shorter, to
check the command. A full run takes about 15 minutes:

1. every file once by its SHA-256;
2. `wrk -t2 -c64 -d30s` of `/10k.bin` (R_max) and `wrk -t2 -c200 -d30s` (no
   error of `connect`);
3. `vegeta attack` of `/10k.bin` over 64 connections that stay open at 10,
   25, 50, 75 and 90 % of R_max, 60 s each after a warm-up of 10 s;
4. `/1k.bin` at 50 % of R_max; the ceiling of `/256k.bin` and a stage at
   50 % of it;
5. `/10k.bin` with a new connection for each request, at 100 and 300 a
   second and at 25 % of R_max (run after step 6, with nginx started again);
6. nginx with `exclusive.conf`: its ceiling and a stage at 50 %;
7. `posix-net readfile` of `/www/256k.bin` and `/www/10k.bin` in the guest.

`--no-buffers` runs steps 1 to 4 and 7. `--machine host` runs steps 1 to 5
and stages at 1 000, 2 500, 5 000, 7 500 and 10 000 requests a second.

Run one measurement at a time: other guests share the Mac's cores. The
command claims a MAC suffix of its own (`vz-run --mac-suffix S` sets the
fifth byte of the MAC addresses, `02:73:74:66:SS:0N`; `cargo xtask` takes
the lowest suffix from 1 that no other run holds and no running `vz-run`
has), so a guest of `vz-run` beside it has another MAC address and another
lease on the NAT and cannot take the address over. Such a guest only
earns a warning at the start. A guest with the same suffix (a runner
started by hand with the same key) would take the lease: the command looks
again before and after every ceiling and stage, a row with a new guest of
the same suffix is marked `foreign guest`, and on VZ the run stops there.
The table notes the other
machines of QEMU and VZ and the Mac's load average at the start and the end.

## Reading the table

`target/nginx-bench/<time>-<what>/table.md` holds the numbers, the exact
command of every load and the notes; beside it the output of every tool, the
console and vegeta's results (`gunzip` gives the file `vegeta report` and
`vegeta encode` read). xtask sorts the latencies itself: p50 and p99 by the
nearest rank, p99.9 only from 100 000 requests. A stage is marked
`foreign guest` (above), `errors` with a failed request, an answer other
than 200 or a line `malloc(...) failed` of nginx, `saturated` below 95 % of
its rate, and `generator late` when the p99 of its lag behind the schedule
passes 0.1 ms; no marked stage goes in a table of p99. A ceiling of wrk is
marked `errors` with errors of `connect`, timeouts, answers other than 200
or `malloc(...) failed` (the errors of reading at the end of a run on QEMU
come from the forwarded port and leave it unmarked); no ladder is built on a
marked ceiling of `/10k.bin`. Beside each stage `seconds-<step>.csv` sums it
up by the second: requests, p50, p99 and the longest latency, answers other
than 200 and the longest lag.

`wrk` prints its transfer in MiB (1 048 576 bytes); the MB/s of the stages
are 10^6 bytes a second.

On QEMU the load goes through the user network's forwarded port, which
listens with a backlog of one: the connections of wrk and vegeta queue
there, and the ceiling is partly the Mac's. VZ reaches the guest directly.
