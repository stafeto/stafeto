# The measurement of nginx (`cargo xtask nginx-bench`)

A manual measurement on an Apple Silicon Mac: ci can run neither HVF nor VZ,
so it only builds the four images and runs the host tests of the command.

## What it needs

- `brew install wrk vegeta` (wrk 4.2.0 for the ceiling and the connection
  errors, vegeta 12.13.0 for the latencies at a fixed rate); `brew install
  nginx` for the reference run on the Mac.
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

Run one measurement at a time and no other guest beside it: every guest of
`vz-run` has the MAC address 02:73:74:66:00:01 and so the same lease on the
NAT, and a second VZ guest takes the address over in the middle of a stage
(answers 404 or refusals from the other guest). The table notes the other
machines of QEMU and VZ seen at the start and the end of the run.

## Reading the table

`target/nginx-bench/<time>-<what>/table.md` holds the numbers, the exact
command of every load and the notes; beside it the output of every tool, the
console and vegeta's results (`gunzip` gives the file `vegeta report` and
`vegeta encode` read). xtask sorts the latencies itself: p50 and p99 by the
nearest rank, p99.9 only from 100 000 requests. A stage is marked
`saturated` below 95 % of its rate and `errors` with a failed request, an
answer other than 200 or a line `malloc(...) failed` of nginx; neither goes
in a table of p99.

On QEMU the load goes through the user network's forwarded port, which
listens with a backlog of one: the connections of wrk and vegeta queue
there, and the ceiling is partly the Mac's. VZ reaches the guest directly.
