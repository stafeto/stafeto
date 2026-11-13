# The Linux guest of the measurement (`cargo xtask linux-guest`)

Stage P7 of the network subproject measures nginx on stafeto against nginx
on Linux, both as guests of Apple's Virtualization.framework on one Mac.
This page covers the Linux side and the check that both sides stand on equal
ground. The measurement itself (ladders, rates, tables) is the next part.

## What the guest is

Alpine Linux 3.24, aarch64, from the packages that
`tools/linux-guest/alpine.lock` pins by SHA-256: `linux-virt` 6.18.60,
nginx 1.30.6 and OpenSSL 3.5.9 (the versions of `packages/nginx.toml` and
`packages/openssl.toml`), musl, BusyBox, PCRE2, zlib, iperf3 and the
`alpine-baselayout-data` files and the `openssl` program. The build resolves no dependency: it takes
exactly the files of the lock, and every `DT_NEEDED` of every ELF file must be
found in the initramfs before the guest ever boots.

`tools/build-linux-guest.py` downloads the packages into
`~/.cache/stafeto/alpine/<sha256>.apk` (shared by all clones), checks each
against the lock and reads it in memory: no member of an archive is written to
disk under the name the archive gives it, and no program of the archives runs
on the Mac. It then

- unpacks the kernel from its EFI zboot wrapper (`vmlinuz-virt`: a PE file with
  `zimg` at offset 4 and a gzip payload) to the `Image` that VZ boots, and
  refuses a file whose payload does not carry `ARMd` at offset 0x38;
- takes the three modules virtio-net needs and the packet sockets of the DHCP
  client from the kernel package, unpacked, which `/init` loads with `insmod`;
- adds `tools/linux-guest/init` and an overlay made by xtask (below);
- writes `Image`, `initramfs.cpio.gz` (format `newc`, owner root, time 0, sorted
  names: the same lock and overlay give the same bytes) and `MANIFEST` (the pins,
  the licence of every package from its `.PKGINFO`, the SHA-256 of both images)
  into `target/linux-guest/`.

When Alpine drops a pinned build from the branch, the build stops and names the
package; update the lock and record the new pins in the report of the run.

## The same settings and files

`cargo xtask linux-guest build` writes the overlay from the sources that
stafeto's image uses: `tools/nginx/nginx.conf` as `/etc/nginx/nginx.conf`, and the
files under `/www`: `index.html`, `1k.bin`, `10k.bin`, `256k.bin`, the set W1
(900 files of 10 KiB under `/www/s/`) and the set W2 (64 files of 256 KiB under
`/www/l/`), from the generators of `rootfs` and `nginx_probe` and fixed seeds.
`/etc/nginx/mime.types` is the `conf/mime.types` of the nginx source that
stafeto's image carries, written into the overlay as well, so that a new pin of
the nginx package cannot change it.

The RAM service serves the files of an image straight from the image, so their bytes do not count against its writable pages; the limit is the table of the image, 2 048 entries and 2 048 files since this change (`lib/bootimg/src/rootfs.rs`, 1 024 before), which W1 needs.

Stafeto's side is `boot-net-bench.img` (about 48 MB with the two sets): the network image of VZ with its own
table of `init` (`services/init/src/table/bench.rs`). Its shell, and so nginx,
runs on all four CPUs (`BENCH_CPUS = 0b1111`); the network service has all four
too (one stack instance on each, its thread of the line's interrupts on the boot
CPU) and the other services stay on the CPUs of the services. No other image
names `BENCH_CPUS` (a test of `init` scans the tables). Provisional owner ruling
B2: four CPUs and 1 GiB for both guests (`vz-run --cpus 4 --memory 1024`).

The row F1 has its own image, `boot-net-bench-fast.img`: the image of nginx on
the stack on VZ (two network devices, `nginx-fast`) with the table
`table-bench-fast-vz`, which differs from that image's table in the launcher of
the shell alone (all four CPUs). The second device has the static address
`192.168.64.250`. ci builds both images.

## The check

```
cargo xtask linux-guest build    # target/linux-guest/{Image,initramfs.cpio.gz,MANIFEST}
cargo xtask linux-guest run      # the guest's shell on the terminal (poweroff -f ends it)
cargo xtask linux-guest check    # both guests, one after the other
```

`check` claims a MAC suffix for each guest (`vz-run --mac-suffix`), boots it with
four CPUs, and compares with what stafeto's sources say:

- `nginx -V`: the version of nginx and of the OpenSSL it was built with;
- the fingerprint of `nginx -T`: the lines of nginx's own about the syntax and
  the test are dropped, the allowed differences (`worker_processes`, `user`,
  `worker_connections`, `worker_shutdown_timeout`, the `reuseport` parameter) are
  masked, and the rest is hashed; the expected text is built from
  `nginx.conf` and `mime.types`;
- the files under `/www`: `openssl dgst -sha256 $(find /www -type f)` (the one
  hashing program both guests have; stafeto's BusyBox has no `sha256sum`). A file
  that is missing, extra or changed is named; the paths and hashes are hashed once
  more into the digest of the report;
- every file of `/www` (the four of the first measurements, the 900 files of W1 and
  the 64 files of W2) fetched from the Mac over HTTP and compared byte by byte, so a
  server that refuses one file of the sets, as nginx does when it has no descriptor
  left for it (`open() failed (24: Too many open files)`), fails the check;
- nginx must not print `running with OpenSSL`: the library of the guest is the one
  nginx was built with;
- the lease macOS gave the guest's MAC address (`/var/db/dhcpd_leases`) is the
  address the console shows;
- `nproc` says 4, and the MAC address of the guest is the one the run set.

A guest that differs ends the check with an error, and no run starts on it. The
console logs, the output of `nginx -V`, the lines `configure arguments` of both
sides and their difference (`configure-arguments.txt`), the attempts of the first
answer (`*-first-answer.txt`), the kernel settings of the Linux guest
(`linux-sysctl.txt`, the defaults the measurement of "Linux as it comes" runs on)
the Mac's load average and the other machines of VZ and QEMU before and after each guest (`*-conditions.txt`; no quiet Mac is asked for, the conditions are recorded) and the virtio-net feature bits go to `target/linux-guest/check-<time>/`. The two
times of the table are liveness checks: from the start of `vz-run` to the prompt,
and from the moment four workers of nginx and the shell are up to the first answer
on the Mac, taken the same way on both sides.

## What stays different

The fingerprint of `nginx -T` covers the text of the settings only. What is
built into the two nginx differs, and the report of a measurement names it:

| What | Linux (Alpine) | stafeto | Effect on HTTP |
|---|---|---|---|
| compiler and flags | gcc 15, the flags of `abuild.conf` of the branch (stack protector, PIE) | clang, `-Os -fno-stack-protector -fPIC -mno-outline-atomics -mfix-cortex-a53-835769` | CPU time per request |
| modules built in | `gzip`, `gunzip`, `gzip_static`, `sub`, `addition`, `realip`, `dav`, `flv`, `mp4`, `slice`, `secure_link`, `auth_request`, `stub_status`, `v3`, dynamic modules | `--without-http_gzip_module`, `ssl` and `v2` only | slight: the filters of `gzip`, `sub`, `addition` and `gunzip` sit in the chain and test their flag on every answer; one setting cannot level it |
| `--with-threads`, `--with-file-aio` | yes | no | none while `aio` is off |
| PCRE2 | the library of Alpine, with JIT | 10.49 built here, no JIT | none: no regular expression in the settings, `pcre_jit` is off |
| OpenSSL | `libcrypto3` of Alpine with assembly | 3.5.9 built here, assembly with probes by SIGILL | none for HTTP, large for TLS (W4 and W5: print `openssl version -a` on both sides) |
| libc and allocator | musl, mallocng | relibc | a property of the systems |
| `--with-compat` | yes | no | negligible |

The raw `*-nginx-v.txt` and `configure-arguments.txt` of every check hold both
sides. Alpine's packages are pinned by SHA-256 taken from one download over
HTTPS on 2026-11-05; the signatures of the packages and of `APKINDEX` are not
checked.

## The descriptors the sets need

nginx keeps every file it served open with `open_file_cache max=1000`, so a worker
that has served all of W1 holds 900 files, its sockets and the descriptors it has
besides (the guest of Linux showed 14 of those for an idle worker). Both systems give a
process 1 024 descriptors: `RLIMIT_NOFILE` of Linux is 1 024 by default, and the
layer of stafeto takes 1 024 numbers (`OPEN_MAX` of `lib/posix-fs`). 900 files, the 64
connections of one worker and the 14 others stay under that on both systems, and
a set of 1 000 files would not. The RAM service gives a session 1 072 places, 8 192
open descriptions for the whole service and 6 144 of them for one root
(`services/ramfs`), so its own limits are no tighter than the layer's.

## The guest is never shipped

The guest is built on the machine that measures and stays in `target/`. Its
kernel and BusyBox are GPL-2.0-only, so a release that carried them would owe
their sources. `tools/dist.py` stops a release in which an archive holds a
member named like the guest (`target/linux-guest`, `initramfs.cpio`, `vmlinuz`,
`.apk`) or a file with the SHA-256 of its `Image` or `initramfs.cpio.gz`
(`tools/test_linux_guest.py` covers the check). The build script, the lock and
`init` are source files of the repository and ship with it under the project
licence.

## Host tests and ci

`tools/test_linux_guest.py` (the builder on synthetic files: pins, zboot
headers, the closure of libraries, the archive, the dist check) and the tests of
`xtask/src/linux_guest.rs` (the fingerprints) run in `cargo xtask ci`
(`host tests`); the step `nginx-bench images` also builds `boot-net-bench.img`.
Ci downloads no Alpine package.
