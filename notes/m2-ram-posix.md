# RAM file service and first C program

This is the first user-space file slice of subproject 2. `proto/fs` defines
OPEN, READ, WRITE, SEEK, STAT and CLOSE. `services/ramfs` owns a bounded
scratch file and a fixed `/etc/motd`. Each client connection has its own
eight-entry open-file table. The service uses one thread and no allocator.
The protocol has distinct missing-path, bad-descriptor and no-space codes.

`lib/rt/src/fs.rs` maps file descriptors 3 and above to the service. It
maps descriptors 0, 1 and 2 to the kernel console. Input currently polls
the native console and yields between empty polls; the normal UART driver
has a separate input path. This first interface is intended for the
dedicated RAMFS boot images, not yet for a general interactive shell.

`cargo xtask ramfs` builds `boot-ramfs.img`, starts the service and a
Rust client, and waits for `ramfs-probe: ok`. The client checks a read-only
file, missing path, invalid descriptor after close, overwrite through a
seek, size and stdout. Host tests check independent session offsets and
that an out-of-space write leaves the file intact. A wrong reply length
for CLOSE was caught by the first guest run and corrected.

`cargo xtask cprobe` builds Picolibc 1.8.12 at pinned commit
`2ae376c6cdf4fef90ca2388ecf7a07457fa63cff` through
`tools/build-picolibc.py`, then builds `boot-cprobe.img`. Its Rust entry
sets up the RAM service session and calls statically linked C code.
The C code uses `fopen`, `fread`, `fclose`, `open`, `read`, `write`,
`lseek`, `fstat`, `printf` and `fflush`. The shared `lib/posix` bridge maps
Picolibc's POSIX hooks to the Rust client. Picolibc is built without TLS,
with a 1 MiB internal heap and POSIX console support. The probe is
single-threaded.

The current RAMFS is bounded to two known paths, with one writable file
of 1 KiB. STAT returns the size of an open regular file. It has no path
lookup for arbitrary boot-image files, directory operations, creation,
or process-launch operations. These are explicit tasks before BusyBox
`ash`; the first applet can run directly from the boot image as an init
client, using the same RAM service for its files.

`cargo xtask busybox` downloads the pinned BusyBox 1.37.0 archive,
checks its SHA-256, applies a small compatibility layer, and compiles
the `cat` and `echo` applets with the same Picolibc. The GPL-licensed
`tests/busybox` wrapper invokes BusyBox's dispatcher with
`busybox cat /etc/motd` from the boot image. The QEMU test checks the
file's contents and the client's exit code 0. Only the applets needed
for this probe are linked; this is not yet an interactive BusyBox shell.
The generated BusyBox source and objects live under `target/busybox/`.
The next step toward `ash` needs process launch and wait, pipes,
descriptor duplication, signal behavior, and shared console input.
