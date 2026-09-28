# Initial Rust POSIX C ABI

`posix-abi` exports C file entry points implemented in GPL-3.0-or-later Rust:
`open`, `close`, `read`, `write`, `lseek`, `dup`, `dup2`, `dup3`, `chdir`,
`getcwd`, and `_exit`. Errors return the C sentinel and set current-thread
`errno`. Successful calls retain errno. Access modes and close-on-exec/fork
open flags are accepted; file creation and the remaining flags are pending.
Null buffers for zero-byte I/O still validate the descriptor and access mode.

ABI 1 is AArch64 LP64: pointers, long, size_t, ssize_t and off_t are 64-bit;
int is 32-bit. `stafeto_posix_abi_version()` checks the linked library version.
The versioned development sysroot is staged under
`target/posix-sysroot/0.1.0/aarch64-stafeto`. Numeric constants in the shared
C header are generated from `posix-abi/src/constants.rs`; template headers
provide the initial declarations. Build it with:

```
python3 tools/build-posix-sysroot.py --probe
cargo xtask posix-abi
```

The tool stages headers and builds `lib/libc.a` from Rust `posix-crt`. Its
`--probe` option invokes freestanding Clang/LLD against that archive with
`-nostdinc` and `-nostdlib`. The C source uses only the staged headers;
Picolibc is neither built nor linked. `cargo xtask posix-abi` boots both the
Cargo-linked C probe and the separately Clang-linked executable in QEMU,
then runs a distinct guest image for native-thread errno checks. The full
`cargo xtask ci` includes all three guest runs and target Clippy.

`posix-crt` unwraps init's ServiceArgs, builds up to 16 writable argument
strings, supplies a NULL-terminated argv and an empty environment, sets the
current-thread context, calls C main, and returns its eight-bit status.
The kernel's existing TPIDR_EL0 save/restore supports a 48-byte thread block
with errno at offset 16. A scope restores the previous thread register;
the first two words are reserved for later ELF TLS support. This block does
not yet load arbitrary `_Thread_local` objects from an ELF TLS segment.

The C probe checks type widths, ABI version, errno offset and retention,
argc/argv/environ, error numbers, shared file offsets, 64-bit seeking,
relative paths, zero I/O, duplication, redirection/restoration, and a file
at descriptor zero. The TLS probe creates two native guest threads and
checks distinct errno addresses and values across repeated context switches;
it also checks restoring a nested scope. Changing off_t to 32 bits in the
header deliberately fails the C static assertion; restoring it passes.
These checks follow the thread isolation requirement in
[POSIX.1-2024 section 2.3](https://pubs.opengroup.org/onlinepubs/9799919799/functions/V2_chap02.html).

This sysroot is an initial, experimental subset. Process allocation is
available through [the heap milestone](m2-rust-posix-heap.md). Stdio,
remaining headers, environment inheritance,
ELF TLS templates, constructor/destructor startup, signal handling, and
multi-thread process file state still require implementation. File scopes
borrow a PosixFs exclusively; a second thread can initialize its own errno
but sharing process descriptors needs the separate POSIX service. BusyBox
continues to use the MIT bridge; this GPL library stays out of its link graph.

Stat structures and metadata are added by [the next milestone](m2-rust-posix-stat.md).

The [directory milestone](m2-rust-posix-dir.md) adds descriptor-backed streams
and a private registry pointer to the thread block; errno stays at offset 16.
