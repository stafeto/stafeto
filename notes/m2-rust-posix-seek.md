# Rust POSIX seek and I/O validation

The GPL-3.0-or-later `posix-fs` API now provides signed 64-bit `lseek`.
The file service owns the offset and computes the result in one request.
The new additive `SEEK_FROM` method carries an i64 delta and an origin;
the old u32 absolute `SEEK` method remains available to the C bridge.
`SEEK_SET`, `SEEK_CUR`, and `SEEK_END` map to `Start`, `Current`, and `End`.
`Data` and `Hole` cover the origins added by
[POSIX.1-2024](https://pubs.opengroup.org/onlinepubs/9799919799/functions/lseek.html).
RAM files report a single data extent and a virtual hole at EOF, including
zero-filled gaps. This is a permitted conservative extent representation.

A failed seek leaves the offset unchanged. Negative results report
`InvalidArgument`, signed overflow reports `OffsetOverflow`, and data/hole
searches at or past EOF report `NoData`. Seeking beyond EOF does not extend
the file. A later write fills the intervening gap with zero bytes.
The RAM payload remains bounded at 1024 bytes; large valid offsets can be
positioned and read at EOF, while writes beyond capacity report `NoSpace`.

Zero-length file reads and writes now reach the service, so it validates
the descriptor and access mode. Zero-length writes leave the file length
unchanged, even when the current offset is beyond EOF. Reading a write-only
file or writing a read-only file now reports `BadFileDescriptor` instead
of an invalid-request error. Console zero-length operations retain their
non-blocking behavior.

Two new RAM host tests and the guest probe verify origins, 64-bit extremes,
error preservation, gap contents, invalid descriptors, and access modes.
The zero-I/O test detects accidental file extension by an empty write;
the seek test detects offset mutation on errors, truncation to u32,
and missing zero filling. Removing the empty-write guard deliberately
failed the zero-I/O test because the file grew to 100 bytes. Restoring
the guard made that test pass. `cargo xtask ramfs` verifies the Rust client,
wire codec, service dispatch, and error mapping in QEMU. Existing
`cargo xtask cprobe` and `cargo xtask ash-dialog` check the C/BusyBox path.

This remains an incremental file layer. A C ABI, process-owned descriptor
tables, shared open descriptions for duplication and inheritance,
permissions, richer metadata, and byte-oriented namespace resolution are
still required. The GPL Rust client is kept outside BusyBox's link graph.
