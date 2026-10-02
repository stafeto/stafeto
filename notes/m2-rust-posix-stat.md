# Rust POSIX stat metadata

The Rust C ABI now exports stat, fstat and lstat against the RAM namespace.
The GPL-3.0-or-later posix-types package owns their LP64 structures and
checked conversions; posix-abi owns the C entry points and errno mapping.
Headers and libc.a remain part of experimental sysroot 0.1.0, ABI 1.
Existing file calls and the temporary BusyBox bridge remain compatible.

## Data path

INFO_PATH and INFO_FD extend proto-fs without changing existing methods.
Each reply contains a four-byte status and 92 bytes of explicit fields.
No C structure padding is transported over IPC. Readers reject truncated
messages, invalid kinds, permission bits outside 07777, zero block sizes,
and trailing bytes. The request/reply fits MESSAGE_MAX of 128 bytes.

The RAM service supplies stable device/inode identity, kind, permissions,
link count, owner/group, size, preferred block size, 512-byte block count,
and access, modification and status-change timestamps. Root has inode 1
and four links; etc and tmp have two links. Files have one link each.
The immutable motd has mode 0444, and opening it for writing gives EACCES.
The scratch file has mode 0644; size reflects successful writes.
Independent sessions observe the same metadata and inode identity.

A successful read request with a positive length updates access time,
including an EOF return of zero. A successful positive write updates
modification and status-change times. Zero-length I/O and errors preserve
metadata. Untimed Ram::read/write remain deterministic data primitives;
the service uses read_at/write_at with its clock on every request.

## ABI and errors

struct stat is 120 bytes, aligned to eight bytes. st_size is at offset 48
and st_atim at offset 72; each timespec occupies 16 bytes. Rust and C
independently assert these properties. Mode constants are defined in
posix-types and generated into the shared stafeto/abi.h header.

Unsigned device, inode and link fields retain their full 64-bit range.
Sizes and block counts above INT64_MAX fail with EOVERFLOW. Invalid
metadata fails with EIO. Conversion happens before writing the caller's
output, so errors leave the destination untouched. Null arguments report
EFAULT; invalid and closed descriptors report EBADF. Relative paths use
the working directory; a trailing slash on a regular file gives ENOTDIR.

## Validation

- cargo test -p posix-types -p proto-fs -p ramfs --lib checks wide values,
  normalized nanoseconds, signed overflow, malformed metadata, wire field
  order, every truncated length, inode identity and precise clock updates.
- cargo xtask posix-abi boots the same C program through Cargo and direct
  Clang linking. It checks stat/fstat identity across dup, file and console
  kinds, lstat, errors, output preservation, size and timestamp updates.
  The existing native-thread errno probe also runs.
- cargo xtask ramfs checks existing file, path and descriptor behavior.
- cargo xtask cprobe and cargo xtask ash-dialog check the temporary bridge
  and interactive BusyBox path. cargo xtask ci includes host and guest tests.

Changing the access-time condition from a nonempty request to a positive
return count deliberately fails the RAM test at EOF: access time remains
30 where 40 is expected. Restoring the condition passes the regression test.

## Remaining work

The service clock is the platform counter expressed in nanoseconds and carries
no configured wall time since the Unix epoch. A realtime clock service and
epoch provisioning are required for conforming file times. The fixed RAM
namespace has no symbolic links, so lstat currently equals stat; links
require final-component no-follow resolution. All owners are uid/gid zero;
credential-based access checks, chmod, chown and mutable directories remain.
Console fstat supplies provisional character-device metadata with zero
timestamps until a terminal service owns its node. st_blocks reports the
logical RAM extent rounded to 512 bytes, without disk allocation accounting.
These probes establish the implemented subset; full POSIX conformance lies outside their scope.

References: [read semantics](https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/read.html)
and [file timestamp rules](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html).
