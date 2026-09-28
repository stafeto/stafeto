# Rust directory streams

The GPL-3.0-or-later C ABI now exports opendir, fdopendir, readdir, closedir,
dirfd, rewinddir, telldir and seekdir. dirent.h defines an opaque DIR type
and a 144-byte LP64 dirent with an eight-byte inode, a d_type extension,
and a NUL-terminated name. Rust and C assert the layout independently.
Mode, type and name constants are generated from Rust definitions.

## Descriptor ownership

Read-only open now accepts RAM directories. Opening a directory for writing
fails with EISDIR. O_DIRECTORY is checked atomically by the RAM service;
a regular file fails with ENOTDIR. Regular-file behavior is unchanged.

Each directory open description owns its current entry position. Separate
opens have independent positions; dup shares the backend and its position.
The new READ_DIR_FD protocol returns kind, inode and raw name bytes and
advances the service-owned position after an entry. EOF leaves it unchanged.
Directory reads, including legacy path-based reads, update directory atime.
Data read/write on a directory fails with EISDIR without changing metadata.

opendir allocates a process descriptor and sets its close-on-exec flag.
fdopendir adopts the supplied directory descriptor without duplicating it
or changing its flags. Failure leaves ownership with the caller. dirfd
returns that same descriptor, and closedir closes it. A duplicate keeps
the open description alive. The caller must not close or replace a stream's
owned descriptor independently. Rust callers must explicitly close Directory.

## Storage and positions

The current single-owner ABI scope reserves OPEN_MAX stable stream slots;
streams compete with files for the 32 process descriptors. This gives the
same EMFILE boundary as ordinary open, including freed descriptor zero.
Each stream has its own entry buffer. UnsafeCell protects these buffers
from whole-registry mutable reborrows when another stream is used.
Pointers are valid only in the file scope that created them. Slots can be
reused after closedir; pointers to closed streams are invalid.

The private thread block grows to 48 bytes for the registry pointer while
errno remains at offset 16. with_errno requires no directory storage.
Returning from with_files attempts to close remaining owned streams;
ordinary duplicated descriptors survive. Process scopes now share the
registry through [the file owner](m2-rust-posix-shared.md). Process allocation is now
available as described in [m2-rust-posix-heap.md](m2-rust-posix-heap.md).

The fixed namespace uses entry indices as opaque position cookies. telldir
reads the service position; seekdir restores it and rewinddir resets it.
Callers pass cookies returned by telldir for that stream since its last
rewind. Negative positions fail without moving the cursor. SEEK_DATA and
SEEK_HOLE on directory descriptors fail with EINVAL. These rules will need
stable cookies and mutation handling for a mutable filesystem.

## Validation

Two new protocol host tests check wide inode values, byte names, EOF,
truncated headers, malformed kinds, zero inode, empty names, NUL and slash.
A RAM host test checks independent positions, actual inode values, access
updates, restoration, invalid requests and preservation on errors.
Deliberately disabling position advancement fails at the second entry:
the test receives dot instead of dot-dot. Restoring the increment passes.

cargo xtask posix-abi boots the extended C probe through Cargo and standalone
Clang linking. It checks relative paths, types, inode values, independent
entry buffers, EOF errno retention, position cookies, descriptor adoption,
duplication and closing, invalid arguments, O_DIRECTORY, EMFILE and reuse.
cargo xtask ramfs also checks close-on-exec, fdopendir flag retention and
scope cleanup with a surviving duplicate. cprobe and ash-dialog preserve
the existing BusyBox path; cargo xtask ci includes the full verification.

## Remaining interfaces

scandir and C/POSIX alphasort are now provided by
[the selection milestone](m2-rust-posix-scan.md). Additional locale data,
locale objects and the remaining locale interfaces are still pending.
Mutable namespaces, symlinks, byte-path lookup and full credential checks
remain pending. The current protocol fits names in one IPC message; larger
filesystem entries will require a bounded continuation or shared buffer.
The fixed C name array follows the experimental NAME_MAX of 128 bytes.
File timestamps still use the platform counter until epoch provisioning.
BusyBox continues to link its temporary MIT bridge; a separate Rust POSIX
service will expose this implementation through IPC to compatible clients.

References: [directory header](https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/dirent.h.html)
and [directory return and errno rules](https://pubs.opengroup.org/onlinepubs/007904875/functions/readdir_r.html).
