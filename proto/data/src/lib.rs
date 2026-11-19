// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The protocol of the data file service (services/datafs), proto_wire, version 3. Every number goes
//! low byte first, every call is one request and one reply whose first four bytes are the status.
//!
//! Version 3 is the version the POSIX layer of a program speaks: permissions, identity, the times
//! and numbers of files, `chmod`, `chown`, `utimensat`, `access`, a directory listing in batches,
//! and the limits a shell and `tar` need. It is complete for the series that freezes it. Locks and
//! transfers through shared memory stay out of it.
//!
//! # Paths and descriptions
//!
//! The service holds the files of the volume mounted at `/data`: paths are absolute from the root of
//! the volume (`/ssh/host_key` for `/data/ssh/host_key`), canonical, with no `.` and `..`, at most
//! `MAX_PATH` bytes (so that `/data` and a path reach `proto_fs::MAX_PATH`, 511), and each name at
//! most `NAME_MAX`. The layer normalises a path before it sends it. The service drops a `.`
//! component and an empty one, and answers INVALID for a `..` component: it walks the volume once,
//! from the root, and the entries of that walk must be the components of the path one for one
//! (littlefs resolves `..` lexically, without looking up the name before it, so a `..` would hide a
//! missing directory). A file is at most `FILE_MAX` bytes: an offset or size past it is TOO_BIG. An
//! open file or directory is a description: it has its own position and flags, and a count of the
//! sessions (and passes) that hold it. The number of a description (a handle, one u32) is the same
//! in every session that holds it, and a session that does not hold it gets BAD_HANDLE. A handle is
//! the place of the description (bits 0 to 7), its generation (8 to 15) and the epoch of the
//! service instance (16 to 31): a handle of an earlier instance, which a client keeps over a
//! restart, answers STALE. A call that reads or writes carries its bytes in the message, at most
//! `MAX_READ` or `MAX_WRITE`.
//!
//! # Requests
//!
//! Numbers 1 to 24 are the numbers of version 2 and never change. A request carries its fields in
//! the order of the table, the path (when there is one) last and running to the end of the message.
//! A message with bytes left over or short of a field is BAD_SIZE. Times are i64 nanoseconds since
//! the Unix epoch. A mode is the twelve bits 07777; a request with any other bit set is INVALID.
//!
//! | Request | Bytes after the header | Reply after the status |
//! |---|---|---|
//! | OPEN (1) | `flags` u32, `mode` u32, the path | `handle` u32, `kind` u32 |
//! | CLOSE (2) | `handle` u32 | none |
//! | READ (3) | `handle` u32, `count` u32 | `count` u32, the bytes |
//! | WRITE (4) | `handle` u32, the bytes | `count` u32 |
//! | SEEK (5) | `handle` u32, `offset` i64, `whence` u32 | `position` u64 |
//! | FSYNC (6) | `handle` u32 | none |
//! | TRUNCATE (7) | `handle` u32, `size` u64 | none |
//! | STAT (8) | the path | the stat record (64 bytes) |
//! | FSTAT (9) | `handle` u32 | the stat record (64 bytes) |
//! | MKDIR (10) | `mode` u32, the path | none |
//! | UNLINK (11), RMDIR (12) | the path | none |
//! | RENAME (13) | `from_len` u32, the path `from`, the path `to` | none |
//! | READDIR (14) | `handle` u32 | `more` u32, then entries to the end of the message |
//! | REWIND (15) | `handle` u32 | none |
//! | STATFS (16) | none | `blocks` u64, `free` u64, `avail` u64, `block` u32 |
//! | PREAD (17) | `handle` u32, `count` u32, `offset` u64 | `count` u32, the bytes |
//! | PWRITE (18) | `handle` u32, `offset` u64, the bytes | `count` u32 |
//! | CLONE (19) | `count` u32 (1 to `CLONE_MAX`), then that many handles | `birth` u32, and one handle: a new session of the service (SEND, TRANSFER) that holds the descriptions, for a child process |
//! | CLONE_MORE (20) | `birth` u32, `count` u32 (1 to `CLONE_MAX`), then the handles | none |
//! | EXPORT (21) | `handle` u32 | one handle: a pass for the description (TRANSFER alone) |
//! | ADOPT (22) | none, and one handle: a pass | `handle` u32, `kind` u32 |
//! | GET_FLAGS (23) | `handle` u32 | `flags` u32 (the access bits, APPEND, SYNC, DIRECTORY) |
//! | SET_FLAGS (24) | `handle` u32, `flags` u32 (APPEND and SYNC only) | none |
//! | BIND (25) | none, and one handle: a copy of the caller's identity session of the process service | none |
//! | CHMOD (26) | `mode` u32, the path | none |
//! | CHOWN (27) | `uid` u32, `gid` u32, the path | none |
//! | FCHMOD (28) | `handle` u32, `mode` u32 | none |
//! | FCHOWN (29) | `handle` u32, `uid` u32, `gid` u32 | none |
//! | UTIMENS (30) | `atime` i64, `mtime` i64, the path | none |
//! | FUTIMENS (31) | `handle` u32, `atime` i64, `mtime` i64 | none |
//! | ACCESS (32) | `bits` u32 (`ACCESS_READ`, `ACCESS_WRITE`, `ACCESS_EXEC`, or 0), `flags` u32 (`ACCESS_REAL` or 0), the path | none |
//! | WHERE (33) | `handle` u32 | the canonical path of the description, to the end of the message |
//! | SESSION (34) | none, and one handle: a copy of the caller's identity session; through the root channel only | one handle: a new session of the service (SEND, TRANSFER), already bound |
//! | VERIFY_SESSION (35) | none, and one handle (SEND, TRANSFER), through the root channel only | one handle: the offered session itself, which is a live session of the service |
//!
//! `uid` and `gid` of CHOWN and FCHOWN equal to `UID_KEEP` (u32::MAX) mean "leave as is". `atime`
//! and `mtime` of UTIMENS and FUTIMENS take `UTIME_NOW` (the present moment, read by the service)
//! and `UTIME_OMIT` (leave as is) beside a time of the caller's choice. The volume has no links, so
//! `lchown` and `fchownat` with `AT_SYMLINK_NOFOLLOW` map to CHOWN.
//!
//! **Times.** A time is an i64 count of nanoseconds, which covers 1677-09-21 00:12:43 to
//! 2262-04-11 23:47:16 UTC. The layer clamps a time outside that range to the nearest end before it
//! sends the request (and reports the end it clamped to by the value `stat` gives back).
//!
//! **Opening.** OPEN with READ or WRITE opens a file or, with DIRECTORY, a directory. OPEN with
//! neither READ nor WRITE is valid only as exactly `DIRECTORY` (for `chdir`, `fchdir` and
//! `O_SEARCH`): it checks search permission on the directory itself and gives a description with
//! no access bits, on which READ, PREAD, WRITE, PWRITE, TRUNCATE and READDIR answer BAD_HANDLE. Any
//! other OPEN without READ or WRITE is INVALID.
//!
//! READ and WRITE use the position of the description and move it; PREAD and PWRITE take the
//! position in the call and leave the description's alone. A description opened with APPEND (or
//! given it by SET_FLAGS) writes every WRITE at the end of the file, and the end is taken when the
//! write runs: two writers never overwrite each other. PWRITE writes at its offset whatever the
//! flag says (POSIX.1-2024; Linux appends). A description with SYNC makes every write durable before
//! its reply, as FSYNC does. Descriptions of one path share one file, so a write through one is
//! seen by a read through another at once. UNLINK of a file that is open and RENAME over one succeed:
//! the open descriptions keep the old file, which goes when the last of them closes (the service
//! keeps it under a hidden directory meanwhile and removes what a stop left at the next mount;
//! FSTAT then answers `nlink` 0, and WHERE answers NO_ENTRY). A RENAME over an open file takes two
//! commits of the volume (the old target moves to the hidden directory, then the source moves): the
//! target carries a mark with its home name between them, and the next mount puts a marked file
//! whose home name is missing back, so after a cut of the power the old name or the new is there
//! once the service has mounted again. The service never answers a request before that mount work
//! is done. A directory that is open (or is the current directory of a client, which holds a
//! description of it) is BUSY for RENAME and RMDIR, and so is a directory that contains one: RENAME
//! of a directory that has an open directory description anywhere below it is BUSY. So is a
//! directory with an open file anywhere below it (the service keeps the path of an open file).
//!
//! # The stat record
//!
//! STAT and FSTAT give one record of `STAT_LEN` (64) bytes:
//!
//! | Bytes | Field |
//! |---|---|
//! | 0..4 | `kind` u32 (`KIND_FILE`, `KIND_DIRECTORY`) |
//! | 4..8 | `mode` u32 (the bits 07777) |
//! | 8..12 | `uid` u32 |
//! | 12..16 | `gid` u32 |
//! | 16..24 | `size` u64 (0 for a directory) |
//! | 24..32 | `ino` u64, the file's number, unique on the volume and kept by RENAME |
//! | 32..40 | `atime` i64 |
//! | 40..48 | `mtime` i64 |
//! | 48..56 | `ctime` i64 |
//! | 56..60 | `nlink` u32: 1, and 0 for a file that was unlinked while open |
//! | 60..64 | zero |
//!
//! A reader rejects a record whose last four bytes are not zero.
//!
//! # Directory listing
//!
//! READDIR answers `more` u32, then entries to the end of the message. An entry is `ino` u64,
//! `kind` u32, `name_len` u32 (1 to `NAME_MAX`) and the name: `DIR_ENTRY_HEAD` (16) bytes and the
//! name. The service puts in the reply as many entries as it chooses up to what the message holds,
//! in the order of the directory, `.` and `..` first, and may stop before the message is full.
//! `more` is 1 when entries are left and 0 when the reply reaches the end of the directory; a reply
//! with `more` 1 carries at least one entry, and a reply with no entries has `more` 0 (it is the
//! end). The `ino` of an entry equals the `ino` that STAT gives for that name. The position of the
//! description moves past the entries given; REWIND puts it back at the start. The hidden
//! directory of the service is never listed. READDIR on a description that has no access bits (see
//! Opening) is BAD_HANDLE.
//!
//! # Identity and permissions
//!
//! The rules are those of `posix-perm` (POSIX.1-2024 XBD 4.7 and the pages of the functions), the
//! same code as the RAM file service uses. The service keeps these:
//!
//! 1. **Who may speak.** A session knows who its client is in two ways and no other. A session
//!    whose label has `SERVICE` set (and `OWN` clear) belongs to a native client of the list the
//!    init service keeps; its identity is user 0, group 0, no supplementary groups and no file size
//!    limit, and a POSIX program never gets the mark. Any other session is bound by SESSION or
//!    BIND. SESSION (through the root channel) makes a session that is bound from the start; BIND
//!    binds a session made by CLONE, and binds again a session whose binding lapsed. Either
//!    carries a copy of the caller's identity session of the process service; the service asks
//!    the process service through its notary session (Vouch) about it, keeps the PID, the six
//!    identifiers, the supplementary groups, the file size limit and the root of the expenditure
//!    with the generation of the record, and reads that generation again before each job of the
//!    session, asking Vouch once more with the stored copy when it moved: a request sent after
//!    `setuid` returned is checked by the new identity. The vouching runs in the service's worker
//!    thread, so the reply to SESSION and BIND is deferred like the reply to any other job. A copy
//!    the process service does not vouch for is ACCESS (SESSION makes no session then). A BIND on a
//!    session that is still bound is INVALID.
//! 2. **A binding can lapse.** When the process service no longer vouches for the stored copy (the
//!    process executed a new image, or exited, so the record's identity session is another), the
//!    session is unbound again: it answers NOT_BOUND until the layer sends BIND with a fresh copy.
//!    A session that is unbound (a CLONE session before its first BIND, or one whose binding
//!    lapsed) answers NOT_BOUND to every request except BIND, CLOSE, CLONE, CLONE_MORE and the
//!    requests that only read or hand on a description it holds: READ, PREAD, SEEK, FSTAT,
//!    READDIR, REWIND, WHERE, GET_FLAGS, EXPORT and ADOPT. WRITE, PWRITE, TRUNCATE, FSYNC,
//!    SET_FLAGS, FCHMOD, FCHOWN and FUTIMENS need a binding, as does every request that names a
//!    path. A session made by CLONE inherits neither the mark nor the identity: the child binds its
//!    own session.
//! 3. **Where a check happens.** OPEN checks search on every directory of the path and read or
//!    write by the access bits of the flags (TRUNCATE needs write; creating a file needs write and
//!    search on the parent; a directory opened with no access bits needs search on itself); the
//!    description keeps the result in its flags. A request on a description does not look at the
//!    file's mode again: a description keeps its rights over `chmod`, `chown` and a `setuid` of the
//!    process, and over `fork`, `exec` and a pass. FCHMOD, FCHOWN and FUTIMENS check the owner at
//!    the time of the call, by the identity of the session. STAT, ACCESS, MKDIR, UNLINK, RMDIR,
//!    RENAME, CHMOD, CHOWN and UTIMENS check everything at the time of the call, with search on
//!    every directory of the path. Failing search or a mode bit is ACCESS; failing ownership is
//!    PERMISSION.
//! 4. **Superuser.** The effective user 0 passes read, write and search. Execute needs a bit, and
//!    no file of the volume executes anyway (the layer answers `execve` itself). Only user 0
//!    changes an owner (`_POSIX_CHOWN_RESTRICTED`).
//! 5. **Creation.** The mode of OPEN with CREATE and of MKDIR arrives with the process's umask
//!    applied. The owner is the caller; the group is the caller's group, or the group of the parent
//!    when it has the set-group-ID bit; a new directory under such a parent keeps the bit; a new
//!    file in a group its creator is not in loses the bit. The attribute is written in the same job
//!    as the name. A directory holds at most `DIR_ENTRIES_MAX` entries: a create (OPEN with CREATE,
//!    MKDIR, or a RENAME that adds a name to a directory) in a full directory is NO_SPACE (ENOSPC,
//!    the directory cannot be expanded). See the section on the size of a directory.
//! 6. **Sticky directories, UNLINK, RMDIR, RENAME.** These need write and search on the parent
//!    (ACCESS when refused). In a directory with the sticky bit they also need the owner of the
//!    entry, the owner of the directory or user 0: PERMISSION when refused, for the source and for
//!    an existing target alike (POSIX.1-2024 XBD 4.5). RENAME of a directory to another parent
//!    needs write permission on that directory too. UNLINK of a directory is IS_DIRECTORY, RMDIR of
//!    a file is NOT_DIRECTORY, RMDIR of a directory with entries is NOT_EMPTY, and RENAME of a
//!    directory into its own subtree is INVALID.
//! 7. **`chmod` and `chown`.** CHMOD and FCHMOD need the owner or user 0, and a caller outside the
//!    file's group loses the set-group-ID bit it asked for. CHOWN and FCHOWN by a user other than 0
//!    change only the group of a file of the caller, to a group of the caller; a change of owner or
//!    group clears the set-user-ID and set-group-ID bits of a file; a directory keeps them. A write
//!    clears them too. The bits are stored and never act: nothing on the volume is executed.
//! 8. **`utimensat`.** Two `UTIME_NOW` values need the owner, user 0 or write permission (ACCESS
//!    when refused); any value of the caller's choice needs the owner or user 0 (PERMISSION); two
//!    `UTIME_OMIT` need nothing.
//! 9. **ACCESS.** It checks the bits with the real identifiers when `ACCESS_REAL` is set and with
//!    the effective ones otherwise, and the search along the path uses the same identifiers as the
//!    bits do; bits 0 asks only that the path resolves with search allowed.
//! 10. **Times.** A write sets `mtime` and `ctime` of the file; the service writes the attribute
//!     at FSYNC, at the last close of the file with writes, and at CHMOD, CHOWN and UTIMENS. A
//!     change of a directory's entries (create, remove, rename in it) sets its `mtime` and
//!     `ctime`. A read never sets `atime`; creation and UTIMENS do. The clock is the service's.
//! 11. **Numbers.** `ino` comes from the attribute. The service hands numbers out of blocks of
//!     `INO_BLOCK` it reserves with one commit of the counter at the root, so a restart skips the
//!     numbers it had not given out; an entry with no attribute gets a number derived from its
//!     path with the top bit set.
//! 12. **Defaults.** A new volume has the root `0755`, user 0, group 0, and the hidden directory
//!     `0700`. An entry with no attribute (a volume of version 2) reads as `0700` for a directory
//!     and `0600` for a file, owned by user 0, group 0, and the root as `0755`; the first mount of
//!     version 3 writes the attribute of every such entry, moves out every inline file (see the
//!     downgrade section) and then the format mark 4 at the root.
//! 13. **Limits of a write.** A WRITE or PWRITE stops short at a limit: it writes up to the file
//!     size limit of the bound identity (and `FILE_MAX`) or up to the last free block the caller
//!     may use, and answers that count. FILE_SIZE_LIMIT, TOO_BIG or NO_SPACE comes only when no
//!     byte was written; the layer sends SIGXFSZ with FILE_SIZE_LIMIT and gives EFBIG. A TRUNCATE
//!     past the limit has no part to write and answers the status at once.
//! 14. **The reserve.** With fewer than `RESERVE_BLOCKS` free blocks, a caller other than user 0
//!     gets NO_SPACE for a write (after the bytes that fit), a create (OPEN with CREATE, MKDIR), a
//!     RENAME and a change of attributes (CHMOD, CHOWN, UTIMENS and the variants by description),
//!     because each may split or compact a pair of metadata blocks; user 0 does all of these into
//!     the reserve; UNLINK and RMDIR pass always. STATFS `avail` leaves the reserve out and `free`
//!     does not.
//! 15. **The channels.** The root channel (label `ROOT`) takes SESSION and VERIFY_SESSION and
//!     nothing else; any other session answers them, and the root answers every other method, with
//!     IS_ROOT. VERIFY_SESSION answers the offered session itself when it is a live session of the
//!     service that a POSIX client holds, and BAD_HANDLE with no handle otherwise (a pass and the
//!     session of a native client are not offered sessions). Every session SESSION makes is bound at
//!     birth, so no process holds an unbound session from the root. The reason is that the label
//!     of the root channel is one for all its holders: a limit of unbound sessions per root channel
//!     would be a limit for the whole system.
//!
//! # Durability
//!
//! FSYNC makes the file's data, size, place in the tree and attribute durable before it answers.
//! MKDIR, UNLINK, RMDIR, RENAME, CHMOD, CHOWN and UTIMENS are durable when they answer; each is one
//! commit of the volume (one attribute write), so a cut of the power leaves the old attribute or
//! the new. RENAME is one step: after a cut the old name or the new is there. A file the service
//! made with OPEN and CREATE exists, empty, from the open; its bytes are the file's after the FSYNC
//! or the CLOSE that follows, and a cut before that leaves the contents of the last sync.
//! Creating names the entry in one commit and writes its attribute in a second, so a cut between
//! them leaves an empty entry that reads as the default above (closed to everyone except user 0).
//!
//! # Downgrade safety
//!
//! A volume whose format mark is above `VOLUME_FORMAT` was written by a later service: this one
//! refuses to mount it (every request answers NOT_READY). An attribute whose `format` or length it
//! does not know is never rewritten: the entry reads as the default of rule 12, and a request that
//! would write its attribute (CHMOD, CHOWN, UTIMENS, the time of a write) answers CORRUPT.
//!
//! The format mark is 4 (`VOLUME_FORMAT`) when every entry has its record and no file is inline
//! (its bytes inside the pair of its directory). A volume of the part A build has the mark 3 and
//! small files written since are inline; a volume of the 0.5 release has neither. littlefs 2.11.3
//! loses a write at the start or in the middle of an inline file (the close answers CORRUPT, the old
//! bytes stay) once inline data is off, which the service keeps it, so the mount work of a volume
//! with a mark under 4 moves out every non-empty inline file (open for writing, seek to the end,
//! write no byte: one commit, the old file or the moved one after a cut) in the walk that gives the
//! records, then writes the mark 4. The walk costs about 27 reads for each file and about 62 more for
//! each file it moves, and holds READY for as long as it takes: a volume of many small files made by
//! the part A build or the 0.5 release is converted at its first mount before the first request (at
//! most `CONVERT_MAX` writes in one run; the next mount goes on). A service that writes the mark 3
//! refuses a volume with the mark 4 (NOT_READY), which keeps a build that makes inline files from
//! writing on a volume that has none. Every file takes a block of its own, and moving a file out takes
//! one: on a nearly full volume that is NO_SPACE for the caller who is not user 0.
//!
//! # The size of a directory
//!
//! A directory has at most `DIR_ENTRIES_MAX` entries (1024), a minimum the service guarantees; the
//! service step may fix a different value after measurement, never a smaller one. The count does
//! not live on the volume: the 48-byte attribute record has no free byte, and a second attribute
//! on the directory would cost one more commit of it for every name that is made, removed or
//! renamed. The service counts the entries of a directory by one scan (a few hundred device
//! reads for 1,000 entries) the first time a name is added to it, keeps the count in memory for a
//! few directories, and follows it with each name it adds or removes; a rename, a removal of the
//! directory or a change of its attributes drops what it kept. A restart starts with no counts.
//!
//! A volume holds at most `PAIRS_MAX` (2,048) metadata pairs and `DIRS_MAX` (1,024) directories (the
//! root and the hidden directory of the service among them). A
//! directory is one pair and a large directory splits into more; a file has a block of its own
//! (the data never goes inside a pair), so many files make pairs only through their names (about 16
//! names of 8 bytes, 11 of 32 and 3 of 255 bytes to a pair, with the record of each). Removing a
//! directory looks the pair before it up in the list of all pairs, about 3.2 reads for each pair, so
//! the pairs bound the longest job and the directories bound the series of a `rm -rf`. MKDIR is
//! NO_SPACE at either cap; the creation of a file and a RENAME into another directory at the cap of
//! pairs; a RENAME within a directory to a longer name too, at the cap of pairs (a longer name splits
//! pairs); a removal, a write, a truncation and a change of mode or times never are. The service
//! counts pairs and directories exactly at the mount, at each refresh walk and before it first
//! refuses (one fetch of each pair, about two reads for each: 6,000 reads at the cap), and keeps an
//! estimate of the pairs between counts: the count plus 2 for each MKDIR, 1 for each creation, 1 for
//! each RENAME into another directory and 1 for each RENAME that lengthens the name. The estimate can
//! fall short by 0 or 1 (a first write into an empty file grows the pair by 8 bytes; a same-size
//! CHMOD can compact and split a pair that was over half a block), so the count can pass 2,048 by that
//! much until the next refresh walk. Near the cap a creation whose estimate has reached it counts the
//! pairs inside its own job (4,000 to 6,000 reads: 1.5 to 2 s on gp3). A refusal is
//! made only on an exact count; after a confirmed refusal the service does not count again until
//! the first removal. The directories are counted exactly and followed: 1 for each MKDIR and RMDIR.
//! The line `datafs: pairs N of 2048, directories M of 1024` tells each count. A volume that holds
//! more than the caps (a volume of an older release) mounts and works, and only the requests above
//! are refused.
//!
//! # The attribute of an entry
//!
//! The constants `ATTR_*`, `VOLUME_FORMAT`, `INO_BLOCK`, `RESERVE_BLOCKS` and the `Attr` record are
//! the format of the volume and live in `lib/datafs/src/attr.rs`; the table below is their text.
//!
//! The service keeps each entry's record (`Attr`, `ATTR_LEN` 48 bytes) as the user attribute
//! `ATTR_TYPE` (0x70) of the entry in the volume; the volume's `format` mark is the attribute
//! `ATTR_FORMAT_TYPE` (0x66) of the root (one u32, `VOLUME_FORMAT`) and the number counter the
//! attribute `ATTR_COUNTER_TYPE` (0x69) of the root (one u64). The type of the entry comes from
//! the volume itself.
//!
//! | Bytes | Field |
//! |---|---|
//! | 0..4 | `uid` u32 |
//! | 4..8 | `gid` u32 |
//! | 8..12 | `mode` u32 (the bits 07777) |
//! | 12..16 | `format` u32 (`ATTR_FORMAT`) |
//! | 16..24 | `ino` u64 |
//! | 24..32 | `atime` i64 |
//! | 32..40 | `mtime` i64 |
//! | 40..48 | `ctime` i64 |
//!
//! # Statuses and errno
//!
//! [`ERRNO`] gives the POSIX error each status of the service becomes in the layer; see the table
//! there. A session whose channel dies with the service sees `PEER_CLOSED` and gives EIO; a full
//! queue (`WouldBlock` from the service's loop) is retried by the layer.
//!
//! # Limits
//!
//! `HELD_MAX` descriptions per session, `ROOT_DESCRIPTIONS` distinct descriptions, `ROOT_CLONES`
//! live clones and `PASSES_MAX` unspent passes per process tree, and `DIR_ENTRIES_MAX` entries per
//! directory are minimums the service guarantees: it may raise them inside the frozen series, and a
//! client must not depend on the value. Past them TOO_MANY_OPEN (NO_SPACE for a directory). A table
//! of the service that is full as a whole answers TABLE_FULL. The fixed bounds, which are layout and
//! never change, are `CLONE_MAX`, `MAX_PATH`, `NAME_MAX`, `STAT_LEN`, `MAX_READ` and `MAX_WRITE`.
//!
//! CLONE makes a session of the service for a child and gives it the descriptions listed (one
//! reference each, and the position shared with the parent). `birth` names that session for
//! CLONE_MORE, which the parent sends while the child has sent nothing, to add more; a description
//! the session holds already is passed over. EXPORT makes a pass that holds one reference of the
//! description; ADOPT, sent by whoever holds the pass, spends it and gives the description to the
//! sender's session (the reference of the pass becomes the session's). A pass whose last copy goes
//! unspent gives its reference up. An ADOPT refused for either limit leaves the pass unspent, and
//! the service gives the pass handle back in the reply.

#![cfg_attr(not(test), no_std)]

use abi::MESSAGE_MAX;
use proto_wire::{HEADER_LEN, Header, Reader, Status, Writer};

pub const VERSION: u16 = 3;

/// The longest path, in bytes: `/data` and a path reach `proto_fs::MAX_PATH` (511), and two of
/// them with the fields of RENAME fill one message exactly. A fixed bound.
pub const MAX_PATH: usize = 506;
/// The largest size of a file, in bytes (2^31 - 1); an offset or size past it is TOO_BIG.
pub const FILE_MAX: u64 = (1 << 31) - 1;
/// The longest name of an entry. A fixed bound.
pub const NAME_MAX: usize = 255;
/// The bytes one READ or WRITE carries at most. Fixed bounds.
pub const MAX_READ: usize = MESSAGE_MAX - 8;
pub const MAX_WRITE: usize = MESSAGE_MAX - HEADER_LEN - 4;
/// The bytes of a block of the volume.
pub const BLOCK: u32 = 4096;
/// The descriptions one session holds at most (a read-write open file or directory each): a
/// minimum the service guarantees.
pub const HELD_MAX: usize = 32;
/// The descriptions CLONE and CLONE_MORE carry at most. A fixed bound, with a value of its own so
/// that `HELD_MAX` can grow.
pub const CLONE_MAX: usize = 32;
/// The passes one process tree has made and not spent at once: a minimum.
pub const PASSES_MAX: usize = 8;
/// The live clones of one process tree (the sessions made by CLONE under one client): a minimum.
pub const ROOT_CLONES: usize = 32;
/// The distinct descriptions the sessions of one process tree hold together: a minimum.
pub const ROOT_DESCRIPTIONS: usize = 48;
/// The entries of one directory: a minimum the service guarantees and the service step may fix
/// after measurement (never smaller). A create past it is NO_SPACE.
pub const DIR_ENTRIES_MAX: usize = 1024;
/// The metadata pairs of one volume at which a creation stops: a minimum the service guarantees. A
/// removal of a directory looks the pair before its own up in the list of all the pairs (about 3.2
/// reads for each pair), so the cost of the longest single job, a RMDIR, is about 3.2 reads for each
/// pair, 6,700 at the cap and its overrun of 2,100 (2.2 s at 3,000 reads a second). A MKDIR, the
/// creation of a file, a RENAME into another directory and, at the cap, a RENAME to a longer name are
/// NO_SPACE past it; a removal, a write, a truncation, a change of mode or times and a RENAME that
/// does not lengthen the name never are.
pub const PAIRS_MAX: u64 = 2048;
/// The directories of one volume (the root and the hidden directory of the service among them) at
/// which MKDIR stops: a minimum. The series of removals of a tree costs about one read for each
/// pair of the volume for each directory, so the directories bound the length of `rm -rf`: 1,024
/// directories behind 2,000 pairs are about two million reads. Only MKDIR is refused.
pub const DIRS_MAX: u64 = 1024;
/// The flags of OPEN.
pub const READ: u32 = 1;
pub const WRITE: u32 = 2;
/// Both access bits: read and write.
pub const READ_WRITE_BOTH: u32 = READ | WRITE;
pub const CREATE: u32 = 4;
pub const EXCLUSIVE: u32 = 8;
pub const TRUNCATE: u32 = 16;
pub const APPEND: u32 = 32;
/// The path must name a directory (a handle for READDIR).
pub const DIRECTORY: u32 = 64;
/// Every write of the description is durable before its reply (`O_SYNC` and `O_DSYNC`).
pub const SYNC: u32 = 128;
pub const FLAGS_ALL: u32 = READ | WRITE | CREATE | EXCLUSIVE | TRUNCATE | APPEND | DIRECTORY | SYNC;
/// The flags SET_FLAGS may change.
pub const SET_FLAGS_ALL: u32 = APPEND | SYNC;

/// The kinds of a file and of a directory, as a reply names them.
pub const KIND_FILE: u32 = 1;
pub const KIND_DIRECTORY: u32 = 2;

pub const SEEK_SET: u32 = 0;
pub const SEEK_CUR: u32 = 1;
pub const SEEK_END: u32 = 2;

/// CHOWN and FCHOWN: this value of `uid` or `gid` leaves it as it is.
pub const UID_KEEP: u32 = u32::MAX;
/// UTIMENS and FUTIMENS: the time is the present moment.
pub const UTIME_NOW: i64 = i64::MIN;
/// UTIMENS and FUTIMENS: the time stays as it is.
pub const UTIME_OMIT: i64 = i64::MIN + 1;
/// The bits of ACCESS (the values of `R_OK`, `W_OK` and `X_OK`; 0 is `F_OK`).
pub const ACCESS_READ: u32 = 4;
pub const ACCESS_WRITE: u32 = 2;
pub const ACCESS_EXEC: u32 = 1;
/// The flag of ACCESS that checks the real identifiers (`access`); clear it for the effective
/// ones (`AT_EACCESS`).
pub const ACCESS_REAL: u32 = 1;
/// The bits of a mode.
pub const MODE_MASK: u32 = 0o7777;

/// The label of a session a native client of init's list holds (rule 1): bit 61, as the profile of
/// the RAM file service has. Init gives it and nobody else.
pub const SERVICE: u64 = 1 << 61;
/// The mark of the labels the service makes for its own sessions.
pub const OWN: u64 = 1 << 63;
/// The mark of the labels of passes (EXPORT), with `OWN`: a pass is not a session.
pub const PASS: u64 = OWN | 1 << 58;
/// The label of the service's root channel (rule 15): bit 60 with `OWN`.
pub const ROOT: u64 = OWN | 1 << 60;

/// Whether `label` is the profile of a native client.
pub const fn is_service(label: u64) -> bool {
    label & OWN == 0 && label & SERVICE != 0
}

/// Whether `label` is a pass made by EXPORT.
pub const fn is_pass(label: u64) -> bool {
    label & PASS == PASS && label != ROOT
}

/// Whether `label` is the root channel.
pub const fn is_root(label: u64) -> bool {
    label == ROOT
}

/// The bytes of the stat record.
pub const STAT_LEN: usize = 64;

/// The codes of the service (`Status::Unknown`), clear of the codes of the wire (below 512) and of the
/// other services (blk 1101, the file service's).
pub const NO_ENTRY: u32 = 1201;
pub const EXISTS: u32 = 1202;
pub const NOT_DIRECTORY: u32 = 1203;
pub const IS_DIRECTORY: u32 = 1204;
pub const NOT_EMPTY: u32 = 1205;
pub const BAD_HANDLE: u32 = 1206;
pub const TOO_BIG: u32 = 1207;
pub const INVALID: u32 = 1208;
pub const NO_SPACE: u32 = 1209;
pub const IO: u32 = 1210;
pub const TOO_MANY_OPEN: u32 = 1211;
pub const NAME_TOO_LONG: u32 = 1212;
/// A file or a directory in use cannot be removed or renamed.
pub const BUSY: u32 = 1213;
/// The volume is not mounted (no data volume, or it failed).
pub const NOT_READY: u32 = 1214;
pub const CORRUPT: u32 = 1215;
/// The handle is of an earlier instance of the service (a restart since it was given).
pub const STALE: u32 = 1216;
/// The caller's identity lacks a permission bit, or the process service does not vouch for the
/// identity it sent (EACCES).
pub const ACCESS: u32 = 1217;
/// A table of the service as a whole is full (descriptions, open files, directories, sessions,
/// passes): ENFILE. TOO_MANY_OPEN is a limit of the session or of its process tree: EMFILE.
pub const TABLE_FULL: u32 = 1218;
/// The caller lacks the standing the operation needs, being neither the owner nor user 0 (EPERM).
pub const PERMISSION: u32 = 1219;
/// The session has neither the native-client mark nor a binding (rules 1 and 2).
pub const NOT_BOUND: u32 = 1220;
/// A write or an extension that has no room under the file size limit of the bound identity,
/// answered when no byte was written (rule 13).
pub const FILE_SIZE_LIMIT: u32 = 1221;
/// A request through the wrong channel: a session request on the root, or a root request on a
/// session (rule 15).
pub const IS_ROOT: u32 = 1222;
/// The service refuses every change (EROFS).
pub const READ_ONLY: u32 = 1223;

pub const CODES: [u32; 23] = [
    NO_ENTRY,
    EXISTS,
    NOT_DIRECTORY,
    IS_DIRECTORY,
    NOT_EMPTY,
    BAD_HANDLE,
    TOO_BIG,
    INVALID,
    NO_SPACE,
    IO,
    TOO_MANY_OPEN,
    NAME_TOO_LONG,
    BUSY,
    NOT_READY,
    CORRUPT,
    STALE,
    ACCESS,
    TABLE_FULL,
    PERMISSION,
    NOT_BOUND,
    FILE_SIZE_LIMIT,
    IS_ROOT,
    READ_ONLY,
];

/// The POSIX errors the statuses become (the names of `<errno.h>`; the layer owns the numbers).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Errno {
    Eacces,
    Eperm,
    Enoent,
    Eexist,
    Enotdir,
    Eisdir,
    Enotempty,
    Ebadf,
    Efbig,
    Einval,
    Enospc,
    Eio,
    Emfile,
    Enfile,
    Enametoolong,
    Ebusy,
    Erofs,
}

/// The errno of each status of the service. Where a status becomes EIO the layer does more first:
/// NOT_BOUND makes it BIND and send the call again once; STALE marks the descriptor of the
/// restarted service (EIO for the call, `close` succeeds); NOT_READY, CORRUPT and IS_ROOT are the
/// service's own failures. FILE_SIZE_LIMIT is EFBIG after the layer's SIGXFSZ; TOO_BIG is EFBIG
/// for an offset or size past `FILE_MAX`. NO_SPACE is ENOSPC, also for a full directory (the
/// directory cannot be expanded).
pub const ERRNO: [(u32, Errno); 23] = [
    (NO_ENTRY, Errno::Enoent),
    (EXISTS, Errno::Eexist),
    (NOT_DIRECTORY, Errno::Enotdir),
    (IS_DIRECTORY, Errno::Eisdir),
    (NOT_EMPTY, Errno::Enotempty),
    (BAD_HANDLE, Errno::Ebadf),
    (TOO_BIG, Errno::Efbig),
    (INVALID, Errno::Einval),
    (NO_SPACE, Errno::Enospc),
    (IO, Errno::Eio),
    (TOO_MANY_OPEN, Errno::Emfile),
    (NAME_TOO_LONG, Errno::Enametoolong),
    (BUSY, Errno::Ebusy),
    (NOT_READY, Errno::Eio),
    (CORRUPT, Errno::Eio),
    (STALE, Errno::Eio),
    (ACCESS, Errno::Eacces),
    (TABLE_FULL, Errno::Enfile),
    (PERMISSION, Errno::Eperm),
    (NOT_BOUND, Errno::Eio),
    (FILE_SIZE_LIMIT, Errno::Efbig),
    (IS_ROOT, Errno::Eio),
    (READ_ONLY, Errno::Erofs),
];

/// The errno of a status code of the service, or None for a code that is not the service's.
pub fn errno(code: u32) -> Option<Errno> {
    ERRNO.iter().find(|(c, _)| *c == code).map(|(_, e)| *e)
}

pub const fn code(code: u32) -> Status {
    Status::Unknown(code)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Open = 1,
    Close = 2,
    Read = 3,
    Write = 4,
    Seek = 5,
    Fsync = 6,
    Truncate = 7,
    Stat = 8,
    Fstat = 9,
    Mkdir = 10,
    Unlink = 11,
    Rmdir = 12,
    Rename = 13,
    Readdir = 14,
    Rewind = 15,
    Statfs = 16,
    Pread = 17,
    Pwrite = 18,
    Clone = 19,
    CloneMore = 20,
    Export = 21,
    Adopt = 22,
    GetFlags = 23,
    SetFlags = 24,
    Bind = 25,
    Chmod = 26,
    Chown = 27,
    Fchmod = 28,
    Fchown = 29,
    Utimens = 30,
    Futimens = 31,
    Access = 32,
    Where = 33,
    Session = 34,
    VerifySession = 35,
}

/// The number of methods.
pub const METHOD_COUNT: usize = 35;

impl Method {
    pub const ALL: [Method; METHOD_COUNT] = [
        Method::Open,
        Method::Close,
        Method::Read,
        Method::Write,
        Method::Seek,
        Method::Fsync,
        Method::Truncate,
        Method::Stat,
        Method::Fstat,
        Method::Mkdir,
        Method::Unlink,
        Method::Rmdir,
        Method::Rename,
        Method::Readdir,
        Method::Rewind,
        Method::Statfs,
        Method::Pread,
        Method::Pwrite,
        Method::Clone,
        Method::CloneMore,
        Method::Export,
        Method::Adopt,
        Method::GetFlags,
        Method::SetFlags,
        Method::Bind,
        Method::Chmod,
        Method::Chown,
        Method::Fchmod,
        Method::Fchown,
        Method::Utimens,
        Method::Futimens,
        Method::Access,
        Method::Where,
        Method::Session,
        Method::VerifySession,
    ];

    pub const fn number(self) -> u16 {
        self as u16
    }

    pub fn from_number(number: u16) -> Option<Method> {
        Method::ALL.into_iter().find(|m| m.number() == number)
    }

    pub const fn header(self) -> Header {
        Header::new(self.number(), VERSION)
    }

    /// The methods only the root channel takes (rule 15).
    pub const fn is_root_method(self) -> bool {
        matches!(self, Method::Session | Method::VerifySession)
    }
}

/// The method numbers of every request, for a service's table.
pub const METHODS: [u16; METHOD_COUNT] = {
    let mut numbers = [0; METHOD_COUNT];
    let mut i = 0;
    while i < METHOD_COUNT {
        numbers[i] = Method::ALL[i].number();
        i += 1;
    }
    numbers
};

fn start(method: Method, w: &mut Writer) -> Result<(), Status> {
    method.header().write(w)
}

/// A time of UTIMENS or FUTIMENS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeSpec {
    Now,
    Omit,
    At(i64),
}

impl TimeSpec {
    pub const fn word(self) -> i64 {
        match self {
            TimeSpec::Now => UTIME_NOW,
            TimeSpec::Omit => UTIME_OMIT,
            TimeSpec::At(t) => t,
        }
    }

    /// The time of a word: the two sentinels, and any other value is a time.
    pub fn from_word(word: i64) -> Result<TimeSpec, Status> {
        match word {
            UTIME_NOW => Ok(TimeSpec::Now),
            UTIME_OMIT => Ok(TimeSpec::Omit),
            t => Ok(TimeSpec::At(t)),
        }
    }
}

// The requests, written by a client.

/// OPEN of version 3.
pub fn open(path: &[u8], flags: u32, mode: u32, w: &mut Writer) -> Result<(), Status> {
    start(Method::Open, w)?;
    w.u32(flags)?;
    w.u32(mode)?;
    w.bytes(path)
}

pub fn handle_call(method: Method, handle: u32, w: &mut Writer) -> Result<(), Status> {
    start(method, w)?;
    w.u32(handle)
}

pub fn read(handle: u32, count: u32, w: &mut Writer) -> Result<(), Status> {
    start(Method::Read, w)?;
    w.u32(handle)?;
    w.u32(count)
}

pub fn write(handle: u32, bytes: &[u8], w: &mut Writer) -> Result<(), Status> {
    start(Method::Write, w)?;
    w.u32(handle)?;
    w.bytes(bytes)
}

pub fn seek(handle: u32, offset: i64, whence: u32, w: &mut Writer) -> Result<(), Status> {
    start(Method::Seek, w)?;
    w.u32(handle)?;
    w.u64(offset as u64)?;
    w.u32(whence)
}

pub fn truncate(handle: u32, size: u64, w: &mut Writer) -> Result<(), Status> {
    start(Method::Truncate, w)?;
    w.u32(handle)?;
    w.u64(size)
}

/// A request whose body is the path alone: STAT, UNLINK, RMDIR.
pub fn path_call(method: Method, path: &[u8], w: &mut Writer) -> Result<(), Status> {
    start(method, w)?;
    w.bytes(path)
}

pub fn mkdir(path: &[u8], mode: u32, w: &mut Writer) -> Result<(), Status> {
    start(Method::Mkdir, w)?;
    w.u32(mode)?;
    w.bytes(path)
}

pub fn rename(from: &[u8], to: &[u8], w: &mut Writer) -> Result<(), Status> {
    start(Method::Rename, w)?;
    w.u32(from.len() as u32)?;
    w.bytes(from)?;
    w.bytes(to)
}

pub fn statfs(w: &mut Writer) -> Result<(), Status> {
    start(Method::Statfs, w)
}

pub fn pread(handle: u32, count: u32, offset: u64, w: &mut Writer) -> Result<(), Status> {
    start(Method::Pread, w)?;
    w.u32(handle)?;
    w.u32(count)?;
    w.u64(offset)
}

pub fn pwrite(handle: u32, offset: u64, bytes: &[u8], w: &mut Writer) -> Result<(), Status> {
    start(Method::Pwrite, w)?;
    w.u32(handle)?;
    w.u64(offset)?;
    w.bytes(bytes)
}

/// CLONE of at most `CLONE_MAX` handles.
pub fn clone(handles: &[u32], w: &mut Writer) -> Result<(), Status> {
    start(Method::Clone, w)?;
    w.u32(handles.len() as u32)?;
    handles.iter().try_for_each(|&h| w.u32(h))
}

pub fn clone_more(birth: u32, handles: &[u32], w: &mut Writer) -> Result<(), Status> {
    start(Method::CloneMore, w)?;
    w.u32(birth)?;
    w.u32(handles.len() as u32)?;
    handles.iter().try_for_each(|&h| w.u32(h))
}

/// ADOPT: the header alone (the pass goes as a handle of the call).
pub fn adopt(w: &mut Writer) -> Result<(), Status> {
    start(Method::Adopt, w)
}

pub fn set_flags(handle: u32, flags: u32, w: &mut Writer) -> Result<(), Status> {
    start(Method::SetFlags, w)?;
    w.u32(handle)?;
    w.u32(flags)
}

/// BIND, SESSION and VERIFY_SESSION: the header alone (the one handle goes with the call).
pub fn header_only(method: Method, w: &mut Writer) -> Result<(), Status> {
    start(method, w)
}

pub fn chmod(path: &[u8], mode: u32, w: &mut Writer) -> Result<(), Status> {
    start(Method::Chmod, w)?;
    w.u32(mode)?;
    w.bytes(path)
}

pub fn chown(path: &[u8], uid: u32, gid: u32, w: &mut Writer) -> Result<(), Status> {
    start(Method::Chown, w)?;
    w.u32(uid)?;
    w.u32(gid)?;
    w.bytes(path)
}

pub fn fchmod(handle: u32, mode: u32, w: &mut Writer) -> Result<(), Status> {
    start(Method::Fchmod, w)?;
    w.u32(handle)?;
    w.u32(mode)
}

pub fn fchown(handle: u32, uid: u32, gid: u32, w: &mut Writer) -> Result<(), Status> {
    start(Method::Fchown, w)?;
    w.u32(handle)?;
    w.u32(uid)?;
    w.u32(gid)
}

pub fn utimens(
    path: &[u8],
    atime: TimeSpec,
    mtime: TimeSpec,
    w: &mut Writer,
) -> Result<(), Status> {
    start(Method::Utimens, w)?;
    w.u64(atime.word() as u64)?;
    w.u64(mtime.word() as u64)?;
    w.bytes(path)
}

pub fn futimens(
    handle: u32,
    atime: TimeSpec,
    mtime: TimeSpec,
    w: &mut Writer,
) -> Result<(), Status> {
    start(Method::Futimens, w)?;
    w.u32(handle)?;
    w.u64(atime.word() as u64)?;
    w.u64(mtime.word() as u64)
}

pub fn access(path: &[u8], bits: u32, flags: u32, w: &mut Writer) -> Result<(), Status> {
    start(Method::Access, w)?;
    w.u32(bits)?;
    w.u32(flags)?;
    w.bytes(path)
}

// The requests, read by the service from the body after the header.

/// OPEN: `(flags, mode, path)`. INVALID for flags outside `FLAGS_ALL`, a mode outside the mode
/// bits, or neither READ nor WRITE with any flags but exactly DIRECTORY (see Opening).
pub fn read_open<'a>(mut body: Reader<'a>) -> Result<(u32, u32, &'a [u8]), Status> {
    let flags = body.u32()?;
    let mode = body.u32()?;
    let path = body.bytes(body.left())?;
    if flags & !FLAGS_ALL != 0 || mode & !MODE_MASK != 0 {
        return Err(code(INVALID));
    }
    if flags & READ_WRITE_BOTH == 0 && flags != DIRECTORY {
        return Err(code(INVALID));
    }
    Ok((flags, mode, path))
}

/// MKDIR and CHMOD: `(mode, path)`.
pub fn read_mode_path<'a>(mut body: Reader<'a>) -> Result<(u32, &'a [u8]), Status> {
    let mode = body.u32()?;
    let path = body.bytes(body.left())?;
    if mode & !MODE_MASK != 0 {
        return Err(code(INVALID));
    }
    Ok((mode, path))
}

/// CHOWN: `(uid, gid, path)`.
pub fn read_chown<'a>(mut body: Reader<'a>) -> Result<(u32, u32, &'a [u8]), Status> {
    let uid = body.u32()?;
    let gid = body.u32()?;
    let path = body.bytes(body.left())?;
    Ok((uid, gid, path))
}

/// FCHMOD after its handle: the mode.
pub fn read_fchmod(mut body: Reader<'_>) -> Result<u32, Status> {
    let mode = body.u32()?;
    body.finish()?;
    if mode & !MODE_MASK != 0 {
        return Err(code(INVALID));
    }
    Ok(mode)
}

/// FCHOWN after its handle: `(uid, gid)`.
pub fn read_fchown(mut body: Reader<'_>) -> Result<(u32, u32), Status> {
    let uid = body.u32()?;
    let gid = body.u32()?;
    body.finish()?;
    Ok((uid, gid))
}

/// UTIMENS: `(atime, mtime, path)`.
pub fn read_utimens<'a>(mut body: Reader<'a>) -> Result<(TimeSpec, TimeSpec, &'a [u8]), Status> {
    let atime = TimeSpec::from_word(body.u64()? as i64)?;
    let mtime = TimeSpec::from_word(body.u64()? as i64)?;
    let path = body.bytes(body.left())?;
    Ok((atime, mtime, path))
}

/// FUTIMENS after its handle: `(atime, mtime)`.
pub fn read_futimens(mut body: Reader<'_>) -> Result<(TimeSpec, TimeSpec), Status> {
    let atime = TimeSpec::from_word(body.u64()? as i64)?;
    let mtime = TimeSpec::from_word(body.u64()? as i64)?;
    body.finish()?;
    Ok((atime, mtime))
}

/// ACCESS: `(bits, flags, path)`. INVALID for bits outside the three or flags outside `ACCESS_REAL`.
pub fn read_access<'a>(mut body: Reader<'a>) -> Result<(u32, u32, &'a [u8]), Status> {
    let bits = body.u32()?;
    let flags = body.u32()?;
    let path = body.bytes(body.left())?;
    if bits & !7 != 0 || flags & !ACCESS_REAL != 0 {
        return Err(code(INVALID));
    }
    Ok((bits, flags, path))
}

/// The handles of CLONE or CLONE_MORE after their first words: the count was read, the rest are
/// `count` words. At most `CLONE_MAX` and at most the room of `out`; a count that does not fit
/// the body is BAD_SIZE.
pub fn read_handles(mut body: Reader<'_>, count: u32, out: &mut [u32]) -> Result<usize, Status> {
    let count = count as usize;
    if count > CLONE_MAX || count > out.len() {
        return Err(code(INVALID));
    }
    for slot in out.iter_mut().take(count) {
        *slot = body.u32()?;
    }
    body.finish()?;
    Ok(count)
}

/// The two paths of RENAME from its body.
pub fn read_rename<'a>(mut body: Reader<'a>) -> Result<(&'a [u8], &'a [u8]), Status> {
    let from_len = body.u32()? as usize;
    let from = body.bytes(from_len)?;
    let to = body.bytes(body.left())?;
    Ok((from, to))
}

/// The status of a reply and the reader of the fields after it.
pub fn reply(bytes: &[u8]) -> Result<Reader<'_>, Status> {
    let mut r = Reader::new(bytes);
    match Status::from_code(r.u32()?) {
        Status::Ok => Ok(r),
        status => Err(status),
    }
}

// The records.

/// The reply of STAT and FSTAT and the head of an entry of READDIR (the module text has the
/// layout).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stat {
    pub kind: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub ino: u64,
    pub atime: i64,
    pub mtime: i64,
    pub ctime: i64,
    pub nlink: u32,
}

impl Stat {
    pub fn write(&self, w: &mut Writer) -> Result<(), Status> {
        w.bytes(&self.to_bytes())
    }

    pub fn to_bytes(&self) -> [u8; STAT_LEN] {
        let mut b = [0u8; STAT_LEN];
        b[0..4].copy_from_slice(&self.kind.to_le_bytes());
        b[4..8].copy_from_slice(&self.mode.to_le_bytes());
        b[8..12].copy_from_slice(&self.uid.to_le_bytes());
        b[12..16].copy_from_slice(&self.gid.to_le_bytes());
        b[16..24].copy_from_slice(&self.size.to_le_bytes());
        b[24..32].copy_from_slice(&self.ino.to_le_bytes());
        b[32..40].copy_from_slice(&self.atime.to_le_bytes());
        b[40..48].copy_from_slice(&self.mtime.to_le_bytes());
        b[48..56].copy_from_slice(&self.ctime.to_le_bytes());
        b[56..60].copy_from_slice(&self.nlink.to_le_bytes());
        b
    }

    /// BAD_SIZE for a length other than `STAT_LEN` or a nonzero tail.
    pub fn from_bytes(bytes: &[u8]) -> Result<Stat, Status> {
        let mut r = Reader::new(bytes);
        let stat = Stat::read(&mut r)?;
        r.finish()?;
        Ok(stat)
    }

    pub fn read(r: &mut Reader<'_>) -> Result<Stat, Status> {
        let stat = Stat {
            kind: r.u32()?,
            mode: r.u32()?,
            uid: r.u32()?,
            gid: r.u32()?,
            size: r.u64()?,
            ino: r.u64()?,
            atime: r.u64()? as i64,
            mtime: r.u64()? as i64,
            ctime: r.u64()? as i64,
            nlink: r.u32()?,
        };
        if r.u32()? != 0 {
            return Err(Status::BadSize);
        }
        Ok(stat)
    }
}

/// The bytes of an entry of READDIR before its name: `ino` u64, `kind` u32, `name_len` u32.
pub const DIR_ENTRY_HEAD: usize = 16;
/// The bytes of a READDIR reply before its entries: the status and `more`.
pub const DIR_REPLY_HEAD: usize = 8;

/// The entries of one READDIR reply, built by the service before it writes the reply.
pub struct DirBatch {
    bytes: [u8; MESSAGE_MAX - DIR_REPLY_HEAD],
    len: usize,
}

impl DirBatch {
    pub const fn new() -> DirBatch {
        DirBatch {
            bytes: [0; MESSAGE_MAX - DIR_REPLY_HEAD],
            len: 0,
        }
    }

    /// Adds an entry when it fits; false (and nothing added) when it does not, or when the name
    /// is empty or longer than `NAME_MAX`.
    pub fn push(&mut self, ino: u64, kind: u32, name: &[u8]) -> bool {
        let need = DIR_ENTRY_HEAD + name.len();
        if name.is_empty() || name.len() > NAME_MAX || self.len + need > self.bytes.len() {
            return false;
        }
        let at = self.len;
        self.bytes[at..at + 8].copy_from_slice(&ino.to_le_bytes());
        self.bytes[at + 8..at + 12].copy_from_slice(&kind.to_le_bytes());
        self.bytes[at + 12..at + 16].copy_from_slice(&(name.len() as u32).to_le_bytes());
        self.bytes[at + DIR_ENTRY_HEAD..at + need].copy_from_slice(name);
        self.len += need;
        true
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The reply after the status: `more` and the entries. A batch with `more` set carries at
    /// least one entry (rule of the listing), which this refuses to break: INVALID.
    pub fn write(&self, more: bool, w: &mut Writer) -> Result<(), Status> {
        if more && self.is_empty() {
            return Err(code(INVALID));
        }
        w.u32(u32::from(more))?;
        w.bytes(&self.bytes[..self.len])
    }
}

impl Default for DirBatch {
    fn default() -> DirBatch {
        DirBatch::new()
    }
}

/// One entry of a READDIR reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirEntry<'a> {
    pub ino: u64,
    pub kind: u32,
    pub name: &'a [u8],
}

/// The entries of a READDIR reply after the status.
pub struct DirEntries<'a> {
    pub more: bool,
    body: Reader<'a>,
}

/// Reads `more` and prepares the entries: BAD_SIZE for a `more` other than 0 or 1, or 1 with no
/// entry after it.
pub fn read_dir_reply(mut body: Reader<'_>) -> Result<DirEntries<'_>, Status> {
    let more = match body.u32()? {
        0 => false,
        1 => true,
        _ => return Err(Status::BadSize),
    };
    if more && body.left() == 0 {
        return Err(Status::BadSize);
    }
    Ok(DirEntries { more, body })
}

impl<'a> DirEntries<'a> {
    /// The next entry, None at the end of the message; BAD_SIZE for a broken entry.
    pub fn next_entry(&mut self) -> Result<Option<DirEntry<'a>>, Status> {
        if self.body.left() == 0 {
            return Ok(None);
        }
        let ino = self.body.u64()?;
        let kind = self.body.u32()?;
        let len = self.body.u32()? as usize;
        if len == 0 || len > NAME_MAX {
            return Err(Status::BadSize);
        }
        Ok(Some(DirEntry {
            ino,
            kind,
            name: self.body.bytes(len)?,
        }))
    }
}

// The layouts of both sides at compile time: the records, the longest request of each method and
// the batch of the longest names must fit the message and the numbers.
const _: () = {
    assert!(STAT_LEN == 64);
    assert!(DIR_ENTRY_HEAD == 16);
    // `/data` and a path reach the file service's longest path.
    assert!(MAX_PATH + "/data".len() == proto_fs_max_path());
    // The longest request of each method with a path fits one message, RENAME exactly.
    assert!(HEADER_LEN + 4 + 4 + MAX_PATH <= MESSAGE_MAX); // OPEN
    assert!(HEADER_LEN + 4 + MAX_PATH <= MESSAGE_MAX); // MKDIR, CHMOD
    assert!(HEADER_LEN + 8 + MAX_PATH <= MESSAGE_MAX); // CHOWN, ACCESS
    assert!(HEADER_LEN + 16 + MAX_PATH <= MESSAGE_MAX); // UTIMENS
    assert!(HEADER_LEN + 4 + 2 * MAX_PATH == MESSAGE_MAX); // RENAME
    // The longest reply of WHERE fits, and so does CLONE of the most handles.
    assert!(4 + MAX_PATH <= MESSAGE_MAX);
    assert!(HEADER_LEN + 8 + 4 * CLONE_MAX <= MESSAGE_MAX);
    // One entry with the longest name fits a READDIR reply.
    assert!(DIR_REPLY_HEAD + DIR_ENTRY_HEAD + NAME_MAX <= MESSAGE_MAX);
    // A name fits a path, the flags do not overlap, a session can hold what a clone carries.
    assert!(NAME_MAX < MAX_PATH);
    assert!(FLAGS_ALL == 255);
    assert!(SET_FLAGS_ALL & !FLAGS_ALL == 0);
    assert!(CLONE_MAX <= HELD_MAX);
    assert!(FILE_MAX == 0x7fff_ffff);
    // The marks of labels stay apart.
    assert!(SERVICE & OWN == 0 && ROOT & SERVICE == 0);
    assert!(
        is_service(SERVICE) && !is_service(SERVICE | OWN) && is_root(ROOT) && !is_root(SERVICE)
    );
    assert!(UTIME_NOW < UTIME_OMIT);
};

/// The longest path of the file service, `proto_fs::MAX_PATH` (a test compares the two).
const fn proto_fs_max_path() -> usize {
    511
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(w: &Writer) -> Reader<'_> {
        Reader::new(&w.as_bytes()[HEADER_LEN..])
    }

    #[test]
    fn the_labels_of_passes_sessions_natives_and_the_root_are_told_apart() {
        assert!(is_pass(PASS | 7));
        assert!(!is_pass(OWN | 7), "a clone or SESSION session is no pass");
        assert!(!is_pass(ROOT), "the root channel is no pass");
        assert!(!is_pass(SERVICE | 7));
        assert!(is_service(SERVICE | 7));
        assert!(!is_service(PASS | 7));
    }

    fn sample() -> Stat {
        Stat {
            kind: KIND_FILE,
            mode: 0o644,
            uid: 1000,
            gid: 100,
            size: 0x0102_0304_0506,
            ino: 77,
            atime: 1,
            mtime: -2,
            ctime: 3,
            nlink: 1,
        }
    }

    /// The bytes of a request: the header of the method, then `rest`.
    fn bytes_of(method: Method, rest: &[u8]) -> Vec<u8> {
        let mut v = method.header().bytes().to_vec();
        v.extend_from_slice(rest);
        v
    }

    #[test]
    fn numbers_and_codes_are_fixed() {
        assert_eq!(
            Method::ALL.map(Method::number),
            core::array::from_fn(|i| i as u16 + 1)
        );
        assert_eq!(METHODS, Method::ALL.map(Method::number));
        for (method, number) in [
            (Method::Open, 1),
            (Method::SetFlags, 24),
            (Method::Bind, 25),
            (Method::Chmod, 26),
            (Method::Chown, 27),
            (Method::Fchmod, 28),
            (Method::Fchown, 29),
            (Method::Utimens, 30),
            (Method::Futimens, 31),
            (Method::Access, 32),
            (Method::Where, 33),
            (Method::Session, 34),
            (Method::VerifySession, 35),
        ] {
            assert_eq!(method.number(), number);
        }
        for m in Method::ALL {
            assert_eq!(Method::from_number(m.number()), Some(m));
        }
        assert_eq!(Method::from_number(0), None);
        assert_eq!(Method::from_number(36), None);
        for (i, a) in CODES.iter().enumerate() {
            assert!(*a > 1200 && *a < 1300, "{a}");
            assert!(!CODES[i + 1..].contains(a));
        }
        assert_eq!(
            CODES,
            [
                1201, 1202, 1203, 1204, 1205, 1206, 1207, 1208, 1209, 1210, 1211, 1212, 1213, 1214,
                1215, 1216, 1217, 1218, 1219, 1220, 1221, 1222, 1223
            ]
        );
        assert_eq!(
            (PERMISSION, NOT_BOUND, FILE_SIZE_LIMIT, IS_ROOT, READ_ONLY),
            (1219, 1220, 1221, 1222, 1223)
        );
        assert_eq!(VERSION, 3);
    }

    #[test]
    fn every_status_has_one_errno() {
        assert_eq!(ERRNO.map(|(c, _)| c), CODES);
        for code in CODES {
            assert!(errno(code).is_some());
        }
        assert_eq!(errno(0), None);
        assert_eq!(errno(ACCESS), Some(Errno::Eacces));
        assert_eq!(errno(PERMISSION), Some(Errno::Eperm));
        assert_eq!(errno(FILE_SIZE_LIMIT), Some(Errno::Efbig));
        assert_eq!(errno(TOO_BIG), Some(Errno::Efbig));
        assert_eq!(errno(TOO_MANY_OPEN), Some(Errno::Emfile));
        assert_eq!(errno(TABLE_FULL), Some(Errno::Enfile));
        assert_eq!(errno(NO_SPACE), Some(Errno::Enospc));
        assert_eq!(errno(READ_ONLY), Some(Errno::Erofs));
        assert_eq!(errno(STALE), Some(Errno::Eio));
        assert_eq!(errno(BAD_HANDLE), Some(Errno::Ebadf));
    }

    #[test]
    fn the_limits_and_bounds_are_pinned() {
        assert_eq!(
            (
                HELD_MAX,
                ROOT_DESCRIPTIONS,
                ROOT_CLONES,
                PASSES_MAX,
                DIR_ENTRIES_MAX
            ),
            (32, 48, 32, 8, 1024)
        );
        assert_eq!((CLONE_MAX, MAX_PATH, NAME_MAX), (32, 506, 255));
        assert_eq!((STAT_LEN, DIR_ENTRY_HEAD), (64, 16));
        assert_eq!((MAX_READ, MAX_WRITE), (MESSAGE_MAX - 8, MESSAGE_MAX - 12));
        assert_eq!(FILE_MAX, 2_147_483_647);
        assert_eq!(MAX_PATH + "/data".len(), proto_fs::MAX_PATH);
    }

    #[test]
    fn the_stat_record_is_64_bytes_and_round_trips() {
        let bytes = sample().to_bytes();
        assert_eq!(bytes.len(), 64);
        assert_eq!(Stat::from_bytes(&bytes), Ok(sample()));
        // Byte for byte.
        let mut want = [0u8; 64];
        want[0] = 1;
        want[4..6].copy_from_slice(&[0xa4, 0x01]);
        want[8..10].copy_from_slice(&1000u16.to_le_bytes());
        want[12] = 100;
        want[16..24].copy_from_slice(&0x0102_0304_0506u64.to_le_bytes());
        want[24] = 77;
        want[32] = 1;
        want[40..48].copy_from_slice(&(-2i64).to_le_bytes());
        want[48] = 3;
        want[56] = 1;
        assert_eq!(bytes, want);
        // A record of 60 bytes, of 65, or with a nonzero tail is refused.
        assert_eq!(Stat::from_bytes(&bytes[..60]), Err(Status::BadSize));
        let mut long = [0u8; 65];
        long[..64].copy_from_slice(&bytes);
        assert_eq!(Stat::from_bytes(&long), Err(Status::BadSize));
        let mut dirty = bytes;
        dirty[63] = 1;
        assert_eq!(Stat::from_bytes(&dirty), Err(Status::BadSize));
        let mut w = Writer::new();
        sample().write(&mut w).unwrap();
        assert_eq!(w.as_bytes(), bytes);
    }

    #[test]
    fn every_request_is_pinned_byte_for_byte() {
        let one = |f: &dyn Fn(&mut Writer) -> Result<(), Status>| {
            let mut w = Writer::new();
            f(&mut w).unwrap();
            w.as_bytes().to_vec()
        };
        assert_eq!(
            one(&|w| open(b"/a", READ | CREATE, 0o640, w)),
            bytes_of(Method::Open, &[5, 0, 0, 0, 0xa0, 0x01, 0, 0, b'/', b'a'])
        );
        assert_eq!(
            one(&|w| handle_call(Method::Close, 9, w)),
            bytes_of(Method::Close, &[9, 0, 0, 0])
        );
        assert_eq!(
            one(&|w| read(9, 5, w)),
            bytes_of(Method::Read, &[9, 0, 0, 0, 5, 0, 0, 0])
        );
        assert_eq!(
            one(&|w| write(9, b"xy", w)),
            bytes_of(Method::Write, &[9, 0, 0, 0, b'x', b'y'])
        );
        assert_eq!(
            one(&|w| seek(9, -1, SEEK_END, w)),
            bytes_of(
                Method::Seek,
                &[
                    9, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 2, 0, 0, 0
                ]
            )
        );
        assert_eq!(
            one(&|w| truncate(9, 0x0102, w)),
            bytes_of(Method::Truncate, &[9, 0, 0, 0, 2, 1, 0, 0, 0, 0, 0, 0])
        );
        assert_eq!(
            one(&|w| path_call(Method::Stat, b"/s", w)),
            bytes_of(Method::Stat, b"/s")
        );
        assert_eq!(
            one(&|w| mkdir(b"/d", 0o755, w)),
            bytes_of(Method::Mkdir, &[0xed, 0x01, 0, 0, b'/', b'd'])
        );
        assert_eq!(
            one(&|w| rename(b"/a", b"/bc", w)),
            bytes_of(Method::Rename, &[2, 0, 0, 0, b'/', b'a', b'/', b'b', b'c'])
        );
        assert_eq!(one(&|w| statfs(w)), bytes_of(Method::Statfs, &[]));
        assert_eq!(
            one(&|w| pread(9, 5, 7, w)),
            bytes_of(
                Method::Pread,
                &[9, 0, 0, 0, 5, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0]
            )
        );
        assert_eq!(
            one(&|w| pwrite(9, 7, b"z", w)),
            bytes_of(Method::Pwrite, &[9, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, b'z'])
        );
        assert_eq!(
            one(&|w| clone(&[5, 6], w)),
            bytes_of(Method::Clone, &[2, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0])
        );
        assert_eq!(
            one(&|w| clone_more(3, &[5], w)),
            bytes_of(Method::CloneMore, &[3, 0, 0, 0, 1, 0, 0, 0, 5, 0, 0, 0])
        );
        assert_eq!(one(&|w| adopt(w)), bytes_of(Method::Adopt, &[]));
        assert_eq!(
            one(&|w| set_flags(9, APPEND | SYNC, w)),
            bytes_of(Method::SetFlags, &[9, 0, 0, 0, 160, 0, 0, 0])
        );
        for m in [Method::Bind, Method::Session, Method::VerifySession] {
            assert_eq!(one(&|w| header_only(m, w)), bytes_of(m, &[]));
        }
        assert_eq!(
            one(&|w| chmod(b"/c", 0o4755, w)),
            bytes_of(Method::Chmod, &[0xed, 0x09, 0, 0, b'/', b'c'])
        );
        assert_eq!(
            one(&|w| chown(b"/c", 7, UID_KEEP, w)),
            bytes_of(Method::Chown, &[7, 0, 0, 0, 255, 255, 255, 255, b'/', b'c'])
        );
        assert_eq!(
            one(&|w| fchmod(9, 0o600, w)),
            bytes_of(Method::Fchmod, &[9, 0, 0, 0, 0x80, 0x01, 0, 0])
        );
        assert_eq!(
            one(&|w| fchown(9, 1, 2, w)),
            bytes_of(Method::Fchown, &[9, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0])
        );
        let now = UTIME_NOW.to_le_bytes();
        let omit = UTIME_OMIT.to_le_bytes();
        let mut want = now.to_vec();
        want.extend_from_slice(&omit);
        want.extend_from_slice(b"/t");
        assert_eq!(
            one(&|w| utimens(b"/t", TimeSpec::Now, TimeSpec::Omit, w)),
            bytes_of(Method::Utimens, &want)
        );
        let mut want = vec![9, 0, 0, 0];
        want.extend_from_slice(&5i64.to_le_bytes());
        want.extend_from_slice(&omit);
        assert_eq!(
            one(&|w| futimens(9, TimeSpec::At(5), TimeSpec::Omit, w)),
            bytes_of(Method::Futimens, &want)
        );
        assert_eq!(
            one(&|w| access(b"/f", 5, ACCESS_REAL, w)),
            bytes_of(Method::Access, &[5, 0, 0, 0, 1, 0, 0, 0, b'/', b'f'])
        );
        assert_eq!(
            one(&|w| handle_call(Method::Where, 9, w)),
            bytes_of(Method::Where, &[9, 0, 0, 0])
        );
        // The header: method, version 3, four zero bytes.
        assert_eq!(Method::Open.header().bytes(), [1, 0, 3, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn two_paths_fill_a_message_exactly() {
        let mut w = Writer::new();
        rename(&[b'a'; MAX_PATH], &[b'b'; MAX_PATH], &mut w).unwrap();
        assert_eq!(w.as_bytes().len(), MESSAGE_MAX);
        let (from, to) = read_rename(body(&w)).unwrap();
        assert_eq!((from.len(), to.len()), (MAX_PATH, MAX_PATH));
    }

    #[test]
    fn open_with_no_access_is_valid_only_as_a_directory() {
        let mut w = Writer::new();
        open(b"/a/b", READ | CREATE, 0o640, &mut w).unwrap();
        assert_eq!(
            read_open(body(&w)),
            Ok((READ | CREATE, 0o640, &b"/a/b"[..]))
        );
        let mut w = Writer::new();
        open(&[b'x'; MAX_PATH], FLAGS_ALL, MODE_MASK, &mut w).unwrap();
        assert_eq!(read_open(body(&w)).unwrap().2.len(), MAX_PATH);
        for bad_flags in [256, 0, CREATE, APPEND, DIRECTORY | CREATE, SYNC] {
            let mut w = Writer::new();
            open(b"/a", bad_flags, 0, &mut w).unwrap();
            assert_eq!(read_open(body(&w)), Err(code(INVALID)), "{bad_flags}");
        }
        let mut w = Writer::new();
        open(b"/a", DIRECTORY, 0, &mut w).unwrap();
        assert_eq!(read_open(body(&w)), Ok((DIRECTORY, 0, &b"/a"[..])));
        let mut w = Writer::new();
        open(b"/a", DIRECTORY | READ, 0, &mut w).unwrap();
        assert!(read_open(body(&w)).is_ok());
        let mut w = Writer::new();
        open(b"/a", READ, 0o10000, &mut w).unwrap();
        assert_eq!(read_open(body(&w)), Err(code(INVALID)));
        let mut w = Writer::new();
        mkdir(b"/d", 0o755, &mut w).unwrap();
        assert_eq!(read_mode_path(body(&w)), Ok((0o755, &b"/d"[..])));
    }

    #[test]
    fn chown_carries_both_ids_and_the_path() {
        let mut w = Writer::new();
        chown(&[b'p'; MAX_PATH], 7, UID_KEEP, &mut w).unwrap();
        let (uid, gid, path) = read_chown(body(&w)).unwrap();
        assert_eq!((uid, gid, path.len()), (7, UID_KEEP, MAX_PATH));
        assert_eq!(w.as_bytes().len(), HEADER_LEN + 8 + MAX_PATH);
        let mut w = Writer::new();
        chmod(b"/a", 0o10000, &mut w).unwrap();
        assert_eq!(read_mode_path(body(&w)), Err(code(INVALID)));
    }

    #[test]
    fn handle_forms_carry_their_fields() {
        let mut w = Writer::new();
        fchmod(9, 0o600, &mut w).unwrap();
        let mut r = body(&w);
        assert_eq!(r.u32(), Ok(9));
        assert_eq!(read_fchmod(r), Ok(0o600));
        let mut w = Writer::new();
        fchown(9, UID_KEEP, 5, &mut w).unwrap();
        let mut r = body(&w);
        assert_eq!(r.u32(), Ok(9));
        assert_eq!(read_fchown(r), Ok((UID_KEEP, 5)));
        let mut w = Writer::new();
        futimens(9, TimeSpec::Now, TimeSpec::At(-5), &mut w).unwrap();
        let mut r = body(&w);
        assert_eq!(r.u32(), Ok(9));
        assert_eq!(read_futimens(r), Ok((TimeSpec::Now, TimeSpec::At(-5))));
        let mut r = Reader::new(&[0; 5]);
        assert_eq!(r.u32(), Ok(0));
        assert_eq!(read_fchmod(r), Err(Status::BadSize));
    }

    #[test]
    fn utimens_takes_now_omit_and_a_time() {
        let mut w = Writer::new();
        utimens(
            b"/f",
            TimeSpec::Omit,
            TimeSpec::At(1_700_000_000_000_000_000),
            &mut w,
        )
        .unwrap();
        assert_eq!(
            read_utimens(body(&w)),
            Ok((
                TimeSpec::Omit,
                TimeSpec::At(1_700_000_000_000_000_000),
                &b"/f"[..]
            ))
        );
        assert_eq!(TimeSpec::from_word(UTIME_NOW), Ok(TimeSpec::Now));
        assert_eq!(TimeSpec::from_word(UTIME_OMIT), Ok(TimeSpec::Omit));
        assert_eq!(
            TimeSpec::from_word(UTIME_OMIT + 1),
            Ok(TimeSpec::At(UTIME_OMIT + 1))
        );
        assert_eq!(TimeSpec::from_word(0), Ok(TimeSpec::At(0)));
        assert_eq!(TimeSpec::from_word(i64::MAX), Ok(TimeSpec::At(i64::MAX)));
    }

    #[test]
    fn access_carries_bits_flags_and_the_path() {
        let mut w = Writer::new();
        access(b"/f", ACCESS_READ | ACCESS_EXEC, ACCESS_REAL, &mut w).unwrap();
        assert_eq!(read_access(body(&w)), Ok((5, ACCESS_REAL, &b"/f"[..])));
        let mut w = Writer::new();
        access(b"/f", 8, 0, &mut w).unwrap();
        assert_eq!(read_access(body(&w)), Err(code(INVALID)));
        let mut w = Writer::new();
        access(b"/f", 0, 2, &mut w).unwrap();
        assert_eq!(read_access(body(&w)), Err(code(INVALID)));
    }

    #[test]
    fn root_methods_are_session_and_verify_session() {
        assert!(Method::Session.is_root_method() && Method::VerifySession.is_root_method());
        assert!(!Method::Bind.is_root_method() && !Method::Open.is_root_method());
    }

    #[test]
    fn a_batch_of_the_longest_names_fits_the_message() {
        let name = [b'n'; NAME_MAX];
        let mut batch = DirBatch::new();
        let mut held = 0;
        while batch.push(9 + held, KIND_FILE, &name) {
            held += 1;
        }
        // 3 entries of 16 + 255 bytes and the 8 bytes before them.
        assert_eq!(held, 3);
        let mut w = Writer::new();
        w.u32(0).unwrap();
        batch.write(true, &mut w).unwrap();
        assert!(w.as_bytes().len() <= MESSAGE_MAX);
        let mut entries = read_dir_reply(Reader::new(&w.as_bytes()[4..])).unwrap();
        assert!(entries.more);
        let mut count = 0;
        while let Some(entry) = entries.next_entry().unwrap() {
            assert_eq!(
                entry,
                DirEntry {
                    ino: 9 + count,
                    kind: KIND_FILE,
                    name: &name[..]
                }
            );
            count += 1;
        }
        assert_eq!(count, 3);
    }

    #[test]
    fn an_entry_is_pinned_byte_for_byte() {
        let mut batch = DirBatch::new();
        assert!(batch.push(0x0102, KIND_DIRECTORY, b"ab"));
        let mut w = Writer::new();
        batch.write(false, &mut w).unwrap();
        assert_eq!(
            w.as_bytes(),
            [
                0, 0, 0, 0, 2, 1, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, b'a', b'b'
            ]
        );
    }

    #[test]
    fn a_batch_of_short_names_and_the_end_of_a_directory() {
        let mut batch = DirBatch::new();
        let mut held = 0;
        while batch.push(1, KIND_FILE, b"a.txt") {
            held += 1;
        }
        assert_eq!(held, (MESSAGE_MAX - DIR_REPLY_HEAD) / (DIR_ENTRY_HEAD + 5));
        assert!(!batch.push(1, KIND_FILE, b""));
        assert!(!DirBatch::new().push(1, KIND_FILE, &[b'x'; NAME_MAX + 1]));
        // The end of a directory: more 0 and no entries.
        let mut w = Writer::new();
        w.u32(0).unwrap();
        DirBatch::new().write(false, &mut w).unwrap();
        let mut entries = read_dir_reply(Reader::new(&w.as_bytes()[4..])).unwrap();
        assert!(!entries.more);
        assert_eq!(entries.next_entry(), Ok(None));
        // A reply with `more` and no entry is not valid, on either side.
        assert_eq!(
            DirBatch::new().write(true, &mut Writer::new()),
            Err(code(INVALID))
        );
        assert!(read_dir_reply(Reader::new(&1u32.to_le_bytes())).is_err());
        // A broken entry is BAD_SIZE.
        let mut bytes = [0u8; 4 + 16];
        bytes[0] = 1;
        bytes[4 + 12..].copy_from_slice(&300u32.to_le_bytes());
        let mut entries = read_dir_reply(Reader::new(&bytes)).unwrap();
        assert_eq!(entries.next_entry(), Err(Status::BadSize));
        assert!(read_dir_reply(Reader::new(&2u32.to_le_bytes())).is_err());
    }

    #[test]
    fn labels_tell_the_profile_and_the_root() {
        assert!(is_service(SERVICE | 5));
        assert!(!is_service(5));
        assert!(!is_service(OWN | SERVICE));
        assert!(is_root(ROOT));
        assert!(!is_root(ROOT | 1));
        assert_eq!(SERVICE, 1 << 61);
        assert_eq!(ROOT, 1 << 63 | 1 << 60);
    }

    #[test]
    fn clone_carries_its_handles() {
        let mut w = Writer::new();
        clone(&[5, 6, 7], &mut w).unwrap();
        let mut r = Reader::new(&w.as_bytes()[HEADER_LEN..]);
        let count = r.u32().unwrap();
        let mut out = [0; CLONE_MAX];
        assert_eq!(read_handles(r, count, &mut out), Ok(3));
        assert_eq!(out[..3], [5, 6, 7]);
        let mut w = Writer::new();
        clone_more(9, &[1], &mut w).unwrap();
        let mut r = Reader::new(&w.as_bytes()[HEADER_LEN..]);
        assert_eq!(r.u32(), Ok(9));
        let count = r.u32().unwrap();
        assert_eq!(read_handles(r, count, &mut out), Ok(1));
        let r = Reader::new(&[0; 4]);
        assert_eq!(read_handles(r, 99, &mut out), Err(code(INVALID)));
        let r = Reader::new(&[0; 4]);
        assert!(read_handles(r, 2, &mut out).is_err());
        let r = Reader::new(&[0; 8]);
        assert!(read_handles(r, 1, &mut out).is_err());
        let mut small = [0u32; 2];
        let r = Reader::new(&[0; 12]);
        assert_eq!(read_handles(r, 3, &mut small), Err(code(INVALID)));
        let mut w = Writer::new();
        clone(&[1; CLONE_MAX], &mut w).unwrap();
        assert!(w.as_bytes().len() <= MESSAGE_MAX);
    }

    #[test]
    fn a_full_write_fits() {
        let mut w = Writer::new();
        write(1, &[0; MAX_WRITE], &mut w).unwrap();
        assert_eq!(w.as_bytes().len(), MESSAGE_MAX);
    }
}
