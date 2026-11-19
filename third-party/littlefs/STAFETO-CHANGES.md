# The change to littlefs 2.11.3

The sources in this directory are the release v2.11.3 of littlefs (tag commit
`6cb4e86540eca0d9ba62500a298385c9d863c8be`) with the one change below. The change is also in
`stafeto-changes.patch`, a unified diff against the release. The licence (BSD-3-Clause,
`LICENSE.md`) is that of the release and stays as it is: the change adds code to `lfs.c` and
`lfs.h` under the same licence and under the same copyright notice, and `LICENSE.md` asks only
that the notice and the disclaimer stay with the sources, which they do. This file states that
the copy is modified, so that the notice is not read as saying it is the release.

## What was added

Two functions that only read. They add no field to any structure, change no function of the
release and change nothing on the disk: a volume written by the release reads with the change
and the other way round.

- `lfs_dir_read_attr(lfs, dir, info, type, buffer, size, &res)` in `lfs.h` and `lfs.c`. It does what
  `lfs_dir_read` does (it calls `lfs_dir_read_`), and then reads the user attribute `type` of the
  entry it returned from the metadata pair the iterator already holds (`dir->m`, the entry's id
  is `dir->id - 1`, because `lfs_dir_read_` has advanced `dir->id` past the entry). `*res` is the
  size of the attribute on disk, or `LFS_ERR_NOATTR` when the entry has none, which is always so
  for `.` and `..` (they are not entries of a pair). The return value is that of `lfs_dir_read`:
  positive for an entry, 0 at the end, negative for an error.
- `lfs_stat_attr(lfs, path, info, type, buffer, size, &res)` in `lfs.h` and `lfs.c`. It does what
  `lfs_stat` does and then reads the attribute with `lfs_dir_get` from the pair the lookup found,
  with the root as `lfs_getattr` handles it: one `lfs_dir_find` and the gets of the name, of the
  structure and of the attribute. `*res` as above; the return value is 0 or a negative error.
- A private helper, `lfs_dir_getattr_`, which both use: the tail of `lfs_getattr_` over a pair
  and an id.

Each has the public wrapper with `LFS_LOCK` and `LFS_TRACE` and the private function with a
trailing underscore, as the functions around them do. The attribute buffer is read as
`lfs_getattr` reads it (padded with zeros, truncated to `size` and to `LFS_ATTR_MAX`).

## Why

The data file service (`lib/datafs`) keeps the owner, the mode, the times and the file number of
every entry as one user attribute of 48 bytes, and a directory listing needs it for every
entry. The release reads an attribute by path (`lfs_getattr`), which looks the path up again.
Measured on the host (`lib/datafs/src/tests_entry_attr.rs`), with the read size of the data
service, a block of 4096 bytes, and the device reads counted on a volume just mounted: listing a
directory of 1,000 entries that have no attribute costs 42 reads, and with the attribute of each
entry by path 24,492. For entries that carry the 48-byte attribute, as the service keeps them,
the listing alone costs 140 reads (123 to 146 after the attributes were rewritten three times) and
with `lfs_dir_read_attr` the same, where the attribute of each entry by path costs 72,602. A `stat`
with its attribute at depth 2 costs 9 reads, the same as the stat alone, and 18 as two lookups.
The cost depends on the layout of the pairs: with the read size of one sector of 512 bytes the
listing of the same directory cost 1,791 reads (5,505 after three rewrites), and the iterator
added about 0.9 read for each entry. The plan of the service caps a directory at 1,024 entries,
which these figures cover.

## Against which release

littlefs v2.11.3 (`LFS_VERSION` 0x0002000b, disk format 2.1). Checksums of the files of the
release and of the two changed files:

```
a36d6a095785ddea9571d541d68d3e4ef01d5b255a99d17d3f07fb6ea60ea132  lfs.c (release)
b1befd7288d08815accc8f9af744c55686c0b9e3ac0061c32ceee38a1b3eb96d  lfs.h (release)
f2fbde533670560434bd9f5a547174cc7c5a4670a02c47b4bd85180dced8b2ec  lfs_util.c
548d46aa524dc7449e16739286c1a422a52f9de727ff0be0c2ffc5593f5ca981  lfs_util.h
0cb4ff1daf5fdc1359c6a6ee3116092f08fc100c9d58b1b77ab17bfd801f856d  LICENSE.md
6dd74dfc58ac93589f8e002bb73c0830a59206912cfe8c951c07eb2bd5fccad0  SPEC.md
2a8b3459d74b9fa8bdd947738522c46331739405b1fc3d70f057f636a1dea768  DESIGN.md
dcbdc815892164b427b0835e6a1f06d7a240b0cf4d66814c9bfb1448442b3726  lfs.c (with the change)
361a9b1292e01e5ef48c918caceee14c585e77be3665b711575f0f1bed277953  lfs.h (with the change)
```

`tools/check-littlefs.py` (run by `cargo xtask ci` as "littlefs sources") fails when a file of the
release differs from its checksum, when `lfs.c` or `lfs.h` differs from the release plus the
change, or when `stafeto-changes.patch` applied backwards to them does not give the release.

## How to carry it to a new release

1. Unpack the new release and copy its `lfs.c`, `lfs.h`, `lfs_util.c`, `lfs_util.h`,
   `LICENSE.md`, `SPEC.md` and `DESIGN.md` here. Check its `LFS_VERSION`, and that `lfs_dir_read_`,
   `lfs_stat_`, `lfs_getattr_`, `lfs_dir_get` and `lfs_dir_getinfo` still have the shape the
   change relies on (`lfs_dir_read_` leaves `dir->id` one past the entry; the attribute is a tag
   of the same pair as the entry's name).
2. Apply `stafeto-changes.patch` with `patch -p1` from the root of the repository (or by hand if
   the context moved) to the new `lfs.c` and `lfs.h`.
3. Rebuild the patch (`diff -u` of the new release against the files here) as
   `stafeto-changes.patch`, put the checksums of the new release and of the changed files in
   this file, in `README.md` and in `tools/check-littlefs.py`, and change the version in
   `Cargo.toml` and `src/lib.rs`.
4. Run `cargo test -p datafs`: `tests_entry_attr.rs` compares the attribute of every entry of
   a directory with `lfs_getattr` by path, across several metadata pairs.
5. When a release has the same functions, delete the change: remove the patch, this file, the two
   functions' use in `lib/datafs/csrc/glue.c` and `lib/datafs/src/fs.rs`, and the check.
