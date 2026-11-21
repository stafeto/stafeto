# The change to littlefs 2.11.3

The sources in this directory are the release v2.11.3 of littlefs (tag commit
`6cb4e86540eca0d9ba62500a298385c9d863c8be`) with the changes below. The change is also in
`stafeto-changes.patch`, a unified diff against the release. The licence (BSD-3-Clause,
`LICENSE.md`) is that of the release and stays as it is: the change adds code to `lfs.c` and
`lfs.h` under the same licence and under the same copyright notice, and `LICENSE.md` asks only
that the notice and the disclaimer stay with the sources, which they do. This file states that
the copy is modified, so that the notice is not read as saying it is the release.

## What was added

Four functions that only read (the change of the repair, further down, is the one that writes). They add no field to any structure of the release, and change
nothing on the disk: a volume written by the release reads with the change and the other way
round. One function of the release, `lfs_dir_find`, is split to carry the third (below): its body
becomes `lfs_dir_find_` with one more argument, and `lfs_dir_find` calls it with that argument
NULL, so every caller of the release behaves as before.

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
- `lfs_path_attrs(lfs, path, info, type, out, buffer, size, capacity, &count)` in `lfs.h` and
  `lfs.c`, with `struct lfs_path_attr {res, type}`. It does `lfs_stat_attr` for the root and for
  every entry of the path in one walk: `lfs_dir_find_` calls `lfs_path_walk_visit` for the root and
  right after it matches each entry, when the pair that holds the entry is still the one it
  fetched, and the visit reads the attribute from that pair into the caller's `out` (the kind and
  the size of the attribute) and `buffer` (`size` bytes for each entry). Entries that `.` and
  `..` make the path skip are never matched and have no place. `*count` is the number of places
  filled also when the call fails, so that a caller still has the attributes of the directories
  above a missing name (`LFS_ERR_NOENT`) or a file in the middle of the path (`LFS_ERR_NOTDIR`);
  a path of more entries than `capacity` gives `LFS_ERR_NAMETOOLONG`. The status of the last entry
  is returned as `lfs_stat` does. A walk of a path of depth d costs about what an `lfs_stat` of it costs, 3 reads for each
  component with the read size of 4096 (26 against 27 at depth 8), where a lookup of each prefix
  repeats from the root.
- A private helper, `lfs_dir_getattr_`, which they use: the tail of `lfs_getattr_` over a pair
  and an id.
- `lfs_fs_pairs(lfs, &pairs, &dirs)` in `lfs.h` and `lfs.c`: the number of metadata pairs, the length of
  the threaded list of pairs that `lfs_fs_traverse_` walks (the superblock's pair first), and the
  number of directories, by one `lfs_dir_fetch` for each pair with the cycle check of the
  traversal. A pair whose tail is a hard tail (`dir.split`) continues its directory with the
  next pair; any other tail is a soft tail and the next pair begins a directory; the first pair is
  the root. About two reads for each pair, where `lfs_fs_pred` (which a removal of a directory uses
  to find the pair before the one it removes) walks the same list from its head. The data service
  caps the pairs and the directories of a volume with it.

Each of the four has the public wrapper with `LFS_LOCK` and `LFS_TRACE` and the private function with a
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

The path walk was added because a check of search permission on each directory of a path needs
the attribute of every ancestor, and a lookup of each prefix from the root costs the square of the
depth: 60,301 reads for the 201 prefixes of a path of depth 200, against 602 for the walk (8 and 26
reads at depth 2 and 8, against 10 and 109).

## A change to the repair after a power loss

One more change, to the write path, the first of its kind here: `lfs_fs_deorphan`, which the volume
runs after a power loss that left an orphan (`lfs_fs_mkconsistent`, called by the data service at
every mount), asks `lfs_fs_parent` for the parent of every head of a directory, and each ask walks the list
of metadata pairs from its head: a repair costs about two walks for each directory, so D
directories in a list of P pairs cost about 2*D*P fetches. Measured on the host
(`scale_orphan_mount` in `lib/datafs/src/tests_scale.rs`), the dearest mount after a cut inside
RMDIR or RENAME over a directory, with the parents of the directories far from the head of the list: 79,587
reads at 135 directories and 256 pairs, 1,443,988 at 539 and 1,024, 6,003,785 at 1,077 and 2,048
(10 minutes at 10,000 reads a second).

- `struct lfs_config` has two more fields at its end, `orphan_buffer` and `orphan_size`. With NULL
  (the default of a zeroed configuration) nothing changes. With a table of 4-byte alignment, the repair
  after a power loss (`lfs_fs_deorphan(lfs, true)`) walks the list once and writes into the table, for
  every directory entry, the pair that the entry names and the pair that holds the entry, under each of the
  entry's two blocks (the release's `lfs_pair_cmp` calls two pairs that share a block equal). Each ask
  for a parent is then answered from the table: no entry names the pair (the answer of the walk,
  `LFS_ERR_NOENT`), or the one holder the table names is fetched with the very match `lfs_fs_parent`
  uses, which gives the tag and the parent. A key that has two holders (a move a power loss left
  half done has the entry under both names), a fetch that finds no match (the entry was deleted later
  in the log of its pair) and a table that is full are answered by `lfs_fs_parent` itself, so every
  answer is the one the release gives. The table is three quarters full at most, 12 bytes a cell.
- The table is scratch for one call of `lfs_fs_deorphan`, built again after each commit of the repair
  and not kept. A write that fails ends the call with its error and leaves nothing behind; the next
  mount starts with no table. The repair that runs with no power loss (`lfs_fs_deorphan(lfs, false)`,
  after a relocation) does not use the table.
- Nothing changes on the disk: the repair makes the same commits, in the same order, with or without the table
  (the test below compares the disks byte for byte).
- The data service gives the table 48 KiB (4,096 cells, 1,536 directories), `ORPHAN_CELLS` in
  `lib/datafs/csrc/glue.c`. A volume with more directories than that is repaired with the walk.
- Measured (`scale_orphan_table`): the dearest mount after a cut is 26,159 reads at 540 directories
  and 1,024 pairs and 53,996 at 1,077 and 2,048 (5.4 s at 10,000 reads a second, against 600 s). Tests:
  `the_table_of_the_repair_of_orphans_leaves_the_disk_of_the_walk` (a cut at every sector of MKDIR, RMDIR and
  RENAME over a directory, four sets of surviving sectors: the disk after the mount is the same with the
  table and without it) and `scale_orphan_table` (the same at the scale of the plan, by name).

## A known defect of the release that the service works around

With `inline_max = -1` (no inlined files) littlefs 2.11.3, with or without this change, loses a write at the start or in the middle of an existing inline file (a file that an earlier configuration kept inside the pair of its directory): moving the file out (`lfs_file_outline`, `lfs_file_relocate`) copies only the bytes before the write position, flushing the rest then fails, and the close answers `LFS_ERR_CORRUPT`; the write is lost and the old bytes stay. Appending, `O_TRUNC` and truncating down work. The service moves every inline file out before a write can meet this: open for writing, seek to the end and write no byte (one commit, the whole file moves), by the conversion job after the mount and, for a file the job has not reached, at the first open of the path for writing or truncation. The test that reproduces the defect is `without_the_move_out_a_write_in_the_middle_of_an_old_inline_file_is_lost` in `lib/datafs/src/tests_perm.rs`: it fails when a release stops losing the write, and then the move-out can go. The release's own message about it is not sent yet.

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
4eb79f059f224cf2ea53ef31f6b4c899bae1c2f8d69a51003815e507bde1ab67  lfs.c (with the change)
5ed746718dd5be8435d070861a344a945b463d7f9f515ffc93477ad2e02f1f63  lfs.h (with the change)
```

`tools/check-littlefs.py` (run by `cargo xtask ci` as "littlefs sources") fails when a file of the
release differs from its checksum, when `lfs.c` or `lfs.h` differs from the release plus the
change, or when `stafeto-changes.patch` applied backwards to them does not give the release.

## How to carry it to a new release

1. Unpack the new release and copy its `lfs.c`, `lfs.h`, `lfs_util.c`, `lfs_util.h`,
   `LICENSE.md`, `SPEC.md` and `DESIGN.md` here. Check its `LFS_VERSION`, and that `lfs_dir_read_`,
   `lfs_stat_`, `lfs_getattr_`, `lfs_dir_get` and `lfs_dir_getinfo` still have the shape the
   change relies on (`lfs_dir_read_` leaves `dir->id` one past the entry; the attribute is a tag
   of the same pair as the entry's name). Take the new release's `lfs_dir_find` and split it
   again as the change does, and never copy the old body over it: the new body becomes
   `lfs_dir_find_` with the `walk` argument, `lfs_dir_find` calls it with NULL, and the two
   places that call `lfs_path_walk_visit` are right after the empty-path check (the root) and
   right after the loop that matches the name (the entry just found, while `dir` is still the
   pair that holds it). The rest of the body must equal the release's.
   `lfs_fs_pairs` relies on three things of the release: the threaded list of metadata pairs
   starts at the superblock's pair `{0, 1}` and each pair's `tail` names the next (the list
   `lfs_fs_traverse_` walks); `lfs_tortoise_detectcycles` is the cycle check of that walk; and
   `lfs_dir_fetch` of a pair gives the `tail` of the directory it holds, the same shape as in
   `lfs_fs_pred`; the count of directories relies on `dir.split` being true exactly when the
   pair's tail is a hard tail (a continuation of the same directory) and false for a soft tail.
   The table of the repair relies on `lfs_fs_parent` and `lfs_fs_parent_match` (the match on `LFS_TYPE_DIRSTRUCT` with the mask `LFS_MKTAG(0x7ff, 0, 0x3ff)`) and on the two commits of `lfs_fs_deorphan` that follow a repair; keep the table's answer equal to `lfs_fs_parent`'s.
   Check that the new release's `lfs_fs_traverse_` still begins its walk with
   `dir.tail = {0, 1}`, runs the cycle check before each fetch and goes on to `dir.tail`, and keep
   the function in step with it.
2. Apply `stafeto-changes.patch` with `patch -p1` from the root of the repository (or by hand if
   the context moved) to the new `lfs.c` and `lfs.h`.
3. Rebuild the patch (`diff -u` of the new release against the files here) as
   `stafeto-changes.patch`, put the checksums of the new release and of the changed files in
   this file, in `README.md` and in `tools/check-littlefs.py`, and change the version in
   `Cargo.toml` and `src/lib.rs`.
4. Run `cargo test -p datafs`: `tests_entry_attr.rs` compares the attribute of every entry of
   a directory with `lfs_getattr` by path, across several metadata pairs, and
   `tests_scale.rs` compares the disk after the repair of orphans with and without the table.
5. When a release has the same functions, delete the change: remove the patch, this file, the use
   of the four functions and the table of the repair in `lib/datafs/csrc/glue.c` and `lib/datafs/src/fs.rs`, and the check.
