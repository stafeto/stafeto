# littlefs 2.11.3

The sources of littlefs, a small fail-safe file system for microcontrollers, as they stand in the
release tarball, with the changes that `STAFETO-CHANGES.md` states (three functions that read the
user attribute of an entry with the entry or along a path, and a fourth that counts the metadata pairs, a table for the repair of orphans after a power loss, wayposts for the blocks of a file read in order, a write that is not read back (`trust_prog`), and a flush of the tail of a rewrite in steps, in `lfs.c` and `lfs.h`; the patch is `stafeto-changes.patch`).
`tools/check-littlefs.py` checks the tree against the checksums below. `lib/datafs` compiles `lfs.c` and `lfs_util.c` with
the settings its `build.rs` names and is the only user.

| | |
|---|---|
| Project | https://github.com/littlefs-project/littlefs |
| Release | v2.11.3 (2026-03-25), tag commit `6cb4e86540eca0d9ba62500a298385c9d863c8be` |
| Tarball | `https://github.com/littlefs-project/littlefs/archive/refs/tags/v2.11.3.tar.gz` |
| Tarball SHA-256 | `15521be8aaed133c453e7337714e029a9f62480ab41f59c4ba5d18297a076207` |
| Licence | BSD-3-Clause, `LICENSE.md` (Copyright (c) 2022 The littlefs authors, Copyright (c) 2017 Arm Limited) |

The files of this directory, by SHA-256 (those of the release are the same as in the tarball;
`lfs.c` and `lfs.h` are listed as the release has them, and with the change below the list):

```
a36d6a095785ddea9571d541d68d3e4ef01d5b255a99d17d3f07fb6ea60ea132  lfs.c
b1befd7288d08815accc8f9af744c55686c0b9e3ac0061c32ceee38a1b3eb96d  lfs.h
f2fbde533670560434bd9f5a547174cc7c5a4670a02c47b4bd85180dced8b2ec  lfs_util.c
548d46aa524dc7449e16739286c1a422a52f9de727ff0be0c2ffc5593f5ca981  lfs_util.h
0cb4ff1daf5fdc1359c6a6ee3116092f08fc100c9d58b1b77ab17bfd801f856d  LICENSE.md
6dd74dfc58ac93589f8e002bb73c0830a59206912cfe8c951c07eb2bd5fccad0  SPEC.md
2a8b3459d74b9fa8bdd947738522c46331739405b1fc3d70f057f636a1dea768  DESIGN.md
```

With the change (`lfs.c` and `lfs.h` as they stand in this directory):

```
ff1199db116f6bf5d53f283308504b8c47af5af2b33d8d471f450ebced9d524a  lfs.c
c9f7c2b7c76eee3be0634c41daf2b0738d68d5e2ca65037844338f74083dd68b  lfs.h
```

`SPEC.md` and `DESIGN.md` describe the on-disk format and the design, for the reader of
`lib/datafs`. The licence file travels with the binaries: `cargo xtask ci` (tools/check-licenses.py)
lists this crate in THIRD-PARTY-NOTICES.

To move to a newer release, replace the seven files with those of the new tarball, carry the change
over as `STAFETO-CHANGES.md` says, change the version in `Cargo.toml` and `src/lib.rs`, and update
this table. The disk format of littlefs 2 stays
readable across the 2.x releases; the version of the format a volume carries is set when it is
formatted (`lfs_format`).
