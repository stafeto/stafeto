# Files on /data for programs

This is what a POSIX program gets from the data volume: the directory `/data`, which the data file service (`datafs`, over littlefs on the data disk) serves and which keeps its files across reboots. The service's own rules are in `docs/packages.md` ("The data file service") and in `proto/data/src/lib.rs`; the departures from POSIX are listed in `docs/posix-coverage.md`.

## What it is

- **The mount point.** A path belongs to the volume when its absolute form is `/data` or begins with `/data/`. The layer reads the path as text (the current directory and the dots applied first), so `/datax` is an ordinary name of the RAM file service, and `/data/..` is `/`. An image whose table has the data file service (the images of the try-out) has an empty directory `/data` of the RAM file service, so `ls /` shows it; an image with no service has no `/data`, so `du /` and `find /` meet nothing there.
- **No volume, no RAM.** A path under `/data` never goes to the RAM file service. An image whose process service has no data root (no data service in the image, or it has not registered yet) answers EIO for such a path after one second of trying.
- **Lexical dots.** `a/ghost/..` under `/data` names `a` and succeeds, where the RAM file service looks the name up and answers ENOENT.
- **Links.** The volume has no symbolic or hard links: `symlink` is EPERM, `link` of a file is EMLINK, and `readlink` of an existing path is EINVAL. `rename` and `link` between `/data` and another file system are EXDEV.

## Who may do what

- **Identity.** The first call under `/data` takes a session with the data service for the process: the layer asks the process service for the service's root and sends it SESSION with a copy of the process's identity session, which the service checks with the process service before it answers. The service then knows the process's user, group, supplementary groups and file size limit, and checks the rules of POSIX (the same code as the RAM file service uses): search on every directory of a path, read and write by the mode of a file, ownership for `chmod`, `chown` and `utimensat`.
- **After `setuid` and `exec`.** A request sent after `setuid` returned is checked by the new identity. An `exec` ends the binding of the session; the layer binds it again (BIND) at the first call that needs an identity, and descriptions already open are read without it.
- **Open descriptions keep their rights.** A description keeps the rights it was opened with over `chmod`, `chown`, `setuid`, `fork`, `exec` and a pass through a socket.
- **Creation.** A new file or directory has the mode of the call with the process's umask applied, the process's effective user and group, and the sticky-directory rule on removal and rename. A file made before 0.6 has no record of an owner or mode: it shows root, group 0 and mode 0600 (0700 for a directory) until the service has converted it, which it does after READY, one entry at a time, so a program that starts at once can see the default for a while.
- **The reserve.** When fewer than 64 blocks are free, a caller other than user 0 gets ENOSPC for a write, a creation, a rename and a change of attributes. User 0 works into the reserve, and removal always works.

## What a call does

- **Names.** `mkdir`, `rmdir`, `unlink`, `rename`, `chmod`, `chown` and `utimensat` are durable when the call returns: after a power cut the name or the attribute is there once.
- **File data.** A write is visible to every description of the file at once. It reaches the disk at `fsync` or `fdatasync`, at the close of the last description and when the service needs the room; after `fsync` the bytes, the size, the name and the times are durable. A file written to a temporary name, synced and renamed over the old one leaves one whole generation after a cut, the old or the new.
- **Open files.** `unlink` and `rename` over an open file succeed; the open descriptions go on reading and writing the old file, which goes when the last of them closes (`fstat` shows `st_nlink` 0). A directory that is open, or is the current directory of a process, or holds one, answers EBUSY for `rmdir` and `rename`, so the string `getcwd` returns stays true.
- **Write and read sizes.** A message carries 1,012 bytes of a write and 1,004 of a pwrite, and 1,016 of a read. A call with a larger buffer is a loop of messages. Each message is atomic against the other writers and readers of the file, and the end of an O_APPEND description is taken for each message. So records of up to 1 KiB written in one call never interleave, and a larger record written by two processes, or read while another process rewrites the file in place, can be mixed. The result of a write is the sum of the messages that went; a failure after some of them (ENOSPC, EFBIG, EINTR) is that sum and the next call meets the error again, and the limit of the file size also sends SIGXFSZ when no byte went.
- **Speed.** A call is one message of 1 KiB at most, so a large file is thousands of calls: 8 MiB took 8,290 write calls and 11.4 s under QEMU (about 1.4 ms a call). Programs that copy large files should expect that rate and write in buffers of 1,004 bytes or more. The figure on real hardware comes from the throughput probe of the release.
- **`mmap`.** A private mapping of a file reads the file at the call; a shared mapping is ENODEV. A program is never run from the volume: `exec` of a path under `/data` is EACCES, and `access(X_OK)` of a regular file there too.
- **Locks and passes.** Record locks (`fcntl` F_SETLK and the others) are ENOLCK. A description of `/data` goes through a Unix socket with SCM_RIGHTS and keeps its rights.
- **Directories.** `readdir` lists `.` and `..` first, in batches; `d_ino` is the number `stat` gives, also for `..` of the root of the volume. `telldir` and `seekdir` count entries, so after a removal in the directory between them `seekdir` resumes later by the number removed before the position. `O_SEARCH` and `O_PATH` open a directory for search only.
- **Truncation.** `open` for reading with O_TRUNC is two opens, one for writing that truncates and closes and the reading one after it, so another process can write between them.

## Limits

| Limit | Value | Answer beyond it |
|---|---|---|
| Directories on a volume (the root and the hidden directory for unlinked open files count) | 1,024 | ENOSPC for `mkdir` |
| Metadata pairs on a volume | 2,048 | ENOSPC for `mkdir`, the creation of a file and a `rename` into another directory (at the cap also a `rename` to a longer name) |
| Entries in a directory | 1,024 | ENOSPC for a creation |
| Size of a file | 2^31 - 1 bytes | EFBIG |
| Path | 506 bytes below `/data` | ENAMETOOLONG |
| Name | 255 bytes | ENAMETOOLONG |
| Descriptions a session holds | 32 | EMFILE |
| Clones of a process tree (`fork`, `posix_spawn`) | 32 | EAGAIN |

Removal, writes, truncation and changes of mode and times are never refused by the two caps. Every file takes at least 4 KiB (inline data is off). A volume holds about 20,000 to 30,000 files with names up to 32 bytes and about 6,000 with names of 255 bytes. A creation near the cap recounts the pairs, which takes 1.5 to 2 s on an EBS gp3 volume, and one removal takes up to about 2 s there; a tree of a thousand directories takes about 18 minutes to remove (3.3 million reads at 3,000 reads a second).

## When the volume is missing

In an image that has the service, a missing volume or a service marked broken leaves no root with the process service, and every call by a path under `/data` answers EIO after the layer's second of tries. A listing of `/` still shows `/data` (the entry is the RAM file service's), and `ls -l /`, `ls /data`, `du /` and `find /` each stop for a second at that one path and report it (`du: /data: I/O error`) before they go on with the rest; they ask for `/data` once, so the stall is one second a command and not one for each entry. A program that calls `/data` in a loop sees the second at each call. This is accepted: the alternative, an answer that comes at once, would need the layer to know whether the service is meant to be there, which only init knows.

## Remaining risks

- **The queue of the root.** Every SESSION request of every process arrives with the one label of the root, and the requests over the tree's share of jobs wait in a queue of 32 in the order they came. A process that keeps a thread for every one of the 32 places can still make the sessions of other processes wait. A label of the root for each process tree is planned for 0.7.
- **Trust in the vouchers.** A service that asks the process service who a client is (the pipe, network, IPC and data services) holds a copy of the client's identity session that can be duplicated, and could present it to another such service. The services are trusted with it. A copy that serves Vouch alone needs a right of the kernel that does not exist.
- **Atomicity.** A write is atomic per message of 1,012 bytes (a pwrite 1,004): a larger write, and a larger read of a file another process rewrites in place, can be mixed with other processes' bytes. The transfer through a memory object that removes this is planned after 0.6.
- **A misstated kind in SCM_RIGHTS.** A pass travels with the kind of its service. If the kind of a pass is misstated, the service that is handed the pass does not know it and refuses it with BAD_HANDLE, and the pass is gone: the description the sender exported is lost to the sender. A layer that states kinds as built here never does this.

## When the data service restarts

A descriptor opened before the restart answers EIO to every call but `close`, which succeeds. The first call by path takes a session with the new instance; a call that meets the end of the old session goes on at once with the new one. The current directory is opened again from its string. Names made before the restart are there, files written and not synced are as the last sync left them.

## Where to look next

`docs/posix-coverage.md` lists each departure, `tests/open-posix/data-pass.txt` and `data-expected-not-pass.txt` list the Open POSIX tests that pass on the volume and those that do not by design, and `cargo xtask data-posix`, `open-posix --data` and `data-save` are the probes.
