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
- **Times.** `atime` is set when a file is made and by `utimensat`; a read never updates it (the volume behaves as mounted with `noatime`). A write sets `mtime` and `ctime`, a name added to or removed from a directory sets those of the directory.
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

## An editor on the volume

BusyBox `vi` of the shell image edits files under `/data`. It writes a file in place (`open` with `O_WRONLY | O_CREAT`, `write`, `ftruncate`, `close`), which the volume serves like any other write: the bytes are durable at the close of the last description. `cargo xtask vi-dialog` types lines into a new file, saves with `:wq`, reads it back with `cat`, edits it again and reads it after a second boot of the same disk.

## Accounts and homes

The image's `/etc/passwd`, `/etc/group` and `/etc/shadow` are immutable files of the RAM file service. The boot script (`/etc/rc`) moves an ordinary copy over each before anything else runs (the service `datakey` has placed the merge described below as `/etc/<file>.new`; an image without it gets a copy of the image's file), so `adduser`, `addgroup`, `deluser`, `delgroup`, `chpasswd`, `passwd` and `su` write ordinary files.

With a volume `datakey` keeps the three files on it as `/etc/passwd`, `/etc/group` and `/etc/shadow` of the volume (the directory is 0700 and the files 0600, each written to a temporary file, synced and renamed, shadow first), once a second when they have changed and two looks agree. At each boot it merges the image's files with the volume's: an account of the image keeps its name, numbers and passwd fields, and takes the line of `/etc/shadow` (so `passwd root` stays) and the member lists of the image's groups from the volume; an account of the volume that the image lacks is accepted when its user number is 1000 or more and not 65534, no account has that number, and its group exists, and a group of the volume needs a number of 1000 or more that nobody has (what is refused is named on the console and left out); an account of the image that the volume lacks comes back with the image's locked line of `/etc/shadow`, and a group of the image that the volume lacks (when the volume has a group file) comes back with no members, so a deleted account returns locked and a `wheel` an operator emptied does not return with `user`; an entry with number 0 under a name but `root` never comes in; a line with the wrong number of fields, a name outside `[a-z_][a-z0-9_-]*` or a control character is dropped; an empty hash is a lock. A volume carried to another instance takes its accounts with it.

What the merge does not keep, so that an operator is not surprised after a reboot: an account or group made with `adduser -S` or `addgroup -S` (numbers 100 to 999, which belong to the image), and a name outside `[a-z_][a-z0-9_-]*` that BusyBox accepted (a capital letter, a dot): both vanish at the next boot, with a console line from `datakey`. Make an ordinary account with `adduser NAME` or `adduser -h /data/home/NAME NAME` and a lower-case name. The volume's `/etc` must belong to root with mode 0700 (and `/home` to root, with no write right for the group or others), or `datakey` neither reads nor writes the account files there and says so. A set of account files that cannot be read, or has a file above 4 096 bytes, is not saved, and the console says so once.

The package manager works from the boot script and the console only; over SSH it reports "no package service": `doas pkg` and `su` start a set-user-ID program, which takes no package session from its caller, and the loader does not yet verify the package slot (a separate task of series 0.7 that blocks the v0.7.0 tag).

Closing `user`: `passwd -l user` locks the password and nothing else, because Dropbear takes the key and ignores `/etc/shadow` for it, and `ec2-key` writes the instance's key again at each boot. Root rights end by taking `user` out of the group `wheel` (`deluser user wheel`; the member list of the volume wins at the next boot). A key login ends only with an instance launched with no key pair (no key is written then); no setting of the account closes it. The console is root's (mode 0600): an ordinary account cannot open `/dev/console`, and the console name of the shell's BusyBox (`ash-getty`) ends for it with status 126.

The permanent `datakey` costs one process and about 190 KiB (its stack of 128 KiB and 60 KiB of static buffers). Measured in the second boot of `cargo xtask users persist` (2 GiB machine, the image of the try-out, `datakey` running with the volume mounted): `init: free pages 193424 of 515711`, `MemFree 436744 kB` and 15 processes in `/proc`. The 190 KiB are 48 pages of the 193,424 free. The count of 15 processes is the whole table in use after the boot; the capacity of the table was not measured here.

The home of `user` is `/data/home/user` with a volume (made by `datakey`, owner 1000:100, mode 0700) and `/home/user` in memory without one (`ec2-key` makes it, empty, at each boot and says so). A home of another account lives on the volume only when it is made there: `adduser -h /data/home/NAME NAME` (BusyBox has no default home to change). `adduser NAME` alone makes `/home/NAME` in memory, which a reboot loses. `cargo xtask users persist` boots the image of the try-out twice over one volume and checks that the note in the home, the added account, the hashes of root and the new account, and the host key come back.

## Where to look next

`docs/posix-coverage.md` lists each departure, `tests/open-posix/data-pass.txt` and `data-expected-not-pass.txt` list the Open POSIX tests that pass on the volume and those that do not by design, and `cargo xtask data-posix`, `open-posix --data`, `data-save` and `vi-dialog` are the probes.
