# Rust POSIX file client

`lib/posix-fs` is a GPL-3.0-or-later, `no_std` client for the first Rust
POSIX file operations. It owns a working directory, resolves relative
paths through `posix-path`, maps file-service failures to `FsError`, and
provides `open`, `close`, `read`, `write`, `seek_set`, `fstat`, `stat`,
`chdir`, `opendir`, and `readdir`. A later seek milestone adds signed
64-bit `lseek` with all five POSIX.1-2024 origins. The RAM service's `LOOKUP` request
returns a node kind and current size without opening the file. Directory
iteration keeps its cursor in the client; `Directory::rewind` resets it.

`cargo xtask ramfs` boots a GPL-licensed probe that checks metadata,
relative access after `chdir`, directory entries and end-of-directory,
and errors for missing paths, regular files used as directories, and a
trailing slash on a regular file. `cargo xtask ci` checks the guest build
with Clippy and verifies the license boundary.

This API is an incremental POSIX layer. The file protocol still accepts
UTF-8 paths, file metadata contains only kind and size, metadata sizes are
32-bit, and directory descriptors cannot be opened as file descriptors.
Path components are currently normalized lexically because the RAM service
has no symbolic links. The namespace service must resolve each component
and enforce directory search permissions before this can meet full POSIX
pathname semantics. BusyBox continues to use its MIT bridge and does not
link this GPL package.
