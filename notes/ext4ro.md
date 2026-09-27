# Read-only ext4 probe

`lib/ext4ro` adapts `ext4-view` 1.0.0 to a bounded byte reader. The only
operation exposed to the storage source is `read_exact_at`; a request beyond
the device length fails before reaching the source. This interface is ready
for a block-device service client.

`lib/ext4ro/tests/ext4.img` was made with e2fsprogs 1.47.4. Run
`sh lib/ext4ro/tests/make-image.sh` to regenerate it; set
`E2FSPROGS_BIN_DIR` if `mke2fs` and `e2fsck` are elsewhere. The script adds
a file and a symbolic link, then checks the filesystem with `e2fsck -fn`.
Host tests read both paths and reject a truncated device. The crate also
builds for `aarch64-unknown-none` without `std`.

`cargo xtask ext4ro` boots `tests/ext4ro` as a temporary init in QEMU. It
embeds the same image, mounts it, reads through the link, and exits with
code 0 only when the bytes match. The kernel then prints its expected
"init exited with code 0" panic and powers off. `cargo xtask test` includes
this probe. The probe's fixed bump heap is limited to this test program;
the filesystem service will need a reusable allocator.

The next integration step is to replace the embedded image with a Virtio
block client and keep `lib/ext4ro`'s read-only adapter. A file-service
protocol and mount namespace will then make the files available to other
processes.
