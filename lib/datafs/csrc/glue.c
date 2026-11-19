// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

// The flat interface of littlefs the Rust side calls: one volume in one block of memory the
// caller owns, every buffer inside it (littlefs never allocates here), files and directories as
// slot numbers. The device is behind five functions of the Rust side (datafs_rs_*).
#include <stddef.h>
#include <stdint.h>

#include "lfs.h"

// The label of a cache that holds no block (littlefs's own LFS_BLOCK_NULL, which lfs.c keeps private).
#define NO_BLOCK ((lfs_block_t)-1)
#define BLOCK 4096u
#define SECTOR 512u
// The allocator's window holds one bit for every block of the volume, up to this many bytes (the
// whole of a 4 GiB volume). With a window of the volume's size the allocator walks the file system
// once for all the free space; a smaller window made it walk again after every 8 * size blocks,
// dozens of times inside one call of the service on a volume half full.
#define LOOKAHEAD_MAX (128u * 1024u)

#ifndef DATAFS_FILES
#define DATAFS_FILES 8
#endif
#ifndef DATAFS_DIRS
#define DATAFS_DIRS 4
#endif

int datafs_rs_read(void *ctx, uint32_t block, uint32_t off, void *buffer, uint32_t size);
int datafs_rs_prog(void *ctx, uint32_t block, uint32_t off, const void *buffer, uint32_t size);
int datafs_rs_sync(void *ctx);

struct datafs {
    lfs_t lfs;
    struct lfs_config cfg;
    void *ctx;
    uint8_t read_cache[BLOCK];
    uint8_t prog_cache[BLOCK];
    uint8_t lookahead[LOOKAHEAD_MAX];
    lfs_file_t file[DATAFS_FILES];
    struct lfs_file_config file_cfg[DATAFS_FILES];
    uint8_t file_cache[DATAFS_FILES][BLOCK];
    uint8_t file_used[DATAFS_FILES];
    struct lfs_attr file_attr[DATAFS_FILES];
    uint8_t file_attr_data[DATAFS_FILES][64];
    uint32_t erases;
    lfs_dir_t dir[DATAFS_DIRS];
    uint8_t dir_used[DATAFS_DIRS];
};

size_t datafs_state_size(void) { return sizeof(struct datafs); }
size_t datafs_state_align(void) { return _Alignof(struct datafs); }
int datafs_files(void) { return DATAFS_FILES; }
int datafs_dirs(void) { return DATAFS_DIRS; }

// littlefs labels a read cache with the block, offset and size of a read before it calls the
// device, and keeps the label when the read fails, so the next read of that block would take the
// stale bytes of the cache for the block. When a read fails, the caches that carry its block lose
// the label: the cache of the volume, and the cache of an open file that is reading (a file that is
// writing keeps its cache: that holds data waiting to be written). Every entry point of this file that
// reads goes through here, so a failed read (a device that failed, a walk stopped on purpose, a
// stop notice) leaves a state that can be used on.
static void forget_failed_read(struct datafs *d, lfs_block_t block)
{
    if (d->lfs.rcache.block == block) {
        d->lfs.rcache.block = NO_BLOCK;
    }
    for (int i = 0; i < DATAFS_FILES; i++) {
        if (d->file_used[i] && (d->file[i].flags & LFS_F_READING) &&
            d->file[i].cache.block == block) {
            d->file[i].cache.block = NO_BLOCK;
        }
    }
}

static int dev_read(const struct lfs_config *c, lfs_block_t block, lfs_off_t off, void *buffer,
                    lfs_size_t size)
{
    struct datafs *d = c->context;
    int err = datafs_rs_read(d->ctx, block, off, buffer, size);
    if (err) {
        forget_failed_read(d, block);
    }
    return err;
}

static int dev_prog(const struct lfs_config *c, lfs_block_t block, lfs_off_t off,
                    const void *buffer, lfs_size_t size)
{
    struct datafs *d = c->context;
    return datafs_rs_prog(d->ctx, block, off, buffer, size);
}

// The blocks need no erase: the device overwrites in place.
// The count is what the host measurements read: how many erases littlefs asks for.
static int dev_erase(const struct lfs_config *c, lfs_block_t block)
{
    struct datafs *d = c->context;
    (void)block;
    d->erases++;
    return 0;
}

static int dev_sync(const struct lfs_config *c)
{
    struct datafs *d = c->context;
    return datafs_rs_sync(d->ctx);
}

// Sets the volume up over a device of `blocks` blocks of 4 KiB. Nothing is read.
void datafs_setup(struct datafs *d, uint32_t blocks)
{
    uint8_t *bytes = (uint8_t *)d;
    for (size_t i = 0; i < sizeof(*d); i++) {
        bytes[i] = 0;
    }
    d->cfg.context = d;
    d->cfg.read = dev_read;
    d->cfg.prog = dev_prog;
    d->cfg.erase = dev_erase;
    d->cfg.sync = dev_sync;
    d->cfg.read_size = SECTOR;
    d->cfg.prog_size = SECTOR;
    d->cfg.block_size = BLOCK;
    d->cfg.block_count = blocks;
    // A virtual disk wears no block out: no relocation by erase count.
    d->cfg.block_cycles = -1;
    d->cfg.cache_size = BLOCK;
    // One bit for each block, a multiple of 8 bytes, at least 8 and at most LOOKAHEAD_MAX.
    uint32_t window = ((blocks + 63u) / 64u) * 8u;
    if (window < 8u) {
        window = 8u;
    }
    if (window > LOOKAHEAD_MAX) {
        window = LOOKAHEAD_MAX;
    }
    d->cfg.lookahead_size = window;
    // lfs_fs_gc must not compact metadata: the walk of the allocator is all it is asked for.
    d->cfg.compact_thresh = (lfs_size_t)-1;
    d->cfg.read_buffer = d->read_cache;
    d->cfg.prog_buffer = d->prog_cache;
    d->cfg.lookahead_buffer = d->lookahead;
    for (int i = 0; i < DATAFS_FILES; i++) {
        d->file_cfg[i].buffer = d->file_cache[i];
    }
}

// The host measurements only: the allocator's window over a buffer the caller owns (`size` bytes,
// a multiple of 8), set between `datafs_setup` and the next format or mount. The service never
// calls this.
void datafs_set_lookahead(struct datafs *d, uint8_t *buffer, uint32_t size)
{
    d->cfg.lookahead_size = size;
    d->cfg.lookahead_buffer = buffer;
}

// The size of the window the volume was set up with, in blocks.
uint32_t datafs_window_blocks(const struct datafs *d) { return d->cfg.lookahead_size * 8u; }

// The erases littlefs has asked for since the setup.
uint32_t datafs_erases(const struct datafs *d) { return d->erases; }

// The first block, the next block to hand out and the size in blocks of the allocator's window.
// The next block goes back to 0 at each walk of the volume.
void datafs_window_state(const struct datafs *d, uint32_t *out)
{
    out[0] = d->lfs.lookahead.start;
    out[1] = d->lfs.lookahead.next;
    out[2] = d->lfs.lookahead.size;
}

// The blocks of the window that are free and still to be handed out (the zero bits from `next` to the
// end of the window), read from memory with no device access. With a window as large as the volume
// that is the free count of the volume as of the last walk, less what has been given out since.
int64_t datafs_window_free(const struct datafs *d)
{
    int64_t free_blocks = 0;
    for (lfs_block_t i = d->lfs.lookahead.next; i < d->lfs.lookahead.size; i++) {
        if (!(d->lfs.lookahead.buffer[i / 8] & (1U << (i % 8)))) {
            free_blocks++;
        }
    }
    return free_blocks;
}

// Walks the file system once and fills the allocator's window from it, at a point where no
// operation is half done (littlefs counts the blocks of the open files in the walk, so a file that
// is written and awaits its sync keeps its blocks). The window is dropped first, so the walk is made
// whether or not the window was full. lfs_fs_gc compacts no metadata here (`compact_thresh` is
// off), so the walk only reads.
int datafs_walk(struct datafs *d, void *ctx)
{
    d->ctx = ctx;
    d->lfs.lookahead.size = 0;
    d->lfs.lookahead.next = 0;
    d->lfs.lookahead.ckpoint = d->lfs.block_count;
    int err = lfs_fs_gc(&d->lfs);
    if (err) {
        // A walk that failed (or was stopped) leaves the window empty (littlefs drops it) and
        // no cache labelled with a block it did not load.
        d->lfs.rcache.block = NO_BLOCK;
    }
    return err;
}

int datafs_format(struct datafs *d, void *ctx)
{
    d->ctx = ctx;
    return lfs_format(&d->lfs, &d->cfg);
}

// Mounts and finishes what a cut of the power left half done (a rename between two directories
// that was committed in the first and not yet in the second, a directory made and not linked):
// until that is done a listing of a directory with a pending move skips an entry after the moved
// one. The writes of the repair are the ones of the next operation, made now.
int datafs_mount(struct datafs *d, void *ctx)
{
    d->ctx = ctx;
    int err = lfs_mount(&d->lfs, &d->cfg);
    if (err < 0) {
        return err;
    }
#ifdef DATAFS_BREAK_CONSISTENT
    err = 0;
#else
    err = lfs_fs_mkconsistent(&d->lfs);
#endif
    if (err < 0) {
        lfs_unmount(&d->lfs);
    }
    return err;
}

int datafs_unmount(struct datafs *d, void *ctx)
{
    d->ctx = ctx;
    return lfs_unmount(&d->lfs);
}

// The blocks in use, or a negative error.
int64_t datafs_used(struct datafs *d, void *ctx)
{
    d->ctx = ctx;
    return lfs_fs_size(&d->lfs);
}

// A file: the slot, or a negative error (LFS_ERR_NOMEM when every slot is open).
int datafs_open(struct datafs *d, void *ctx, const char *path, int flags)
{
    d->ctx = ctx;
    for (int i = 0; i < DATAFS_FILES; i++) {
        if (!d->file_used[i]) {
            int err = lfs_file_opencfg(&d->lfs, &d->file[i], path, flags, &d->file_cfg[i]);
            if (err < 0) {
                return err;
            }
            d->file_used[i] = 1;
            return i;
        }
    }
    return LFS_ERR_NOMEM;
}

// The host measurements only: a file opened with one user attribute in its configuration, which
// littlefs writes when the file is synced.
int datafs_open_attr(struct datafs *d, void *ctx, const char *path, int flags, uint8_t type,
                     const void *buffer, uint32_t size)
{
    d->ctx = ctx;
    if (size > sizeof(d->file_attr_data[0])) {
        return LFS_ERR_INVAL;
    }
    for (int i = 0; i < DATAFS_FILES; i++) {
        if (!d->file_used[i]) {
            for (uint32_t j = 0; j < size; j++) {
                d->file_attr_data[i][j] = ((const uint8_t *)buffer)[j];
            }
            d->file_attr[i].type = type;
            d->file_attr[i].buffer = d->file_attr_data[i];
            d->file_attr[i].size = size;
            d->file_cfg[i].attrs = &d->file_attr[i];
            d->file_cfg[i].attr_count = 1;
            int err = lfs_file_opencfg(&d->lfs, &d->file[i], path, flags, &d->file_cfg[i]);
            if (err < 0) {
                d->file_cfg[i].attrs = NULL;
                d->file_cfg[i].attr_count = 0;
                return err;
            }
            d->file_used[i] = 1;
            return i;
        }
    }
    return LFS_ERR_NOMEM;
}

static int file_ok(struct datafs *d, int slot)
{
    return slot >= 0 && slot < DATAFS_FILES && d->file_used[slot];
}

int datafs_close(struct datafs *d, void *ctx, int slot)
{
    d->ctx = ctx;
    if (!file_ok(d, slot)) {
        return LFS_ERR_BADF;
    }
    d->file_used[slot] = 0;
    int err = lfs_file_close(&d->lfs, &d->file[slot]);
    d->file_cfg[slot].attrs = NULL;
    d->file_cfg[slot].attr_count = 0;
    return err;
}

int64_t datafs_read(struct datafs *d, void *ctx, int slot, void *buffer, uint32_t size)
{
    d->ctx = ctx;
    if (!file_ok(d, slot)) {
        return LFS_ERR_BADF;
    }
    return lfs_file_read(&d->lfs, &d->file[slot], buffer, size);
}

int64_t datafs_write(struct datafs *d, void *ctx, int slot, const void *buffer, uint32_t size)
{
    d->ctx = ctx;
    if (!file_ok(d, slot)) {
        return LFS_ERR_BADF;
    }
    return lfs_file_write(&d->lfs, &d->file[slot], buffer, size);
}

int datafs_sync(struct datafs *d, void *ctx, int slot)
{
    d->ctx = ctx;
    if (!file_ok(d, slot)) {
        return LFS_ERR_BADF;
    }
    return lfs_file_sync(&d->lfs, &d->file[slot]);
}

int64_t datafs_seek(struct datafs *d, void *ctx, int slot, int32_t offset, int whence)
{
    d->ctx = ctx;
    if (!file_ok(d, slot)) {
        return LFS_ERR_BADF;
    }
    return lfs_file_seek(&d->lfs, &d->file[slot], offset, whence);
}

int datafs_truncate(struct datafs *d, void *ctx, int slot, uint32_t size)
{
    d->ctx = ctx;
    if (!file_ok(d, slot)) {
        return LFS_ERR_BADF;
    }
    return lfs_file_truncate(&d->lfs, &d->file[slot], size);
}

int64_t datafs_size(struct datafs *d, void *ctx, int slot)
{
    d->ctx = ctx;
    if (!file_ok(d, slot)) {
        return LFS_ERR_BADF;
    }
    return lfs_file_size(&d->lfs, &d->file[slot]);
}

int datafs_mkdir(struct datafs *d, void *ctx, const char *path)
{
    d->ctx = ctx;
    return lfs_mkdir(&d->lfs, path);
}

int datafs_remove(struct datafs *d, void *ctx, const char *path)
{
    d->ctx = ctx;
    return lfs_remove(&d->lfs, path);
}

int datafs_rename(struct datafs *d, void *ctx, const char *from, const char *to)
{
    d->ctx = ctx;
    return lfs_rename(&d->lfs, from, to);
}

// The type (1 file, 2 directory), the size and the name (256 bytes) of `path`.
int datafs_stat(struct datafs *d, void *ctx, const char *path, uint8_t *type, uint32_t *size,
                char *name)
{
    struct lfs_info info;
    d->ctx = ctx;
    int err = lfs_stat(&d->lfs, path, &info);
    if (err < 0) {
        return err;
    }
    *type = info.type;
    *size = info.size;
    for (size_t i = 0; i <= LFS_NAME_MAX; i++) {
        name[i] = info.name[i];
    }
    return 0;
}

int datafs_opendir(struct datafs *d, void *ctx, const char *path)
{
    d->ctx = ctx;
    for (int i = 0; i < DATAFS_DIRS; i++) {
        if (!d->dir_used[i]) {
            int err = lfs_dir_open(&d->lfs, &d->dir[i], path);
            if (err < 0) {
                return err;
            }
            d->dir_used[i] = 1;
            return i;
        }
    }
    return LFS_ERR_NOMEM;
}

static int dir_ok(struct datafs *d, int slot)
{
    return slot >= 0 && slot < DATAFS_DIRS && d->dir_used[slot];
}

int datafs_closedir(struct datafs *d, void *ctx, int slot)
{
    d->ctx = ctx;
    if (!dir_ok(d, slot)) {
        return LFS_ERR_BADF;
    }
    d->dir_used[slot] = 0;
    return lfs_dir_close(&d->lfs, &d->dir[slot]);
}

// The next entry of a directory: 1 with the entry in the outputs, 0 at the end.
int datafs_readdir(struct datafs *d, void *ctx, int slot, uint8_t *type, uint32_t *size,
                   char *name)
{
    struct lfs_info info;
    d->ctx = ctx;
    if (!dir_ok(d, slot)) {
        return LFS_ERR_BADF;
    }
    int res = lfs_dir_read(&d->lfs, &d->dir[slot], &info);
    if (res > 0) {
        *type = info.type;
        *size = info.size;
        for (size_t i = 0; i <= LFS_NAME_MAX; i++) {
            name[i] = info.name[i];
        }
    }
    return res;
}

int datafs_rewinddir(struct datafs *d, void *ctx, int slot)
{
    d->ctx = ctx;
    if (!dir_ok(d, slot)) {
        return LFS_ERR_BADF;
    }
    return lfs_dir_rewind(&d->lfs, &d->dir[slot]);
}

// The user attribute `type` of the file or directory at `path` (the root is "/"): its size and the
// bytes (at most `size`), or a negative error (LFS_ERR_NOATTR when there is none).
int datafs_getattr(struct datafs *d, void *ctx, const char *path, uint8_t type, void *buffer,
                   uint32_t size)
{
    d->ctx = ctx;
    return lfs_getattr(&d->lfs, path, type, buffer, size);
}

// Sets the attribute in one commit of the directory that holds the entry.
int datafs_setattr(struct datafs *d, void *ctx, const char *path, uint8_t type, const void *buffer,
                   uint32_t size)
{
    d->ctx = ctx;
    return lfs_setattr(&d->lfs, path, type, buffer, size);
}

int datafs_removeattr(struct datafs *d, void *ctx, const char *path, uint8_t type)
{
    d->ctx = ctx;
    return lfs_removeattr(&d->lfs, path, type);
}

// The entries of a directory with the attribute `attr` of each, and the status of a path with its
// attribute, from the two functions of the change to littlefs (third-party/littlefs/STAFETO-CHANGES.md).

// As datafs_readdir, and for an entry the user attribute `attr` of the entry: its size in
// *attr_res (LFS_ERR_NOATTR when there is none, always for "." and ".."), the bytes in `buffer`
// (at most `bufsize`).
int datafs_readdir_attr(struct datafs *d, void *ctx, int slot, uint8_t *type, uint32_t *size,
                        char *name, uint8_t attr, void *buffer, uint32_t bufsize,
                        int32_t *attr_res)
{
    struct lfs_info info;
    lfs_ssize_t found = LFS_ERR_NOATTR;
    d->ctx = ctx;
    if (!dir_ok(d, slot)) {
        return LFS_ERR_BADF;
    }
    int res = lfs_dir_read_attr(&d->lfs, &d->dir[slot], &info, attr, buffer, bufsize, &found);
    if (res > 0) {
        *type = info.type;
        *size = info.size;
        for (size_t i = 0; i <= LFS_NAME_MAX; i++) {
            name[i] = info.name[i];
        }
        *attr_res = (int32_t)found;
    }
    return res;
}

// As datafs_stat, and the user attribute `attr` of the entry as datafs_readdir_attr gives it.
int datafs_stat_attr(struct datafs *d, void *ctx, const char *path, uint8_t *type, uint32_t *size,
                     char *name, uint8_t attr, void *buffer, uint32_t bufsize, int32_t *attr_res)
{
    struct lfs_info info;
    lfs_ssize_t found = LFS_ERR_NOATTR;
    d->ctx = ctx;
    int err = lfs_stat_attr(&d->lfs, path, &info, attr, buffer, bufsize, &found);
    if (err < 0) {
        return err;
    }
    *type = info.type;
    *size = info.size;
    for (size_t i = 0; i <= LFS_NAME_MAX; i++) {
        name[i] = info.name[i];
    }
    *attr_res = (int32_t)found;
    return 0;
}
