// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

// The flat interface of littlefs the Rust side calls: one volume in one block of memory the
// caller owns, every buffer inside it (littlefs never allocates here), files and directories as
// slot numbers. The device is behind five functions of the Rust side (datafs_rs_*).
#include <stddef.h>
#include <stdint.h>
#include <string.h>

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

// The table of the repair of orphans after a power loss (lfs_config.orphan_buffer): a cell of 12
// bytes holds one block that a directory entry names. A directory has two blocks and its entry is
// in the log of its parent's pair, where the entries that a later commit replaced count too, so
// the cells are 4 times the 1,024 directories of the plan (`proto_data::DIRS_MAX`) and the table
// is used up to three quarters: 4,096 cells, 48 KiB, 3,072 blocks. A volume with more blocks than
// that is repaired for the keys that did not fit with the walk of the release.
#define ORPHAN_CELLS 4096u

// The wayposts each open file keeps for finding the blocks of a read (lfs_config.ctz_hints, at most
// LFS_CTZ_HINTS_MAX). The disk is the same with any number, 0 included.
#define CTZ_HINTS 16u

// The cache of metadata blocks (the device's read function below): 128 sets of 4 ways, 512 blocks of
// 4 KiB (2 MiB), the least recently used way of a set goes first. A path walked from the root again
// and again reads the same pairs, so the blocks of the directories on the paths in use are what the
// cache holds: the 246 directories of the chain of the scale volume are 492 blocks, with `/` and
// `/.layers` just under the 512. The limit is the working set: past 512 blocks of the paths in use
// the walks read about one walk of pairs from the device for each directory (about 90,000 reads for
// the build of the scale volume).
#define MCACHE_SETS 128u
#define MCACHE_WAYS 4u
#define MCACHE_BLOCKS (MCACHE_SETS * MCACHE_WAYS)

#ifndef DATAFS_FILES
#define DATAFS_FILES 24
#endif
#ifndef DATAFS_DIRS
#define DATAFS_DIRS 16
#endif

int datafs_rs_read(void *ctx, uint32_t block, uint32_t off, void *buffer, uint32_t size);
int datafs_rs_prog(void *ctx, uint32_t block, uint32_t off, const void *buffer, uint32_t size);
int datafs_rs_sync(void *ctx);
int datafs_rs_check(void *ctx);

struct datafs {
    lfs_t lfs;
    struct lfs_config cfg;
    void *ctx;
    uint8_t read_cache[BLOCK];
    uint8_t prog_cache[BLOCK];
    uint8_t lookahead[LOOKAHEAD_MAX];
    uint32_t orphans[ORPHAN_CELLS * 3u];
    lfs_file_t file[DATAFS_FILES];
    struct lfs_file_config file_cfg[DATAFS_FILES];
    uint8_t file_cache[DATAFS_FILES][BLOCK];
    uint8_t file_used[DATAFS_FILES];
    struct lfs_attr file_attr[DATAFS_FILES];
    uint8_t file_attr_data[DATAFS_FILES][64];
    uint32_t erases;
    lfs_dir_t dir[DATAFS_DIRS];
    uint8_t dir_used[DATAFS_DIRS];
    // The cache of metadata blocks: the block each slot holds, the time of its last use (0 for an
    // empty slot), the clock, the hits and misses so far, whether the cache is on, and the blocks.
    uint32_t mc_block[MCACHE_BLOCKS];
    uint32_t mc_stamp[MCACHE_BLOCKS];
    uint32_t mc_clock;
    uint32_t mc_hits;
    uint32_t mc_misses;
    uint32_t mc_off;
    // Set while datafs_walk runs: a read the cache answers asks the device for its stop points.
    uint32_t walking;
    uint8_t mc_data[MCACHE_BLOCKS][BLOCK];
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

// The cache of metadata blocks. littlefs reads a pair of metadata blocks again for each step of
// each path, and a block of a directory's pair is read from the device in 4 KiB each time with no
// other cache than the one block of `rcache`. A block that a read for metadata loaded (lfs_t's
// `data_read` clear) is kept here, whole. It is written through: the device's program function
// writes the device first and then the same bytes into the copy, the erase function drops the copy,
// and a program that fails drops it, so that what the cache holds is always what the device holds
// (the order of the writes to the device, and with it what a power cut leaves, is the one of a
// volume with no cache). The memory is lost with the service, so a restart after a cut reads the
// device.
static uint32_t mc_first(lfs_block_t block)
{
    // The top 7 bits of the product are the set: 128 sets.
    return (((uint32_t)block * 2654435761u) >> 25) * MCACHE_WAYS;
}

// The slot that holds `block`, or -1.
static int mc_find(const struct datafs *d, lfs_block_t block)
{
    uint32_t first = mc_first(block);
    for (uint32_t w = 0; w < MCACHE_WAYS; w++) {
        uint32_t i = first + w;
        if (d->mc_stamp[i] != 0 && d->mc_block[i] == block) {
            return (int)i;
        }
    }
    return -1;
}

static void mc_touch(struct datafs *d, uint32_t slot)
{
    d->mc_clock++;
    if (d->mc_clock == 0) {
        d->mc_clock = 1;
    }
    d->mc_stamp[slot] = d->mc_clock;
}

// Keeps the block, in an empty slot of its set or in the one used least recently.
static void mc_insert(struct datafs *d, lfs_block_t block, const void *bytes)
{
    uint32_t first = mc_first(block);
    uint32_t slot = first;
    uint32_t oldest = 0;
    for (uint32_t w = 0; w < MCACHE_WAYS; w++) {
        uint32_t i = first + w;
        uint32_t age = d->mc_stamp[i] == 0 ? 0xffffffffu : d->mc_clock - d->mc_stamp[i];
        if (age >= oldest) {
            oldest = age;
            slot = i;
        }
    }
    d->mc_block[slot] = block;
    memcpy(d->mc_data[slot], bytes, BLOCK);
    mc_touch(d, slot);
}

static void mc_drop(struct datafs *d, lfs_block_t block)
{
    int slot = mc_find(d, block);
    if (slot >= 0) {
        d->mc_stamp[slot] = 0;
    }
}

static void mc_clear(struct datafs *d)
{
    for (uint32_t i = 0; i < MCACHE_BLOCKS; i++) {
        d->mc_stamp[i] = 0;
    }
}

static int dev_read(const struct lfs_config *c, lfs_block_t block, lfs_off_t off, void *buffer,
                    lfs_size_t size)
{
    struct datafs *d = c->context;
    int cached = !d->mc_off && !d->lfs.data_read;
    if (cached) {
        int slot = mc_find(d, block);
        if (slot >= 0 && off + size <= BLOCK) {
            if (d->walking) {
                int stop = datafs_rs_check(d->ctx);
                if (stop) {
                    forget_failed_read(d, block);
                    return stop;
                }
            }
            memcpy(buffer, d->mc_data[slot] + off, size);
            mc_touch(d, (uint32_t)slot);
            d->mc_hits++;
            return 0;
        }
    }
    int err = datafs_rs_read(d->ctx, block, off, buffer, size);
    if (err) {
        forget_failed_read(d, block);
    } else if (cached && off == 0 && size == BLOCK) {
        d->mc_misses++;
        mc_insert(d, block, buffer);
    }
    return err;
}

static int dev_prog(const struct lfs_config *c, lfs_block_t block, lfs_off_t off,
                    const void *buffer, lfs_size_t size)
{
    struct datafs *d = c->context;
    int err = datafs_rs_prog(d->ctx, block, off, buffer, size);
#ifndef DATAFS_BREAK_CACHE_STALE
    int slot = mc_find(d, block);
    if (slot >= 0) {
        if (err || off + size > BLOCK) {
            d->mc_stamp[slot] = 0;
        } else {
            memcpy(d->mc_data[slot] + off, buffer, size);
        }
    }
#endif
    return err;
}

// The blocks need no erase: the device overwrites in place.
// The count is what the host measurements read: how many erases littlefs asks for.
static int dev_erase(const struct lfs_config *c, lfs_block_t block)
{
    struct datafs *d = c->context;
    d->erases++;
#ifndef DATAFS_BREAK_CACHE_STALE
    mc_drop(d, block);
#endif
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
    // All but the blocks of the cache: a slot's stamp says whether its block is there (and the blocks
    // are 2 MiB, which a clear would touch page by page).
    memset(d, 0, offsetof(struct datafs, mc_data));
    d->cfg.context = d;
    d->cfg.read = dev_read;
    d->cfg.prog = dev_prog;
    d->cfg.erase = dev_erase;
    d->cfg.sync = dev_sync;
    // A read of a block is one request of the device (8 sectors in one cell of the disk service).
    // With a read size of one sector, a metadata get that walks back through the log of a pair
    // reads once for each sector it crosses: up to 24 reads for each entry of a directory listing.
    d->cfg.read_size = BLOCK;
    d->cfg.prog_size = SECTOR;
    d->cfg.block_size = BLOCK;
    d->cfg.block_count = blocks;
    // A virtual disk wears no block out: no relocation by erase count.
    d->cfg.block_cycles = -1;
    d->cfg.cache_size = BLOCK;
    // No data inside a pair of metadata: a file of any size has a block of its own. A file of up to
    // 500 bytes or so lived in the pair of its directory, which made a directory of 1,024 small
    // files 513 pairs and a removal in it walk the list of pairs. A volume of an older release (or
    // of a build with inline data on) that has such a file reads it as before, but a write at its
    // start or in its middle is lost with LFS_ERR_CORRUPT: only an append, O_TRUNC or a truncation
    // moves it out safely. The mount work therefore moves every inline file out (`datafs_outline`)
    // before the first request and marks the volume (the format mark 4).
    d->cfg.inline_max = (lfs_size_t)-1;
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
    d->cfg.orphan_buffer = d->orphans;
    d->cfg.orphan_size = sizeof(d->orphans);
    // The wayposts of an open file for the blocks of a read in order (a file read from start to end
    // costs a few reads of the disk for each block, and about log2(n) without them).
    d->cfg.ctz_hints = CTZ_HINTS;
    // The disk service answers every program with a status, so a program is not read back: the
    // block it wrote stays in the read cache (lfs_config.trust_prog).
    d->cfg.trust_prog = 1;
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

// The host tests only: the table of the repair of orphans on (the service's) or off (the walk of the
// release), set between `datafs_setup` and the next mount.
void datafs_set_orphan_table(struct datafs *d, int on)
{
    d->cfg.orphan_buffer = on ? d->orphans : NULL;
    d->cfg.orphan_size = on ? sizeof(d->orphans) : 0;
}

// The host tests only: wear levelling on (a pair of metadata moves to a new block every `cycles`
// compactions), which makes the half-done relocations the repair of orphans must find.
void datafs_set_block_cycles(struct datafs *d, int32_t cycles)
{
    d->cfg.block_cycles = cycles;
}

// The host tests only: the number of wayposts of an open file, 0 for none (the release's walk of the
// skip list), set between `datafs_setup` and the next mount.
void datafs_set_ctz_hints(struct datafs *d, uint32_t hints)
{
    d->cfg.ctz_hints = hints;
}

// The host tests only: 1 (the service's) leaves a program unread and its block in the read cache, 0
// is the release's read back, set between `datafs_setup` and the next mount.
void datafs_set_trust_prog(struct datafs *d, uint32_t on)
{
    d->cfg.trust_prog = on;
}

// The same with a table of `cells` cells (at most ORPHAN_CELLS), for the tests of a full table.
void datafs_set_orphan_cells(struct datafs *d, uint32_t cells)
{
    if (cells > ORPHAN_CELLS) {
        cells = ORPHAN_CELLS;
    }
    d->cfg.orphan_buffer = cells ? d->orphans : NULL;
    d->cfg.orphan_size = cells * 12u;
}

// The host measurements and tests: the cache of metadata blocks off (0) or on (1), and the hits and
// misses it has counted since the setup (out[0], out[1]).
void datafs_set_cache(struct datafs *d, uint32_t on)
{
    d->mc_off = on ? 0 : 1;
    mc_clear(d);
}

void datafs_cache_stats(const struct datafs *d, uint32_t *out)
{
    out[0] = d->mc_hits;
    out[1] = d->mc_misses;
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
    // A write asks for this count (the room it may take), so it counts a word of 32 bits at a time:
    // a bit at a time cost a loop of a million rounds for a volume of 4 GiB at each part of a write.
    const uint8_t *buffer = d->lfs.lookahead.buffer;
    lfs_block_t i = d->lfs.lookahead.next;
    const lfs_block_t size = d->lfs.lookahead.size;
    int64_t free_blocks = 0;
    while (i < size && (i % 32u) != 0) {
        free_blocks += !(buffer[i / 8] & (1U << (i % 8)));
        i++;
    }
    while (i + 32u <= size) {
        uint32_t word = (uint32_t)buffer[i / 8] | ((uint32_t)buffer[i / 8 + 1] << 8) |
                        ((uint32_t)buffer[i / 8 + 2] << 16) | ((uint32_t)buffer[i / 8 + 3] << 24);
        free_blocks += 32 - (int64_t)lfs_popc(word);
        i += 32u;
    }
    while (i < size) {
        free_blocks += !(buffer[i / 8] & (1U << (i % 8)));
        i++;
    }
    return free_blocks;
}

// Walks the file system once and fills the allocator's window from it, at a point where no
// operation is half done (littlefs counts the blocks of the open files in the walk, so a file that
// is written and awaits its sync keeps its blocks; so does a file whose flush of the tail is half
// done between two steps: the part copied is counted through f->block and f->pos, the old list
// through the directory entry). The window is dropped first, so the walk is made
// whether or not the window was full. lfs_fs_gc compacts no metadata here (`compact_thresh` is
// off), so the walk only reads.
int datafs_walk(struct datafs *d, void *ctx)
{
    d->ctx = ctx;
    d->lfs.lookahead.size = 0;
    d->lfs.lookahead.next = 0;
    d->lfs.lookahead.ckpoint = d->lfs.block_count;
    d->walking = 1;
    int err = lfs_fs_gc(&d->lfs);
    d->walking = 0;
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
    mc_clear(d);
    return lfs_format(&d->lfs, &d->cfg);
}

// Mounts and finishes what a cut of the power left half done (a rename between two directories
// that was committed in the first and not yet in the second, a directory made and not linked):
// until that is done a listing of a directory with a pending move skips an entry after the moved
// one. The writes of the repair are the ones of the next operation, made now.
int datafs_mount(struct datafs *d, void *ctx)
{
    d->ctx = ctx;
    mc_clear(d);
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

// The metadata pairs of the volume (the pairs of the directories, the pairs that large directories
// split into, and the superblock's) and its directories, in out[0] and out[1]: 0, or a negative
// error. One fetch of each pair.
int datafs_pairs(struct datafs *d, void *ctx, uint32_t *out)
{
    d->ctx = ctx;
    lfs_size_t pairs = 0, dirs = 0;
    int err = lfs_fs_pairs(&d->lfs, &pairs, &dirs);
    if (err == 0) {
        out[0] = pairs;
        out[1] = dirs;
    }
    return err;
}

// Whether the file at `path` is inline (its bytes are in the pair of its directory) and not empty,
// and with `dry` zero it is moved out to blocks of its own: 1 for such a file, 0 for any other, or a
// negative error. A write at the start or in the middle of an inline file fails at close with
// LFS_ERR_CORRUPT when inline data is off (littlefs 2.11.3 copies only the bytes before the write
// when it moves the file out), so a volume made with inline data on is made safe first: open the
// file for writing, seek to its end and write no byte, which moves the whole file out in one commit
// (the old file or the moved one is there after a cut). A file already in a block is not touched.
int datafs_outline(struct datafs *d, void *ctx, const char *path, int dry)
{
    d->ctx = ctx;
    int slot = -1;
    for (int i = 0; i < DATAFS_FILES; i++) {
        if (!d->file_used[i]) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        return LFS_ERR_NOMEM;
    }
    int err = lfs_file_opencfg(&d->lfs, &d->file[slot], path, dry ? LFS_O_RDONLY : LFS_O_RDWR,
                               &d->file_cfg[slot]);
    if (err < 0) {
        return err;
    }
    int result = 0;
    if ((d->file[slot].flags & LFS_F_INLINE) && lfs_file_size(&d->lfs, &d->file[slot]) > 0) {
        result = 1;
        if (!dry) {
            lfs_soff_t at = lfs_file_seek(&d->lfs, &d->file[slot], 0, LFS_SEEK_END);
            lfs_ssize_t wrote = at < 0 ? at : lfs_file_write(&d->lfs, &d->file[slot], "", 0);
            if (wrote < 0) {
                result = (int)wrote;
            }
        }
    }
    int closed = lfs_file_close(&d->lfs, &d->file[slot]);
    return result >= 0 && closed < 0 ? closed : result;
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

// Whether the open file in `slot` is inline and not empty (see `datafs_outline`).
int datafs_file_inline(struct datafs *d, void *ctx, int slot)
{
    d->ctx = ctx;
    if (!file_ok(d, slot)) {
        return LFS_ERR_BADF;
    }
    return (d->file[slot].flags & LFS_F_INLINE) && lfs_file_size(&d->lfs, &d->file[slot]) > 0;
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

// The bytes a flush of the file would copy now (0: none), and one step of that copy of at most
// `blocks` blocks: 1 when more is left, 0 when done (see lfs_file_flush_step).
int64_t datafs_tail(struct datafs *d, void *ctx, int slot)
{
    d->ctx = ctx;
    if (!file_ok(d, slot)) {
        return LFS_ERR_BADF;
    }
    return lfs_file_tail(&d->lfs, &d->file[slot]);
}

int datafs_flush_step(struct datafs *d, void *ctx, int slot, uint32_t blocks)
{
    d->ctx = ctx;
    if (!file_ok(d, slot)) {
        return LFS_ERR_BADF;
    }
    return lfs_file_flush_step(&d->lfs, &d->file[slot], blocks);
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
    // lfs_stat leaves the size of a directory and of the root as it was: start from zero.
    memset(&info, 0, sizeof(info));
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

// The directory whose metadata pair is `pair0` and `pair1` (from the `pair` of datafs_path_attrs),
// opened with no walk of its path: the slot, or a negative error.
int datafs_opendir_pair(struct datafs *d, void *ctx, uint32_t pair0, uint32_t pair1)
{
    d->ctx = ctx;
    lfs_block_t pair[2] = {pair0, pair1};
    for (int i = 0; i < DATAFS_DIRS; i++) {
        if (!d->dir_used[i]) {
            int err = lfs_dir_open_pair(&d->lfs, &d->dir[i], pair);
            if (err < 0) {
                return err;
            }
            d->dir_used[i] = 1;
            return i;
        }
    }
    return LFS_ERR_NOMEM;
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

// The position of the iterator of a directory (the entries it has gone past), and a move to such a
// position: the iterator of a read that failed has advanced, and the listing goes back to where it was.
int64_t datafs_tell_dir(struct datafs *d, void *ctx, int slot)
{
    d->ctx = ctx;
    if (!dir_ok(d, slot)) {
        return LFS_ERR_BADF;
    }
    return lfs_dir_tell(&d->lfs, &d->dir[slot]);
}

int datafs_seek_dir(struct datafs *d, void *ctx, int slot, uint32_t off)
{
    d->ctx = ctx;
    if (!dir_ok(d, slot)) {
        return LFS_ERR_BADF;
    }
    return lfs_dir_seek(&d->lfs, &d->dir[slot], off);
}

// Tests: the inline limit of the configuration, for the next mount (0 is littlefs's default, which
// keeps a small file in its directory's pair: the layout of the volumes an older release made).
void datafs_set_inline(struct datafs *d, uint32_t max)
{
    d->cfg.inline_max = max;
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
// attribute, from the functions of the change to littlefs (third-party/littlefs/STAFETO-CHANGES.md).

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
    memset(&info, 0, sizeof(info));
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

// The status of `path` and the user attribute `attr` of the root and of every entry of the path in
// one walk of it (lfs_path_attrs): `out` and `buffer` (`each` bytes for an entry) have room for
// `capacity` entries, and *count says how many are filled, also when the call fails. When the path
// names a directory, `pair` receives the two blocks of its metadata pair, else NO_BLOCK in both.
int datafs_path_attrs(struct datafs *d, void *ctx, const char *path, uint8_t *type, uint32_t *size,
                      char *name, uint8_t attr, struct lfs_path_attr *out, uint8_t *buffer,
                      uint32_t each, uint32_t capacity, uint32_t *count, uint32_t *pair)
{
    struct lfs_info info;
    lfs_size_t filled = 0;
    memset(&info, 0, sizeof(info));
    d->ctx = ctx;
    pair[0] = NO_BLOCK;
    pair[1] = NO_BLOCK;
    int err = lfs_path_attrs(&d->lfs, path, &info, attr, out, buffer, each, capacity, &filled, pair);
    *count = filled;
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
