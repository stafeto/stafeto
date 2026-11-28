/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/*
 * The probe of the POSIX layer on the layered root. Built with -fno-builtin; every result is
 * compared. The image has the layer service, and every path of the root but the pass-through names
 * (/data /proc /dev /tmp /run) is decided by it. The volume is made offline (xtask
 * data_image::LAYER_POSIX_VOLUME_ENTRIES) and the lower set is the boot image (xtask rootfs,
 * boot-layer-posix.img); this file knows both by heart:
 *
 *   lower (the file service)                  the layer of the user (layer 00 of the volume)
 *   /bin/layer-posix, -suid, -gone            bin/.wh.layer-posix-gone, bin/layer-upper-prog
 *   /etc/layer-hidden, /etc/layer-lower       etc/.wh.layer-hidden, layer-note, layer-own (0640
 *                                             1000:1000, number tag|5), layer-secret (0600),
 *                                             layer-world
 *   /lower/{hidden,keep,shadowed}             lower/.wh.hidden, shadowed (other bytes)
 *   /lowdir/{l1,l2}                           lowdir/.wh..wh..opq (opaque), u1
 *   /many/f00 to f19                          many/.wh.f00 to .wh.f15, own
 *   /lowpriv (0700) /f, /plain/{a,b,c}        (no name: the file service lists them)
 *   /private/lower                            private (0700) /f
 *
 * Started by init as a POSIX process of the root (user 0) after the layer service said READY: the
 * launcher role starts /bin/layer-posix with posix_spawn (a loader-started process can fork), and
 * that program (role "run") makes the checks. The first call on a path of the root takes a session
 * from the process service. The roles "child-list", "forged", "setid" and "genuine" are the program
 * started again by spawn and by exec, and the set-ID program.
 *
 * Every check prints "layer-posix: <name> ok" or "layer-posix: <name> FAILED" after the line of the
 * condition that failed, and the next check runs: one boot shows every defect. The end is
 * "layer-posix: checks passed" with no failure.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;
extern int lp_session(void);
extern int stafeto_probe_loader_start(unsigned mode);
extern unsigned stafeto_probe_loader_listen(void);
extern unsigned stafeto_probe_loader_stop(void);

#ifndef LAYER_POSIX_MODE
#define LAYER_POSIX_MODE "run"
#endif

/* st_dev of every name of the layered root (the bytes of "layr"), and the number a file the layer of
 * the user made has (bit 62 and the number the volume gave). */
#define LAYERED_DEVICE 0x6c617972UL
#define DATA_DEVICE 0x64617461UL
#define UPPER_TAG (1ULL << 62)
#define OWN_BYTES "owned bytes of the layer\n"

#define LP_CHECK(cond)                                                                       \
    do {                                                                                     \
        if (!(cond)) {                                                                       \
            printf("layer-posix: check failed at line %d: %s (errno %d)\n", __LINE__, #cond,  \
                   errno);                                                                   \
            return 20;                                                                       \
        }                                                                                    \
    } while (0)

/* The result of a call that must fail with `err`. */
#define FAILS(call, err) (((call) == -1) && errno == (err))
#define FAILS_NULL(call, err) (((call) == NULL) && errno == (err))

static int wait_ok(pid_t pid) {
    int status = 0;
    if (waitpid(pid, &status, 0) != pid) return -1;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return 128 + (WTERMSIG(status) & 0x7f);
}

/* Reads a whole small file: its length, or -1 (errno from the failed call). */
static long read_file(const char *path, char *buf, size_t cap) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    size_t got = 0;
    for (;;) {
        ssize_t r = read(fd, buf + got, cap - 1 - got);
        if (r < 0) {
            int saved = errno;
            close(fd);
            errno = saved;
            return -1;
        }
        if (r == 0) break;
        got += (size_t)r;
        if (got >= cap - 1) break;
    }
    close(fd);
    buf[got] = 0;
    return (long)got;
}

/* Whether the file at `path` has exactly the bytes `want`. */
static int has_bytes(const char *path, const char *want) {
    char buf[256];
    long n = read_file(path, buf, sizeof buf);
    return n == (long)strlen(want) && strcmp(buf, want) == 0;
}

static int fd_has_bytes(int fd, const char *want) {
    char buf[256];
    long got = 0;
    for (;;) {
        ssize_t r = read(fd, buf + got, sizeof buf - 1 - (size_t)got);
        if (r < 0) return 0;
        if (r == 0) break;
        got += r;
    }
    buf[got] = 0;
    return got == (long)strlen(want) && strcmp(buf, want) == 0;
}

/* The names of a directory stream with their d_type. */
#define MAX_NAMES 96
struct names {
    char name[MAX_NAMES][64];
    unsigned char type[MAX_NAMES];
    int count;
};

static int collect(DIR *d, struct names *out) {
    struct dirent *e;
    out->count = 0;
    errno = 0;
    while ((e = readdir(d)) != NULL) {
        if (out->count == MAX_NAMES || strlen(e->d_name) >= sizeof out->name[0]) return -1;
        strcpy(out->name[out->count], e->d_name);
        out->type[out->count] = e->d_type;
        out->count++;
    }
    return errno == 0 ? 0 : -1;
}

/* How many times `name` is in the list. */
static int occurrences(const struct names *l, const char *name) {
    int n = 0;
    for (int i = 0; i < l->count; i++)
        if (strcmp(l->name[i], name) == 0) n++;
    return n;
}

static unsigned char type_of(const struct names *l, const char *name) {
    for (int i = 0; i < l->count; i++)
        if (strcmp(l->name[i], name) == 0) return l->type[i];
    return 0;
}

/* The names a listing of /etc must have: the layer's and the lower set's, each once, without the
 * one the layer deletes. */
static int etc_list_is_right(const struct names *l) {
    return occurrences(l, ".") == 1 && occurrences(l, "..") == 1 && occurrences(l, "layer-note") == 1 &&
           occurrences(l, "layer-own") == 1 && occurrences(l, "layer-secret") == 1 &&
           occurrences(l, "layer-world") == 1 && occurrences(l, "layer-lower") == 1 &&
           occurrences(l, "layer-hidden") == 0;
}

/* ---- the reads of files ---- */

static int upper_file(void) {
    struct stat st, fst;
    int fd = open("/etc/layer-own", O_RDONLY);
    LP_CHECK(fd >= 0);
    LP_CHECK(fstat(fd, &fst) == 0);
    LP_CHECK(fd_has_bytes(fd, OWN_BYTES));
    LP_CHECK(stat("/etc/layer-own", &st) == 0);
    LP_CHECK(S_ISREG(st.st_mode) && (st.st_mode & 07777) == 0640);
    LP_CHECK(st.st_uid == 1000 && st.st_gid == 1000 && st.st_size == (off_t)strlen(OWN_BYTES));
    /* The root is one device, for a stat of the path and for the description it gave. */
    LP_CHECK(st.st_dev == LAYERED_DEVICE && fst.st_dev == LAYERED_DEVICE);
    LP_CHECK(st.st_ino == fst.st_ino && (st.st_ino >> 62) == 1 && (st.st_ino & 0xffff) == 5);
    LP_CHECK(close(fd) == 0);
    LP_CHECK(lstat("/etc/layer-own", &st) == 0 && st.st_dev == LAYERED_DEVICE);
    return 0;
}

static int lower_file(void) {
    struct stat st, fst;
    int fd = open("/etc/layer-lower", O_RDONLY);
    LP_CHECK(fd >= 0);
    LP_CHECK(fstat(fd, &fst) == 0 && stat("/etc/layer-lower", &st) == 0);
    LP_CHECK(fd_has_bytes(fd, "lower of etc\n"));
    LP_CHECK(close(fd) == 0);
    LP_CHECK(S_ISREG(st.st_mode) && (st.st_mode & 07777) == 0644 && st.st_uid == 0);
    /* The same device and the same number from the path and from the description, and the device
     * is the root's one number. */
    LP_CHECK(st.st_dev == LAYERED_DEVICE && fst.st_dev == LAYERED_DEVICE);
    LP_CHECK(st.st_ino == fst.st_ino && (st.st_ino >> 62) == 0);
    LP_CHECK(stat("/bin/layer-posix", &st) == 0 && S_ISREG(st.st_mode) &&
             (st.st_mode & 07777) == 0755 && st.st_dev == LAYERED_DEVICE);
    return 0;
}

static int shadow_and_keep(void) {
    LP_CHECK(has_bytes("/lower/shadowed", "upper shadow\n"));
    LP_CHECK(has_bytes("/lower/keep", "lower keep\n"));
    LP_CHECK(has_bytes("/etc/layer-note", "layer note\n"));
    return 0;
}

static int deleted_names(void) {
    struct stat st;
    LP_CHECK(FAILS(open("/etc/layer-hidden", O_RDONLY), ENOENT));
    LP_CHECK(FAILS(stat("/etc/layer-hidden", &st), ENOENT));
    LP_CHECK(FAILS(lstat("/etc/layer-hidden", &st), ENOENT));
    LP_CHECK(FAILS(access("/etc/layer-hidden", F_OK), ENOENT));
    LP_CHECK(FAILS(open("/lower/hidden", O_RDONLY), ENOENT));
    LP_CHECK(FAILS(open("/lowdir/l1", O_RDONLY), ENOENT));
    char link[32];
    LP_CHECK(FAILS(readlink("/etc/layer-hidden", link, sizeof link), ENOENT));
    LP_CHECK(FAILS(open("/etc/never-was", O_RDONLY), ENOENT));
    return 0;
}

static int stat_of_paths(void) {
    struct stat st;
    LP_CHECK(stat("/etc", &st) == 0 && S_ISDIR(st.st_mode) && st.st_dev == LAYERED_DEVICE);
    LP_CHECK(stat("/etc/", &st) == 0 && S_ISDIR(st.st_mode));
    LP_CHECK(stat("/", &st) == 0 && S_ISDIR(st.st_mode) && st.st_dev == LAYERED_DEVICE);
    LP_CHECK(stat("/plain", &st) == 0 && S_ISDIR(st.st_mode) && st.st_dev == LAYERED_DEVICE);
    LP_CHECK(FAILS(stat("/etc/layer-lower/", &st), ENOTDIR));
    LP_CHECK(FAILS(stat("/etc/layer-own/", &st), ENOTDIR));
    LP_CHECK(FAILS(stat("/etc/layer-own/x", &st), ENOTDIR));
    LP_CHECK(stat("/etc/../etc/./layer-own", &st) == 0 && st.st_uid == 1000);
    /* The names the root passes through keep the devices of their own services. */
    LP_CHECK(stat("/tmp", &st) == 0 && st.st_dev != LAYERED_DEVICE);
    LP_CHECK(stat("/data", &st) == 0 && st.st_dev == DATA_DEVICE);
    LP_CHECK(stat("/dev/null", &st) == 0 && st.st_dev != LAYERED_DEVICE);
    return 0;
}

static int access_and_links(void) {
    char link[32];
    LP_CHECK(access("/etc/layer-own", R_OK) == 0);
    LP_CHECK(access("/etc/layer-lower", R_OK) == 0);
    LP_CHECK(access("/bin/layer-posix", X_OK) == 0);
    /* A file of the layer of the user is no program. */
    LP_CHECK(FAILS(access("/bin/layer-upper-prog", X_OK), EACCES));
    LP_CHECK(access("/etc/layer-own", W_OK) == 0);
    LP_CHECK(FAILS(readlink("/etc/layer-own", link, sizeof link), EINVAL));
    LP_CHECK(FAILS(readlink("/etc/layer-lower", link, sizeof link), EINVAL));
    return 0;
}

/* ---- the listings ---- */

static int merged_listing(void) {
    struct names l;
    DIR *d = opendir("/etc");
    LP_CHECK(d != NULL);
    LP_CHECK(collect(d, &l) == 0);
    LP_CHECK(etc_list_is_right(&l));
    LP_CHECK(type_of(&l, "layer-own") == DT_REG && type_of(&l, "layer-lower") == DT_REG);
    LP_CHECK(type_of(&l, ".") == DT_DIR && type_of(&l, "..") == DT_DIR);
    int total = l.count;
    /* rewinddir starts again; telldir and seekdir go back to an entry. */
    rewinddir(d);
    struct dirent *e;
    LP_CHECK((e = readdir(d)) != NULL);
    LP_CHECK((e = readdir(d)) != NULL);
    char second[64];
    strcpy(second, e->d_name);
    long where = telldir(d);
    LP_CHECK((e = readdir(d)) != NULL);
    char third[64];
    strcpy(third, e->d_name);
    int seen = 3;
    while (readdir(d) != NULL) seen++;
    LP_CHECK(seen == total);
    seekdir(d, where);
    LP_CHECK((e = readdir(d)) != NULL && strcmp(e->d_name, third) == 0);
    LP_CHECK(strcmp(second, third) != 0);
    LP_CHECK(closedir(d) == 0);
    /* The same list from a descriptor, through fdopendir; fstat of the description is the root's. */
    int fd = open("/etc", O_RDONLY | O_DIRECTORY);
    LP_CHECK(fd >= 0);
    struct stat st;
    LP_CHECK(fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) && st.st_dev == LAYERED_DEVICE);
    /* A directory has nothing to make durable, as one of the file service. */
    LP_CHECK(fsync(fd) == 0);
    d = fdopendir(fd);
    LP_CHECK(d != NULL && collect(d, &l) == 0 && etc_list_is_right(&l) && l.count == total);
    LP_CHECK(closedir(d) == 0);
    /* The root, a directory of the layer too. */
    d = opendir("/");
    LP_CHECK(d != NULL && collect(d, &l) == 0);
    LP_CHECK(occurrences(&l, "etc") == 1 && occurrences(&l, "bin") == 1 && occurrences(&l, "plain") == 1);
    LP_CHECK(closedir(d) == 0);
    return 0;
}

static int lower_listing(void) {
    struct names l;
    DIR *d = opendir("/plain");
    LP_CHECK(d != NULL && collect(d, &l) == 0);
    LP_CHECK(occurrences(&l, "a") == 1 && occurrences(&l, "b") == 1 && occurrences(&l, "c") == 1 && l.count == 5);
    LP_CHECK(closedir(d) == 0);
    d = opendir("/lowpriv");
    LP_CHECK(d != NULL && collect(d, &l) == 0 && occurrences(&l, "f") == 1);
    LP_CHECK(closedir(d) == 0);
    LP_CHECK(FAILS_NULL(opendir("/etc/layer-lower"), ENOTDIR));
    LP_CHECK(FAILS_NULL(opendir("/etc/layer-hidden"), ENOENT));
    return 0;
}

/* The listing of /many has no entry in the first replies: the layer hides the first sixteen of the
 * twenty lower files in a row, and the replies that took them say there is more. */
static int listing_over_empty_replies(void) {
    struct names l;
    DIR *d = opendir("/many");
    LP_CHECK(d != NULL && collect(d, &l) == 0);
    LP_CHECK(l.count == 2 + 4 + 1);
    LP_CHECK(occurrences(&l, "own") == 1 && occurrences(&l, "f16") == 1 && occurrences(&l, "f17") == 1 &&
             occurrences(&l, "f18") == 1 && occurrences(&l, "f19") == 1);
    for (int i = 0; i < 16; i++) {
        char name[8];
        snprintf(name, sizeof name, "f%02d", i);
        LP_CHECK(occurrences(&l, name) == 0);
    }
    LP_CHECK(closedir(d) == 0);
    LP_CHECK(has_bytes("/many/f16", "many 16\n"));
    LP_CHECK(FAILS(open("/many/f03", O_RDONLY), ENOENT));
    return 0;
}

static int opaque_directory(void) {
    struct names l;
    DIR *d = opendir("/lowdir");
    LP_CHECK(d != NULL && collect(d, &l) == 0);
    LP_CHECK(occurrences(&l, "u1") == 1 && occurrences(&l, "l1") == 0 && occurrences(&l, "l2") == 0 && l.count == 3);
    LP_CHECK(closedir(d) == 0);
    LP_CHECK(has_bytes("/lowdir/u1", "u1\n"));
    return 0;
}

/* ---- the relative paths and the current directory ---- */

static int paths_against_a_merged_directory(void) {
    struct stat st;
    int d = open("/etc", O_RDONLY | O_DIRECTORY);
    LP_CHECK(d >= 0);
    int fd = openat(d, "layer-own", O_RDONLY);
    LP_CHECK(fd >= 0 && fd_has_bytes(fd, OWN_BYTES));
    close(fd);
    fd = openat(d, "layer-lower", O_RDONLY);
    LP_CHECK(fd >= 0 && fd_has_bytes(fd, "lower of etc\n"));
    close(fd);
    LP_CHECK(FAILS(openat(d, "layer-hidden", O_RDONLY), ENOENT));
    LP_CHECK(fstatat(d, "layer-own", &st, 0) == 0 && st.st_uid == 1000 && st.st_dev == LAYERED_DEVICE);
    LP_CHECK(FAILS(fstatat(d, "layer-hidden", &st, 0), ENOENT));
    LP_CHECK(faccessat(d, "layer-lower", R_OK, 0) == 0);
    LP_CHECK(FAILS(faccessat(d, "layer-hidden", F_OK, 0), ENOENT));
    /* `..` of a description is the root. */
    fd = openat(d, "../lower/keep", O_RDONLY);
    LP_CHECK(fd >= 0 && fd_has_bytes(fd, "lower keep\n"));
    close(fd);
    LP_CHECK(fstatat(d, "..", &st, 0) == 0 && S_ISDIR(st.st_mode));
    close(d);
    return 0;
}

static int paths_against_a_lower_directory(void) {
    struct stat st;
    int d = open("/plain", O_RDONLY | O_DIRECTORY);
    LP_CHECK(d >= 0);
    int fd = openat(d, "a", O_RDONLY);
    LP_CHECK(fd >= 0 && fd_has_bytes(fd, "a\n"));
    LP_CHECK(fstat(fd, &st) == 0 && st.st_dev == LAYERED_DEVICE);
    close(fd);
    LP_CHECK(fstatat(d, "b", &st, 0) == 0 && st.st_dev == LAYERED_DEVICE);
    /* A path that leaves the directory by `..` reaches a name of the layer through the service. */
    fd = openat(d, "../etc/layer-own", O_RDONLY);
    LP_CHECK(fd >= 0 && fd_has_bytes(fd, OWN_BYTES));
    close(fd);
    LP_CHECK(FAILS(openat(d, "../etc/layer-hidden", O_RDONLY), ENOENT));
    LP_CHECK(FAILS(openat(d, "z", O_RDONLY), ENOENT));
    close(d);
    return 0;
}

static int pass_through_names(void) {
    struct stat st, fst;
    LP_CHECK(mkdir("/tmp/lp", 0755) == 0);
    int d = open("/tmp/lp", O_RDONLY | O_DIRECTORY);
    LP_CHECK(d >= 0);
    int fd = openat(d, "f", O_CREAT | O_WRONLY, 0644);
    LP_CHECK(fd >= 0 && write(fd, "tmp bytes\n", 10) == 10 && close(fd) == 0);
    LP_CHECK(has_bytes("/tmp/lp/f", "tmp bytes\n"));
    fd = openat(d, "f", O_RDONLY);
    LP_CHECK(fd >= 0 && fstat(fd, &fst) == 0 && stat("/tmp/lp/f", &st) == 0);
    LP_CHECK(fst.st_dev != LAYERED_DEVICE);
    LP_CHECK(st.st_dev == fst.st_dev);
    LP_CHECK(st.st_ino == fst.st_ino);
    close(fd);
    LP_CHECK(rename("/tmp/lp/f", "/tmp/lp/g") == 0 && has_bytes("/tmp/lp/g", "tmp bytes\n"));
    LP_CHECK(unlink("/tmp/lp/g") == 0 && FAILS(open("/tmp/lp/g", O_RDONLY), ENOENT));
    close(d);
    LP_CHECK(rmdir("/tmp/lp") == 0);
    /* /run is made by the probe, as an image with no such directory has it made. */
    LP_CHECK(mkdir("/run", 0755) == 0 || errno == EEXIST);
    LP_CHECK(mkdir("/run/lp", 0755) == 0 && rmdir("/run/lp") == 0);
    return 0;
}

/* A path against a directory below a pass-through name that leaves it by `..` is the root's. */
static int dotdot_out_of_tmp(void) {
    LP_CHECK(mkdir("/tmp/lq", 0755) == 0);
    int d = open("/tmp/lq", O_RDONLY | O_DIRECTORY);
    LP_CHECK(d >= 0);
    LP_CHECK(FAILS(openat(d, "../../etc/layer-hidden", O_RDONLY), ENOENT));
    int fd = openat(d, "../../etc/layer-own", O_RDONLY);
    LP_CHECK(fd >= 0 && fd_has_bytes(fd, OWN_BYTES));
    close(fd);
    close(d);
    LP_CHECK(rmdir("/tmp/lq") == 0);
    return 0;
}

/* A link below a pass-through name that leads into the root, met by a path against a descriptor of
 * the directory (the file service walks it from the descriptor): the walk is routed through the
 * layer service, so a read sees the merged view and a write to a lower program is refused (a program
 * is never copied up, so the refusal is the layer service's: a plain file would be copied). */
static int link_below_a_pass_through_directory(void) {
    struct stat st;
    LP_CHECK(mkdir("/tmp/ld", 0755) == 0);
    LP_CHECK(symlink("/etc", "/tmp/ld/l") == 0);
    LP_CHECK(symlink("/bin", "/tmp/ld/b") == 0);
    int d = open("/tmp/ld", O_RDONLY | O_DIRECTORY);
    LP_CHECK(d >= 0);
    LP_CHECK(FAILS(openat(d, "l/layer-hidden", O_RDONLY), ENOENT));
    int fd = openat(d, "l/layer-own", O_RDONLY);
    LP_CHECK(fd >= 0 && fd_has_bytes(fd, OWN_BYTES));
    close(fd);
    LP_CHECK(fstatat(d, "l/layer-own", &st, 0) == 0 && st.st_dev == LAYERED_DEVICE);
    LP_CHECK(FAILS(openat(d, "b/layer-posix", O_WRONLY), EROFS));
    LP_CHECK(has_bytes("/etc/layer-lower", "lower of etc\n"));
    close(d);
    LP_CHECK(unlink("/tmp/ld/l") == 0 && unlink("/tmp/ld/b") == 0 && rmdir("/tmp/ld") == 0);
    return 0;
}

static int current_directory(void) {
    char cwd[64];
    LP_CHECK(chdir("/etc") == 0);
    LP_CHECK(getcwd(cwd, sizeof cwd) != NULL && strcmp(cwd, "/etc") == 0);
    LP_CHECK(has_bytes("layer-own", OWN_BYTES) && has_bytes("./layer-lower", "lower of etc\n"));
    LP_CHECK(FAILS(open("layer-hidden", O_RDONLY), ENOENT));
    LP_CHECK(has_bytes("../lower/keep", "lower keep\n"));
    int d = open("/lower", O_RDONLY | O_DIRECTORY);
    LP_CHECK(d >= 0 && fchdir(d) == 0);
    close(d);
    LP_CHECK(getcwd(cwd, sizeof cwd) != NULL && strcmp(cwd, "/lower") == 0);
    LP_CHECK(has_bytes("keep", "lower keep\n") && has_bytes("shadowed", "upper shadow\n"));
    /* A directory of the lower set alone: the file service gives its canonical path. */
    LP_CHECK(chdir("/plain") == 0);
    LP_CHECK(getcwd(cwd, sizeof cwd) != NULL && strcmp(cwd, "/plain") == 0);
    LP_CHECK(has_bytes("a", "a\n"));
    d = open("/plain", O_RDONLY | O_DIRECTORY);
    LP_CHECK(d >= 0 && chdir("/") == 0 && fchdir(d) == 0);
    close(d);
    LP_CHECK(has_bytes("b", "b\n"));
    LP_CHECK(FAILS(chdir("/etc/layer-lower"), ENOTDIR));
    LP_CHECK(FAILS(chdir("/etc/layer-hidden"), ENOENT));
    LP_CHECK(FAILS(chdir("/lowdir/l1"), ENOENT));
    LP_CHECK(getcwd(cwd, sizeof cwd) != NULL && strcmp(cwd, "/plain") == 0);
    LP_CHECK(chdir("/") == 0);
    LP_CHECK(getcwd(cwd, sizeof cwd) != NULL && strcmp(cwd, "/") == 0);
    LP_CHECK(has_bytes("etc/layer-own", OWN_BYTES));
    return 0;
}

static int real_paths(void) {
    char buf[PATH_MAX];
    LP_CHECK(realpath("/etc/../etc/layer-own", buf) != NULL && strcmp(buf, "/etc/layer-own") == 0);
    LP_CHECK(realpath("/plain/../plain/a", buf) != NULL && strcmp(buf, "/plain/a") == 0);
    LP_CHECK(realpath("/etc/layer-lower", buf) != NULL && strcmp(buf, "/etc/layer-lower") == 0);
    LP_CHECK(FAILS_NULL(realpath("/etc/layer-hidden", buf), ENOENT));
    LP_CHECK(FAILS_NULL(realpath("/etc/layer-own/x", buf), ENOTDIR));
    return 0;
}

/* ---- fork, spawn and exec ---- */

/* The role of a program that lists the directory its descriptor `argv[2]` names, and ends 0 when
 * the list is the one of /etc. */
static int child_list(char **argv) {
    struct names l;
    int fd = atoi(argv[2]);
    DIR *d = fdopendir(fd);
    if (d == NULL || collect(d, &l) != 0) return 2;
    return etc_list_is_right(&l) ? 0 : 3;
}

static int fork_shares_the_description(void) {
    struct names l;
    int fd = open("/etc", O_RDONLY | O_DIRECTORY);
    LP_CHECK(fd >= 0);
    DIR *d = fdopendir(fd);
    LP_CHECK(d != NULL);
    pid_t pid = fork();
    LP_CHECK(pid >= 0);
    if (pid == 0) {
        /* The child reads through the description it inherited: all of it, as the parent read none. */
        _exit(collect(d, &l) == 0 && etc_list_is_right(&l) ? 0 : 1);
    }
    LP_CHECK(wait_ok(pid) == 0);
    /* One description, one position: the child's reads moved the parent's too, so the parent finds
     * the end. */
    LP_CHECK(collect(d, &l) == 0 && l.count == 0);
    rewinddir(d);
    LP_CHECK(collect(d, &l) == 0 && etc_list_is_right(&l));
    LP_CHECK(closedir(d) == 0);
    return 0;
}

static int spawn_child_list(const char *file, int fd) {
    char fdtext[16];
    snprintf(fdtext, sizeof fdtext, "%d", fd);
    char *argv[] = {"layer-posix", "child-list", fdtext, NULL};
    pid_t pid = 0;
    if (posix_spawn(&pid, file, NULL, NULL, argv, environ) != 0) return -1;
    return wait_ok(pid);
}

static int spawn_shares_the_description(void) {
    struct names l;
    int fd = open("/etc", O_RDONLY | O_DIRECTORY);
    LP_CHECK(fd >= 0);
    LP_CHECK(spawn_child_list("/bin/layer-posix", fd) == 0);
    DIR *d = fdopendir(fd);
    LP_CHECK(d != NULL && collect(d, &l) == 0 && l.count == 0);
    LP_CHECK(closedir(d) == 0);
    /* A descriptor with FD_CLOEXEC is not in the new image. */
    fd = open("/etc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    LP_CHECK(fd >= 0);
    LP_CHECK(spawn_child_list("/bin/layer-posix", fd) == 2);
    close(fd);
    return 0;
}

static int exec_keeps_the_description(void) {
    struct names l;
    int fd = open("/etc", O_RDONLY | O_DIRECTORY);
    LP_CHECK(fd >= 0);
    pid_t pid = fork();
    LP_CHECK(pid >= 0);
    if (pid == 0) {
        char fdtext[16];
        snprintf(fdtext, sizeof fdtext, "%d", fd);
        char *argv[] = {"layer-posix", "child-list", fdtext, NULL};
        execv("/bin/layer-posix", argv);
        _exit(99);
    }
    LP_CHECK(wait_ok(pid) == 0);
    DIR *d = fdopendir(fd);
    LP_CHECK(d != NULL && collect(d, &l) == 0 && l.count == 0);
    LP_CHECK(closedir(d) == 0);
    return 0;
}

static int programs_of_the_layers(void) {
    pid_t pid = 0;
    char *argv[] = {"layer-posix", "exit0", NULL};
    /* A program the layer deletes is not there, and a program of the layer of the user is no program. */
    LP_CHECK(posix_spawn(&pid, "/bin/layer-posix-gone", NULL, NULL, argv, environ) == ENOENT);
    LP_CHECK(posix_spawn(&pid, "/bin/layer-upper-prog", NULL, NULL, argv, environ) == EACCES);
    LP_CHECK(posix_spawn(&pid, "/bin/never-was", NULL, NULL, argv, environ) == ENOENT);
    LP_CHECK(posix_spawn(&pid, "/bin/layer-posix", NULL, NULL, argv, environ) == 0);
    LP_CHECK(wait_ok(pid) == 0);
    LP_CHECK(FAILS(execv("/bin/layer-posix-gone", argv), ENOENT));
    LP_CHECK(FAILS(execv("/bin/layer-upper-prog", argv), EACCES));
    LP_CHECK(FAILS(execv("/etc/layer-lower", argv), EACCES));
    return 0;
}

/* The child of a fork binds the clone of the session with its own identity at its first call: as
 * user 1000 it is refused what the parent, the superuser, reads. */
static int fork_binds_its_own_identity(void) {
    char buf[64];
    LP_CHECK(has_bytes("/etc/layer-secret", "secret\n"));
    pid_t pid = fork();
    LP_CHECK(pid >= 0);
    if (pid == 0) {
        if (!has_bytes("/etc/layer-secret", "secret\n")) _exit(1);
        if (setgid(100) != 0 || setuid(1000) != 0) _exit(2);
        /* The identity changed: the binding lapses and the layer binds again. */
        if (!FAILS(open("/etc/layer-secret", O_RDONLY), EACCES)) _exit(3);
        if (!has_bytes("/etc/layer-own", OWN_BYTES)) _exit(4);
        _exit(0);
    }
    LP_CHECK(wait_ok(pid) == 0);
    /* The parent's session is its own and still the superuser's. */
    LP_CHECK(read_file("/etc/layer-secret", buf, sizeof buf) == 7);
    return 0;
}

/* ---- the rights ---- */

static int rights_of_another_user(void) {
    pid_t pid = fork();
    LP_CHECK(pid >= 0);
    if (pid == 0) {
        struct names l;
        struct stat st;
        if (setgid(100) != 0 || setuid(1000) != 0) _exit(1);
        /* A file of the layer whose own mode closes it, and a directory of the layer that is closed. */
        if (!FAILS(open("/etc/layer-secret", O_RDONLY), EACCES)) _exit(2);
        if (!FAILS(open("/private/f", O_RDONLY), EACCES)) _exit(3);
        /* Both checks must pass: the closed directory of the layer hides the lower name too. */
        if (!FAILS(open("/private/lower", O_RDONLY), EACCES)) _exit(4);
        if (!FAILS(stat("/private/lower", &st), EACCES)) _exit(5);
        /* A closed directory of the lower set alone is the file service's to refuse. */
        if (!FAILS(open("/lowpriv/f", O_RDONLY), EACCES)) _exit(6);
        if (!FAILS_NULL(opendir("/lowpriv"), EACCES)) _exit(7);
        /* What the mode allows is read. */
        if (!has_bytes("/etc/layer-own", OWN_BYTES)) _exit(8);
        if (!has_bytes("/etc/layer-world", "for everyone\n")) _exit(9);
        if (!has_bytes("/etc/layer-lower", "lower of etc\n")) _exit(10);
        DIR *d = opendir("/etc");
        if (d == NULL || collect(d, &l) != 0 || !etc_list_is_right(&l)) _exit(11);
        closedir(d);
        if (!FAILS(access("/etc/layer-secret", R_OK), EACCES)) _exit(12);
        _exit(0);
    }
    int code = wait_ok(pid);
    if (code != 0) printf("layer-posix: the other user's child ended with %d\n", code);
    LP_CHECK(code == 0);
    return 0;
}

/* ---- a read only file system ---- */

static int writes_to_the_lower_set_are_refused(void) {
    struct stat st;
    struct timespec times[2] = {{1, 0}, {1, 0}};
    /* A program of the lower set is never copied up: every write to it is refused. A file that is no
     * program is copied up when it is written (the copy phase, `layer-posix copy`). */
    LP_CHECK(FAILS(open("/bin/layer-posix", O_WRONLY), EROFS));
    LP_CHECK(FAILS(open("/bin/layer-posix", O_RDWR), EROFS));
    LP_CHECK(FAILS(open("/bin/layer-posix", O_RDONLY | O_TRUNC), EROFS));
    LP_CHECK(FAILS(chmod("/bin/layer-posix", 0600), EROFS));
    LP_CHECK(FAILS(chown("/bin/layer-posix", 1, 1), EROFS));
    LP_CHECK(FAILS(utimensat(AT_FDCWD, "/bin/layer-posix", times, 0), EROFS));
    LP_CHECK(FAILS(truncate("/bin/layer-posix", 0), EROFS));
    /* A directory is not opened for writing. */
    LP_CHECK(FAILS(open("/plain", O_WRONLY), EISDIR));
    /* A lower name is not renamed (EXDEV), and the volume has no hard links. */
    LP_CHECK(FAILS(rename("/etc/layer-lower", "/etc/renamed"), EXDEV));
    LP_CHECK(FAILS(rename("/etc/layer-lower", "/tmp/renamed"), EXDEV));
    LP_CHECK(FAILS(rename("/bin/layer-posix", "/bin/renamed"), EXDEV));
    LP_CHECK(FAILS(link("/etc/layer-lower", "/etc/hard"), EMLINK));
    /* A path against a description of a lower directory is refused as well. */
    int lower = open("/plain", O_RDONLY | O_DIRECTORY);
    LP_CHECK(lower >= 0);
    LP_CHECK(FAILS(openat(lower, "../bin/layer-posix", O_WRONLY), EROFS));
    LP_CHECK(FAILS(renameat(lower, "a", lower, "a2"), EXDEV));
    close(lower);
    /* Nothing was written below the layers. */
    LP_CHECK(has_bytes("/etc/layer-lower", "lower of etc\n") && has_bytes("/plain/a", "a\n"));
    LP_CHECK(stat("/etc/layer-lower", &st) == 0 && (st.st_mode & 07777) == 0644 && st.st_uid == 0);
    LP_CHECK(stat("/bin/layer-posix", &st) == 0 && (st.st_mode & 07777) == 0755 && st.st_uid == 0);
    LP_CHECK(FAILS(stat("/etc/renamed", &st), ENOENT) && FAILS(stat("/etc/hard", &st), ENOENT));
    return 0;
}

/* The attributes of a lower file or directory are not changed through a description either. */
static int attributes_of_descriptions(void) {
    struct stat st;
    struct timespec times[2] = {{1, 0}, {1, 0}};
    const char *paths[] = {"/etc/layer-lower", "/plain"};
    for (int i = 0; i < 2; i++) {
        int fd = open(paths[i], O_RDONLY);
        LP_CHECK(fd >= 0);
        LP_CHECK(FAILS(fchmod(fd, 0777), EROFS));
        LP_CHECK(FAILS(fchown(fd, 1, 1), EROFS));
        LP_CHECK(FAILS(futimens(fd, times), EROFS));
        close(fd);
    }
    LP_CHECK(stat("/etc/layer-lower", &st) == 0 && (st.st_mode & 07777) == 0644 && st.st_uid == 0);
    LP_CHECK(stat("/etc/layer-own", &st) == 0 && (st.st_mode & 07777) == 0640 && st.st_uid == 1000);
    return 0;
}

/* A child that inherited the descriptions of a lower and a layer file: the role `dev-child` after an
 * exec (the mark of the lower one crosses it, the layer one's does not: the departure). */
static int dev_child(char **argv) {
    struct stat low, up;
    if (fstat(atoi(argv[2]), &low) != 0 || fstat(atoi(argv[3]), &up) != 0) return 2;
    if (low.st_dev != LAYERED_DEVICE) return 3;
    if (up.st_dev != DATA_DEVICE) return 4;
    return 0;
}

static int device_across_fork_and_exec(void) {
    struct stat st;
    int low = open("/etc/layer-lower", O_RDONLY);
    int up = open("/etc/layer-own", O_RDONLY);
    int fork_only = open("/etc/layer-note", O_RDONLY | O_CLOFORK);
    LP_CHECK(low >= 0 && up >= 0 && fork_only >= 0);
    pid_t pid = fork();
    LP_CHECK(pid >= 0);
    if (pid == 0) {
        if (fstat(low, &st) != 0 || st.st_dev != LAYERED_DEVICE) _exit(1);
        if (fstat(up, &st) != 0 || st.st_dev != LAYERED_DEVICE) _exit(2);
        /* O_CLOFORK of the pass is kept: the description is not in the child. */
        if (!FAILS(fstat(fork_only, &st), EBADF)) _exit(3);
        _exit(0);
    }
    LP_CHECK(wait_ok(pid) == 0);
    LP_CHECK(fstat(fork_only, &st) == 0);
    pid = fork();
    LP_CHECK(pid >= 0);
    if (pid == 0) {
        char a[16], b[16];
        snprintf(a, sizeof a, "%d", low);
        snprintf(b, sizeof b, "%d", up);
        char *argv[] = {"layer-posix", "dev-child", a, b, NULL};
        execv("/bin/layer-posix", argv);
        _exit(99);
    }
    LP_CHECK(wait_ok(pid) == 0);
    close(low);
    close(up);
    close(fork_only);
    return 0;
}

/* The role `nopath-child`: a description of the service that crossed an exec has no path. */
static int nopath_child(char **argv) {
    int fd = atoi(argv[2]);
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode)) return 2;
    if (!FAILS(openat(fd, "layer-own", O_RDONLY), EOPNOTSUPP)) return 3;
    if (!FAILS(fchdir(fd), EOPNOTSUPP)) return 4;
    DIR *d = fdopendir(fd);
    struct names l;
    if (d == NULL || collect(d, &l) != 0 || !etc_list_is_right(&l)) return 5;
    return 0;
}

static int no_path_after_exec(void) {
    int fd = open("/etc", O_RDONLY | O_DIRECTORY);
    LP_CHECK(fd >= 0);
    pid_t pid = fork();
    LP_CHECK(pid >= 0);
    if (pid == 0) {
        char a[16];
        snprintf(a, sizeof a, "%d", fd);
        char *argv[] = {"layer-posix", "nopath-child", a, NULL};
        execv("/bin/layer-posix", argv);
        _exit(99);
    }
    LP_CHECK(wait_ok(pid) == 0);
    close(fd);
    return 0;
}

/* ---- the session in the slot ---- */

/* The listener of a forged layer service: the count of the requests it got. */
static void *forged_listener(void *unused) {
    (void)unused;
    return (void *)(unsigned long)stafeto_probe_loader_listen();
}

/* Starts `path` in the role `role` with a channel of the probe's own in the Layer place (mode 9),
 * served here as a forged service. Its exit status goes to `*status`, the requests the forged
 * service got to `*requests`. The probe holds a description of the service, so that the child has a
 * session of its own to be given. */
static int forged_run(const char *path, const char *role, int *status, unsigned *requests) {
    pthread_t listener;
    void *count = NULL;
    char fdtext[16];
    int held = open("/etc", O_RDONLY | O_DIRECTORY);
    if (held < 0) return -1;
    snprintf(fdtext, sizeof fdtext, "%d", held);
    char *argv[] = {"layer-posix", (char *)role, fdtext, NULL};
    pid_t pid = 0;
    if (stafeto_probe_loader_start(9) != 0) return -1;
    if (pthread_create(&listener, NULL, forged_listener, NULL) != 0) return -1;
    if (posix_spawn(&pid, path, NULL, NULL, argv, environ) != 0) return -1;
    if (waitpid(pid, status, 0) != pid) return -1;
    if (stafeto_probe_loader_stop() != 0) return -1;
    if (pthread_join(listener, &count) != 0) return -1;
    *requests = (unsigned)(unsigned long)count;
    close(held);
    return 0;
}

/* The role `forged`: a program that is not set-ID has the forged channel in the place, which
 * answers nothing the names need. */
static int forged_role(void) {
    if (lp_session() != 1) return 2;
    if (open("/etc/layer-lower", O_RDONLY) >= 0) return 3;
    return 0;
}

/* The role `setid`: a set-ID program has the service's session of its own in the place of the
 * forged one, and reads. */
static int setid_role(void) {
    char buf[64];
    if (read_file("/etc/layer-lower", buf, sizeof buf) != 13) return 2;
    if (strcmp(buf, "lower of etc\n") != 0) return 3;
    return 0;
}

/* The role `genuine`: a set-ID program that got the parent's genuine session keeps it with the
 * description the parent holds, and the session is bound to the program's own identity: the
 * effective user 1000 is refused what the superuser parent reads. */
static int genuine_role(char **argv) {
    struct names l;
    int fd = atoi(argv[2]);
    DIR *d = fdopendir(fd);
    if (d == NULL || collect(d, &l) != 0 || !etc_list_is_right(&l)) return 2;
    if (!FAILS(open("/etc/layer-secret", O_RDONLY), EACCES)) return 3;
    if (!has_bytes("/etc/layer-world", "for everyone\n")) return 4;
    if (geteuid() != 1000 || getuid() != 0) return 5;
    return 0;
}

static int slot_checks(void) {
    int status = 0;
    unsigned requests = 0;
    /* A program that is not set-ID takes the forged channel and asks it. */
    LP_CHECK(forged_run("/bin/layer-posix", "forged", &status, &requests) == 0);
    LP_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    LP_CHECK(requests != 0);
    /* A set-ID program is given a new session of the service, and the forgery gets no request. */
    LP_CHECK(forged_run("/bin/layer-posix-suid", "setid", &status, &requests) == 0);
    LP_CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    LP_CHECK(requests == 0);
    /* The parent's own session stands. */
    LP_CHECK(has_bytes("/etc/layer-lower", "lower of etc\n"));
    return 0;
}

static int setid_keeps_the_genuine_session(void) {
    char fdtext[16];
    int fd = open("/etc", O_RDONLY | O_DIRECTORY);
    LP_CHECK(fd >= 0);
    snprintf(fdtext, sizeof fdtext, "%d", fd);
    char *argv[] = {"layer-posix", "genuine", fdtext, NULL};
    pid_t pid = 0;
    LP_CHECK(posix_spawn(&pid, "/bin/layer-posix-suid", NULL, NULL, argv, environ) == 0);
    int code = wait_ok(pid);
    if (code != 0) printf("layer-posix: the set-ID program ended with %d\n", code);
    LP_CHECK(code == 0);
    LP_CHECK(has_bytes("/etc/layer-secret", "secret\n"));
    close(fd);
    return 0;
}

/* ---- a lower link leads through the merged view ---- */

/* The lower set has /lowlink (to `lower`) and /lower/ln (to `keep`). The RAM file service answers
 * the expansion of a link with a redirect that routes by the path, so the layer service decides
 * what the target is: the name the layer deletes is gone and the one it shadows is the layer's. */
static int lower_links(void) {
    struct stat st;
    char buf[64];
    LP_CHECK(lstat("/lower/ln", &st) == 0 && S_ISLNK(st.st_mode) && st.st_dev == LAYERED_DEVICE);
    LP_CHECK(readlink("/lower/ln", buf, sizeof buf) == 4 && memcmp(buf, "keep", 4) == 0);
    LP_CHECK(has_bytes("/lower/ln", "lower keep\n"));
    LP_CHECK(stat("/lower/ln", &st) == 0 && S_ISREG(st.st_mode) && st.st_dev == LAYERED_DEVICE);
    LP_CHECK(lstat("/lowlink", &st) == 0 && S_ISLNK(st.st_mode));
    LP_CHECK(has_bytes("/lowlink/keep", "lower keep\n"));
    LP_CHECK(has_bytes("/lowlink/shadowed", "upper shadow\n"));
    LP_CHECK(FAILS(open("/lowlink/hidden", O_RDONLY), ENOENT));
    LP_CHECK(stat("/lowlink", &st) == 0 && S_ISDIR(st.st_mode));
    DIR *d = opendir("/lowlink");
    LP_CHECK(d != NULL);
    struct names l;
    LP_CHECK(collect(d, &l) == 0 && occurrences(&l, "keep") == 1 && occurrences(&l, "hidden") == 0);
    LP_CHECK(closedir(d) == 0);
    char path[PATH_MAX];
    LP_CHECK(realpath("/lowlink/keep", path) != NULL && strcmp(path, "/lower/keep") == 0);
    /* A program of the lower set that a link names is run through its canonical path. */
    LP_CHECK(chdir("/lowlink") == 0 && getcwd(path, sizeof path) != NULL && strcmp(path, "/lower") == 0);
    LP_CHECK(chdir("/") == 0);
    return 0;
}

/* ---- the write phase: the changes of names on the layer (the role "write") ---- */

#define WRITE_BYTES "written through the layer\n"

static int put_file(const char *path, const char *bytes, mode_t mode) {
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, mode);
    if (fd < 0) return -1;
    size_t n = strlen(bytes);
    if (write(fd, bytes, n) != (ssize_t)n) {
        close(fd);
        return -1;
    }
    return close(fd);
}

static int exists(const char *path) {
    struct stat st;
    return lstat(path, &st) == 0;
}

/* Whether `name` is listed in the directory `dir`, `times` times. */
static int listed(const char *dir, const char *name, int times) {
    struct names l;
    DIR *d = opendir(dir);
    if (d == NULL) return 0;
    int ok = collect(d, &l) == 0 && occurrences(&l, name) == times;
    closedir(d);
    return ok;
}

static int created_file(void) {
    struct stat st, fst;
    int fd = open("/etc/w-new", O_CREAT | O_EXCL | O_RDWR, 0640);
    LP_CHECK(fd >= 0);
    LP_CHECK(write(fd, WRITE_BYTES, strlen(WRITE_BYTES)) == (ssize_t)strlen(WRITE_BYTES));
    LP_CHECK(lseek(fd, 0, SEEK_SET) == 0);
    LP_CHECK(fd_has_bytes(fd, WRITE_BYTES));
    LP_CHECK(fstat(fd, &fst) == 0 && close(fd) == 0);
    LP_CHECK(stat("/etc/w-new", &st) == 0);
    LP_CHECK(S_ISREG(st.st_mode) && (st.st_mode & 07777) == 0640 && st.st_uid == 0);
    LP_CHECK(st.st_size == (off_t)strlen(WRITE_BYTES));
    /* The number is the layer's (bit 62), and the device is the root's, from the path and from the
     * description. */
    LP_CHECK(st.st_dev == LAYERED_DEVICE && fst.st_dev == LAYERED_DEVICE && st.st_ino == fst.st_ino);
    LP_CHECK((st.st_ino >> 62) == 1);
    LP_CHECK(has_bytes("/etc/w-new", WRITE_BYTES));
    LP_CHECK(listed("/etc", "w-new", 1));
    LP_CHECK(FAILS(open("/etc/w-new", O_CREAT | O_EXCL | O_WRONLY, 0600), EEXIST));
    fd = open("/etc/w-new", O_CREAT | O_RDONLY, 0600);
    LP_CHECK(fd >= 0 && fd_has_bytes(fd, WRITE_BYTES) && close(fd) == 0);
    LP_CHECK((stat("/etc/w-new", &st) == 0) && (st.st_mode & 07777) == 0640);
    /* In a directory of the lower set alone: the layer makes the directory first. */
    LP_CHECK(put_file("/plain/w-new", "p\n", 0644) == 0);
    LP_CHECK(stat("/plain", &st) == 0 && S_ISDIR(st.st_mode) && (st.st_mode & 07777) == 0755);
    LP_CHECK(listed("/plain", "a", 1) && listed("/plain", "w-new", 1) && listed("/plain", "c", 1));
    LP_CHECK(has_bytes("/plain/a", "a\n") && has_bytes("/plain/w-new", "p\n"));
    /* A directory made in a directory of the layer that also has lower names. */
    LP_CHECK(mkdir("/many/w-a", 0755) == 0 && put_file("/many/w-a/f", "deep\n", 0600) == 0);
    LP_CHECK(has_bytes("/many/w-a/f", "deep\n"));
    return 0;
}

static int rewritten_file(void) {
    struct stat st;
    struct timespec times[2] = {{1, 0}, {2, 0}};
    LP_CHECK(put_file("/etc/layer-own", "short\n", 0600) == 0);
    LP_CHECK(has_bytes("/etc/layer-own", "short\n"));
    /* The mode a file has is the file's: the one it had stays. */
    LP_CHECK(stat("/etc/layer-own", &st) == 0 && (st.st_mode & 07777) == 0640 && st.st_uid == 1000);
    int fd = open("/etc/layer-own", O_WRONLY | O_APPEND);
    LP_CHECK(fd >= 0 && write(fd, "more\n", 5) == 5 && close(fd) == 0);
    LP_CHECK(has_bytes("/etc/layer-own", "short\nmore\n"));
    LP_CHECK(truncate("/etc/layer-own", 3) == 0);
    LP_CHECK(stat("/etc/layer-own", &st) == 0 && st.st_size == 3 && has_bytes("/etc/layer-own", "sho"));
    /* The attributes of a file of the layer: by the path and by the description. */
    LP_CHECK(chmod("/etc/layer-own", 0600) == 0);
    LP_CHECK(stat("/etc/layer-own", &st) == 0 && (st.st_mode & 07777) == 0600);
    fd = open("/etc/layer-own", O_RDWR);
    LP_CHECK(fd >= 0 && fchmod(fd, 0640) == 0 && fchown(fd, 1000, 1000) == 0 && futimens(fd, times) == 0);
    LP_CHECK(fstat(fd, &st) == 0 && (st.st_mode & 07777) == 0640 && st.st_mtime == 2 && close(fd) == 0);
    LP_CHECK(chown("/etc/layer-own", 1000, 100) == 0);
    LP_CHECK(utimensat(AT_FDCWD, "/etc/layer-own", times, 0) == 0);
    LP_CHECK(stat("/etc/layer-own", &st) == 0 && st.st_gid == 100 && st.st_mtime == 2 && st.st_uid == 1000);
    LP_CHECK(chown("/etc/layer-own", 1000, 1000) == 0);
    return 0;
}

static int directories(void) {
    struct stat st;
    LP_CHECK(mkdir("/etc/w-dir", 0750) == 0);
    LP_CHECK(stat("/etc/w-dir", &st) == 0 && S_ISDIR(st.st_mode) && (st.st_mode & 07777) == 0750);
    LP_CHECK(st.st_uid == 0 && st.st_dev == LAYERED_DEVICE && listed("/etc", "w-dir", 1));
    LP_CHECK(FAILS(mkdir("/etc/w-dir", 0755), EEXIST) && FAILS(mkdir("/plain", 0755), EEXIST));
    LP_CHECK(FAILS(mkdir("/etc/layer-lower", 0755), EEXIST) && FAILS(mkdir("/", 0755), EEXIST));
    LP_CHECK(FAILS(mkdir("/etc/layer-lower/x", 0755), ENOTDIR) && FAILS(mkdir("/nowhere/x", 0755), ENOENT));
    LP_CHECK(put_file("/etc/w-dir/f", "f\n", 0644) == 0);
    LP_CHECK(FAILS(rmdir("/etc/w-dir"), ENOTEMPTY));
    LP_CHECK(FAILS(rmdir("/etc/layer-world"), ENOTDIR) && FAILS(rmdir("/etc/none"), ENOENT));
    LP_CHECK(unlink("/etc/w-dir/f") == 0 && rmdir("/etc/w-dir") == 0);
    LP_CHECK(FAILS(stat("/etc/w-dir", &st), ENOENT) && listed("/etc", "w-dir", 0));
    /* A directory of the lower set alone is copied up with its own mode, then holds the new one. */
    LP_CHECK(mkdir("/lowpriv/sub", 0755) == 0);
    LP_CHECK(stat("/lowpriv", &st) == 0 && (st.st_mode & 07777) == 0700);
    LP_CHECK(listed("/lowpriv", "f", 1) && listed("/lowpriv", "sub", 1));
    return 0;
}

static int deletions(void) {
    struct stat st;
    /* A name of the layer alone. */
    LP_CHECK(unlink("/etc/layer-note") == 0);
    LP_CHECK(FAILS(stat("/etc/layer-note", &st), ENOENT) && FAILS(open("/etc/layer-note", O_RDONLY), ENOENT));
    LP_CHECK(listed("/etc", "layer-note", 0));
    /* A name of the lower set: a mark of deletion, so it is gone and not listed. */
    LP_CHECK(unlink("/etc/layer-lower") == 0);
    LP_CHECK(FAILS(stat("/etc/layer-lower", &st), ENOENT) && FAILS(open("/etc/layer-lower", O_RDONLY), ENOENT));
    LP_CHECK(FAILS(access("/etc/layer-lower", F_OK), ENOENT) && listed("/etc", "layer-lower", 0));
    LP_CHECK(unlink("/lower/keep") == 0 && FAILS(open("/lower/keep", O_RDONLY), ENOENT));
    LP_CHECK(listed("/lower", "keep", 0) && listed("/lower", "shadowed", 1));
    /* A file of the layer over a lower name: both go. */
    LP_CHECK(unlink("/lower/shadowed") == 0 && FAILS(open("/lower/shadowed", O_RDONLY), ENOENT));
    LP_CHECK(listed("/lower", "shadowed", 0));
    /* The marks are no names. */
    LP_CHECK(listed("/etc", ".wh.layer-lower", 0) && FAILS(stat("/etc/.wh.layer-lower", &st), ENOENT));
    LP_CHECK(FAILS(unlink("/etc/layer-lower"), ENOENT) && FAILS(unlink("/etc/never"), ENOENT));
    LP_CHECK(FAILS(unlink("/etc"), EISDIR) && FAILS(unlink("/plain"), EISDIR));
    /* The name made again is a new file, with the mark out of the way. */
    LP_CHECK(put_file("/etc/layer-lower", "recreated\n", 0644) == 0);
    LP_CHECK(has_bytes("/etc/layer-lower", "recreated\n") && listed("/etc", "layer-lower", 1));
    return 0;
}

static int removed_directories(void) {
    struct stat st;
    struct names l;
    LP_CHECK(unlink("/plain/w-new") == 0);
    LP_CHECK(FAILS(rmdir("/plain"), ENOTEMPTY) && FAILS(rmdir("/lowdir"), ENOTEMPTY));
    LP_CHECK(unlink("/plain/a") == 0 && unlink("/plain/b") == 0 && unlink("/plain/c") == 0);
    LP_CHECK(rmdir("/plain") == 0);
    LP_CHECK(FAILS(stat("/plain", &st), ENOENT) && FAILS(open("/plain/a", O_RDONLY), ENOENT));
    LP_CHECK(listed("/", "plain", 0));
    /* A directory made over it is opaque: nothing of the lower one shows through. */
    LP_CHECK(mkdir("/plain", 0711) == 0);
    LP_CHECK(stat("/plain", &st) == 0 && (st.st_mode & 07777) == 0711);
    DIR *d = opendir("/plain");
    LP_CHECK(d != NULL && collect(d, &l) == 0 && l.count == 2 && closedir(d) == 0);
    LP_CHECK(FAILS(open("/plain/a", O_RDONLY), ENOENT));
    LP_CHECK(put_file("/plain/x", "x\n", 0644) == 0 && listed("/plain", "x", 1) && listed("/plain", "a", 0));
    return 0;
}

static int opaque_directory_stays_removed(void) {
    struct stat st;
    /* /lowdir is a directory of the layer over a lower one (opaque): removing it must not bring the
     * lower one back, and nor must moving it. */
    LP_CHECK(unlink("/lowdir/u1") == 0 && rmdir("/lowdir") == 0);
    LP_CHECK(FAILS(stat("/lowdir", &st), ENOENT) && FAILS(open("/lowdir/l1", O_RDONLY), ENOENT));
    LP_CHECK(mkdir("/lowdir", 0755) == 0 && listed("/lowdir", "l1", 0));
    LP_CHECK(rmdir("/lowdir") == 0);
    LP_CHECK(FAILS(stat("/lowdir", &st), ENOENT) && FAILS(open("/lowdir/l2", O_RDONLY), ENOENT));
    LP_CHECK(listed("/", "lowdir", 0));
    LP_CHECK(mkdir("/lowdir", 0755) == 0 && put_file("/lowdir/n", "n\n", 0644) == 0);
    LP_CHECK(rename("/lowdir", "/lowdir2") == 0);
    LP_CHECK(FAILS(stat("/lowdir", &st), ENOENT) && FAILS(open("/lowdir/l1", O_RDONLY), ENOENT));
    LP_CHECK(has_bytes("/lowdir2/n", "n\n") && listed("/lowdir2", "l1", 0) && listed("/lowdir2", "n", 1));
    /* A directory moved onto an opaque one over a lower directory is opaque too. */
    LP_CHECK(mkdir("/lowdir", 0755) == 0 && mkdir("/lowsrc", 0755) == 0 && put_file("/lowsrc/s", "s\n", 0644) == 0);
    LP_CHECK(rename("/lowsrc", "/lowdir") == 0);
    LP_CHECK(listed("/lowdir", "s", 1) && listed("/lowdir", "l1", 0));
    return 0;
}

static int renames(void) {
    struct stat before, st;
    char buf[64];
    LP_CHECK(stat("/etc/w-new", &before) == 0);
    LP_CHECK(rename("/etc/w-new", "/etc/w-moved") == 0);
    LP_CHECK(FAILS(stat("/etc/w-new", &st), ENOENT) && has_bytes("/etc/w-moved", WRITE_BYTES));
    LP_CHECK(stat("/etc/w-moved", &st) == 0 && st.st_ino == before.st_ino && (st.st_mode & 07777) == 0640);
    LP_CHECK(listed("/etc", "w-new", 0) && listed("/etc", "w-moved", 1));
    /* A directory with what is in it, open while it moves. */
    LP_CHECK(mkdir("/etc/w-d1", 0755) == 0 && put_file("/etc/w-d1/f", "d1f\n", 0644) == 0);
    LP_CHECK(mkdir("/etc/w-d1/sub", 0755) == 0 && put_file("/etc/w-d1/sub/g", "g\n", 0644) == 0);
    DIR *d = opendir("/etc/w-d1");
    LP_CHECK(d != NULL);
    LP_CHECK(rename("/etc/w-d1", "/etc/w-d2") == 0);
    LP_CHECK(FAILS(stat("/etc/w-d1", &st), ENOENT) && has_bytes("/etc/w-d2/sub/g", "g\n"));
    struct names l;
    LP_CHECK(collect(d, &l) == 0 && occurrences(&l, "f") == 1 && occurrences(&l, "sub") == 1);
    LP_CHECK(closedir(d) == 0);
    /* Into another directory, and over an existing file. */
    LP_CHECK(rename("/etc/w-d2/f", "/many/w-f") == 0 && has_bytes("/many/w-f", "d1f\n"));
    LP_CHECK(put_file("/etc/w-over", "over\n", 0600) == 0);
    LP_CHECK(rename("/etc/w-moved", "/etc/w-over") == 0 && has_bytes("/etc/w-over", WRITE_BYTES));
    /* A name of the layer that shadows a lower one: the lower one stays hidden. */
    LP_CHECK(rename("/etc/layer-lower", "/etc/w-ll") == 0);
    LP_CHECK(FAILS(stat("/etc/layer-lower", &st), ENOENT) && has_bytes("/etc/w-ll", "recreated\n"));
    LP_CHECK(listed("/etc", "layer-lower", 0) && listed("/etc", "w-ll", 1));
    /* What it refuses. */
    LP_CHECK(FAILS(rename("/lowpriv/f", "/lowpriv/f2"), EXDEV) && FAILS(rename("/lower", "/lower2"), EXDEV));
    LP_CHECK(FAILS(rename("/etc/w-over", "/tmp/w-over"), EXDEV) && FAILS(rename("/tmp", "/etc/w-tmp-dir"), EXDEV));
    LP_CHECK(FAILS(rename("/etc/never", "/etc/x"), ENOENT));
    LP_CHECK(FAILS(rename("/etc/w-d2", "/etc/w-d2/sub/x"), EINVAL));
    LP_CHECK(FAILS(rename("/etc/w-over", "/etc/w-d2"), EISDIR) && FAILS(rename("/etc/w-d2", "/etc/w-over"), ENOTDIR));
    LP_CHECK(mkdir("/etc/w-full", 0755) == 0 && put_file("/etc/w-full/x", "x\n", 0644) == 0);
    LP_CHECK(FAILS(rename("/etc/w-d2/sub", "/etc/w-full"), ENOTEMPTY));
    LP_CHECK(unlink("/etc/w-full/x") == 0 && rename("/etc/w-d2/sub", "/etc/w-full") == 0);
    LP_CHECK(has_bytes("/etc/w-full/g", "g\n"));
    (void)buf;
    return 0;
}

static int symbolic_links(void) {
    struct stat st;
    char buf[64];
    LP_CHECK(symlink("layer-world", "/etc/w-link") == 0);
    LP_CHECK(readlink("/etc/w-link", buf, sizeof buf) == 11 && memcmp(buf, "layer-world", 11) == 0);
    LP_CHECK(lstat("/etc/w-link", &st) == 0 && S_ISLNK(st.st_mode) && st.st_size == 11 && st.st_dev == LAYERED_DEVICE);
    LP_CHECK(stat("/etc/w-link", &st) == 0 && S_ISREG(st.st_mode) && st.st_size == 13);
    LP_CHECK(has_bytes("/etc/w-link", "for everyone\n"));
    struct names l;
    DIR *d = opendir("/etc");
    LP_CHECK(d != NULL && collect(d, &l) == 0 && type_of(&l, "w-link") == DT_LNK && closedir(d) == 0);
    LP_CHECK(FAILS(symlink("x", "/etc/w-link"), EEXIST) && FAILS(symlink("x", "/etc/layer-world"), EEXIST));
    LP_CHECK(FAILS(readlink("/etc/layer-world", buf, sizeof buf), EINVAL));
    LP_CHECK(FAILS(open("/etc/w-link", O_RDONLY | O_NOFOLLOW), ELOOP));
    /* A link to a directory, in the root: a path through it, the canonical path, chdir. */
    LP_CHECK(symlink("/etc", "/w-dlink") == 0);
    LP_CHECK(has_bytes("/w-dlink/layer-world", "for everyone\n") && stat("/w-dlink", &st) == 0 && S_ISDIR(st.st_mode));
    char path[PATH_MAX];
    LP_CHECK(realpath("/w-dlink/layer-world", path) != NULL && strcmp(path, "/etc/layer-world") == 0);
    LP_CHECK(chdir("/w-dlink") == 0 && getcwd(path, sizeof path) != NULL && strcmp(path, "/etc") == 0);
    LP_CHECK(has_bytes("layer-world", "for everyone\n") && chdir("/") == 0);
    /* The changes through it are the changes of the directory it names. */
    LP_CHECK(mkdir("/w-dlink/w-via", 0755) == 0 && stat("/etc/w-via", &st) == 0 && S_ISDIR(st.st_mode));
    LP_CHECK(put_file("/w-dlink/w-via/f", "via\n", 0644) == 0 && has_bytes("/etc/w-via/f", "via\n"));
    LP_CHECK(rename("/w-dlink/w-via", "/etc/w-via2") == 0 && has_bytes("/etc/w-via2/f", "via\n"));
    LP_CHECK(unlink("/w-dlink/w-via2/f") == 0 && rmdir("/w-dlink/w-via2") == 0);
    /* A link with a `..`, to a name of the lower set that the layer changed, and to a name of the
     * lower set the layer did not. */
    LP_CHECK(symlink("../etc/layer-world", "/lower/w-rel") == 0);
    LP_CHECK(has_bytes("/lower/w-rel", "for everyone\n"));
    LP_CHECK(symlink("/etc/w-ll", "/many/w-ll") == 0 && has_bytes("/many/w-ll", "recreated\n"));
    /* A link to a pass-through name: what is written through it is the service's. */
    LP_CHECK(symlink("/tmp", "/etc/w-tmp") == 0);
    LP_CHECK(put_file("/etc/w-tmp/w-t", "tmp via link\n", 0644) == 0 && has_bytes("/tmp/w-t", "tmp via link\n"));
    LP_CHECK(unlink("/etc/w-tmp/w-t") == 0 && FAILS(stat("/tmp/w-t", &st), ENOENT));
    LP_CHECK(unlink("/etc/w-tmp") == 0);
    /* A loop. */
    LP_CHECK(symlink("w-b", "/etc/w-a") == 0 && symlink("w-a", "/etc/w-b") == 0);
    LP_CHECK(FAILS(open("/etc/w-a", O_RDONLY), ELOOP) && FAILS(stat("/etc/w-a", &st), ELOOP));
    LP_CHECK(lstat("/etc/w-a", &st) == 0 && S_ISLNK(st.st_mode));
    LP_CHECK(unlink("/etc/w-a") == 0 && unlink("/etc/w-b") == 0);
    /* A link is removed, and the name it led to stays. */
    LP_CHECK(unlink("/etc/w-link") == 0 && FAILS(lstat("/etc/w-link", &st), ENOENT));
    LP_CHECK(has_bytes("/etc/layer-world", "for everyone\n"));
    /* A link made where a name of the lower set was deleted. */
    LP_CHECK(symlink("recreated-elsewhere", "/etc/layer-hidden") == 0);
    LP_CHECK(readlink("/etc/layer-hidden", buf, sizeof buf) == 19);
    LP_CHECK(unlink("/etc/layer-hidden") == 0 && FAILS(lstat("/etc/layer-hidden", &st), ENOENT));
    /* A change through a link of the lower set (to /lower): the directory is made canonical first. */
    LP_CHECK(mkdir("/lowlink/w-ld", 0755) == 0 && stat("/lower/w-ld", &st) == 0 && S_ISDIR(st.st_mode));
    LP_CHECK(put_file("/lowlink/w-ld/f", "ld\n", 0644) == 0 && has_bytes("/lower/w-ld/f", "ld\n"));
    LP_CHECK(rename("/lowlink/w-ld/f", "/lowlink/w-ld/g") == 0 && has_bytes("/lower/w-ld/g", "ld\n"));
    LP_CHECK(symlink("g", "/lowlink/w-ld/h") == 0 && has_bytes("/lower/w-ld/h", "ld\n"));
    LP_CHECK(unlink("/lowlink/w-ld/h") == 0 && unlink("/lowlink/w-ld/g") == 0 && rmdir("/lowlink/w-ld") == 0);
    LP_CHECK(FAILS(stat("/lower/w-ld", &st), ENOENT));
    return 0;
}

static int reserved_names_and_limits(void) {
    struct stat st;
    LP_CHECK(FAILS(link("/etc/layer-world", "/etc/w-hard"), EMLINK));
    LP_CHECK(FAILS(open("/etc/.wh.x", O_CREAT | O_WRONLY, 0644), EINVAL));
    LP_CHECK(FAILS(open("/etc/.wh..wh..opq", O_CREAT | O_WRONLY, 0644), EINVAL));
    LP_CHECK(FAILS(mkdir("/etc/.wh.x", 0755), EINVAL) && FAILS(symlink("x", "/etc/.wh.y"), EINVAL));
    LP_CHECK(FAILS(rename("/etc/layer-world", "/etc/.wh.z"), EINVAL) && FAILS(unlink("/etc/.wh.q"), EINVAL));
    LP_CHECK(FAILS(stat("/etc/.wh.layer-hidden", &st), ENOENT) && has_bytes("/etc/layer-world", "for everyone\n"));
    LP_CHECK(FAILS(mkfifo("/etc/w-fifo", 0644), EPERM));
    /* A name of 250 bytes is fine, and a path through two of them passes what the volume keeps. */
    char path[PATH_MAX];
    int n = snprintf(path, sizeof path, "/etc/");
    memset(path + n, 'a', 250);
    n += 250;
    path[n] = 0;
    LP_CHECK(mkdir(path, 0755) == 0);
    path[n] = '/';
    memset(path + n + 1, 'b', 250);
    path[n + 251] = 0;
    LP_CHECK(FAILS(mkdir(path, 0755), ENAMETOOLONG));
    LP_CHECK(FAILS(open(path, O_CREAT | O_WRONLY, 0644), ENAMETOOLONG));
    path[n] = 0;
    LP_CHECK(rmdir(path) == 0);
    return 0;
}

/* The rights of another user: `body` runs as user 1000, group 100, in a child that ends with the code
 * of the first thing that went wrong. */
static int as_user(int (*body)(void)) {
    pid_t pid = fork();
    LP_CHECK(pid >= 0);
    if (pid == 0) {
        if (setgid(100) != 0 || setuid(1000) != 0) _exit(1);
        _exit(body());
    }
    int code = wait_ok(pid);
    if (code != 0) printf("layer-posix: the other user's child ended with %d\n", code);
    LP_CHECK(code == 0);
    return 0;
}

static int user_rights_body(void) {
    struct stat st;
    struct timespec times[2] = {{3, 0}, {3, 0}};
    /* /etc is 0755 of root: no name is made or removed there by user 1000. */
    if (!FAILS(open("/etc/w-user", O_CREAT | O_WRONLY, 0644), EACCES)) return 2;
    if (!FAILS(mkdir("/etc/w-userdir", 0755), EACCES)) return 3;
    if (!FAILS(unlink("/etc/layer-world"), EACCES)) return 4;
    if (!FAILS(symlink("x", "/etc/w-userlink"), EACCES)) return 5;
    /* A directory of the lower set that is closed to the user: the same. */
    if (!FAILS(open("/lowpriv/w-user", O_CREAT | O_WRONLY, 0644), EACCES)) return 6;
    /* A file that is another's: not written, not changed. */
    if (!FAILS(open("/etc/layer-world", O_WRONLY), EACCES)) return 7;
    if (!FAILS(chmod("/etc/layer-world", 0777), EPERM)) return 8;
    if (!FAILS(utimensat(AT_FDCWD, "/etc/layer-world", times, 0), EPERM)) return 9;
    /* The owner of a file may change it. */
    if (chmod("/etc/layer-own", 0600) != 0 || chmod("/etc/layer-own", 0640) != 0) return 10;
    int fd = open("/etc/layer-own", O_WRONLY | O_APPEND);
    if (fd < 0 || write(fd, "u", 1) != 1 || close(fd) != 0) return 11;
    /* A new name is the user's: owner, group and the mode with the mask. */
    if (open("/world/mine", O_CREAT | O_WRONLY, 0666) < 0) return 12;
    if (stat("/world/mine", &st) != 0 || st.st_uid != 1000 || st.st_gid != 100) return 13;
    if (mkdir("/world/udir", 0755) != 0 || rmdir("/world/udir") != 0) return 14;
    if (symlink("mine", "/world/ulink") != 0 || unlink("/world/ulink") != 0) return 15;
    if (rename("/world/mine", "/world/mine2") != 0 || unlink("/world/mine2") != 0) return 16;
    return 0;
}

static int rights_of_another_user_on_the_layer(void) {
    LP_CHECK(as_user(user_rights_body) == 0);
    /* The refusals changed nothing, and the user's file did not outlive its removal. */
    struct stat st;
    LP_CHECK(!exists("/etc/w-user") && !exists("/etc/w-userdir") && !exists("/lowpriv/w-user"));
    LP_CHECK(stat("/etc/layer-world", &st) == 0 && (st.st_mode & 07777) == 0644 && has_bytes("/etc/layer-world", "for everyone\n"));
    LP_CHECK(!exists("/world/mine") && !exists("/world/mine2"));
    return 0;
}

/* The sticky bit of /world (01777 of root): user 1000 removes and moves its own names only. */
static int sticky_body(void) {
    if (put_file("/world/own", "own\n", 0644) != 0) return 2;
    if (!FAILS(unlink("/world/rootfile"), EPERM)) return 3;
    if (!FAILS(rename("/world/rootfile", "/world/stolen"), EPERM)) return 4;
    if (!FAILS(rename("/world/own", "/world/rootfile"), EPERM)) return 5;
    if (!FAILS(rmdir("/world/rootdir"), EPERM)) return 6;
    if (!exists("/world/rootfile") || !exists("/world/rootdir")) return 7;
    if (unlink("/world/own") != 0) return 8;
    return 0;
}

static int a_sticky_directory_is_kept(void) {
    LP_CHECK(as_user(sticky_body) == 0);
    LP_CHECK(exists("/world/rootfile") && exists("/world/rootdir") && !exists("/world/stolen"));
    return 0;
}

static int the_lower_set_is_not_written(void) {
    struct stat st;
    struct timespec times[2] = {{1, 0}, {1, 0}};
    /* A program of the lower set is not copied up, so it is not written; the files are (`copy`). */
    LP_CHECK(FAILS(open("/bin/layer-posix", O_WRONLY), EROFS) && FAILS(open("/bin/layer-posix", O_RDONLY | O_TRUNC), EROFS));
    LP_CHECK(FAILS(truncate("/bin/layer-posix", 0), EROFS) && FAILS(chmod("/bin/layer-posix", 0600), EROFS));
    LP_CHECK(FAILS(chown("/bin/layer-posix", 1, 1), EROFS) && FAILS(utimensat(AT_FDCWD, "/bin/layer-posix", times, 0), EROFS));
    LP_CHECK(FAILS(link("/lowpriv/f", "/lowpriv/h"), EMLINK));
    /* The attributes of a description of a lower file are not changed through it (the path of the
     * description is not known to the layer, so no copy is made). */
    int fd = open("/lowpriv/f", O_RDONLY);
    LP_CHECK(fd >= 0 && FAILS(fchmod(fd, 0600), EROFS) && FAILS(fchown(fd, 1, 1), EROFS));
    LP_CHECK(close(fd) == 0);
    LP_CHECK(has_bytes("/lowpriv/f", "lower closed\n"));
    LP_CHECK(stat("/lowpriv/f", &st) == 0 && (st.st_mode & 07777) == 0644 && st.st_uid == 0);
    return 0;
}

static int changes_against_descriptions(void) {
    struct stat st;
    char buf[16];
    int merged = open("/etc", O_RDONLY | O_DIRECTORY);
    int lower = open("/lowpriv", O_RDONLY | O_DIRECTORY);
    LP_CHECK(merged >= 0 && lower >= 0);
    int fd = openat(merged, "w-at", O_CREAT | O_WRONLY, 0644);
    LP_CHECK(fd >= 0 && write(fd, "at\n", 3) == 3 && close(fd) == 0);
    LP_CHECK(has_bytes("/etc/w-at", "at\n") && fstatat(merged, "w-at", &st, 0) == 0);
    LP_CHECK(mkdirat(merged, "w-atd", 0755) == 0 && unlinkat(merged, "w-atd", AT_REMOVEDIR) == 0);
    LP_CHECK(symlinkat("w-at", merged, "w-atl") == 0 && readlinkat(merged, "w-atl", buf, sizeof buf) == 4);
    LP_CHECK(unlinkat(merged, "w-atl", 0) == 0 && renameat(merged, "w-at", merged, "w-at2") == 0);
    LP_CHECK(fchmodat(merged, "w-at2", 0600, 0) == 0 && fstatat(merged, "w-at2", &st, 0) == 0 && (st.st_mode & 07777) == 0600);
    LP_CHECK(unlinkat(merged, "w-at2", 0) == 0);
    /* The attributes of a merged directory by its description are those of the directory. */
    struct timespec dt[2] = {{7, 0}, {8, 0}};
    LP_CHECK(fchmod(merged, 0755) == 0 && fchown(merged, 0, 0) == 0 && futimens(merged, dt) == 0);
    LP_CHECK(fstat(merged, &st) == 0 && (st.st_mode & 07777) == 0755 && st.st_mtime == 8);
    /* Against a directory of the lower set alone. */
    fd = openat(lower, "w-new2", O_CREAT | O_WRONLY, 0644);
    LP_CHECK(fd >= 0 && close(fd) == 0 && listed("/lowpriv", "w-new2", 1));
    LP_CHECK(FAILS(openat(lower, "../bin/layer-posix", O_WRONLY), EROFS));
    LP_CHECK(unlinkat(lower, "w-new2", 0) == 0);
    close(merged);
    close(lower);
    /* A path against a descriptor of a directory below /tmp, through a link into the root: the write
     * is the layer's own. */
    LP_CHECK(mkdir("/tmp/wd", 0755) == 0 && symlink("/etc", "/tmp/wd/l") == 0);
    int td = open("/tmp/wd", O_RDONLY | O_DIRECTORY);
    LP_CHECK(td >= 0);
    fd = openat(td, "l/w-fd", O_CREAT | O_WRONLY, 0644);
    LP_CHECK(fd >= 0 && close(fd) == 0 && stat("/etc/w-fd", &st) == 0 && st.st_dev == LAYERED_DEVICE);
    LP_CHECK(unlinkat(td, "l/w-fd", 0) == 0 && FAILS(stat("/etc/w-fd", &st), ENOENT));
    close(td);
    LP_CHECK(unlink("/tmp/wd/l") == 0 && rmdir("/tmp/wd") == 0);
    /* The last file: its number, which the second boot compares with the numbers it makes. */
    fd = open("/etc/w-marker", O_CREAT | O_RDWR, 0644);
    LP_CHECK(fd >= 0 && fstat(fd, &st) == 0);
    char text[32];
    int n = snprintf(text, sizeof text, "%llx\n", (unsigned long long)st.st_ino);
    LP_CHECK(write(fd, text, (size_t)n) == n && close(fd) == 0);
    return 0;
}

/* ---- the second boot: the names the write phase left (the role "reread") ---- */

static int the_names_made_are_kept(void) {
    struct stat st;
    LP_CHECK(has_bytes("/etc/w-over", WRITE_BYTES));
    LP_CHECK(stat("/etc/w-over", &st) == 0 && (st.st_mode & 07777) == 0640 && st.st_uid == 0);
    LP_CHECK(has_bytes("/etc/w-full/g", "g\n") && has_bytes("/many/w-f", "d1f\n"));
    LP_CHECK(has_bytes("/many/w-a/f", "deep\n") && has_bytes("/plain/x", "x\n"));
    /* "sho" of the truncation and the byte the other user appended. */
    LP_CHECK(has_bytes("/etc/layer-own", "shou") && stat("/etc/layer-own", &st) == 0);
    LP_CHECK(st.st_uid == 1000 && st.st_gid == 1000 && (st.st_mode & 07777) == 0640);
    LP_CHECK(stat("/etc/w-d2", &st) == 0 && S_ISDIR(st.st_mode) && (st.st_mode & 07777) == 0755);
    LP_CHECK(listed("/etc", "w-over", 1) && listed("/etc", "w-moved", 0) && listed("/etc", "w-new", 0));
    LP_CHECK(stat("/lowpriv", &st) == 0 && (st.st_mode & 07777) == 0700);
    LP_CHECK(listed("/lowpriv", "f", 1) && listed("/lowpriv", "sub", 1) && listed("/lowpriv", "w-new2", 0));
    LP_CHECK(has_bytes("/lowpriv/f", "lower closed\n"));
    return 0;
}

static int the_names_deleted_stay_deleted(void) {
    struct stat st;
    LP_CHECK(FAILS(stat("/etc/layer-note", &st), ENOENT) && FAILS(stat("/etc/layer-lower", &st), ENOENT));
    LP_CHECK(FAILS(open("/lower/keep", O_RDONLY), ENOENT) && FAILS(open("/lower/shadowed", O_RDONLY), ENOENT));
    LP_CHECK(FAILS(open("/etc/layer-hidden", O_RDONLY), ENOENT));
    LP_CHECK(listed("/etc", "layer-note", 0) && listed("/etc", "layer-lower", 0) && listed("/etc", "w-ll", 1));
    LP_CHECK(has_bytes("/etc/w-ll", "recreated\n"));
    LP_CHECK(listed("/lower", "keep", 0) && listed("/lower", "shadowed", 0) && listed("/lower", "hidden", 0));
    LP_CHECK(listed("/lower", "ln", 1) && listed("/lower", "w-rel", 1));
    LP_CHECK(listed("/etc", ".wh.layer-lower", 0) && listed("/etc", ".wh.layer-note", 0));
    LP_CHECK(FAILS(stat("/etc/w-d1", &st), ENOENT));
    return 0;
}

static int the_directory_made_over_a_removed_one_is_opaque(void) {
    struct stat st;
    struct names l;
    LP_CHECK(stat("/plain", &st) == 0 && (st.st_mode & 07777) == 0711);
    DIR *d = opendir("/plain");
    LP_CHECK(d != NULL && collect(d, &l) == 0 && occurrences(&l, "x") == 1 && l.count == 3 && closedir(d) == 0);
    LP_CHECK(FAILS(open("/plain/a", O_RDONLY), ENOENT) && FAILS(open("/plain/c", O_RDONLY), ENOENT));
    return 0;
}

static int the_links_are_kept(void) {
    char buf[64];
    struct stat st;
    LP_CHECK(readlink("/w-dlink", buf, sizeof buf) == 4 && memcmp(buf, "/etc", 4) == 0);
    LP_CHECK(lstat("/w-dlink", &st) == 0 && S_ISLNK(st.st_mode));
    LP_CHECK(has_bytes("/w-dlink/layer-world", "for everyone\n"));
    LP_CHECK(readlink("/lower/w-rel", buf, sizeof buf) == 18 && has_bytes("/lower/w-rel", "for everyone\n"));
    LP_CHECK(has_bytes("/many/w-ll", "recreated\n"));
    struct names l;
    DIR *d = opendir("/");
    LP_CHECK(d != NULL && collect(d, &l) == 0 && type_of(&l, "w-dlink") == DT_LNK && closedir(d) == 0);
    LP_CHECK(!exists("/etc/w-link") && !exists("/etc/w-a") && !exists("/etc/w-tmp"));
    return 0;
}

static int the_numbers_go_on_and_the_owners_are_kept(void) {
    struct stat st, mark;
    char text[32];
    LP_CHECK(read_file("/etc/w-marker", text, sizeof text) > 0);
    unsigned long long old = strtoull(text, NULL, 16);
    LP_CHECK(stat("/etc/w-marker", &mark) == 0 && (unsigned long long)mark.st_ino == old);
    LP_CHECK(put_file("/etc/w-after", "after\n", 0644) == 0);
    LP_CHECK(stat("/etc/w-after", &st) == 0 && (st.st_ino >> 62) == 1 && st.st_ino > old);
    LP_CHECK(stat("/etc/w-over", &st) == 0 && (unsigned long long)st.st_ino != old && (st.st_ino >> 62) == 1);
    LP_CHECK(stat("/world/rootfile", &st) == 0 && st.st_uid == 0 && exists("/world/rootdir"));
    LP_CHECK(unlink("/etc/w-after") == 0);
    return 0;
}

/* ---- the run ---- */

static int failures;

static void run_check(const char *name, int (*check)(void)) {
    int code = check();
    if (code == 0) {
        printf("layer-posix: %s ok\n", name);
    } else {
        printf("layer-posix: %s FAILED\n", name);
        failures++;
    }
}

/* The directory `/.layers` of the data volume is the layer service's: the superuser of a program
 * does not see it through /data either (the data file service answers as if it were not there),
 * so no layer is written past the index of the layer service. */
static int layers_directory_is_hidden(void) {
    struct stat st;
    LP_CHECK(FAILS(stat("/data/.layers", &st), ENOENT));
    LP_CHECK(FAILS(stat("/data/.layers/00", &st), ENOENT));
    LP_CHECK(FAILS(open("/data/.layers/COMPOSITION", O_RDONLY), ENOENT));
    LP_CHECK(FAILS(mkdir("/data/.layers/x", 0755), ENOENT));
    LP_CHECK(FAILS(unlink("/data/.layers/COMPOSITION"), ENOENT));
    LP_CHECK(FAILS(rename("/data/.layers/COMPOSITION", "/data/taken"), ENOENT));
    DIR *d = opendir("/data");
    LP_CHECK(d != NULL);
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        LP_CHECK(strcmp(e->d_name, ".layers") != 0);
    }
    closedir(d);
    return 0;
}

static int first(void) {
    /* The program has no session with the layer service until its first path call. */
    if (lp_session() != 0) {
        printf("layer-posix: the program started with a session\n");
        failures++;
    }
    run_check("a file of the layer of the user is read", upper_file);
    run_check("a lower file is read", lower_file);
    run_check("a name of the layer shadows the lower one", shadow_and_keep);
    run_check("the names the layer deletes are gone", deleted_names);
    run_check("stat of paths and the layered device", stat_of_paths);
    run_check("access and readlink", access_and_links);
    run_check("a merged directory is listed once", merged_listing);
    run_check("a lower directory is listed", lower_listing);
    run_check("a listing goes on over empty replies", listing_over_empty_replies);
    run_check("an opaque directory lists its own names", opaque_directory);
    run_check("paths against a merged directory", paths_against_a_merged_directory);
    run_check("paths against a lower directory", paths_against_a_lower_directory);
    run_check("the pass-through names are the services' own", pass_through_names);
    run_check("a path out of a pass-through directory is the root's", dotdot_out_of_tmp);
    run_check("a link below a pass-through directory is routed through the layer", link_below_a_pass_through_directory);
    run_check("chdir and fchdir", current_directory);
    run_check("realpath", real_paths);
    run_check("a forked child shares the directory description", fork_shares_the_description);
    run_check("a spawned program keeps the directory description", spawn_shares_the_description);
    run_check("an exec keeps the directory description", exec_keeps_the_description);
    run_check("programs of the layers", programs_of_the_layers);
    run_check("a forked child binds its own identity", fork_binds_its_own_identity);
    run_check("rights of another user", rights_of_another_user);
    run_check("writes to the lower set are refused", writes_to_the_lower_set_are_refused);
    run_check("the attributes of descriptions are kept", attributes_of_descriptions);
    run_check("a lower link leads through the merged view", lower_links);
    run_check("descriptions keep the device across fork and exec", device_across_fork_and_exec);
    run_check("a description of the service has no path after exec", no_path_after_exec);
    run_check("a set-ID program is given the service's session", slot_checks);
    run_check("a set-ID program keeps the genuine session and binds it", setid_keeps_the_genuine_session);
    run_check("the directory of the layers is hidden from programs", layers_directory_is_hidden);
    if (failures != 0) {
        printf("layer-posix: %d checks failed\n", failures);
        return 20;
    }
    printf("layer-posix: checks passed\n");
    return 0;
}

static int write_first(void) {
    if (lp_session() != 0) {
        printf("layer-posix: the program started with a session\n");
        failures++;
    }
    run_check("a file is created and written", created_file);
    run_check("a file of the layer is rewritten", rewritten_file);
    run_check("directories are made and removed", directories);
    run_check("names are deleted from the layer and from the lower set", deletions);
    run_check("directories are removed and made again opaque", removed_directories);
    run_check("an opaque directory removed or moved stays removed", opaque_directory_stays_removed);
    run_check("names are renamed inside the layer", renames);
    run_check("symbolic links of the layer", symbolic_links);
    run_check("hard links, reserved names and long paths", reserved_names_and_limits);
    run_check("the rights of another user on the layer", rights_of_another_user_on_the_layer);
    run_check("a sticky directory is kept", a_sticky_directory_is_kept);
    run_check("a program of the lower set is not written", the_lower_set_is_not_written);
    run_check("changes against descriptions", changes_against_descriptions);
    if (failures != 0) {
        printf("layer-posix: %d checks failed\n", failures);
        return 20;
    }
    printf("layer-posix: write checks passed\n");
    return 0;
}

static int reread_first(void) {
    run_check("the names made are kept", the_names_made_are_kept);
    run_check("the names deleted stay deleted", the_names_deleted_stay_deleted);
    run_check("a directory made over a removed one is opaque", the_directory_made_over_a_removed_one_is_opaque);
    run_check("the links are kept", the_links_are_kept);
    run_check("the numbers go on and the owners are kept", the_numbers_go_on_and_the_owners_are_kept);
    if (failures != 0) {
        printf("layer-posix: %d checks failed\n", failures);
        return 20;
    }
    printf("layer-posix: reread checks passed\n");
    return 0;
}

/* ---- the copy phase: a lower file is copied up when it is written (the roles "copy" and
 * "copyreread") ----
 *
 * The lower set of this image has the directory /copyup (xtask layer_posix::copy_lower_files). The
 * layer service answers a write of a file of it COPYING, a worker thread copies the file, and the
 * program's layer waits and asks again: the program sees an open (or a chmod) that takes the time
 * of the copy and then works. The number and the device of the file stay those of the lower file, and
 * so do its owner, mode and times. The lines "layer-posix: marker <name>" tell the xtask where a
 * read open and two writers lie among the lines of the layer service, which counts its copies. */

#define BIG_BYTES (16UL << 20)
#define TWO_BYTES (3UL << 20)
#define BIG_BYTE(i) ((unsigned char)(((i) * 7 + ((i) >> 12)) | 1))

/* The numbers the copy phase saw after the copies, which the second boot compares. */
#define NUMBERED 8
static const char *numbered_paths[NUMBERED] = {
    "/copyup/append", "/copyup/attrs",  "/copyup/trunc", "/copyup/chmod",
    "/copyup/chown",  "/copyup/utime",  "/copyup/dir",   "/copyup/link",
};

static int same_attributes(const struct stat *a, const struct stat *b) {
    return a->st_mode == b->st_mode && a->st_uid == b->st_uid && a->st_gid == b->st_gid &&
           a->st_ino == b->st_ino && a->st_dev == b->st_dev;
}

static int same_times(const struct stat *a, const struct stat *b) {
    return a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec;
}

static int copy_of_a_written_file(void) {
    struct stat before, after;
    LP_CHECK(stat("/copyup/append", &before) == 0 && before.st_dev == LAYERED_DEVICE);
    LP_CHECK(has_bytes("/copyup/append", "lower line\n"));
    int fd = open("/copyup/append", O_WRONLY | O_APPEND);
    LP_CHECK(fd >= 0 && write(fd, "added\n", 6) == 6 && close(fd) == 0);
    LP_CHECK(has_bytes("/copyup/append", "lower line\nadded\n"));
    LP_CHECK(stat("/copyup/append", &after) == 0 && after.st_size == 17);
    LP_CHECK(same_attributes(&before, &after));
    /* The copy is the layer's file now: the next write needs no copy and the number is the same. */
    fd = open("/copyup/append", O_RDWR);
    LP_CHECK(fd >= 0 && fstat(fd, &after) == 0 && after.st_ino == before.st_ino && close(fd) == 0);
    return 0;
}

static int the_copy_keeps_the_attributes(void) {
    struct stat before, after;
    LP_CHECK(stat("/copyup/attrs", &before) == 0);
    LP_CHECK((before.st_mode & 07777) == 0751 && before.st_uid == 1001 && before.st_gid == 102);
    /* The change of nothing that has to copy the file all the same. */
    LP_CHECK(chown("/copyup/attrs", (uid_t)-1, (gid_t)-1) == 0);
    LP_CHECK(stat("/copyup/attrs", &after) == 0);
    LP_CHECK(same_attributes(&before, &after) && same_times(&before, &after));
    LP_CHECK(after.st_size == before.st_size && has_bytes("/copyup/attrs", "attrs bytes\n"));
    return 0;
}

static int a_cut_open_makes_an_empty_copy(void) {
    struct stat before, after;
    LP_CHECK(stat("/copyup/trunc", &before) == 0 && before.st_size == 10);
    LP_CHECK((before.st_mode & 07777) == 0600 && before.st_uid == 1000 && before.st_gid == 100);
    int fd = open("/copyup/trunc", O_WRONLY | O_TRUNC);
    LP_CHECK(fd >= 0 && close(fd) == 0);
    LP_CHECK(stat("/copyup/trunc", &after) == 0 && after.st_size == 0);
    LP_CHECK(same_attributes(&before, &after));
    LP_CHECK(has_bytes("/copyup/trunc", ""));
    fd = open("/copyup/trunc", O_WRONLY);
    LP_CHECK(fd >= 0 && write(fd, "new\n", 4) == 4 && close(fd) == 0);
    LP_CHECK(has_bytes("/copyup/trunc", "new\n"));
    return 0;
}

static int changes_of_a_lower_file(void) {
    struct stat before, after;
    struct timespec times[2] = {{5, 0}, {6, 0}};
    LP_CHECK(stat("/copyup/chmod", &before) == 0);
    LP_CHECK(chmod("/copyup/chmod", 0600) == 0);
    LP_CHECK(stat("/copyup/chmod", &after) == 0 && (after.st_mode & 07777) == 0600);
    LP_CHECK(after.st_ino == before.st_ino && after.st_uid == before.st_uid);
    LP_CHECK(has_bytes("/copyup/chmod", "chmod me\n"));
    LP_CHECK(stat("/copyup/chown", &before) == 0 && chown("/copyup/chown", 1002, 103) == 0);
    LP_CHECK(stat("/copyup/chown", &after) == 0 && after.st_uid == 1002 && after.st_gid == 103);
    LP_CHECK(after.st_ino == before.st_ino && (after.st_mode & 07777) == (before.st_mode & 07777));
    LP_CHECK(has_bytes("/copyup/chown", "chown me\n"));
    LP_CHECK(stat("/copyup/utime", &before) == 0 && utimensat(AT_FDCWD, "/copyup/utime", times, 0) == 0);
    LP_CHECK(stat("/copyup/utime", &after) == 0 && after.st_atim.tv_sec == 5 && after.st_mtim.tv_sec == 6);
    LP_CHECK(after.st_ino == before.st_ino && has_bytes("/copyup/utime", "utime\n"));
    LP_CHECK(stat("/copyup/trunc2", &before) == 0 && truncate("/copyup/trunc2", 4) == 0);
    LP_CHECK(stat("/copyup/trunc2", &after) == 0 && after.st_size == 4 && after.st_ino == before.st_ino);
    LP_CHECK(has_bytes("/copyup/trunc2", "trun"));
    return 0;
}

static int changes_of_a_lower_directory(void) {
    struct stat before, after;
    struct timespec times[2] = {{7, 0}, {8, 0}};
    LP_CHECK(stat("/copyup/dir", &before) == 0 && S_ISDIR(before.st_mode));
    LP_CHECK((before.st_mode & 07777) == 0750 && before.st_uid == 1000 && before.st_gid == 100);
    LP_CHECK(chmod("/copyup/dir", 0700) == 0);
    LP_CHECK(stat("/copyup/dir", &after) == 0 && (after.st_mode & 07777) == 0700);
    LP_CHECK(after.st_ino == before.st_ino && after.st_dev == before.st_dev);
    LP_CHECK(chown("/copyup/dir", 1003, 104) == 0 && utimensat(AT_FDCWD, "/copyup/dir", times, 0) == 0);
    LP_CHECK(stat("/copyup/dir", &after) == 0 && after.st_uid == 1003 && after.st_gid == 104);
    LP_CHECK(after.st_ino == before.st_ino && after.st_mtim.tv_sec == 8);
    /* No content moved: the lower names still show through the directory of the layer. */
    DIR *d = opendir("/copyup/dir");
    LP_CHECK(d != NULL);
    struct names n;
    LP_CHECK(collect(d, &n) == 0);
    closedir(d);
    int seen = 0;
    for (int i = 0; i < n.count; i++) {
        if (strcmp(n.name[i], "in") == 0) seen++;
    }
    LP_CHECK(seen == 1 && has_bytes("/copyup/dir/in", "inside\n"));
    return 0;
}

static int lchown_of_a_lower_link(void) {
    struct stat before, after;
    char text[16];
    LP_CHECK(lstat("/copyup/link", &before) == 0 && S_ISLNK(before.st_mode));
    LP_CHECK(lchown("/copyup/link", 1005, 106) == 0);
    LP_CHECK(lstat("/copyup/link", &after) == 0 && S_ISLNK(after.st_mode));
    LP_CHECK(after.st_uid == 1005 && after.st_gid == 106 && after.st_ino == before.st_ino);
    LP_CHECK(readlink("/copyup/link", text, sizeof text) == 6 && memcmp(text, "append", 6) == 0);
    return 0;
}

static int a_lower_program_is_never_copied_and_still_runs(void) {
    struct stat st;
    LP_CHECK(FAILS(open("/bin/layer-posix", O_WRONLY | O_APPEND), EROFS));
    LP_CHECK(FAILS(open("/bin/layer-posix", O_WRONLY | O_TRUNC), EROFS));
    LP_CHECK(FAILS(chmod("/bin/layer-posix", 0644), EROFS));
    LP_CHECK(FAILS(chown("/bin/layer-posix", 1, 1), EROFS));
    LP_CHECK(FAILS(truncate("/bin/layer-posix", 0), EROFS));
    LP_CHECK(stat("/bin/layer-posix", &st) == 0 && st.st_dev == LAYERED_DEVICE && st.st_size > 4096);
    LP_CHECK((st.st_mode & 07777) == 0755);
    pid_t pid = 0;
    char *argv[] = {"layer-posix", "exit0", NULL};
    LP_CHECK(posix_spawn(&pid, "/bin/layer-posix", NULL, NULL, argv, environ) == 0);
    LP_CHECK(wait_ok(pid) == 0);
    return 0;
}

static int a_read_open_copies_nothing(void) {
    struct stat st;
    char buf[32];
    printf("layer-posix: marker read-begin\n");
    int fd = open("/copyup/read", O_RDONLY);
    LP_CHECK(fd >= 0 && read(fd, buf, sizeof buf) == 10 && memcmp(buf, "read only\n", 10) == 0);
    LP_CHECK(close(fd) == 0);
    LP_CHECK(stat("/copyup/read", &st) == 0 && access("/copyup/read", R_OK) == 0);
    LP_CHECK(has_bytes("/copyup/read", "read only\n") && lstat("/copyup/link", &st) == 0);
    DIR *d = opendir("/copyup");
    LP_CHECK(d != NULL);
    struct names n;
    LP_CHECK(collect(d, &n) == 0 && n.count >= 10);
    closedir(d);
    printf("layer-posix: marker read-end\n");
    return 0;
}

static int two_writers_of_one_file_make_one_copy(void) {
    int gate[2];
    LP_CHECK(pipe(gate) == 0);
    printf("layer-posix: marker two-begin\n");
    pid_t pid = fork();
    LP_CHECK(pid >= 0);
    if (pid == 0) {
        char go;
        if (read(gate[0], &go, 1) != 1) _exit(1);
        int fd = open("/copyup/two", O_WRONLY | O_APPEND);
        if (fd < 0 || write(fd, "child\n", 6) != 6 || close(fd) != 0) _exit(2);
        _exit(0);
    }
    LP_CHECK(write(gate[1], "g", 1) == 1);
    int fd = open("/copyup/two", O_WRONLY | O_APPEND);
    LP_CHECK(fd >= 0 && write(fd, "parent\n", 7) == 7 && close(fd) == 0);
    LP_CHECK(wait_ok(pid) == 0);
    printf("layer-posix: marker two-end\n");
    close(gate[0]);
    close(gate[1]);
    /* Both lines are there, whole, after the 3 MiB of the lower file. */
    struct stat st;
    LP_CHECK(stat("/copyup/two", &st) == 0 && st.st_size == (off_t)(TWO_BYTES + 13));
    char tail[16];
    fd = open("/copyup/two", O_RDONLY);
    LP_CHECK(fd >= 0 && pread(fd, tail, 13, (off_t)TWO_BYTES) == 13 && close(fd) == 0);
    tail[13] = 0;
    LP_CHECK(strcmp(tail, "child\nparent\n") == 0 || strcmp(tail, "parent\nchild\n") == 0);
    return 0;
}

static volatile sig_atomic_t alarmed;
static void on_alarm(int sig) {
    (void)sig;
    alarmed++;
}

/* The first byte of the file and a byte after its middle are the lower file's. */
static int is_the_big_file(const char *path) {
    unsigned char b[2];
    struct stat st;
    if (stat(path, &st) != 0 || st.st_size != (off_t)BIG_BYTES) return 0;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    int ok = pread(fd, b, 1, 0) == 1 && b[0] == BIG_BYTE(0) &&
             pread(fd, b + 1, 1, (off_t)(BIG_BYTES / 2 + 5)) == 1 && b[1] == BIG_BYTE(BIG_BYTES / 2 + 5);
    close(fd);
    return ok;
}

/* A signal during the wait for the copy of 16 MiB (the copy takes the time of the disk, the timer
 * fires at 200 ms): without SA_RESTART the open ends with EINTR and the copy goes on in the layer
 * service (the open asked again takes the copy that is there); with SA_RESTART the open goes on and
 * returns the descriptor. */
static int a_signal_during_the_wait(const char *path, int restart) {
    struct sigaction sa;
    struct sigevent ev;
    struct itimerspec timer = {{0, 0}, {0, 200000000}};
    struct itimerspec off = {{0, 0}, {0, 0}};
    timer_t clock_timer;
    memset(&sa, 0, sizeof sa);
    memset(&ev, 0, sizeof ev);
    ev.sigev_notify = SIGEV_SIGNAL;
    ev.sigev_signo = SIGALRM;
    sa.sa_handler = on_alarm;
    sa.sa_flags = restart ? SA_RESTART : 0;
    sigemptyset(&sa.sa_mask);
    LP_CHECK(sigaction(SIGALRM, &sa, NULL) == 0);
    alarmed = 0;
    LP_CHECK(timer_create(CLOCK_MONOTONIC, &ev, &clock_timer) == 0);
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    LP_CHECK(timer_settime(clock_timer, 0, &timer, NULL) == 0);
    int fd = open(path, O_WRONLY | O_APPEND);
    int err = errno;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("layer-posix: the open of the file of 16 MiB took %ld ms\n", (long)((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000));
    timer_settime(clock_timer, 0, &off, NULL);
    timer_delete(clock_timer);
    if (restart) {
        if (fd < 0) printf("layer-posix: the open ended with errno %d\n", err);
        LP_CHECK(fd >= 0 && alarmed >= 1);
    } else {
        if (fd >= 0 || err != EINTR) printf("layer-posix: the open gave %d, errno %d\n", fd, err);
        LP_CHECK(fd == -1 && err == EINTR && alarmed == 1);
        fd = open(path, O_WRONLY | O_APPEND);
        LP_CHECK(fd >= 0);
    }
    /* The file is not written: its size is past the limit of a program's writes (SIGXFSZ). */
    LP_CHECK(close(fd) == 0);
    LP_CHECK(is_the_big_file(path));
    return 0;
}

static int signal_without_restart(void) {
    return a_signal_during_the_wait("/copyup/big1", 0);
}

static int signal_with_restart(void) {
    return a_signal_during_the_wait("/copyup/big2", 1);
}

/* The numbers of the copies go to a file of the layer for the second boot. */
static int the_numbers_are_kept(void) {
    char text[NUMBERED * 48];
    size_t at = 0;
    for (int i = 0; i < NUMBERED; i++) {
        struct stat st;
        LP_CHECK(lstat(numbered_paths[i], &st) == 0 && st.st_dev == LAYERED_DEVICE);
        at += (size_t)snprintf(text + at, sizeof text - at, "%s %llx\n", numbered_paths[i], (unsigned long long)st.st_ino);
    }
    int fd = open("/etc/copy-numbers", O_CREAT | O_WRONLY | O_EXCL, 0644);
    LP_CHECK(fd >= 0 && write(fd, text, at) == (ssize_t)at && close(fd) == 0);
    return 0;
}

static int copy_first(void) {
    if (lp_session() != 0) {
        printf("layer-posix: the program started with a session\n");
        failures++;
    }
    run_check("a lower file that is written is copied up", copy_of_a_written_file);
    run_check("the copy keeps the owner, the mode, the times and the number", the_copy_keeps_the_attributes);
    run_check("a cut open makes an empty copy with the lower attributes", a_cut_open_makes_an_empty_copy);
    run_check("chmod, chown, utimensat and truncate of a lower file copy it up", changes_of_a_lower_file);
    run_check("chmod, chown and utimensat of a lower directory keep its number", changes_of_a_lower_directory);
    run_check("lchown of a lower link copies the link", lchown_of_a_lower_link);
    run_check("a lower program is never copied up and still runs", a_lower_program_is_never_copied_and_still_runs);
    run_check("a read open copies nothing", a_read_open_copies_nothing);
    run_check("two writers of one file make one copy", two_writers_of_one_file_make_one_copy);
    run_check("a signal during the wait of a copy is EINTR without SA_RESTART", signal_without_restart);
    run_check("a signal during the wait of a copy goes on with SA_RESTART", signal_with_restart);
    run_check("the numbers of the copies are kept", the_numbers_are_kept);
    if (failures != 0) {
        printf("layer-posix: %d checks failed\n", failures);
        return 20;
    }
    printf("layer-posix: copy checks passed\n");
    return 0;
}

/* The second boot: the copies are the layer's, with the numbers they had, and what they hold. */
static int the_copies_are_kept(void) {
    char text[NUMBERED * 48 + 1];
    long n = read_file("/etc/copy-numbers", text, sizeof text);
    LP_CHECK(n > 0);
    char *line = text;
    for (int i = 0; i < NUMBERED; i++) {
        char *end = strchr(line, '\n');
        LP_CHECK(end != NULL);
        *end = 0;
        char *space = strrchr(line, ' ');
        LP_CHECK(space != NULL);
        *space = 0;
        LP_CHECK(strcmp(line, numbered_paths[i]) == 0);
        unsigned long long ino = strtoull(space + 1, NULL, 16);
        struct stat st;
        LP_CHECK(lstat(line, &st) == 0 && st.st_dev == LAYERED_DEVICE);
        if ((unsigned long long)st.st_ino != ino) printf("layer-posix: %s has number %llx, was %llx\n", line, (unsigned long long)st.st_ino, ino);
        LP_CHECK((unsigned long long)st.st_ino == ino);
        line = end + 1;
    }
    struct stat st;
    LP_CHECK(has_bytes("/copyup/append", "lower line\nadded\n") && has_bytes("/copyup/trunc", "new\n"));
    LP_CHECK(has_bytes("/copyup/chmod", "chmod me\n") && has_bytes("/copyup/trunc2", "trun"));
    LP_CHECK(stat("/copyup/attrs", &st) == 0 && (st.st_mode & 07777) == 0751 && st.st_uid == 1001);
    LP_CHECK(stat("/copyup/chmod", &st) == 0 && (st.st_mode & 07777) == 0600);
    LP_CHECK(stat("/copyup/dir", &st) == 0 && (st.st_mode & 07777) == 0700 && st.st_uid == 1003);
    LP_CHECK(lstat("/copyup/link", &st) == 0 && st.st_uid == 1005 && S_ISLNK(st.st_mode));
    LP_CHECK(is_the_big_file("/copyup/big1") && is_the_big_file("/copyup/big2"));
    /* The directory of the layer shows its lower name still. */
    LP_CHECK(has_bytes("/copyup/dir/in", "inside\n"));
    /* A file that is already the layer's is written without a copy. */
    int fd = open("/copyup/append", O_WRONLY | O_APPEND);
    LP_CHECK(fd >= 0 && write(fd, "again\n", 6) == 6 && close(fd) == 0);
    LP_CHECK(has_bytes("/copyup/append", "lower line\nadded\nagain\n"));
    return 0;
}

static int copyreread_first(void) {
    run_check("the copies are the layer's with the numbers they had", the_copies_are_kept);
    if (failures != 0) {
        printf("layer-posix: %d checks failed\n", failures);
        return 20;
    }
    printf("layer-posix: copy reread checks passed\n");
    return 0;
}

/* The program init starts has no code in its map to copy, so it cannot fork (the layer answers
 * ENOSYS); a program the loader starts can. The first role is therefore a launcher: it starts the
 * program from /bin with posix_spawn and passes on how it ended. */
static int launcher(void) {
    char *argv[] = {"layer-posix", LAYER_POSIX_MODE, NULL};
    pid_t pid = 0;
    int code = posix_spawn(&pid, "/bin/layer-posix", NULL, NULL, argv, environ);
    if (code != 0) {
        printf("layer-posix: the launcher could not start /bin/layer-posix (error %d)\n", code);
        return 20;
    }
    int status = wait_ok(pid);
    if (status != 0) printf("layer-posix: the program ended with %d\n", status);
    return status == 0 ? 0 : 20;
}

int main(int argc, char **argv) {
    if (argc > 2 && strcmp(argv[1], "child-list") == 0) return child_list(argv);
    if (argc > 1 && strcmp(argv[1], "exit0") == 0) return 0;
    if (argc > 3 && strcmp(argv[1], "dev-child") == 0) return dev_child(argv);
    if (argc > 2 && strcmp(argv[1], "nopath-child") == 0) return nopath_child(argv);
    if (argc > 1 && strcmp(argv[1], "forged") == 0) return forged_role();
    if (argc > 1 && strcmp(argv[1], "setid") == 0) return setid_role();
    if (argc > 2 && strcmp(argv[1], "genuine") == 0) return genuine_role(argv);
    if (argc > 1 && strcmp(argv[1], "run") == 0) return first();
    if (argc > 1 && strcmp(argv[1], "write") == 0) return write_first();
    if (argc > 1 && strcmp(argv[1], "reread") == 0) return reread_first();
    if (argc > 1 && strcmp(argv[1], "copy") == 0) return copy_first();
    if (argc > 1 && strcmp(argv[1], "copyreread") == 0) return copyreread_first();
    return launcher();
}
