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
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
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

/* The names a listing of /etc must have: the layer's and the lower set's, each once, and not the
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
     * is the root's, not the RAM file service's. */
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
    LP_CHECK(FAILS(access("/etc/layer-own", W_OK), EROFS));
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

static int writes_are_refused(void) {
    struct stat st;
    LP_CHECK(FAILS(open("/etc/layer-lower", O_WRONLY), EROFS));
    LP_CHECK(FAILS(open("/etc/layer-lower", O_RDWR), EROFS));
    LP_CHECK(FAILS(open("/etc/layer-own", O_WRONLY), EROFS));
    LP_CHECK(FAILS(open("/etc/layer-lower", O_RDONLY | O_TRUNC), EROFS));
    LP_CHECK(FAILS(open("/etc/newfile", O_CREAT | O_WRONLY, 0644), EROFS));
    LP_CHECK(FAILS(open("/newtop", O_CREAT | O_WRONLY, 0644), EROFS));
    LP_CHECK(FAILS(mkdir("/etc/newdir", 0755), EROFS));
    LP_CHECK(FAILS(mkdir("/newdir", 0755), EROFS));
    LP_CHECK(FAILS(unlink("/etc/layer-lower"), EROFS));
    LP_CHECK(FAILS(rename("/etc/layer-lower", "/etc/renamed"), EROFS));
    LP_CHECK(FAILS(rename("/etc/layer-lower", "/tmp/renamed"), EROFS));
    LP_CHECK(FAILS(chmod("/etc/layer-lower", 0600), EROFS));
    LP_CHECK(FAILS(truncate("/etc/layer-lower", 0), EROFS));
    LP_CHECK(FAILS(symlink("/etc/layer-lower", "/etc/lnk"), EROFS));
    LP_CHECK(FAILS(link("/etc/layer-lower", "/etc/hard"), EROFS));
    /* A path against a description of a directory is refused as well. */
    int merged = open("/etc", O_RDONLY | O_DIRECTORY);
    int lower = open("/plain", O_RDONLY | O_DIRECTORY);
    LP_CHECK(merged >= 0 && lower >= 0);
    LP_CHECK(FAILS(openat(merged, "n", O_CREAT | O_WRONLY, 0644), EROFS));
    LP_CHECK(FAILS(openat(lower, "n", O_CREAT | O_WRONLY, 0644), EROFS));
    LP_CHECK(FAILS(openat(lower, "a", O_WRONLY), EROFS));
    LP_CHECK(FAILS(unlinkat(lower, "a", 0), EROFS));
    LP_CHECK(FAILS(mkdirat(lower, "d", 0755), EROFS));
    close(merged);
    close(lower);
    /* Nothing was written below the layers. */
    LP_CHECK(has_bytes("/etc/layer-lower", "lower of etc\n") && has_bytes("/plain/a", "a\n"));
    LP_CHECK(stat("/etc/layer-lower", &st) == 0 && (st.st_mode & 07777) == 0644);
    LP_CHECK(FAILS(stat("/etc/newfile", &st), ENOENT) && FAILS(stat("/etc/newdir", &st), ENOENT));
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
 * description the parent holds, and the session is bound to the program's identity, not the
 * parent's: the effective user 1000 is refused what the superuser parent reads. */
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
    run_check("chdir and fchdir", current_directory);
    run_check("realpath", real_paths);
    run_check("a forked child shares the directory description", fork_shares_the_description);
    run_check("a spawned program keeps the directory description", spawn_shares_the_description);
    run_check("an exec keeps the directory description", exec_keeps_the_description);
    run_check("programs of the layers", programs_of_the_layers);
    run_check("a forked child binds its own identity", fork_binds_its_own_identity);
    run_check("rights of another user", rights_of_another_user);
    run_check("writes are refused", writes_are_refused);
    run_check("a set-ID program is given the service's session", slot_checks);
    run_check("a set-ID program keeps the genuine session and binds it", setid_keeps_the_genuine_session);
    if (failures != 0) {
        printf("layer-posix: %d checks failed\n", failures);
        return 20;
    }
    printf("layer-posix: checks passed\n");
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
    if (argc > 1 && strcmp(argv[1], "forged") == 0) return forged_role();
    if (argc > 1 && strcmp(argv[1], "setid") == 0) return setid_role();
    if (argc > 2 && strcmp(argv[1], "genuine") == 0) return genuine_role(argv);
    if (argc > 1 && strcmp(argv[1], "run") == 0) return first();
    return launcher();
}
