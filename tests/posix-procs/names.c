/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
/* The functions of the names and metadata (5i-5): each with the result seen
 * through lstat, readlink, access or fstatat before and after, and each error
 * of its row. Included by files.c; the process runs as the superuser and
 * switches its effective user where a row needs an unprivileged caller. */
#include <dirent.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/statvfs.h>

#define NAMES_ROOT "/tmp/nm"

/* The line of the failed check is the code of the failure. */
#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                    \
            printf("names.c:%d: %s (errno %d)\n", __LINE__, #condition, errno); \
            return __LINE__;                                                   \
        }                                                                      \
    } while (0)
/* A call that fails with `code`. */
#define FAILS(call, code)                                                      \
    do {                                                                       \
        errno = 0;                                                             \
        long long got_ = (long long)(call);                                    \
        if (got_ != -1 || errno != (code)) {                                   \
            printf("names.c:%d: %s gave %lld errno %d, wanted -1 and %d\n",    \
                   __LINE__, #call, got_, errno, (int)(code));                 \
            return __LINE__;                                                   \
        }                                                                      \
    } while (0)
#define OK(call)                                                               \
    do {                                                                       \
        errno = 0;                                                             \
        long long got_ = (long long)(call);                                    \
        if (got_ == -1) {                                                      \
            printf("names.c:%d: %s failed with errno %d\n", __LINE__, #call,   \
                   errno);                                                     \
            return __LINE__;                                                   \
        }                                                                      \
    } while (0)

static long long names_ns(struct timespec t) {
    return (long long)t.tv_sec * 1000000000LL + t.tv_nsec;
}

static void names_pause(void) {
    struct timespec delay = {0, 3000000};
    nanosleep(&delay, NULL);
}

/* A file with `text` in it, mode 0644 under the mask. */
static int names_put(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    size_t length = strlen(text);
    if ((size_t)write(fd, text, length) != length) {
        close(fd);
        return -1;
    }
    return close(fd);
}

/* The permission bits of `path` (lstat), or -1. */
static int names_mode(const char *path) {
    struct stat st;
    if (lstat(path, &st)) return -1;
    return (int)(st.st_mode & 07777);
}

static int names_exists(const char *path) {
    struct stat st;
    return lstat(path, &st) == 0;
}

/* The modification time of `directory` set to one second after the epoch,
 * ready to see move; the change time then is what the call left. */
static long long names_ctime_after_age;

static int names_age(const char *directory) {
    struct timespec old[2] = {{1, 0}, {1, 0}};
    struct stat st;
    if (utimensat(AT_FDCWD, directory, old, 0) || stat(directory, &st)) return -1;
    names_ctime_after_age = names_ns(st.st_ctim);
    names_pause();
    return 0;
}

/* Whether both the modification and the change time of `directory` moved
 * since names_age. */
static int names_aged(const char *directory) {
    struct stat st;
    if (stat(directory, &st)) return 0;
    return names_ns(st.st_mtim) != 1000000000LL && names_ns(st.st_ctim) > names_ctime_after_age;
}

static int names_unlink(void) {
    CHECK(names_put(NAMES_ROOT "/u1", "x") == 0);
    CHECK(names_age(NAMES_ROOT) == 0);
    OK(unlink(NAMES_ROOT "/u1"));
    CHECK(!names_exists(NAMES_ROOT "/u1"));
    CHECK(names_aged(NAMES_ROOT));
    FAILS(unlink(NAMES_ROOT "/u1"), ENOENT);
    OK(mkdir(NAMES_ROOT "/ud", 0755));
    /* A directory is no business of unlink, even for the superuser. */
    FAILS(unlink(NAMES_ROOT "/ud"), EPERM);
    CHECK(names_exists(NAMES_ROOT "/ud"));
    CHECK(names_put(NAMES_ROOT "/u2", "x") == 0);
    FAILS(unlink(NAMES_ROOT "/u2/"), ENOTDIR);
    CHECK(names_exists(NAMES_ROOT "/u2"));
    FAILS(unlinkat(AT_FDCWD, NAMES_ROOT "/u2", 7), EINVAL);
    FAILS(unlink(""), ENOENT);
    FAILS(unlink(NAMES_ROOT "/missing/x"), ENOENT);
    FAILS(unlink(NAMES_ROOT "/u2/x"), ENOTDIR);
    /* A failed unlink changes no time. */
    CHECK(names_age(NAMES_ROOT) == 0);
    FAILS(unlink(NAMES_ROOT "/ud"), EPERM);
    FAILS(unlink(NAMES_ROOT "/u1"), ENOENT);
    CHECK(!names_aged(NAMES_ROOT));
    /* A link that has others leaves them, and the ctime of the file moves. */
    OK(link(NAMES_ROOT "/u2", NAMES_ROOT "/u3"));
    struct stat before, after;
    OK(stat(NAMES_ROOT "/u2", &before));
    CHECK(before.st_nlink == 2);
    names_pause();
    OK(unlink(NAMES_ROOT "/u3"));
    OK(stat(NAMES_ROOT "/u2", &after));
    CHECK(after.st_nlink == 1 && names_ns(after.st_ctim) > names_ns(before.st_ctim));
    /* An open file lives on unlinked. */
    int fd = open(NAMES_ROOT "/u2", O_RDONLY);
    CHECK(fd >= 0);
    OK(unlink(NAMES_ROOT "/u2"));
    char byte;
    CHECK(read(fd, &byte, 1) == 1 && byte == 'x');
    CHECK(close(fd) == 0);
    OK(rmdir(NAMES_ROOT "/ud"));
    return 0;
}

static int names_rmdir_mkdir(void) {
    OK(mkdir(NAMES_ROOT "/d", 0777));
    /* The mask 022 cuts the mode. */
    CHECK(names_mode(NAMES_ROOT "/d") == 0755);
    FAILS(mkdir(NAMES_ROOT "/d", 0755), EEXIST);
    OK(symlink(NAMES_ROOT "/nowhere", NAMES_ROOT "/dangling"));
    FAILS(mkdir(NAMES_ROOT "/dangling", 0755), EEXIST);
    OK(mkdir(NAMES_ROOT "/d/e/", 0700));
    CHECK(names_mode(NAMES_ROOT "/d/e") == 0700);
    FAILS(mkdir(NAMES_ROOT "/missing/x", 0755), ENOENT);
    CHECK(names_put(NAMES_ROOT "/plain", "x") == 0);
    FAILS(mkdir(NAMES_ROOT "/plain/x", 0755), ENOTDIR);
    FAILS(mkdir("", 0755), ENOENT);
    /* The new directory has two links, its parent one more. */
    struct stat st;
    OK(stat(NAMES_ROOT "/d/e", &st));
    CHECK(S_ISDIR(st.st_mode) && st.st_nlink == 2);
    OK(stat(NAMES_ROOT "/d", &st));
    CHECK(st.st_nlink == 3);
    /* mkdirat from a descriptor. */
    int dirfd = open(NAMES_ROOT "/d", O_RDONLY | O_DIRECTORY);
    CHECK(dirfd >= 0);
    OK(mkdirat(dirfd, "f", 0755));
    CHECK(names_exists(NAMES_ROOT "/d/f"));
    FAILS(mkdirat(dirfd, "f", 0755), EEXIST);
    CHECK(close(dirfd) == 0);
    FAILS(mkdirat(-1, "x", 0755), EBADF);
    /* rmdir. */
    FAILS(rmdir(NAMES_ROOT "/d"), ENOTEMPTY);
    FAILS(rmdir(NAMES_ROOT "/d/e/."), EINVAL);
    FAILS(rmdir(NAMES_ROOT "/plain"), ENOTDIR);
    FAILS(rmdir(NAMES_ROOT "/missing"), ENOENT);
    FAILS(rmdir("/"), EBUSY);
    CHECK(names_age(NAMES_ROOT "/d") == 0);
    OK(rmdir(NAMES_ROOT "/d/e/"));
    CHECK(!names_exists(NAMES_ROOT "/d/e") && names_aged(NAMES_ROOT "/d"));
    OK(rmdir(NAMES_ROOT "/d/f"));
    OK(stat(NAMES_ROOT "/d", &st));
    CHECK(st.st_nlink == 2);
    OK(rmdir(NAMES_ROOT "/d"));
    /* A directory removed under a descriptor: the descriptor stays. */
    OK(mkdir(NAMES_ROOT "/gone", 0755));
    dirfd = open(NAMES_ROOT "/gone", O_RDONLY | O_DIRECTORY);
    CHECK(dirfd >= 0);
    OK(rmdir(NAMES_ROOT "/gone"));
    FAILS(openat(dirfd, "x", O_RDONLY), ENOENT);
    CHECK(close(dirfd) == 0);
    OK(unlink(NAMES_ROOT "/plain"));
    OK(unlink(NAMES_ROOT "/dangling"));
    return 0;
}

static int names_rename(void) {
    OK(mkdir(NAMES_ROOT "/r", 0755));
    OK(mkdir(NAMES_ROOT "/r/p", 0755));
    OK(mkdir(NAMES_ROOT "/r/q", 0755));
    CHECK(names_put(NAMES_ROOT "/r/p/a", "alpha") == 0);
    CHECK(names_age(NAMES_ROOT "/r/p") == 0 && names_age(NAMES_ROOT "/r/q") == 0);
    OK(rename(NAMES_ROOT "/r/p/a", NAMES_ROOT "/r/q/b"));
    CHECK(!names_exists(NAMES_ROOT "/r/p/a"));
    CHECK(names_aged(NAMES_ROOT "/r/p") && names_aged(NAMES_ROOT "/r/q"));
    char text[8] = {0};
    int fd = open(NAMES_ROOT "/r/q/b", O_RDONLY);
    CHECK(fd >= 0 && read(fd, text, 7) == 5 && !strcmp(text, "alpha"));
    CHECK(close(fd) == 0);
    /* Over an existing file: the old inode goes. */
    CHECK(names_put(NAMES_ROOT "/r/p/c", "gamma") == 0);
    OK(rename(NAMES_ROOT "/r/p/c", NAMES_ROOT "/r/q/b"));
    struct stat st;
    OK(stat(NAMES_ROOT "/r/q/b", &st));
    CHECK(st.st_size == 5);
    fd = open(NAMES_ROOT "/r/q/b", O_RDONLY);
    CHECK(fd >= 0 && read(fd, text, 7) == 5 && !strcmp(text, "gamma"));
    CHECK(close(fd) == 0);
    /* A directory over an empty directory; over a full one ENOTEMPTY. */
    OK(mkdir(NAMES_ROOT "/r/d1", 0755));
    OK(mkdir(NAMES_ROOT "/r/d2", 0755));
    CHECK(names_put(NAMES_ROOT "/r/d1/in", "x") == 0);
    OK(rename(NAMES_ROOT "/r/d1", NAMES_ROOT "/r/d2"));
    CHECK(names_exists(NAMES_ROOT "/r/d2/in") && !names_exists(NAMES_ROOT "/r/d1"));
    OK(mkdir(NAMES_ROOT "/r/d3", 0755));
    FAILS(rename(NAMES_ROOT "/r/d3", NAMES_ROOT "/r/d2"), ENOTEMPTY);
    /* The kinds do not mix. */
    FAILS(rename(NAMES_ROOT "/r/q/b", NAMES_ROOT "/r/d3"), EISDIR);
    FAILS(rename(NAMES_ROOT "/r/d3", NAMES_ROOT "/r/q/b"), ENOTDIR);
    FAILS(rename(NAMES_ROOT "/r/q/b/", NAMES_ROOT "/r/q/z"), ENOTDIR);
    FAILS(rename(NAMES_ROOT "/r/q/b", NAMES_ROOT "/r/q/z/"), ENOTDIR);
    CHECK(names_exists(NAMES_ROOT "/r/q/b") && !names_exists(NAMES_ROOT "/r/q/z"));
    /* Into its own descendant, and the last component . or .. . */
    OK(mkdir(NAMES_ROOT "/r/d3/sub", 0755));
    FAILS(rename(NAMES_ROOT "/r/d3", NAMES_ROOT "/r/d3/sub/x"), EINVAL);
    FAILS(rename(NAMES_ROOT "/r/d3/.", NAMES_ROOT "/r/y"), EINVAL);
    FAILS(rename(NAMES_ROOT "/r/d3/..", NAMES_ROOT "/r/y"), EINVAL);
    FAILS(rename(NAMES_ROOT "/r/d3", NAMES_ROOT "/r/d3/."), EINVAL);
    FAILS(rename("", NAMES_ROOT "/r/y"), ENOENT);
    FAILS(rename(NAMES_ROOT "/r/q/b", ""), ENOENT);
    FAILS(rename(NAMES_ROOT "/r/none", NAMES_ROOT "/r/y"), ENOENT);
    FAILS(rename(NAMES_ROOT "/r/q/b", NAMES_ROOT "/r/none/y"), ENOENT);
    /* A symbolic link is renamed itself, and replaced itself. */
    OK(symlink(NAMES_ROOT "/r/q/b", NAMES_ROOT "/r/l1"));
    OK(symlink("elsewhere", NAMES_ROOT "/r/l2"));
    OK(rename(NAMES_ROOT "/r/l1", NAMES_ROOT "/r/l3"));
    OK(lstat(NAMES_ROOT "/r/l3", &st));
    CHECK(S_ISLNK(st.st_mode));
    CHECK(names_exists(NAMES_ROOT "/r/q/b"));
    OK(rename(NAMES_ROOT "/r/l3", NAMES_ROOT "/r/l2"));
    char target[64] = {0};
    CHECK(readlink(NAMES_ROOT "/r/l2", target, sizeof target) == (ssize_t)strlen(NAMES_ROOT "/r/q/b"));
    /* The same file under two names: nothing happens, both stay. */
    OK(link(NAMES_ROOT "/r/q/b", NAMES_ROOT "/r/q/b2"));
    OK(rename(NAMES_ROOT "/r/q/b", NAMES_ROOT "/r/q/b2"));
    CHECK(names_exists(NAMES_ROOT "/r/q/b") && names_exists(NAMES_ROOT "/r/q/b2"));
    OK(rename(NAMES_ROOT "/r/q/b", NAMES_ROOT "/r/q/b"));
    /* A directory moves with its entries and its .. . */
    OK(rename(NAMES_ROOT "/r/d3", NAMES_ROOT "/r/q/d3"));
    OK(stat(NAMES_ROOT "/r/q/d3/sub/..", &st));
    struct stat parent;
    OK(stat(NAMES_ROOT "/r/q/d3", &parent));
    CHECK(st.st_ino == parent.st_ino);
    OK(stat(NAMES_ROOT "/r/q/d3/..", &st));
    OK(stat(NAMES_ROOT "/r/q", &parent));
    CHECK(st.st_ino == parent.st_ino);
    /* renameat from descriptors; after the directory of a descriptor moved. */
    int from = open(NAMES_ROOT "/r/q", O_RDONLY | O_DIRECTORY);
    int to = open(NAMES_ROOT "/r/p", O_RDONLY | O_DIRECTORY);
    CHECK(from >= 0 && to >= 0);
    OK(rename(NAMES_ROOT "/r/p", NAMES_ROOT "/r/p2"));
    OK(renameat(from, "b2", to, "moved"));
    CHECK(names_exists(NAMES_ROOT "/r/p2/moved") && !names_exists(NAMES_ROOT "/r/q/b2"));
    FAILS(renameat(-1, "x", to, "y"), EBADF);
    CHECK(close(from) == 0 && close(to) == 0);
    /* The superuser needs no right; EACCES for another on a directory
     * without write permission. */
    OK(chmod(NAMES_ROOT "/r/p2", 0555));
    OK(chmod(NAMES_ROOT "/r", 0777));
    OK(seteuid(1000));
    FAILS(rename(NAMES_ROOT "/r/q/b", NAMES_ROOT "/r/p2/n"), EACCES);
    FAILS(rename(NAMES_ROOT "/r/p2/moved", NAMES_ROOT "/r/q/n"), EACCES);
    OK(seteuid(0));
    return 0;
}

static int names_link_symlink(void) {
    OK(mkdir(NAMES_ROOT "/k", 0755));
    CHECK(names_put(NAMES_ROOT "/k/f", "data") == 0);
    struct stat a, b;
    names_pause();
    OK(link(NAMES_ROOT "/k/f", NAMES_ROOT "/k/g"));
    OK(stat(NAMES_ROOT "/k/f", &a));
    OK(stat(NAMES_ROOT "/k/g", &b));
    CHECK(a.st_ino == b.st_ino && a.st_nlink == 2);
    FAILS(link(NAMES_ROOT "/k/f", NAMES_ROOT "/k/g"), EEXIST);
    FAILS(link(NAMES_ROOT "/k/none", NAMES_ROOT "/k/h"), ENOENT);
    FAILS(link(NAMES_ROOT "/k/f", NAMES_ROOT "/k/none/h"), ENOENT);
    FAILS(link(NAMES_ROOT "/k", NAMES_ROOT "/k2"), EPERM);
    FAILS(link(NAMES_ROOT "/k/f/", NAMES_ROOT "/k/h"), ENOTDIR);
    FAILS(linkat(AT_FDCWD, NAMES_ROOT "/k/f", AT_FDCWD, NAMES_ROOT "/k/h", 0x7000), EINVAL);
    /* Without AT_SYMLINK_FOLLOW the new name is a link to the symbolic link. */
    OK(symlink(NAMES_ROOT "/k/f", NAMES_ROOT "/k/s"));
    OK(link(NAMES_ROOT "/k/s", NAMES_ROOT "/k/s2"));
    OK(lstat(NAMES_ROOT "/k/s2", &a));
    CHECK(S_ISLNK(a.st_mode) && a.st_nlink == 2);
    OK(linkat(AT_FDCWD, NAMES_ROOT "/k/s", AT_FDCWD, NAMES_ROOT "/k/s3", AT_SYMLINK_FOLLOW));
    OK(lstat(NAMES_ROOT "/k/s3", &a));
    CHECK(S_ISREG(a.st_mode) && a.st_nlink == 3);
    /* linkat from descriptors. */
    int dirfd = open(NAMES_ROOT "/k", O_RDONLY | O_DIRECTORY);
    CHECK(dirfd >= 0);
    OK(linkat(dirfd, "f", dirfd, "viafd", 0));
    CHECK(names_exists(NAMES_ROOT "/k/viafd"));
    CHECK(close(dirfd) == 0);
    /* symlink: the target is kept as it is. */
    char text[600];
    OK(symlink("../a/b/../c", NAMES_ROOT "/k/t1"));
    memset(text, 0, sizeof text);
    CHECK(readlink(NAMES_ROOT "/k/t1", text, sizeof text) == 11 && !strcmp(text, "../a/b/../c"));
    FAILS(symlink("x", NAMES_ROOT "/k/t1"), EEXIST);
    FAILS(symlink("x", NAMES_ROOT "/k/none/t"), ENOENT);
    FAILS(symlink("x", ""), ENOENT);
    char longest[600];
    memset(longest, 'z', sizeof longest);
    longest[511] = 0;
    OK(symlink(longest, NAMES_ROOT "/k/t511"));
    CHECK(readlink(NAMES_ROOT "/k/t511", text, sizeof text) == 511);
    longest[511] = 'z';
    longest[512] = 0;
    FAILS(symlink(longest, NAMES_ROOT "/k/t512"), ENAMETOOLONG);
    CHECK(!names_exists(NAMES_ROOT "/k/t512"));
    /* An empty target is made; it leads nowhere. */
    OK(symlink("", NAMES_ROOT "/k/empty"));
    CHECK(readlink(NAMES_ROOT "/k/empty", text, sizeof text) == 0);
    FAILS(open(NAMES_ROOT "/k/empty", O_RDONLY), ENOENT);
    /* readlink: cut to the buffer, without a NUL. */
    memset(text, '#', sizeof text);
    CHECK(readlink(NAMES_ROOT "/k/t1", text, 4) == 4 && !memcmp(text, "../a#", 5));
    FAILS(readlink(NAMES_ROOT "/k/f", text, sizeof text), EINVAL);
    FAILS(readlink(NAMES_ROOT "/k/none", text, sizeof text), ENOENT);
    FAILS(readlink(NAMES_ROOT "/k/t1", text, 0), EINVAL);
    dirfd = open(NAMES_ROOT "/k", O_RDONLY | O_DIRECTORY);
    CHECK(readlinkat(dirfd, "t1", text, sizeof text) == 11);
    CHECK(close(dirfd) == 0);
    /* The times of the directory move with a new name. */
    CHECK(names_age(NAMES_ROOT "/k") == 0);
    OK(symlink("x", NAMES_ROOT "/k/t2"));
    CHECK(names_aged(NAMES_ROOT "/k"));
    return 0;
}

static int names_chmod_chown(void) {
    OK(mkdir(NAMES_ROOT "/c", 0777));
    CHECK(names_put(NAMES_ROOT "/c/f", "x") == 0);
    /* The time of a change of metadata is on the calendar clock; the first
     * chmod puts the change time on it, and the second moves it. */
    struct stat before, after;
    OK(chmod(NAMES_ROOT "/c/f", 0600));
    OK(stat(NAMES_ROOT "/c/f", &before));
    names_pause();
    OK(chmod(NAMES_ROOT "/c/f", 0640));
    CHECK(names_mode(NAMES_ROOT "/c/f") == 0640);
    OK(stat(NAMES_ROOT "/c/f", &after));
    CHECK(names_ns(after.st_ctim) > names_ns(before.st_ctim));
    int fd = open(NAMES_ROOT "/c/f", O_RDONLY);
    CHECK(fd >= 0);
    OK(fchmod(fd, 0604));
    CHECK(names_mode(NAMES_ROOT "/c/f") == 0604);
    OK(fchmodat(AT_FDCWD, NAMES_ROOT "/c/f", 0600, 0));
    CHECK(names_mode(NAMES_ROOT "/c/f") == 0600);
    /* chmod follows a link, a link itself is not changed. */
    OK(symlink("f", NAMES_ROOT "/c/l"));
    OK(chmod(NAMES_ROOT "/c/l", 0644));
    CHECK(names_mode(NAMES_ROOT "/c/f") == 0644);
    FAILS(fchmodat(AT_FDCWD, NAMES_ROOT "/c/l", 0600, AT_SYMLINK_NOFOLLOW), EOPNOTSUPP);
    FAILS(fchmodat(AT_FDCWD, NAMES_ROOT "/c/l", 0600, 0x7000), EINVAL);
    FAILS(chmod(NAMES_ROOT "/c/none", 0600), ENOENT);
    FAILS(chmod(NAMES_ROOT "/c/f/x", 0600), ENOTDIR);
    FAILS(fchmod(-1, 0600), EBADF);
    FAILS(chmod(NAMES_ROOT "/c/l/", 0600), ENOTDIR);
    /* set-ID bits of the superuser stay; chown by the superuser clears them. */
    OK(chmod(NAMES_ROOT "/c/f", 06755));
    CHECK(names_mode(NAMES_ROOT "/c/f") == 06755);
    OK(chown(NAMES_ROOT "/c/f", 1000, 2000));
    struct stat st;
    OK(stat(NAMES_ROOT "/c/f", &st));
    CHECK(st.st_uid == 1000 && st.st_gid == 2000 && (st.st_mode & 06000) == 0);
    /* An ID of -1 keeps the field. */
    OK(chown(NAMES_ROOT "/c/f", (uid_t)-1, 3000));
    OK(stat(NAMES_ROOT "/c/f", &st));
    CHECK(st.st_uid == 1000 && st.st_gid == 3000);
    OK(chown(NAMES_ROOT "/c/f", 1001, (gid_t)-1));
    OK(stat(NAMES_ROOT "/c/f", &st));
    CHECK(st.st_uid == 1001 && st.st_gid == 3000);
    OK(fchown(fd, 1000, 2000));
    OK(fstat(fd, &st));
    CHECK(st.st_uid == 1000 && st.st_gid == 2000);
    CHECK(close(fd) == 0);
    /* lchown changes the link, chown the file the link leads to. */
    OK(lchown(NAMES_ROOT "/c/l", 777, 888));
    OK(lstat(NAMES_ROOT "/c/l", &st));
    CHECK(st.st_uid == 777 && st.st_gid == 888);
    OK(stat(NAMES_ROOT "/c/f", &st));
    CHECK(st.st_uid == 1000);
    OK(fchownat(AT_FDCWD, NAMES_ROOT "/c/l", 12, 13, AT_SYMLINK_NOFOLLOW));
    OK(lstat(NAMES_ROOT "/c/l", &st));
    CHECK(st.st_uid == 12 && st.st_gid == 13);
    FAILS(fchownat(AT_FDCWD, NAMES_ROOT "/c/l", 12, 13, 0x7000), EINVAL);
    FAILS(chown(NAMES_ROOT "/c/none", 1, 1), ENOENT);
    FAILS(fchown(-1, 1, 1), EBADF);
    /* The owner (uid 1000, group 0 effective) may set the group to its own
     * only; the set-group-ID bit of a file of another group goes with chmod. */
    OK(chown(NAMES_ROOT "/c/f", 1000, 2000));
    OK(seteuid(1000));
    FAILS(chown(NAMES_ROOT "/c/f", 1001, (gid_t)-1), EPERM);
    FAILS(chown(NAMES_ROOT "/c/f", (uid_t)-1, 5), EPERM);
    OK(chmod(NAMES_ROOT "/c/f", 02755));
    CHECK(names_mode(NAMES_ROOT "/c/f") == 0755);
    OK(chmod(NAMES_ROOT "/c/f", 04755));
    CHECK(names_mode(NAMES_ROOT "/c/f") == 04755);
    OK(seteuid(0));
    /* Another user: not the owner. */
    OK(seteuid(2000));
    FAILS(chmod(NAMES_ROOT "/c/f", 0600), EPERM);
    FAILS(fchmodat(AT_FDCWD, NAMES_ROOT "/c/f", 0600, 0), EPERM);
    FAILS(chown(NAMES_ROOT "/c/f", 2000, (gid_t)-1), EPERM);
    OK(seteuid(0));
    CHECK(names_mode(NAMES_ROOT "/c/f") == 04755);
    return 0;
}

static int names_access(void) {
    OK(mkdir(NAMES_ROOT "/a", 0777));
    CHECK(names_put(NAMES_ROOT "/a/f", "x") == 0);
    OK(chmod(NAMES_ROOT "/a/f", 0600));
    OK(access(NAMES_ROOT "/a/f", F_OK));
    OK(access(NAMES_ROOT "/a/f", R_OK | W_OK));
    /* The superuser executes a directory and what has an x bit, no more. */
    FAILS(access(NAMES_ROOT "/a/f", X_OK), EACCES);
    OK(access(NAMES_ROOT "/a", X_OK));
    OK(chmod(NAMES_ROOT "/a/f", 0701));
    OK(access(NAMES_ROOT "/a/f", X_OK));
    FAILS(access(NAMES_ROOT "/a/none", F_OK), ENOENT);
    FAILS(access(NAMES_ROOT "/a/f/x", F_OK), ENOTDIR);
    FAILS(access("", F_OK), ENOENT);
    FAILS(access(NAMES_ROOT "/a/f", 8), EINVAL);
    FAILS(faccessat(AT_FDCWD, NAMES_ROOT "/a/f", F_OK, 0x7000), EINVAL);
    FAILS(faccessat(AT_FDCWD, NAMES_ROOT "/a/f", F_OK, AT_SYMLINK_NOFOLLOW), EINVAL);
    /* An owner of 1000 with mode 0600; the real user is 0, the effective 1000. */
    OK(chmod(NAMES_ROOT "/a/f", 0600));
    OK(chown(NAMES_ROOT "/a/f", 0, 0));
    OK(seteuid(1000));
    OK(access(NAMES_ROOT "/a/f", R_OK));
    FAILS(faccessat(AT_FDCWD, NAMES_ROOT "/a/f", R_OK, AT_EACCESS), EACCES);
    OK(faccessat(AT_FDCWD, NAMES_ROOT "/a/f", F_OK, AT_EACCESS));
    OK(seteuid(0));
    /* From a descriptor; a relative path against a file is ENOTDIR. */
    int dirfd = open(NAMES_ROOT "/a", O_RDONLY | O_DIRECTORY);
    CHECK(dirfd >= 0);
    OK(faccessat(dirfd, "f", R_OK, 0));
    FAILS(faccessat(dirfd, "none", F_OK, 0), ENOENT);
    OK(faccessat(-1, NAMES_ROOT "/a/f", F_OK, 0));
    int filefd = open(NAMES_ROOT "/a/f", O_RDONLY);
    CHECK(filefd >= 0);
    FAILS(faccessat(filefd, "x", F_OK, 0), ENOTDIR);
    FAILS(faccessat(99, "x", F_OK, 0), EBADF);
    CHECK(close(filefd) == 0 && close(dirfd) == 0);
    /* No right of search on a directory of the path. */
    OK(mkdir(NAMES_ROOT "/a/closed", 0700));
    CHECK(names_put(NAMES_ROOT "/a/closed/in", "x") == 0);
    OK(seteuid(1000));
    OK(access(NAMES_ROOT "/a/closed/in", F_OK));
    FAILS(faccessat(AT_FDCWD, NAMES_ROOT "/a/closed/in", F_OK, AT_EACCESS), EACCES);
    OK(seteuid(0));
    return 0;
}

static int names_times(void) {
    OK(mkdir(NAMES_ROOT "/t", 0777));
    CHECK(names_put(NAMES_ROOT "/t/f", "x") == 0);
    struct stat st;
    struct timespec set[2] = {{1111, 123}, {2222, 456}};
    OK(utimensat(AT_FDCWD, NAMES_ROOT "/t/f", set, 0));
    OK(stat(NAMES_ROOT "/t/f", &st));
    CHECK(st.st_atim.tv_sec == 1111 && st.st_atim.tv_nsec == 123);
    CHECK(st.st_mtim.tv_sec == 2222 && st.st_mtim.tv_nsec == 456);
    CHECK(st.st_ctim.tv_sec != 2222);
    /* UTIME_OMIT leaves the time as it is. */
    struct timespec omit[2] = {{0, UTIME_OMIT}, {3333, 0}};
    OK(utimensat(AT_FDCWD, NAMES_ROOT "/t/f", omit, 0));
    OK(stat(NAMES_ROOT "/t/f", &st));
    CHECK(st.st_atim.tv_sec == 1111 && st.st_mtim.tv_sec == 3333);
    /* Two OMIT change nothing, ctime too. */
    struct stat before;
    OK(stat(NAMES_ROOT "/t/f", &before));
    names_pause();
    struct timespec both[2] = {{0, UTIME_OMIT}, {0, UTIME_OMIT}};
    OK(utimensat(AT_FDCWD, NAMES_ROOT "/t/f", both, 0));
    OK(stat(NAMES_ROOT "/t/f", &st));
    CHECK(names_ns(st.st_ctim) == names_ns(before.st_ctim));
    /* UTIME_NOW and no times at all are now. */
    struct timespec now[2] = {{0, UTIME_NOW}, {0, UTIME_NOW}};
    OK(utimensat(AT_FDCWD, NAMES_ROOT "/t/f", now, 0));
    OK(stat(NAMES_ROOT "/t/f", &st));
    CHECK(names_ns(st.st_atim) != 1111000000123LL && st.st_atim.tv_sec != 1111 && st.st_mtim.tv_sec != 3333);
    OK(utimensat(AT_FDCWD, NAMES_ROOT "/t/f", set, 0));
    OK(utimensat(AT_FDCWD, NAMES_ROOT "/t/f", NULL, 0));
    OK(stat(NAMES_ROOT "/t/f", &st));
    CHECK(st.st_atim.tv_sec != 1111 && st.st_mtim.tv_sec != 2222);
    /* futimens, and the times of a link itself. */
    int fd = open(NAMES_ROOT "/t/f", O_RDONLY);
    CHECK(fd >= 0);
    OK(futimens(fd, set));
    OK(fstat(fd, &st));
    CHECK(st.st_atim.tv_sec == 1111 && st.st_mtim.tv_sec == 2222);
    CHECK(close(fd) == 0);
    OK(symlink("f", NAMES_ROOT "/t/l"));
    OK(utimensat(AT_FDCWD, NAMES_ROOT "/t/l", set, AT_SYMLINK_NOFOLLOW));
    OK(lstat(NAMES_ROOT "/t/l", &st));
    CHECK(st.st_mtim.tv_sec == 2222);
    /* The errors. */
    struct timespec bad[2] = {{0, 1000000000}, {0, 0}};
    FAILS(utimensat(AT_FDCWD, NAMES_ROOT "/t/f", bad, 0), EINVAL);
    bad[0].tv_nsec = -1;
    FAILS(utimensat(AT_FDCWD, NAMES_ROOT "/t/f", bad, 0), EINVAL);
    FAILS(utimensat(AT_FDCWD, NAMES_ROOT "/t/f", set, 0x7000), EINVAL);
    FAILS(utimensat(AT_FDCWD, NAMES_ROOT "/t/none", set, 0), ENOENT);
    FAILS(futimens(-1, set), EBADF);
    /* Another user: an explicit time wants the owner, NOW the right of
     * writing, and OMIT nothing at all. */
    OK(chmod(NAMES_ROOT "/t/f", 0644));
    OK(seteuid(1000));
    FAILS(utimensat(AT_FDCWD, NAMES_ROOT "/t/f", set, 0), EPERM);
    FAILS(utimensat(AT_FDCWD, NAMES_ROOT "/t/f", now, 0), EACCES);
    OK(utimensat(AT_FDCWD, NAMES_ROOT "/t/f", both, 0));
    OK(seteuid(0));
    return 0;
}

static int names_truncate(void) {
    OK(mkdir(NAMES_ROOT "/z", 0777));
    int fd = open(NAMES_ROOT "/z/f", O_RDWR | O_CREAT | O_TRUNC, 0644);
    CHECK(fd >= 0);
    CHECK(write(fd, "abcdefghij", 10) == 10);
    struct stat st;
    /* Smaller. */
    OK(ftruncate(fd, 4));
    OK(fstat(fd, &st));
    CHECK(st.st_size == 4);
    /* The offset of the description is where it was. */
    CHECK(lseek(fd, 0, SEEK_CUR) == 10);
    /* Larger: zeros after the old end. */
    OK(ftruncate(fd, 4000));
    OK(fstat(fd, &st));
    CHECK(st.st_size == 4000);
    char bytes[4000];
    size_t have = 0;
    while (have < sizeof bytes) {
        ssize_t got = pread(fd, bytes + have, sizeof bytes - have, (off_t)have);
        CHECK(got > 0);
        have += (size_t)got;
    }
    CHECK(!memcmp(bytes, "abcd", 4));
    for (int i = 4; i < 4000; i++) CHECK(bytes[i] == 0);
    /* The times of the file move. */
    struct timespec old[2] = {{1, 0}, {1, 0}};
    OK(futimens(fd, old));
    OK(fstat(fd, &st));
    long long changed = names_ns(st.st_ctim);
    names_pause();
    OK(ftruncate(fd, 4001));
    OK(fstat(fd, &st));
    CHECK(names_ns(st.st_mtim) != 1000000000LL && names_ns(st.st_ctim) > changed);
    OK(ftruncate(fd, 0));
    OK(fstat(fd, &st));
    CHECK(st.st_size == 0);
    /* The errors. */
    FAILS(ftruncate(fd, -1), EINVAL);
    FAILS(ftruncate(fd, 1LL << 40), EFBIG);
    OK(fstat(fd, &st));
    CHECK(st.st_size == 0);
    CHECK(close(fd) == 0);
    FAILS(ftruncate(fd, 0), EBADF);
    fd = open(NAMES_ROOT "/z/f", O_RDONLY);
    CHECK(fd >= 0);
    FAILS(ftruncate(fd, 0), EBADF);
    CHECK(close(fd) == 0);
    FAILS(ftruncate(1, 0), EINVAL);
    int dirfd = open(NAMES_ROOT "/z", O_RDONLY | O_DIRECTORY);
    CHECK(dirfd >= 0);
    FAILS(ftruncate(dirfd, 0), EISDIR);
    CHECK(close(dirfd) == 0);
    /* truncate by name. */
    CHECK(names_put(NAMES_ROOT "/z/t", "0123456789") == 0);
    OK(truncate(NAMES_ROOT "/z/t", 3));
    OK(stat(NAMES_ROOT "/z/t", &st));
    CHECK(st.st_size == 3);
    FAILS(truncate(NAMES_ROOT "/z/none", 3), ENOENT);
    FAILS(truncate(NAMES_ROOT "/z", 3), EISDIR);
    FAILS(truncate(NAMES_ROOT "/z/t", -1), EINVAL);
    OK(chmod(NAMES_ROOT "/z/t", 0444));
    OK(seteuid(1000));
    FAILS(truncate(NAMES_ROOT "/z/t", 1), EACCES);
    OK(seteuid(0));
    /* A file of a descriptor opened for append: truncated all the same. */
    fd = open(NAMES_ROOT "/z/t", O_WRONLY | O_APPEND);
    CHECK(fd >= 0);
    OK(ftruncate(fd, 1));
    CHECK(close(fd) == 0);
    return 0;
}

static int names_statvfs(void) {
    OK(mkdir(NAMES_ROOT "/v", 0777));
    struct statvfs before, after, file;
    /* The service gives the nodes of earlier sections back in the background:
     * the count of free nodes is read until it stands still. */
    OK(statvfs(NAMES_ROOT "/v", &before));
    for (int steady = 0; steady < 5;) {
        names_pause();
        OK(statvfs(NAMES_ROOT "/v", &after));
        steady = after.f_ffree == before.f_ffree ? steady + 1 : 0;
        before = after;
    }
    CHECK(before.f_namemax == 255 && before.f_bsize > 0 && before.f_files > 0);
    OK(mkdir(NAMES_ROOT "/v/d", 0755));
    OK(statvfs(NAMES_ROOT "/v", &after));
    CHECK(after.f_ffree + 1 == before.f_ffree);
    int fd = open(NAMES_ROOT "/v", O_RDONLY | O_DIRECTORY);
    CHECK(fd >= 0);
    OK(fstatvfs(fd, &file));
    CHECK(file.f_ffree == after.f_ffree && file.f_blocks == after.f_blocks);
    CHECK(close(fd) == 0);
    CHECK(fstatvfs(fd, &file) == -1 && errno == EBADF);
    /* A file of mode 0 answers: only the search of the directories above it
     * counts. */
    CHECK(names_put(NAMES_ROOT "/v/zero", "x") == 0);
    OK(chmod(NAMES_ROOT "/v/zero", 0));
    OK(seteuid(1000));
    OK(statvfs(NAMES_ROOT "/v/zero", &file));
    CHECK(file.f_namemax == 255);
    OK(seteuid(0));
    FAILS(statvfs(NAMES_ROOT "/v/none", &file), ENOENT);
    FAILS(statvfs(NAMES_ROOT "/v/zero/x", &file), ENOTDIR);
    FAILS(statvfs("", &file), ENOENT);
    /* The console has no blocks; its names are 255 bytes. */
    OK(fstatvfs(1, &file));
    CHECK(file.f_blocks == 0 && file.f_files == 0 && file.f_namemax == 255);
    return 0;
}

static int names_descriptor_bases(void) {
    OK(mkdir(NAMES_ROOT "/b", 0777));
    OK(mkdir(NAMES_ROOT "/b/dir", 0755));
    CHECK(names_put(NAMES_ROOT "/b/dir/in", "inside") == 0);
    int dirfd = open(NAMES_ROOT "/b/dir", O_RDONLY | O_DIRECTORY);
    CHECK(dirfd >= 0);
    int fd = openat(dirfd, "in", O_RDONLY);
    CHECK(fd >= 0);
    char text[8] = {0};
    CHECK(read(fd, text, 6) == 6 && !strcmp(text, "inside"));
    CHECK(close(fd) == 0);
    /* The directory moves: the descriptor leads to it still. */
    OK(rename(NAMES_ROOT "/b/dir", NAMES_ROOT "/b/moved"));
    fd = openat(dirfd, "in", O_RDONLY);
    CHECK(fd >= 0 && close(fd) == 0);
    struct stat st;
    OK(fstatat(dirfd, "in", &st, 0));
    CHECK(st.st_size == 6);
    OK(fstatat(dirfd, ".", &st, 0));
    CHECK(S_ISDIR(st.st_mode));
    OK(fstatat(dirfd, "", &st, AT_EMPTY_PATH));
    CHECK(S_ISDIR(st.st_mode));
    FAILS(fstatat(dirfd, "in", &st, 0x7000), EINVAL);
    FAILS(fstatat(dirfd, "", &st, 0), ENOENT);
    FAILS(fstatat(dirfd, "none", &st, 0), ENOENT);
    /* An absolute path looks at no descriptor. */
    fd = openat(-1, "/etc/motd", O_RDONLY);
    CHECK(fd >= 0 && close(fd) == 0);
    OK(fstatat(dirfd, "/etc/motd", &st, 0));
    /* A closed number, a descriptor of a file, the console. */
    FAILS(openat(99, "x", O_RDONLY), EBADF);
    int filefd = open(NAMES_ROOT "/b/moved/in", O_RDONLY);
    CHECK(filefd >= 0);
    FAILS(openat(filefd, "x", O_RDONLY), ENOTDIR);
    FAILS(fstatat(filefd, "x", &st, 0), ENOTDIR);
    FAILS(openat(1, "x", O_RDONLY), ENOTDIR);
    CHECK(close(filefd) == 0);
    /* The right to search is looked at every time: another user is refused
     * once the mode of the directory goes. */
    OK(chmod(NAMES_ROOT "/b/moved", 0));
    OK(seteuid(1000));
    FAILS(openat(dirfd, "in", O_RDONLY), EACCES);
    FAILS(fstatat(dirfd, "in", &st, 0), EACCES);
    OK(seteuid(0));
    OK(chmod(NAMES_ROOT "/b/moved", 0755));
    CHECK(close(dirfd) == 0);
    return 0;
}

static int names_directories(void) {
    OK(mkdir(NAMES_ROOT "/w", 0777));
    OK(mkdir(NAMES_ROOT "/w/one", 0755));
    OK(mkdir(NAMES_ROOT "/w/one/two", 0755));
    CHECK(names_put(NAMES_ROOT "/w/one/file", "x") == 0);
    char cwd[PATH_MAX];
    int dirfd = open(NAMES_ROOT "/w/one", O_RDONLY | O_DIRECTORY);
    CHECK(dirfd >= 0);
    OK(fchdir(dirfd));
    CHECK(getcwd(cwd, sizeof cwd) && !strcmp(cwd, NAMES_ROOT "/w/one"));
    CHECK(names_exists("file") && names_exists("two"));
    CHECK(close(dirfd) == 0);
    /* The current directory is a place: .. is the directory above it. */
    OK(chdir("two"));
    OK(chdir(".."));
    OK(chdir(".."));
    CHECK(getcwd(cwd, sizeof cwd) && !strcmp(cwd, NAMES_ROOT "/w"));
    OK(symlink("one/two", NAMES_ROOT "/w/link"));
    OK(chdir("link"));
    CHECK(getcwd(cwd, sizeof cwd) && !strcmp(cwd, NAMES_ROOT "/w/one/two"));
    OK(chdir("/"));
    FAILS(fchdir(99), EBADF);
    int filefd = open(NAMES_ROOT "/w/one/file", O_RDONLY);
    CHECK(filefd >= 0);
    FAILS(fchdir(filefd), ENOTDIR);
    CHECK(close(filefd) == 0);
    FAILS(fchdir(1), ENOTDIR);
    /* A directory without the right of search. */
    OK(mkdir(NAMES_ROOT "/w/closed", 0700));
    dirfd = open(NAMES_ROOT "/w/closed", O_RDONLY | O_DIRECTORY);
    CHECK(dirfd >= 0);
    OK(seteuid(1000));
    FAILS(fchdir(dirfd), EACCES);
    FAILS(chdir(NAMES_ROOT "/w/closed"), EACCES);
    OK(seteuid(0));
    CHECK(close(dirfd) == 0);
    CHECK(getcwd(cwd, sizeof cwd) && !strcmp(cwd, "/"));
    /* realpath: through two links and .. , by a relative path, of a file. */
    OK(mkdir(NAMES_ROOT "/w/a", 0755));
    OK(mkdir(NAMES_ROOT "/w/a/b", 0755));
    OK(symlink("b", NAMES_ROOT "/w/a/l1"));
    OK(symlink("../a/l1", NAMES_ROOT "/w/a/l2"));
    char *resolved = realpath(NAMES_ROOT "/w/a/l2/../b", NULL);
    CHECK(resolved && !strcmp(resolved, NAMES_ROOT "/w/a/b"));
    free(resolved);
    char fixed[PATH_MAX];
    CHECK(realpath(NAMES_ROOT "/w/./a//l2", fixed) == fixed && !strcmp(fixed, NAMES_ROOT "/w/a/b"));
    OK(chdir(NAMES_ROOT "/w/a"));
    resolved = realpath(".", NULL);
    CHECK(resolved && !strcmp(resolved, NAMES_ROOT "/w/a"));
    free(resolved);
    resolved = realpath("l1/../..", NULL);
    CHECK(resolved && !strcmp(resolved, NAMES_ROOT "/w"));
    free(resolved);
    resolved = realpath(NAMES_ROOT "/w/one/file", NULL);
    CHECK(resolved && !strcmp(resolved, NAMES_ROOT "/w/one/file"));
    free(resolved);
    resolved = realpath("/", NULL);
    CHECK(resolved && !strcmp(resolved, "/"));
    free(resolved);
    errno = 0;
    CHECK(realpath(NAMES_ROOT "/w/none", NULL) == NULL && errno == ENOENT);
    errno = 0;
    CHECK(realpath("", NULL) == NULL && errno == ENOENT);
    errno = 0;
    CHECK(realpath(NAMES_ROOT "/w/one/file/x", NULL) == NULL && errno == ENOTDIR);
    OK(symlink("loop2", NAMES_ROOT "/w/loop1"));
    OK(symlink("loop1", NAMES_ROOT "/w/loop2"));
    errno = 0;
    CHECK(realpath(NAMES_ROOT "/w/loop1", NULL) == NULL && errno == ELOOP);
    errno = 0;
    CHECK(realpath(NULL, NULL) == NULL && errno == EINVAL);
    /* A failed call leaves the buffer of the caller to the caller. */
    errno = 0;
    CHECK(realpath(NAMES_ROOT "/w/none", fixed) == NULL && errno == ENOENT);
    OK(chdir("/"));
    return 0;
}

/* The records of posix_getdents. The directories that the service lists
 * are the fixed ones and those of the boot image: /etc holds `motd`, the root
 * holds `etc` and `tmp`. A directory made at run time lists `.` and `..`
 * only (the service has no listing of such nodes yet). */
static int names_entries(void) {
    int fd = open("/etc", O_RDONLY | O_DIRECTORY);
    CHECK(fd >= 0);
    union {
        char bytes[2048];
        struct posix_dent align;
    } buffer;
    /* A buffer that holds one record, and not two. */
    ssize_t first = posix_getdents(fd, buffer.bytes, 40, 0);
    struct posix_dent *record = (struct posix_dent *)buffer.bytes;
    CHECK(first > 0 && first <= 40);
    CHECK(record->d_reclen == first && record->d_reclen % 8 == 0);
    CHECK(!strcmp(record->d_name, ".") && record->d_type == DT_DIR && record->d_ino != 0);
    /* A buffer that holds no record: EINVAL, and the offset stays. */
    off_t at = lseek(fd, 0, SEEK_CUR);
    CHECK(at > 0);
    errno = 0;
    CHECK(posix_getdents(fd, buffer.bytes, 8, 0) == -1 && errno == EINVAL);
    CHECK(lseek(fd, 0, SEEK_CUR) == at);
    errno = 0;
    CHECK(posix_getdents(fd, buffer.bytes, 0, 0) == -1 && errno == EINVAL);
    CHECK(lseek(fd, 0, SEEK_CUR) == at);
    /* The next record is `..`: the offset moved past `.` only. */
    ssize_t second = posix_getdents(fd, buffer.bytes, 40, 0);
    CHECK(second > 0 && !strcmp(record->d_name, ".."));
    /* Rewound, then all of it: each name once, its type, a length that
     * reaches the next record, the last one too. */
    CHECK(lseek(fd, 0, SEEK_SET) == 0);
    ssize_t total = posix_getdents(fd, buffer.bytes, sizeof buffer, 0);
    CHECK(total > 0);
    int dots = 0, dotdots = 0, motds = 0, count = 0;
    ssize_t used = 0;
    while (used < total) {
        record = (struct posix_dent *)(buffer.bytes + used);
        CHECK(record->d_reclen >= 24 && record->d_reclen % 8 == 0);
        CHECK(record->d_reclen >= 19 + strlen(record->d_name) + 1);
        CHECK(record->d_ino != 0);
        if (!strcmp(record->d_name, ".")) { dots++; CHECK(record->d_type == DT_DIR); }
        else if (!strcmp(record->d_name, "..")) { dotdots++; CHECK(record->d_type == DT_DIR); }
        else if (!strcmp(record->d_name, "motd")) { motds++; CHECK(record->d_type == DT_REG); }
        else CHECK(0);
        used += record->d_reclen;
        count++;
    }
    CHECK(used == total && count == 3 && dots == 1 && dotdots == 1 && motds == 1);
    /* The end is 0, and stays. */
    CHECK(posix_getdents(fd, buffer.bytes, sizeof buffer, 0) == 0);
    CHECK(posix_getdents(fd, buffer.bytes, sizeof buffer, 0) == 0);
    /* One record at a time reaches the same three. */
    CHECK(lseek(fd, 0, SEEK_SET) == 0);
    count = 0;
    for (;;) {
        ssize_t got = posix_getdents(fd, buffer.bytes, 32, 0);
        CHECK(got >= 0);
        if (got == 0) break;
        record = (struct posix_dent *)buffer.bytes;
        CHECK((size_t)got == record->d_reclen);
        count++;
        CHECK(count < 20);
    }
    CHECK(count == 3);
    CHECK(close(fd) == 0);
    FAILS(posix_getdents(fd, buffer.bytes, sizeof buffer, 0), EBADF);
    /* The root: `etc` and `tmp` are directories. */
    fd = open("/", O_RDONLY | O_DIRECTORY);
    CHECK(fd >= 0);
    total = posix_getdents(fd, buffer.bytes, sizeof buffer, 0);
    CHECK(total > 0);
    int etc = 0, tmp = 0;
    for (used = 0; used < total; used += record->d_reclen) {
        record = (struct posix_dent *)(buffer.bytes + used);
        if (!strcmp(record->d_name, "etc")) { etc++; CHECK(record->d_type == DT_DIR); }
        if (!strcmp(record->d_name, "tmp")) { tmp++; CHECK(record->d_type == DT_DIR); }
    }
    CHECK(etc == 1 && tmp == 1);
    CHECK(close(fd) == 0);
    fd = open("/etc/motd", O_RDONLY);
    CHECK(fd >= 0);
    FAILS(posix_getdents(fd, buffer.bytes, sizeof buffer, 0), ENOTDIR);
    CHECK(close(fd) == 0);
    return 0;
}

static int names_dup3(void) {
    int fd = open("/etc/motd", O_RDONLY);
    CHECK(fd >= 0);
    /* The descriptor that closes on fork: the child of a fork sees it
     * closed (procs.c, the stage of the forks). */
    CHECK(dup3(fd, 31, O_CLOFORK) == 31);
    int flags = fcntl(31, F_GETFD);
    CHECK(flags >= 0 && (flags & FD_CLOFORK) && !(flags & FD_CLOEXEC));
    CHECK(close(31) == 0);
    CHECK(dup3(fd, 30, O_CLOEXEC) == 30);
    flags = fcntl(30, F_GETFD);
    CHECK(flags >= 0 && (flags & FD_CLOEXEC));
    CHECK(dup3(fd, 30, 0) == 30);
    flags = fcntl(30, F_GETFD);
    CHECK(flags >= 0 && !(flags & FD_CLOEXEC));
    CHECK(close(30) == 0);
    FAILS(dup3(fd, fd, 0), EINVAL);
    FAILS(dup3(fd, 29, O_APPEND), EINVAL);
    FAILS(dup3(1, 32, 0), EBADF);
    FAILS(dup3(99, 29, 0), EBADF);
    FAILS(dup3(-1, 29, 0), EBADF);
    CHECK(close(fd) == 0);
    return 0;
}

static int names_limits(void) {
    CHECK(SYMLOOP_MAX == 32 && SYMLINK_MAX == 511);
    CHECK(sysconf(_SC_SYMLOOP_MAX) == 32);
    CHECK(pathconf("/tmp", _PC_SYMLINK_MAX) == 511);
    OK(mkdir(NAMES_ROOT "/m", 0777));
    CHECK(names_put(NAMES_ROOT "/m/l0", "end") == 0);
    char name[64], target[64];
    for (int i = 1; i <= 33; i++) {
        snprintf(name, sizeof name, NAMES_ROOT "/m/l%d", i);
        snprintf(target, sizeof target, "l%d", i - 1);
        OK(symlink(target, name));
    }
    /* 32 links are followed, the 33rd is a loop. */
    int fd = open(NAMES_ROOT "/m/l32", O_RDONLY);
    CHECK(fd >= 0 && close(fd) == 0);
    FAILS(open(NAMES_ROOT "/m/l33", O_RDONLY), ELOOP);
    struct stat st;
    OK(stat(NAMES_ROOT "/m/l32", &st));
    FAILS(stat(NAMES_ROOT "/m/l33", &st), ELOOP);
    OK(lstat(NAMES_ROOT "/m/l33", &st));
    /* A name of 255 bytes, a component of 256. */
    char path[600];
    memcpy(path, NAMES_ROOT "/m/", sizeof NAMES_ROOT "/m/");
    size_t at = strlen(path);
    memset(path + at, 'n', 255);
    path[at + 255] = 0;
    OK(mkdir(path, 0755));
    path[at + 255] = 'n';
    path[at + 256] = 0;
    FAILS(mkdir(path, 0755), ENAMETOOLONG);
    return 0;
}

/* remove, and the sticky bit. */
static int names_remove_sticky(void) {
    OK(mkdir(NAMES_ROOT "/s", 0777));
    CHECK(names_put(NAMES_ROOT "/s/f", "x") == 0);
    OK(remove(NAMES_ROOT "/s/f"));
    CHECK(!names_exists(NAMES_ROOT "/s/f"));
    OK(mkdir(NAMES_ROOT "/s/d", 0755));
    OK(remove(NAMES_ROOT "/s/d"));
    CHECK(!names_exists(NAMES_ROOT "/s/d"));
    /* The error of unlink is the error of remove. */
    FAILS(remove(NAMES_ROOT "/s/none"), ENOENT);
    CHECK(names_put(NAMES_ROOT "/s/f", "x") == 0);
    FAILS(remove(NAMES_ROOT "/s/f/x"), ENOTDIR);
    OK(mkdir(NAMES_ROOT "/s/full", 0755));
    CHECK(names_put(NAMES_ROOT "/s/full/in", "x") == 0);
    FAILS(remove(NAMES_ROOT "/s/full"), ENOTEMPTY);
    OK(unlink(NAMES_ROOT "/s/full/in"));
    OK(rmdir(NAMES_ROOT "/s/full"));
    /* A sticky directory: the name of a file of another is not for removal. */
    OK(mkdir(NAMES_ROOT "/s/sticky", 01777));
    CHECK(names_mode(NAMES_ROOT "/s/sticky") == 01755);
    OK(chmod(NAMES_ROOT "/s/sticky", 01777));
    CHECK(names_mode(NAMES_ROOT "/s/sticky") == 01777);
    CHECK(names_put(NAMES_ROOT "/s/sticky/theirs", "x") == 0);
    OK(chmod(NAMES_ROOT "/s/sticky/theirs", 0666));
    OK(mkdir(NAMES_ROOT "/s/sticky/dir", 0777));
    OK(seteuid(1000));
    FAILS(remove(NAMES_ROOT "/s/sticky/theirs"), EPERM);
    FAILS(unlink(NAMES_ROOT "/s/sticky/theirs"), EPERM);
    FAILS(rename(NAMES_ROOT "/s/sticky/theirs", NAMES_ROOT "/s/sticky/mine"), EPERM);
    FAILS(rmdir(NAMES_ROOT "/s/sticky/dir"), EPERM);
    /* Its own file goes. */
    CHECK(names_put(NAMES_ROOT "/s/sticky/own", "x") == 0);
    OK(remove(NAMES_ROOT "/s/sticky/own"));
    OK(seteuid(0));
    CHECK(names_exists(NAMES_ROOT "/s/sticky/theirs"));
    /* The owner of the directory removes what is in it. */
    OK(chown(NAMES_ROOT "/s/sticky", 1000, 0));
    OK(seteuid(1000));
    OK(remove(NAMES_ROOT "/s/sticky/theirs"));
    OK(seteuid(0));
    return 0;
}

static int names_mkdtemp(void) {
    char template[] = NAMES_ROOT "/mkdtemp.XXXXXX";
    CHECK(mkdtemp(template) == template);
    size_t prefix = strlen(NAMES_ROOT "/mkdtemp.");
    CHECK(strlen(template) == prefix + 6 && strncmp(template, NAMES_ROOT "/mkdtemp.", prefix) == 0);
    CHECK(strcmp(template + prefix, "XXXXXX") != 0);
    struct stat st;
    OK(stat(template, &st));
    CHECK(S_ISDIR(st.st_mode) && (st.st_mode & 0777) == 0700);
    OK(rmdir(template));
    char bad[] = NAMES_ROOT "/mkdtemp.XXXXX";
    FAILS(mkdtemp(bad) == NULL ? -1 : 0, EINVAL);
    return 0;
}

static long long names_realtime(void) {
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    return names_ns(now);
}

/* The times of the two families of methods order together: the older
 * methods (open with creation, write, read, readdir) and the operations of
 * Change and Data (chmod, utimensat, ftruncate) read the same calendar
 * clock. A program such as make compares the times of different files, and
 * a creation must not come after a later chmod. */
static int names_clocks(void) {
    struct stat st;
    long long before, after, created, written, changed, first, second;

    /* The creation, a write, then chmod: the change times come in that order. */
    before = names_realtime();
    int fd = open(NAMES_ROOT "/k1", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    CHECK(fd >= 0);
    after = names_realtime();
    OK(fstat(fd, &st));
    created = names_ns(st.st_ctim);
    CHECK(before <= created && created <= after);
    CHECK(names_ns(st.st_mtim) >= before && names_ns(st.st_mtim) <= after);
    names_pause();
    CHECK(write(fd, "x", 1) == 1);
    OK(fstat(fd, &st));
    written = names_ns(st.st_ctim);
    CHECK(created < written);
    CHECK(close(fd) == 0);
    names_pause();
    before = names_realtime();
    OK(chmod(NAMES_ROOT "/k1", 0600));
    after = names_realtime();
    OK(stat(NAMES_ROOT "/k1", &st));
    changed = names_ns(st.st_ctim);
    CHECK(written < changed);
    CHECK(before <= changed && changed <= after);

    /* A write of an older method, then a truncate of a Data job on another
     * file: the later one has the later modification time. */
    CHECK(names_put(NAMES_ROOT "/k2", "0123456789") == 0);
    CHECK(names_put(NAMES_ROOT "/k3", "0123456789") == 0);
    names_pause();
    before = names_realtime();
    fd = open(NAMES_ROOT "/k2", O_WRONLY);
    CHECK(fd >= 0 && write(fd, "x", 1) == 1 && close(fd) == 0);
    after = names_realtime();
    OK(stat(NAMES_ROOT "/k2", &st));
    first = names_ns(st.st_mtim);
    CHECK(before <= first && first <= after);
    names_pause();
    OK(truncate(NAMES_ROOT "/k3", 4));
    OK(stat(NAMES_ROOT "/k3", &st));
    second = names_ns(st.st_mtim);
    CHECK(first < second);
    CHECK(second <= names_realtime());

    /* The other way round: the truncate first, then the write. */
    names_pause();
    OK(truncate(NAMES_ROOT "/k2", 3));
    OK(stat(NAMES_ROOT "/k2", &st));
    first = names_ns(st.st_mtim);
    names_pause();
    fd = open(NAMES_ROOT "/k3", O_WRONLY);
    CHECK(fd >= 0 && write(fd, "y", 1) == 1 && close(fd) == 0);
    OK(stat(NAMES_ROOT "/k3", &st));
    second = names_ns(st.st_mtim);
    CHECK(first < second);

    /* utimensat with the time of now (Change) against a read (an older
     * method sets the access time). */
    names_pause();
    struct timespec now_times[2] = {{0, UTIME_NOW}, {0, UTIME_NOW}};
    OK(utimensat(AT_FDCWD, NAMES_ROOT "/k2", now_times, 0));
    OK(stat(NAMES_ROOT "/k2", &st));
    first = names_ns(st.st_mtim);
    names_pause();
    char byte;
    fd = open(NAMES_ROOT "/k3", O_RDONLY);
    CHECK(fd >= 0 && read(fd, &byte, 1) == 1 && close(fd) == 0);
    OK(stat(NAMES_ROOT "/k3", &st));
    second = names_ns(st.st_atim);
    CHECK(first < second);
    CHECK(second <= names_realtime());

    OK(unlink(NAMES_ROOT "/k1"));
    OK(unlink(NAMES_ROOT "/k2"));
    OK(unlink(NAMES_ROOT "/k3"));
    return 0;
}

static int names_all(void) {
    umask(022);
    OK(mkdir(NAMES_ROOT, 0777));
    OK(chmod(NAMES_ROOT, 0777));
    static const struct {
        const char *what;
        int (*run)(void);
    } sections[] = {
        {"unlink", names_unlink},
        {"rmdir and mkdir", names_rmdir_mkdir},
        {"rename", names_rename},
        {"link, symlink and readlink", names_link_symlink},
        {"chmod and chown", names_chmod_chown},
        {"access", names_access},
        {"utimensat and futimens", names_times},
        {"ftruncate and truncate", names_truncate},
        {"statvfs and fstatvfs", names_statvfs},
        {"paths against descriptors", names_descriptor_bases},
        {"fchdir, getcwd and realpath", names_directories},
        {"posix_getdents", names_entries},
        {"dup3", names_dup3},
        {"limits of the links", names_limits},
        {"remove and the sticky bit", names_remove_sticky},
        {"mkdtemp", names_mkdtemp},
        {"times of the two families of methods", names_clocks},
    };
    for (unsigned i = 0; i < sizeof sections / sizeof sections[0]; i++) {
        int failed = sections[i].run();
        if (failed) {
            printf("posix-files: names: %s failed at names.c:%d\n", sections[i].what, failed);
            return failed;
        }
        printf("posix-files: names: %s ok\n", sections[i].what);
    }
    return 0;
}
