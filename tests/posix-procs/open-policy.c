/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
#include <pthread.h>
#include <sys/stat.h>

static void *policy_mask_worker(void *argument) {
    mode_t *previous = argument;
    *previous = umask(0137);
    return NULL;
}
struct policy_writer { int fd, count, error; char byte; };
static void *policy_append_writer(void *argument) {
    struct policy_writer *writer = argument;
    for (int i = 0; i < writer->count; ++i) {
        if (write(writer->fd, &writer->byte, 1) != 1) { writer->error = errno ? errno : EIO; break; }
    }
    return NULL;
}
static int check_open_policy(void) {
    struct stat info;
    mode_t saved_mask = umask(0022), previous = 0;
    pthread_t setter;
    if (pthread_create(&setter, NULL, policy_mask_worker, &previous) || pthread_join(setter, NULL)) return 1;
    if (previous != 0022) return 2;
    int fd = open("/tmp/public-policy-mode", O_RDWR | O_CREAT | O_EXCL, 0777);
    if (fd < 0 || fstat(fd, &info) || (info.st_mode & 07777) != 0640 || info.st_uid != geteuid() || info.st_gid != getegid()) return 3;
    if (write(fd, "mode", 4) != 4 || close(fd)) return 4;
    errno = 0;
    if (open("/tmp/public-policy-mode", O_RDONLY | O_CREAT | O_EXCL, 0) != -1 || errno != EEXIST) return 5;
    fd = open("/tmp/public-policy-mode", O_RDONLY | O_CREAT, 0);
    if (fd < 0 || fstat(fd, &info) || info.st_size != 4 || (info.st_mode & 07777) != 0640 || close(fd)) return 6;
    umask(0);
    fd = open("/tmp/public-policy-zero", O_RDWR | O_CREAT | O_EXCL, 0);
    if (fd < 0 || fstat(fd, &info) || (info.st_mode & 07777) != 0 || write(fd, "zero", 4) != 4) return 7;
    if (seteuid(65533)) return 8;
    errno = 0;
    int other = open("/tmp/public-policy-zero", O_RDONLY);
    if (other != -1 || errno != EACCES || write(fd, "held", 4) != 4) return 9;
    if (seteuid(0) || close(fd)) return 10;
    umask(0);
    fd = open("/tmp/public-policy-append", O_RDWR | O_CREAT | O_EXCL | O_APPEND, 0600);
    other = open("/tmp/public-policy-append", O_WRONLY | O_APPEND);
    if (fd < 0 || other < 0) return 11;
    struct policy_writer writers[2] = {{fd, 10, 0, 'A'}, {other, 10, 0, 'B'}};
    pthread_t threads[2];
    if (pthread_create(&threads[0], NULL, policy_append_writer, &writers[0]) || pthread_create(&threads[1], NULL, policy_append_writer, &writers[1])) return 12;
    if (pthread_join(threads[0], NULL) || pthread_join(threads[1], NULL) || writers[0].error || writers[1].error) return 13;
    int alias = dup(fd);
    off_t before = lseek(fd, 0, SEEK_CUR);
    if (alias < 0 || before <= 0 || fstat(fd, &info) || info.st_size != 20) return 14;
    if (pwrite(alias, "Q", 1, 0) != 1 || lseek(fd, 0, SEEK_CUR) != before || fstat(fd, &info) || info.st_size != 20) return 15;
    char bytes[20];
    if (pread(fd, bytes, sizeof bytes, 0) != sizeof bytes || bytes[0] != 'Q') return 16;
    int a = 0, b = 0;
    for (unsigned i = 1; i < sizeof bytes; ++i) { if (bytes[i] == 'A') ++a; else if (bytes[i] == 'B') ++b; else return 17; }
    if (a + b != 19 || a < 9 || b < 9 || close(alias) || close(other) || close(fd)) return 18;
    fd = open("/tmp/public-policy-append", O_RDWR | O_TRUNC);
    if (fd < 0 || fstat(fd, &info) || info.st_size != 0 || write(fd, "new", 3) != 3 || close(fd)) return 19;
    errno = 0;
    if (open("/tmp", O_RDONLY | O_CREAT, 0600) != -1 || errno != EISDIR) return 20;
    errno = 0;
    if (open("/tmp", O_RDONLY | O_CREAT | O_EXCL, 0600) != -1 || errno != EEXIST) return 21;
    fd = open("/etc/motd", O_RDONLY | O_CREAT, 0);
    if (fd < 0 || close(fd)) return 22;
    errno = 0;
    if (open("/etc/motd", O_WRONLY | O_TRUNC) != -1 || errno != EROFS) return 23;
    umask(saved_mask);
    puts("posix-files: public CREATE mode, current umask, APPEND/pwrite aliases and TRUNC ok");
    return 0;
}
