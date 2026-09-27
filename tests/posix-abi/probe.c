/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>

_Static_assert(sizeof(void *) == 8, "pointer ABI");
_Static_assert(sizeof(int) == 4, "int ABI");
_Static_assert(sizeof(long) == 8, "long ABI");
_Static_assert(sizeof(size_t) == 8, "size_t ABI");
_Static_assert(sizeof(ssize_t) == 8, "ssize_t ABI");
_Static_assert(sizeof(off_t) == 8, "off_t ABI");
_Static_assert(ABI_VERSION == 1, "ABI version");

static int same(const char *a, const char *b, size_t count) {
    for (size_t i = 0; i < count; i++) if (a[i] != b[i]) return 0;
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 2 || !argv || argv[2] != NULL || !same(argv[0], "posix-abi-probe", 15)
            || !same(argv[1], "argument", 9) || !environ || environ[0] != NULL) return 1;
    if (stafeto_posix_abi_version() != ABI_VERSION ||
            (char *)__errno_location() - (char *)__builtin_thread_pointer() != STAFETO_ERRNO_OFFSET) return 33;
    errno = 123;
    int fd = open("/etc/motd", O_RDONLY | O_CLOEXEC);
    if (fd != 3 || errno != 123) return 2;
    int copy = dup(fd);
    char text[32] = {0};
    if (copy != 4 || read(fd, text, 3) != 3 || !same(text, "sta", 3)) return 3;
    if (read(copy, text, 4) != 4 || !same(text, "feto", 4)) return 4;
    if (close(fd) != 0 || read(copy, text, 7) != 7 || !same(text, " ramfs\n", 7)) return 5;
    if (read(fd, NULL, 0) != -1 || errno != EBADF || close(copy) != 0) return 6;
    if (open("/missing", O_RDONLY) != -1 || errno != ENOENT) return 7;
    if (open(NULL, O_RDONLY) != -1 || errno != EFAULT) return 8;
    if (open("/etc/motd", O_ACCMODE) != -1 || errno != EINVAL) return 9;
    char too_long[130];
    for (size_t i = 0; i < sizeof(too_long) - 1; i++) too_long[i] = 'x';
    too_long[129] = 0;
    if (open(too_long, O_RDONLY) != -1 || errno != ENAMETOOLONG) return 10;
    if (chdir("/etc") != 0 || getcwd(text, sizeof(text)) != text || !same(text, "/etc", 5)) return 11;
    if (getcwd(text, 4) != NULL || errno != ERANGE) return 12;
    fd = open("motd", O_RDONLY);
    if (fd != 3 || lseek(fd, -1, SEEK_END) != 13 || read(fd, text, 1) != 1 || text[0] != '\n') return 13;
    if (lseek(fd, INT64_MAX, SEEK_SET) != INT64_MAX) return 14;
    if (lseek(fd, 1, SEEK_CUR) != -1 || errno != EOVERFLOW || lseek(fd, 0, SEEK_CUR) != INT64_MAX) return 15;
    if (lseek(fd, -1, SEEK_SET) != -1 || errno != EINVAL) return 16;
    if (lseek(fd, 0, 99) != -1 || errno != EINVAL) return 17;
    if (lseek(fd, 0, SEEK_DATA) != 0 || lseek(fd, 0, SEEK_HOLE) != 14) return 18;
    if (write(fd, NULL, 0) != -1 || errno != EBADF || close(fd) != 0) return 19;
    int saved = dup(STDOUT_FILENO);
    fd = open("/tmp/probe", O_RDWR);
    if (saved != 3 || fd != 4 || dup2(fd, 1) != 1 || close(fd) != 0) return 20;
    if (write(1, "Rust C ABI", 10) != 10 || lseek(1, 0, SEEK_SET) != 0
            || read(1, text, 10) != 10 || !same(text, "Rust C ABI", 10)) return 21;
    if (dup2(-1, 1) != -1 || errno != EBADF || lseek(1, 0, SEEK_CUR) != 10) return 22;
    if (dup3(1, 1, O_CLOEXEC) != -1 || errno != EINVAL) return 23;
    if (dup3(1, 5, O_CLOFORK) != 5 || close(5) != 0) return 24;
    if (dup2(saved, 1) != 1 || close(saved) != 0) return 25;
    if (lseek(1, 0, SEEK_SET) != -1 || errno != ESPIPE) return 26;
    if (read(1, text, sizeof(text)) != -1 || errno != EBADF) return 27;
    if (read(-1, text, sizeof(text)) != -1 || errno != EBADF) return 28;
    if (write(1, NULL, 1) != -1 || errno != EFAULT) return 29;
    if (close(0) != 0 || open("motd", O_RDONLY) != 0 || read(0, text, 1) != 1 || text[0] != 's') return 30;
    if (close(0) != 0 || close(0) != -1 || errno != EBADF) return 31;
    const char result[] = "posix-abi-probe: ok\n";
    if (write(1, result, sizeof(result) - 1) != (ssize_t)(sizeof(result) - 1)) return 32;
    return 0;
}
