/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
extern int files_fake_identity(void);
extern int files_full_sessions(void);
extern int files_open_stages(void);
#include "pending-open.c"
#if LOADER_ABORT_PROBE
#include "loader-abort.c"
#endif
int main(void) {
    int fd = open("/tmp/probe", O_WRONLY);
    if (fd < 0 || close(fd) || geteuid() != 0) return 1;
    if (files_fake_identity()) return 2;
    fd = open("/tmp/probe", O_WRONLY);
    if (fd < 0 || close(fd)) return 3;
    if (seteuid(65533)) return 4;
    errno = 0; fd = open("/tmp/probe", O_WRONLY);
    if (fd != -1 || errno != EACCES) return 5;
    printf("posix-files: uid %u euid %u denied %d\n", (unsigned)getuid(), (unsigned)geteuid(), errno);
    if (seteuid(0)) return 6;
    fd = open("/tmp/probe", O_WRONLY);
    if (fd < 0 || close(fd)) return 7;
    fd = open("/etc/../etc/./motd", O_RDONLY);
    char bytes[7] = {0};
    if (fd < 0 || read(fd, bytes, 6) != 6 || memcmp(bytes,"stafet",6) || close(fd)) return 8;
    const char invalid[] = {'/',(char)255,0}; errno = 0;
    if (open(invalid, O_RDONLY) != -1 || errno != ENOENT) return 9;
    char name[257]; name[0] = '/'; memset(name+1,'x',255); name[256]=0; errno = 0;
    if (open(name,O_RDONLY) != -1 || errno != ENOENT) return 10;
    name[255]='x'; char over[258]; memcpy(over,name,256);over[256]='x';over[257]=0;errno=0;
    if (open(over,O_RDONLY) != -1 || errno != ENAMETOOLONG) return 11;
    fd = open("/dev/null", O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0600);
    if (fd < 0 || write(fd, "null", 4) != 4 || close(fd)) return 15;
    fd = open("/dev/urandom", O_WRONLY | O_APPEND);
    if (fd < 0 || write(fd, "random", 6) != 6 || close(fd)) return 16;
    errno = 0;
    if (open("/etc/motd", O_RDONLY | O_CREAT, 0600) != -1 || errno != EINVAL) return 17;
    errno = 0;
    if (open("/tmp/changes-missing", O_WRONLY | O_CREAT, 0600) != -1 || errno != ENOENT) return 18;
    puts("posix-files: compatibility device-only flags ok");
    int staged = files_open_stages();
    if (staged) { printf("posix-files: staged Open failed %d\n", staged); return 14; }
    puts("posix-files: staged CREATE/TRUNC cached outcome and hidden fd ok");
    if (files_full_sessions()) return 12;
    puts("posix-files: 16 sessions with 32 retained descriptors ok");
#if LOADER_ABORT_PROBE
    if (files_loader_abort()) return 13;
#endif
    int pending = check_pending_dup();
    if (pending) { printf("posix-files: Pending dup failed %d\n", pending); return 19; }
    pending = check_pending_claimant();
    if (pending) { printf("posix-files: Pending claimant failed %d\n", pending); return 22; }
    pending = check_pending_ended();
    if (pending) { printf("posix-files: Pending Ended failed %d\n", pending); return 20; }
    puts("posix-files: identity and proofs ok"); return 0;
}
