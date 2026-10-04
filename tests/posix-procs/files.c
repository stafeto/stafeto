/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
extern int files_fake_identity(void);
extern int files_full_sessions(void);
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
    if (files_full_sessions()) return 12;
    puts("posix-files: 16 sessions with 32 retained descriptors ok");
    puts("posix-files: identity and proofs ok"); return 0;
}
