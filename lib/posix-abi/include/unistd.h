/* SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1 */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
#ifndef STAFETO_UNISTD_H
#define STAFETO_UNISTD_H
#include <sys/types.h>
#include <stafeto/abi.h>
extern char **environ;
pid_t getpid(void);
pid_t getppid(void);
uid_t getuid(void);
uid_t geteuid(void);
gid_t getgid(void);
gid_t getegid(void);
int setuid(uid_t uid);
int seteuid(uid_t uid);
int setgid(gid_t gid);
int setegid(gid_t gid);
int close(int fd);
ssize_t read(int fd, void *buffer, size_t count);
ssize_t write(int fd, const void *buffer, size_t count);
off_t lseek(int fd, off_t offset, int origin);
int dup(int fd);
int dup2(int source, int target);
int dup3(int source, int target, int flags);
int chdir(const char *path);
char *getcwd(char *buffer, size_t size);
_Noreturn void _exit(int status);
#endif
