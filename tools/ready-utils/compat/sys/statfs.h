// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
// The Linux AArch64 layout, for code that reads the fields.
#ifndef STAFETO_SYS_STATFS_H
#define STAFETO_SYS_STATFS_H
#include <sys/types.h>
typedef struct { int val[2]; } fsid_t;
struct statfs {
	long f_type, f_bsize;
	unsigned long f_blocks, f_bfree, f_bavail, f_files, f_ffree;
	fsid_t f_fsid;
	long f_namelen, f_frsize, f_flags, f_spare[4];
};
int statfs(const char *, struct statfs *);
int fstatfs(int, struct statfs *);
#endif
