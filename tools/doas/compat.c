/* SPDX-License-Identifier: ISC */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* What OpenDoas wants of the C library and relibc lacks: closefrom. The
 * descriptors of a process are few (the process service holds a small table),
 * so the loop stops at the lesser of the limit sysconf gives and 1024. */
#include <unistd.h>

void closefrom(int lowfd) {
    long max = sysconf(_SC_OPEN_MAX);
    if (max < 0 || max > 1024) max = 1024;
    for (long fd = lowfd; fd < max; fd++) (void)close((int)fd);
}

/* relibc's setresuid and setresgid answer ENOSYS for a change (the process
 * service has no call that sets the three identifiers apart). doas asks for all
 * three to be the same, which setuid and setgid do for a process of root. */
#include <errno.h>
#include <sys/types.h>

int setresgid(gid_t rgid, gid_t egid, gid_t sgid) {
    if (rgid == egid && egid == sgid) return setgid(rgid);
    errno = ENOSYS;
    return -1;
}

int setresuid(uid_t ruid, uid_t euid, uid_t suid) {
    if (ruid == euid && euid == suid) return setuid(ruid);
    errno = ENOSYS;
    return -1;
}
