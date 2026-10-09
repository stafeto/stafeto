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
extern int files_data_stages(void);
extern int files_change_stages(void);
extern int files_names_stages(void);
extern int files_names_hold_places(int tenths);
extern int files_names_wait_for_places(void);
extern int files_names_places_in_use(void);
#include "pending-open.c"
#include "open-policy.c"
#include "names.c"
#if LOADER_ABORT_PROBE
#include "loader-abort.c"
#endif
/* A thread holds the sixteen places of the jobs of the session for thirty
 * milliseconds; an operation of another thread waits for one and goes on. */
static volatile int holder_result = -1;
static void *holder(void *unused) {
    holder_result = files_names_hold_places(300);
    return unused;
}
static long long monotonic_ms(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (long long)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}
static int check_wait_for_places(void) {
    pthread_t thread;
    if (pthread_create(&thread, NULL, holder, NULL)) return 71;
    for (int turns = 0; files_names_places_in_use() < 16; turns++) {
        if (turns > 2000) return 72;
        struct timespec pause = {0, 1000000};
        nanosleep(&pause, NULL);
    }
    long long start = monotonic_ms();
    int answer = files_names_wait_for_places();
    long long waited = monotonic_ms() - start;
    pthread_join(thread, NULL);
    if (answer != 0) { printf("posix-files: the operation among sixteen gave %d\n", answer); return 73; }
    if (holder_result != 0) return 74;
    if (waited < 10) { printf("posix-files: the operation did not wait: %lld ms\n", waited); return 75; }
    return 0;
}

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
    fd = open("/etc/motd", O_RDONLY | O_CREAT, 0600);
    if (fd < 0 || close(fd)) return 17;
    errno = 0;
    if (open("/tmp/changes-missing", O_WRONLY | O_TRUNC, 0600) != -1 || errno != ENOENT) return 18;
    puts("posix-files: device flags and existing CREATE ok");
    int policy = check_open_policy();
    if (policy) { printf("posix-files: public Open policy failed %d\n", policy); return 23; }
    int staged = files_open_stages();
    if (staged) { printf("posix-files: staged Open failed %d\n", staged); return 14; }
    puts("posix-files: staged CREATE/TRUNC cached outcome and hidden fd ok");
    int data = files_data_stages();
    if (data) { printf("posix-files: Data stages failed %d\n", data); return 24; }
    puts("posix-files: paid Data bytes, replay, exact lease and cleanup ok");
    int change = files_change_stages();
    if (change) { printf("posix-files: Change stages failed %d\n", change); return 25; }
    puts("posix-files: raw Change requests ok");
    int names = files_names_stages();
    if (names) { printf("posix-files: names stages failed %d\n", names); return 26; }
    int waiting = check_wait_for_places();
    if (waiting) { printf("posix-files: waiting for a place failed %d\n", waiting); return 28; }
    puts("posix-files: an operation of a thread waited for the places of another and went on");
    int names_probe = names_all();
    if (names_probe) { printf("posix-files: names failed %d\n", names_probe); return 29; }
    puts("posix-files: names and metadata functions ok");
    puts("posix-files: layer names ok");
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
