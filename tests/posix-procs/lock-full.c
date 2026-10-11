// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
/* Real published segments; metadata and gates never alias a locked inode. */
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
extern int full_telemetry(unsigned, unsigned, uint64_t, uint64_t, unsigned, uint64_t[6]);
extern int full_identity(unsigned, uint64_t[4]);
extern int full_source(unsigned, uint64_t[2]);
static unsigned profile, family;
static const uint64_t cookie = UINT64_C(0x66756c6c32353601);
struct record {
    uint64_t pid, root, generation, inode, source[2];
    unsigned family, count;
    char phase;
};
static struct timespec tick = {0, 10000000};
static unsigned owners(unsigned f) {
    return profile == 4 ? (f < 4 ? 4 : 1) : (f < 2 ? 3 : f < 7 ? 2 : 1);
}
static unsigned first(unsigned f) {
    unsigned n = 0;
    for (unsigned i = 0; i < f; ++i) n += owners(i);
    return n;
}
static unsigned segments(unsigned f, unsigned local) {
    if (profile == 4) return f < 4 ? 12 : 16;
    return f < 2 ? (local == 2 ? 11 : 12) : f < 7 ? 17 : 16;
}
static void path(char out[64], const char *kind, unsigned index) {
    snprintf(out, 64, "/tmp/lock-full-%s-%u", kind, index);
}
static int fail(const char *what, unsigned n) {
    printf("lock-full: FAIL profile=%u family=%u %s index=%u errno=%d\n", profile, family, what, n, errno);
    fflush(stdout); return 1;
}
static int publish(const char *name, const void *bytes, size_t size) {
    int fd = open(name, O_CREAT | O_EXCL | O_RDWR, 0666);
    if (fd < 0) return -1;
    int ok = fchmod(fd, 0666) == 0 && (!size || write(fd, bytes, size) == (ssize_t)size);
    if (close(fd)) ok = 0;
    return ok ? 0 : -1;
}
static int gate(const char *name) {
    for (unsigned n = 0; n < 3000; ++n) {
        int fd = open(name, O_RDONLY);
        if (fd >= 0) { close(fd); return 0; }
        nanosleep(&tick, NULL);
    }
    return -1;
}
static int read_record(unsigned index, struct record *r) {
    char name[64]; path(name, "state", index);
    int fd = open(name, O_RDONLY);
    if (fd < 0) return -1;
    int ok = read(fd, r, sizeof(*r)) == (ssize_t)sizeof(*r);
    close(fd); return ok ? 0 : -1;
}
static int write_record(unsigned index, const struct record *r) {
    char name[64]; path(name, "state", index);
    int fd = open(name, O_WRONLY);
    if (fd < 0) return -1;
    int ok = pwrite(fd, r, sizeof(*r), 0) == (ssize_t)sizeof(*r);
    close(fd); return ok ? 0 : -1;
}
static int turn(unsigned index, int advance) {
    for (unsigned n = 0; n < 3000; ++n) {
        int fd = open("/tmp/lock-full-turn", O_RDWR);
        unsigned actual = ~0u;
        if (fd < 0) return -1;
        int ok = pread(fd, &actual, sizeof(actual), 0) == (ssize_t)sizeof(actual);
        if (ok && actual == index && advance) {
            ++actual; ok = pwrite(fd, &actual, sizeof(actual), 0) == (ssize_t)sizeof(actual);
        }
        close(fd);
        if (!ok) return -1;
        if (actual == index + (unsigned)advance) return 0;
        nanosleep(&tick, NULL);
    }
    return -1;
}
static int totals(int fd, uint64_t epoch, uint64_t out[6]) {
    return full_telemetry((unsigned)fd, 5, cookie, epoch, 0, out);
}
static int drained(int fd) {
    uint64_t out[6];
    for (unsigned n = 0; n < 1024; ++n) {
        if (totals(fd, 0, out)) return -1;
        if (out[2] == 0 && out[3] == 0) return 0;
    }
    return -1;
}
static int set(int fd, short kind, unsigned segment) {
    struct flock lock = {.l_type = kind, .l_whence = SEEK_SET, .l_start = (off_t)(2 * segment), .l_len = 1};
    return fcntl(fd, F_SETLK, &lock);
}
static int hold(unsigned local) {
    unsigned index = first(family) + local;
    if (turn(index, 0)) return fail("setup turn", index);
    char name[64]; path(name, "file", index);
    int fd = open(name, O_RDWR);
    struct record r = {.family = family, .count = segments(family, local), .phase = 'H'};
    uint64_t who[4]; struct stat st;
    if (fd < 0 || full_identity((unsigned)getpid(), who) || who[0] != (uint64_t)getpid() || who[1] != 1
        || fstat(fd, &st) || full_source((unsigned)fd, r.source)) return fail("self source identity", index);
    r.pid = who[0]; r.root = who[2]; r.generation = who[3]; r.inode = (uint64_t)st.st_ino;
    for (unsigned s = 0; s < r.count; ++s) {
        if (drained(fd) || set(fd, F_WRLCK, s)) return fail("real SET", index);
    }
    if (drained(fd) || write_record(index, &r) || turn(index, 1)) return fail("publish holder", index);
    if (gate("/tmp/lock-full-stop")) return fail("Stop gate", index);
    uint64_t exact[2];
    if (full_source((unsigned)fd, exact) || memcmp(exact, r.source, sizeof(exact)) || fstat(fd, &st)
        || (uint64_t)st.st_ino != r.inode) return fail("retained source generation", index);
    /* No source close or broad unlock occurs before the capture Stop. */
    for (unsigned s = 0; s < r.count; ++s) if (set(fd, F_UNLCK, s)) return fail("teardown unlock", index);
    if (close(fd)) return fail("teardown close", index);
    return 0;
}
static int alive(unsigned target, int wanted) {
    uint64_t words[4];
    return full_identity(target, words) || words[1] != (uint64_t)wanted;
}
static int reap(pid_t child) {
    int status = 0;
    return waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) || alive((unsigned)child, 0);
}
static int runner(void) {
    /* All local forks precede acquisition of the runner's source and locks. */
    pid_t children[3] = {0};
    unsigned count = owners(family);
    for (unsigned i = 1; i < count; ++i) {
        pid_t child = fork();
        if (child < 0) return fail("real fork", i);
        if (!child) _exit(hold(i));
        children[i - 1] = child;
    }
    int bad = hold(0);
    for (unsigned i = 1; i < count; ++i) if (reap(children[i - 1])) bad = fail("child Page dead", i);
    return bad;
}
static int create_files(void) {
    unsigned zero = 0;
    struct record empty = {0};
    for (unsigned i = 0; i < first(8); ++i) {
        char name[64]; path(name, "file", i);
        if (publish(name, NULL, 0)) return fail("create source", i);
        path(name, "state", i);
        if (publish(name, &empty, sizeof(empty))) return fail("create metadata", i);
    }
    for (unsigned i = 0; i < 8; ++i) {
        char name[64]; path(name, "launcher", i);
        if (publish(name, &empty, sizeof(empty))) return fail("create launcher metadata", i);
    }
    if (publish("/tmp/lock-full-controller", NULL, 0) || publish("/tmp/lock-full-turn", &zero, sizeof(zero))) return fail("create gates", 0);
    int fd = open("/tmp/lock-full-controller", O_RDWR); uint64_t actual[6];
    if (fd < 0 || totals(fd, 0, actual) || actual[1] || actual[2] || actual[3] || actual[4] || actual[5]) return fail("actual empty Budget", 0);
    if (close(fd) || publish("/tmp/lock-full-ready", NULL, 0)) return fail("publish ready", 0);
    return 0;
}
static int census(int fd, const struct record records[20], uint64_t epoch) {
    uint64_t paid[8][2] = {{0}};
    unsigned counts[8] = {0};
    for (unsigned f = 0; f < 8; ++f) {
        const struct record *r = &records[first(f)];
        paid[f][0] = r->root; paid[f][1] = r->generation;
        for (unsigned i = 0; i < owners(f); ++i) {
            const struct record *o = &records[first(f) + i];
            if (o->root != paid[f][0] || o->generation != paid[f][1]) return fail("owner payer mismatch", f);
            counts[f] += o->count;
        }
        unsigned wanted = profile == 4 ? (f < 4 ? 48 : 16) : f < 2 ? 35 : f < 7 ? 34 : 16;
        if (counts[f] != wanted) return fail("approved payer distribution", f);
        for (unsigned old = 0; old < f; ++old) if (!memcmp(paid[old], paid[f], sizeof(paid[f]))) return fail("distinct Create payer", f);
    }
    unsigned first_slot = 0, found = 0, seen = 0;
    /* Each successful reply advances at least one physical index; no unbounded restart. */
    for (unsigned rpc = 0; first_slot < 320 && rpc < 320; ++rpc) {
        uint64_t out[6];
        if (full_telemetry((unsigned)fd, 4, cookie, epoch, first_slot, out)) return fail("actual census RPC", first_slot);
        uint64_t next = out[1], flags = out[2], visits = flags & ~(UINT64_C(1) << 63);
        if (!visits || visits > 8 || next != first_slot + visits || next > 320 || out[5] >> 48) return fail("census cursor", first_slot);
        if (flags >> 63) {
            unsigned f;
            for (f = 0; f < 8; ++f) if (paid[f][0] == out[3] && paid[f][1] == out[4]) break;
            if (f == 8 || seen & (1u << f) || out[5] != counts[f]) return fail("actual payer count or generation", first_slot);
            seen |= 1u << f; ++found;
            printf("lock-full: payer profile=%u family=%u root=%llu gen=%llu published=%u visits=%llu\n", profile, f,
                   (unsigned long long)out[3], (unsigned long long)out[4], counts[f], (unsigned long long)visits);
        } else if (out[3] || out[4] || out[5]) return fail("empty census identity", first_slot);
        first_slot = (unsigned)next;
    }
    return found != 8 || seen != 255 || first_slot != 320 ? fail("all eight actual payers", found) : 0;
}
static int coordinator(void) {
    int fd = open("/tmp/lock-full-controller", O_RDWR);
    if (fd < 0) return fail("controller open", 0);
    if (turn(first(8), 0) || drained(fd)) return fail("complete stable setup", 0);
    uint64_t out[6];
    if (totals(fd, 0, out) || out[1] != 256 || out[2] || out[3] || out[4] != 128 || out[5] != 8)
        return fail("actual 256/0/0/128/8 Budget", 0);
    uint64_t launchers[8] = {0};
    for (unsigned f = 0; f < 8; ++f) {
        char name[64]; path(name, "launcher", f);
        int meta = open(name, O_RDONLY); struct record r;
        if (meta < 0 || read(meta, &r, sizeof(r)) != (ssize_t)sizeof(r)) return fail("launcher metadata", f);
        close(meta);
        if (r.phase != 'L' || r.family != f || !r.pid || alive((unsigned)r.pid, 1)) return fail("launcher Page live", f);
        launchers[f] = r.pid;
        for (unsigned old = 0; old < f; ++old) if (launchers[old] == r.pid) return fail("distinct launchers", f);
    }
    struct record records[20] = {{0}};
    for (unsigned i = 0; i < first(8); ++i) {
        struct record *r = &records[i];
        unsigned f = 0; while (first(f + 1) <= i) ++f;
        if (read_record(i, r) || r->phase != 'H' || r->family != f || r->count != segments(f, i - first(f))
            || !r->pid || r->pid == (uint64_t)getpid() || !r->root || !r->generation || !r->source[1]
            || alive((unsigned)r->pid, 1)) return fail("real owner metadata/Page", i);
        for (unsigned f = 0; f < 8; ++f) if (launchers[f] == r->pid) return fail("holder differs from launcher", i);
        for (unsigned old = 0; old < i; ++old) if (records[old].pid == r->pid || records[old].inode == r->inode) return fail("distinct owner/source", i);
        char name[64]; path(name, "file", i);
        int source = open(name, O_RDWR); struct stat st;
        if (source < 0 || fstat(source, &st) || (uint64_t)st.st_ino != r->inode) return fail("witness inode", i);
        for (unsigned edge = 0; edge < 2; ++edge) {
            struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = (off_t)(edge ? 2 * (r->count - 1) : 0), .l_len = 1};
            if (fcntl(source, F_GETLK, &lock) || lock.l_type != F_WRLCK || lock.l_pid != (pid_t)r->pid)
                return fail("foreign PID GETLK real critical/filler", i);
        }
        if (close(source)) return fail("witness close", i);
    }
    printf("lock-full: live Pages profile=%u launchers=8 holders=%u total=%u\n", profile, first(8), 8 + first(8));
    if (census(fd, records, 0)) return 1;
    if (full_telemetry((unsigned)fd, 0, cookie, 0, profile, out) || out[0] != 1 || out[1] != profile || out[2] != 32 || out[3] != 1 || out[4] || out[5] != 1)
        return fail("Begin stable witness", 0);
    uint64_t epoch = out[0];
    if (full_telemetry((unsigned)fd, 3, cookie, epoch, 0, out) || out[3] != 1 || out[4]) return fail("Header capture live", 0);
    if (totals(fd, epoch, out) || out[1] != 256 || out[2] || out[3] || out[4] != 128 || out[5] != 8 || census(fd, records, epoch))
        return fail("retained stable witness", 0);
    if (full_telemetry((unsigned)fd, 2, cookie, epoch, 0, out)) return fail("Stop capture", 0);
    printf("lock-full: stable profile=%u participating=%u owners=%u published=256 private=0 retired=0 common=128 payers=8 epoch=%llu\n",
           profile, profile, first(8), (unsigned long long)epoch);
    if (close(fd) || publish("/tmp/lock-full-stop", NULL, 0)) return fail("release owners after Stop", 0);
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 4 || (strcmp(argv[1], "full-launch") && strcmp(argv[1], "full-run"))) return 1;
    profile = (unsigned)(argv[2][0] - '0'); family = (unsigned)(argv[3][0] - '0');
    if ((profile != 4 && profile != 7) || family > 7 || argv[2][1] || argv[3][1]) return 1;
    if (!strcmp(argv[1], "full-run")) return runner();
    if (!family) { if (create_files()) return 1; }
    else if (gate("/tmp/lock-full-ready")) return fail("files ready", family);
    uint64_t who[4]; struct record r = {.family = family, .phase = 'L'};
    if (full_identity((unsigned)getpid(), who) || who[0] != (uint64_t)getpid() || who[1] != 1) return fail("launcher self Page", family);
    r.pid = who[0]; r.root = who[2]; r.generation = who[3];
    char name[64]; path(name, "launcher", family); int meta = open(name, O_WRONLY);
    if (meta < 0 || pwrite(meta, &r, sizeof(r), 0) != (ssize_t)sizeof(r)) return fail("publish launcher identity", family);
    close(meta);
    char *args[] = {"procs-child", "full-run", argv[2], argv[3], NULL}, *env[] = {NULL};
    pid_t child = -1;
    int spawned = posix_spawn(&child, "/bin/procs-child", NULL, NULL, args, env);
    if (spawned) { errno = spawned; return fail("spawn mapped runner", family); }
    int bad = !family ? coordinator() : 0;
    if (reap(child)) bad = fail("runner Page dead", family);
    if (!bad) printf("lock-full: genuine family %u profile=%u ok\n", family, profile);
    return bad;
}
