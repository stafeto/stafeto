// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
/* Real published segments; metadata and gates never alias a locked inode. */
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <signal.h>
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
#ifndef FULL_DUP
#define FULL_DUP 0
#endif
#if FULL_DUP
static int dup_primary = -1, dup_alias = -1, dup_source = -1, dup_foreign_b = -1;
#endif
#ifndef FULL_OFD
#define FULL_OFD 0
#endif
#if FULL_OFD
static int ofd_primary = -1, ofd_alias = -1;
#endif
#ifndef FULL_RING
#define FULL_RING 0
#endif
#ifndef FULL_CAPACITY
#define FULL_CAPACITY 0
#endif
#ifndef FULL_WAKE
#define FULL_WAKE 0
#endif
#ifndef FULL_DEATH
#define FULL_DEATH 0
#endif
#ifndef FULL_CLOSE
#define FULL_CLOSE 0
#endif
#if FULL_CLOSE
static int close_alias = -1;
#endif
#if FULL_DEATH
static pid_t death_runner;
static int death_reaped;
#endif
#if FULL_CAPACITY
static volatile sig_atomic_t capacity_signal;
#if FULL_WAKE
static volatile sig_atomic_t capacity_error;
#endif
#if FULL_WAKE && !FULL_CLOSE
static int wake_fd = -1;
#endif
#endif
static unsigned profile, family;
static const uint64_t cookie = UINT64_C(0x66756c6c32353601);
struct record {
    uint64_t pid, root, generation, inode, source[2];
    unsigned family, count;
    char phase;
#if FULL_RING
    uint64_t label, wait_source[2], key_slot, key_generation;
    int result, error;
    unsigned complete_seen, release_seen, canonical;
    int signal_status, signal_error;
#endif
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
#if FULL_RING
static int set(int fd, short kind, unsigned segment);
extern void full_ring_arm(void);
extern void full_ring_disarm(void);
extern int full_row_valid(const uint64_t[20][6]);
extern unsigned full_ring_method_mask(void);
static struct record ring_results[17];
static struct record ring_record;
static unsigned ring_index;
static int ring_bad;
/* Observational hook after actual Start/Arm or strict terminal decoding. */
void full_ring_observed(unsigned phase, unsigned slot, uint64_t generation,
                        unsigned packed, uint64_t description_generation, unsigned canonical) {
    int saved = errno;
    if (!generation || slot >= 16 || packed != ring_record.wait_source[0]
        || description_generation != ring_record.wait_source[1]) ring_bad = 1;
    if (ring_record.key_generation && (ring_record.key_slot != slot
        || ring_record.key_generation != generation)) ring_bad = 1;
    ring_record.key_slot = slot; ring_record.key_generation = generation;
    if (phase == 1) ring_record.phase = 'S';
#if FULL_WAKE
    ring_record.signal_status = capacity_signal; ring_record.signal_error = capacity_error;
    if (phase == 1 && capacity_signal) ring_record.phase = 'W';
#endif
    if (phase == 2) { ring_record.phase = 'C'; ring_record.complete_seen = 1; }
    if (phase == 3) ring_record.release_seen = 1;
    if (canonical != ~0u) ring_record.canonical = canonical;
    if (write_record(ring_index, &ring_record)) ring_bad = 1;
    errno = saved;
}
static int ring_identity(int fd, struct record *r, int target) {
    uint64_t out[6], source[2];
    if (full_source((unsigned)fd, source) || full_telemetry((unsigned)fd, 6, cookie, 0, 0, out)
        || out[0] || !out[1] || out[2] != r->pid || out[3] != r->root
        || out[4] != r->generation || out[5] != source[1]) return -1;
    if (target) {
        if (r->label != out[1]) return -1;
        memcpy(r->wait_source, source, sizeof(source));
    } else r->label = out[1];
    return 0;
}
#if !FULL_CAPACITY
static int ring_wait(int own, int target, unsigned index, struct record *r) {
    char name[64]; path(name, "go", index);
    if (gate(name)) return fail("ring Start gate", index);
    ring_record = *r; ring_index = index; ring_bad = 0;
    full_ring_arm();
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
    errno = 0;
    int result = fcntl(target, F_SETLKW, &lock), error = errno;
    full_ring_disarm();
    *r = ring_record;
    if (ring_bad || !r->complete_seen || !r->key_generation
        || (result != 0 && (result != -1 || error != EDEADLK))) {
        printf("lock-full: ring diagnostic owner=%u result=%d error=%d bad=%d complete=%u phase=%c label=%llu key=%llu/%llu target=%llu/%llu\n",
               index, result, error, ring_bad, r->complete_seen, r->phase,
               (unsigned long long)r->label, (unsigned long long)r->key_slot,
               (unsigned long long)r->key_generation, (unsigned long long)r->wait_source[0],
               (unsigned long long)r->wait_source[1]);
        return fail("ring canonical result", index);
    }
    /* Keep fillers and both descriptors; remove only each critical segment. */
    if (!result && set(target, F_UNLCK, 0)) return fail("ring acquired unlock", index);
    if (set(own, F_UNLCK, 0)) return fail("ring original unlock", index);
    printf("lock-full: ring terminal owner=%u result=%d errno=%d key=%llu/%llu\n", index,
           result, error, (unsigned long long)r->key_slot, (unsigned long long)r->key_generation);
    r->result = result; r->error = error; r->phase = result ? 'D' : 'O';
    if (write_record(index, r)) return fail("ring terminal metadata", index);
    return 0;
}
#endif
#endif
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
#if FULL_OFD
    if (fd == ofd_primary) return fcntl(fd, F_OFD_SETLK, &lock);
#endif
#if FULL_DUP > 1
    if (fd == dup_primary) return fcntl(fd, F_OFD_SETLK, &lock);
#endif
    return fcntl(fd, F_SETLK, &lock);
}
#if FULL_CAPACITY
#include "lock-full-capacity.c"
#endif
#if FULL_OFD
static int ofd_hold(int fd, unsigned index, struct record *record);
#endif
#if FULL_DUP
static int dup_setup(int fd);
static int dup_hold(int fd, unsigned index, struct record *record);
#endif
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
#if FULL_RING
    int target = -1;
    if (index < (FULL_CAPACITY ? 17u : 16u)) {
        path(name, "file", FULL_CAPACITY ? (index < 16 ? 16 : 0) : (index + 1) % 16); target = open(name, O_RDWR);
        if (target < 0 || ring_identity(fd, &r, 0) || ring_identity(target, &r, 1))
            return fail("authenticated own and WAIT sources", index);
    }
#endif
#if FULL_WAKE
    if (index < 16) {
        struct sigaction action = {.sa_handler = capacity_handler, .sa_flags = SA_RESTART};
        sigemptyset(&action.sa_mask);
#if FULL_CLOSE
        action.sa_flags = index == 0 ? SA_RESTART : 0;
        if (!index) {
            uint64_t alias_source[2];
            close_alias = dup(fd);
            if (close_alias < 0 || full_source((unsigned)close_alias, alias_source)
                || memcmp(alias_source, r.source, sizeof(alias_source)))
                return fail("pre-Begin exact original-description alias", index);
        }
#else
        if (!index) wake_fd = fd;
#endif
        if (sigaction(SIGUSR1, &action, NULL)) return fail("pre-Begin wake handler", index);
    }
#endif
#if FULL_OFD
    if (!index) {
        uint64_t alias_source[2];
        ofd_primary = fd; ofd_alias = dup(fd);
        if (ofd_alias < 0 || full_source((unsigned)ofd_alias, alias_source)
            || memcmp(alias_source, r.source, sizeof(alias_source)) || pwrite(fd, "Q", 1, 0) != 1)
            return fail("real OFD alias and read byte", index);
    }
#endif
#if FULL_DUP
    if (!index && dup_setup(fd)) return fail("pre-Begin replacement descriptors", index);
#endif
    for (unsigned s = 0; s < r.count; ++s) {
        if (drained(fd) || set(fd, F_WRLCK, s)) return fail("real SET", index);
    }
    if (drained(fd) || write_record(index, &r) || turn(index, 1)) return fail("publish holder", index);
#if FULL_RING
    #if FULL_CAPACITY
    #if FULL_WAKE
    if (index < 17 && wake_wait(fd, target, index, &r)) return 1;
#else
    if (index < (FULL_DEATH ? 16u : 17u) && capacity_wait(target, index, &r)) return 1;
#endif
#else
    if (index < 16 && ring_wait(fd, target, index, &r)) return 1;
#endif
#endif
#if FULL_OFD
    if (!index) return ofd_hold(fd, index, &r);
#endif
#if FULL_DUP
    if (!index) return dup_hold(fd, index, &r);
#endif
    if (gate("/tmp/lock-full-stop")) return fail("Stop gate", index);
    uint64_t exact[2];
    if (full_source((unsigned)fd, exact) || memcmp(exact, r.source, sizeof(exact)) || fstat(fd, &st)
        || (uint64_t)st.st_ino != r.inode) return fail("retained source generation", index);
    /* No source close or broad unlock occurs before the capture Stop. */
    for (unsigned s = 0; s < r.count; ++s) if (set(fd, F_UNLCK, s)) return fail("teardown unlock", index);
#if FULL_RING
    if (target >= 0) {
        if (full_source((unsigned)target, exact) || memcmp(exact, r.wait_source, sizeof(exact))
            || close(target)) return fail("retained WAIT source generation", index);
    }
#endif
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
#if FULL_DUP
    if (publish("/tmp/lock-full-dup-state", NULL, 0)) return fail("create replacement metadata", 0);
#endif
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
#if FULL_RING
static int ring_phase(unsigned index, char wanted, struct record *out) {
    for (unsigned n = 0; n < 3000; ++n) {
        if (read_record(index, out)) return -1;
        if (out->phase == wanted || (wanted == 'T' && (out->phase == 'D' || out->phase == 'O' || out->phase == 'E' || out->phase == 'N'))) return 0;
        if (out->phase == 'D' || out->phase == 'O' || (wanted == 'S' && out->phase == 'C')) return -1;
        nanosleep(&tick, NULL);
    }
    return -1;
}
#if !FULL_CAPACITY
static int ring_capture(int fd, uint64_t epoch, const struct record initial[20]) {
    for (unsigned i = 0; i < 16; ++i) {
        char name[64]; path(name, "go", i);
        if (publish(name, NULL, 0)) return fail("release exact ring owner", i);
        printf("lock-full: ring await Sleeping owner=%u\n", i);
        if (i < 15) {
            struct record r;
            if (ring_phase(i, 'S', &r) || !r.key_generation || r.key_slot >= 16
                || r.label != initial[i].label || r.pid != initial[i].pid
                || memcmp(r.wait_source, initial[i].wait_source, sizeof(r.wait_source)))
                return fail("actual first fifteen sleeping keys", i);
            printf("lock-full: ring Sleeping owner=%u label=%llu key=%llu/%llu\n", i,
                   (unsigned long long)r.label, (unsigned long long)r.key_slot,
                   (unsigned long long)r.key_generation);
        } else printf("lock-full: ring final Start released\n");
    }
    unsigned success = 0, deadlock = 0;
    for (unsigned i = 0; i < 16; ++i) {
        struct record r;
        printf("lock-full: ring await terminal owner=%u\n", i);
        if (ring_phase(i, 'T', &r) || !r.complete_seen || !r.key_generation
            || r.label != initial[i].label || r.pid != initial[i].pid
            || memcmp(r.wait_source, initial[i].wait_source, sizeof(r.wait_source))
            || (r.phase == 'D' ? (r.result != -1 || r.error != EDEADLK) : r.result != 0))
            return fail("all exact ring terminal receipts", i);
        ring_results[i] = r;
        success += r.result == 0; deadlock += r.result == -1 && r.error == EDEADLK;
        printf("lock-full: ring key profile=%u owner=%u label=%llu slot=%llu gen=%llu source=%llu/%llu result=%d errno=%d\n",
               profile, i, (unsigned long long)r.label, (unsigned long long)r.key_slot,
               (unsigned long long)r.key_generation, (unsigned long long)r.wait_source[0],
               (unsigned long long)r.wait_source[1], r.result, r.error);
    }
    uint64_t out[6];
    for (unsigned n = 0; n < 1024; ++n) {
        if (totals(fd, epoch, out)) return fail("ring occupancy RPC", n);
        if (!out[2] && !out[3]) break;
    }
    if (out[1] != 240 || out[2] || out[3] || out[4] != 112 || out[5] != 8
        || success != 15 || deadlock != 1) return fail("honest ring 240/0/0/112/8 transition", 0);
    printf("lock-full: ring profile=%u successes=15 deadlock=1 published=240 private=0 retired=0 common=112 payers=8\n", profile);
    return 0;
}
#endif
static int ring_rows(int fd, uint64_t epoch) {
    unsigned covered = 0, methods = 0, full_deadlock = 0;
    for (unsigned row = 0; row < 32; ++row) {
        uint64_t pages[20][6] = {{0}};
        int code = full_telemetry((unsigned)fd, 1, cookie, epoch, row << 16, pages[0]);
        if (code == -304) continue;
        if (code) return fail("strict row header", row);
        for (unsigned page = 1; page < 20; ++page)
            if (full_telemetry((unsigned)fd, 1, cookie, epoch, (row << 16) | page, pages[page]))
                return fail("strict row page", row);
        if (full_row_valid(pages)) return fail("complete bounded row", row);
        unsigned mask = (unsigned)pages[0][4], kind = (unsigned)pages[0][5];
        covered |= mask;
        if (kind >= 54 && kind <= 58) methods |= 1u << (kind - 54);
        for (unsigned bit = 0; bit < 16; ++bit) {
            if (!(mask & (1u << bit))) continue;
            uint64_t *w = pages[2 + bit];
            unsigned visits = (unsigned)((pages[19][2 + bit / 8] >> ((bit % 8) * 8)) & 255);
            if ((bit == 2 || bit == 5 || bit == 7 || bit == 14) && !(pages[19][4] & (1u << bit))) {
                unsigned owner;
                for (owner = 0; owner < (FULL_CAPACITY ? 17u : 16u); ++owner)
                    if (ring_results[owner].label == w[2] && ring_results[owner].key_slot == w[3]
                        && ring_results[owner].key_generation == w[4]) break;
                if (owner == (FULL_CAPACITY ? 17u : 16u)) return fail("row full WAIT receipt identity", bit);
            }
            if (bit == 7 && pages[1][2] == (UINT64_C(256) | (UINT64_C(128) << 48))
                && pages[1][4] == 8 && !(pages[19][4] & (1u << bit))) full_deadlock = 1;
            printf("lock-full: dispatch profile=%u row=%u kind=%u bit=%u visited=%u before=%llu after=%llu took=%llu whole=%llu waited=%llu serial=%llu ambiguous=%u witness=%llu/%llu/%llu/%llu\n",
                   profile, row, kind, bit, visits, (unsigned long long)pages[1][2],
                   (unsigned long long)pages[1][3], (unsigned long long)pages[0][3],
                   (unsigned long long)pages[18][2], (unsigned long long)pages[18][3],
                   (unsigned long long)pages[0][1], (unsigned)((pages[19][4] >> bit) & 1), (unsigned long long)w[2],
                   (unsigned long long)w[3], (unsigned long long)w[4], (unsigned long long)w[5]);
        }
    }
    unsigned required = (1u << 0) | (1u << 1) | (1u << 2) | (1u << 4)
        | (1u << 5) | (1u << 6) | (1u << 7) | (1u << 14);
    if (FULL_CAPACITY) required = (1u << 2) | (1u << 14);
    if (FULL_WAKE) required |= (1u << 0) | (1u << 1) | (1u << 4);
    if ((covered & required) != required || (methods & full_ring_method_mask()) != full_ring_method_mask() || (!FULL_CAPACITY && !full_deadlock))
        return fail("actual ring required branches and full deadlock", covered);
    printf("lock-full: %s dispatch profile=%u mask=%u methods=%u full-deadlock=%u\n", FULL_WAKE ? "wake" : FULL_CAPACITY ? "capacity" : "ring", profile, covered, methods, !FULL_CAPACITY);
    return 0;
}

#endif
#if FULL_DEATH
#include "lock-full-death.c"
#endif
#if FULL_CLOSE
#include "lock-full-close.c"
#endif
#if FULL_OFD
#include "lock-full-ofd.c"
#endif
#if FULL_DUP
#include "lock-full-dup.c"
#endif
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
#if FULL_WAKE || FULL_OFD || FULL_DUP
    int wake_witness = -1;
    uint64_t wake_source[2] = {0};
#endif
    for (unsigned i = 0; i < first(8); ++i) {
        struct record *r = &records[i];
        unsigned f = 0; while (first(f + 1) <= i) ++f;
        if (read_record(i, r) || r->phase != 'H' || r->family != f || r->count != segments(f, i - first(f))
            || !r->pid || r->pid == (uint64_t)getpid() || !r->root || !r->generation || !r->source[1]
            || alive((unsigned)r->pid, 1)) return fail("real owner metadata/Page", i);
#if FULL_RING
        if (i < (FULL_CAPACITY ? 17u : 16u) && (!r->label || !r->wait_source[1])) return fail("authenticated WAIT metadata", i);
#endif
        for (unsigned f = 0; f < 8; ++f) if (launchers[f] == r->pid) return fail("holder differs from launcher", i);
        for (unsigned old = 0; old < i; ++old) if (records[old].pid == r->pid || records[old].inode == r->inode) return fail("distinct owner/source", i);
        char name[64]; path(name, "file", i);
        int source = open(name, O_RDWR); struct stat st;
        if (source < 0 || fstat(source, &st) || (uint64_t)st.st_ino != r->inode) return fail("witness inode", i);
        for (unsigned edge = 0; edge < 2; ++edge) {
            struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = (off_t)(edge ? 2 * (r->count - 1) : 0), .l_len = 1};
            if (fcntl(source, F_GETLK, &lock) || lock.l_type != F_WRLCK || lock.l_pid != ((FULL_OFD || FULL_DUP > 1) && !i ? -1 : (pid_t)r->pid))
                return fail("foreign PID GETLK real critical/filler", i);
        }
#if FULL_WAKE || FULL_OFD || FULL_DUP
        if (!i) {
            if (full_source((unsigned)source, wake_source)) return fail("wake witness full source", i);
            wake_witness = source;
        } else
#endif
#if FULL_DUP
        if (i == 1) dup_foreign_b = source;
        else
#endif
        if (close(source)) return fail("witness close", i);
    }
    printf("lock-full: live Pages profile=%u launchers=8 holders=%u total=%u\n", profile, first(8), 8 + first(8));
    if (census(fd, records, 0)) return 1;
#if FULL_CAPACITY
    char observer_name[64]; path(observer_name, "file", 16);
    int observer_source = open(observer_name, O_RDWR);
    struct stat observer_stat;
    if (observer_source < 0 || fstat(observer_source, &observer_stat)
        || (uint64_t)observer_stat.st_ino != records[16].inode)
        return fail("pre-Begin exact observer source", 16);
#endif
#if FULL_RING
    if (full_telemetry((unsigned)fd, 6, 0, 0, 0, out) != -304
        || full_telemetry((unsigned)fd, 6, cookie, 0, 1, out) != -310)
        return fail("identity rejects zero nonce and stale source", 0);
#endif
#if FULL_OFD
    if (ofd_before(wake_witness, &records[0]) || close(fd)) return 1;
    fd = dup(wake_witness);
    if (fd < 0) return fail("exact witness Scope local alias", 0);
#endif
#if FULL_DUP
    uint64_t duplicate_who[4];
    if (full_identity((unsigned)getpid(), duplicate_who) || duplicate_who[0] == records[0].pid
        || duplicate_who[0] == records[1].pid || duplicate_who[2] != records[0].root
        || duplicate_who[3] != records[0].generation || close(fd)) return fail("actual foreign replacement payer", 0);
    fd = dup(wake_witness);
    if (fd < 0) return fail("replacement exact Scope alias", 0);
#endif
    if (full_telemetry((unsigned)fd, 0, cookie, 0, profile, out) || out[0] != 1 || out[1] != profile || out[2] != 32 || out[3] != 1 || out[4] || out[5] != 1)
        return fail("Begin stable witness", 0);
    uint64_t epoch = out[0];
#if FULL_RING
    if (full_telemetry((unsigned)fd, 6, cookie, 0, 0, out) != -310)
        return fail("identity forbidden after Begin", 0);
#endif
    if (full_telemetry((unsigned)fd, 3, cookie, epoch, 0, out) || out[3] != 1 || out[4]) return fail("Header capture live", 0);
    if (totals(fd, epoch, out) || out[1] != 256 || out[2] || out[3] || out[4] != 128 || out[5] != 8 || census(fd, records, epoch))
        return fail("retained stable witness", 0);
#if FULL_RING
    #if FULL_CAPACITY
    #if FULL_WAKE
#if FULL_CLOSE
    if (close_capture(fd, observer_source, wake_witness, wake_source, epoch, records)) return 1;
#else
    if (wake_capture(fd, observer_source, wake_witness, wake_source, epoch, records)) return 1;
#endif
#else
#if FULL_DEATH
    if (death_capture(fd, observer_source, epoch, records)) return 1;
#else
    if (capacity_capture(fd, observer_source, epoch, records)) return 1;
#endif
#endif
#else
    if (ring_capture(fd, epoch, records)) return 1;
#endif
#endif
#if FULL_OFD
    if (ofd_capture(fd, wake_witness, epoch, &records[0])) return 1;
#endif
#if FULL_DUP
    if (dup_capture(fd, wake_witness, epoch, records)) return 1;
#endif
    if (full_telemetry((unsigned)fd, 2, cookie, epoch, 0, out) || out[0] != epoch
        || out[1] != profile || out[2] != 32 || out[3] || out[4] || out[5] != epoch)
        return fail("Stop capture exact successful state", 0);
#if FULL_RING
    if (full_telemetry((unsigned)fd, 6, cookie, 0, 0, out) != -310)
        return fail("identity forbidden after Stop", 0);
    if (ring_rows(fd, epoch)) return 1;
#if FULL_DEATH
    if (death_rows(fd, epoch, &records[0])) return 1;
#endif
#if FULL_CLOSE
    if (close_rows(fd, epoch, &records[0])) return 1;
#endif
#endif
#if FULL_OFD
    if (ofd_rows(fd, epoch, &records[0])) return 1;
#endif
    printf("lock-full: %s profile=%u participating=%u owners=%u published=256 private=0 retired=0 common=128 payers=8 epoch=%llu\n",
           (FULL_RING | FULL_OFD | FULL_DUP) ? "initial" : "stable", profile, profile, first(8), (unsigned long long)epoch);
    #if FULL_CAPACITY
    if (close(observer_source)) return fail("observer close after Stop", 16);
#endif
#if FULL_WAKE || FULL_OFD || FULL_DUP
    if (close(wake_witness)) return fail("wake witness close after Stop", 0);
#endif
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
#if FULL_DEATH
    death_runner = child;
#endif
    int bad = !family ? coordinator() : 0;
#if FULL_DEATH
    if ((!family && death_reaped) ? 0 : reap(child))
#else
    if (reap(child))
#endif
        bad = fail("runner Page dead", family);
    if (!bad) printf("lock-full: genuine family %u profile=%u ok\n", family, profile);
    return bad;
}
