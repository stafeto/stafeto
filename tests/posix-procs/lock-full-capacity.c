// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
/* Included only by the dedicated full-capacity image, after shared helpers. */
extern int full_wait_observe(unsigned, unsigned, uint64_t, uint64_t, unsigned, uint64_t, unsigned);
extern int full_wait_retired(unsigned, uint64_t);
extern unsigned full_no_locks(void);
extern unsigned full_cancelled(void);
static int ring_phase(unsigned, char, struct record *);
static void capacity_handler(int signal) {
    int saved = errno;
    if (signal == SIGUSR1) {
#if FULL_WAKE
#if FULL_CLOSE
        int result = close(close_alias);
#else
        struct flock lock = {.l_type = F_UNLCK, .l_whence = SEEK_SET, .l_start = 2, .l_len = 1};
        int result = fcntl(wake_fd, F_SETLK, &lock);
#endif
        capacity_error = result ? errno : 0;
        capacity_signal = result ? -1 : 1;
#else
        capacity_signal = 1;
#endif
    }
    errno = saved;
}
#if !FULL_WAKE
static int capacity_wait(int target, unsigned index, struct record *r) {
    struct sigaction action = {.sa_handler = capacity_handler};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, NULL)) return fail("capacity handler", index);
    char name[64]; path(name, "go", index);
    if (gate(name)) return fail("capacity Start gate", index);
    ring_record = *r; ring_index = index; ring_bad = 0; capacity_signal = 0;
    full_ring_arm();
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
    errno = 0;
    int result = fcntl(target, F_SETLKW, &lock), error = errno;
    full_ring_disarm(); *r = ring_record;
    if (ring_bad || !r->key_generation || !r->release_seen || result != -1
        || (index < 16 ? (!capacity_signal || !r->complete_seen || error != EINTR || r->canonical != full_cancelled())
                        : (!r->complete_seen || error != ENOLCK || r->canonical != full_no_locks())))
        return fail("capacity exact canonical cancellation or NO_LOCKS", index);
    if (full_wait_retired((unsigned)r->key_slot, r->key_generation) != 1)
        return fail("capacity local ack and retired key", index);
    printf("lock-full: capacity key profile=%u owner=%u pid=%llu label=%llu slot=%llu gen=%llu source=%llu/%llu canonical=%u result=%d errno=%d\n",
           profile, index, (unsigned long long)r->pid, (unsigned long long)r->label,
           (unsigned long long)r->key_slot, (unsigned long long)r->key_generation,
           (unsigned long long)r->wait_source[0], (unsigned long long)r->wait_source[1], r->canonical, result, error);
    r->result = result; r->error = error; r->phase = index < 16 ? 'E' : 'N';
    if (write_record(index, r)) return fail("capacity terminal metadata", index);
    return 0;
}
#endif
static int capacity_exact(const struct record *initial, const struct record *r) {
    return r->label == initial->label && r->pid == initial->pid && r->key_generation
        && r->key_slot < 16 && !memcmp(r->wait_source, initial->wait_source, sizeof(r->wait_source));
}
#if !FULL_WAKE && !FULL_DEATH
static int capacity_capture(int fd, int source, uint64_t epoch, const struct record initial[20]) {
    char name[64];
    for (unsigned i = 0; i < 16; ++i) {
        path(name, "go", i);
        struct record r;
        if (publish(name, NULL, 0) || ring_phase(i, 'S', &r) || !capacity_exact(&initial[i], &r))
            return fail("sixteen real capacity Sleeping", i);
        if (full_wait_observe((unsigned)source, (unsigned)r.pid, cookie, r.label,
                              (unsigned)r.key_slot, r.key_generation, 1) != 1)
            return fail("exact genuine Sleeping registration", i);
        ring_results[i] = r;
    }
    uint64_t out[6];
    if (totals(fd, epoch, out) || out[1] != 256 || out[2] || out[3] || out[4] != 128 || out[5] != 8)
        return fail("capacity sixteen retains filled256", 16);
    path(name, "go", 16);
    struct record extra;
    if (publish(name, NULL, 0) || ring_phase(16, 'N', &extra) || !capacity_exact(&initial[16], &extra)
        || extra.result != -1 || extra.error != ENOLCK || extra.canonical != full_no_locks()
        || !extra.release_seen || !extra.complete_seen)
        return fail("seventeenth genuine global capacity refusal", 16);
    ring_results[16] = extra;
    for (unsigned i = 0; i < 16; ++i) {
        if (kill((pid_t)initial[i].pid, SIGUSR1)) return fail("genuine capacity SIGUSR1", i);
        struct record r;
        if (ring_phase(i, 'E', &r) || !capacity_exact(&initial[i], &r) || r.result != -1
            || r.error != EINTR || !r.complete_seen || !r.release_seen)
            return fail("genuine canonical EINTR", i);
        ring_results[i] = r;
        if (full_wait_observe((unsigned)source, (unsigned)r.pid, cookie, r.label,
                              (unsigned)r.key_slot, r.key_generation, 0) != 0)
            return fail("exact Queue and Pool debt gone", i);
    }
    if (totals(fd, epoch, out) || out[1] != 256 || out[2] || out[3] || out[4] != 128 || out[5] != 8)
        return fail("capacity cancellation retains filled256", 0);
    printf("lock-full: capacity profile=%u sleeping=16 refused=1 cancelled=16 published=256 private=0 retired=0 common=128 payers=8\n", profile);
    return 0;
}

#endif
#if FULL_WAKE
#include "lock-full-wake.c"
#endif
