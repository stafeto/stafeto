// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
/* Genuine PID death, with no observer-issued rescue operation. */
static int death_capture(int fd, int source, uint64_t epoch, const struct record initial[20]) {
    char name[64];
    for (unsigned i = 0; i < 16; ++i) {
        path(name, "go", i); struct record r;
        if (publish(name, NULL, 0) || ring_phase(i, 'S', &r) || !capacity_exact(&initial[i], &r)
            || full_wait_observe((unsigned)source, (unsigned)r.pid, cookie, r.label,
                                 (unsigned)r.key_slot, r.key_generation, 1) != 1)
            return fail("death sixteen actual Sleeping", i);
        ring_results[i] = r;
    }
    uint64_t out[6];
    if (totals(fd, epoch, out) || out[1] != 256 || out[2] || out[3] || out[4] != 128 || out[5] != 8
        || death_runner != (pid_t)initial[0].pid || initial[0].count != 12)
        return fail("death actual256 and parent identity", 0);
    if (kill(death_runner, SIGTERM)) return fail("death genuine SIGTERM", 0);
    int status = 0;
    if (waitpid(death_runner, &status, 0) != death_runner || !WIFSIGNALED(status)
        || WTERMSIG(status) != SIGTERM || alive((unsigned)death_runner, 0))
        return fail("death parent waitpid and Page", 0);
    death_reaped = 1;
    int settled = 0;
    for (unsigned n = 0; n < 3000; ++n) {
        if (totals(fd, epoch, out)) return fail("death actual budget", n);
        int gone = full_wait_observe((unsigned)source, (unsigned)initial[0].pid, cookie,
                                     ring_results[0].label, (unsigned)ring_results[0].key_slot,
                                     ring_results[0].key_generation, 0);
        if (gone < 0) return fail("death exact observer", n);
        if (!gone && out[1] == 244 && !out[2] && !out[3] && out[4] == 116 && out[5] == 8) { settled = 1; break; }
        nanosleep(&tick, NULL);
    }
    if (!settled) return fail("death exact Queue Pool and retired cleanup", 0);
    for (unsigned i = 1; i < 16; ++i) {
        struct record r;
        if (ring_phase(i, 'S', &r) || r.key_slot != ring_results[i].key_slot
            || r.key_generation != ring_results[i].key_generation || r.complete_seen
            || kill((pid_t)initial[i].pid, SIGUSR1) || ring_phase(i, 'E', &r)
            || !capacity_exact(&initial[i], &r) || r.error != EINTR || r.result != -1
            || !r.release_seen || !r.complete_seen || r.canonical != full_cancelled())
            return fail("death remaining genuine cancellation", i);
        ring_results[i] = r;
        if (full_wait_observe((unsigned)source, (unsigned)r.pid, cookie, r.label,
                              (unsigned)r.key_slot, r.key_generation, 0) != 0)
            return fail("death remaining exact debt", i);
    }
    if (totals(fd, epoch, out) || out[1] != 244 || out[2] || out[3] || out[4] != 116 || out[5] != 8)
        return fail("death final actual244", 0);
    printf("lock-full: death profile=%u sleeping=16 departed=1 cancelled=15 published=244 private=0 retired=0 common=116 payers=8\n", profile);
    return 0;
}
static int death_effect(int fd, uint64_t epoch, unsigned row, unsigned bit, uint64_t pages[20][6]) {
    int code = full_telemetry((unsigned)fd, 1, cookie, epoch, row << 16, pages[0]);
    if (code == -304) return 0;
    if (code) return -1;
    for (unsigned page = 1; page < 20; ++page)
        if (full_telemetry((unsigned)fd, 1, cookie, epoch, (row << 16) | page, pages[page])) return -1;
    if (full_row_valid(pages) || !(pages[0][4] & (1u << bit)) || (pages[19][4] & (1u << bit))) return -1;
    return 1;
}
static int death_rows(int fd, uint64_t epoch, const struct record *initial) {
    uint64_t pages[20][6];
    if (death_effect(fd, epoch, 27, 12, pages) != 1) return fail("death exact registration effect", 0);
    uint64_t *w = pages[14];
    if (w[2] != ring_results[0].label || (uint32_t)w[3] != ring_results[0].key_slot
        || !(w[3] >> 32) || (w[3] >> 32) > 16 || w[4] != ring_results[0].key_generation
        || (uint32_t)w[5] != full_cancelled() || ((w[5] >> 32) & 255) != 0 || (w[5] >> 40) >= 5120)
        return fail("death complete removed registration identity", 0);
    int audit = death_effect(fd, epoch, 26, 8, pages);
    if (audit < 0) return fail("death audit exact row", 0);
    if (audit) {
        w = pages[10]; uint64_t first = (uint32_t)w[3], end = w[3] >> 32;
        if (w[2] != initial->pid || w[4] != initial->pid % 256 || w[4] < first || w[4] >= end
            || end - first > 8 || w[5] != 1) return fail("death exact actual removed PID", 0);
    }
    if (death_effect(fd, epoch, 30, 0, pages) != 1) return fail("death exact Actor group retirement", 0);
    w = pages[2];
    if (w[2] != initial->pid || !w[4] || !w[5]
        || (((uint64_t)(uint32_t)w[3] + 1) | (w[4] << 32)) != initial->inode)
        return fail("death actual full PID inode group", 0);
    printf("lock-full: death effects profile=%u exact-registration=1 exact-group=1 natural-audit=%d\n", profile, audit);
    return 0;
}
