// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
/* Genuine same-PID alias close while an exact unrelated WAIT stays live. */
static int close_capture(int fd, int source, int witness, const uint64_t exact_source[2], uint64_t epoch, const struct record initial[20]) {
    char name[64];
    for (unsigned i = 0; i < 16; ++i) {
        struct record r; path(name, "go", i);
        if (publish(name, NULL, 0) || ring_phase(i, 'S', &r) || !capacity_exact(&initial[i], &r)
            || full_wait_observe((unsigned)source, (unsigned)r.pid, cookie, r.label,
                                 (unsigned)r.key_slot, r.key_generation, 1) != 1)
            return fail("close sixteen genuine Sleeping", i);
        ring_results[i] = r;
    }
    uint64_t out[6];
    if (totals(fd, epoch, out) || out[1] != 256 || out[2] || out[3] || out[4] != 128 || out[5] != 8)
        return fail("close initial filled256", 0);
    if (kill((pid_t)initial[0].pid, SIGUSR1)) return fail("close genuine restarting SIGUSR1", 0);
    struct record after;
    if (ring_phase(0, 'W', &after) || !capacity_exact(&initial[0], &after)
        || after.key_slot != ring_results[0].key_slot || after.key_generation != ring_results[0].key_generation
        || after.signal_status != 1 || after.signal_error || after.complete_seen || after.release_seen)
        return fail("handler unlock keeps exact live WAIT", 0);
    for (unsigned n = 0; n < 1024; ++n) {
        if (totals(fd, epoch, out)) return fail("close actual cleanup budget", n);
        if (!out[2] && !out[3]) break;
    }
    if (alive((unsigned)initial[0].pid, 1) || out[1] != 244 || out[2] || out[3] || out[4] != 116 || out[5] != 8)
        return fail("actual handler244 common116", 0);
    uint64_t actual_source[2];
    if (full_source((unsigned)witness, actual_source) || memcmp(actual_source, exact_source, sizeof(actual_source)))
        return fail("close retained exact range source", 0);
    struct flock critical = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
    struct flock filler = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 2, .l_len = 1};
    if (fcntl(witness, F_GETLK, &critical) || critical.l_type != F_UNLCK
        || fcntl(witness, F_GETLK, &filler) || filler.l_type != F_UNLCK)
        return fail("same-PID close removed critical and filler", 0);
    printf("lock-full: close handler profile=%u published=244 common=116 label=%llu key=%llu/%llu\n", profile,
           (unsigned long long)after.label, (unsigned long long)after.key_slot, (unsigned long long)after.key_generation);
    path(name, "go", 16);
    if (publish(name, NULL, 0)) return fail("release background critical", 16);
    for (unsigned i = 0; i < 16; ++i) {
        struct record r;
        if (ring_phase(i, 'O', &r) || !capacity_exact(&initial[i], &r)
            || r.key_slot != ring_results[i].key_slot || r.key_generation != ring_results[i].key_generation
            || r.result || r.canonical || !r.complete_seen || !r.release_seen)
            return fail("all sixteen close canonical successes", i);
        ring_results[i] = r;
        if (full_wait_observe((unsigned)source, (unsigned)r.pid, cookie, r.label,
                              (unsigned)r.key_slot, r.key_generation, 0) != 0)
            return fail("close exact Queue and Pool debt gone", i);
    }
    for (unsigned n = 0; n < 1024; ++n) {
        if (totals(fd, epoch, out)) return fail("close actual final occupancy", n);
        if (!out[2] && !out[3]) break;
    }
    if (out[1] != 243 || out[2] || out[3] || out[4] != 116 || out[5] != 8)
        return fail("close honest243 common116", 0);
    printf("lock-full: close profile=%u sleeping=16 successes=16 published=243 private=0 retired=0 common=116 payers=8\n", profile);
    return 0;
}

static int close_rows(int fd, uint64_t epoch, const struct record *initial) {
    uint64_t pages[20][6];
    for (unsigned page = 0; page < 20; ++page)
        if (full_telemetry((unsigned)fd, 1, cookie, epoch, (28u << 16) | page, pages[page]))
            return fail("close exact effect pages", page);
    if (full_row_valid(pages) || !(pages[0][4] & (1u << 15)) || (pages[19][4] & (1u << 15)))
        return fail("close bounded unambiguous actual revoke", 0);
    uint64_t *w = pages[17];
    if (w[2] != initial->pid || (uint32_t)w[3] != (uint32_t)initial->source[0]
        || (w[3] >> 32) >= 16 || w[4] != initial->source[1] || !w[5])
        return fail("close actual PID source description CloseKey", 0);
    printf("lock-full: close effect profile=%u pid=%llu source=%llu/%llu key=%llu/%llu last-alias=0\n",
           profile, (unsigned long long)w[2], (unsigned long long)(uint32_t)w[3],
           (unsigned long long)w[4], (unsigned long long)(w[3] >> 32), (unsigned long long)w[5]);
    return 0;
}
