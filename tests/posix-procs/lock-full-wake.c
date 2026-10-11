// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
/* Included only after the shared full-capacity helpers. */
static int wake_wait(int own, int target, unsigned index, struct record *r) {
    char name[64]; path(name, "go", index);
    if (index == 16) {
        if (gate(name) || set(own, F_UNLCK, 0)) return fail("background critical wake unlock", index);
        r->phase = 'U';
        return write_record(index, r) ? fail("background unlock observation", index) : 0;
    }
    /* Handler and immutable ownfd were installed before the published H metadata. */
    if (gate(name)) return fail("wake Start gate", index);
    ring_record = *r; ring_index = index; ring_bad = 0; capacity_signal = 0; capacity_error = 0;
    full_ring_arm();
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
    int result = fcntl(target, F_SETLKW, &lock), error = errno;
    full_ring_disarm(); *r = ring_record;
    if (ring_bad || result || !r->complete_seen || !r->release_seen || r->canonical
        || !r->key_generation || (!index && (r->signal_status != 1 || r->signal_error)))
        return fail("wake exact canonical success and retained custody", index);
    if (full_wait_retired((unsigned)r->key_slot, r->key_generation) != 1)
        return fail("wake local ack and retired key", index);
    if (set(target, F_UNLCK, 0)) return fail("wake acquired critical unlock", index);
    r->result = result; r->error = error; r->phase = 'O';
    printf("lock-full: wake key profile=%u owner=%u pid=%llu label=%llu slot=%llu gen=%llu source=%llu/%llu canonical=%u\n",
           profile, index, (unsigned long long)r->pid, (unsigned long long)r->label,
           (unsigned long long)r->key_slot, (unsigned long long)r->key_generation,
           (unsigned long long)r->wait_source[0], (unsigned long long)r->wait_source[1], r->canonical);
    return write_record(index, r) ? fail("wake terminal metadata", index) : 0;
}
static int wake_capture(int fd, int source, int witness, const uint64_t exact_source[2], uint64_t epoch, const struct record initial[20]) {
    char name[64];
    for (unsigned i = 0; i < 16; ++i) {
        struct record r; path(name, "go", i);
        if (publish(name, NULL, 0) || ring_phase(i, 'S', &r) || !capacity_exact(&initial[i], &r)
            || full_wait_observe((unsigned)source, (unsigned)r.pid, cookie, r.label,
                                 (unsigned)r.key_slot, r.key_generation, 1) != 1)
            return fail("wake sixteen genuine Sleeping", i);
        ring_results[i] = r;
    }
    uint64_t out[6];
    if (totals(fd, epoch, out) || out[1] != 256 || out[2] || out[3] || out[4] != 128 || out[5] != 8)
        return fail("wake initial filled256", 0);
    if (kill((pid_t)initial[0].pid, SIGUSR1)) return fail("wake genuine restarting SIGUSR1", 0);
    struct record after;
    if (ring_phase(0, 'W', &after) || !capacity_exact(&initial[0], &after)
        || after.key_slot != ring_results[0].key_slot || after.key_generation != ring_results[0].key_generation
        || after.signal_status != 1 || after.signal_error || after.complete_seen || after.release_seen)
        return fail("handler unlock keeps exact live WAIT", 0);
    if (totals(fd, epoch, out) || out[1] != 255 || out[2] || out[3] || out[4] != 127 || out[5] != 8)
        return fail("actual handler255 common127", 0);
    uint64_t actual_source[2];
    if (full_source((unsigned)witness, actual_source) || memcmp(actual_source, exact_source, sizeof(actual_source)))
        return fail("wake retained exact range source", 0);
    struct flock critical = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
    struct flock filler = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 2, .l_len = 1};
    if (fcntl(witness, F_GETLK, &critical) || critical.l_type != F_WRLCK
        || critical.l_pid != (pid_t)initial[0].pid || critical.l_start != 0 || critical.l_len != 1
        || fcntl(witness, F_GETLK, &filler) || filler.l_type != F_UNLCK)
        return fail("handler removed exact filler and preserved critical", 0);
    printf("lock-full: wake handler profile=%u published=255 common=127 label=%llu key=%llu/%llu\n", profile,
           (unsigned long long)after.label, (unsigned long long)after.key_slot, (unsigned long long)after.key_generation);
    path(name, "go", 16);
    if (publish(name, NULL, 0)) return fail("release background critical", 16);
    for (unsigned i = 0; i < 16; ++i) {
        struct record r;
        if (ring_phase(i, 'O', &r) || !capacity_exact(&initial[i], &r)
            || r.key_slot != ring_results[i].key_slot || r.key_generation != ring_results[i].key_generation
            || r.result || r.canonical || !r.complete_seen || !r.release_seen)
            return fail("all sixteen wake canonical successes", i);
        ring_results[i] = r;
        if (full_wait_observe((unsigned)source, (unsigned)r.pid, cookie, r.label,
                              (unsigned)r.key_slot, r.key_generation, 0) != 0)
            return fail("wake exact Queue and Pool debt gone", i);
    }
    for (unsigned n = 0; n < 1024; ++n) {
        if (totals(fd, epoch, out)) return fail("wake actual final occupancy", n);
        if (!out[2] && !out[3]) break;
    }
    if (out[1] != 254 || out[2] || out[3] || out[4] != 127 || out[5] != 8)
        return fail("wake honest254 common127", 0);
    printf("lock-full: wake profile=%u sleeping=16 successes=16 published=254 private=0 retired=0 common=127 payers=8\n", profile);
    return 0;
}
