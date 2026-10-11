// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
/* True ordinary Read custody outlives both numeric aliases. */
extern int full_ofd_arm(unsigned);
extern int full_ofd_local_state(uint64_t[4]);
extern int full_ofd_counts(unsigned, uint64_t, uint64_t, unsigned, uint64_t, uint64_t[6]);
extern void full_ofd_replay_arm(void);
extern int full_ofd_replay_ok(void);
extern int full_row_valid(const uint64_t[20][6]);
extern int full_close_key_valid(unsigned, uint64_t);
extern unsigned full_ofd_description_slot(unsigned);
static struct record ofd_record;
static int ofd_bad;
static int ofd_phase(char phase, struct record *record) {
    for (unsigned n = 0; n < 3000; ++n) {
        if (read_record(0, record)) return -1;
        if (record->phase == phase) return 0;
        nanosleep(&tick, NULL);
    }
    return -1;
}
void full_ofd_window(void) {
    uint64_t loan[4];
    if (full_ofd_local_state(loan) || loan[0] != 1 || loan[1] != 1 || loan[2] || loan[3] != 1) { ofd_bad = 1; return; }
    full_ofd_replay_arm();
    if (close(ofd_alias) || full_ofd_replay_ok()) { ofd_bad = 2; return; }
    ofd_alias = -1;
    if (full_ofd_local_state(loan) || loan[0] != 1 || loan[1] != 1 || loan[2] || loan[3] != 1) { ofd_bad = 3; return; }
    ofd_record.phase = 'A';
    if (write_record(0, &ofd_record) || gate("/tmp/lock-full-ofd-last")) { ofd_bad = 4; return; }
    full_ofd_replay_arm();
    if (close(ofd_primary) || full_ofd_replay_ok()) { ofd_bad = 5; return; }
    ofd_primary = -1;
    if (full_ofd_local_state(loan) || loan[0] != 1 || loan[1] != 1 || loan[2] != 1 || loan[3]) { ofd_bad = 6; return; }
    ofd_record.phase = 'B';
    if (write_record(0, &ofd_record) || gate("/tmp/lock-full-ofd-read")) ofd_bad = 7;
}
static int ofd_hold(int fd, unsigned index, struct record *record) {
    ofd_record = *record;
    if (gate("/tmp/lock-full-ofd-start") || full_ofd_arm((unsigned)fd)) return fail("arm genuine Read loan", index);
    char byte = 0;
    ssize_t length = read(fd, &byte, 1);
    if (ofd_bad || length != 1 || byte != 'Q') return fail("exact captured Target Read after last fd", (unsigned)ofd_bad);
    uint64_t loan[4];
    if (full_ofd_local_state(loan) || loan[0] || loan[1] || loan[2] || loan[3]) return fail("ordinary loan unhold finished", index);
    ofd_record.phase = 'O';
    if (write_record(0, &ofd_record) || gate("/tmp/lock-full-stop")) return fail("OFD loan completion and Stop", index);
    return 0;
}
static int ofd_snapshot(int witness, uint64_t epoch, const struct record *record, unsigned refs, unsigned fds) {
    uint64_t out[6];
    if (full_ofd_counts((unsigned)witness, cookie, epoch, (unsigned)record->source[0], record->source[1], out)
        || out[1] != 1 || out[2] != refs || out[3] != fds
        || out[4] != full_ofd_description_slot((unsigned)record->source[0]) || out[5] != record->source[1]) return fail("actual retained OFD refs and generation", fds);
    return 0;
}
static int ofd_before(int witness, const struct record *record) {
    uint64_t out[6], who[4];
    if (full_identity((unsigned)getpid(), who) || who[2] != record->root || who[3] != record->generation
        || ofd_snapshot(witness, 0, record, 1, 1)) return fail("same genuine payer and OFD description", 0);
    if (full_ofd_counts((unsigned)witness, cookie, 0, (unsigned)record->source[0], record->source[1] ^ (UINT64_C(1) << 32), out)
        || out[1] || out[2] || out[3] || out[4] || out[5]) return fail("old full generation stays absent", 0);
    if (full_ofd_counts((unsigned)witness, 0, 0, (unsigned)record->source[0], record->source[1], out) != -304)
        return fail("observer rejects zero nonce", 0);
    return 0;
}
static int ofd_ranges(int witness, int locked) {
    for (unsigned segment = 0; segment < 2; ++segment) {
        struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = segment ? 2 : 0, .l_len = 1};
        if (fcntl(witness, F_GETLK, &lock) || lock.l_type != (locked ? F_WRLCK : F_UNLCK)
            || (locked && (lock.l_pid != -1 || lock.l_start != (off_t)(segment ? 2 : 0) || lock.l_len != 1)))
            return fail("foreign exact OFD critical and filler", segment);
    }
    return 0;
}
static int ofd_capture(int controller, int witness, uint64_t epoch, const struct record *record) {
    struct record observed;
    uint64_t out[6];
    if (publish("/tmp/lock-full-ofd-start", NULL, 0) || ofd_phase('A', &observed)
        || memcmp(observed.source, record->source, sizeof(record->source)) || observed.pid != record->pid
        || ofd_snapshot(witness, epoch, record, 1, 1) || ofd_ranges(witness, 1)) return fail("first alias preserves OFD", 0);
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
    errno = 0;
    if (fcntl(witness, F_SETLK, &lock) != -1 || errno != EAGAIN || totals(controller, epoch, out)
        || out[1] != 256 || out[2] || out[3] || out[4] != 128 || out[5] != 8) return fail("first alias retains paid256 conflict", 0);
    if (publish("/tmp/lock-full-ofd-last", NULL, 0) || ofd_phase('B', &observed)
        || memcmp(observed.source, record->source, sizeof(record->source)) || observed.pid != record->pid
        || ofd_snapshot(witness, epoch, record, 1, 0) || ofd_ranges(witness, 0)) return fail("last real fd removes OFD before unhold", 0);
    for (unsigned n = 0; n < 1024; ++n) {
        if (totals(controller, epoch, out)) return fail("OFD separate retired repayment", n);
        if (!out[2] && !out[3]) break;
    }
    if (out[1] != 244 || out[2] || out[3] || out[4] != 116 || out[5] != 8) return fail("OFD actual244 common116", 0);
    if (fcntl(witness, F_SETLK, &lock) || totals(controller, epoch, out)
        || out[1] != 245 || out[2] || out[3] || out[4] != 117 || out[5] != 8) return fail("foreign successful SET paid245 common117", 0);
    lock.l_type = F_UNLCK;
    if (fcntl(witness, F_SETLK, &lock) || ofd_snapshot(witness, epoch, record, 1, 0)
        || publish("/tmp/lock-full-ofd-read", NULL, 0) || ofd_phase('O', &observed)) return fail("finish real read only after foreign effect", 0);
    if (full_ofd_counts((unsigned)witness, cookie, epoch, (unsigned)record->source[0], record->source[1], out)
        || out[1] || out[2] || out[3] || out[4] || out[5]) return fail("old physical generation gone after unhold", 0);
    for (unsigned n = 0; n < 1024; ++n) {
        if (totals(controller, epoch, out)) return fail("foreign paid record retirement", n);
        if (!out[2] && !out[3]) break;
    }
    if (out[1] != 244 || out[2] || out[3] || out[4] != 116 || out[5] != 8) return fail("final OFD244 common116", 0);
    printf("lock-full: ofd loan profile=%u published=244 private=0 retired=0 common=116 payers=8 first-alias=retained last-fd=retired read=Q replay=2\n", profile);
    return 0;
}
static int ofd_rows(int fd, uint64_t epoch, const struct record *record) {
    uint64_t pages[20][6];
    for (unsigned page = 0; page < 20; ++page)
        if (full_telemetry((unsigned)fd, 1, cookie, epoch, (28u << 16) | page, pages[page])) return fail("OFD exact Close effect pages", page);
    if (full_row_valid(pages) || !(pages[0][4] & (1u << 15)) || (pages[19][4] & (1u << 15))) return fail("OFD actual unambiguous Close effect", 0);
    uint64_t *w = pages[17];
    if (w[2] != record->pid || (uint32_t)w[3] != (uint32_t)record->source[0] || w[4] != record->source[1]
        || w[3] >> 62 != 3 || full_close_key_valid((unsigned)((w[3] >> 32) & 0x3fffffff), w[5])) return fail("OFD full description last-fd CloseKey", 0);
    printf("lock-full: ofd effect profile=%u took=%llu whole=%llu waited=%llu description=%llu/%llu key=%llu/%llu\n", profile,
        (unsigned long long)pages[0][3], (unsigned long long)pages[18][2], (unsigned long long)pages[18][3],
        (unsigned long long)full_ofd_description_slot((unsigned)w[3]), (unsigned long long)w[4], (unsigned long long)((w[3] >> 32) & 0x3fffffff), (unsigned long long)w[5]);
    return 0;
}
