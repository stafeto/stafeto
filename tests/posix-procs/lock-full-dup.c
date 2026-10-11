// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
/* Real replacement preserves the source and freezes the old target lifetime. */
extern int full_dup_sample(unsigned, uint64_t[4]);
extern void full_dup_arm(void);
extern int full_dup_no_event(void);
extern int full_dup_key_valid(uint64_t, uint64_t);
extern int full_row_valid(const uint64_t[20][6]);
extern int full_dup_event(uint64_t[10]);
extern int full_dup_check(const uint64_t[12], const uint64_t[12], const uint64_t[10], unsigned);
extern int full_dup_unchanged(const uint64_t[12], const uint64_t[12], int, int, int, int);
extern int full_dup_inodes(uint64_t, uint64_t, uint64_t);
extern int full_dup_effect(const uint64_t[20][6], const uint64_t[4]);
struct dup_state { uint64_t before[12], after[12], event[10], final_event[10];
    uint64_t a_inode, b_inode, source_inode, target_inode; int source_flags, target_flags; char phase; };
static struct dup_state dup_initial;
static uint64_t dup_expected_effect[4];
static uint64_t dup_expected_pid;
static int dup_frozen(const struct dup_state *state) {
    return full_dup_unchanged(dup_initial.before, state->before, 0, 0, 0, 0)
        || state->a_inode != dup_initial.a_inode || state->b_inode != dup_initial.b_inode;
}

static int dup_samples(uint64_t samples[12]) {
    memset(samples, 0, 12 * sizeof(*samples));
    return full_dup_sample((unsigned)dup_primary, samples)
        || full_dup_sample((unsigned)dup_source, samples + 4)
        || (dup_alias >= 0 && full_dup_sample((unsigned)dup_alias, samples + 8));
}
static int dup_setup(int fd) {
    char name[64]; path(name, "file", 1);
    dup_primary = fd; dup_source = open(name, O_RDWR);
    if (FULL_DUP != 2) dup_alias = dup(fd);
    if (dup_source < 0 || (FULL_DUP != 2 && dup_alias < 0)) return -1;
    return fcntl(dup_source, F_SETFD, FULL_DUP == 1 ? FD_CLOEXEC | FD_CLOFORK : 0)
        || fcntl(fd, F_SETFD, FD_CLOEXEC);
}
static int dup_write(const struct dup_state *state) {
    int fd = open("/tmp/lock-full-dup-state", O_WRONLY);
    if (fd < 0) return -1;
    int bad = pwrite(fd, state, sizeof(*state), 0) != (ssize_t)sizeof(*state);
    return close(fd) || bad;
}
static int dup_phase(char phase, struct dup_state *state) {
    for (unsigned n = 0; n < 3000; ++n) {
        int fd = open("/tmp/lock-full-dup-state", O_RDONLY);
        ssize_t count = fd < 0 ? -1 : read(fd, state, sizeof(*state));
        if (fd >= 0 && close(fd)) return -1;
        if (count == (ssize_t)sizeof(*state) && state->phase == phase) return 0;
        nanosleep(&tick, NULL);
    }
    return -1;
}
static int dup_hold(int fd, unsigned index, struct record *record) {
    struct dup_state state = {0};
    if (dup_samples(state.before)) return fail("replacement initial full identities", index);
    struct stat initial_a, initial_b;
    if (fstat(fd, &initial_a) || fstat(dup_source, &initial_b)
        || (uint64_t)initial_a.st_ino != record->inode || initial_a.st_ino == initial_b.st_ino)
        return fail("replacement initial exact inode pair", index);
    state.a_inode = (uint64_t)initial_a.st_ino; state.b_inode = (uint64_t)initial_b.st_ino;
    int source_flags = fcntl(dup_source, F_GETFD), target_flags = fcntl(fd, F_GETFD);
    state.source_flags = source_flags; state.target_flags = target_flags;
    if (source_flags != (FULL_DUP == 1 ? FD_CLOEXEC | FD_CLOFORK : 0) || target_flags != FD_CLOEXEC)
        return fail("replacement preexisting descriptor flags", index);
    full_dup_arm(); errno = 0;
    int result = FULL_DUP == 1 ? dup2(fd, fd) : dup3(fd, fd, O_CLOEXEC);
    int error = errno;
    if ((FULL_DUP == 1 ? result != fd : result != -1 || error != EINVAL)
        || full_dup_no_event() || dup_samples(state.after)
        || full_dup_unchanged(state.before, state.after, source_flags, target_flags,
            fcntl(dup_source, F_GETFD), fcntl(fd, F_GETFD)))
        return fail("self replacement has no effect", index);
    if (FULL_DUP > 1) {
        full_dup_arm(); errno = 0;
        result = dup3(dup_source, fd, -1); error = errno;
        if (result != -1 || error != EINVAL || full_dup_no_event() || dup_samples(state.after)
            || full_dup_unchanged(state.before, state.after, source_flags, target_flags,
                fcntl(dup_source, F_GETFD), fcntl(fd, F_GETFD))) return fail("invalid dup3 flags preserve target", index);
    }
    state.phase = 'S';
    if (dup_write(&state) || gate("/tmp/lock-full-dup-start")) return fail("replacement start gate", index);
    full_dup_arm();
    result = FULL_DUP == 1 ? dup2(dup_source, fd) : dup3(dup_source, fd, O_CLOEXEC | O_CLOFORK);
    if (result != fd || full_dup_event(state.event) || dup_samples(state.after)
        || full_dup_check(state.before, state.after, state.event, FULL_DUP == 2)) return fail("frozen target replacement", index);
    state.source_flags = fcntl(dup_source, F_GETFD); state.target_flags = fcntl(fd, F_GETFD);
    if (state.source_flags != source_flags || state.target_flags != (FULL_DUP == 1 ? 0 : FD_CLOEXEC | FD_CLOFORK)
        || state.event[6] != (uint64_t)(FULL_DUP == 1 ? 0 : 3)) return fail("replacement flags belong to target", index);
    struct stat old, next;
    if (fstat(dup_source, &next) || fstat(fd, &old) || full_dup_inodes(state.b_inode, (uint64_t)next.st_ino, (uint64_t)old.st_ino))
        return fail("source inode becomes target", index);
    state.source_inode = (uint64_t)next.st_ino; state.target_inode = (uint64_t)old.st_ino;
    state.phase = 'P';
    if (dup_write(&state) || gate("/tmp/lock-full-dup-last")) return fail("replacement foreign effect gate", index);
    if (FULL_DUP == 3) {
        full_dup_arm();
        if (close(dup_alias) || full_dup_event(state.final_event)
            || memcmp(state.final_event, state.before + 8, 4 * sizeof(uint64_t))
            || state.final_event[4] || state.final_event[5] || state.final_event[6]
            || state.final_event[7] != 1 || full_dup_key_valid(state.final_event[8], state.final_event[9])) return fail("surviving OFD final exact alias close", index);
        dup_alias = -1;
    }
    state.phase = 'D';
    if (dup_write(&state) || gate("/tmp/lock-full-dup-refill")) return fail("replacement paid refill gate", index);
    if (FULL_DUP == 1) dup_primary = dup_alias;
    else { char name[64]; path(name, "file", 0); dup_primary = open(name, O_RDWR); }
    if (dup_primary < 0 || full_source((unsigned)dup_primary, record->source)
        || fstat(dup_primary, &old) || (uint64_t)old.st_ino != record->inode)
        return fail("refill exact A description", index);
    if (FULL_DUP > 1 && record->source[0] == state.before[2] && record->source[1] == state.before[3])
        return fail("refill has new OFD lifetime", index);
    for (unsigned segment = 0; segment < record->count; ++segment)
        if (set(dup_primary, F_WRLCK, segment) || drained(dup_primary)) return fail("real twelve segment refill", segment);
    if (full_dup_sample((unsigned)dup_primary, state.after)) return fail("actual refill entry lifetime", index);
    state.phase = 'R';
    if (dup_write(&state)) return fail("refill scalar receipt", index);
    record->phase = 'R';
    if (write_record(0, record) || gate("/tmp/lock-full-stop")) return fail("replacement refill Stop gate", index);
    for (unsigned segment = 0; segment < record->count; ++segment)
        if (set(dup_primary, F_UNLCK, segment)) return fail("replacement teardown A", segment);
    if (close(dup_primary) || close(fd) || close(dup_source)) return fail("replacement teardown descriptors", index);
    return 0;
}
static int dup_ranges(int fd, int locked, pid_t owner) {
    for (unsigned edge = 0; edge < 2; ++edge) {
        struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = edge ? 22 : 0, .l_len = 1};
        if (fcntl(fd, F_GETLK, &lock) || lock.l_type != (locked ? F_WRLCK : F_UNLCK)
            || (locked && (lock.l_pid != owner || lock.l_start != (off_t)(edge ? 22 : 0) || lock.l_len != 1)))
            return fail("replacement exact foreign ranges", edge);
    }
    if (locked) {
        struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
        errno = 0;
        if (fcntl(fd, F_SETLK, &lock) != -1 || errno != EAGAIN) return fail("foreign full-table conflict precedes payment", 0);
    }
    return 0;
}
static int dup_budget(int controller, uint64_t epoch, unsigned published, unsigned common) {
    uint64_t out[6] = {0};
    for (unsigned n = 0; n < 1024; ++n) {
        if (totals(controller, epoch, out)) return fail("replacement actual repayment", n);
        if (!out[2] && !out[3]) break;
    }
    if (out[1] != published || out[2] || out[3] || out[4] != common || out[5] != 8)
        return fail("replacement exact paid Budget", published);
    return 0;
}
static int dup_before(int witness, const struct record records[20]) {
    struct stat a, b; uint64_t foreign_a[2], foreign_b[2];
    if (full_source((unsigned)witness, foreign_a) || full_source((unsigned)dup_foreign_b, foreign_b)
        || dup_phase('S', &dup_initial) || fstat(witness, &a) || fstat(dup_foreign_b, &b)
        || (uint64_t)a.st_ino != records[0].inode || (uint64_t)b.st_ino != records[1].inode
        || dup_initial.a_inode != records[0].inode || dup_initial.b_inode != records[1].inode
        || dup_initial.a_inode == dup_initial.b_inode
        || dup_initial.before[2] != records[0].source[0] || dup_initial.before[3] != records[0].source[1]
        || dup_initial.before[6] == 0 || dup_initial.before[7] == 0
        || (foreign_a[0] == dup_initial.before[2] && foreign_a[1] == dup_initial.before[3])
        || (foreign_b[0] == dup_initial.before[6] && foreign_b[1] == dup_initial.before[7]))
        return fail("replacement exact A/B before Begin", 0);
    dup_expected_pid = records[0].pid;
    return 0;
}
static int dup_expect_effect(const uint64_t event[10], const uint64_t old[4], unsigned ofd, unsigned last) {
    if (memcmp(event, old, 4 * sizeof(uint64_t)) || event[7] != last
        || full_dup_key_valid(event[8], event[9])) return -1;
    dup_expected_effect[0] = dup_expected_pid;
    dup_expected_effect[1] = old[2] | (event[8] << 32) | ((uint64_t)ofd << 62) | ((uint64_t)last << 63);
    dup_expected_effect[2] = old[3]; dup_expected_effect[3] = event[9];
    return 0;
}
static int dup_capture(int controller, int witness, uint64_t epoch, struct record records[20]) {
    int other = dup_foreign_b; struct stat st; uint64_t other_source[2], source[2];
    const struct record original = records[0];
    struct dup_state state;
    if (other < 0 || fstat(other, &st) || (uint64_t)st.st_ino != records[1].inode
        || full_source((unsigned)other, other_source) || full_source((unsigned)witness, source)
        || dup_phase('S', &state) || dup_frozen(&state) || state.before[2] != records[0].source[0] || state.before[3] != records[0].source[1]
        || dup_ranges(witness, 1, FULL_DUP == 1 ? (pid_t)records[0].pid : -1)
        || dup_ranges(other, 1, (pid_t)records[1].pid) || dup_budget(controller, epoch, 256, 128))
        return fail("replacement preserved initial full baseline", 0);
    if (publish("/tmp/lock-full-dup-start", NULL, 0) || dup_phase('P', &state)
        || dup_frozen(&state) || full_dup_check(dup_initial.before, state.after, state.event, FULL_DUP == 2)
        || full_dup_inodes(dup_initial.b_inode, state.source_inode, state.target_inode)
        || (FULL_DUP != 3 && dup_expect_effect(state.event, dup_initial.before, FULL_DUP > 1, FULL_DUP == 2))
        || dup_ranges(witness, FULL_DUP == 3, -1) || dup_ranges(other, 1, (pid_t)records[1].pid)
        || dup_budget(controller, epoch, FULL_DUP == 3 ? 256 : 244, FULL_DUP == 3 ? 128 : 116))
        return fail("replacement immediate foreign effect", 0);
    printf("lock-full: dup effect profile=%u mode=%u old=%llu/%llu entry=%llu new=%llu/%llu key=%llu/%llu last=%llu\n", profile, FULL_DUP,
        (unsigned long long)state.before[2], (unsigned long long)state.before[3], (unsigned long long)state.before[1],
        (unsigned long long)state.after[2], (unsigned long long)state.after[3], (unsigned long long)state.event[8],
        (unsigned long long)state.event[9], (unsigned long long)state.event[7]);
    if (publish("/tmp/lock-full-dup-last", NULL, 0) || dup_phase('D', &state)
        || dup_frozen(&state)
        || (FULL_DUP == 3 && dup_expect_effect(state.final_event, dup_initial.before + 8, 1, 1))
        || dup_ranges(witness, 0, 0) || dup_ranges(other, 1, (pid_t)records[1].pid) || dup_budget(controller, epoch, 244, 116))
        return fail("last alias completed logical retirement", 0);
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
    if (fcntl(witness, F_SETLK, &lock) || dup_budget(controller, epoch, 245, 117)) return fail("replacement foreign paid SET", 0);
    lock.l_type = F_UNLCK;
    if (fcntl(witness, F_SETLK, &lock) || dup_budget(controller, epoch, 244, 116)
        || publish("/tmp/lock-full-dup-refill", NULL, 0)) return fail("replacement explicit paid UNLCK", 0);
    for (unsigned n = 0; n < 3000; ++n) {
        if (read_record(0, &records[0])) return fail("replacement refill metadata", n);
        if (records[0].phase == 'R') break;
        nanosleep(&tick, NULL);
    }
    uint64_t exact[2];
    if (records[0].phase != 'R' || records[0].pid != original.pid || records[0].root != original.root
        || records[0].generation != original.generation || records[0].inode != original.inode
        || records[0].family != original.family || records[0].count != original.count
        || dup_phase('R', &state) || dup_frozen(&state) || state.after[2] != records[0].source[0] || state.after[3] != records[0].source[1]
        || (FULL_DUP == 1 ? memcmp(records[0].source, original.source, sizeof(original.source)) == 0
                         : memcmp(records[0].source, original.source, sizeof(original.source)) != 0) == 0
        || dup_ranges(witness, 1, FULL_DUP == 1 ? (pid_t)records[0].pid : -1)
        || dup_ranges(other, 1, (pid_t)records[1].pid) || dup_budget(controller, epoch, 256, 128)
        || census(controller, records, epoch) || full_source((unsigned)other, exact)
        || memcmp(exact, other_source, sizeof(exact)) || full_source((unsigned)witness, exact)
        || memcmp(exact, source, sizeof(exact)) || close(other)) return fail("replacement full restored witness", 0);
    printf("lock-full: dup profile=%u mode=%u published=256 private=0 retired=0 common=128 payers=8 restored=12\n", profile, FULL_DUP);
    return 0;
}

static int dup_rows(int fd, uint64_t epoch) {
    unsigned seen = 0, close_effect = 0;
    for (unsigned row = 0; row < 32; ++row) {
        uint64_t pages[20][6] = {{0}};
        int code = full_telemetry((unsigned)fd, 1, cookie, epoch, row << 16, pages[0]);
        if (code == -304) continue;
        if (code) return fail("replacement strict row header", row);
        for (unsigned page = 1; page < 20; ++page)
            if (full_telemetry((unsigned)fd, 1, cookie, epoch, (row << 16) | page, pages[page]))
                return fail("replacement strict row page", row);
        if (full_row_valid(pages)) return fail("replacement complete dispatch bound", row);
        if (row == 28) {
            if (full_dup_effect(pages, dup_expected_effect)) return fail("replacement exact RAM CloseEvent effect", row);
            close_effect = 1;
        }
        ++seen;
        printf("lock-full: dup dispatch profile=%u mode=%u row=%u kind=%llu took=%llu whole=%llu waited=%llu mask=%llu ambiguous=%llu\n",
            profile, FULL_DUP, row, (unsigned long long)pages[0][5], (unsigned long long)pages[0][3],
            (unsigned long long)pages[18][2], (unsigned long long)pages[18][3],
            (unsigned long long)pages[0][4], (unsigned long long)pages[19][4]);
    }
    if (!close_effect || !seen) return fail("replacement actual CloseEvent dispatch missing", 0);
    printf("lock-full: dup measured profile=%u mode=%u rows=%u CloseEvent=1 B=20410\n", profile, FULL_DUP, seen);
    return 0;
}
