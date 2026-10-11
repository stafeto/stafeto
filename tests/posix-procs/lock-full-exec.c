// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
/* One retained description crosses a genuine exec and a new authenticated image. */
#include "lock-full-exec-io.h"
enum { EXEC_BYTES = 2816, EXEC_WORDS = 352 };
extern int full_exec_binding(uint64_t[9]);
extern int full_exec_sample(unsigned, uint64_t[4]);
extern int full_exec_valid(const uint64_t *, size_t, unsigned, uint64_t, uint64_t);
extern int full_exec_absence(const int[20]);
extern int full_exec_frozen(const uint64_t *, const uint64_t[32]);
extern int full_exec_advance(unsigned, unsigned);
extern int full_exec_old_scope(unsigned, uint64_t, uint64_t, uint64_t, uint64_t);
static uint64_t exec_a_source[2], exec_b_source[2];
static unsigned exec_phase = 1;
_Static_assert(EXEC_WORDS * sizeof(uint64_t) == EXEC_BYTES, "bounded state layout");
_Static_assert(sizeof(exec_state) == 4096, "one static state page");
_Static_assert(sizeof(exec_initial_header) == 256, "independent frozen header");
static int exec_advance(unsigned next) {
    if (full_exec_advance(exec_phase, next)) return -1;
    exec_phase = next; return 0;
}

static uint64_t exec_tag(uint64_t pid, uint64_t image) {
    return cookie ^ (pid << 16) ^ (image << 32) ^ ((uint64_t)FULL_EXEC << 8) ^ profile;
}
static int exec_read(void) {
    return full_exec_io_read(exec_state_fd, exec_state, 0, EXEC_WORDS);
}
static int exec_write(unsigned first_word, unsigned words) {
    return full_exec_io_write(exec_state_fd, exec_state + first_word, first_word, words);
}
static int exec_wait(unsigned word) {
    for (unsigned n = 0; n < 3000; ++n) {
        uint64_t marker;
        if (full_exec_io_read(exec_state_fd, &marker, word, 1)) return -1;
        if (marker) return marker == exec_nonce ? 0 : -1;
        nanosleep(&tick, NULL);
    }
    return -1;
}
static int exec_setup(int fd, struct record *record) {
    struct stat source, state;
    uint64_t sample[4];
    exec_primary = fd;
    exec_state_fd = open("/tmp/lock-full-exec-state", O_RDWR);
    if (exec_state_fd < 0 || fcntl(fd, F_GETFD) != 0 || fcntl(exec_state_fd, F_GETFD) != 0
        || full_exec_binding(exec_state + 8) || full_exec_sample((unsigned)fd, sample)
        || fstat(fd, &source) || fstat(exec_state_fd, &state) || source.st_ino == state.st_ino
        || state.st_size != 4096 || (uint64_t)source.st_ino != record->inode
        || exec_state[9] != record->pid || exec_state[13] != record->root
        || exec_state[14] != record->generation) return -1;
    exec_nonce = exec_tag(exec_state[9], exec_state[11]);
    exec_state[0] = UINT64_C(0x6578656332353602); exec_state[1] = 1;
    exec_state[2] = FULL_EXEC; exec_state[3] = exec_nonce;
    exec_state[5] = (uint64_t)exec_state_fd; exec_state[6] = 0; exec_state[7] = record->inode;
    memcpy(exec_state + 17, sample, sizeof(sample));
    exec_state[26] = 256; exec_state[27] = 128; exec_state[28] = 8;
    exec_state[31] = exec_nonce;
    if (full_exec_valid(exec_state, EXEC_BYTES, 1, FULL_EXEC, exec_nonce)) return -1;
    /* The INITIAL commit follows the complete scalar header. */
    return exec_write(0, 31) || exec_write(31, 1);
}
static int exec_hold(int fd, unsigned index, struct record *record) {
    (void)record;
    if (exec_wait(30) || exec_read()
        || full_exec_valid(exec_state, EXEC_BYTES, 2, FULL_EXEC, exec_nonce) || exec_advance(2))
        return fail("retained exec original permission", index);
    uint64_t sample[4];
    if (full_exec_sample((unsigned)fd, sample) || memcmp(sample, exec_state + 17, sizeof(sample))
        || fcntl(fd, F_GETFD) || fcntl(exec_state_fd, F_GETFD)) return fail("retained exec exact original fd", index);
    char profile_arg[2] = {(char)('0' + profile), 0}, state_arg[12];
    snprintf(state_arg, sizeof(state_arg), "%d", exec_state_fd);
    char *args[] = {"procs-child", "full-after-exec", profile_arg, "0", state_arg, NULL};
    char *env[] = {NULL};
    execve("/bin/procs-child", args, env);
    return fail("real retained exec unexpectedly returned", index);
}
static int exec_after(int state_fd) {
    exec_state_fd = state_fd;
    if (exec_read()) return fail("new image complete retained state", 0);
    exec_nonce = exec_tag(exec_state[9], exec_state[11]);
    if (full_exec_valid(exec_state, EXEC_BYTES, 2, FULL_EXEC, exec_nonce)
        || exec_state[5] != (uint64_t)state_fd || exec_advance(2)) return fail("new image exact old permission", 0);
    exec_primary = (int)exec_state[17];
    uint64_t *receipt = exec_state + 32; struct stat st;
    if (full_exec_sample((unsigned)exec_primary, receipt) || full_exec_binding(receipt + 4)
        || fstat(exec_primary, &st)) return fail("new image authenticated retained source", 0);
    receipt[13] = (uint64_t)fcntl(exec_primary, F_GETFD); receipt[14] = (uint64_t)st.st_ino;
    receipt[15] = (uint64_t)state_fd;
    uint64_t denied[6];
    if (fcntl(state_fd, F_GETFD)
        || full_exec_old_scope((unsigned)exec_primary, exec_state[21], exec_state[22], cookie, exec_state[4]) != -310
        || full_telemetry((unsigned)exec_primary, 3, cookie, exec_state[4], 0, denied) != -310)
        return fail("fresh image cannot vouch old capture", 0);
    receipt[16] = 310; receipt[17] = 3; receipt[18] = exec_nonce; receipt[23] = exec_nonce;
    if (full_exec_valid(exec_state, EXEC_BYTES, 3, FULL_EXEC, exec_nonce)
        || exec_advance(3) || exec_write(32, 23) || exec_write(55, 1)) return fail("new image committed scalar receipt", 0);
    if (exec_wait(185) || exec_read()
        || full_exec_valid(exec_state, EXEC_BYTES, 4, FULL_EXEC, exec_nonce)
        || exec_state[187] != profile || exec_advance(4)) return fail("new image exact stopped old capture ACK", 0);
    /* No close or unlock precedes the stable observer's Stop ACK. */
    for (unsigned n = 0; n < segments(0, 0); ++n)
        if (set(exec_primary, F_UNLCK, n)) return fail("retained exec teardown", n);
    return close(exec_primary) || close(state_fd) ? fail("retained exec descriptors after Stop", 0) : 0;
}
static int exec_before(int controller, int witness, const struct record records[20]) {
    uint64_t who[4]; struct stat a, b;
    exec_state_fd = open("/tmp/lock-full-exec-state", O_RDWR);
    if (exec_state_fd < 0 || exec_read()) return fail("observer complete INITIAL", 0);
    exec_nonce = exec_tag(records[0].pid, exec_state[11]);
    if (full_exec_valid(exec_state, EXEC_BYTES, 1, FULL_EXEC, exec_nonce)
        || exec_state[9] != records[0].pid || exec_state[13] != records[0].root
        || exec_state[14] != records[0].generation || exec_state[7] != records[0].inode
        || exec_state[19] != records[0].source[0] || exec_state[20] != records[0].source[1]
        || full_source((unsigned)controller, exec_state + 21)
        || full_identity((unsigned)getpid(), who) || who[0] == records[0].pid
        || who[2] != records[0].root || who[3] != records[0].generation
        || full_source((unsigned)witness, exec_a_source)
        || full_source((unsigned)exec_foreign_b, exec_b_source)
        || fstat(witness, &a) || fstat(exec_foreign_b, &b)
        || (uint64_t)a.st_ino != records[0].inode || (uint64_t)b.st_ino != records[1].inode
        || a.st_ino == b.st_ino || !memcmp(exec_a_source, records[0].source, sizeof(exec_a_source))
        || !memcmp(exec_b_source, records[1].source, sizeof(exec_b_source)))
        return fail("observer exact old PID Root Da and foreign pair", 0);
    exec_state[23] = who[0]; exec_state[24] = who[2]; exec_state[25] = who[3];
    memcpy(exec_initial_header, exec_state, sizeof(exec_initial_header));
    return 0;
}
static int exec_absent(int controller, uint64_t epoch) {
    int status[20]; uint64_t out[6];
    for (unsigned page = 0; page < 20; ++page)
        status[page] = full_telemetry((unsigned)controller, 1, cookie, epoch, (28u << 16) | page, out);
    return full_exec_absence(status);
}
static int exec_foreign(int witness, const struct record records[20]) {
    struct stat st; uint64_t source[2];
    if (full_source((unsigned)witness, source) || memcmp(source, exec_a_source, sizeof(source))
        || fstat(witness, &st) || (uint64_t)st.st_ino != records[0].inode
        || full_source((unsigned)exec_foreign_b, source) || memcmp(source, exec_b_source, sizeof(source))
        || fstat(exec_foreign_b, &st) || (uint64_t)st.st_ino != records[1].inode) return -1;
    for (unsigned file = 0; file < 2; ++file) for (unsigned edge = 0; edge < 2; ++edge) {
        int fd = file ? exec_foreign_b : witness;
        const struct record *r = records + file;
        struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET,
            .l_start = (off_t)(edge ? 2 * (r->count - 1) : 0), .l_len = 1};
        if (fcntl(fd, F_GETLK, &lock) || lock.l_type != F_WRLCK
            || lock.l_pid != (!file && FULL_EXEC == 2 ? -1 : (pid_t)r->pid)
            || lock.l_start != (off_t)(edge ? 2 * (r->count - 1) : 0) || lock.l_len != 1) return -1;
        lock.l_type = F_WRLCK; errno = 0;
        if (fcntl(fd, F_SETLK, &lock) != -1 || errno != EAGAIN) return -1;
    }
    return 0;
}
static int exec_capture(int controller, int witness, uint64_t epoch, const struct record records[20]) {
    uint64_t out[6];
    if (exec_absent(controller, epoch) || exec_foreign(witness, records)) return fail("original full retained exec baseline", 0);
    exec_state[4] = epoch; exec_state[29] = 2; exec_state[30] = exec_nonce;
    if (full_exec_valid(exec_state, EXEC_BYTES, 2, FULL_EXEC, exec_nonce)
        || exec_advance(2) || exec_write(4, 1) || exec_write(21, 9) || exec_write(30, 1)
        || exec_wait(55) || exec_read()) return fail("observer ordered real exec permission and receipt", 0);
    if (full_exec_frozen(exec_state, exec_initial_header)
        || full_exec_valid(exec_state, EXEC_BYTES, 3, FULL_EXEC, exec_nonce)
        || exec_advance(3)
        || exec_foreign(witness, records) || census(controller, records, epoch)
        || totals(controller, epoch, out) || out[1] != 256 || out[2] || out[3] || out[4] != 128 || out[5] != 8
        || exec_absent(controller, epoch)) return fail("retained exec foreign full budget and fresh image", 0);
    if (full_telemetry((unsigned)controller, 2, cookie, epoch, 0, out)
        || out[0] != epoch || out[1] != profile || out[2] != 32 || out[3] || out[4] || out[5] != epoch
        || exec_absent(controller, epoch)) return fail("old observer exact capture Stop and absence", 0);
    exec_state[176] = epoch; exec_state[177] = 4; exec_state[178] = exec_nonce;
    exec_state[179] = 1; exec_state[181] = UINT64_C(0xfffff) << 32; exec_state[184] = 1;
    exec_state[185] = exec_nonce; memcpy(exec_state + 186, out, sizeof(out));
    if (full_exec_valid(exec_state, EXEC_BYTES, 4, FULL_EXEC, exec_nonce)
        || exec_advance(4) || exec_write(176, 9) || exec_write(186, 6) || exec_write(185, 1)) return fail("persist old observer Stop ACK", 0);
    printf("lock-full: exec retained profile=%u mode=%u pid=%llu old-image=%llu new-image=%llu da=%llu/%llu old-credential=%llu new-credential=%llu oldscope=denied published=256 common=128 payers=8\n",
        profile, FULL_EXEC, (unsigned long long)exec_state[9], (unsigned long long)exec_state[11],
        (unsigned long long)exec_state[39], (unsigned long long)exec_state[19], (unsigned long long)exec_state[20],
        (unsigned long long)exec_state[12], (unsigned long long)exec_state[40]);
    return 0;
}
