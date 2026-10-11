// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
/* Host fault injection uses the actual guest transfer helper. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
static ssize_t returned;
static size_t requested;
static off_t offset;
static unsigned calls;
static ssize_t read_fault(int fd, void *output, size_t bytes, off_t at) {
    (void)output; assert(fd == 7); requested = bytes; offset = at; ++calls;
    return returned;
}
static ssize_t write_fault(int fd, const void *input, size_t bytes, off_t at) {
    (void)input; assert(fd == 7); requested = bytes; offset = at; ++calls;
    return returned;
}
#define pread read_fault
#define pwrite write_fault
#include "lock-full-exec-io.h"
#undef pread
#undef pwrite
int main(void) {
    uint64_t state[352] = {0};
    for (unsigned words = 1; words <= 352; ++words) {
        ssize_t bytes = (ssize_t)(words * sizeof(uint64_t));
        returned = bytes;
        assert(!full_exec_io_read(7, state, 0, words));
        assert(!full_exec_io_write(7, state, 352 - words, words));
        assert(requested == (size_t)bytes && offset == (off_t)((352 - words) * 8));
        for (returned = -1; returned < bytes; ++returned) {
            assert(full_exec_io_read(7, state, 0, words));
            assert(full_exec_io_write(7, state, 352 - words, words));
        }
        returned = bytes + 1;
        assert(full_exec_io_read(7, state, 0, words));
        assert(full_exec_io_write(7, state, 0, words));
    }
    unsigned before = calls;
    assert(full_exec_io_read(7, NULL, 0, 1));
    assert(full_exec_io_write(7, NULL, 0, 1));
    assert(full_exec_io_read(7, state, 0, 0));
    assert(full_exec_io_write(7, state, 352, 1));
    assert(full_exec_io_read(7, state, 351, 2));
    assert(full_exec_io_write(7, state, 1, 352));
    assert(calls == before);
    puts("retained-exec I/O: exact reads/writes, all short counts and bounds PASS");
    return 0;
}
