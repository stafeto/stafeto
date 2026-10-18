// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

// QEMU TCG plugin: the translation blocks of the kernel that ran. The
// first execution of a block appends one line "<start> <instructions>
// <executions>" (hexadecimal address, decimal counts) to
// "<prefix>.<pid>.trace", and so does every execution whose number is a
// power of two; the last line of a block holds its count to within a factor
// of two. Each line is written at once, so the file is whole when the run
// ends by a kill. Under -icount the instructions of a block times its
// executions is the count of instructions the block cost the run.
// Only addresses in the upper half of the address space are kept: the
// kernel is linked there (kernel/kernel.ld), and the boot code that runs
// before the MMU is on is not part of any entry path.
//
// Arguments: prefix=<path prefix of the output file>.

#include <glib.h>
#include <qemu-plugin.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define KERNEL_HALF 0xffff000000000000ull

struct block {
    uint64_t start;
    unsigned insns;
    uint64_t count;
};

static int out_fd = -1;

static void executed(unsigned int vcpu, void *data)
{
    struct block *b = data;
    uint64_t count = __atomic_add_fetch(&b->count, 1, __ATOMIC_RELAXED);
    if (count & (count - 1)) {
        return;
    }
    char line[80];
    int n = snprintf(line, sizeof line, "%llx %u %llu\n",
                     (unsigned long long)b->start, b->insns,
                     (unsigned long long)count);
    if (write(out_fd, line, n) < 0) {
        return;
    }
}

static void translated(struct qemu_plugin_tb *tb, void *data)
{
    uint64_t start = qemu_plugin_tb_vaddr(tb);
    if (start < KERNEL_HALF) {
        return;
    }
    struct block *b = g_new0(struct block, 1);
    b->start = start;
    b->insns = qemu_plugin_tb_n_insns(tb);
    qemu_plugin_register_vcpu_tb_exec_cb(tb, executed, QEMU_PLUGIN_CB_NO_REGS, b);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    const char *prefix = NULL;
    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "prefix=", 7) == 0) {
            prefix = argv[i] + 7;
        }
    }
    if (!prefix) {
        fprintf(stderr, "trace plugin: prefix=<path> is required\n");
        return -1;
    }
    char path[4096];
    snprintf(path, sizeof path, "%s.%d.trace", prefix, (int)getpid());
    out_fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
        perror(path);
        return -1;
    }
    qemu_plugin_register_vcpu_tb_trans_cb(id, translated, NULL);
    return 0;
}
