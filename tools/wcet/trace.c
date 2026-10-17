// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

// QEMU TCG plugin: the translation blocks of the kernel that ran. The
// first execution of a block appends one line "<start> <instructions>"
// (hexadecimal address, decimal count) to "<prefix>.<pid>.trace". The line
// is written at once, so the file is whole when the run ends by a kill.
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
    int seen;
};

static int out_fd = -1;

static void executed(unsigned int vcpu, void *data)
{
    struct block *b = data;
    if (__atomic_exchange_n(&b->seen, 1, __ATOMIC_RELAXED)) {
        return;
    }
    char line[48];
    int n = snprintf(line, sizeof line, "%llx %u\n",
                     (unsigned long long)b->start, b->insns);
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
