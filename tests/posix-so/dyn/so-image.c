/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The mappings of the objects of libc.so as the layer's map shows them:
 * the code of printf and a string of the read-only data. Prints the number
 * of mappings of each object (a process that shares libc.so with live ones
 * shows one more than each of them) and the layer's mark of the image. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern int stafeto_probe_image(uintptr_t address, uint64_t *out);

int main(void) {
    uint64_t code[5] = {0}, data[5] = {0};
    /* strsignal gives a string of libc.so's read-only data. */
    const char *text = strsignal(2);
    int code_found = stafeto_probe_image((uintptr_t)&printf, code);
    int data_found = stafeto_probe_image((uintptr_t)text, data);
    printf("so-image: found=%d%d code=%llu data=%llu write=%llu%llu image=%llu%llu\n", code_found,
           data_found, (unsigned long long)code[0], (unsigned long long)data[0],
           (unsigned long long)code[2], (unsigned long long)data[2],
           (unsigned long long)code[4], (unsigned long long)data[4]);
    return code_found == 1 && data_found == 1 ? 0 : 1;
}
