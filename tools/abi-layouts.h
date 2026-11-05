// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

/* The table the ABI probe writes (tools/abi-layouts.c): rows of a name and a
 * number in the section .stafeto_abi, which `cargo xtask abi` dumps. It needs
 * no header of the library. */
#ifndef STAFETO_ABI_LAYOUTS_H
#define STAFETO_ABI_LAYOUTS_H

struct row {
    char name[48];
    unsigned long long value;
};

#define V(n, v) { n, (unsigned long long)(v) },
#define S(t) V("sizeof " #t, sizeof(t)) V("alignof " #t, _Alignof(t))
#define O(t, f) V("offsetof " #t "." #f, __builtin_offsetof(t, f))
#define C(n) V(#n, n)


#endif
