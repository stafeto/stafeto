// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
// The BSD <sys/cdefs.h> macros the sources of nbase and paxmirabilis use.
#ifndef STAFETO_SYS_CDEFS_H
#define STAFETO_SYS_CDEFS_H
#include <features.h>
#ifndef __BEGIN_DECLS
#define __BEGIN_DECLS
#define __END_DECLS
#endif
#define __COPYRIGHT(x)
#define __FBSDID(x)
#define __SCCSID(x)
#define __RCSID(x)
#define __dead2
#define __printflike(x, y) __attribute__((format(printf, x, y)))
#define __DECONST(a, v) ((a)(v))
#define __unused __attribute__((unused))
#endif
