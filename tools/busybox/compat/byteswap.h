// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
/* glibc's <byteswap.h>, which BusyBox includes on Linux and relibc lacks. */
#ifndef STAFETO_BYTESWAP_H
#define STAFETO_BYTESWAP_H
#define bswap_16(x) __builtin_bswap16(x)
#define bswap_32(x) __builtin_bswap32(x)
#define bswap_64(x) __builtin_bswap64(x)
#endif
