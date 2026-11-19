/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* CRC-32 of IEEE 802.3 (the one of zlib and of the probes of the compositor). */
#ifndef STAFETO_CRC_H
#define STAFETO_CRC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The CRC-32 of `len` bytes. */
uint32_t crc32_bytes(const void *data, size_t len);

/* The running form: start with crc32_start(), feed, finish with crc32_finish(). */
uint32_t crc32_start(void);
uint32_t crc32_feed(uint32_t state, const void *data, size_t len);
uint32_t crc32_finish(uint32_t state);

/* The CRC-32 of the R, G and B bytes of each point of an XRGB8888 frame, row
 * by row (the word of a point is 0xXXRRGGBB, low byte first), as the probes
 * take it over a snapshot. `stride` is the length of a row in bytes. */
uint32_t crc32_xrgb(const uint8_t *pixels, unsigned width, unsigned height, unsigned stride);

#ifdef __cplusplus
}
#endif

#endif
