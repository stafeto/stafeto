/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/*
 * The part of the Linux kernel header <linux/types.h> that the DRM headers
 * of libdrm and of Mesa (drm.h, drm-uapi/drm.h) include: the fixed-width
 * integer types with the kernel's names. The sysroot of relibc has no kernel
 * headers; programs of this system call no DRM device, and the headers are
 * only read for the sizes and names of their structures.
 */

#ifndef STAFETO_MESA_LINUX_TYPES_H
#define STAFETO_MESA_LINUX_TYPES_H

#include <stddef.h>
#include <stdint.h>

typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int8_t __s8;
typedef int16_t __s16;
typedef int32_t __s32;
typedef int64_t __s64;

typedef __u16 __le16;
typedef __u32 __le32;
typedef __u64 __le64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;

typedef unsigned long __kernel_size_t;
typedef long __kernel_ssize_t;
typedef long __kernel_long_t;
typedef unsigned long __kernel_ulong_t;

#endif
