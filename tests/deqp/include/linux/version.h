/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/*
 * <linux/version.h> for the build of VK-GL-CTS (tools/build-deqp.py): the
 * Vulkan memory utilities of the tree test the kernel version for the DMA
 * heap allocator. stafeto has no such device, so the version is 0 and the
 * allocator stays out.
 */
#ifndef _STAFETO_LINUX_VERSION_H
#define _STAFETO_LINUX_VERSION_H

#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))
#define LINUX_VERSION_CODE 0

#endif
