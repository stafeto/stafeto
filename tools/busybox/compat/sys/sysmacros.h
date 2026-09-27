// SPDX-License-Identifier: MIT
#ifndef STAFETO_SYSMACROS_H
#define STAFETO_SYSMACROS_H
#define major(x) ((unsigned)((x) >> 8))
#define minor(x) ((unsigned)((x) & 255))
#define makedev(x,y) (((x) << 8) | (y))
#endif
