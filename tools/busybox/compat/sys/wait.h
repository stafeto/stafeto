// SPDX-License-Identifier: MIT
#ifndef STAFETO_WAIT_H
#define STAFETO_WAIT_H
#include_next <sys/wait.h>
#ifndef WCOREDUMP
#define WCOREDUMP(status) ((status) & 0x80)
#endif
#endif
