/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
 *
 * The few definitions F-Stack's host files took from DPDK's headers
 * (rte_config.h, rte_string_fns.h, rte_log.h, rte_eal.h), for the build
 * without DPDK on stafeto: the table sizes, the string splitter and a log
 * with one stream and a level per type.
 */

#ifndef FF_STAFETO_RTE_H
#define FF_STAFETO_RTE_H

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define RTE_MAX_LCORE 128
#define RTE_MAX_ETHPORTS 32
#define __rte_unused __attribute__((__unused__))

/*
 * Splits `string` in place at each `delim` into at most `maxtokens`
 * tokens, as DPDK's rte_strsplit: the tokens are the pieces between the
 * delimiters, the delimiters become NUL bytes, and the count is returned
 * (-1 on bad arguments).
 */
static inline int
rte_strsplit(char *string, int stringlen, char **tokens, int maxtokens, char delim)
{
    int i, tok = 0;
    int tokstart = 1;

    if (string == NULL || tokens == NULL || maxtokens <= 0)
        return -1;
    for (i = 0; i < stringlen; i++) {
        if (string[i] == '\0' || tok >= maxtokens)
            break;
        if (tokstart) {
            tokstart = 0;
            tokens[tok++] = &string[i];
        }
        if (string[i] == delim) {
            string[i] = '\0';
            tokstart = 1;
        }
    }
    return tok;
}

/* The log: messages at or under both the global level and their type's. */
#define FF_STAFETO_LOG_TYPES 32
#define FF_STAFETO_LOG_INFO 7U
#define FF_STAFETO_LOG_DEBUG 8U

extern FILE *ff_stafeto_log_stream;
extern uint32_t ff_stafeto_log_global;
extern uint32_t ff_stafeto_log_levels[FF_STAFETO_LOG_TYPES];

static inline int
rte_openlog_stream(FILE *f)
{
    ff_stafeto_log_stream = f;
    return 0;
}

static inline void
rte_log_set_global_level(uint32_t level)
{
    ff_stafeto_log_global = level;
}

static inline int
rte_log_set_level(uint32_t logtype, uint32_t level)
{
    if (logtype >= FF_STAFETO_LOG_TYPES)
        return -1;
    ff_stafeto_log_levels[logtype] = level;
    return 0;
}

static inline int
rte_vlog(uint32_t level, uint32_t logtype, const char *format, va_list ap)
{
    if (level > ff_stafeto_log_global)
        return 0;
    if (logtype < FF_STAFETO_LOG_TYPES && level > ff_stafeto_log_levels[logtype])
        return 0;
    return vfprintf(ff_stafeto_log_stream ? ff_stafeto_log_stream : stderr, format, ap);
}

#endif /* FF_STAFETO_RTE_H */
