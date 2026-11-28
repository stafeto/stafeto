/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The text of one --spawn argument of the manager: APPID,PATH[,ARG...]. Pure
 * parsing with no call to the system, tested on the host (launch_test.c). */
#ifndef DESK_LAUNCH_H
#define DESK_LAUNCH_H

#include "policy.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DESK_SPAWN_ARGS 8
#define DESK_SPAWN_PATH 128
#define DESK_SPAWN_TEXT 256

typedef struct desk_spawn {
    char app_id[DESK_TEXT_MAX + 1];
    char path[DESK_SPAWN_PATH];
    char *argv[DESK_SPAWN_ARGS + 2];   /* the path, the arguments, a null */
    char text[DESK_SPAWN_TEXT];        /* the arguments point into it */
} desk_spawn;

/* Parses `text` into *out. 0, or -1 when the text has no path, has more than
 * DESK_SPAWN_ARGS arguments, or holds an application id, a path or the whole
 * text that does not fit its place (nothing is cut). */
int desk_spawn_parse(desk_spawn *out, const char *text);

#ifdef __cplusplus
}
#endif

#endif
