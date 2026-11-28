/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

#include "launch.h"

#include <string.h>

int desk_spawn_parse(desk_spawn *out, const char *text)
{
    if (strlen(text) >= sizeof out->text) {
        return -1;
    }
    memset(out, 0, sizeof *out);
    memcpy(out->text, text, strlen(text) + 1);
    /* The application id, the path and the arguments. */
    char *fields[DESK_SPAWN_ARGS + 2];
    int count = 0;
    char *p = out->text;
    for (;;) {
        if (count == DESK_SPAWN_ARGS + 2) {
            return -1;
        }
        fields[count++] = p;
        char *comma = strchr(p, ',');
        if (!comma) {
            break;
        }
        *comma = 0;
        p = comma + 1;
    }
    if (count < 2 || strlen(fields[0]) > DESK_TEXT_MAX || strlen(fields[1]) >= sizeof out->path ||
        fields[1][0] == 0) {
        return -1;
    }
    strcpy(out->app_id, fields[0]);
    strcpy(out->path, fields[1]);
    out->argv[0] = out->path;
    for (int i = 2; i < count; i++) {
        out->argv[i - 1] = fields[i];
    }
    out->argv[count - 1] = NULL;
    return 0;
}
