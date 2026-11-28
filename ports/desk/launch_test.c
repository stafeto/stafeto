/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The host test of launch.c (tools/test_desk_port.py). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "launch.h"

static unsigned checks;

#define EXPECT(cond)                                                              \
    do {                                                                          \
        checks++;                                                                 \
        if (!(cond)) {                                                            \
            printf("launch_test: check failed at line %d: %s\n", __LINE__, #cond); \
            exit(1);                                                              \
        }                                                                         \
    } while (0)

int main(void)
{
    desk_spawn s;
    /* A full line: the id, the path and 6 arguments. */
    EXPECT(desk_spawn_parse(&s, "alpha,/bin/c,a,60,80,200,120,C04040") == 0);
    EXPECT(strcmp(s.app_id, "alpha") == 0 && strcmp(s.path, "/bin/c") == 0);
    EXPECT(strcmp(s.argv[0], "/bin/c") == 0 && strcmp(s.argv[1], "a") == 0);
    EXPECT(strcmp(s.argv[6], "C04040") == 0 && s.argv[7] == NULL);
    /* The path alone. */
    EXPECT(desk_spawn_parse(&s, "x,/bin/c") == 0 && s.argv[1] == NULL);
    /* The most arguments: 8 after the path; the null is the tenth slot. */
    EXPECT(desk_spawn_parse(&s, "x,/p,1,2,3,4,5,6,7,8") == 0);
    EXPECT(strcmp(s.argv[8], "8") == 0 && s.argv[9] == NULL);
    /* One more is refused, whatever follows (this wrote past argv once). */
    EXPECT(desk_spawn_parse(&s, "x,/p,1,2,3,4,5,6,7,8,9") == -1);
    EXPECT(desk_spawn_parse(&s, "x,/p,1,2,3,4,5,6,7,8,9,10,11,12") == -1);
    /* No path, an empty path, a text with no comma. */
    EXPECT(desk_spawn_parse(&s, "x") == -1);
    EXPECT(desk_spawn_parse(&s, "x,") == -1);
    EXPECT(desk_spawn_parse(&s, "") == -1);
    /* An id of 64 bytes fits, of 65 is refused whole. */
    char id64[65], id65[66], text[512];
    memset(id64, 'a', 64);
    id64[64] = 0;
    memset(id65, 'a', 65);
    id65[65] = 0;
    snprintf(text, sizeof text, "%s,/p", id64);
    EXPECT(desk_spawn_parse(&s, text) == 0 && strcmp(s.app_id, id64) == 0);
    snprintf(text, sizeof text, "%s,/p", id65);
    EXPECT(desk_spawn_parse(&s, text) == -1);
    /* A path of 127 bytes fits, of 128 is refused. */
    char path[200];
    memset(path, 'p', 127);
    path[127] = 0;
    snprintf(text, sizeof text, "x,%s", path);
    EXPECT(desk_spawn_parse(&s, text) == 0 && strcmp(s.path, path) == 0);
    path[127] = 'p';
    path[128] = 0;
    snprintf(text, sizeof text, "x,%s", path);
    EXPECT(desk_spawn_parse(&s, text) == -1);
    /* A whole text of 255 bytes fits, of 256 is refused. */
    memset(text, 'a', 400);
    memcpy(text, "x,/p,", 5);
    text[255] = 0;
    EXPECT(desk_spawn_parse(&s, text) == 0);
    text[255] = 'a';
    text[256] = 0;
    EXPECT(desk_spawn_parse(&s, text) == -1);
    printf("launch_test: %u checks passed\n", checks);
    return 0;
}
