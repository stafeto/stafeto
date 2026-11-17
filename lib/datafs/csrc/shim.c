// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

// The string functions littlefs calls that the Rust runtime does not supply. Built with
// -fno-builtin, so no loop here turns into a call to the function it defines.
#include <stddef.h>

size_t strlen(const char *s)
{
    size_t n = 0;
    while (s[n] != '\0') {
        n++;
    }
    return n;
}

char *strcpy(char *dest, const char *src)
{
    size_t i = 0;
    do {
        dest[i] = src[i];
    } while (src[i++] != '\0');
    return dest;
}

char *strchr(const char *s, int c)
{
    for (;; s++) {
        if (*s == (char)c) {
            return (char *)s;
        }
        if (*s == '\0') {
            return NULL;
        }
    }
}

size_t strspn(const char *s, const char *accept)
{
    size_t n = 0;
    for (; s[n] != '\0'; n++) {
        const char *a = accept;
        while (*a != '\0' && *a != s[n]) {
            a++;
        }
        if (*a == '\0') {
            break;
        }
    }
    return n;
}

size_t strcspn(const char *s, const char *reject)
{
    size_t n = 0;
    for (; s[n] != '\0'; n++) {
        const char *r = reject;
        while (*r != '\0' && *r != s[n]) {
            r++;
        }
        if (*r != '\0') {
            break;
        }
    }
    return n;
}
