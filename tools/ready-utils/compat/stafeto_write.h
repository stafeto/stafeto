// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
// write(1) of chimerautils prints its greeting with printf and the text with
// putwchar and wprintf on the same stream. relibc fixes the orientation of a
// stream with the first call and refuses the other kind afterwards (POSIX asks
// a program not to mix them), so the two wide calls go through the byte
// functions of the stream, which carry the same bytes in the current locale.
#ifndef STAFETO_WRITE_H
#define STAFETO_WRITE_H
#include <limits.h>
#include <stdio.h>
#include <wchar.h>

static inline wint_t stafeto_putwchar(wchar_t c)
{
	char bytes[MB_LEN_MAX];
	mbstate_t state = {0};
	size_t length = wcrtomb(bytes, c, &state);

	if (length == (size_t)-1 || fwrite(bytes, 1, length, stdout) != length)
		return WEOF;
	return (wint_t)c;
}

// The one use of wprintf prints a control character as <0xNN>.
#define putwchar stafeto_putwchar
#define wprintf(format, ...) printf("<0x%X>", __VA_ARGS__)
#endif
