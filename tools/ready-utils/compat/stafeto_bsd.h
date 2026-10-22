// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
// Included before the sources of the BSD programs (chimerautils, nbase):
// what their systems give and relibc lacks, as macros and constants.
#ifndef STAFETO_BSD_H
#define STAFETO_BSD_H

// relibc's headers name structure members `__unused`, and the BSD
// <sys/cdefs.h> defines a macro of that name. Every header of relibc a
// program includes comes first, so that the macro is defined after them.
#include <sys/types.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/param.h>
#include <paths.h>
#include <regex.h>
#include <time.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <termios.h>
#include <utmpx.h>
#include <nl_types.h>

#define nitems(x) (sizeof(x) / sizeof((x)[0]))
#define __dead __attribute__((__noreturn__))
// m4 prints the name the program was started under.
#define __progname program_invocation_short_name
#ifndef _PATH_DEV
#define _PATH_DEV "/dev/"
#endif
// The basic regular expressions are the default of regcomp.
#ifndef REG_BASIC
#define REG_BASIC 0
#endif

// The functions of chimerautils' compat that relibc has under their names.
#define strftime_bsd strftime
#define strptime_bsd strptime
#define compat_mkstemp mkstemp
#define compat_mkostemp mkostemp
#define compat_mkdtemp mkdtemp

// gencat: relibc's <nl_types.h> declares the structures of the catalog that
// gencat.c declares again; its own copies take other names.
#define _nls_cat_hdr gencat_cat_hdr
#define _nls_set_hdr gencat_set_hdr
#define _nls_msg_hdr gencat_msg_hdr
#ifndef NL_SETMAX
#define NL_SETMAX 255
#endif
#ifndef NL_MSGMAX
#define NL_MSGMAX 32767
#endif

#endif
