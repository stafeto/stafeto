// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
#ifndef STAFETO_SYS_TTYDEFAULTS_H
#define STAFETO_SYS_TTYDEFAULTS_H
#define CTRL(x) ((x) & 037)
#define CEOF CTRL('d')
#define CEOL 0
#define CERASE 0177
#define CINTR CTRL('c')
#define CSTATUS 0
#define CKILL CTRL('u')
#define CMIN 1
#define CQUIT 034
#define CSUSP CTRL('z')
#define CTIME 0
#define CDSUSP CTRL('y')
#define CSTART CTRL('q')
#define CSTOP CTRL('s')
#define CLNEXT CTRL('v')
#define CDISCARD CTRL('o')
#define CWERASE CTRL('w')
#define CREPRINT CTRL('r')
#define CEOT CEOF
#define CBRK CEOL
#define CRPRNT CREPRINT
#define CFLUSH CDISCARD
#endif
