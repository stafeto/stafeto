// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
// The header mk-configure writes for nbase's raise_default_signal: the
// default action of the signal, unblocked, then the signal.
#ifndef STAFETO_MKC_RAISE_DEFAULT_SIGNAL_H
#define STAFETO_MKC_RAISE_DEFAULT_SIGNAL_H
#include <signal.h>
#define raise_default_signal(sig) ({ \
	sigset_t set_; \
	sigemptyset(&set_); \
	sigaddset(&set_, (sig)); \
	signal((sig), SIG_DFL); \
	sigprocmask(SIG_UNBLOCK, &set_, 0); \
	raise(sig); })
#endif
