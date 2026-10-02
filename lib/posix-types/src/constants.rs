// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

pub const S_IFMT: u32 = 61440;
pub const S_IFDIR: u32 = 16384;
pub const S_IFREG: u32 = 32768;
pub const S_IFCHR: u32 = 8192;
pub const S_IFLNK: u32 = 40960;
pub const S_IFBLK: u32 = 24576;
pub const S_IFIFO: u32 = 4096;
pub const S_IFSOCK: u32 = 49152;
pub const S_ISUID: u32 = 2048;
pub const S_ISGID: u32 = 1024;
pub const S_ISVTX: u32 = 512;
pub const S_IRUSR: u32 = 256;
pub const S_IWUSR: u32 = 128;
pub const S_IXUSR: u32 = 64;
pub const S_IRGRP: u32 = 32;
pub const S_IWGRP: u32 = 16;
pub const S_IXGRP: u32 = 8;
pub const S_IROTH: u32 = 4;
pub const S_IWOTH: u32 = 2;
pub const S_IXOTH: u32 = 1;
pub const STAFETO_STAT_SIZE: u32 = 120;
pub const DT_UNKNOWN: u32 = 0;
pub const DT_DIR: u32 = 4;
pub const DT_REG: u32 = 8;
pub const DT_CHR: u32 = 2;
pub const NAME_MAX: u32 = 128;
pub const STAFETO_DIRENT_SIZE: u32 = 144;

pub const SIGHUP: i32 = 1;
pub const SIGINT: i32 = 2;
pub const SIGQUIT: i32 = 3;
pub const SIGILL: i32 = 4;
pub const SIGTRAP: i32 = 5;
pub const SIGABRT: i32 = 6;
pub const SIGBUS: i32 = 7;
pub const SIGFPE: i32 = 8;
pub const SIGKILL: i32 = 9;
pub const SIGUSR1: i32 = 10;
pub const SIGSEGV: i32 = 11;
pub const SIGUSR2: i32 = 12;
pub const SIGPIPE: i32 = 13;
pub const SIGALRM: i32 = 14;
pub const SIGTERM: i32 = 15;
pub const SIGSTKFLT: i32 = 16;
pub const SIGCHLD: i32 = 17;
pub const SIGCONT: i32 = 18;
pub const SIGSTOP: i32 = 19;
pub const SIGTSTP: i32 = 20;
pub const SIGTTIN: i32 = 21;
pub const SIGTTOU: i32 = 22;
pub const SIGURG: i32 = 23;
pub const SIGXCPU: i32 = 24;
pub const SIGXFSZ: i32 = 25;
pub const SIGVTALRM: i32 = 26;
pub const SIGPROF: i32 = 27;
pub const SIGWINCH: i32 = 28;
pub const SIGPOLL: i32 = 29;
pub const SIGPWR: i32 = 30;
pub const SIGSYS: i32 = 31;
pub const SIG_BLOCK: i32 = 1;
pub const SIG_UNBLOCK: i32 = 2;
pub const SIG_SETMASK: i32 = 3;
pub const SA_NODEFER: i32 = 1;
pub const SA_RESETHAND: i32 = 2;
pub const SA_SIGINFO: i32 = 4;
/// A read in two steps that a handler with this flag interrupted goes on
/// waiting (spec 2, 3.3); other calls return EINTR as before.
pub const SA_RESTART: i32 = 16;
/// SIGCHLD only: no SIGCHLD when a child stops (5e).
pub const SA_NOCLDSTOP: i32 = 32;
/// SIGCHLD only: the children leave no zombies (the process service
/// reads it from the record's page).
pub const SA_NOCLDWAIT: i32 = 64;
pub const SS_DISABLE: i32 = 2;
// Source codes are implementation-defined numbers. Reserved standard sources
// are declared for C applications before their generators are implemented.
pub const SI_USER: i32 = 0;
pub const SI_QUEUE: i32 = 64;
pub const SI_TIMER: i32 = 65;
pub const SI_ASYNCIO: i32 = 66;
pub const SI_MESGQ: i32 = 67;
pub const ILL_ILLOPC: i32 = 1;
pub const ILL_ILLOPN: i32 = 2;
pub const ILL_ILLADR: i32 = 3;
pub const ILL_ILLTRP: i32 = 4;
pub const ILL_PRVOPC: i32 = 5;
pub const ILL_PRVREG: i32 = 6;
pub const ILL_COPROC: i32 = 7;
pub const ILL_BADSTK: i32 = 8;
pub const FPE_INTDIV: i32 = 1;
pub const FPE_INTOVF: i32 = 2;
pub const FPE_FLTDIV: i32 = 3;
pub const FPE_FLTOVF: i32 = 4;
pub const FPE_FLTUND: i32 = 5;
pub const FPE_FLTRES: i32 = 6;
pub const FPE_FLTINV: i32 = 7;
pub const FPE_FLTSUB: i32 = 8;
pub const SEGV_MAPERR: i32 = 1;
pub const SEGV_ACCERR: i32 = 2;
pub const BUS_ADRALN: i32 = 1;
pub const BUS_ADRERR: i32 = 2;
pub const BUS_OBJERR: i32 = 3;
pub const CLD_EXITED: i32 = 1;
pub const CLD_KILLED: i32 = 2;
pub const CLD_DUMPED: i32 = 3;
pub const CLD_TRAPPED: i32 = 4;
pub const CLD_STOPPED: i32 = 5;
pub const CLD_CONTINUED: i32 = 6;
/// Implementation-defined cause for pthread_kill and raise; no queued value.
pub const SI_THREAD: i32 = 128;
