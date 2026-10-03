/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

extern unsigned long long stafeto_probe_job_ticket(int);
extern int stafeto_probe_stop_ticket(int, unsigned long long);
extern int stafeto_probe_assign_job(int);
extern int stafeto_probe_return_job(int, unsigned long long);
extern int stafeto_probe_return_job_info(int, unsigned long long, int, int);
extern void stafeto_probe_return_failure(void);

extern int stafeto_probe_loading_pid(void);
extern void stafeto_probe_fork_early(void (*window)(void));
extern int stafeto_probe_loads(void);
static int loading_signal, loading_pid, loading_result, loading_report, loading_report_errno;
static void job_loading_window(void) {
    loading_pid = stafeto_probe_loading_pid();
    loading_result = kill(loading_pid, loading_signal);
    if (loading_signal == SIGSTOP) {
        loading_report = waitpid(loading_pid, NULL, WUNTRACED | WNOHANG);
        loading_report_errno = errno;
    }
}

static void job_set(sigset_t *set);

static int job_after_exec(int want_pending) {
    sigset_t pending, jobs;
    job_set(&jobs);
    if (sigpending(&pending) != 0 || sigismember(&pending, SIGTSTP) != want_pending) return 11;
    struct timespec zero = {0, 0};
    siginfo_t info;
    if (want_pending && (sigtimedwait(&jobs, &info, &zero) != SIGTSTP
        || info.si_pid != getpid() || info.si_code != 0)) return 12;
    return 0;
}

/* Included by procs.c so every operation uses the same observed checks. */
static void job_set(sigset_t *set) {
    sigemptyset(set);
    sigaddset(set, SIGTSTP);
    sigaddset(set, SIGTTIN);
    sigaddset(set, SIGTTOU);
    sigaddset(set, SIGCONT);
}

static void *job_sender(void *argument) {
    int signal = (int)(long)argument;
    for (unsigned i = 0; i < 40; i++) {
        if (pthread_kill(main_thread, signal) != 0) return (void *)1;
    }
    return NULL;
}

static int job_assigned, job_owner_gate[2];
static void *job_exec_owner(void *unused) {
    (void)unused;
    int result = stafeto_probe_assign_job(SIGTSTP);
    __atomic_store_n(&job_assigned, result == 0 ? 1 : -1, __ATOMIC_SEQ_CST);
    char byte;
    while (read(job_owner_gate[0], &byte, 1) < 0 && errno == EINTR) {}
    return NULL;
}

static pid_t job_process_sender(void) {
    pid_t parent = getpid(), sender = fork();
    if (sender == 0) _exit(kill(parent, SIGTSTP) == 0 ? 0 : 1);
    expect("job sender created", sender > 0, 1);
    reap("job sender exits", sender, 0, 0);
    return sender;
}

static void job_hup(int signal) {
    handled = signal;
}

static int job_control(void) {
    expect("linked job-control group", setpgid(0, 0), 0);
    sigset_t jobs, pending, chld;
    job_set(&jobs);
    expect("block job signals", sigprocmask(SIG_BLOCK, &jobs, NULL), 0);
    expect("raise blocked TSTP", raise(SIGTSTP), 0);
    expect("blocked TSTP pending", sigpending(&pending), 0);
    expect("TSTP bit", sigismember(&pending, SIGTSTP), 1);
    struct timespec zero = {0, 0};
    siginfo_t info;
    expect("sigwait consumes blocked TSTP", sigtimedwait(&jobs, &info, &zero), SIGTSTP);
    expect("TSTP thread information", info.si_code, -6);
    expect("raise blocked CONT", raise(SIGCONT), 0);
    expect("raise cancels CONT", raise(SIGTTIN), 0);
    expect("pending after TTIN", sigpending(&pending), 0);
    expect("CONT was cancelled", sigismember(&pending, SIGCONT), 0);
    expect("CONT cancels TTIN", raise(SIGCONT), 0);
    expect("pending after CONT", sigpending(&pending), 0);
    expect("TTIN was cancelled", sigismember(&pending, SIGTTIN), 0);
    expect("consume CONT", sigtimedwait(&jobs, &info, &zero), SIGCONT);

    main_thread = pthread_self();
    pthread_t first, second;
    expect("first concurrent sender", pthread_create(&first, NULL, job_sender, (void *)(long)SIGTSTP), 0);
    expect("second concurrent sender", pthread_create(&second, NULL, job_sender, (void *)(long)SIGCONT), 0);
    void *result = (void *)1;
    expect("join first sender", pthread_join(first, &result), 0);
    expect("first sender status", result == NULL, 1);
    expect("join second sender", pthread_join(second, &result), 0);
    expect("second sender status", result == NULL, 1);
    expect("final CONT generation", raise(SIGCONT), 0);
    expect("concurrent pending", sigpending(&pending), 0);
    expect("concurrent TSTP cancelled", sigismember(&pending, SIGTSTP), 0);
    expect("consume concurrent CONT", sigtimedwait(&jobs, &info, &zero), SIGCONT);
    expect("unblock job signals", sigprocmask(SIG_UNBLOCK, &jobs, NULL), 0);
    printf("posix-jobs: blocked sigwait and concurrent generations passed\n");

    unsigned long long ticket = stafeto_probe_job_ticket(SIGTSTP);
    expect("job generation ticket", ticket != ~0ULL, 1);
    expect("cancel captured stop", kill(getpid(), SIGCONT), 0);
    pid_t caller = getpid(), resumer = fork();
    if (resumer == 0) { pause_ms(250); kill(caller, SIGCONT); _exit(0); }
    expect("late stop resumer", resumer > 0, 1);
    struct timespec began, finished;
    clock_gettime(CLOCK_MONOTONIC, &began);
    expect("late StopSelf is harmless", stafeto_probe_stop_ticket(SIGTSTP, ticket), 0);
    clock_gettime(CLOCK_MONOTONIC, &finished);
    long long elapsed = (finished.tv_sec - began.tv_sec) * 1000000000LL + finished.tv_nsec - began.tv_nsec;
    expect("late stop never suspended caller", elapsed < 100000000LL, 1);
    reap("late stop resumer", resumer, 0, 0);
    expect("cancelled give_back rejected", stafeto_probe_return_job(SIGTSTP, ticket), 0);
    expect("no resurrected stop", sigpending(&pending), 0);
    expect("stale stop remains absent", sigismember(&pending, SIGTSTP), 0);
    expect("block return information", sigprocmask(SIG_BLOCK, &jobs, NULL), 0);
    pid_t sender = job_process_sender();
    ticket = stafeto_probe_job_ticket(SIGTSTP);
    expect("assign return information", stafeto_probe_assign_job(SIGTSTP), 0);
    stafeto_probe_return_failure();
    expect("failed return keeps mask", sigprocmask(SIG_BLOCK, &jobs, NULL), 0);
    expect("failed return keeps pending", sigpending(&pending), 0);
    expect("failed return keeps assignment", sigismember(&pending, SIGTSTP), 1);
    expect("mask returns assignment", sigprocmask(SIG_BLOCK, &jobs, NULL), 0);
    expect("returned signal", sigtimedwait(&jobs, &info, &zero), SIGTSTP);
    expect("returned sender", info.si_pid, sender);
    expect("returned sender code", info.si_code, 0);
    sender = job_process_sender();
    expect("coalesced return", stafeto_probe_return_job_info(SIGTSTP, ticket, 300, -6), 0);
    expect("coalesced signal", sigtimedwait(&jobs, &info, &zero), SIGTSTP);
    expect("coalescing preserves sender", info.si_pid, sender);
    expect("coalescing preserves code", info.si_code, 0);
    expect("cancel old information epoch", kill(getpid(), SIGCONT), 0);
    sender = job_process_sender();
    expect("stale return acknowledged", stafeto_probe_return_job_info(SIGTSTP, ticket, 300, -6), 0);
    expect("new signal after stale return", sigtimedwait(&jobs, &info, &zero), SIGTSTP);
    expect("stale return preserves sender", info.si_pid, sender);
    expect("stale return preserves code", info.si_code, 0);
    expect("unblock return information", sigprocmask(SIG_UNBLOCK, &jobs, NULL), 0);

    for (int local = 0; local < 4; local++) {
        pid_t image = fork();
        if (image == 0) {
            if (sigprocmask(SIG_BLOCK, &jobs, NULL) != 0 || kill(getpid(), SIGTSTP) != 0) _exit(13);
            if (local == 2) {
                pthread_t owner;
                if (pipe(job_owner_gate) != 0) _exit(18);
                if (pthread_create(&owner, NULL, job_exec_owner, NULL) != 0) _exit(16);
                while (__atomic_load_n(&job_assigned, __ATOMIC_SEQ_CST) == 0) sched_yield();
                if (__atomic_load_n(&job_assigned, __ATOMIC_SEQ_CST) != 1) _exit(17);
                pause_ms(20);
                stafeto_probe_return_failure();
            } else if (stafeto_probe_assign_job(SIGTSTP) != 0) _exit(13);
            if (local == 1 && (raise(SIGCONT) != 0 || raise(SIGTSTP) != 0)) _exit(14);
            char *next[] = {"procs-child", local == 1 ? "jobexec-local" : "jobexec-process", NULL};
            char *env[] = {NULL};
            if (local == 3) stafeto_probe_return_failure();
            execve("/bin/procs-child", next, env);
            if (local == 3 && errno == EIO) {
                sigset_t current;
                if (sigprocmask(SIG_SETMASK, NULL, &current) != 0
                    || sigismember(&current, SIGTSTP) != 1) _exit(19);
                if (sigtimedwait(&jobs, &info, &zero) != SIGTSTP
                    || info.si_pid != getpid() || info.si_code != 0) _exit(20);
                _exit(0);
            }
            _exit(15);
        }
        reap(local == 1 ? "exec discards fresh local stop after cancelled process stop"
                   : local == 2 ? "multithread exec retries return and preserves sender"
                   : local == 3 ? "failed exec return preserves assignment and mask"
                   : "exec preserves process-origin stop epoch", image, 0, 0);
    }
    printf("posix-jobs: late StopSelf give_back and exec origin passed\n");


    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_flags = SA_NOCLDSTOP;
    expect("NOCLDSTOP", sigaction(SIGCHLD, &action, NULL), 0);
    expect("block SIGCHLD", sigprocmask(SIG_BLOCK, &chld, NULL), 0);
    int gate[2];
    expect("child gate", pipe(gate), 0);
    pid_t child = fork();
    if (child == 0) {
        close(gate[1]);
        sigset_t cont;
        sigemptyset(&cont);
        sigaddset(&cont, SIGCONT);
        if (sigprocmask(SIG_BLOCK, &cont, NULL) != 0 || raise(SIGSTOP) != 0) _exit(1);
        siginfo_t got;
        if (sigtimedwait(&cont, &got, &zero) != SIGCONT) _exit(2);
        char byte = 0;
        if (read(gate[0], &byte, 1) != 1 || byte != 'x') _exit(3);
        _exit(0);
    }
    expect("fork stop child", child > 0, 1);
    close(gate[0]);
    expect("WNOWAIT stopped report", waitid(P_PID, child, &info, WSTOPPED | WNOWAIT), 0);
    expect("stopped report code", info.si_code, CLD_STOPPED);
    expect("stopped report signal", info.si_status, SIGSTOP);
    int status = 0;
    expect("waitpid stop consumes report", waitpid(child, &status, WUNTRACED), child);
    expect("WIFSTOPPED", WIFSTOPPED(status), 1);
    expect("WSTOPSIG", WSTOPSIG(status), SIGSTOP);
    expect("NOCLDSTOP suppresses stop SIGCHLD", sigtimedwait(&chld, &info, &zero) < 0 ? errno : 0, EAGAIN);
    expect("CONT despite blocked CONT", kill(child, SIGCONT), 0);
    expect("waitpid continued", waitpid(child, &status, WCONTINUED), child);
    expect("WIFCONTINUED", WIFCONTINUED(status), 1);
    expect("NOCLDSTOP suppresses continued SIGCHLD", sigtimedwait(&chld, &info, &zero) < 0 ? errno : 0, EAGAIN);
    expect("rapid STOP after CONT", kill(child, SIGSTOP), 0);
    expect("STOP replaces unconsumed CONT", waitid(P_PID, child, &info, WSTOPPED | WNOWAIT), 0);
    expect("rapid stopped report", info.si_code, CLD_STOPPED);
    expect("rapid CONT after WNOWAIT", kill(child, SIGCONT), 0);
    memset(&info, 0, sizeof info);
    expect("CONT replaces WNOWAIT STOP", waitid(P_PID, child, &info, WSTOPPED | WNOHANG), 0);
    expect("no stale stop report", info.si_pid, 0);
    expect("CONT WNOWAIT", waitid(P_PID, child, &info, WCONTINUED | WNOWAIT), 0);
    expect("continued report", info.si_code, CLD_CONTINUED);
    expect("STOP replaces WNOWAIT CONT", kill(child, SIGSTOP), 0);
    memset(&info, 0, sizeof info);
    expect("no stale continued report", waitid(P_PID, child, &info, WCONTINUED | WNOHANG), 0);
    expect("no continued PID", info.si_pid, 0);
    expect("final CONT", kill(child, SIGCONT), 0);
    expect("release child", write(gate[1], "x", 1), 1);
    close(gate[1]);
    reap("continued child", child, 0, 0);
    expect("end still posts SIGCHLD", sigtimedwait(&chld, &info, &zero), SIGCHLD);
    expect("end report code", info.si_code, CLD_EXITED);
    action.sa_flags = 0;
    expect("restore SIGCHLD", sigaction(SIGCHLD, &action, NULL), 0);
    expect("unblock SIGCHLD", sigprocmask(SIG_UNBLOCK, &chld, NULL), 0);
    printf("posix-jobs: wait stop continue and NOCLDSTOP passed\n");

    /* A default TSTP stops a nonorphaned group; an orphaned group proceeds. */
    expect("TSTP child gate", pipe(gate), 0);
    child = fork();
    if (child == 0) {
        close(gate[1]);
        char byte;
        if (setpgid(0, 0) != 0 || signal(SIGCONT, SIG_IGN) == SIG_ERR
            || read(gate[0], &byte, 1) != 1 || raise(SIGTSTP) != 0) _exit(4);
        _exit(0);
    }
    close(gate[0]);
    expect("release TSTP child", write(gate[1], "x", 1), 1);
    close(gate[1]);
    expect("default TSTP wait", waitpid(child, &status, WUNTRACED), child);
    expect("default TSTP stop", WIFSTOPPED(status) && WSTOPSIG(status) == SIGTSTP, 1);
    expect("group STOP accepted", kill(-child, SIGSTOP), 0);
    expect("ignored CONT resumes TSTP child", kill(-child, SIGCONT), 0);
    reap("TSTP child", child, 0, 0);
    child = fork();
    if (child == 0) {
        if (setsid() < 0 || raise(SIGTSTP) != 0) _exit(5);
        _exit(0);
    }
    reap("orphaned TSTP child", child, 0, 0);

    /* Exiting the sole parent link schedules HUP and CONT for stopped members. */
    expect("orphan observation pipe", pipe(gate), 0);
    child = fork();
    if (child == 0) {
        close(gate[0]);
        if (setsid() < 0) _exit(6);
        pid_t grandchild = fork();
        if (grandchild == 0) {
            if (setpgid(0, 0) != 0) _exit(7);
            signal(SIGHUP, job_hup);
            handled = 0;
            if (raise(SIGSTOP) != 0) _exit(8);
            if (handled != SIGHUP || write(gate[1], "h", 1) != 1) _exit(9);
            _exit(0);
        }
        int stopped = 0;
        if (waitpid(grandchild, &stopped, WUNTRACED) != grandchild || !WIFSTOPPED(stopped)) _exit(10);
        _exit(0);
    }
    close(gate[1]);
    char byte = 0;
    expect("new orphan HUP then CONT", read(gate[0], &byte, 1), 1);
    expect("orphan HUP marker", byte, 'h');
    close(gate[0]);
    reap("orphan parent", child, 0, 0);
    printf("posix-jobs: default stops and orphan HUP CONT passed\n");
    for (int killed = 0; killed < 2; ++killed) {
        unsigned long long before = stafeto_probe_pool();
        loading_signal = killed ? SIGKILL : SIGSTOP;
        stafeto_probe_fork_early(job_loading_window);
        child = fork();
        stafeto_probe_fork_early(NULL);
        if (child == 0) _exit(0);
        expect("signal Loading", loading_result, 0);
        if (!killed) {
            expect("Loading has no wait status until Commit", loading_report, -1);
            expect("Loading wait errno", loading_report_errno, ECHILD);
        }
        if (killed) {
            expect("KILL aborts Loading", child < 0, 1);
            expect("KILL frees loader places", stafeto_probe_loads(), 2);
            unsigned long long after = stafeto_probe_pool();
            expect("KILL frees loading quota", after + 32 * 4096 >= before, 1);
        } else {
            expect("STOP permits loader Commit", child, loading_pid);
            expect("STOP report after Commit", waitpid(child, &status, WUNTRACED), child);
            expect("stopped child entered no code", WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP, 1);
            expect("CONT committed child", kill(child, SIGCONT), 0);
            reap("loading stop child", child, 0, 0);
        }
    }
    printf("posix-jobs: loading STOP Commit and KILL cleanup passed\n");
    return failures != 0;
}
