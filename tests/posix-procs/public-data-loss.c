/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
extern int files_data_loss_register(unsigned);
extern int files_data_loss_ready(void);
extern int files_data_loss_status(int);
extern int files_data_loss_help(void);
extern int files_data_loss_helper(void);
extern void files_data_loss_release(void);
extern int files_data_loss_finish(void);
struct data_loss_worker { int fd, case_number, returned, result; unsigned char bytes[1016]; };
static struct data_loss_worker data_loss_work;
static int data_loss_helper_returned;
static int data_loss_helper_go;
static void *data_loss_original(void *argument) {
    struct data_loss_worker *work = argument;
    if (public_data_thread_stack()) {
        work->result = -1;
        __atomic_store_n(&work->returned, 1, __ATOMIC_SEQ_CST);
        return NULL;
    }
    int result = files_data_loss_register((unsigned)work->case_number);
    if (!result) {
        result = work->case_number == 3
            ? (int)pread(work->fd, work->bytes, sizeof(work->bytes), 0)
            : (int)write(work->fd, "lost", 4);
    }
    work->result = result;
    __atomic_store_n(&work->returned, 1, __ATOMIC_SEQ_CST);
    return NULL;
}
static void *data_loss_foreign_helper(void *argument) {
    (void)argument;
    if (public_data_thread_stack()) {
        __atomic_store_n(&data_loss_helper_returned, 1, __ATOMIC_SEQ_CST);
        return NULL;
    }
    while (!__atomic_load_n(&data_loss_helper_go, __ATOMIC_ACQUIRE)) pending_pause();
    (void)files_data_loss_helper();
    __atomic_store_n(&data_loss_helper_returned, 1, __ATOMIC_SEQ_CST);
    return NULL;
}
static int check_public_data_loss(void) {
    for (int scenario = 1; scenario <= 3; ++scenario) {
        int fd = open("/tmp/public-data-loss", O_CREAT | O_TRUNC | O_RDWR, 0600);
        if (fd < 0) return 1;
        data_loss_work = (struct data_loss_worker){ .fd = fd, .case_number = scenario };
        if (scenario == 3) {
            memset(data_loss_work.bytes, 'R', sizeof(data_loss_work.bytes));
            if (write(fd, data_loss_work.bytes, 1012) != 1012 || pwrite(fd, "RRRR", 4, 1012) != 4) return 2;
        }
        pthread_t helper;
        if (scenario == 3) {
            __atomic_store_n(&data_loss_helper_returned, 0, __ATOMIC_SEQ_CST);
            __atomic_store_n(&data_loss_helper_go, 0, __ATOMIC_RELEASE);
            /* pthread_create collects ended owners and helps live records.
             * Create this dormant helper before the original admits Data. */
            if (pthread_create(&helper, NULL, data_loss_foreign_helper, NULL)) return 8;
        }
        pthread_t original;
        if (pthread_create(&original, NULL, data_loss_original, &data_loss_work)) return 3;
        int observed = 0;
        for (int retry = 0; retry < 1000; ++retry) {
            if (__atomic_load_n(&data_loss_work.returned, __ATOMIC_SEQ_CST)) return 4;
            int status = scenario == 3 ? files_data_loss_ready() : files_data_loss_status(0);
            if (status < 0) return 5;
            if (status == (scenario == 3 ? 1 : 2)) { observed = 1; break; }
            pending_pause();
        }
        if (!observed) return 5;
        if (scenario < 3) {
            if (files_data_loss_help() || files_data_loss_finish()) return 6;
            char bytes[4];
            ssize_t count = pread(fd, bytes, sizeof(bytes), 0);
            if (count != (scenario == 1 ? 0 : 4) || (count && memcmp(bytes, "lost", 4))) return 7;
        } else {
            __atomic_store_n(&data_loss_helper_go, 1, __ATOMIC_RELEASE);
            observed = 0;
            for (int retry = 0; retry < 1000; ++retry) {
                if (__atomic_load_n(&data_loss_helper_returned, __ATOMIC_SEQ_CST)) return 9;
                int status = files_data_loss_status(1);
                if (status < 0) return 10;
                if (status == 2) { observed = 1; break; }
                pending_pause();
            }
            if (!observed) return 10;
            files_data_loss_release();
            if (pthread_join(original, NULL) || data_loss_work.result != 1016) return 11;
            for (size_t i = 0; i < sizeof(data_loss_work.bytes); ++i)
                if (data_loss_work.bytes[i] != 'R') return 11;
            if (files_data_loss_finish()) return 13;
            /* Original join reclaims that allocation; helper is native Ended.
             * Final physical comparison is performed before the original join
             * in the two owner-loss cases. Scalar completion is checked here. */
        }
        if (close(fd)) return 12;
        /* Native Ended workers retain their relibc allocation until exit. */
    }
    puts("posix-files: public Data Start Commit and Query Waiting End recovery ok");
    return 0;
}
