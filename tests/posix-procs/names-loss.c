/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */
/* The loss of a reply in the middle of an operation on names: the service
 * did what the request asked and the answer never reached the layer, which
 * sends the same request again. Each operation ends with the effect of one
 * execution. A second execution shows in the result (EEXIST for mkdir,
 * ENOENT for rename and unlink, a link count of 3), a request under a new key
 * shows in the places of the service that fill (JOBS_FULL answered as EIO).
 * Included by files.c after names.c, for the image with the hook of the
 * driver (names_loss.rs). */

extern int files_loss_arm(int kind);
extern int files_loss_lost(void);
extern int files_loss_seen(int kind);
extern void files_loss_disarm(void);

#define LOSS_ROOT "/tmp/loss"
/* The kinds of request, as names_loss.rs numbers them. */
enum { LOSS_START = 1, LOSS_SECOND, LOSS_DONE, LOSS_COMMIT, LOSS_RELEASE };

/* The reply of `kind` was lost once, and the request went twice. */
#define LOST_ONCE(kind)                                                        \
    do {                                                                       \
        CHECK(files_loss_lost() == 1);                                         \
        CHECK(files_loss_seen(kind) == 2);                                     \
    } while (0)

static int loss_names(void) {
    struct stat st;
    char text[16];

    /* Start: the job exists after the lost reply, the same key finds it.
     * Forty rounds fill the places of the service if each took another key. */
    for (int round = 0; round < 40; round++) {
        CHECK(files_loss_arm(LOSS_START) == 0);
        OK(mkdir(LOSS_ROOT "/d", 0755));
        LOST_ONCE(LOSS_START);
        OK(stat(LOSS_ROOT "/d", &st));
        CHECK(S_ISDIR(st.st_mode));
        CHECK(files_loss_arm(LOSS_START) == 0);
        OK(rmdir(LOSS_ROOT "/d"));
        LOST_ONCE(LOSS_START);
        CHECK(!names_exists(LOSS_ROOT "/d"));
    }
    CHECK(files_names_places_in_use() == 0);

    /* The Step that commits: one effect, the saved outcome answers the repeat. */
    CHECK(names_put(LOSS_ROOT "/f", "x") == 0);
    CHECK(files_loss_arm(LOSS_DONE) == 0);
    OK(link(LOSS_ROOT "/f", LOSS_ROOT "/g"));
    LOST_ONCE(LOSS_DONE);
    OK(stat(LOSS_ROOT "/f", &st));
    CHECK(st.st_nlink == 2);
    OK(stat(LOSS_ROOT "/g", &st));
    CHECK(st.st_nlink == 2);

    CHECK(files_loss_arm(LOSS_DONE) == 0);
    OK(rename(LOSS_ROOT "/g", LOSS_ROOT "/h"));
    LOST_ONCE(LOSS_DONE);
    CHECK(!names_exists(LOSS_ROOT "/g") && names_exists(LOSS_ROOT "/h"));

    CHECK(files_loss_arm(LOSS_DONE) == 0);
    OK(unlink(LOSS_ROOT "/h"));
    LOST_ONCE(LOSS_DONE);
    CHECK(!names_exists(LOSS_ROOT "/h"));
    OK(stat(LOSS_ROOT "/f", &st));
    CHECK(st.st_nlink == 1);

    CHECK(files_loss_arm(LOSS_DONE) == 0);
    OK(mkdir(LOSS_ROOT "/m", 0755));
    LOST_ONCE(LOSS_DONE);
    CHECK(files_loss_arm(LOSS_DONE) == 0);
    OK(rmdir(LOSS_ROOT "/m"));
    LOST_ONCE(LOSS_DONE);
    CHECK(!names_exists(LOSS_ROOT "/m"));

    CHECK(files_loss_arm(LOSS_DONE) == 0);
    OK(chmod(LOSS_ROOT "/f", 0600));
    LOST_ONCE(LOSS_DONE);
    CHECK(names_mode(LOSS_ROOT "/f") == 0600);

    /* A refusal is an outcome too: the repeat gives the same errno. */
    CHECK(files_loss_arm(LOSS_DONE) == 0);
    FAILS(unlink(LOSS_ROOT "/missing"), ENOENT);
    LOST_ONCE(LOSS_DONE);
    CHECK(files_loss_arm(LOSS_DONE) == 0);
    FAILS(rename(LOSS_ROOT "/missing", LOSS_ROOT "/f2"), ENOENT);
    LOST_ONCE(LOSS_DONE);
    CHECK(files_loss_arm(LOSS_DONE) == 0);
    FAILS(mkdir(LOSS_ROOT, 0755), EEXIST);
    LOST_ONCE(LOSS_DONE);

    /* Second: the second path or the contents are stored once. */
    CHECK(files_loss_arm(LOSS_SECOND) == 0);
    OK(symlink("target-of-the-link", LOSS_ROOT "/l"));
    LOST_ONCE(LOSS_SECOND);
    memset(text, 0, sizeof text);
    CHECK(readlink(LOSS_ROOT "/l", text, sizeof text) == 16 && memcmp(text, "target-of-the-li", 16) == 0);
    CHECK(files_loss_arm(LOSS_SECOND) == 0);
    OK(rename(LOSS_ROOT "/f", LOSS_ROOT "/f3"));
    LOST_ONCE(LOSS_SECOND);
    CHECK(!names_exists(LOSS_ROOT "/f") && names_exists(LOSS_ROOT "/f3"));
    CHECK(files_loss_arm(LOSS_SECOND) == 0);
    OK(link(LOSS_ROOT "/f3", LOSS_ROOT "/f4"));
    LOST_ONCE(LOSS_SECOND);
    OK(stat(LOSS_ROOT "/f3", &st));
    CHECK(st.st_nlink == 2);
    OK(unlink(LOSS_ROOT "/f4"));
    OK(unlink(LOSS_ROOT "/f3"));
    OK(unlink(LOSS_ROOT "/l"));

    /* Release: the effect stands, the job ends, the place is free. */
    for (int round = 0; round < 40; round++) {
        CHECK(files_loss_arm(LOSS_RELEASE) == 0);
        OK(mkdir(LOSS_ROOT "/r", 0755));
        LOST_ONCE(LOSS_RELEASE);
        CHECK(files_loss_arm(LOSS_RELEASE) == 0);
        OK(rmdir(LOSS_ROOT "/r"));
        LOST_ONCE(LOSS_RELEASE);
    }
    CHECK(files_names_places_in_use() == 0);
    CHECK(files_loss_arm(LOSS_RELEASE) == 0);
    FAILS(unlink(LOSS_ROOT "/missing"), ENOENT);
    LOST_ONCE(LOSS_RELEASE);
    return 0;
}

/* ftruncate is a Data job: the Start, the Commit and the Release lose a reply. */
static int loss_truncate(void) {
    struct stat st;
    int fd = open(LOSS_ROOT "/t", O_RDWR | O_CREAT | O_TRUNC, 0644);
    CHECK(fd >= 0);
    CHECK(write(fd, "0123456789", 10) == 10);
    static const int kinds[] = {LOSS_START, LOSS_COMMIT, LOSS_RELEASE};
    long long sizes[] = {7, 4, 12};
    for (int i = 0; i < 3; i++) {
        CHECK(files_loss_arm(kinds[i]) == 0);
        OK(ftruncate(fd, sizes[i]));
        LOST_ONCE(kinds[i]);
        OK(fstat(fd, &st));
        CHECK(st.st_size == sizes[i]);
    }
    char bytes[12];
    CHECK(pread(fd, bytes, sizeof bytes, 0) == 12);
    CHECK(memcmp(bytes, "0123", 4) == 0);
    for (int i = 4; i < 12; i++) CHECK(bytes[i] == 0);
    CHECK(close(fd) == 0);
    OK(unlink(LOSS_ROOT "/t"));
    CHECK(files_names_places_in_use() == 0);
    return 0;
}

static int names_loss_all(void) {
    OK(mkdir(LOSS_ROOT, 0777));
    int failed = loss_names();
    if (!failed) failed = loss_truncate();
    files_loss_disarm();
    if (failed) {
        printf("posix-files: names loss failed at names-loss.c:%d\n", failed);
        return failed;
    }
    OK(rmdir(LOSS_ROOT));
    puts("posix-files: a lost reply of Start, Second, Step, Commit and Release leaves one effect");
    return 0;
}
