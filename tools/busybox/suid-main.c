/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com> */

/* The main of the set-user-ID BusyBox of the images (/bin/su and /bin/passwd,
 * tools/build-libc-so.py programs). Its build holds the two applets and no
 * other (tools/build-busybox.py, WORK_SUID): this main hands the program to
 * BusyBox's dispatcher, which renamed its own main to applets_main, and has
 * no branch of its own. The main of the shell's BusyBox starts a console
 * session when argv[0] is a certain word, and that must never run in a file
 * that carries the set-user-ID bit. */
int applets_main(int argc, char **argv);

int main(int argc, char **argv) {
    return applets_main(argc, argv);
}
