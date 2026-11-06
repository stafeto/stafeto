// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//config:config CRYPT_PROBE
//config:	bool "crypt-probe"
//config:	default y
//config:	help
//config:	A probe of how the C library's crypt refuses a password and of the
//config:	account files of the image, for the guest tests:
//config:	crypt-probe crypt | accounts | newgrp.

//applet:IF_CRYPT_PROBE(APPLET_ODDNAME(crypt-probe, crypt_probe, BB_DIR_USR_BIN, BB_SUID_DROP, crypt_probe))

//kbuild:lib-$(CONFIG_CRYPT_PROBE) += stafeto_cryptprobe.o

//usage:#define crypt_probe_trivial_usage
//usage:       "crypt | accounts | newgrp"
//usage:#define crypt_probe_full_usage "\n\n"
//usage:       "Check that crypt gives no string for a key of 257 to 1024 bytes or a setting\n"
//usage:       "of a short password field, that /etc/shadow locks every account, and that\n"
//usage:       "newgrp refuses a user with a long password"

#include <crypt.h>
#include <sys/wait.h>
#include "libbb.h"

static int failures;

static void check(int ok, const char *what)
{
	printf("crypt-probe: %s: %s\n", what, ok ? "ok" : "FAILED");
	if (!ok)
		failures++;
}

/* What a program that compares strings does: the password is right when
 * crypt answers a string equal to the field. */
static int accepts(const char *key, const char *field)
{
	const char *out = crypt(key, field);

	return out != NULL && strcmp(out, field) == 0;
}

static void probe_crypt(void)
{
	static const size_t lengths[] = { 257, 300, 512, 1024 };
	static const char *const fields[] = { "*", "!", "x", "" };
	char key[1025], hash[256], borrowed[300];
	const char *out;
	unsigned i, j;
	int ok;

	memset(key, 'k', sizeof(key) - 1);
	key[sizeof(key) - 1] = '\0';

	out = crypt("pw", "$6$saltstring");
	check(out && strncmp(out, "$6$saltstring$", 14) == 0, "a short key hashes with $6$");
	snprintf(hash, sizeof(hash), "%s", out ? out : "");

	ok = 1;
	for (i = 0; i < ARRAY_SIZE(lengths); i++) {
		key[lengths[i]] = '\0';
		for (j = 0; j < ARRAY_SIZE(fields); j++) {
			errno = 0;
			out = crypt(key, fields[j]);
			if (out != NULL || errno == 0 || accepts(key, fields[j])) {
				printf("crypt-probe: key %u field \"%s\" gave %s\n",
					(unsigned)lengths[i], fields[j], out ? out : "an error without errno");
				ok = 0;
			}
		}
		/* the setting of another entry as the salt (the field is too short for one) */
		snprintf(borrowed, sizeof(borrowed), "%s", hash);
		errno = 0;
		out = crypt(key, borrowed);
		if (out != NULL || errno == 0 || (out && out[0] == '*')) {
			printf("crypt-probe: key %u with a $6$ salt gave %s\n",
				(unsigned)lengths[i], out ? out : "an error without errno");
			ok = 0;
		}
		for (j = 0; j < ARRAY_SIZE(fields); j++)
			if (out && strcmp(out, fields[j]) == 0)
				ok = 0;
		key[lengths[i]] = 'k';
	}
	key[sizeof(key) - 1] = '\0';
	check(ok, "a key of 257 to 1024 bytes against *, !, x, an empty field and a borrowed $6$ salt is refused");

	errno = 0;
	check(crypt("pw", "$5$saltstring") != NULL && crypt(key, "$5$saltstring") == NULL && errno != 0,
		"a long key against $5$ gives NULL with errno");
	check(crypt("pw", "$6$\xc3\xa9") == NULL, "a non-ASCII salt gives NULL");
	check(crypt("pw", "$6$rounds=10000000$x") == NULL, "rounds above 9999999 give NULL");
	check(accepts("pw", hash), "the right password is accepted");
	check(!accepts("other", hash), "another password is refused");
	snprintf(borrowed, sizeof(borrowed), "!%s", hash);
	check(!accepts("pw", borrowed), "a locked hash accepts nothing");
}

static void probe_accounts(void)
{
	char line[512];
	FILE *f;
	int rows, ok;

	f = fopen("/etc/shadow", "r");
	check(f != NULL, "/etc/shadow opens");
	rows = 0;
	ok = 1;
	while (f && fgets(line, sizeof(line), f)) {
		char *pw = strchr(line, ':');

		rows++;
		if (!pw || pw[1] != '!')
			ok = 0;
	}
	if (f)
		fclose(f);
	check(rows >= 3 && ok, "every entry of /etc/shadow is locked with !");

	f = fopen("/etc/passwd", "r");
	check(f != NULL, "/etc/passwd opens");
	rows = 0;
	ok = 1;
	while (f && fgets(line, sizeof(line), f)) {
		char *pw = strchr(line, ':');

		rows++;
		if (!pw || pw[1] != 'x' || pw[2] != ':')
			ok = 0;
	}
	if (f)
		fclose(f);
	check(rows >= 3 && ok, "every password field of /etc/passwd is x");
}

static void probe_newgrp(void)
{
	char key[1026];
	int fds[2], status = 0;
	pid_t pid;

	memset(key, 'k', 1024);
	key[1024] = '\n';
	key[1025] = '\0';
	if (pipe(fds) != 0) {
		check(0, "pipe");
		return;
	}
	pid = fork();
	if (pid < 0) {
		check(0, "fork");
		return;
	}
	if (pid == 0) {
		/* user 1000 of group 100: not a member of group root */
		if (setgid(100) != 0 || setuid(1000) != 0)
			_exit(125);
		dup2(fds[0], 0);
		close(fds[0]);
		close(fds[1]);
		execl("/bin/newgrp", "newgrp", "-c", "echo GRANTED", "root", (char *)NULL);
		_exit(126);
	}
	close(fds[0]);
	if (write(fds[1], key, 1025) != 1025)
		check(0, "the password is written");
	close(fds[1]);
	check(waitpid(pid, &status, 0) == pid, "newgrp ends");
	printf("crypt-probe: newgrp status %d\n", status);
	check(WIFEXITED(status) && WEXITSTATUS(status) == 1, "newgrp as user refuses a password of 1024 bytes");
}

int crypt_probe_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int crypt_probe_main(int argc UNUSED_PARAM, char **argv)
{
	const char *what = argv[1];

	if (!what)
		bb_show_usage();
	if (!strcmp(what, "crypt"))
		probe_crypt();
	else if (!strcmp(what, "accounts"))
		probe_accounts();
	else if (!strcmp(what, "newgrp"))
		probe_newgrp();
	else
		bb_show_usage();
	printf("crypt-probe: %d failures\n", failures);
	return failures != 0;
}
