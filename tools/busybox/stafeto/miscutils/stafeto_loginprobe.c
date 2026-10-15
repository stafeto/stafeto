// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//config:config LOGIN_PROBE
//config:	bool "login-probe"
//config:	default y
//config:	help
//config:	A probe of the C library's login name, system log and user
//config:	accounting functions (getlogin, syslog, utmpx), for the guest
//config:	tests: login-probe login | syslog | utmpx.

//applet:IF_LOGIN_PROBE(APPLET_ODDNAME(login-probe, login_probe, BB_DIR_USR_BIN, BB_SUID_DROP, login_probe))

//kbuild:lib-$(CONFIG_LOGIN_PROBE) += stafeto_loginprobe.o

//usage:#define login_probe_trivial_usage
//usage:       "login | syslog | utmpx"
//usage:#define login_probe_full_usage "\n\n"
//usage:       "Exercise getlogin and getlogin_r; openlog, syslog, setlogmask and closelog;\n"
//usage:       "the utmpx functions on /var/run/utmpx"

#include <syslog.h>
#include <utmpx.h>
#include "libbb.h"

static int failures;

static void check(int ok, const char *what)
{
	printf("login-probe: %s: %s\n", what, ok ? "ok" : "FAILED");
	if (!ok)
		failures++;
}

static void probe_login(void)
{
	char small[2], big[64];
	char *name = getlogin();
	int r;

	printf("login-probe: getlogin %s\n", name ? name : "NULL");
	r = getlogin_r(big, sizeof(big));
	printf("login-probe: getlogin_r %d %s\n", r, r == 0 ? big : "-");
	check(name && r == 0 && strcmp(name, big) == 0, "getlogin and getlogin_r agree");
	r = getlogin_r(small, sizeof(small));
	check(r == ERANGE, "getlogin_r with a buffer of 2 bytes gives ERANGE");
}

static void probe_syslog(void)
{
	int old;

	openlog("probe", LOG_PID, LOG_USER);
	old = setlogmask(LOG_UPTO(LOG_WARNING));
	printf("login-probe: setlogmask returned %d\n", old);
	check(old == LOG_UPTO(LOG_DEBUG), "the first mask lets every priority through");
	check(setlogmask(0) == LOG_UPTO(LOG_WARNING), "setlogmask(0) returns the mask and keeps it");
	syslog(LOG_INFO, "hidden %d", 1);
	syslog(LOG_ERR, "shown %d", 2);
	syslog(LOG_WARNING, "also-shown %s", "three");
	closelog();
	setlogmask(LOG_UPTO(LOG_DEBUG));
	syslog(LOG_NOTICE, "after-close %d", 4);
	closelog();
	puts("login-probe: syslog written");
}

static void put(struct utmpx *u, short type, const char *user, const char *id, const char *line, pid_t pid)
{
	memset(u, 0, sizeof(*u));
	u->ut_type = type;
	snprintf(u->ut_user, sizeof(u->ut_user), "%s", user);
	memcpy(u->ut_id, id, strnlen(id, sizeof(u->ut_id)));
	snprintf(u->ut_line, sizeof(u->ut_line), "%s", line);
	u->ut_pid = pid;
	u->ut_tv.tv_sec = 1000;
}

static int count_entries(void)
{
	int n = 0;
	setutxent();
	while (getutxent())
		n++;
	endutxent();
	return n;
}

static void probe_utmpx(void)
{
	struct utmpx u, key, *r;
	int before, after;

	/* the database of the image is read only: the writer works on a file of its own */
	check(utmpxname("/tmp/utmpx") == 0, "utmpxname");
	before = count_entries();
	printf("login-probe: entries at the start %d\n", before);
	setutxent();
	put(&u, USER_PROCESS, "alice", "a1", "ttyA", 100);
	r = pututxline(&u);
	check(r != NULL && strcmp(r->ut_user, "alice") == 0, "pututxline of alice");
	put(&u, USER_PROCESS, "bob", "b1", "ttyB", 101);
	setutxent();
	r = pututxline(&u);
	check(r != NULL && strcmp(r->ut_user, "bob") == 0, "pututxline of bob");
	put(&u, BOOT_TIME, "", "", "~", 0);
	setutxent();
	check(pututxline(&u) != NULL, "pututxline of a boot time");
	after = count_entries();
	printf("login-probe: entries now %d\n", after);
	check(after == before + 3, "three entries were appended");

	memset(&key, 0, sizeof(key));
	key.ut_type = USER_PROCESS;
	memcpy(key.ut_id, "b1", 2);
	setutxent();
	r = getutxid(&key);
	printf("login-probe: getutxid b1 -> %s\n", r ? r->ut_user : "none");
	check(r && strcmp(r->ut_user, "bob") == 0 && r->ut_pid == 101, "getutxid finds bob by id");

	memset(&key, 0, sizeof(key));
	key.ut_type = BOOT_TIME;
	setutxent();
	r = getutxid(&key);
	check(r && r->ut_type == BOOT_TIME, "getutxid finds the boot time by type");

	memset(&key, 0, sizeof(key));
	snprintf(key.ut_line, sizeof(key.ut_line), "ttyA");
	setutxent();
	r = getutxline(&key);
	printf("login-probe: getutxline ttyA -> %s\n", r ? r->ut_user : "none");
	check(r && strcmp(r->ut_user, "alice") == 0, "getutxline finds alice by line");

	snprintf(key.ut_line, sizeof(key.ut_line), "nowhere");
	setutxent();
	check(getutxline(&key) == NULL, "getutxline of a line nobody has gives NULL");

	/* alice logs out: the record with her id is overwritten, none added */
	put(&u, DEAD_PROCESS, "", "a1", "ttyA", 100);
	setutxent();
	r = pututxline(&u);
	check(r != NULL && r->ut_type == DEAD_PROCESS, "pututxline of a dead process");
	check(count_entries() == after, "the dead entry replaced alice's record");
	memset(&key, 0, sizeof(key));
	key.ut_type = USER_PROCESS;
	memcpy(key.ut_id, "a1", 2);
	setutxent();
	r = getutxid(&key);
	check(r && r->ut_type == DEAD_PROCESS, "alice's id now names a dead process");
	endutxent();
}

int login_probe_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int login_probe_main(int argc UNUSED_PARAM, char **argv)
{
	const char *what = argv[1];

	if (!what)
		bb_show_usage();
	if (!strcmp(what, "login"))
		probe_login();
	else if (!strcmp(what, "syslog"))
		probe_syslog();
	else if (!strcmp(what, "utmpx"))
		probe_utmpx();
	else
		bb_show_usage();
	printf("login-probe: %d failures\n", failures);
	return failures != 0;
}
