// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

// The names, the options and the usage of the ready-made utilities that
// BusyBox lacks (tools/build-ready-utils.py): getconf, join and pathchk of
// sbase, file and iconv of toybox, compress of ncompress, csplit, gencat, m4
// and write of chimerautils, pr of nbase, pax of paxmirabilis, newgrp of
// util-linux, tput and tabs of ncurses. Their code is not
// here: each program's main, renamed ready_<name>_main, is linked from the
// archive that script builds. This file is only read by BusyBox's generators.

//config:config READY_GETCONF
//config:	bool "getconf (sbase)"
//config:	default y
//config:	help
//config:	getconf from sbase, MIT.
//config:
//config:config READY_JOIN
//config:	bool "join (sbase)"
//config:	default y
//config:	help
//config:	join from sbase, MIT.
//config:
//config:config READY_PATHCHK
//config:	bool "pathchk (sbase)"
//config:	default y
//config:	help
//config:	pathchk from sbase, MIT.
//config:
//config:config READY_FILE
//config:	bool "file (toybox)"
//config:	default y
//config:	help
//config:	file from toybox, 0BSD.
//config:
//config:config READY_ICONV
//config:	bool "iconv (toybox)"
//config:	default y
//config:	help
//config:	iconv from toybox, 0BSD.
//config:
//config:config READY_COMPRESS
//config:	bool "compress (ncompress)"
//config:	default y
//config:	help
//config:	compress from ncompress, public domain.
//config:
//config:config READY_CSPLIT
//config:	bool "csplit (chimerautils)"
//config:	default y
//config:	help
//config:	csplit from chimerautils, BSD-2-Clause.
//config:
//config:config READY_GENCAT
//config:	bool "gencat (chimerautils)"
//config:	default y
//config:	help
//config:	gencat from chimerautils, BSD-2-Clause and ISC.
//config:
//config:config READY_M4
//config:	bool "m4 (chimerautils)"
//config:	default y
//config:	help
//config:	m4 from chimerautils, BSD-3-Clause.
//config:
//config:config READY_WRITE
//config:	bool "write (chimerautils)"
//config:	default y
//config:	help
//config:	write from chimerautils, BSD-3-Clause.
//config:
//config:config READY_PR
//config:	bool "pr (nbase)"
//config:	default y
//config:	help
//config:	pr from nbase, BSD-3-Clause.
//config:
//config:config READY_PAX
//config:	bool "pax (paxmirabilis)"
//config:	default y
//config:	help
//config:	pax from paxmirabilis, BSD-3-Clause.
//config:
//config:config READY_NEWGRP
//config:	bool "newgrp (util-linux)"
//config:	default y
//config:	help
//config:	newgrp from util-linux, GPL-2.0-or-later.
//config:
//config:config READY_TPUT
//config:	bool "tput (ncurses)"
//config:	default y
//config:	help
//config:	tput from ncurses, MIT.
//config:
//config:config READY_TABS
//config:	bool "tabs (ncurses)"
//config:	default y
//config:	help
//config:	tabs from ncurses, MIT.

//applet:IF_READY_GETCONF(APPLET_ODDNAME(getconf, ready_getconf, BB_DIR_USR_BIN, BB_SUID_DROP, getconf))
//applet:IF_READY_JOIN(APPLET_ODDNAME(join, ready_join, BB_DIR_USR_BIN, BB_SUID_DROP, join))
//applet:IF_READY_PATHCHK(APPLET_ODDNAME(pathchk, ready_pathchk, BB_DIR_USR_BIN, BB_SUID_DROP, pathchk))
//applet:IF_READY_FILE(APPLET_ODDNAME(file, ready_file, BB_DIR_USR_BIN, BB_SUID_DROP, file))
//applet:IF_READY_ICONV(APPLET_ODDNAME(iconv, ready_iconv, BB_DIR_USR_BIN, BB_SUID_DROP, iconv))
//applet:IF_READY_COMPRESS(APPLET_ODDNAME(compress, ready_compress, BB_DIR_USR_BIN, BB_SUID_DROP, compress))
//applet:IF_READY_CSPLIT(APPLET_ODDNAME(csplit, ready_csplit, BB_DIR_USR_BIN, BB_SUID_DROP, csplit))
//applet:IF_READY_GENCAT(APPLET_ODDNAME(gencat, ready_gencat, BB_DIR_USR_BIN, BB_SUID_DROP, gencat))
//applet:IF_READY_M4(APPLET_ODDNAME(m4, ready_m4, BB_DIR_USR_BIN, BB_SUID_DROP, m4))
//applet:IF_READY_WRITE(APPLET_ODDNAME(write, ready_write, BB_DIR_USR_BIN, BB_SUID_DROP, write))
//applet:IF_READY_PR(APPLET_ODDNAME(pr, ready_pr, BB_DIR_USR_BIN, BB_SUID_DROP, pr))
//applet:IF_READY_PAX(APPLET_ODDNAME(pax, ready_pax, BB_DIR_USR_BIN, BB_SUID_DROP, pax))
//applet:IF_READY_NEWGRP(APPLET_ODDNAME(newgrp, ready_newgrp, BB_DIR_USR_BIN, BB_SUID_DROP, newgrp))
//applet:IF_READY_TPUT(APPLET_ODDNAME(tput, ready_tput, BB_DIR_USR_BIN, BB_SUID_DROP, tput))
//applet:IF_READY_TABS(APPLET_ODDNAME(tabs, ready_tabs, BB_DIR_USR_BIN, BB_SUID_DROP, tabs))

//usage:#define getconf_trivial_usage
//usage:       "[-v specification] name [path]"
//usage:#define getconf_full_usage "\n\n"
//usage:       "Print the value of a configuration variable (sbase)"
//usage:
//usage:#define join_trivial_usage
//usage:       "[-1 field] [-2 field] [-a 1|2] [-e string] [-o list] [-t delim] [-v 1|2] file1 file2"
//usage:#define join_full_usage "\n\n"
//usage:       "Join the lines of two sorted files on a common field (sbase)"
//usage:
//usage:#define pathchk_trivial_usage
//usage:       "[-pP] pathname..."
//usage:#define pathchk_full_usage "\n\n"
//usage:       "Check that pathnames are valid and portable (sbase)"
//usage:
//usage:#define file_trivial_usage
//usage:       "[-bhLs] file..."
//usage:#define file_full_usage "\n\n"
//usage:       "Tell the type of files (toybox)"
//usage:
//usage:#define iconv_trivial_usage
//usage:       "[-cs] [-f from] [-t to] [file...]"
//usage:#define iconv_full_usage "\n\n"
//usage:       "Convert the character encoding of files (toybox)"
//usage:
//usage:#define compress_trivial_usage
//usage:       "[-cdfrv] [-b bits] [file...]"
//usage:#define compress_full_usage "\n\n"
//usage:       "Compress files with LZW into .Z files (ncompress)"
//usage:
//usage:#define csplit_trivial_usage
//usage:       "[-ks] [-f prefix] [-n number] file arg1 ... argn"
//usage:#define csplit_full_usage "\n\n"
//usage:       "Split a file into pieces at the lines its arguments name (chimerautils)"
//usage:
//usage:#define gencat_trivial_usage
//usage:       "catfile msgfile ..."
//usage:#define gencat_full_usage "\n\n"
//usage:       "Compile message catalogs from message text sources (chimerautils)"
//usage:
//usage:#define m4_trivial_usage
//usage:       "[-d flags] [-t name] [-D name[=value]] [-U name] [-I dir] [file ...]"
//usage:#define m4_full_usage "\n\n"
//usage:       "Expand the macros of the files (chimerautils)"
//usage:
//usage:#define write_trivial_usage
//usage:       "user [terminal]"
//usage:#define write_full_usage "\n\n"
//usage:       "Send messages to the terminal of a user (chimerautils)"
//usage:
//usage:#define pr_trivial_usage
//usage:       "[+page] [-column] [-adFmrt] [-e[char][gap]] [-h header] [-i[char][gap]] [-l lines] [-n[char][width]] [-o offset] [-s[char]] [-w width] [-fp] [file ...]"
//usage:#define pr_full_usage "\n\n"
//usage:       "Print files in pages and columns (nbase)"
//usage:
//usage:#define pax_trivial_usage
//usage:       "[-cdnvz] [-f archive] [-s replstr] ... [pattern ...]"
//usage:#define pax_full_usage "\n\n"
//usage:       "Read, write and list archives (paxmirabilis)"
//usage:
//usage:#define newgrp_trivial_usage
//usage:       "[-c command] [group]"
//usage:#define newgrp_full_usage "\n\n"
//usage:       "Change the group of the login and start a shell (util-linux)"
//usage:
//usage:#define tput_trivial_usage
//usage:       "[-T type] capname [parameter ...]"
//usage:#define tput_full_usage "\n\n"
//usage:       "Print the value of a terminfo capability (ncurses)"
//usage:
//usage:#define tabs_trivial_usage
//usage:       "[-T type] [-n | -a | -c | ...]"
//usage:#define tabs_full_usage "\n\n"
//usage:       "Set the tab stops of the terminal (ncurses)"
