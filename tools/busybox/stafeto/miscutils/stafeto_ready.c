// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

// The names, the options and the usage of the ready-made utilities that
// BusyBox lacks (tools/build-ready-utils.py): getconf, join and pathchk of
// sbase, file and iconv of toybox, compress of ncompress. Their code is not
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

//applet:IF_READY_GETCONF(APPLET_ODDNAME(getconf, ready_getconf, BB_DIR_USR_BIN, BB_SUID_DROP, getconf))
//applet:IF_READY_JOIN(APPLET_ODDNAME(join, ready_join, BB_DIR_USR_BIN, BB_SUID_DROP, join))
//applet:IF_READY_PATHCHK(APPLET_ODDNAME(pathchk, ready_pathchk, BB_DIR_USR_BIN, BB_SUID_DROP, pathchk))
//applet:IF_READY_FILE(APPLET_ODDNAME(file, ready_file, BB_DIR_USR_BIN, BB_SUID_DROP, file))
//applet:IF_READY_ICONV(APPLET_ODDNAME(iconv, ready_iconv, BB_DIR_USR_BIN, BB_SUID_DROP, iconv))
//applet:IF_READY_COMPRESS(APPLET_ODDNAME(compress, ready_compress, BB_DIR_USR_BIN, BB_SUID_DROP, compress))

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
