#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Focused fixtures for normative names omitted by NAME/contents extraction."""

import importlib.util
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location(
    "inventory", Path(__file__).with_name("posix-inventory.py"))
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


def section(name, body):
    return f'<h4 class="mansect">{name}</h4><blockquote>{body}</blockquote>'


def reference(name, header, synopsis, description="fixture"):
    return (section("NAME", name + " — fixture")
            + section("SYNOPSIS", f"#include &lt;{header}&gt;<br>" + synopsis)
            + section("DESCRIPTION", description))


def xsi(body):
    return ("<a href=\"javascript:open_code('XSI')\">XSI</a>"
            '<img src="opt-start.gif">' + body + '<img src="opt-end.gif">')


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.cache = Path(self.directory.name)
        (self.cache / "basedefs").mkdir()
        self.write("pselect.html", reference("pselect, select", "sys/select.h",
                   "int pselect(int); int select(int); void FD_CLR(int, fd_set*); "
                   "int FD_ISSET(int, fd_set*); void FD_SET(int, fd_set*); void FD_ZERO(fd_set*);"))
        self.write("fork.html", reference("fork", "unistd.h", "pid_t fork(void); pid_t _Fork(void);"))
        self.write("va_arg.html", reference("va_arg, va_copy, va_end, va_start", "stdarg.h",
                   "type va_arg(va_list, type); void va_copy(va_list, va_list); "
                   "void va_end(va_list); void va_start(va_list, argN);"))
        self.write("getdate.html", reference("getdate", "time.h",
                   xsi("struct tm *getdate(const char*);"), "An external object getdate_err has type int."))
        self.write("basedefs/time.h.html", section("DESCRIPTION", xsi("declare getdate_err as int")))
        self.write("contents.html", ''.join(f'<a href="{p}.html">{p}</a>'
                   for p in ["pselect", "fork", "getdate"]))
        names = {"pselect": "pselect", "select": "pselect", "fork": "fork", "_Fork": "fork",
                 "getdate": "getdate", "getdate_err": "getdate", "asctime_r": "asctime",
                 "ctime_r": "ctime"}
        names.update({n: "pselect" for n in ["FD_CLR", "FD_ISSET", "FD_SET", "FD_ZERO"]})
        names.update({n: "va_arg" for n in ["va_arg", "va_copy", "va_end", "va_start"]})
        self.write("functions-index.html", ''.join(
            f'<a href="../functions/{p}.html"><i>{n}</i>()</a>' for n, p in names.items()))

    def write(self, name, text):
        (self.cache / name).write_text(text)

    def test_synopsis_aliases_and_missing_contents_page(self):
        rows, pages = inventory.inventory(self.cache)
        by_name = {r[0]: r for r in rows}
        self.assertEqual(pages, 4)
        for name in ["FD_CLR", "FD_ISSET", "FD_SET", "FD_ZERO", "_Fork",
                     "va_arg", "va_copy", "va_end", "va_start"]:
            self.assertEqual(by_name[name][2], "required")
        self.assertNotIn("asctime_r", by_name)
        self.assertNotIn("ctime_r", by_name)

    def test_getdate_object_uses_xbd_option(self):
        self.assertEqual(inventory.getdate_error_entry(self.cache),
                         ("getdate_err", "getdate", "option", "time.h", "XSI"))
        self.write("basedefs/time.h.html", section("DESCRIPTION", "unscoped getdate_err"))
        with self.assertRaisesRegex(ValueError, "explicit XSI"):
            inventory.getdate_error_entry(self.cache)

    def test_unresolved_index_name_fails_reconciliation(self):
        index = (self.cache / "functions-index.html").read_text()
        self.write("functions-index.html", index + '<a href="../functions/missing.html">missing()</a>')
        self.write("missing.html", (self.cache / "fork.html").read_text())
        with self.assertRaisesRegex(ValueError, "missing.*missing"):
            inventory.inventory(self.cache)


if __name__ == "__main__":
    unittest.main()
