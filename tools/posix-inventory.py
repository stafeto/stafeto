#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

"""Extract interfaces and headers from official POSIX.1-2024 pages.

The checked-in TSV records names and references only. Pass --cache to keep
downloaded pages outside the repository when auditing an extraction change.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from pathlib import Path
import re
from urllib.parse import unquote
from urllib.request import urlopen


BASE = "https://pubs.opengroup.org/onlinepubs/9799919799/functions/"
XBD_BASE = "https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/"
INDEX_BASE = "https://pubs.opengroup.org/onlinepubs/9799919799/idx/"
# Issue 8, Austin Group Defect 1410 removes these functions. The alphabetical
# index retains their historical URLs, so they are not normative interfaces.
REMOVED = {"asctime_r", "ctime_r"}
SECTION = re.compile(
    r'<h4 class="mansect"[^>]*>.*?\b%s</h4>\s*<blockquote[^>]*>(.*?)</blockquote>',
    re.S | re.I,
)


class Synopsis(HTMLParser):
    def __init__(self):
        super().__init__()
        self.characters = []
        self.options = []
        self.stack = []
        self.next_option = ""

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a":
            match = re.search(r"open_code\('([^']+)'\)", attrs.get("href", ""))
            if match:
                self.next_option = unquote(match.group(1))
        elif tag == "img":
            src = attrs.get("src", "")
            if src.endswith("opt-start.gif"):
                self.stack.append(self.next_option)
                self.next_option = ""
            elif src.endswith("opt-end.gif"):
                if not self.stack:
                    raise ValueError("unmatched option end")
                self.stack.pop()
        elif tag == "br":
            self.handle_data("\n")

    def handle_data(self, data):
        for char in data:
            self.characters.append(char)
            self.options.append(tuple(self.stack))

    @property
    def text(self):
        return "".join(self.characters)


def page(cache, name, base=BASE, remote_name=None):
    path = cache / name
    if path.exists():
        return path.read_text(encoding="utf-8")
    with urlopen(base + (remote_name or name), timeout=30) as response:
        content = response.read().decode("utf-8")
    path.write_text(content, encoding="utf-8")
    return content


def section(html, name):
    match = re.search(SECTION.pattern % name, html, SECTION.flags)
    if not match:
        raise ValueError(f"missing {name} section")
    return match.group(1)


def alphabetical_interfaces(html):
    result = {}
    for filename, body in re.findall(
        r'<a\b[^>]*href="(?:\.\./functions/)?([_A-Za-z0-9]+\.html)"[^>]*>(.*?)</a>',
        html, re.S | re.I,
    ):
        text = Synopsis()
        text.feed(body)
        name = re.sub(r"\(\)$", "", text.text.strip())
        if not re.fullmatch(r"[_A-Za-z][_A-Za-z0-9]*", name):
            raise ValueError(f"invalid alphabetical interface {name!r}")
        if name in result and result[name] != filename:
            raise ValueError(f"conflicting alphabetical URLs for {name}")
        result[name] = filename
    if not result:
        raise ValueError("empty alphabetical interface index")
    return result


def classification(scopes):
    required = any(all(code in ("CX", "OB") for code in scope) for scope in scopes)
    codes = sorted({code for scope in scopes for code in scope if code not in ("CX", "OB")})
    return "required" if required else "option", ",".join(codes) or "-"


def entries(cache, filename, indexed_names=()):
    html = page(cache, filename)
    names = Synopsis()
    names.feed(section(html, "NAME"))
    head = names.text.split("—", 1)[0].strip()
    synopsis = Synopsis()
    synopsis.feed(section(html, "SYNOPSIS"))
    headers = sorted(set(re.findall(r"#include\s*<\s*([^>]+?)\s*>", synopsis.text)))
    if not headers:
        raise ValueError(f"{filename}: no headers")
    declared = {part.strip() for part in head.split(",")}
    # NAME can omit aliases and function-like macros that SYNOPSIS requires.
    # Limit candidates to names independently listed by the official index.
    declared.update(set(re.findall(r"\b([_A-Za-z][_A-Za-z0-9]*)\s*\(", synopsis.text))
                    & set(indexed_names))
    result = []
    for name in sorted(declared):
        if not re.fullmatch(r"[_A-Za-z][_A-Za-z0-9]*", name):
            raise ValueError(f"{filename}: invalid name {name!r}")
        positions = [match.start() for match in re.finditer(r"\b" + name + r"\b", synopsis.text)]
        if not positions:
            raise ValueError(f"{filename}: {name} absent from synopsis")
        scopes = [synopsis.options[pos] for pos in positions]
        requirement, codes = classification(scopes)
        result.append((name, filename.removesuffix(".html"), requirement, ",".join(headers), codes))
    return result


def getdate_error_entry(cache):
    # XSH DESCRIPTION defines this object without an option marker. XBD time.h
    # explicitly encloses its declaration in XSI, which supplies its status.
    description = Synopsis()
    description.feed(section(page(cache, "getdate.html"), "DESCRIPTION"))
    if not re.search(r"\bgetdate_err\b", description.text):
        raise ValueError("getdate DESCRIPTION no longer defines getdate_err")
    xbd = cache / "basedefs"
    xbd.mkdir(exist_ok=True)
    declaration = Synopsis()
    declaration.feed(section(page(xbd, "time.h.html", XBD_BASE), "DESCRIPTION"))
    scopes = [declaration.options[m.start()]
              for m in re.finditer(r"\bgetdate_err\b", declaration.text)]
    if not scopes or any(scope != ("XSI",) for scope in scopes):
        raise ValueError("time.h getdate_err needs explicit XSI declaration")
    return ("getdate_err", "getdate", "option", "time.h", "XSI")


def inventory(cache):
    index = page(cache, "contents.html")
    pages = sorted(set(re.findall(r'href="(?:\.\./functions/)?([A-Za-z0-9_]+\.html)', index)))
    pages = [name for name in pages if name not in ("V2_chap01.html", "V2_chap02.html", "V2_chap03.html", "contents.html")]
    alphabetical = alphabetical_interfaces(
        page(cache, "functions-index.html", INDEX_BASE, "functions.html"))
    with ThreadPoolExecutor(max_workers=8) as pool:
        grouped = list(pool.map(lambda name: entries(cache, name, alphabetical), pages))
    by_name = {}
    for group in grouped:
        for row in group:
            if row[0] in by_name:
                raise ValueError(f"duplicate interface name {row[0]}")
            by_name[row[0]] = row
    by_name["getdate_err"] = getdate_error_entry(cache)
    # Pages absent from contents (currently va_arg) are discovered by the
    # alphabetical index. Once their NAME aliases are loaded, skip those URLs.
    for name, filename in sorted(alphabetical.items()):
        if name in by_name or name in REMOVED:
            continue
        for row in entries(cache, filename, alphabetical):
            if row[0] in by_name:
                if by_name[row[0]][2:] != row[2:]:
                    raise ValueError(f"conflicting interface alias {row[0]}")
            else:
                by_name[row[0]] = row
    expected = set(alphabetical) - REMOVED
    if set(by_name) != expected:
        raise ValueError(f"index mismatch: missing {sorted(expected - set(by_name))}, "
                         f"unexpected {sorted(set(by_name) - expected)}")
    rows = sorted(by_name.values())
    return rows, len({row[1] for row in rows})


def header_entry(cache, filename):
    html = page(cache, filename, XBD_BASE)
    synopsis = Synopsis()
    synopsis.feed(section(html, "SYNOPSIS"))
    match = re.search(r"#include\s*<([^>]+)>", synopsis.text)
    if not match:
        raise ValueError(f"{filename}: no include in synopsis")
    scope = synopsis.options[match.start()]
    required = all(code in ("CX", "OB") for code in scope)
    codes = sorted(code for code in scope if code not in ("CX", "OB"))
    return (match.group(1), filename.removesuffix(".html"),
            "required" if required else "option", ",".join(codes) or "-")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--xbd-output", type=Path)
    args = parser.parse_args()
    args.cache.mkdir(parents=True, exist_ok=True)
    rows, page_count = inventory(args.cache)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as file:
        file.write("# SPDX-License-Identifier: GPL-3.0-or-later\n")
        file.write("# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>\n")
        file.write("# POSIX.1-2024 XSH, " + BASE + "contents.html\n")
        file.write("# name\tpage\trequirement\theaders\toption_codes\n")
        for row in rows:
            file.write("\t".join(row) + "\n")
    print(f"{page_count} pages, {len(rows)} names, {sum(row[2] == 'required' for row in rows)} required")
    if args.xbd_output:
        xbd_cache = args.cache / "basedefs"
        xbd_cache.mkdir(exist_ok=True)
        xbd_index = page(xbd_cache, "contents.html", XBD_BASE)
        xbd_pages = sorted(set(re.findall(r'href="(?:\.\./basedefs/)?([A-Za-z0-9_]+\.h\.html)', xbd_index)))
        with ThreadPoolExecutor(max_workers=8) as pool:
            headers = sorted(pool.map(lambda name: header_entry(xbd_cache, name), xbd_pages))
        if len(headers) != 86 or sum(row[2] == "required" for row in headers) != 70:
            raise ValueError("XBD header count changed; audit the source and extraction")
        args.xbd_output.parent.mkdir(parents=True, exist_ok=True)
        with args.xbd_output.open("w", encoding="utf-8") as file:
            file.write("# SPDX-License-Identifier: GPL-3.0-or-later\n")
            file.write("# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>\n")
            file.write("# POSIX.1-2024 XBD, " + XBD_BASE + "contents.html\n")
            file.write("# header\tpage\trequirement\toption_codes\n")
            for row in headers:
                file.write("\t".join(row) + "\n")
        print(f"{len(headers)} XBD headers, {sum(row[2] == 'required' for row in headers)} required")


if __name__ == "__main__":
    main()
