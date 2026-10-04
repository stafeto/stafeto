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


def page(cache, name, base=BASE):
    path = cache / name
    if path.exists():
        return path.read_text(encoding="utf-8")
    with urlopen(base + name, timeout=30) as response:
        content = response.read().decode("utf-8")
    path.write_text(content, encoding="utf-8")
    return content


def section(html, name):
    match = re.search(SECTION.pattern % name, html, SECTION.flags)
    if not match:
        raise ValueError(f"missing {name} section")
    return match.group(1)


def entries(cache, filename):
    html = page(cache, filename)
    names = Synopsis()
    names.feed(section(html, "NAME"))
    head = names.text.split("—", 1)[0].strip()
    synopsis = Synopsis()
    synopsis.feed(section(html, "SYNOPSIS"))
    headers = sorted(set(re.findall(r"#include\s*<\s*([^>]+?)\s*>", synopsis.text)))
    if not headers:
        raise ValueError(f"{filename}: no headers")
    result = []
    for name in (part.strip() for part in head.split(",")):
        if not re.fullmatch(r"[_A-Za-z][_A-Za-z0-9]*", name):
            raise ValueError(f"{filename}: invalid name {name!r}")
        positions = [match.start() for match in re.finditer(r"\b" + name + r"\b", synopsis.text)]
        if not positions:
            raise ValueError(f"{filename}: {name} absent from synopsis")
        scopes = [synopsis.options[pos] for pos in positions]
        required = any(all(code in ("CX", "OB") for code in scope) for scope in scopes)
        codes = sorted({code for scope in scopes for code in scope if code not in ("CX", "OB")})
        result.append((name, filename.removesuffix(".html"), "required" if required else "option", ",".join(headers), ",".join(codes) or "-"))
    return result


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
    index = page(args.cache, "contents.html")
    pages = sorted(set(re.findall(r'href="(?:\.\./functions/)?([A-Za-z0-9_]+\.html)', index)))
    pages = [name for name in pages if name not in ("CMPLX.html", "V2_chap01.html", "V2_chap02.html", "V2_chap03.html", "contents.html")]
    with ThreadPoolExecutor(max_workers=8) as pool:
        grouped = list(pool.map(lambda name: entries(args.cache, name), pages))
    rows = sorted((row for group in grouped for row in group), key=lambda row: row[0])
    names = [row[0] for row in rows]
    if len(names) != len(set(names)):
        raise ValueError("duplicate interface name")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as file:
        file.write("# SPDX-License-Identifier: GPL-3.0-or-later\n")
        file.write("# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>\n")
        file.write("# POSIX.1-2024 XSH, " + BASE + "contents.html\n")
        file.write("# name\tpage\trequirement\theaders\toption_codes\n")
        for row in rows:
            file.write("\t".join(row) + "\n")
    print(f"{len(pages)} pages, {len(rows)} names, {sum(row[2] == 'required' for row in rows)} required")
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
