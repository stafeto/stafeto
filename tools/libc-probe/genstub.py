# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>
"""Turn a relibc Linux platform file into ENOSYS stubs (bodies replaced)."""
import re, sys

FORWARD = {}  # name -> body, filled in by caller via a file

def stub_for(ret):
    ret = ret.strip()
    if ret == "!":
        return "unsafe { stafeto_exit(127) }"
    if ret.startswith("Result"):
        return "Err(Errno(ENOSYS))"
    if ret == "Errno":
        return "Errno(ENOSYS)"
    if ret.startswith("Option"):
        return "None"
    if ret == "bool":
        return "true"
    if ret in ("pid_t", "uid_t", "gid_t", "mode_t", "crate::pthread::OsTid"):
        return {"pid_t": "0", "uid_t": "0", "gid_t": "0", "mode_t": "0o022",
                "crate::pthread::OsTid": "crate::pthread::OsTid::default()"}[ret]
    if ret == "usize":
        return "4096"
    raise SystemExit(f"unknown return type {ret!r}")

def process(text, overrides):
    out = []
    i = 0
    pat = re.compile(r"^    ((?:pub )?(?:unsafe )?fn (\w+)[^{]*?)\{", re.M | re.S)
    in_impl = False
    pos = 0
    for m in pat.finditer(text):
        if m.start() < pos:
            continue
        sig, name = m.group(1), m.group(2)
        # find matching brace
        depth, j = 0, m.end() - 1
        while True:
            c = text[j]
            if c == "{": depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0: break
            j += 1
        out.append(text[pos:m.start()])
        retm = re.search(r"->\s*(.*?)\s*$", sig.strip(), re.S)
        ret = retm.group(1) if retm else "()"
        body = overrides.get(name)
        if body is None:
            body = "()" if ret == "()" else stub_for(ret)
        sig_clean = re.sub(r"\bmut (\w+):", r"\1:", sig)
        out.append(f"    {sig_clean.rstrip()} {{\n        {body}\n    }}")
        pos = j + 1
    out.append(text[pos:])
    return "".join(out)

if __name__ == "__main__":
    src, dst = sys.argv[1], sys.argv[2]
    overrides = {}
    if len(sys.argv) > 3:
        cur = None
        for line in open(sys.argv[3]):
            if line.startswith("@@ "):
                cur = line[3:].strip(); overrides[cur] = ""
            elif cur:
                overrides[cur] += line
        overrides = {k: v.strip() for k, v in overrides.items()}
    open(dst, "w").write(process(open(src).read(), overrides))
