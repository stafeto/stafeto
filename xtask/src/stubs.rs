// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The public functions of relibc that exist but answer ENOSYS on stafeto,
//! found in relibc's sources (`cargo xtask coverage`).
//!
//! A method of the stafeto platform (`src/platform/stafeto`) is a stub when
//! its whole body is `Err(Errno(ENOSYS))`. A method the platform leaves to
//! the trait's default (`src/platform/pal`) is a stub when that default
//! only calls stub methods (`access` calls `faccessat`). A public function
//! (`src/header`) is a stub when every call it makes is a stub: a stub
//! method through `Sys::` (`remove` calls `unlink` and `rmdir`) or a
//! function of relibc that is a stub (`alarm` calls `alarm_timespec`, which
//! calls `timer_create`); opening and closing a descriptor do not count
//! (`statvfs`). A call of a function that is not a stub, or that the sources do not define, keeps the
//! function out (`posix_spawnp` calls `posix_spawn`).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The sources of a relibc checkout the table is read from.
pub(crate) struct Sources {
    /// `src/platform/stafeto`: the platform's own methods.
    pub platform: Vec<String>,
    /// `src/platform/pal`: the traits with their default methods.
    pub pal: Vec<String>,
    /// `src/header`: the public functions.
    pub header: Vec<String>,
}

/// Every `.rs` file under `dir`, in a stable order.
fn rust_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        for entry in entries {
            let path = entry.map_err(|e| e.to_string())?.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}

fn read_all(dir: &Path) -> Result<Vec<String>, String> {
    rust_files(dir)?
        .iter()
        .map(|path| std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display())))
        .collect()
}

impl Sources {
    /// The sources of the checkout at `root` (relibc's `src`).
    pub fn read(root: &Path) -> Result<Sources, String> {
        let src = root.join("src");
        Ok(Sources {
            platform: read_all(&src.join("platform/stafeto"))?,
            pal: read_all(&src.join("platform/pal"))?,
            header: read_all(&src.join("header"))?,
        })
    }
}

/// `source` without `//` comments (also doc comments).
fn without_comments(source: &str) -> String {
    source
        .lines()
        .map(|line| line.find("//").map_or(line, |at| &line[..at]))
        .collect::<Vec<_>>()
        .join("\n")
}

fn is_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// The functions of `source` (comments already removed) with a body: name
/// and the text between the braces of the body.
fn functions(source: &str) -> Vec<(String, String)> {
    let bytes = source.as_bytes();
    let mut found = Vec::new();
    let mut at = 0;
    while let Some(offset) = source[at..].find("fn ") {
        let start = at + offset;
        at = start + 3;
        if start > 0 && is_word(bytes[start - 1]) {
            continue;
        }
        let name: String = source[at..]
            .chars()
            .take_while(|c| is_word(*c as u8) && c.is_ascii())
            .collect();
        if name.is_empty() {
            continue;
        }
        // The signature ends at a `{` (a body) or a `;` (none) outside
        // the parentheses and brackets.
        let mut depth = 0i32;
        let mut open = None;
        for (i, byte) in bytes[at + name.len()..].iter().enumerate() {
            match byte {
                b'(' | b'[' => depth += 1,
                b')' | b']' => depth -= 1,
                b';' if depth == 0 => break,
                b'{' if depth == 0 => {
                    open = Some(at + name.len() + i);
                    break;
                }
                _ => {}
            }
        }
        let Some(open) = open else { continue };
        let mut braces = 0i32;
        let mut close = None;
        for (i, byte) in bytes[open..].iter().enumerate() {
            match byte {
                b'{' => braces += 1,
                b'}' => {
                    braces -= 1;
                    if braces == 0 {
                        close = Some(open + i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(close) = close else { continue };
        found.push((name, source[open + 1..close].to_owned()));
    }
    found
}

/// Whether `body` only answers ENOSYS.
fn answers_enosys(body: &str) -> bool {
    let squeezed: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    let squeezed = squeezed.strip_prefix("return").unwrap_or(&squeezed);
    let squeezed = squeezed.strip_suffix(';').unwrap_or(squeezed);
    matches!(
        squeezed,
        "Err(Errno(ENOSYS))" | "Err(Errno(crate::header::errno::ENOSYS))"
    )
}

/// The names `prefix::name(` calls in `body`.
fn calls<'a>(body: &'a str, prefix: &str) -> BTreeSet<&'a str> {
    let mut names = BTreeSet::new();
    let mut at = 0;
    while let Some(offset) = body[at..].find(prefix) {
        let start = at + offset;
        at = start + prefix.len();
        if start > 0 && is_word(body.as_bytes()[start - 1]) {
            continue;
        }
        let name = body[at..]
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .next()
            .unwrap_or("");
        if !name.is_empty() && body[at + name.len()..].trim_start().starts_with('(') {
            names.insert(name);
        }
    }
    names
}

/// `text` with the contents of its string literals removed.
fn without_strings(text: &str) -> String {
    let mut out = String::new();
    let mut inside = false;
    let mut escaped = false;
    for c in text.chars() {
        if inside {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                inside = false;
                out.push('"');
            }
        } else {
            if c == '"' {
                inside = true;
            }
            out.push(c);
        }
    }
    out
}

/// The plain functions `body` calls (`name(` in snake case, not a method,
/// a path, a macro or a variant such as `Err(`).
fn plain_calls(body: &str) -> BTreeSet<String> {
    let body = &without_strings(body);
    let mut names = BTreeSet::new();
    for (i, byte) in body.bytes().enumerate() {
        if byte != b'(' {
            continue;
        }
        let end = body[..i].trim_end().len();
        let name = body[..end]
            .rsplit(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .next()
            .unwrap_or("");
        let before = body[..end - name.len()].trim_end();
        if !name.is_empty()
            && !before.ends_with('.')
            && !before.ends_with("::")
            && !before.ends_with('!')
            && name.starts_with(|c: char| c.is_ascii_lowercase() || c == '_')
            && !matches!(
                name,
                "unsafe" | "if" | "match" | "while" | "return" | "let" | "in" | "for" | "else"
            )
        {
            names.insert(name.to_owned());
        }
    }
    names
}

/// The platform methods that answer ENOSYS: their own stubs, and the
/// defaults of the traits that only call stubs.
fn stub_methods(sources: &Sources) -> BTreeSet<String> {
    let mut own = BTreeSet::new();
    let mut stubs = BTreeSet::new();
    for source in &sources.platform {
        for (name, body) in functions(&without_comments(source)) {
            if answers_enosys(&body) {
                stubs.insert(name.clone());
            }
            own.insert(name);
        }
    }
    let defaults: BTreeMap<String, String> = sources
        .pal
        .iter()
        .flat_map(|source| functions(&without_comments(source)))
        .filter(|(name, _)| !own.contains(name))
        .collect();
    loop {
        let before = stubs.len();
        for (name, body) in &defaults {
            let callees = calls(body, "Self::");
            if !callees.is_empty() && callees.iter().all(|callee| stubs.contains(*callee)) {
                stubs.insert(name.clone());
            }
        }
        if stubs.len() == before {
            return stubs;
        }
    }
}

/// The calls that do not decide whether a function works: opening and
/// closing a descriptor (`statvfs` opens the path, asks `fstatvfs`, closes)
/// and dropping a lock guard.
const NEUTRAL: [&str; 4] = ["open", "openat", "close", "drop"];

/// Stubs the reading above does not see, each confirmed by hand in relibc's
/// sources: `mkdtemp` reaches `Sys::mkdir` through a closure it passes to
/// `inner_mktemp`, and `realpath` asks `Sys::fpath` after a
/// `File::open`. Each name must
/// be in the XSH inventory (a test of `coverage`).
pub(crate) const CONFIRMED: [&str; 2] = ["mkdtemp", "realpath"];

/// The public functions of relibc that answer ENOSYS on stafeto, and the
/// functions behind them: a function is a stub when it calls at least one
/// platform method or function of relibc that is a stub, and every call it
/// makes (`Sys::name(` or `name(` of a function of `src/header`) is a stub
/// or neutral. A call of a function that is not a stub, or that the sources do not define, keeps the
/// function out. The set is closed by repeating until it stops growing.
pub(crate) fn stub_functions(sources: &Sources) -> BTreeSet<String> {
    let methods = stub_methods(sources);
    let mut found: BTreeSet<String> = CONFIRMED.iter().map(|name| (*name).to_owned()).collect();
    let mut bodies: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for source in &sources.header {
        for (name, body) in functions(&without_comments(source)) {
            bodies.entry(name).or_default().push(body);
        }
    }
    loop {
        let before = found.len();
        for (name, versions) in &bodies {
            // Every definition of the name must be a stub (the same name in
            // two headers, as with a wrapper and its own caller).
            let stub = versions.iter().all(|body| {
                let methods_called = calls(body, "Sys::");
                let plain = plain_calls(body);
                let mut deciding = 0;
                let mut all_stubs = true;
                for callee in &methods_called {
                    if NEUTRAL.contains(callee) {
                        continue;
                    }
                    deciding += 1;
                    all_stubs &= methods.contains(*callee);
                }
                for callee in &plain {
                    if NEUTRAL.contains(&callee.as_str()) {
                        continue;
                    }
                    deciding += 1;
                    all_stubs &= found.contains(callee) && callee != name;
                }
                deciding > 0 && all_stubs
            });
            if stub {
                found.insert(name.clone());
            }
        }
        if found.len() == before {
            return found;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sources(platform: &str, pal: &str, header: &str) -> Sources {
        Sources {
            platform: vec![platform.to_owned()],
            pal: vec![pal.to_owned()],
            header: vec![header.to_owned()],
        }
    }

    const PLATFORM: &str = "
impl Pal for Sys {
    fn faccessat(fd: c_int, path: CStr) -> Result<()> {
        // not yet
        Err(Errno(ENOSYS))
    }
    fn chdir(path: CStr) -> Result<()> {
        ret(unsafe { stafeto_chdir(path.as_ptr()) }).map(|_| ())
    }
    fn unlinkat(fd: c_int, path: CStr, flags: c_int) -> Result<()> {
        Err(Errno(ENOSYS))
    }
    fn rename(path: CStr) -> Result<()> {
        ret(unsafe { stafeto_rename(path.as_ptr()) }).map(|_| ())
    }
    fn mmap(len: usize) -> Result<()> {
        if len == 0 {
            return Err(Errno(ENOSYS));
        }
        Ok(())
    }
}";

    const PAL: &str = "
pub trait Pal {
    fn access(path: CStr, mode: c_int) -> Result<()> {
        Self::faccessat(AT_FDCWD, path, mode, 0)
    }
    fn faccessat(fd: c_int, path: CStr, amode: c_int, flags: c_int) -> Result<()>;
    fn unlink(path: CStr) -> Result<()> {
        Self::unlinkat(AT_FDCWD, path, 0)
    }
    fn rmdir(path: CStr) -> Result<()> {
        Self::unlinkat(AT_FDCWD, path, AT_REMOVEDIR)
    }
    fn chdir(path: CStr) -> Result<()>;
    fn rename(path: CStr) -> Result<()> {
        Self::unlinkat(AT_FDCWD, path, 0)
    }
    fn getcwd() -> Result<()> {
        Self::chdir(path)
    }
}";

    const HEADER: &str = "
#[unsafe(no_mangle)]
pub unsafe extern \"C\" fn access(path: *const c_char, mode: c_int) -> c_int {
    Sys::access(path, mode).map(|()| 0).or_minus_one_errno()
}
#[unsafe(no_mangle)]
pub unsafe extern \"C\" fn remove(path: *const c_char) -> c_int {
    Sys::unlink(path).or_else(|_err| Sys::rmdir(path)).map(|()| 0).or_minus_one_errno()
}
#[unsafe(no_mangle)]
pub unsafe extern \"C\" fn chdir(path: *const c_char) -> c_int {
    Sys::chdir(path).map(|()| 0).or_minus_one_errno()
}
#[unsafe(no_mangle)]
pub unsafe extern \"C\" fn mkdtemp(path: *mut c_char) -> *mut c_char {
    Sys::open(path, 0);
    Sys::unlink(path);
    path
}
#[unsafe(no_mangle)]
pub unsafe extern \"C\" fn spawnp(path: *const c_char) -> c_int {
    if Sys::access(path, 0).is_err() {
        return 2;
    }
    spawn(path)
}
fn alarm_timespec(seconds: u32) -> u32 {
    Sys::faccessat(0, seconds, 0, 0);
    Sys::unlinkat(0, seconds, 0);
    0
}
#[unsafe(no_mangle)]
pub unsafe extern \"C\" fn alarm(seconds: u32) -> u32 {
    alarm_timespec(seconds)
}
#[unsafe(no_mangle)]
pub unsafe extern \"C\" fn statvfs(path: *const c_char) -> c_int {
    let fd = Sys::open(path, 0);
    let result = Sys::faccessat(fd, path, 0, 0);
    Sys::close(fd);
    result
}
#[unsafe(no_mangle)]
pub unsafe extern \"C\" fn getcwd_twice(path: *const c_char) -> c_int {
    Sys::open(path, 0);
    Sys::chdir(path);
    Sys::close(0);
    0
}
#[unsafe(no_mangle)]
pub unsafe extern \"C\" fn mmap(len: usize) -> c_int {
    Sys::mmap(len).map(|()| 0).or_minus_one_errno()
}";

    /// A method whose whole body is ENOSYS is a stub; one that answers
    /// ENOSYS for some arguments only (`mmap`) is not.
    #[test]
    fn a_platform_method_that_only_answers_enosys_is_a_stub() {
        let stubs = stub_methods(&sources(PLATFORM, PAL, HEADER));
        assert!(stubs.contains("faccessat"));
        assert!(stubs.contains("unlinkat"));
        assert!(!stubs.contains("chdir"));
        assert!(!stubs.contains("mmap"));
    }

    /// A default that only calls stubs is a stub; one that calls a working
    /// method is not.
    #[test]
    fn a_default_method_over_stubs_is_a_stub() {
        let stubs = stub_methods(&sources(PLATFORM, PAL, HEADER));
        for name in ["access", "unlink", "rmdir"] {
            assert!(stubs.contains(name), "{name}");
        }
        assert!(!stubs.contains("getcwd"));
        // The platform's own working method wins over a default of stubs.
        assert!(!stubs.contains("rename"));
    }

    /// A public function is a stub when every call it makes is a stub:
    /// through `Sys::` (`remove`, `mkdtemp`), through a function of relibc
    /// that is one (`alarm` over `alarm_timespec`), with opening and closing
    /// a descriptor not counting (`statvfs`). One that also calls a working
    /// method (`getcwd_twice`), a function the sources do not define
    /// (`spawnp`) or none (`chdir` is working) is not.
    #[test]
    fn a_public_function_over_stubs_is_a_stub() {
        let found = stub_functions(&sources(PLATFORM, PAL, HEADER));
        let names: Vec<_> = found.iter().map(String::as_str).collect();
        assert_eq!(
            names,
            [
                "access",
                "alarm",
                "alarm_timespec",
                "mkdtemp",
                "realpath", // confirmed by hand, not in the test sources
                "remove",
                "statvfs"
            ]
        );
    }

    /// Strings, macros, constructors and methods are not plain calls.
    #[test]
    fn only_plain_functions_count_as_calls() {
        let names = |body| plain_calls(body).into_iter().collect::<Vec<_>>();
        assert_eq!(names("spawn(path)"), ["spawn"]);
        assert_eq!(names("let x = helper(1); other(x)"), ["helper", "other"]);
        assert!(names("trace_expr!(Sys::socket(d), \"socket({})\", d)").is_empty());
        assert!(names("let (Some(a), None) = (b.get(), Out::new(c))").is_empty());
        assert!(names("Err(Errno(EINVAL)).or_minus_one_errno()").is_empty());
        assert!(names("if x { 1 } else { 2 }").is_empty());
    }

    #[test]
    fn comments_and_bodiless_signatures_are_skipped() {
        let source = without_comments("fn a() -> u8; // fn b() {}\nfn c() { 1 }");
        let found = functions(&source);
        assert_eq!(found, [("c".to_owned(), " 1 ".to_owned())]);
        assert!(answers_enosys(" return Err(Errno(ENOSYS)); "));
        assert!(!answers_enosys("Err(Errno(EINVAL))"));
    }
}
