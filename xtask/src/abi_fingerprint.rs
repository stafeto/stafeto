// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask abi`: the fingerprint of the ABI that packages build against
//! (docs/packages.md), in `packages/abi.txt`:
//!
//! ```text
//! format 1
//! series 0.3
//! state open
//! libc <64 hex>
//! layouts <64 hex>
//! loader <64 hex>
//! protocols <64 hex>
//! ```
//!
//! Each part is the SHA-256 of sorted lines, which `abi --explain` writes to
//! `target/abi/<part>.txt`. A series that is `open` has not been published,
//! so a change is printed and passes; a `frozen` series fails the check when
//! anything changed.

use pkgfmt::sha;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const PARTS: [&str; 4] = ["libc", "layouts", "loader", "protocols"];
const ROW: usize = 56;
const NAME: usize = 48;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    Open,
    Frozen,
}

impl State {
    fn word(self) -> &'static str {
        match self {
            State::Open => "open",
            State::Frozen => "frozen",
        }
    }
}

/// The lines of the four parts.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Parts(pub [Vec<String>; 4]);

impl Parts {
    pub fn digests(&self) -> [String; 4] {
        std::array::from_fn(|i| digest(&self.0[i]))
    }
}

/// SHA-256 of the lines, each ended by a newline, in hex.
pub fn digest(lines: &[String]) -> String {
    let mut text = lines.join("\n");
    text.push('\n');
    let mut buf = [0u8; 64];
    sha::hex(&sha::sha256(text.as_bytes()), &mut buf).to_string()
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct File {
    pub series: String,
    pub state: State,
    pub digests: [String; 4],
}

impl File {
    pub fn render(&self) -> String {
        let mut out = format!(
            "format 1\nseries {}\nstate {}\n",
            self.series,
            self.state.word()
        );
        for (name, d) in PARTS.iter().zip(&self.digests) {
            out.push_str(&format!("{name} {d}\n"));
        }
        out
    }

    pub fn parse(text: &str) -> Result<File, String> {
        let bad = |n: usize, what: &str| format!("abi.txt line {n}: {what}");
        let mut lines = text.lines();
        let mut next = |n: usize, key: &str| -> Result<String, String> {
            let line = lines.next().ok_or_else(|| bad(n, "the file ends"))?;
            line.strip_prefix(key)
                .and_then(|r| r.strip_prefix(' '))
                .map(str::to_string)
                .ok_or_else(|| bad(n, &format!("expected `{key} ...`")))
        };
        if next(1, "format")? != "1" {
            return Err(bad(1, "format 1 only"));
        }
        let series = next(2, "series")?;
        series_pair(&series).ok_or_else(|| bad(2, "the series is N.N"))?;
        let state = match next(3, "state")?.as_str() {
            "open" => State::Open,
            "frozen" => State::Frozen,
            _ => return Err(bad(3, "the state is open or frozen")),
        };
        let mut digests: [String; 4] = Default::default();
        for (i, name) in PARTS.iter().enumerate() {
            let d = next(4 + i, name)?;
            if d.len() != 64 || !d.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
                return Err(bad(4 + i, "a SHA-256 in lower case hex"));
            }
            digests[i] = d;
        }
        if lines.next().is_some() {
            return Err(bad(8, "nothing follows the four parts"));
        }
        Ok(File {
            series,
            state,
            digests,
        })
    }
}

fn series_pair(s: &str) -> Option<(u32, u32)> {
    let (a, b) = s.split_once('.')?;
    Some((a.parse().ok()?, b.parse().ok()?))
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Check,
    Update,
    Freeze,
}

/// What a run does: the file to write if any, and the lines to print.
#[derive(Debug, PartialEq, Eq)]
pub struct Outcome {
    pub write: Option<File>,
    pub notes: Vec<String>,
}

fn changed(old: &File, now: &[String; 4]) -> Vec<&'static str> {
    PARTS
        .iter()
        .zip(old.digests.iter().zip(now))
        .filter(|(_, (a, b))| a != b)
        .map(|(n, _)| *n)
        .collect()
}

/// The next minor series as a pre-release version: `0.4.0-pre.0` for `0.3`.
fn next_minor(series: &str) -> String {
    let (a, b) = series_pair(series).unwrap_or((0, 0));
    format!("{a}.{}.0-pre.0", b + 1)
}

/// The decision of one run, by the file (if there is one), the digests now,
/// the series of the version of the workspace and the mode.
pub fn decide(
    old: Option<&File>,
    now: &[String; 4],
    series: &str,
    mode: Mode,
    release: bool,
) -> Result<Outcome, String> {
    let fresh = |state| File {
        series: series.to_string(),
        state,
        digests: now.clone(),
    };
    let none = |notes| Outcome { write: None, notes };
    if release && mode != Mode::Check {
        return Err("abi: --release goes with --check only".into());
    }
    let Some(old) = old else {
        return match mode {
            Mode::Check => {
                Err("abi: packages/abi.txt is missing; run cargo xtask abi --update".into())
            }
            Mode::Update => Ok(Outcome {
                write: Some(fresh(State::Open)),
                notes: vec![format!("abi: series {series} written, open")],
            }),
            Mode::Freeze => Ok(Outcome {
                write: Some(fresh(State::Frozen)),
                notes: vec![format!("abi: series {series} written, frozen")],
            }),
        };
    };
    let order = series_pair(&old.series).cmp(&series_pair(series));
    if order == std::cmp::Ordering::Greater {
        return Err(format!(
            "abi: abi.txt is of the series {}, the version is of {series}",
            old.series
        ));
    }
    if order == std::cmp::Ordering::Less {
        return match mode {
            Mode::Check => Err(format!(
                "abi: the version is of the series {series} and abi.txt of {}; run cargo xtask abi --update",
                old.series
            )),
            Mode::Update => Ok(Outcome {
                write: Some(fresh(State::Open)),
                notes: vec![format!("abi: the new series {series} starts open")],
            }),
            Mode::Freeze => Ok(Outcome {
                write: Some(fresh(State::Frozen)),
                notes: vec![format!("abi: the new series {series} starts frozen")],
            }),
        };
    }
    let diff = changed(old, now);
    if release && old.state != State::Frozen {
        return Err(format!(
            "abi: a release needs the series {series} frozen; run cargo xtask abi --freeze"
        ));
    }
    if old.state == State::Frozen && !diff.is_empty() {
        return Err(format!(
            "abi: {} changed in the frozen series {series}; raise the minor version ({}) and run cargo xtask abi --update",
            diff.join(", "),
            next_minor(series)
        ));
    }
    match mode {
        Mode::Check => Ok(none(if diff.is_empty() {
            vec![format!(
                "abi: series {series} {}, no change",
                old.state.word()
            )]
        } else {
            vec![format!(
                "abi: {} changed in the open series {series}; run cargo xtask abi --update before the series is frozen",
                diff.join(", ")
            )]
        })),
        Mode::Update => {
            if diff.is_empty() {
                return Ok(none(vec![format!("abi: series {series} is up to date")]));
            }
            Ok(Outcome {
                write: Some(fresh(State::Open)),
                notes: vec![format!("abi: {} updated", diff.join(", "))],
            })
        }
        Mode::Freeze => {
            if old.state == State::Frozen {
                return Ok(none(vec![format!(
                    "abi: series {series} is already frozen"
                )]));
            }
            Ok(Outcome {
                write: Some(fresh(State::Frozen)),
                notes: vec![format!("abi: series {series} frozen")],
            })
        }
    }
}

// ------------------------------------------------------------------ parts

/// The lines of `libc`: from `llvm-nm -D --defined-only --print-size`, one
/// `<name> func` for a function and `<name> data <size>` for an object of
/// data (`D`, `B`, `R`, `V`). The size of a function is not taken: a change
/// of its code is no change of the ABI.
pub fn libc_lines(nm: &str) -> Vec<String> {
    let mut lines = BTreeSet::new();
    for line in nm.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        let [_, size, kind, name] = f[..] else {
            continue;
        };
        let class = match kind {
            "T" | "W" | "i" | "I" => format!("{name} func"),
            "D" | "B" | "R" | "V" | "G" | "S" => {
                let bytes = u64::from_str_radix(size, 16).unwrap_or(0);
                format!("{name} data {bytes}")
            }
            other => format!("{name} kind-{other}"),
        };
        lines.insert(class);
    }
    lines.into_iter().collect()
}

/// The lines of `layouts` from the rows of the table the probe writes.
pub fn layout_lines(table: &[u8]) -> Result<Vec<String>, String> {
    if !table.len().is_multiple_of(ROW) || table.is_empty() {
        return Err(format!(
            "abi: the table of the probe is {} bytes, which are not whole rows of {ROW}",
            table.len()
        ));
    }
    let mut lines = BTreeSet::new();
    for row in table.chunks(ROW) {
        let end = row[..NAME].iter().position(|&b| b == 0).unwrap_or(NAME);
        let name = std::str::from_utf8(&row[..end])
            .map_err(|_| "abi: a name of the probe is not text".to_string())?;
        let value = u64::from_le_bytes(row[NAME..ROW].try_into().expect("8 bytes"));
        if !lines.insert(format!("{name} {value}")) {
            return Err(format!("abi: the probe names {name} twice"));
        }
    }
    Ok(lines.into_iter().collect())
}

pub fn loader_lines() -> Vec<String> {
    use proto_loader as l;
    let mut v = vec![
        format!("VERSION {}", l::VERSION),
        format!("SLOTS {}", l::SLOTS),
        format!("TRANSFER_SIZE {}", l::TRANSFER_SIZE),
        format!("START_AREA {:#x}", l::START_AREA),
        format!("AREA_MAX {:#x}", l::AREA_MAX),
        format!("HEADER {}", l::HEADER),
        format!("DESCRIPTOR {}", l::DESCRIPTOR),
        format!("DESCRIPTORS {}", l::DESCRIPTORS),
        format!("LIBRARY_BASE {:#x}", l::LIBRARY_BASE),
        format!(
            "LIBRARY_ROOM {:#x}..{:#x}",
            l::LIBRARY_ROOM.start,
            l::LIBRARY_ROOM.end
        ),
        format!("LIBRARY_PATH {}", String::from_utf8_lossy(l::LIBRARY_PATH)),
        format!("INTERP {}", String::from_utf8_lossy(l::INTERP)),
        format!(
            "PROGRAM_ROOM {:#x}..{:#x}",
            l::PROGRAM_ROOM.start,
            l::PROGRAM_ROOM.end
        ),
        format!("STACK_SIZE {}", l::STACK_SIZE),
        format!("ARG_MAX {}", l::ARG_MAX),
        format!("PATH_MAX {}", l::PATH_MAX),
    ];
    for slot in l::Slot::GIVEN {
        v.push(format!("slot {slot:?} {}", slot as u32));
    }
    v.sort();
    v
}

/// The crates `proto/*` in the output of `cargo tree --prefix none
/// --format "{p}"`: name and directory.
pub fn proto_crates(tree: &str, root: &Path) -> Vec<(String, PathBuf)> {
    let proto = root.join("proto");
    let mut found = BTreeSet::new();
    for line in tree.lines() {
        let Some((name, rest)) = line.split_once(' ') else {
            continue;
        };
        let Some(start) = rest.find('(') else {
            continue;
        };
        let Some(len) = rest[start..].find(')') else {
            continue;
        };
        let path = PathBuf::from(&rest[start + 1..start + len]);
        if path.parent() == Some(proto.as_path()) {
            found.insert((name.to_string(), path));
        }
    }
    found.into_iter().collect()
}

/// `pub const VERSION: uNN = N;` of a crate's `src/lib.rs`.
pub fn version_of(source: &str) -> Option<u64> {
    source.lines().find_map(|l| {
        let rest = l.trim().strip_prefix("pub const VERSION:")?;
        let (_, value) = rest.split_once('=')?;
        value.trim().trim_end_matches(';').trim().parse().ok()
    })
}

pub fn protocol_lines(crates: &[(String, PathBuf)]) -> Result<Vec<String>, String> {
    let mut v = Vec::new();
    for (name, dir) in crates {
        let path = dir.join("src/lib.rs");
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        // A crate without a version (the framing of proto-wire) counts with a dash.
        let version = version_of(&text).map_or("-".to_string(), |n| n.to_string());
        v.push(format!("{name} {version}"));
    }
    if v.is_empty() {
        return Err("abi: no protocol crate under proto/ in the closure of the layer".into());
    }
    v.sort();
    Ok(v)
}

fn clang() -> String {
    let brew = Path::new("/opt/homebrew/opt/llvm/bin/clang");
    if brew.exists() {
        brew.display().to_string()
    } else {
        "clang".into()
    }
}

/// Compiles `source` for aarch64 against the headers in `includes` and
/// returns the bytes of the section `.stafeto_abi`.
pub fn probe_table(source: &Path, includes: &[PathBuf], work: &Path) -> Result<Vec<u8>, String> {
    std::fs::create_dir_all(work).map_err(|e| format!("{}: {e}", work.display()))?;
    let object = work.join("layouts.o");
    let section = work.join("layouts.bin");
    let _ = std::fs::remove_file(&section);
    let mut cc = Command::new(clang());
    cc.args([
        "--target=aarch64-linux-gnu",
        "-nostdinc",
        "-fno-stack-protector",
        "-fno-builtin",
        "-std=c11",
        "-O2",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-fno-pic",
    ]);
    if let Some(dir) = source.parent() {
        cc.arg("-I").arg(dir);
    }
    for dir in includes {
        cc.arg("-isystem").arg(dir);
    }
    crate::run_cmd(cc.arg("-c").arg(source).arg("-o").arg(&object))?;
    crate::run_cmd(
        Command::new(crate::llvm_tool("llvm-objcopy")?)
            .arg("--dump-section")
            .arg(format!(".stafeto_abi={}", section.display()))
            .arg(&object),
    )?;
    std::fs::read(&section).map_err(|e| format!("{}: {e}", section.display()))
}

fn compute(tree: &Path) -> Result<Parts, String> {
    let target = crate::target_dir();
    let libc = target.join("libc-so").join("libc.so");
    let nm = crate::stdout_of(
        Command::new(crate::llvm_tool("llvm-nm")?)
            .args(["-D", "--defined-only", "--print-size"])
            .arg(&libc),
    )?;
    let libc_part = libc_lines(&nm);
    if libc_part.is_empty() {
        return Err(format!("abi: {} exports nothing", libc.display()));
    }
    let table = probe_table(
        &tree.join("tools/abi-layouts.c"),
        &[
            target.join("libc-so/sysroot/include"),
            tree.join("lib/posix-crt/include"),
        ],
        &target.join("abi"),
    )?;
    let layouts = layout_lines(&table)?;
    let tree_text = crate::stdout_of(Command::new("cargo").current_dir(tree).args([
        "tree",
        "--offline",
        "--prefix",
        "none",
        "--all-features",
        "-e",
        "normal,build",
        "--format",
        "{p}",
        "-p",
        "posix-abi",
        "-p",
        "posix-crt",
    ]))?;
    let protocols = protocol_lines(&proto_crates(&tree_text, tree))?;
    Ok(Parts([libc_part, layouts, loader_lines(), protocols]))
}

pub fn file_path(tree: &Path) -> PathBuf {
    tree.join("packages/abi.txt")
}

fn write_explain(parts: &Parts, dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for (name, lines) in PARTS.iter().zip(&parts.0) {
        let path = dir.join(format!("{name}.txt"));
        std::fs::write(&path, lines.join("\n") + "\n")
            .map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok(())
}

/// The lines of a part that were not there before, and those that are gone.
pub fn line_diff(before: &[String], after: &[String]) -> Vec<String> {
    let a: BTreeSet<&String> = before.iter().collect();
    let b: BTreeSet<&String> = after.iter().collect();
    let mut out: Vec<String> = a.difference(&b).map(|l| format!("- {l}")).collect();
    out.extend(b.difference(&a).map(|l| format!("+ {l}")));
    out
}

/// `cargo xtask abi [--check|--update|--freeze|--explain] [--release] [--no-build]`.
/// `--no-build` takes the `libc.so` of `target/libc-so` as it is.
pub fn command(args: &[String]) -> Result<(), String> {
    let mut mode = Mode::Check;
    let (mut explain, mut release, mut build) = (false, false, true);
    for a in args {
        match a.as_str() {
            "--check" => mode = Mode::Check,
            "--update" => mode = Mode::Update,
            "--freeze" => mode = Mode::Freeze,
            "--explain" => explain = true,
            "--release" => release = true,
            "--no-build" => build = false,
            other => {
                return Err(format!(
                    "{other}: unknown argument\nusage: cargo xtask abi [--check|--update|--freeze|--explain] [--release] [--no-build]"
                ));
            }
        }
    }
    let tree = crate::root();
    if build {
        crate::libc_so()?;
    }
    let parts = compute(&tree)?;
    let explained = crate::target_dir().join("abi");
    let accepted = explained.join("accepted");
    let previous: Vec<Option<Vec<String>>> = PARTS
        .iter()
        .map(|n| {
            std::fs::read_to_string(accepted.join(format!("{n}.txt")))
                .ok()
                .map(|t| t.lines().map(str::to_string).collect())
        })
        .collect();
    write_explain(&parts, &explained)?;
    if explain {
        println!("abi: the parts are in {}", explained.display());
        return Ok(());
    }
    let path = file_path(&tree);
    let old = match std::fs::read_to_string(&path) {
        Ok(text) => Some(File::parse(&text)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let now = parts.digests();
    let outcome = decide(old.as_ref(), &now, &crate::pkg::series(), mode, release);
    if let Some(old) = &old {
        for (i, name) in PARTS.iter().enumerate() {
            if old.digests[i] != now[i] {
                println!("abi: part {name} differs from abi.txt (now {})", now[i]);
                if let Some(before) = &previous[i] {
                    for l in line_diff(before, &parts.0[i]) {
                        println!("  {l}");
                    }
                }
            }
        }
    }
    let outcome = outcome?;
    for n in &outcome.notes {
        println!("{n}");
    }
    if let Some(file) = outcome.write {
        std::fs::write(&path, file.render()).map_err(|e| format!("{}: {e}", path.display()))?;
        write_explain(&parts, &accepted)?;
        println!("abi: {} written", path.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    fn digests(tag: &str) -> [String; 4] {
        std::array::from_fn(|i| digest(&lines(&[tag, PARTS[i]])))
    }

    fn file(series: &str, state: State, d: &[String; 4]) -> File {
        File {
            series: series.into(),
            state,
            digests: d.clone(),
        }
    }

    #[test]
    fn the_file_is_written_and_read_back_and_refuses_damage() {
        let f = file("0.3", State::Open, &std::array::from_fn(|_| "a".repeat(64)));
        let text = f.render();
        assert!(text.starts_with("format 1\nseries 0.3\nstate open\nlibc "));
        assert_eq!(File::parse(&text).unwrap(), f);
        let frozen = file("0.3", State::Frozen, &digests("a")).render();
        assert!(frozen.contains("state frozen"));
        for bad in [
            text.replace("format 1", "format 2"),
            text.replace("series 0.3", "series 0"),
            text.replace("state open", "state shut"),
            text.replace("loader ", "loaders "),
            format!("{text}more\n"),
            text.lines().take(5).collect::<Vec<_>>().join("\n"),
            text.replacen("libc a", "libc A", 1),
            text.replacen("layouts ", "layouts 12", 1),
        ] {
            assert!(File::parse(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn an_open_series_prints_a_change_and_passes() {
        let old = file("0.3", State::Open, &digests("a"));
        let out = decide(Some(&old), &digests("b"), "0.3", Mode::Check, false).unwrap();
        assert!(out.write.is_none());
        assert!(out.notes[0].contains("libc, layouts, loader, protocols changed"));
        let same = decide(Some(&old), &digests("a"), "0.3", Mode::Check, false).unwrap();
        assert!(same.notes[0].contains("no change"));
        // One part only is named.
        let mut one = digests("a");
        one[2] = digest(&lines(&["other"]));
        let out = decide(Some(&old), &one, "0.3", Mode::Check, false).unwrap();
        assert!(out.notes[0].starts_with("abi: loader changed"));
    }

    #[test]
    fn a_frozen_series_of_the_same_version_fails_on_a_change() {
        let old = file("0.3", State::Frozen, &digests("a"));
        let err = decide(Some(&old), &digests("b"), "0.3", Mode::Check, false).unwrap_err();
        assert!(err.contains("changed in the frozen series 0.3"), "{err}");
        assert!(err.contains("0.4.0-pre.0"), "{err}");
        // A change of one part is named alone, and --update does not hide it.
        let mut one = digests("a");
        one[0] = digest(&lines(&["x"]));
        let err = decide(Some(&old), &one, "0.3", Mode::Check, false).unwrap_err();
        assert!(err.starts_with("abi: libc changed in the frozen"), "{err}");
        assert!(decide(Some(&old), &one, "0.3", Mode::Update, false).is_err());
        assert!(decide(Some(&old), &one, "0.3", Mode::Freeze, false).is_err());
        // No change passes.
        assert!(decide(Some(&old), &digests("a"), "0.3", Mode::Check, false).is_ok());
    }

    #[test]
    fn a_greater_series_is_started_by_update_and_checked_with_an_error() {
        let old = file("0.3", State::Frozen, &digests("a"));
        let err = decide(Some(&old), &digests("b"), "0.4", Mode::Check, false).unwrap_err();
        assert!(err.contains("run cargo xtask abi --update"), "{err}");
        let out = decide(Some(&old), &digests("b"), "0.4", Mode::Update, false).unwrap();
        assert_eq!(out.write, Some(file("0.4", State::Open, &digests("b"))));
        // An older version than the file is an error.
        assert!(decide(Some(&old), &digests("a"), "0.2", Mode::Check, false).is_err());
        // Update of an open series rewrites the digests and keeps it open.
        let open = file("0.4", State::Open, &digests("a"));
        let out = decide(Some(&open), &digests("b"), "0.4", Mode::Update, false).unwrap();
        assert_eq!(out.write, Some(file("0.4", State::Open, &digests("b"))));
        let out = decide(Some(&open), &digests("a"), "0.4", Mode::Update, false).unwrap();
        assert!(out.write.is_none());
    }

    #[test]
    fn freeze_and_the_missing_file() {
        let open = file("0.3", State::Open, &digests("a"));
        let out = decide(Some(&open), &digests("b"), "0.3", Mode::Freeze, false).unwrap();
        assert_eq!(out.write, Some(file("0.3", State::Frozen, &digests("b"))));
        assert!(decide(None, &digests("a"), "0.2", Mode::Check, false).is_err());
        let out = decide(None, &digests("a"), "0.2", Mode::Update, false).unwrap();
        assert_eq!(out.write, Some(file("0.2", State::Open, &digests("a"))));
    }

    #[test]
    fn a_release_needs_a_frozen_series_of_the_same_version() {
        let open = file("0.3", State::Open, &digests("a"));
        let err = decide(Some(&open), &digests("a"), "0.3", Mode::Check, true).unwrap_err();
        assert!(err.contains("needs the series 0.3 frozen"), "{err}");
        let frozen = file("0.3", State::Frozen, &digests("a"));
        assert!(decide(Some(&frozen), &digests("a"), "0.3", Mode::Check, true).is_ok());
        assert!(decide(Some(&frozen), &digests("b"), "0.3", Mode::Check, true).is_err());
        // The series of the version is greater than the file: no release.
        assert!(decide(Some(&frozen), &digests("a"), "0.4", Mode::Check, true).is_err());
        assert!(decide(Some(&frozen), &digests("a"), "0.3", Mode::Update, true).is_err());
        assert!(decide(None, &digests("a"), "0.3", Mode::Check, true).is_err());
    }

    #[test]
    fn the_size_of_a_data_object_is_part_of_libc_and_that_of_a_function_is_not() {
        let nm = "0000000004207d50 0000000000000008 B environ\n\
                  00000000040d1380 000000000000000c T abs\n\
                  0000000004131678 0000000000000004 W __addtf3\n";
        let a = libc_lines(nm);
        assert_eq!(a, lines(&["__addtf3 func", "abs func", "environ data 8"]));
        let longer = nm.replace("0000000000000008 B environ", "0000000000000010 B environ");
        assert_ne!(digest(&libc_lines(&longer)), digest(&a));
        let other_code = nm
            .replace("000000000000000c T abs", "0000000000000090 T abs")
            .replace("04131678", "04131999");
        assert_eq!(digest(&libc_lines(&other_code)), digest(&a));
        // A new name changes it; a data object that moves from B to D does not.
        let more = format!("{nm}00000000040d1390 0000000000000004 T labs\n");
        assert_ne!(digest(&libc_lines(&more)), digest(&a));
        let moved = nm.replace(" B environ", " D environ");
        assert_eq!(digest(&libc_lines(&moved)), digest(&a));
    }

    fn row(name: &str, value: u64) -> Vec<u8> {
        let mut r = vec![0u8; NAME];
        r[..name.len()].copy_from_slice(name.as_bytes());
        r.extend(value.to_le_bytes());
        r
    }

    #[test]
    fn the_rows_of_the_probe_become_sorted_lines() {
        let mut table = row("sizeof struct stat", 128);
        table.extend(row("O_CREAT", 64));
        let l = layout_lines(&table).unwrap();
        assert_eq!(l, lines(&["O_CREAT 64", "sizeof struct stat 128"]));
        assert!(layout_lines(&table[..100]).is_err());
        assert!(layout_lines(&[]).is_err());
        let mut twice = table.clone();
        twice.extend(row("O_CREAT", 64));
        assert!(layout_lines(&twice).unwrap_err().contains("twice"));
    }

    #[test]
    fn the_loader_and_the_protocol_versions_are_read() {
        let l = loader_lines();
        assert!(l.contains(&format!("VERSION {}", proto_loader::VERSION)));
        assert!(l.iter().any(|x| x.starts_with("slot Net ")));
        assert!(l.iter().any(|x| x.starts_with("LIBRARY_PATH /lib/libc.so")));
        assert_eq!(version_of("a\npub const VERSION: u16 = 20;\nb"), Some(20));
        assert_eq!(version_of("const VERSION: u16 = 2;"), None);
        let root = crate::root();
        let tree = format!(
            "posix-abi v0.1.0 ({0}/lib/posix-abi)\nproto-net v0.1.0 ({0}/proto/net)\nproto-fs v0.1.0 ({0}/proto/fs)\nsha2 v0.11.1\nproto-net v0.1.0 ({0}/proto/net) (*)\n",
            root.display()
        );
        let crates = proto_crates(&tree, &root);
        assert_eq!(crates.len(), 2);
        let p = protocol_lines(&crates).unwrap();
        assert_eq!(p.len(), 2);
        assert!(p[0].starts_with("proto-fs "));
        // A change of one version changes the digest.
        let mut q = p.clone();
        q[1] = "proto-net 2".into();
        assert_ne!(digest(&p), digest(&q));
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("stafeto-abi-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The table of a probe over a header with the given `struct stat`.
    fn table_with(tag: &str, fields: &str) -> Vec<u8> {
        let dir = scratch(tag);
        std::fs::create_dir_all(dir.join("include/sys")).unwrap();
        std::fs::write(
            dir.join("include/sys/stat.h"),
            format!("struct stat {{ {fields} }};\n#define O_CREAT 64\n"),
        )
        .unwrap();
        std::fs::copy(
            crate::root().join("tools/abi-layouts.h"),
            dir.join("abi-layouts.h"),
        )
        .unwrap();
        std::fs::write(
            dir.join("probe.c"),
            "#include <sys/stat.h>\n#include \"abi-layouts.h\"\n\
             const struct row stafeto_abi[] __attribute__((section(\".stafeto_abi\"), used)) = {\n\
             S(struct stat) O(struct stat, st_mode) C(O_CREAT)\n};\n",
        )
        .unwrap();
        let table = probe_table(
            &dir.join("probe.c"),
            &[dir.join("include")],
            &dir.join("out"),
        )
        .unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        table
    }

    #[test]
    fn a_change_of_struct_stat_in_the_headers_changes_layouts() {
        let a = layout_lines(&table_with("stat-a", "long st_dev; int st_mode;")).unwrap();
        assert!(a.contains(&"sizeof struct stat 16".to_string()), "{a:?}");
        assert!(a.contains(&"offsetof struct stat.st_mode 8".to_string()));
        assert!(a.contains(&"O_CREAT 64".to_string()));
        let wider =
            layout_lines(&table_with("stat-b", "long st_dev; long pad; int st_mode;")).unwrap();
        assert_ne!(digest(&a), digest(&wider));
        let moved = layout_lines(&table_with("stat-c", "int st_mode; long st_dev;")).unwrap();
        assert_ne!(digest(&a), digest(&moved));
        assert_eq!(
            digest(&a),
            digest(&layout_lines(&table_with("stat-d", "long st_dev; int st_mode;")).unwrap())
        );
    }

    #[test]
    fn the_probe_names_the_structures_and_constants_programs_depend_on() {
        let c = std::fs::read_to_string(crate::root().join("tools/abi-layouts.c")).unwrap();
        for t in [
            "struct stat",
            "struct dirent",
            "struct timespec",
            "struct timeval",
            "struct sigaction",
            "siginfo_t",
            "sigset_t",
            "struct termios",
            "struct winsize",
            "struct pollfd",
            "struct epoll_event",
            "struct sockaddr",
            "struct sockaddr_in",
            "struct sockaddr_in6",
            "struct sockaddr_un",
            "struct addrinfo",
            "struct msghdr",
            "struct iovec",
            "struct rlimit",
            "struct rusage",
            "struct utsname",
            "struct tm",
            "jmp_buf",
            "sigjmp_buf",
            "pthread_attr_t",
            "pthread_mutex_t",
            "pthread_cond_t",
            "pthread_rwlock_t",
            "pthread_once_t",
            "pthread_key_t",
        ] {
            assert!(c.contains(&format!("S({t})")), "{t}");
        }
        for f in ["st_dev", "st_ino", "st_mode", "st_size", "st_mtim"] {
            assert!(c.contains(&format!("O(struct stat, {f})")), "{f}");
        }
        for f in ["sa_handler", "sa_mask", "sa_flags"] {
            assert!(c.contains(&format!("O(struct sigaction, {f})")), "{f}");
        }
        for n in [
            "O_CREAT",
            "FD_CLOEXEC",
            "EINTR",
            "ERANGE",
            "SIGRTMIN",
            "SIGRTMAX",
            "SA_RESTART",
            "S_IFMT",
            "AT_FDCWD",
            "CLOCK_MONOTONIC",
            "_SC_PAGESIZE",
            "POLLIN",
            "EPOLLIN",
            "AF_INET",
            "SOCK_STREAM",
            "SOL_SOCKET",
            "SO_REUSEADDR",
            "MAP_ANONYMOUS",
            "PROT_READ",
            "WNOHANG",
            "PATH_MAX",
            "NAME_MAX",
            "PIPE_BUF",
        ] {
            assert!(c.contains(&format!("C({n})")), "{n}");
        }
        assert!(c.contains("<stafeto/display.h>") && c.contains("<stafeto/fast.h>"));
    }

    #[test]
    fn a_line_diff_shows_what_went_and_what_came() {
        let d = line_diff(&lines(&["a", "b"]), &lines(&["b", "c"]));
        assert_eq!(d, lines(&["- a", "+ c"]));
    }
}
