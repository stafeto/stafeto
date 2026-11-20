// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask pkg-repro`: whether the packages build the same twice
//! (docs/packages.md, "Reproducible builds"). The command builds every
//! package from scratch two times in one checkout, each time with its own
//! output directory and its own `target/` (the third-party build trees, the
//! sysroot and the cargo outputs all live there), then compares what each
//! package installs: the manifest lines without `SOURCE` and the `meta`
//! fields without `recipe`, `commit`, `release` and `size`, the same content
//! that carrying by content compares (carry.rs). One line per package names
//! the first path or field that differs.
//!
//! The command moves `target/` away, so it runs on a runner (the workflow
//! `probe.yml`: `command=pkg-repro`) and refuses anywhere else without
//! `--force`. The two runs share the path of the checkout, as two runs of one
//! workflow do, so a path of the build tree inside a program is no difference
//! here and shows only between runners that use other paths.

use crate::carry::Installed;
use crate::packages;
use pkgfmt::Package as PackageFile;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The verdict for one package.
#[derive(Debug, PartialEq, Eq)]
pub struct Verdict {
    pub name: String,
    /// Every difference, the first path or field first; empty when equal.
    pub differences: Vec<String>,
}

/// The installed content of each package file (`*.stpkg`) of a directory.
fn read(dir: &Path) -> Result<BTreeMap<String, Installed>, String> {
    let mut found = BTreeMap::new();
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.extension().is_none_or(|e| e != "stpkg") {
            continue;
        }
        let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let file = PackageFile::parse(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
        found.insert(file.meta.name.to_string(), Installed::of_file(&file));
    }
    Ok(found)
}

/// Compares the package files of two directories, by package name. A package
/// that only one directory holds differs in `(missing in <side>)`.
pub fn compare(first: &Path, second: &Path) -> Result<Vec<Verdict>, String> {
    let (a, b) = (read(first)?, read(second)?);
    let mut verdicts = Vec::new();
    for name in a
        .keys()
        .chain(b.keys())
        .collect::<std::collections::BTreeSet<_>>()
    {
        let differences = match (a.get(name), b.get(name)) {
            (Some(x), Some(y)) => x.differences(y),
            (Some(_), None) => vec!["(missing in the second build)".to_string()],
            (None, _) => vec!["(missing in the first build)".to_string()],
        };
        verdicts.push(Verdict {
            name: name.clone(),
            differences,
        });
    }
    Ok(verdicts)
}

/// The lines to print: one per package, then the count.
pub fn report(verdicts: &[Verdict], is_base: &dyn Fn(&str) -> bool) -> Vec<String> {
    let mut lines = Vec::new();
    for v in verdicts {
        let kind = if is_base(&v.name) { "base" } else { "optional" };
        lines.push(match v.differences.split_first() {
            None => format!("pkg-repro: {} ({kind}) same", v.name),
            Some((first, [])) => {
                format!("pkg-repro: {} ({kind}) DIFFERS: {first}", v.name)
            }
            Some((first, rest)) => format!(
                "pkg-repro: {} ({kind}) DIFFERS: first difference {first}, {} more",
                v.name,
                rest.len()
            ),
        });
    }
    let differ = verdicts
        .iter()
        .filter(|v| !v.differences.is_empty())
        .count();
    lines.push(format!(
        "pkg-repro: {} packages, {differ} differ",
        verdicts.len()
    ));
    lines
}

/// `target/` of the checkout moved to `to` (replacing what is there).
fn move_target(target: &Path, to: &Path) -> Result<(), String> {
    if to.exists() {
        std::fs::remove_dir_all(to).map_err(|e| format!("{}: {e}", to.display()))?;
    }
    if target.exists() {
        std::fs::rename(target, to)
            .map_err(|e| format!("{} to {}: {e}", target.display(), to.display()))?;
    }
    Ok(())
}

pub fn command(args: &[String]) -> Result<(), String> {
    let force = match args {
        [] => false,
        [a] if a == "--force" => true,
        _ => return Err("usage: pkg-repro [--force]".into()),
    };
    if !force && std::env::var_os("GITHUB_ACTIONS").is_none() {
        return Err("pkg-repro moves target/ away and builds every package twice from scratch: run it on a runner (probe.yml, command=pkg-repro) or pass --force".into());
    }
    let root = crate::root();
    let target = root.join("target");
    if crate::target_dir() != target {
        return Err("pkg-repro wants target/ of the checkout (CARGO_TARGET_DIR is set)".into());
    }
    // The running program lives in target/, which is moved: a copy builds.
    let copy: PathBuf =
        std::env::temp_dir().join(format!("stafeto-pkg-repro-{}", std::process::id()));
    std::fs::create_dir_all(&copy).map_err(|e| format!("{}: {e}", copy.display()))?;
    let exe = copy.join("xtask");
    std::fs::copy(std::env::current_exe().map_err(|e| e.to_string())?, &exe)
        .map_err(|e| format!("{}: {e}", exe.display()))?;
    move_target(&target, &root.join("target-before-repro"))?;
    let mut outs = Vec::new();
    for n in 1..=2 {
        let out = root.join(format!("repro-out-{n}"));
        if out.exists() {
            std::fs::remove_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
        }
        println!(
            "pkg-repro: build {n} of 2 from an empty target/ into {}",
            out.display()
        );
        let status = Command::new(&exe)
            .arg("pkg-build")
            .arg("--out")
            .arg(&out)
            .current_dir(&root)
            .status()
            .map_err(|e| format!("{}: {e}", exe.display()))?;
        if !status.success() {
            return Err(format!("pkg-repro: build {n} failed ({status})"));
        }
        // The build trees of this build stay for the logs; the next one starts empty.
        move_target(&target, &root.join(format!("target-repro-{n}")))?;
        outs.push(out);
    }
    let all = packages::load()?;
    let is_base = |name: &str| {
        all.iter()
            .any(|p| p.name == name && p.kind == packages::Kind::Base)
    };
    let verdicts = compare(&outs[0], &outs[1])?;
    for line in report(&verdicts, &is_base) {
        println!("{line}");
    }
    let bad: Vec<&str> = verdicts
        .iter()
        .filter(|v| !v.differences.is_empty())
        .map(|v| v.name.as_str())
        .collect();
    if bad.is_empty() {
        Ok(())
    } else {
        Err(format!("pkg-repro: not reproducible: {}", bad.join(" ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::carry::tests::{Shape, package_files};

    fn write(dir: &Path, name: &str, shape: &Shape<'_>) {
        let bytes = package_files(
            name,
            "1.0",
            "1",
            &"a".repeat(64),
            &[4; 32],
            "t-release",
            &[3; 32],
            shape,
        );
        std::fs::write(dir.join(format!("{name}-1.0-1.stpkg")), bytes).unwrap();
    }

    fn shape<'a>(byte: &'a [u8], source: &'a [u8]) -> Shape<'a> {
        Shape {
            files: vec![("/usr/bin/x", byte)],
            source: Some(source),
            ..Shape::default()
        }
    }

    fn dirs(tag: &str) -> (PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!("stafeto-repro-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let (a, b) = (base.join("a"), base.join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        (a, b)
    }

    #[test]
    fn equal_packages_are_the_same_whatever_their_source_text() {
        let (a, b) = dirs("same");
        write(&a, "alpha", &shape(b"\x7fELF 1", b"source A"));
        write(&b, "alpha", &shape(b"\x7fELF 1", b"another source text"));
        let verdicts = compare(&a, &b).unwrap();
        assert_eq!(
            verdicts,
            [Verdict {
                name: "alpha".into(),
                differences: vec![]
            }]
        );
        let lines = report(&verdicts, &|_| true);
        assert_eq!(lines[0], "pkg-repro: alpha (base) same");
        assert_eq!(lines[1], "pkg-repro: 1 packages, 0 differ");
    }

    #[test]
    fn a_planted_difference_names_the_first_path() {
        let (a, b) = dirs("planted");
        write(&a, "alpha", &shape(b"\x7fELF 1", b"s"));
        write(&b, "alpha", &shape(b"\x7fELF 2", b"s"));
        write(&a, "beta", &shape(b"same", b"s"));
        write(&b, "beta", &shape(b"same", b"s"));
        let verdicts = compare(&a, &b).unwrap();
        let lines = report(&verdicts, &|n| n == "alpha");
        assert_eq!(lines[0], "pkg-repro: alpha (base) DIFFERS: /usr/bin/x");
        assert_eq!(lines[1], "pkg-repro: beta (optional) same");
        assert_eq!(lines[2], "pkg-repro: 2 packages, 1 differ");
    }

    #[test]
    fn a_package_in_one_build_only_and_a_meta_field_differ() {
        let (a, b) = dirs("missing");
        write(&a, "alpha", &shape(b"x", b"s"));
        write(&a, "gamma", &shape(b"x", b"s"));
        let mut other = shape(b"x", b"s");
        other.license = "GPL-2.0-only";
        write(&b, "alpha", &other);
        let verdicts = compare(&a, &b).unwrap();
        assert_eq!(verdicts[0].differences, ["meta license"]);
        assert_eq!(verdicts[1].differences, ["(missing in the second build)"]);
        let more = Verdict {
            name: "beta".into(),
            differences: vec!["/a".into(), "/b".into(), "meta url".into()],
        };
        assert_eq!(
            report(&[more], &|_| false)[0],
            "pkg-repro: beta (optional) DIFFERS: first difference /a, 2 more"
        );
    }
}
