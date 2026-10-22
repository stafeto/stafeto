// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The places of the kernel that take `OBJ`: every `obj::lock()` in
//! `kernel/src` outside the kernel tests (the `ktest` directory and
//! `ktest.rs`), by file.

use std::collections::BTreeMap;
use std::path::Path;

/// The files that take `OBJ` and how many `obj::lock()` each has.
///
/// The lock has one way in (`obj::lock`, kernel/src/obj.rs), and a stretch of
/// the kernel between two polls for an interrupt waits for the holds of the
/// other CPUs once for each take (B_N, `obj takes of kind`). A take that
/// appears in a new place, or one more in a place that has it, lengthens
/// that wait for the stretches that pass it, and no test need reach the new
/// path to show it. So each place is listed here: a change to this list
/// is a change to the bound, and the person who makes it says so in the
/// commit and shows the takes of the stretches (`obj takes of kind`) with the
/// new count.
pub const OBJ_LOCK_SITES: &[(&str, usize)] = &[
    ("kernel/src/arch/aarch64/exceptions.rs", 1),
    ("kernel/src/channel/mod.rs", 4),
    ("kernel/src/cleanup.rs", 4),
    ("kernel/src/cmd.rs", 2),
    ("kernel/src/irq.rs", 1),
    ("kernel/src/memory.rs", 2),
    ("kernel/src/mm/aspace.rs", 2),
    ("kernel/src/process/control.rs", 3),
    ("kernel/src/process/maps.rs", 1),
    ("kernel/src/process/teardown.rs", 12),
    ("kernel/src/qsbr.rs", 1),
    ("kernel/src/sched.rs", 1),
    ("kernel/src/smp.rs", 1),
    ("kernel/src/syscall/mem.rs", 4),
    ("kernel/src/syscall/mod.rs", 5),
    ("kernel/src/syscall/proc.rs", 2),
    ("kernel/src/timer.rs", 1),
];

/// The counts of `obj::lock()` per file of `kernel/src`, with the line
/// numbers of each, in the code that is not a kernel test. A comment does
/// not count.
pub fn scan(root: &Path) -> Result<BTreeMap<String, Vec<usize>>, String> {
    let mut found = BTreeMap::new();
    walk(root, &root.join("kernel/src"), &mut found)?;
    Ok(found)
}

fn walk(root: &Path, dir: &Path, found: &mut BTreeMap<String, Vec<usize>>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let path = entry.map_err(|e| e.to_string())?.path();
        let name = path
            .strip_prefix(root)
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .into_owned();
        if name == "kernel/src/ktest" || name == "kernel/src/ktest.rs" {
            continue;
        }
        if path.is_dir() {
            walk(root, &path, found)?;
        } else if name.ends_with(".rs") {
            let text = std::fs::read_to_string(&path).map_err(|e| format!("{name}: {e}"))?;
            let lines = sites_in(&text);
            if !lines.is_empty() {
                found.insert(name, lines);
            }
        }
    }
    Ok(())
}

/// The numbers of the lines of `text` that call `obj::lock()` in code.
pub fn sites_in(text: &str) -> Vec<usize> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim_start().starts_with("//"))
        .filter(|(_, line)| line.contains("obj::lock()"))
        .map(|(n, _)| n + 1)
        .collect()
}

/// Compares what the sources have with `expected`: an error names each file
/// whose count differs, and the lines of the takes in it, so that the new
/// place is found.
pub fn compare(
    found: &BTreeMap<String, Vec<usize>>,
    expected: &[(&str, usize)],
) -> Result<(), String> {
    let mut problems = Vec::new();
    for (file, lines) in found {
        let want = expected.iter().find(|(f, _)| f == file).map_or(0, |e| e.1);
        if lines.len() > want {
            problems.push(format!(
                "{file}: {} takes of OBJ, the list has {want}; a new place is among the lines {lines:?}",
                lines.len()
            ));
        } else if lines.len() < want {
            problems.push(format!(
                "{file}: {} takes of OBJ, the list has {want}; a place went (lines now {lines:?})",
                lines.len()
            ));
        }
    }
    for (file, want) in expected {
        if *want > 0 && !found.contains_key(*file) {
            problems.push(format!(
                "{file}: no take of OBJ, the list has {want}; the places went"
            ));
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "the takes of OBJ differ from OBJ_LOCK_SITES (xtask/src/obj_sites.rs):\n  {}\nA take in a new place lengthens the wait of every stretch that passes it: \
             change the list together with the takes of the stretches (`obj takes of kind`) and say why.",
            problems.join("\n  ")
        ))
    }
}

/// The step of the kernel group: the sources against `OBJ_LOCK_SITES`.
pub fn check(root: &Path) -> Result<(), String> {
    let found = scan(root)?;
    compare(&found, OBJ_LOCK_SITES)?;
    let total: usize = found.values().map(Vec::len).sum();
    println!(
        "obj lock sites: {total} takes of OBJ in {} files, as listed",
        found.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(list: &[(&str, &[usize])]) -> BTreeMap<String, Vec<usize>> {
        list.iter()
            .map(|(f, l)| ((*f).to_owned(), l.to_vec()))
            .collect()
    }

    #[test]
    fn the_listed_places_pass() {
        let f = found(&[("a.rs", &[3, 9]), ("b.rs", &[1])]);
        assert!(compare(&f, &[("a.rs", 2), ("b.rs", 1)]).is_ok());
    }

    #[test]
    fn a_take_more_in_a_file_fails_and_names_its_lines() {
        let f = found(&[("a.rs", &[3, 9, 20])]);
        let e = compare(&f, &[("a.rs", 2)]).unwrap_err();
        assert!(e.contains("a.rs: 3 takes of OBJ, the list has 2"), "{e}");
        assert!(e.contains("[3, 9, 20]"), "{e}");
    }

    #[test]
    fn a_take_in_an_unlisted_file_fails() {
        let f = found(&[("a.rs", &[3]), ("new.rs", &[7])]);
        let e = compare(&f, &[("a.rs", 1)]).unwrap_err();
        assert!(e.contains("new.rs: 1 takes of OBJ, the list has 0"), "{e}");
    }

    #[test]
    fn a_take_that_went_fails() {
        let f = found(&[("a.rs", &[3])]);
        assert!(
            compare(&f, &[("a.rs", 2)])
                .unwrap_err()
                .contains("a place went")
        );
        let e = compare(&found(&[]), &[("a.rs", 1)]).unwrap_err();
        assert!(e.contains("a.rs: no take of OBJ"), "{e}");
    }

    #[test]
    fn comments_do_not_count() {
        let text = "fn f() {\n    // crate::obj::lock() would nest\n    let _s = crate::obj::lock();\n    /// obj::lock()\n}\n";
        assert_eq!(sites_in(text), [3]);
    }

    /// The list is the sources' as they are in the repository.
    #[test]
    fn the_sources_have_the_listed_places() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let root = root.canonicalize().unwrap();
        check(&root).unwrap();
    }
}
