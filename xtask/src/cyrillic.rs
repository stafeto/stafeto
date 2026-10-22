// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The repository is in English: no tracked text file holds a Cyrillic
//! letter. The binary files of `xtask/zoneinfo` are skipped, as is any file
//! that is not valid UTF-8.

use std::path::Path;
use std::process::Command;

/// The tracked files under this prefix are binary data.
const SKIPPED: &str = "xtask/zoneinfo/";

fn is_cyrillic(c: char) -> bool {
    ('\u{0400}'..='\u{04FF}').contains(&c)
}

/// The lines of `text` (1-based numbers) that hold a Cyrillic letter.
fn cyrillic_lines(text: &str) -> Vec<usize> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| line.chars().any(is_cyrillic))
        .map(|(i, _)| i + 1)
        .collect()
}

pub fn check(root: &Path) -> Result<(), String> {
    let out = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(root)
        .output()
        .map_err(|e| format!("git ls-files: {e}"))?;
    if !out.status.success() {
        return Err("git ls-files failed".into());
    }
    let mut found = Vec::new();
    for name in out.stdout.split(|&b| b == 0).filter(|n| !n.is_empty()) {
        let Ok(name) = std::str::from_utf8(name) else {
            continue;
        };
        if name.starts_with(SKIPPED) {
            continue;
        }
        // A tracked path that is gone from the tree or is not text is not
        // a case for this check.
        let Ok(bytes) = std::fs::read(root.join(name)) else {
            continue;
        };
        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };
        for line in cyrillic_lines(&text) {
            found.push(format!("{name}:{line}"));
        }
    }
    if found.is_empty() {
        return Ok(());
    }
    let total = found.len();
    found.truncate(20);
    Err(format!(
        "{total} lines with Cyrillic letters (the repository is in English): {}",
        found.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_lines_with_cyrillic() {
        let text = "plain\nstage \u{424}9 here\n\nmore\n\u{43a}\u{43e}\u{434}\n";
        assert_eq!(cyrillic_lines(text), vec![2, 5]);
    }

    #[test]
    fn tracked_files_are_english() {
        check(&crate::root()).unwrap();
    }

    #[test]
    fn latin_and_symbols_pass() {
        assert!(cyrillic_lines("caf\u{e9} \u{2192} \u{3c0} \u{3a9}\n").is_empty());
    }
}
