// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Guards of the header and coverage measures: a list checked in beside the
//! tests names what passed once, and a run in which one of them no longer
//! passes fails. What passes beyond the list is counted and told, so that the
//! list can grow (`STAFETO_BLESS=1` rewrites it from the run).

use std::collections::BTreeSet;
use std::path::Path;

/// The names in a guard list: one a line, `#` starts a comment.
fn names_of(text: &str) -> BTreeSet<&str> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

/// Checks `passed` against the list at `list`; `what` names the measure in
/// the messages. With `STAFETO_BLESS` set the list becomes `passed`, headed
/// by `header`.
pub(crate) fn check(
    what: &str,
    header: &str,
    passed: &BTreeSet<String>,
    list: &Path,
) -> Result<(), String> {
    if std::env::var_os("STAFETO_BLESS").is_some() {
        let mut text = format!("# {header}\n");
        for name in passed {
            text.push_str(name);
            text.push('\n');
        }
        std::fs::write(list, text).map_err(|e| format!("{}: {e}", list.display()))?;
        println!(
            "{what}: {} names written to {}",
            passed.len(),
            list.display()
        );
        return Ok(());
    }
    let text = std::fs::read_to_string(list).map_err(|e| format!("{}: {e}", list.display()))?;
    verdict(what, passed, &text, &list.display().to_string())
}

fn verdict(
    what: &str,
    passed: &BTreeSet<String>,
    list_text: &str,
    list_name: &str,
) -> Result<(), String> {
    let guarded = names_of(list_text);
    let lost: Vec<&str> = guarded
        .iter()
        .copied()
        .filter(|n| !passed.contains(*n))
        .collect();
    let new = passed
        .iter()
        .filter(|n| !guarded.contains(n.as_str()))
        .count();
    println!(
        "{what}: {} guarded, {} pass, {} pass beyond the list{}",
        guarded.len(),
        passed.len(),
        new,
        if new > 0 {
            " (STAFETO_BLESS=1 adds them)"
        } else {
            ""
        }
    );
    if lost.is_empty() {
        return Ok(());
    }
    let shown: Vec<&str> = lost.iter().copied().take(20).collect();
    Err(format!(
        "{what}: {} of the names in {list_name} no longer pass: {}{}",
        lost.len(),
        shown.join(", "),
        if lost.len() > shown.len() {
            ", ..."
        } else {
            ""
        }
    ))
}

/// The tests with outcome `good` in the table of the os-test headers
/// (`test`, `outcome`, ... a line each; `#` lines and the header row apart).
pub(crate) fn headers_passed(table: &str) -> BTreeSet<String> {
    table
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let mut c = l.split('\t');
            let (test, outcome) = (c.next()?, c.next()?);
            (outcome == "good").then(|| test.to_owned())
        })
        .collect()
}

/// The interfaces the coverage table says exist (`xsh NAME`) and the
/// headers the header table says are present (`xbd HEADER`).
pub(crate) fn coverage_passed(interfaces: &str, headers: &str) -> BTreeSet<String> {
    let mut passed = BTreeSet::new();
    for line in interfaces.lines().filter(|l| !l.starts_with('#')) {
        let c: Vec<&str> = line.split('\t').collect();
        if c.len() >= 6 && matches!(c[5], "exported-symbol" | "header-macro") {
            passed.insert(format!("xsh {}", c[0]));
        }
    }
    for line in headers.lines().filter(|l| !l.starts_with('#')) {
        let c: Vec<&str> = line.split('\t').collect();
        if c.len() >= 5 && c[4] == "present" {
            passed.insert(format!("xbd {}", c[0]));
        }
    }
    passed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    #[test]
    fn a_name_that_no_longer_passes_fails_the_guard() {
        let list = "# header\nfoo\nbar\n";
        assert!(verdict("t", &set(&["foo", "bar", "baz"]), list, "list").is_ok());
        let error = verdict("t", &set(&["foo", "baz"]), list, "list").unwrap_err();
        assert!(
            error.contains("bar") && error.contains("1 of the names"),
            "{error}"
        );
    }

    #[test]
    fn the_tables_are_read_by_their_columns() {
        let headers = "# os-test x\ntest\toutcome\tprofile\tstage\tdiagnostic\n\
                       include/a/b.c\tgood\tp\tlink\t\ninclude/a/c.c\tundeclared\tp\tcompile\tx\n";
        assert_eq!(headers_passed(headers), set(&["include/a/b.c"]));
        let interfaces = "# i\nname\tpage\trequirement\theaders\toption_codes\tavailability\tclaimed\n\
                          f\tf\trequired\tx.h\t-\texported-symbol\tyes\n\
                          g\tg\trequired\tx.h\t-\tunresolved\tyes\n\
                          h\th\trequired\tx.h\t-\tstub-enosys\tyes\n\
                          M\tM\trequired\tx.h\t-\theader-macro\tyes\n";
        let xbd = "# h\nheader\tpage\trequirement\toption_codes\tavailable\n\
                   a.h\ta.h\trequired\t-\tpresent\nb.h\tb.h\trequired\t-\tmissing\n";
        assert_eq!(
            coverage_passed(interfaces, xbd),
            set(&["xsh f", "xsh M", "xbd a.h"])
        );
    }
}
