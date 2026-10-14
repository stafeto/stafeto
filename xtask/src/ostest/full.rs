// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Complete basic census, with independent outcomes and bounded guest batches.

use super::*;

const TEST_COUNT: usize = 1187;
const BATCH_TESTS: usize = 48;
// Half the existing RAM storage remains available for runtime files and metadata.
const BATCH_BYTES: usize = 8 * 1024 * 1024;
const BATCH_ENTRIES: usize = 900;

type CensusRow = (String, &'static str, &'static str, String);

const ABORT_DIAGNOSTIC: &str = "[ERROR abort@src/header/stdlib/mod.rs:120] Abort\n";

fn expected_abort_diagnostic(name: &str, phase: &str, text: &str, code: i64) -> bool {
    // The parent checks WIFSIGNALED and SIGABRT; libc logs in the child.
    // Preserve that exact diagnostic without accepting arbitrary exit-0 output.
    name == "basic/stdlib/abort" && phase == "RUNTIME" && text == ABORT_DIAGNOSTIC && code == 0
}

fn record(
    rows: &mut Vec<CensusRow>,
    name: &str,
    phase: &'static str,
    ended: Ended,
    source: &str,
    macros: &str,
) {
    let (result, text) = match ended {
        Ended::Exited(text, 0) if text == "exit: 0\n" => ("PASS", text),
        Ended::Exited(text, code) if expected_abort_diagnostic(name, phase, &text, code) => {
            ("PASS", text)
        }
        Ended::Exited(text, code) if code < 128 && unclaimed_option(source, macros).is_some() => {
            ("UNSUPPORTED", text)
        }
        Ended::Exited(text, _) | Ended::Failed(text) => ("FAIL", text),
    };
    println!(
        "os-test-full {name}: {result} {phase} ({})",
        first_line(&text)
    );
    rows.push((name.to_owned(), result, phase, text));
}

fn batch_finished(log: &str) -> bool {
    log.lines()
        .any(|line| line == "init: os-test-run ended: exit code 0, not restarted")
}

fn write_rows(rows: &[CensusRow]) -> Result<(), String> {
    let mut ordered = rows.to_vec();
    ordered.sort_by(|a, b| a.0.cmp(&b.0));
    let dir = target_dir().join("measure");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let mut text = "test\tresult\tphase\toutcome\n".to_owned();
    for (name, result, phase, detail) in ordered {
        text.push_str(&format!(
            "{name}\t{result}\t{phase}\t{}\n",
            detail.trim_end().replace(['\t', '\n', '\r'], " ")
        ));
    }
    std::fs::write(dir.join("os-test-full-basic.tsv"), text).map_err(|e| e.to_string())
}

#[derive(Default)]
struct Batch {
    tests: Vec<(String, Vec<u8>)>,
    fixtures: Vec<(String, Vec<u8>)>,
}

fn source_fixture(name: &str, source: &str) -> Option<(String, Vec<u8>)> {
    matches!(name, "basic/unistd/faccessat" | "basic/unistd/fchownat")
        .then(|| (format!("{name}.c"), source.as_bytes().to_vec()))
}

fn fits(batch: &Batch, name: &str, bytes: usize, fixture: Option<&(String, Vec<u8>)>) -> bool {
    batch.tests.len() < BATCH_TESTS
        && batch
            .tests
            .iter()
            .chain(&batch.fixtures)
            .map(|f| f.1.len())
            .sum::<usize>()
            + bytes
            + fixture.map_or(0, |f| f.1.len())
            <= BATCH_BYTES
        && entries(
            batch
                .tests
                .iter()
                .chain(&batch.fixtures)
                .map(|f| f.0.as_str())
                .chain(std::iter::once(name))
                .chain(fixture.map(|f| f.0.as_str())),
        ) <= BATCH_ENTRIES
}

fn entries<'a>(names: impl Iterator<Item = &'a str>) -> usize {
    let mut directories = std::collections::BTreeSet::new();
    let mut files = 0;
    for name in names {
        files += 1;
        for (at, _) in name.match_indices('/') {
            directories.insert(&name[..at]);
        }
    }
    // Root, devices, licence and runner list are accounted for conservatively.
    files + directories.len() + 32
}

/// Individual corpus failures are census rows; missing tools remain command failures.
pub fn run(jobs: usize) -> Result<(), String> {
    let begun = Instant::now();
    crate::relibc()?;
    crate::busybox_build()?;
    crate::run_cmd(
        Command::new("python3")
            .arg(crate::root().join("tools/build-os-test.py"))
            .arg("--full-basic"),
    )?;
    let work = target_dir().join("os-test-full");
    let tests = tests_of(&work)?;
    let unique: std::collections::BTreeSet<_> = tests.iter().map(|t| &t.name).collect();
    if tests.len() != TEST_COUNT || unique.len() != TEST_COUNT {
        return Err(format!(
            "full basic inventory: {} rows, {} unique, expected {TEST_COUNT}",
            tests.len(),
            unique.len()
        ));
    }
    let sources = std::fs::read_to_string(work.join("sources.txt")).map_err(|e| e.to_string())?;
    let sources: std::collections::BTreeMap<_, _> = sources
        .lines()
        .map(|line| {
            line.split_once('\t')
                .ok_or_else(|| "bad full-basic sources row".to_owned())
        })
        .collect::<Result<_, _>>()?;
    let macros = unistd_macros()?;
    let bootstrap = work.join("empty-main.o");
    crate::run_cmd(
        Command::new("python3")
            .arg(crate::root().join("tools/check-os-test-headers.py"))
            .arg("--bootstrap")
            .arg(&bootstrap),
    )?;
    let link_dir = work.join("link");
    let link = ProbeLink::new(&bootstrap.display().to_string(), &link_dir)?;
    let objcopy = llvm_tool("llvm-objcopy")?;
    let objdump = llvm_tool("llvm-objdump")?;
    let mut rows = Vec::new();
    let mut batches = Vec::new();
    let mut files = Batch::default();
    let mut contents = std::collections::BTreeMap::new();
    for (number, test) in tests.iter().enumerate() {
        let path = sources
            .get(test.name.as_str())
            .ok_or_else(|| format!("missing source {}", test.name))?;
        let source = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        if let Some(failed) = test.built.strip_prefix('!') {
            record(
                &mut rows,
                &test.name,
                "COMPILE",
                Ended::Exited(format!("{failed}\n"), 1),
                &source,
                &macros,
            );
            continue;
        }
        let scratch = link_dir.join(format!("test-{number}"));
        let elf = link_dir.join(format!("test-{number}.elf"));
        let result = link.link(&test.built, &scratch, &elf);
        if let Err(error) = result {
            let _ = std::fs::remove_dir_all(&scratch);
            if error.starts_with("native linker exited ") {
                record(
                    &mut rows,
                    &test.name,
                    "LINK",
                    Ended::Exited(error, 1),
                    &source,
                    &macros,
                );
                continue;
            }
            write_rows(&rows)?;
            return Err(format!("link infrastructure for {}: {error}", test.name));
        }
        crate::disasm::erratum_835769(&elf, &objdump)?;
        crate::disasm::erratum_843419(&elf)?;
        let stripped = link_dir.join(format!("test-{number}.stripped"));
        crate::run_cmd(
            Command::new(&objcopy)
                .arg("--strip-all")
                .arg(&elf)
                .arg(&stripped),
        )?;
        let bytes = std::fs::read(&stripped).map_err(|e| e.to_string())?;
        for path in [&elf, &stripped] {
            std::fs::remove_file(path).map_err(|e| e.to_string())?;
        }
        std::fs::remove_dir_all(&scratch).map_err(|e| e.to_string())?;
        let fixture = source_fixture(&test.name, &source);
        if !fits(&files, &test.name, bytes.len(), fixture.as_ref()) && !files.tests.is_empty() {
            batches.push(std::mem::take(&mut files));
        }
        if !fits(&files, &test.name, bytes.len(), fixture.as_ref()) {
            record(
                &mut rows,
                &test.name,
                "IMAGE",
                Ended::Failed("single ELF and fixtures exceed existing image budget".to_owned()),
                &source,
                &macros,
            );
            continue;
        }
        contents.insert(test.name.clone(), source);
        files.tests.push((test.name.clone(), bytes));
        if let Some(fixture) = fixture {
            files.fixtures.push(fixture);
        }
    }
    if !files.tests.is_empty() {
        batches.push(files);
    }
    write_rows(&rows)?;
    let kernel = build(Variant::Normal)?;
    let rows = Arc::new(Mutex::new(rows));
    let contents = Arc::new(contents);
    let macros = Arc::new(macros);
    let failures = Arc::new(Mutex::new(Vec::new()));
    let mut boots = Vec::new();
    for (number, files) in batches.into_iter().enumerate() {
        let kernel = kernel.clone();
        let rows = Arc::clone(&rows);
        let contents = Arc::clone(&contents);
        let macros = Arc::clone(&macros);
        let failures = Arc::clone(&failures);
        boots.push(crate::jobs::job(
            &format!("os-test full basic {number}"),
            move || {
                let result = boot(
                    &kernel,
                    &format!("os-test-full-{number}.img"),
                    rootfs::os_test_with_fixtures(&files.tests, &files.fixtures),
                    TIMEOUT,
                );
                let log = match result {
                    Ok((log, _)) => log,
                    Err(error) => {
                        failures
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .push(error);
                        String::new()
                    }
                };
                if !batch_finished(&log) {
                    failures
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(format!(
                            "full basic batch {number} did not finish successfully"
                        ));
                }
                let mut rows = rows.lock().unwrap_or_else(PoisonError::into_inner);
                for (name, _) in files.tests {
                    record(
                        &mut rows,
                        &name,
                        "RUNTIME",
                        outcome(&log, &name),
                        &contents[&name],
                        &macros,
                    );
                }
                write_rows(&rows)
            },
        ));
    }
    crate::jobs::run_all(boots, jobs)?;
    let rows = rows.lock().unwrap_or_else(PoisonError::into_inner);
    let did_not_start = rows
        .iter()
        .filter(|row| row.3.contains("the test did not start"))
        .count();
    let no_end = rows
        .iter()
        .filter(|row| row.3.contains("no end of the test"))
        .count();
    println!("os-test full basic incomplete: {did_not_start} did not start, {no_end} no end");
    validate_rows(
        &rows,
        &tests.iter().map(|t| t.name.clone()).collect::<Vec<_>>(),
    )?;
    let failures = failures.lock().unwrap_or_else(PoisonError::into_inner);
    println!(
        "os-test full basic: {} PASS, {} FAIL, {} UNSUPPORTED of {}, {:.3}s",
        rows.iter().filter(|r| r.1 == "PASS").count(),
        rows.iter().filter(|r| r.1 == "FAIL").count(),
        rows.iter().filter(|r| r.1 == "UNSUPPORTED").count(),
        rows.len(),
        begun.elapsed().as_secs_f64()
    );
    if !failures.is_empty() {
        return Err(format!(
            "full basic boot infrastructure: {}",
            failures.join("; ")
        ));
    }
    Ok(())
}

fn validate_rows(rows: &[CensusRow], expected: &[String]) -> Result<(), String> {
    let names: std::collections::BTreeSet<_> = rows.iter().map(|r| &r.0).collect();
    let wanted: std::collections::BTreeSet<_> = expected.iter().collect();
    if rows.len() != expected.len() || names != wanted {
        return Err("full basic census has missing, duplicate or unexpected terminal rows".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abort_diagnostic_requires_exact_case_phase_and_successful_parent() {
        let classify = |name, phase, ended| {
            let mut rows = Vec::new();
            record(&mut rows, name, phase, ended, "", "");
            rows.pop().unwrap()
        };
        let row = classify(
            "basic/stdlib/abort",
            "RUNTIME",
            Ended::Exited(ABORT_DIAGNOSTIC.into(), 0),
        );
        assert_eq!(row.1, "PASS");
        assert_eq!(row.3, ABORT_DIAGNOSTIC);
        for (name, phase, ended) in [
            (
                "basic/stdlib/abort",
                "RUNTIME",
                Ended::Exited(format!("{ABORT_DIAGNOSTIC}extra\n"), 0),
            ),
            (
                "basic/stdlib/abort",
                "RUNTIME",
                Ended::Exited("Abort\n".into(), 0),
            ),
            (
                "basic/stdlib/exit",
                "RUNTIME",
                Ended::Exited(ABORT_DIAGNOSTIC.into(), 0),
            ),
            (
                "basic/stdlib/abort",
                "LINK",
                Ended::Exited(ABORT_DIAGNOSTIC.into(), 0),
            ),
            (
                "basic/stdlib/abort",
                "COMPILE",
                Ended::Exited(ABORT_DIAGNOSTIC.into(), 0),
            ),
            (
                "basic/stdlib/abort",
                "RUNTIME",
                Ended::Exited(ABORT_DIAGNOSTIC.into(), 1),
            ),
            (
                "basic/stdlib/abort",
                "RUNTIME",
                Ended::Exited(ABORT_DIAGNOSTIC.into(), 134),
            ),
            (
                "basic/stdlib/abort",
                "RUNTIME",
                Ended::Failed(ABORT_DIAGNOSTIC.into()),
            ),
        ] {
            assert_eq!(classify(name, phase, ended).1, "FAIL");
        }
    }

    #[test]
    fn census_classification_preserves_output_status_and_optional_boundaries() {
        for (phase, source, macros, ended, wanted) in [
            (
                "RUNTIME",
                "",
                "",
                Ended::Exited("exit: 0\n".into(), 0),
                "PASS",
            ),
            (
                "RUNTIME",
                "",
                "",
                Ended::Exited("unexpected output\n".into(), 0),
                "FAIL",
            ),
            (
                "RUNTIME",
                "",
                "",
                Ended::Exited("failure\n".into(), 1),
                "FAIL",
            ),
            (
                "RUNTIME",
                "/*[XSI]*/",
                "",
                Ended::Exited("failure\n".into(), 1),
                "UNSUPPORTED",
            ),
            (
                "RUNTIME",
                "/*[XSI]*/",
                "#define _XOPEN_UNIX 1\n",
                Ended::Exited("failure\n".into(), 1),
                "FAIL",
            ),
            (
                "RUNTIME",
                "/*[XSI]*/",
                "",
                Ended::Exited("signal\n".into(), 134),
                "FAIL",
            ),
            (
                "RUNTIME",
                "/*[XSI]*/",
                "",
                Ended::Failed("timeout: the test did not start\n".into()),
                "FAIL",
            ),
            (
                "RUNTIME",
                "/*[XSI]*/",
                "",
                Ended::Failed("timeout: no end of the test\n".into()),
                "FAIL",
            ),
            (
                "COMPILE",
                "",
                "",
                Ended::Exited("undeclared\n".into(), 1),
                "FAIL",
            ),
            (
                "COMPILE",
                "/*[XSI]*/",
                "",
                Ended::Exited("undeclared\n".into(), 1),
                "UNSUPPORTED",
            ),
            (
                "LINK",
                "",
                "",
                Ended::Exited("undefined\n".into(), 1),
                "FAIL",
            ),
            (
                "LINK",
                "/*[XSI]*/",
                "",
                Ended::Exited("undefined\n".into(), 1),
                "UNSUPPORTED",
            ),
        ] {
            let mut rows = Vec::new();
            record(
                &mut rows,
                "basic/check/ordinary",
                phase,
                ended,
                source,
                macros,
            );
            assert_eq!(rows[0].1, wanted, "{phase} {source} {macros}");
        }
    }

    #[test]
    fn full_batch_requires_successful_runner_completion() {
        assert!(batch_finished(
            "test output\ninit: os-test-run ended: exit code 0, not restarted\n"
        ));
        assert!(!batch_finished("@@os-test end basic/check exit 0\n"));
        assert!(!batch_finished(
            "init: os-test-run ended: exit code 1, not restarted\n"
        ));
        assert!(!batch_finished(
            "init: os-test-run ended: signal 6, not restarted\n"
        ));
    }

    #[test]
    fn census_requires_each_expected_terminal_row_exactly_once() {
        let wanted: Vec<String> = vec!["basic/a".into(), "basic/b".into()];
        let a = (wanted[0].clone(), "FAIL", "LINK", "undefined symbol".into());
        let b = (wanted[1].clone(), "PASS", "RUNTIME", "exit: 0".into());
        assert!(validate_rows(&[a.clone(), b.clone()], &wanted).is_ok());
        assert!(validate_rows(std::slice::from_ref(&a), &wanted).is_err());
        assert!(validate_rows(&[a.clone(), a, b], &wanted).is_err());
    }

    #[test]
    fn source_fixtures_are_exact_and_only_for_two_path_tests() {
        let source = "/* normalized pinned bytes */\nint main(void) { return 0; }\n";
        for name in ["basic/unistd/faccessat", "basic/unistd/fchownat"] {
            assert_eq!(
                source_fixture(name, source),
                Some((format!("{name}.c"), source.as_bytes().to_vec()))
            );
        }
        for name in [
            "basic/unistd/access",
            "basic/unistd/faccessat.c",
            "io/faccessat",
        ] {
            assert!(source_fixture(name, source).is_none());
        }
    }

    #[test]
    fn fixture_bytes_and_entries_consume_budget_without_consuming_test_slots() {
        let fixture = ("basic/new.c".to_owned(), vec![0]);
        let bytes = Batch {
            fixtures: vec![("basic/existing.c".into(), vec![0; BATCH_BYTES - 2])],
            ..Batch::default()
        };
        assert!(fits(&bytes, "basic/new", 1, Some(&fixture)));
        assert!(!fits(&bytes, "basic/new", 2, Some(&fixture)));
        let slots = Batch {
            tests: (0..47).map(|n| (format!("basic/t{n}"), vec![])).collect(),
            fixtures: vec![("basic/a.c".into(), vec![]), ("basic/b.c".into(), vec![])],
        };
        assert!(fits(&slots, "basic/new", 1, Some(&fixture)));
        let entries = Batch {
            fixtures: (0..866).map(|n| (format!("basic/f{n}"), vec![])).collect(),
            ..Batch::default()
        };
        assert!(fits(&entries, "basic/new", 0, None));
        assert!(!fits(&entries, "basic/new", 0, Some(&fixture)));
    }

    #[test]
    fn batch_reserves_existing_storage_and_bounds_guest_deadlines() {
        let files = Batch {
            tests: vec![("basic/a/small".into(), vec![0; BATCH_BYTES - 1])],
            ..Batch::default()
        };
        assert!(fits(&files, "basic/b/other", 1, None));
        assert!(!fits(&files, "basic/b/other", 2, None));
        let files = Batch {
            tests: (0..BATCH_TESTS)
                .map(|n| (format!("basic/a/t{n}"), vec![]))
                .collect(),
            ..Batch::default()
        };
        assert!(!fits(&files, "basic/b/other", 1, None));
    }
}
