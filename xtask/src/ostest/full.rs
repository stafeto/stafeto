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

fn fits(files: &[(String, Vec<u8>)], name: &str, bytes: usize) -> bool {
    files.len() < BATCH_TESTS
        && files.iter().map(|f| f.1.len()).sum::<usize>() + bytes <= BATCH_BYTES
        && entries(
            files
                .iter()
                .map(|f| f.0.as_str())
                .chain(std::iter::once(name)),
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
    let mut files = Vec::new();
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
        if !fits(&files, &test.name, bytes.len()) && !files.is_empty() {
            batches.push(std::mem::take(&mut files));
        }
        if !fits(&files, &test.name, bytes.len()) {
            record(
                &mut rows,
                &test.name,
                "IMAGE",
                Ended::Failed("single ELF exceeds existing image budget".to_owned()),
                &source,
                &macros,
            );
            continue;
        }
        contents.insert(test.name.clone(), source);
        files.push((test.name.clone(), bytes));
    }
    if !files.is_empty() {
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
                    rootfs::os_test(&files),
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
                let mut rows = rows.lock().unwrap_or_else(PoisonError::into_inner);
                for (name, _) in files {
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
    fn census_requires_each_expected_terminal_row_exactly_once() {
        let wanted: Vec<String> = vec!["basic/a".into(), "basic/b".into()];
        let a = (wanted[0].clone(), "FAIL", "LINK", "undefined symbol".into());
        let b = (wanted[1].clone(), "PASS", "RUNTIME", "exit: 0".into());
        assert!(validate_rows(&[a.clone(), b.clone()], &wanted).is_ok());
        assert!(validate_rows(std::slice::from_ref(&a), &wanted).is_err());
        assert!(validate_rows(&[a.clone(), a, b], &wanted).is_err());
    }

    #[test]
    fn batch_reserves_existing_storage_and_bounds_guest_deadlines() {
        let files = vec![("basic/a/small".into(), vec![0; BATCH_BYTES - 1])];
        assert!(fits(&files, "basic/b/other", 1));
        assert!(!fits(&files, "basic/b/other", 2));
        let files = (0..BATCH_TESTS)
            .map(|n| (format!("basic/a/t{n}"), vec![]))
            .collect::<Vec<_>>();
        assert!(!fits(&files, "basic/b/other", 1));
    }
}
