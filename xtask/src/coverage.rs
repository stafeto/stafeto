// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Symbol inventory for the POSIX.1-2024 System Interfaces volume. A
//! function that exists in relibc but answers ENOSYS on stafeto (found by
//! `stubs`, in relibc's sources) is a stub and does not count as covered.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::stubs;
use crate::{PROGRAM_TARGET, cargo, llvm_tool, relibc, run_cmd, stdout_of, target_dir};

const INVENTORY: &str = include_str!("../../tests/posix/2024-xsh.tsv");
const XBD_HEADERS: &str = include_str!("../../tests/posix/2024-xbd-headers.tsv");

#[derive(Debug)]
struct Interface<'a> {
    name: &'a str,
    page: &'a str,
    requirement: &'a str,
    headers: &'a str,
    option_codes: &'a str,
}

struct Header<'a> {
    name: &'a str,
    page: &'a str,
    requirement: &'a str,
    option_codes: &'a str,
}

fn interfaces(input: &str) -> Result<Vec<Interface<'_>>, String> {
    let mut seen = BTreeSet::new();
    let mut rows = Vec::new();
    for (index, line) in input.lines().enumerate() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let parts: Vec<_> = line.split('\t').collect();
        if parts.len() != 5 || !matches!(parts[2], "required" | "option") {
            return Err(format!("XSH inventory line {}: invalid fields", index + 1));
        }
        if parts[0].is_empty() || parts[1].is_empty() || parts[3].is_empty() {
            return Err(format!(
                "XSH inventory line {}: empty name, page or header",
                index + 1
            ));
        }
        if !seen.insert(parts[0]) {
            return Err(format!(
                "XSH inventory line {}: duplicate {}",
                index + 1,
                parts[0]
            ));
        }
        rows.push(Interface {
            name: parts[0],
            page: parts[1],
            requirement: parts[2],
            headers: parts[3],
            option_codes: parts[4],
        });
    }
    if rows.is_empty() {
        return Err("XSH inventory is empty".to_owned());
    }
    Ok(rows)
}

fn headers(input: &str) -> Result<Vec<Header<'_>>, String> {
    let mut seen = BTreeSet::new();
    let mut rows = Vec::new();
    for (index, line) in input.lines().enumerate() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let parts: Vec<_> = line.split('\t').collect();
        if parts.len() != 4 || !matches!(parts[2], "required" | "option") {
            return Err(format!("XBD inventory line {}: invalid fields", index + 1));
        }
        if parts[0].is_empty() || parts[1].is_empty() || !seen.insert(parts[0]) {
            return Err(format!(
                "XBD inventory line {}: empty or duplicate header",
                index + 1
            ));
        }
        rows.push(Header {
            name: parts[0],
            page: parts[1],
            requirement: parts[2],
            option_codes: parts[3],
        });
    }
    if rows.len() != 86
        || rows
            .iter()
            .filter(|row| row.requirement == "required")
            .count()
            != 70
    {
        return Err("XBD inventory needs 86 headers, including 70 required".to_owned());
    }
    Ok(rows)
}

fn defined_names(listing: &str) -> BTreeSet<&str> {
    listing
        .lines()
        .filter_map(|line| {
            let words: Vec<_> = line.split_ascii_whitespace().collect();
            let [.., kind, name] = words.as_slice() else {
                return None;
            };
            (kind.len() == 1
                && kind.as_bytes()[0].is_ascii_uppercase()
                && !matches!(*kind, "U" | "N"))
            .then_some(*name)
        })
        .collect()
}

fn names_in(library: &Path) -> Result<BTreeSet<String>, String> {
    let listing = stdout_of(
        Command::new(llvm_tool("llvm-nm")?)
            .args(["--defined-only", "-g", "--no-sort"])
            .arg(library),
    )?;
    Ok(defined_names(&listing)
        .into_iter()
        .map(str::to_owned)
        .collect())
}

fn macro_names(listing: &str) -> BTreeSet<&str> {
    listing
        .lines()
        .filter_map(|line| line.strip_prefix("#define "))
        .filter_map(|rest| {
            rest.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .next()
        })
        .filter(|name| !name.is_empty())
        .collect()
}

struct HeaderScan {
    definitions: BTreeMap<String, BTreeSet<String>>,
    resource_include: PathBuf,
    missing: Vec<String>,
    failed: Vec<String>,
}

fn checked_stdout(command: &mut Command) -> Result<String, String> {
    let output = command
        .output()
        .map_err(|error| format!("{command:?}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{command:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout).map_err(|error| error.to_string())
}

fn header_macros(rows: &[Interface<'_>], include: &Path) -> Result<HeaderScan, String> {
    let brew = Path::new("/opt/homebrew/opt/llvm/bin/clang");
    let clang = if brew.exists() {
        brew.to_path_buf()
    } else {
        PathBuf::from("clang")
    };
    let resource = checked_stdout(Command::new(&clang).arg("-print-resource-dir"))?;
    let resource_include = Path::new(resource.trim()).join("include");
    let headers: BTreeSet<_> = rows.iter().flat_map(|row| row.headers.split(',')).collect();
    let mut scan = HeaderScan {
        definitions: BTreeMap::new(),
        resource_include: resource_include.clone(),
        missing: Vec::new(),
        failed: Vec::new(),
    };
    for header in headers {
        if !include.join(header).exists() && !resource_include.join(header).exists() {
            scan.missing.push(header.to_owned());
            continue;
        }
        let output = checked_stdout(
            Command::new(&clang)
                .args(["--target=aarch64-linux-gnu", "-nostdinc", "-isystem"])
                .arg(include)
                .arg("-isystem")
                .arg(&resource_include)
                .args(["-include", header, "-E", "-dM", "-x", "c", "/dev/null"]),
        );
        match output {
            Ok(output) => {
                scan.definitions.insert(
                    header.to_owned(),
                    macro_names(&output)
                        .into_iter()
                        .map(str::to_owned)
                        .collect(),
                );
            }
            Err(_) => scan.failed.push(header.to_owned()),
        }
    }
    Ok(scan)
}

/// The libc archive, the startup archive, relibc's headers and its sources.
type Paths = (PathBuf, PathBuf, PathBuf, PathBuf);

fn library_paths(args: &[String]) -> Result<Paths, String> {
    match args {
        [] => {
            relibc()?;
            run_cmd(cargo().args([
                "build",
                "--release",
                "--target",
                PROGRAM_TARGET,
                "--package",
                "posix-crt",
            ]))?;
            Ok((
                target_dir().join("relibc/sysroot/lib/libc.a"),
                target_dir()
                    .join(PROGRAM_TARGET)
                    .join("release/libposix_crt.a"),
                target_dir().join("relibc/sysroot/include"),
                target_dir().join("relibc/source"),
            ))
        }
        [flag, libc, flag2, crt] if flag == "--libc" && flag2 == "--crt" => {
            let libc = PathBuf::from(libc);
            let include = libc
                .parent()
                .and_then(Path::parent)
                .ok_or("libc.a needs a sysroot/lib parent")?
                .join("include");
            let source = include
                .parent()
                .and_then(Path::parent)
                .ok_or("libc.a needs a sysroot/lib parent")?
                .join("source");
            Ok((libc, crt.into(), include, source))
        }
        _ => Err("usage: cargo xtask coverage [--libc PATH --crt PATH]".to_owned()),
    }
}

pub(crate) fn run(args: &[String]) -> Result<(), String> {
    let (libc, crt, include, source) = library_paths(args)?;
    let stubs = stubs::stub_functions(&stubs::Sources::read(&source)?);
    let mut names = names_in(&libc)?;
    names.extend(names_in(&crt)?);
    let rows = interfaces(INVENTORY)?;
    let xbd = headers(XBD_HEADERS)?;
    let scan = header_macros(&rows, &include)?;
    let unistd = crate::ostest::macros_of(&include)?;
    let mut counts = BTreeMap::<(&str, &str), usize>::new();
    // The same for the interfaces of options that unistd.h claims.
    let mut claimed_counts = BTreeMap::<&str, usize>::new();
    let mut output = String::from(
        "# POSIX.1-2024 XSH interface inventory\nname\tpage\trequirement\theaders\toption_codes\tavailability\tclaimed\n",
    );
    for row in &rows {
        let availability = if names.contains(row.name) && stubs.contains(row.name) {
            "stub-enosys"
        } else if names.contains(row.name) {
            "exported-symbol"
        } else if row.headers.split(',').any(|header| {
            scan.definitions
                .get(header)
                .is_some_and(|names| names.contains(row.name))
        }) {
            "header-macro"
        } else {
            "unresolved"
        };
        *counts.entry((row.requirement, availability)).or_default() += 1;
        let claimed = crate::ostest::unclaimed_need(row.option_codes, &unistd).is_none();
        if row.requirement == "option" && claimed {
            *claimed_counts.entry(availability).or_default() += 1;
        }
        output.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            row.name,
            row.page,
            row.requirement,
            row.headers,
            row.option_codes,
            availability,
            if claimed { "yes" } else { "no" },
        ));
    }
    let path = target_dir().join("measure/posix-coverage.tsv");
    std::fs::create_dir_all(path.parent().expect("measure path has parent"))
        .map_err(|error| format!("{}: {error}", path.display()))?;
    std::fs::write(&path, output).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut header_counts = BTreeMap::<(&str, bool), usize>::new();
    let mut header_output = String::from(
        "# POSIX.1-2024 XBD header inventory\nheader\tpage\trequirement\toption_codes\tavailable\n",
    );
    let mut required_missing = Vec::new();
    for row in &xbd {
        let available =
            include.join(row.name).exists() || scan.resource_include.join(row.name).exists();
        *header_counts
            .entry((row.requirement, available))
            .or_default() += 1;
        if row.requirement == "required" && !available {
            required_missing.push(row.name);
        }
        header_output.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            row.name,
            row.page,
            row.requirement,
            row.option_codes,
            if available { "present" } else { "missing" }
        ));
    }
    let header_path = target_dir().join("measure/posix-headers.tsv");
    std::fs::write(&header_path, header_output)
        .map_err(|error| format!("{}: {error}", header_path.display()))?;
    for requirement in ["required", "option"] {
        println!(
            "XSH {requirement}: {} exported symbols, {} header macros, {} ENOSYS stubs, {} unresolved",
            counts
                .get(&(requirement, "exported-symbol"))
                .copied()
                .unwrap_or(0),
            counts
                .get(&(requirement, "header-macro"))
                .copied()
                .unwrap_or(0),
            counts
                .get(&(requirement, "stub-enosys"))
                .copied()
                .unwrap_or(0),
            counts
                .get(&(requirement, "unresolved"))
                .copied()
                .unwrap_or(0)
        );
        let count = |availability| {
            counts
                .get(&(requirement, availability))
                .copied()
                .unwrap_or(0)
        };
        let covered = count("exported-symbol") + count("header-macro");
        let total = covered + count("stub-enosys") + count("unresolved");
        println!(
            "XSH {requirement} coverage: {covered} of {total} ({:.1} %), stubs do not count",
            100.0 * covered as f64 / total as f64
        );
    }
    let claimed = |availability| claimed_counts.get(availability).copied().unwrap_or(0);
    let covered = claimed("exported-symbol") + claimed("header-macro");
    let total = covered + claimed("stub-enosys") + claimed("unresolved");
    println!(
        "XSH option coverage of the options unistd.h claims: {covered} of {total} ({:.1} %)",
        100.0 * covered as f64 / total as f64
    );
    println!("XSH interface inventory: {}", path.display());
    println!(
        "XBD required headers: {} present, {} missing; option headers: {} present, {} missing",
        header_counts.get(&("required", true)).copied().unwrap_or(0),
        header_counts
            .get(&("required", false))
            .copied()
            .unwrap_or(0),
        header_counts.get(&("option", true)).copied().unwrap_or(0),
        header_counts.get(&("option", false)).copied().unwrap_or(0),
    );
    println!(
        "Missing required XBD headers: {}",
        required_missing.join(", ")
    );
    println!("XBD header inventory: {}", header_path.display());
    println!(
        "XSH headers: {} checked, {} missing, {} failed preprocessing",
        scan.definitions.len(),
        scan.missing.len(),
        scan.failed.len()
    );
    if !scan.missing.is_empty() {
        println!("Missing XSH headers: {}", scan.missing.join(", "));
    }
    if !scan.failed.is_empty() {
        println!("Headers requiring review: {}", scan.failed.join(", "));
    }
    println!("Guest tests establish runtime behavior and identify platform stubs.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_keeps_required_and_optional_interfaces() {
        let rows = interfaces(INVENTORY).unwrap();
        assert_eq!(rows.len(), 1_241);
        assert_eq!(
            rows.iter()
                .filter(|row| row.requirement == "required")
                .count(),
            1_035
        );
        assert!(
            rows.iter()
                .any(|r| r.name == "getentropy" && r.requirement == "required")
        );
        assert!(
            rows.iter()
                .any(|r| r.name == "mq_open" && r.requirement == "option")
        );
        for name in ["CMPLX", "CMPLXF", "CMPLXL"] {
            assert!(
                rows.iter()
                    .any(|r| r.name == name && r.requirement == "required")
            );
        }
        for name in [
            "FD_CLR", "FD_ISSET", "FD_SET", "FD_ZERO", "_Fork", "va_arg", "va_copy", "va_end",
            "va_start",
        ] {
            assert!(
                rows.iter()
                    .any(|r| r.name == name && r.requirement == "required")
            );
        }
        assert!(rows.iter().any(|r| r.name == "getdate_err"
            && r.requirement == "option"
            && r.option_codes == "XSI"));
        assert!(
            !rows
                .iter()
                .any(|r| matches!(r.name, "asctime_r" | "ctime_r"))
        );
        for (name, requirement) in [
            ("errno", "required"),
            ("tzname", "required"),
            ("in6addr_any", "option"),
            ("in6addr_loopback", "option"),
            ("signgam", "option"),
            ("daylight", "option"),
            ("timezone", "option"),
        ] {
            assert!(
                rows.iter()
                    .any(|row| row.name == name && row.requirement == requirement)
            );
        }
    }

    /// The stubs listed by hand name functions of the standard, so that a
    /// renamed or misspelt entry cannot stay unnoticed.
    #[test]
    fn confirmed_stubs_are_in_the_inventory() {
        let rows = interfaces(INVENTORY).unwrap();
        for name in stubs::CONFIRMED {
            assert!(rows.iter().any(|r| r.name == name), "{name}");
        }
    }

    #[test]
    fn xbd_inventory_covers_required_and_option_headers() {
        let rows = headers(XBD_HEADERS).unwrap();
        assert!(
            rows.iter()
                .any(|row| row.name == "aio.h" && row.requirement == "required")
        );
        assert!(
            rows.iter()
                .any(|row| row.name == "mqueue.h" && row.requirement == "option")
        );
    }

    #[test]
    fn archive_listing_uses_defined_global_names() {
        let listing = "archive.o:\n00000000 T getentropy\n         U absent\n00000000 N debug\n00000000 t local\n";
        assert_eq!(defined_names(listing), BTreeSet::from(["getentropy"]));
    }

    #[test]
    fn macro_listing_separates_function_like_definitions() {
        let listing = "#define fpclassify(x) classify(x)\n#define FD_SET(d,s) set(d,s)\n";
        assert_eq!(
            macro_names(listing),
            BTreeSet::from(["FD_SET", "fpclassify"])
        );
    }
}
