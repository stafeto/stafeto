// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Symbol inventory for the POSIX.1-2024 System Interfaces volume.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use crate::{PROGRAM_TARGET, cargo, llvm_tool, relibc, run_cmd, stdout_of, target_dir};

const INVENTORY: &str = include_str!("../../tests/posix/2024-xsh.tsv");

#[derive(Debug)]
struct Interface<'a> {
    name: &'a str,
    page: &'a str,
    requirement: &'a str,
    headers: &'a str,
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

fn defined_names(listing: &str) -> BTreeSet<&str> {
    listing
        .lines()
        .filter_map(|line| {
            let words: Vec<_> = line.split_ascii_whitespace().collect();
            let [.., kind, name] = words.as_slice() else {
                return None;
            };
            (kind.len() == 1 && kind.as_bytes()[0].is_ascii_uppercase() && *kind != "U")
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

fn library_paths(args: &[String]) -> Result<(std::path::PathBuf, std::path::PathBuf), String> {
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
            ))
        }
        [flag, libc, flag2, crt] if flag == "--libc" && flag2 == "--crt" => {
            Ok((libc.into(), crt.into()))
        }
        _ => Err("usage: cargo xtask coverage [--libc PATH --crt PATH]".to_owned()),
    }
}

pub(crate) fn run(args: &[String]) -> Result<(), String> {
    let (libc, crt) = library_paths(args)?;
    let mut names = names_in(&libc)?;
    names.extend(names_in(&crt)?);
    let rows = interfaces(INVENTORY)?;
    let mut counts = BTreeMap::<(&str, bool), usize>::new();
    let mut output = String::from(
        "# POSIX.1-2024 XSH symbol inventory\nname\tpage\trequirement\theaders\toption_codes\texported_symbol\n",
    );
    for row in &rows {
        let present = names.contains(row.name);
        *counts.entry((row.requirement, present)).or_default() += 1;
        output.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\n",
            row.name,
            row.page,
            row.requirement,
            row.headers,
            row.option_codes,
            if present {
                "present"
            } else {
                "no-exported-symbol"
            },
        ));
    }
    let path = target_dir().join("measure/posix-coverage.tsv");
    std::fs::create_dir_all(path.parent().expect("measure path has parent"))
        .map_err(|error| format!("{}: {error}", path.display()))?;
    std::fs::write(&path, output).map_err(|error| format!("{}: {error}", path.display()))?;
    for requirement in ["required", "option"] {
        println!(
            "XSH {requirement}: {} exported names present, {} without an exported symbol",
            counts.get(&(requirement, true)).copied().unwrap_or(0),
            counts.get(&(requirement, false)).copied().unwrap_or(0),
        );
    }
    println!("XSH symbol inventory: {}", path.display());
    println!("Header macros need a separate check; guest tests establish runtime behavior.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_keeps_required_and_optional_interfaces() {
        let rows = interfaces(INVENTORY).unwrap();
        assert!(rows.len() > 1_200);
        assert!(
            rows.iter()
                .any(|r| r.name == "getentropy" && r.requirement == "required")
        );
        assert!(
            rows.iter()
                .any(|r| r.name == "mq_open" && r.requirement == "option")
        );
    }

    #[test]
    fn archive_listing_uses_defined_global_names() {
        let listing = "archive.o:\n00000000 T getentropy\n         U absent\n00000000 t local\n";
        assert_eq!(defined_names(listing), BTreeSet::from(["getentropy"]));
    }
}
