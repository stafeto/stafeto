// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The lines `pkg` prints for people and for `grep` (pk4-design R13, R10):
//! fields separated by one space, marks in square brackets at the end, in
//! the order of the names. Sizes are in megabytes of 10^6 bytes with one
//! digit after the point; a version made of a commit hash is short.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use pkgfmt::meta::short_version;
use proto_pkg::{ENTRY_DEPENDENCY, ENTRY_IMAGE, ENTRY_REVOKED};

/// `29.3 MB`: megabytes of 10^6 bytes, one digit after the point, rounded to the nearest tenth.
pub fn megabytes(bytes: u64) -> String {
    let tenths = (bytes + 50_000) / 100_000;
    format!("{}.{} MB", tenths / 10, tenths % 10)
}

/// The version `<version>-<release>` with a commit hash made short.
pub fn short(version: &str) -> String {
    match version.rsplit_once('-') {
        Some((v, release)) => format!("{}-{release}", short_version(v)),
        None => short_version(version).to_string(),
    }
}

/// A package that is installed, as `LIST` and `INFO` tell it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Installed {
    pub name: String,
    pub version: String,
    pub sha256: [u8; 32],
    pub flags: u32,
    pub repository: String,
    pub provides: Vec<String>,
    pub depends: Vec<String>,
}

impl Installed {
    pub fn in_image(&self) -> bool {
        self.flags & ENTRY_IMAGE != 0
    }
}

/// A package of the cached index of a repository.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Available {
    pub repository: String,
    pub name: String,
    pub version: String,
    pub sha256: [u8; 32],
    pub provides: Vec<String>,
    pub summary: String,
}

/// The marks of an installed package, in the order `[image]`, `[dependency]`, `[revoked]`.
fn marks(flags: u32) -> String {
    let mut out = String::new();
    for (bit, word) in [
        (ENTRY_IMAGE, "[image]"),
        (ENTRY_DEPENDENCY, "[dependency]"),
        (ENTRY_REVOKED, "[revoked]"),
    ] {
        if flags & bit != 0 {
            out.push(' ');
            out.push_str(word);
        }
    }
    out
}

fn repository_of(i: &Installed) -> String {
    if i.in_image() {
        String::new()
    } else {
        format!(" {}", i.repository)
    }
}

/// `pkg list`: the installed packages by name; with `all`, the packages of the
/// cached indexes that are not installed (`[available]`) and the installed
/// ones whose index record has another SHA-256 (`[upgradable]`).
pub fn list(installed: &[Installed], available: &[Available], all: bool) -> Vec<String> {
    let mut rows: Vec<(String, String)> = Vec::new();
    for i in installed {
        let mut line = format!(
            "{} {}{}{}",
            i.name,
            short(&i.version),
            repository_of(i),
            marks(i.flags)
        );
        let newer = available.iter().any(|a| {
            !i.in_image()
                && a.name == i.name
                && a.repository == i.repository
                && a.sha256 != i.sha256
        });
        if all && newer {
            line.push_str(" [upgradable]");
        }
        rows.push((i.name.clone(), line));
    }
    if all {
        for a in available {
            if installed.iter().any(|i| i.name == a.name) {
                continue;
            }
            rows.push((
                a.name.clone(),
                format!(
                    "{} {} {} [available]",
                    a.name,
                    short(&a.version),
                    a.repository
                ),
            ));
        }
    }
    rows.sort();
    rows.into_iter().map(|(_, l)| l).collect()
}

/// `pkg search`: the packages of the cached indexes whose name, `provides` or
/// summary holds `word` (ASCII case aside).
pub fn search(word: &str, available: &[Available], installed: &[Installed]) -> Vec<String> {
    let word = word.to_ascii_lowercase();
    let has = |text: &str| text.to_ascii_lowercase().contains(&word);
    let mut rows: Vec<(String, String)> = available
        .iter()
        .filter(|a| has(&a.name) || a.provides.iter().any(|p| has(p)) || has(&a.summary))
        .map(|a| {
            let mut line = format!(
                "{} {} {} {}",
                a.name,
                short(&a.version),
                a.repository,
                a.summary
            );
            if installed.iter().any(|i| i.name == a.name) {
                line.push_str(" [installed]");
            }
            (a.name.clone(), line)
        })
        .collect();
    rows.sort();
    rows.into_iter().map(|(_, l)| l).collect()
}

/// What `pkg info` shows.
pub struct Info<'a> {
    pub name: &'a str,
    /// `<version>-<release>`, whole.
    pub version: &'a str,
    pub provides: &'a [String],
    pub depends: &'a [String],
    pub needs: &'a [String],
    pub license: &'a str,
    pub summary: &'a str,
    pub repository: &'a str,
    /// `installed (by request)`, `installed (dependency)`, `part of the image` or `available`.
    pub state: &'a str,
    pub size: u64,
    pub sha256: &'a str,
    /// The notice files the package carries, when it is installed.
    pub notices: &'a [String],
    /// The text of `SOURCE` of an installed package, or the `source` field of an index record.
    pub source: &'a str,
}

/// The lines of `pkg info`.
pub fn info(i: &Info<'_>) -> Vec<String> {
    let field = |key: &str, value: &str| format!("{key:<12}{value}");
    let words = |list: &[String]| list.join(" ");
    let sha = match i.sha256.get(..12) {
        Some(head) if i.sha256.len() > 12 => format!("{head}\u{2026}"),
        _ => i.sha256.to_string(),
    };
    let mut out = alloc::vec![
        field("name", i.name),
        field("version", i.version),
        field("provides", &words(i.provides)),
        field("depends", &words(i.depends)),
        field("needs", &words(i.needs)),
        field("license", i.license),
        field("summary", i.summary),
        field("repository", i.repository),
        field("state", i.state),
        field("size", &i.size.to_string()),
        field("sha256", &sha),
    ];
    for (n, notice) in i.notices.iter().enumerate() {
        out.push(if n == 0 {
            field("notices", notice)
        } else {
            format!("{:<12}{notice}", "")
        });
    }
    out.push("source:".into());
    out.extend(i.source.lines().map(String::from));
    out
}

/// The last line of an installation: `installed doomgeneric e257a095-1 (doom),
/// freedoom 0.13.0-1 (dependency)`. `items` are the packages in the order they
/// were received, with the mark of the requested one; `request` is the name the
/// owner typed, which is named when it is not the package's own.
pub fn installed_line(request: &str, items: &[(&str, &str, bool)]) -> String {
    let mut parts: Vec<String> = Vec::new();
    for &(name, version, world) in items.iter().rev() {
        let mark = match (world, request == name) {
            (true, true) => String::new(),
            (true, false) => format!(" ({request})"),
            (false, _) => " (dependency)".to_string(),
        };
        let part = format!("{name} {}{mark}", short(version));
        if world {
            parts.insert(0, part);
        } else {
            parts.push(part);
        }
    }
    format!("installed {}", parts.join(", "))
}

/// What `pkg check` knows of the store.
pub struct Check<'a> {
    pub generation: u64,
    pub blocks: u64,
    pub free: u64,
    pub block_bytes: u64,
    pub flags: u32,
    pub disk: u32,
    pub image: u32,
    pub revoked: u32,
    pub roots: &'a [&'a str],
}

/// The lines of `pkg check` and whether all is well.
pub fn check(c: &Check<'_>) -> (Vec<String>, bool) {
    let mut lines = alloc::vec![
        format!(
            "store generation {}, {} blocks, {} free ({})",
            c.generation,
            c.blocks,
            c.free,
            megabytes(c.free * c.block_bytes)
        ),
        format!(
            "packages {} on the disk, {} in the image, {} revoked",
            c.disk, c.image, c.revoked
        ),
    ];
    let mut well = c.revoked == 0;
    if c.flags & proto_pkg::STATUS_DAMAGED != 0 {
        lines.push("the store is damaged".into());
        well = false;
    }
    if c.flags & proto_pkg::STATUS_READ_ONLY != 0 {
        lines.push("the store is read-only".into());
        well = false;
    }
    if c.flags & proto_pkg::STATUS_NO_STORE != 0 {
        lines.push("the store is not served".into());
        well = false;
    }
    lines.push(format!("roots {}", c.roots.join(" ")));
    (lines, well)
}

/// The line of the plan of an installation: `installing freedoom 0.13.0-1,
/// doomgeneric e257a095-1 (29.3 MB)`.
pub fn plan(items: &[(&str, &str)], bytes: u64) -> String {
    let names: Vec<String> = items
        .iter()
        .map(|(name, version)| format!("{name} {}", short(version)))
        .collect();
    format!("installing {} ({})", names.join(", "), megabytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use proto_pkg::ENTRY_WORLD;

    fn installed(name: &str, version: &str, flags: u32, repository: &str) -> Installed {
        Installed {
            name: name.into(),
            version: version.into(),
            sha256: [1; 32],
            flags,
            repository: repository.into(),
            provides: vec![],
            depends: vec![],
        }
    }

    #[test]
    fn sizes_are_megabytes_of_a_million_bytes() {
        assert_eq!(megabytes(29_323_264), "29.3 MB");
        assert_eq!(megabytes(28_827_648), "28.8 MB");
        assert_eq!(megabytes(495_616), "0.5 MB");
        assert_eq!(megabytes(0), "0.0 MB");
        assert_eq!(megabytes(49_999), "0.0 MB");
        assert_eq!(megabytes(50_000), "0.1 MB");
        assert_eq!(megabytes(999_999), "1.0 MB");
        assert_eq!(megabytes(1_000_000), "1.0 MB");
        assert_eq!(megabytes(533_000_000), "533.0 MB");
    }

    #[test]
    fn a_commit_in_a_version_is_short() {
        assert_eq!(
            short("e257a09527062bfb986b6e5e0780839b6cbd5b71-1"),
            "e257a095-1"
        );
        assert_eq!(short("1.37.0-1"), "1.37.0-1");
        assert_eq!(short("0.13.0-2"), "0.13.0-2");
        assert_eq!(short("2026-10-20-1"), "2026-10-20-1");
    }

    #[test]
    fn the_plan_line_of_the_note() {
        assert_eq!(
            plan(
                &[
                    ("freedoom", "0.13.0-1"),
                    ("doomgeneric", "e257a09527062bfb986b6e5e0780839b6cbd5b71-1")
                ],
                29_323_264
            ),
            "installing freedoom 0.13.0-1, doomgeneric e257a095-1 (29.3 MB)"
        );
    }

    #[test]
    fn list_is_by_name_with_marks_at_the_end() {
        let rows = [
            installed("hello-games", "1.0-1", ENTRY_WORLD, "games"),
            installed("freedoom", "0.13.0-1", ENTRY_DEPENDENCY, "stafeto"),
            installed("busybox", "1.37.0-1", ENTRY_IMAGE | ENTRY_WORLD, "stafeto"),
            installed(
                "doomgeneric",
                "e257a09527062bfb986b6e5e0780839b6cbd5b71-1",
                ENTRY_WORLD | ENTRY_REVOKED,
                "stafeto",
            ),
        ];
        assert_eq!(
            list(&rows, &[], false),
            [
                "busybox 1.37.0-1 [image]",
                "doomgeneric e257a095-1 stafeto [revoked]",
                "freedoom 0.13.0-1 stafeto [dependency]",
                "hello-games 1.0-1 games",
            ]
        );
    }

    #[test]
    fn list_all_adds_the_available_and_the_upgradable() {
        let rows = [
            installed("freedoom", "0.13.0-1", ENTRY_DEPENDENCY, "stafeto"),
            installed("busybox", "1.37.0-1", ENTRY_IMAGE, "stafeto"),
        ];
        let mut changed = [2u8; 32];
        changed[0] = 9;
        let available = [
            Available {
                repository: "stafeto".into(),
                name: "freedoom".into(),
                version: "0.13.0-2".into(),
                sha256: changed,
                provides: vec![],
                summary: "WAD".into(),
            },
            Available {
                repository: "stafeto".into(),
                name: "hello".into(),
                version: "1.0-1".into(),
                sha256: [3; 32],
                provides: vec![],
                summary: "hi".into(),
            },
            // The package of the image is never upgradable.
            Available {
                repository: "stafeto".into(),
                name: "busybox".into(),
                version: "1.38.0-1".into(),
                sha256: changed,
                provides: vec![],
                summary: "sh".into(),
            },
        ];
        assert_eq!(
            list(&rows, &available, true),
            [
                "busybox 1.37.0-1 [image]",
                "freedoom 0.13.0-1 stafeto [dependency] [upgradable]",
                "hello 1.0-1 stafeto [available]",
            ]
        );
    }

    #[test]
    fn search_looks_in_name_provides_and_summary_without_case() {
        let available = [
            Available {
                repository: "stafeto".into(),
                name: "doomgeneric".into(),
                version: "e257a09527062bfb986b6e5e0780839b6cbd5b71-1".into(),
                sha256: [1; 32],
                provides: vec!["doom".into()],
                summary: "Doom engine (Doomgeneric)".into(),
            },
            Available {
                repository: "stafeto".into(),
                name: "nano".into(),
                version: "9.2-1".into(),
                sha256: [1; 32],
                provides: vec![],
                summary: "Text editor".into(),
            },
        ];
        let have = [installed("doomgeneric", "x-1", 0, "stafeto")];
        assert_eq!(
            search("DOOM", &available, &have),
            ["doomgeneric e257a095-1 stafeto Doom engine (Doomgeneric) [installed]"]
        );
        assert_eq!(
            search("editor", &available, &have),
            ["nano 9.2-1 stafeto Text editor"]
        );
        assert!(search("zzz", &available, &have).is_empty());
    }

    #[test]
    fn info_lines() {
        let notices = vec![
            "/usr/share/licenses/doomgeneric/LICENSE".to_string(),
            "/usr/share/licenses/doomgeneric/SOURCE".to_string(),
        ];
        let list = |text: &str| -> Vec<String> { text.split(' ').map(String::from).collect() };
        let lines = info(&Info {
            name: "doomgeneric",
            version: "e257a09527062bfb986b6e5e0780839b6cbd5b71-1",
            provides: &list("doom"),
            depends: &list("freedoom"),
            needs: &list("display input"),
            license: "GPL-2.0-or-later",
            summary: "Doom engine (Doomgeneric)",
            repository: "stafeto",
            state: "installed (by request)",
            size: 495_616,
            sha256: &"f0e21cc25a37".repeat(5),
            notices: &notices,
            source: "line one\nline two\n",
        });
        assert_eq!(lines[0], "name        doomgeneric");
        assert_eq!(
            lines[1],
            "version     e257a09527062bfb986b6e5e0780839b6cbd5b71-1"
        );
        assert_eq!(lines[2], "provides    doom");
        assert_eq!(lines[3], "depends     freedoom");
        assert_eq!(lines[4], "needs       display input");
        assert_eq!(lines[8], "state       installed (by request)");
        assert_eq!(lines[9], "size        495616");
        assert_eq!(lines[10], "sha256      f0e21cc25a37\u{2026}");
        assert_eq!(
            lines[11],
            "notices     /usr/share/licenses/doomgeneric/LICENSE"
        );
        assert_eq!(
            lines[12],
            "            /usr/share/licenses/doomgeneric/SOURCE"
        );
        assert_eq!(&lines[13..], ["source:", "line one", "line two"]);
        // An available package has no notices yet.
        let none = info(&Info {
            name: "x",
            version: "1-1",
            provides: &[],
            depends: &[],
            needs: &[],
            license: "MIT",
            summary: "s",
            repository: "stafeto",
            state: "available",
            size: 1,
            sha256: "abcd",
            notices: &[],
            source: "src/x.tar.xz",
        });
        assert!(none.iter().all(|l| !l.starts_with("notices")));
        assert_eq!(none[2], "provides    ");
        assert_eq!(&none[11..], ["source:", "src/x.tar.xz"]);
    }

    #[test]
    fn the_last_line_names_the_requested_name_and_the_dependencies() {
        let items = [
            ("freedoom", "0.13.0-1", false),
            (
                "doomgeneric",
                "e257a09527062bfb986b6e5e0780839b6cbd5b71-1",
                true,
            ),
        ];
        assert_eq!(
            installed_line("doom", &items),
            "installed doomgeneric e257a095-1 (doom), freedoom 0.13.0-1 (dependency)"
        );
        assert_eq!(
            installed_line("hello", &[("hello", "1.0-1", true)]),
            "installed hello 1.0-1"
        );
    }

    #[test]
    fn check_lines_and_verdict() {
        let ok = Check {
            generation: 7,
            blocks: 131_072,
            free: 123_905,
            block_bytes: 4096,
            flags: 0,
            disk: 2,
            image: 10,
            revoked: 0,
            roots: &["stafeto-dev-root"],
        };
        let (lines, well) = check(&ok);
        assert!(well);
        assert_eq!(
            lines,
            [
                "store generation 7, 131072 blocks, 123905 free (507.5 MB)",
                "packages 2 on the disk, 10 in the image, 0 revoked",
                "roots stafeto-dev-root"
            ]
        );
        let (lines, well) = check(&Check {
            flags: proto_pkg::STATUS_DAMAGED,
            ..ok
        });
        assert!(!well && lines.iter().any(|l| l == "the store is damaged"));
        assert!(!check(&Check { revoked: 1, ..ok }).1);
        assert!(
            !check(&Check {
                flags: proto_pkg::STATUS_READ_ONLY,
                ..ok
            })
            .1
        );
    }
}
