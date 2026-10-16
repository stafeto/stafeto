// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The packages of the build (docs/packages.md): one description per
//! third-party program in `packages/<name>.toml` with its version, source,
//! SHA-256, licence, dependencies, build script and installed files. The
//! shell image takes its files and programs from this list, the build
//! scripts of `tools/` read version, source and SHA-256 from it, and `check`
//! refuses a description that lacks one of them.

use std::collections::BTreeSet;
use std::path::Path;

/// Whether a package is part of the base set of the system or an add-on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Base,
    Addon,
}

/// A package: the content of its description.
#[derive(Clone, Debug)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub kind: Kind,
    pub url: String,
    pub sha256: String,
    /// The SPDX expression of its licence.
    pub license: String,
    pub depends: Vec<String>,
    /// The script that builds it, from the root of the workspace.
    pub build: String,
    /// The image program its build links, if it has one of its own.
    pub program: Option<String>,
    /// Directories that only this package needs.
    pub dirs: Vec<String>,
    /// The installed files: the path in the image and where its bytes come
    /// from (`elf:<program>`, `terminfo:<entry>` or `bytes:<name>`).
    pub files: Vec<(String, String)>,
}

enum Value {
    Text(String),
    List(Vec<String>),
}

/// The keys of a description and their values: strings and lists of
/// strings, one `key = value` each, `#` comments (the part of TOML the
/// descriptions use, so that Python's `tomllib` reads the same files).
fn parse_table(text: &str) -> Result<Vec<(String, Value)>, String> {
    let mut chars = text.chars().peekable();
    let mut line = 1usize;
    let mut out: Vec<(String, Value)> = Vec::new();
    macro_rules! skip {
        ($commas:expr) => {
            while let Some(&c) = chars.peek() {
                if c == '\n' {
                    line += 1;
                    chars.next();
                } else if c.is_whitespace() || ($commas && c == ',') {
                    chars.next();
                } else if c == '#' {
                    while chars.peek().is_some_and(|&c| c != '\n') {
                        chars.next();
                    }
                } else {
                    break;
                }
            }
        };
    }
    let string = |chars: &mut std::iter::Peekable<std::str::Chars<'_>>, line: usize| {
        chars.next();
        let mut s = String::new();
        loop {
            match chars.next() {
                Some('"') => return Ok(s),
                Some('\\') | Some('\n') | None => {
                    return Err(format!(
                        "line {line}: a string must close on its line, no escapes"
                    ));
                }
                Some(c) => s.push(c),
            }
        }
    };
    loop {
        skip!(false);
        if chars.peek().is_none() {
            return Ok(out);
        }
        let mut key = String::new();
        while let Some(&c) = chars.peek() {
            if c.is_ascii_alphanumeric() || c == '_' {
                key.push(c);
                chars.next();
            } else {
                break;
            }
        }
        while chars.peek().is_some_and(|c| *c == ' ' || *c == '\t') {
            chars.next();
        }
        if key.is_empty() || chars.next() != Some('=') {
            return Err(format!("line {line}: expected `key = value`"));
        }
        while chars.peek().is_some_and(|c| *c == ' ' || *c == '\t') {
            chars.next();
        }
        let value = match chars.peek() {
            Some('"') => Value::Text(string(&mut chars, line)?),
            Some('[') => {
                chars.next();
                let mut items = Vec::new();
                loop {
                    skip!(true);
                    match chars.peek() {
                        Some(']') => {
                            chars.next();
                            break;
                        }
                        Some('"') => items.push(string(&mut chars, line)?),
                        _ => return Err(format!("line {line}: expected a string or `]`")),
                    }
                }
                Value::List(items)
            }
            _ => {
                return Err(format!(
                    "line {line}: a value is a string or a list of strings"
                ));
            }
        };
        if out.iter().any(|(k, _)| *k == key) {
            return Err(format!("line {line}: {key} is given twice"));
        }
        out.push((key, value));
    }
}

/// The package a description (`origin` names where it comes from) holds.
pub fn parse(text: &str, origin: &str) -> Result<Package, String> {
    let fail = |e: String| format!("{origin}: {e}");
    let mut table = parse_table(text).map_err(fail)?;
    let mut take = |key: &str| {
        table
            .iter()
            .position(|(k, _)| k == key)
            .map(|i| table.remove(i).1)
    };
    let text_of = |v: Option<Value>, key: &str| match v {
        Some(Value::Text(s)) => Ok(Some(s)),
        None => Ok(None),
        Some(Value::List(_)) => Err(format!("{origin}: {key} is a string")),
    };
    let list_of = |v: Option<Value>, key: &str| match v {
        Some(Value::List(l)) => Ok(l),
        None => Ok(Vec::new()),
        Some(Value::Text(_)) => Err(format!("{origin}: {key} is a list")),
    };
    let required = |v: Option<String>, key: &str| match v {
        Some(s) if !s.is_empty() => Ok(s),
        _ => Err(format!("{origin}: {key} is missing")),
    };
    let name = required(text_of(take("name"), "name")?, "name")?;
    let version = required(text_of(take("version"), "version")?, "version")?;
    let kind = match required(text_of(take("kind"), "kind")?, "kind")?.as_str() {
        "base" => Kind::Base,
        "addon" => Kind::Addon,
        other => {
            return Err(format!(
                "{origin}: kind {other:?} is neither base nor addon"
            ));
        }
    };
    let url = required(text_of(take("url"), "url")?, "url")?;
    let sha256 = required(text_of(take("sha256"), "sha256")?, "sha256")?;
    let license = required(text_of(take("license"), "license")?, "license")?;
    // The name of the licence file in the source tree: only
    // tools/build-ready-utils.py reads it.
    text_of(take("license_file"), "license_file")?;
    let build = required(text_of(take("build"), "build")?, "build")?;
    let program = text_of(take("program"), "program")?;
    let depends = list_of(take("depends"), "depends")?;
    let dirs = list_of(take("dirs"), "dirs")?;
    let mut files = Vec::new();
    for entry in list_of(take("files"), "files")? {
        let (path, from) = entry
            .split_once(" = ")
            .ok_or_else(|| format!("{origin}: file {entry:?} is not `path = from`"))?;
        files.push((path.to_owned(), from.to_owned()));
    }
    if let Some((key, _)) = table.first() {
        return Err(format!("{origin}: unknown key {key}"));
    }
    Ok(Package {
        name,
        version,
        kind,
        url,
        sha256,
        license,
        depends,
        build,
        program,
        dirs,
        files,
    })
}

/// Why a description is not fit to build from, or `Ok`.
fn validate(p: &Package, origin: &str) -> Result<(), String> {
    let fail = |e: &str| Err(format!("{origin}: {e}"));
    if p.sha256.len() != 64
        || !p
            .sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return fail("sha256 is not 64 lowercase hex digits");
    }
    if !p
        .license
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || ".-+() ".contains(c))
    {
        return fail("license is not an SPDX expression");
    }
    if !p.url.starts_with("https://") {
        return fail("url is not an https URL");
    }
    if p.files.is_empty() {
        return fail("the package installs no file");
    }
    for (path, from) in &p.files {
        if !path.starts_with('/') || path.ends_with('/') {
            return fail(&format!("{path:?} is not an absolute path of a file"));
        }
        match from.split_once(':') {
            Some(("elf" | "terminfo" | "bytes", rest)) if !rest.is_empty() => {}
            _ => return fail(&format!("{from:?} is none of elf:, terminfo:, bytes:")),
        }
    }
    for dir in &p.dirs {
        if !dir.starts_with('/') || dir.ends_with('/') {
            return fail(&format!("{dir:?} is not an absolute path of a directory"));
        }
    }
    Ok(())
}

/// The check of the set: names, dependencies, build scripts, programs and
/// that no path belongs to two packages. `root` holds the scripts.
fn validate_set(packages: &[Package], root: Option<&Path>) -> Result<(), String> {
    let mut names = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for p in packages {
        if !names.insert(p.name.as_str()) {
            return Err(format!("package {} is described twice", p.name));
        }
        if let Some(root) = root
            && !root.join(&p.build).is_file()
        {
            return Err(format!("{}: build script {} is missing", p.name, p.build));
        }
        for path in p.files.iter().map(|f| &f.0).chain(&p.dirs) {
            if !paths.insert(path.as_str()) {
                return Err(format!(
                    "{path} belongs to two packages (one is {})",
                    p.name
                ));
            }
        }
    }
    for p in packages {
        for dep in &p.depends {
            let Some(d) = packages.iter().find(|d| d.name == *dep) else {
                return Err(format!(
                    "{}: depends on {dep}, which is not a package",
                    p.name
                ));
            };
            if p.kind == Kind::Base && d.kind == Kind::Addon {
                return Err(format!(
                    "{}: a base package depends on the add-on {dep}",
                    p.name
                ));
            }
        }
        // The programs a file takes its bytes from are those of the package
        // and of its dependencies.
        let mut known: Vec<&str> = p.program.iter().map(String::as_str).collect();
        for dep in &p.depends {
            known.extend(
                packages
                    .iter()
                    .filter(|d| d.name == *dep)
                    .filter_map(|d| d.program.as_deref()),
            );
        }
        for (path, from) in &p.files {
            if let Some(program) = from.strip_prefix("elf:")
                && !known.contains(&program)
            {
                return Err(format!(
                    "{}: {path} comes from the program {program}, which neither it nor a dependency builds",
                    p.name
                ));
            }
        }
    }
    order(packages).map(drop)
}

/// The packages in build order: the base ones first, each after its
/// dependencies, names in alphabetical order otherwise.
pub fn order(packages: &[Package]) -> Result<Vec<Package>, String> {
    let mut sorted: Vec<&Package> = packages.iter().collect();
    sorted.sort_by(|a, b| (a.kind as u8, &a.name).cmp(&(b.kind as u8, &b.name)));
    let mut out: Vec<Package> = Vec::new();
    while out.len() < packages.len() {
        let next = sorted.iter().find(|p| {
            !out.iter().any(|o| o.name == p.name)
                && p.depends.iter().all(|d| out.iter().any(|o| o.name == *d))
        });
        match next {
            Some(p) => out.push((*p).clone()),
            None => return Err("the dependencies of the packages form a cycle".into()),
        }
    }
    Ok(out)
}

/// Every description in `packages/` of the workspace, validated, in build
/// order.
pub fn load() -> Result<Vec<Package>, String> {
    let root = crate::root();
    let dir = root.join("packages");
    let mut names: Vec<_> = std::fs::read_dir(&dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    names.sort();
    let mut packages = Vec::new();
    for path in names {
        let origin = format!("packages/{}", path.file_name().unwrap().to_string_lossy());
        let text = std::fs::read_to_string(&path).map_err(|e| format!("{origin}: {e}"))?;
        let p = parse(&text, &origin)?;
        validate(&p, &origin)?;
        if format!("{}.toml", p.name) != path.file_name().unwrap().to_string_lossy() {
            return Err(format!("{origin}: describes {}", p.name));
        }
        packages.push(p);
    }
    validate_set(&packages, Some(&root))?;
    order(&packages)
}

/// The check of CI: every description is whole (version, source, SHA-256,
/// licence, files), the set is consistent, and every file of each image
/// that holds packages belongs to exactly one of them or to the base system.
pub fn check() -> Result<(), String> {
    let packages = load()?;
    let image = "boot-ash-dialog.img";
    crate::rootfs::check_owners(image, &crate::rootfs::files_of(image), &of_image(image)?)?;
    let (base, addons) = (
        packages.iter().filter(|p| p.kind == Kind::Base).count(),
        packages.iter().filter(|p| p.kind == Kind::Addon).count(),
    );
    println!("packages ok: {base} base, {addons} add-on");
    Ok(())
}

/// Builds the shell image and prints the table of its packages: name,
/// version, licence, kind, files and bytes (the size of the ELF file of a
/// program, of a terminfo entry, of a listed file).
pub fn table(image: &str) -> Result<(), String> {
    let table = crate::rootfs::package_table(image, |source| {
        let path = match source {
            crate::rootfs::Source::Elf(program) => {
                crate::image_elf(&crate::target_dir(), image, program)
            }
            crate::rootfs::Source::Terminfo(entry) => crate::target_dir()
                .join("ncurses/terminfo")
                .join(&entry[..1])
                .join(entry),
            crate::rootfs::Source::Bytes(_, bytes) => return Ok(bytes.len() as u64),
            crate::rootfs::Source::Variant { .. } => return Err("a variant has no package".into()),
        };
        std::fs::metadata(&path)
            .map(|m| m.len())
            .map_err(|e| format!("{}: {e}", path.display()))
    })?;
    print!("{table}");
    Ok(())
}

/// The value `key` of the package `name`: what the dialogs print as the
/// source of a program in the image.
pub fn value(name: &str, key: &str) -> Result<String, String> {
    let p = load()?
        .into_iter()
        .find(|p| p.name == name)
        .ok_or_else(|| format!("no package {name}"))?;
    match key {
        "version" => Ok(p.version),
        "sha256" => Ok(p.sha256),
        "url" => Ok(p.url),
        "license" => Ok(p.license),
        _ => Err(format!("no key {key}")),
    }
}

/// The packages the image `name` holds: the shell image holds every one of
/// them, base and add-ons. The other images are probes that list the few
/// files they use and hold no package.
pub fn of_image(name: &str) -> Result<Vec<Package>, String> {
    match name {
        "boot-ash-dialog.img" => load(),
        _ => Ok(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
# a comment
name = "demo"
version = "1.0"   # trailing comment
kind = "addon"
url = "https://example.org/demo-1.0.tar.gz"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
license = "MIT"
depends = []
build = "tools/build-demo.py"
program = "demo"
files = [
  "/bin/demo = elf:demo",
  "/etc/demo = bytes:demo",
]
"#;

    fn good() -> Package {
        let p = parse(GOOD, "demo.toml").unwrap();
        validate(&p, "demo.toml").unwrap();
        p
    }

    #[test]
    fn a_description_reads_back() {
        let p = good();
        assert_eq!((p.name.as_str(), p.version.as_str()), ("demo", "1.0"));
        assert_eq!(p.kind, Kind::Addon);
        assert_eq!(p.files.len(), 2);
        assert_eq!(p.files[0], ("/bin/demo".to_owned(), "elf:demo".to_owned()));
    }

    #[test]
    fn a_description_without_sha256_or_licence_is_refused() {
        for key in ["sha256", "license", "version", "url", "build"] {
            let text: String = GOOD
                .lines()
                .filter(|l| !l.starts_with(&format!("{key} =")))
                .map(|l| format!("{l}\n"))
                .collect();
            let error = parse(&text, "demo.toml").unwrap_err();
            assert!(error.contains(&format!("{key} is missing")), "{error}");
        }
        let mut p = good();
        p.sha256 = "abc".into();
        assert!(validate(&p, "x").unwrap_err().contains("sha256"));
        let mut p = good();
        p.license = "Free for all!".into();
        assert!(validate(&p, "x").unwrap_err().contains("license"));
    }

    #[test]
    fn a_package_without_files_is_refused() {
        let mut p = good();
        p.files.clear();
        assert!(validate(&p, "x").unwrap_err().contains("no file"));
    }

    #[test]
    fn a_misspelt_key_and_a_bad_value_are_refused() {
        assert!(parse(&GOOD.replace("license =", "licence ="), "x").is_err());
        assert!(parse("name = demo", "x").is_err());
        assert!(parse("name = \"a\"\nname = \"b\"", "x").is_err());
    }

    #[test]
    fn a_path_belongs_to_one_package() {
        let a = good();
        let mut b = good();
        b.name = "other".into();
        assert!(
            validate_set(&[a.clone(), b], None)
                .unwrap_err()
                .contains("two packages")
        );
        assert!(validate_set(&[a], None).is_ok());
    }

    #[test]
    fn dependencies_must_exist_and_not_loop() {
        let mut a = good();
        a.depends = vec!["ghost".into()];
        assert!(validate_set(&[a], None).unwrap_err().contains("ghost"));
        let mut a = good();
        let mut b = good();
        b.name = "other".into();
        b.files = vec![("/bin/other".into(), "elf:other".into())];
        b.program = Some("other".into());
        a.depends = vec!["other".into()];
        b.depends = vec!["demo".into()];
        assert!(validate_set(&[a, b], None).unwrap_err().contains("cycle"));
    }

    #[test]
    fn a_base_package_does_not_need_an_addon() {
        let mut a = good();
        a.kind = Kind::Base;
        a.depends = vec!["other".into()];
        let mut b = good();
        b.name = "other".into();
        b.files = vec![("/bin/other".into(), "elf:other".into())];
        b.program = Some("other".into());
        assert!(validate_set(&[a, b], None).unwrap_err().contains("add-on"));
    }

    #[test]
    fn the_order_puts_base_first_and_dependencies_before_dependents() {
        let mk = |name: &str, kind, depends: &[&str]| Package {
            name: name.into(),
            kind,
            depends: depends.iter().map(|d| (*d).into()).collect(),
            ..good()
        };
        let list = [
            mk("nano", Kind::Addon, &["ncurses"]),
            mk("ncurses", Kind::Addon, &[]),
            mk("busybox", Kind::Base, &[]),
        ];
        let names: Vec<_> = order(&list).unwrap().into_iter().map(|p| p.name).collect();
        assert_eq!(names, ["busybox", "ncurses", "nano"]);
    }

    #[test]
    fn the_descriptions_of_the_workspace_are_good() {
        let packages = load().unwrap();
        assert!(
            packages
                .iter()
                .any(|p| p.name == "busybox" && p.kind == Kind::Base)
        );
        assert!(
            packages
                .iter()
                .any(|p| p.name == "nano" && p.kind == Kind::Addon)
        );
    }
}
