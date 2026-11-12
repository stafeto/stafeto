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

/// Whether a package belongs to the base set of the system or is optional
/// (spec 5, 3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Base,
    Optional,
}

impl Kind {
    /// The word of the description and of the table.
    pub fn word(self) -> &'static str {
        match self {
            Kind::Base => "base",
            Kind::Optional => "optional",
        }
    }
}

/// The probe images a package goes into.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Image {
    Shell,
    Games,
    Net,
    Fstack,
}

impl Image {
    pub fn word(self) -> &'static str {
        match self {
            Image::Shell => "shell",
            Image::Games => "games",
            Image::Net => "net",
            Image::Fstack => "fstack",
        }
    }
}

/// What builds together and which images hold a package: derived from its
/// kind and image. The base set of the shell image, the add-ons of the shell
/// image, F-Stack, the games (the games image only) and the programs of the
/// network (the images with the network service only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Group {
    Base,
    Addon,
    Fstack,
    Game,
    Net,
}

/// A package: the content of its description.
#[derive(Clone, Debug)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub kind: Kind,
    pub image: Image,
    /// The number of the build of this version: digits.
    pub release: String,
    /// One line, up to 80 characters of ASCII without `"`.
    pub summary: String,
    pub url: String,
    pub sha256: String,
    /// The SPDX expression of its licence.
    pub license: String,
    /// Packages needed when it runs.
    pub depends: Vec<String>,
    /// Packages linked into it when it is built.
    pub build_depends: Vec<String>,
    /// Other names the package answers to.
    pub provides: Vec<String>,
    /// What the device must offer: `display`, `input`, `net`.
    pub needs: Vec<String>,
    /// More notice files of the package: the name in its licence directory
    /// and where the bytes come from (`target:<path from target/>` or
    /// `tree:<path from the root of the tree>`).
    pub notices: Vec<(String, String)>,
    /// The script that builds it, from the root of the workspace.
    pub build: String,
    /// The image program its build links, if it has one of its own.
    pub program: Option<String>,
    /// Directories that only this package needs.
    pub dirs: Vec<String>,
    /// The installed files: the path in the image and where its bytes come
    /// from (`elf:<program>`, `terminfo:<entry>`, `bytes:<name>` or
    /// `link:<target>`, a symbolic link).
    pub files: Vec<(String, String)>,
}

impl Package {
    /// Whether the package needs the network and the second device both,
    /// so only the images with the network service hold it (nginx on the
    /// stack).
    pub fn needs_network_device(&self) -> bool {
        self.group() == Group::Fstack && self.needs.iter().any(|n| n == "net")
    }

    /// The group of the build and of the images (spec 5, 3.3 and the
    /// note of stage PK0, R12.2).
    pub fn group(&self) -> Group {
        match (self.kind, self.image) {
            (_, Image::Fstack) => Group::Fstack,
            (_, Image::Games) => Group::Game,
            (_, Image::Net) => Group::Net,
            (Kind::Base, Image::Shell) => Group::Base,
            (Kind::Optional, Image::Shell) => Group::Addon,
        }
    }
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
        "optional" => Kind::Optional,
        other => {
            return Err(format!(
                "{origin}: kind {other:?} is none of base, optional"
            ));
        }
    };
    let image = match required(text_of(take("image"), "image")?, "image")?.as_str() {
        "shell" => Image::Shell,
        "games" => Image::Games,
        "net" => Image::Net,
        "fstack" => Image::Fstack,
        other => {
            return Err(format!(
                "{origin}: image {other:?} is none of shell, games, net, fstack"
            ));
        }
    };
    let release = required(text_of(take("release"), "release")?, "release")?;
    let summary = required(text_of(take("summary"), "summary")?, "summary")?;
    let url = required(text_of(take("url"), "url")?, "url")?;
    let sha256 = required(text_of(take("sha256"), "sha256")?, "sha256")?;
    let license = required(text_of(take("license"), "license")?, "license")?;
    // The name of the licence file in the source tree: only
    // tools/build-ready-utils.py reads it.
    text_of(take("license_file"), "license_file")?;
    let build = required(text_of(take("build"), "build")?, "build")?;
    let program = text_of(take("program"), "program")?;
    let depends = list_of(take("depends"), "depends")?;
    let build_depends = list_of(take("build_depends"), "build_depends")?;
    let provides = list_of(take("provides"), "provides")?;
    let needs = list_of(take("needs"), "needs")?;
    let mut notices = Vec::new();
    for entry in list_of(take("notices"), "notices")? {
        let (name, from) = entry
            .split_once(" = ")
            .ok_or_else(|| format!("{origin}: notice {entry:?} is not `name = from`"))?;
        notices.push((name.to_owned(), from.to_owned()));
    }
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
        image,
        release,
        summary,
        url,
        sha256,
        license,
        depends,
        build_depends,
        provides,
        needs,
        notices,
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
    if p.release.is_empty() || !p.release.bytes().all(|b| b.is_ascii_digit()) {
        return fail("release is not a string of digits");
    }
    if p.summary.len() > 80 || !p.summary.is_ascii() || p.summary.contains('"') {
        return fail("summary is not one line of up to 80 ASCII characters without a quote");
    }
    if let Some(word) = p
        .needs
        .iter()
        .find(|w| !matches!(w.as_str(), "display" | "input" | "net"))
    {
        return fail(&format!("needs names {word}, none of display, input, net"));
    }
    for (name, from) in &p.notices {
        let plain = |t: &str| {
            !t.is_empty()
                && t.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
        };
        if !plain(name) || matches!(name.as_str(), "LICENSE" | "SOURCE") {
            return fail(&format!(
                "notice name {name:?} is not a plain file name of its own"
            ));
        }
        match from.split_once(':') {
            Some(("target" | "tree", path))
                if !path.is_empty()
                    && !path.starts_with('/')
                    && !path.split('/').any(|c| c == "..") => {}
            _ => {
                return fail(&format!(
                    "notice source {from:?} is none of target:<path>, tree:<path>"
                ));
            }
        }
    }
    for (path, from) in &p.files {
        if !path.starts_with('/') || path.ends_with('/') {
            return fail(&format!("{path:?} is not an absolute path of a file"));
        }
        match from.split_once(':') {
            Some(("elf" | "terminfo" | "bytes", rest)) if !rest.is_empty() => {}
            // A link names a file of its own directory.
            Some(("link", rest))
                if !rest.is_empty()
                    && rest
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
                    && !matches!(rest, "." | "..") => {}
            _ => {
                return fail(&format!(
                    "{from:?} is none of elf:, terminfo:, bytes:, link:<name>"
                ));
            }
        }
    }
    for dir in &p.dirs {
        if !dir.starts_with('/') || dir.ends_with('/') {
            return fail(&format!("{dir:?} is not an absolute path of a directory"));
        }
    }
    Ok(())
}

/// The packages `p` may name in `depends` by image (rule 4 of the note of
/// stage PK0): the shell image's packages only the shell's, the games the
/// shell's and the games', F-Stack the shell's and F-Stack's, the network's
/// any but the games'.
fn image_allows(from: Image, on: Image) -> bool {
    match from {
        Image::Shell => on == Image::Shell,
        Image::Games => matches!(on, Image::Shell | Image::Games),
        Image::Fstack => matches!(on, Image::Shell | Image::Fstack),
        Image::Net => on != Image::Games,
    }
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
    let find = |name: &str| packages.iter().find(|d| d.name == name);
    let installs = |p: &Package| !(p.files.is_empty() && p.dirs.is_empty() && p.program.is_none());
    let mut provided = BTreeSet::new();
    for p in packages {
        // 1: the names a package gives or takes.
        for name in &p.provides {
            if find(name).is_some() || !provided.insert(name.as_str()) {
                return Err(format!(
                    "{}: provides {name}, which is already the name of a package or of what another provides",
                    p.name
                ));
            }
        }
        // A package that installs nothing is the source of another one (the
        // fts of pax, PCRE2 of nginx): some package links it in.
        if !installs(p) && !packages.iter().any(|q| q.build_depends.contains(&p.name)) {
            return Err(format!(
                "{}: the package installs no file and no package links it in (build_depends)",
                p.name
            ));
        }
        for dep in &p.build_depends {
            if find(dep).is_none() {
                return Err(format!(
                    "{}: build_depends names {dep}, which is not a package",
                    p.name
                ));
            }
        }
        for dep in &p.depends {
            let Some(d) = find(dep) else {
                return Err(format!(
                    "{}: depends on {dep}, which is not a package",
                    p.name
                ));
            };
            // 2: a package without files is only linked in.
            if !installs(d) {
                return Err(format!(
                    "{}: depends names {dep}, a package without files (it belongs in build_depends)",
                    p.name
                ));
            }
            // 3: base depends on base; optional never names base.
            if p.kind == Kind::Base && d.kind != Kind::Base {
                return Err(format!(
                    "{}: a base package depends on the optional package {dep}",
                    p.name
                ));
            }
            if p.kind == Kind::Optional && d.kind == Kind::Base {
                return Err(format!(
                    "{}: an optional package names the base package {dep} in depends (the base is always there)",
                    p.name
                ));
            }
            // 4: images.
            if !image_allows(p.image, d.image) {
                return Err(format!(
                    "{}: a package of the {} image depends on {dep} of the {} image",
                    p.name,
                    p.image.word(),
                    d.image.word()
                ));
            }
        }
        // 6: a link names a file of the package, of a package it depends on
        // or of a base package.
        for (path, from) in &p.files {
            let Some(target) = from.strip_prefix("link:") else {
                continue;
            };
            let at = path.rfind('/').unwrap_or(0);
            let whole = format!("{}/{target}", &path[..at]);
            let owner = packages
                .iter()
                .find(|q| q.files.iter().any(|(f, _)| *f == whole));
            let ok = owner.is_some_and(|o| {
                o.name == p.name || p.depends.contains(&o.name) || o.kind == Kind::Base
            });
            if !ok {
                return Err(format!(
                    "{}: {path} links to {whole}, which is no file of the package, of a dependency or of a base package",
                    p.name
                ));
            }
        }
        // The programs a file takes its bytes from are those of the package
        // and of its dependencies.
        let mut known: Vec<&str> = p.program.iter().map(String::as_str).collect();
        for dep in p.depends.iter().chain(&p.build_depends) {
            known.extend(find(dep).and_then(|d| d.program.as_deref()));
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
    // 5: no cycles, in each of the two relations.
    cycle_free(packages, |p| &p.depends)?;
    cycle_free(packages, |p| &p.build_depends)?;
    order(packages).map(drop)
}

/// Fails when following `edges` leads back to a package.
fn cycle_free<'a>(
    packages: &'a [Package],
    edges: impl Fn(&'a Package) -> &'a Vec<String>,
) -> Result<(), String> {
    let mut done: BTreeSet<&str> = BTreeSet::new();
    while done.len() < packages.len() {
        let next = packages.iter().find(|p| {
            !done.contains(p.name.as_str())
                && edges(p)
                    .iter()
                    .all(|d| done.contains(d.as_str()) || !packages.iter().any(|q| q.name == *d))
        });
        match next {
            Some(p) => {
                done.insert(&p.name);
            }
            None => return Err("the dependencies of the packages form a cycle".into()),
        }
    }
    Ok(())
}

/// The packages in build order: the groups in turn (the base ones first),
/// each package after those it links in (`build_depends`), names in
/// alphabetical order otherwise.
pub fn order(packages: &[Package]) -> Result<Vec<Package>, String> {
    let mut sorted: Vec<&Package> = packages.iter().collect();
    sorted.sort_by(|a, b| (a.group() as u8, &a.name).cmp(&(b.group() as u8, &b.name)));
    let mut out: Vec<Package> = Vec::new();
    while out.len() < packages.len() {
        let next = sorted.iter().find(|p| {
            !out.iter().any(|o| o.name == p.name)
                && p.build_depends
                    .iter()
                    .all(|d| out.iter().any(|o| o.name == *d))
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
        let mut p = parse(&text, &origin)?;
        validate(&p, &origin)?;
        // A run that carries packages (carry.rs) fixes the releases.
        if let Some(release) = crate::carry::release_of(&p.name) {
            p.release = release;
        }
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
    for image in [
        "boot-ash-dialog.img",
        "boot-doom.img",
        "boot-net.img",
        "boot-net-curl-steps.img",
        "boot-net-vz.img",
        "boot-net-vz2.img",
        "boot-net-vz2-static.img",
        "boot-fstack-probe.img",
        "boot-net-tls.img",
        "boot-net-tls-steps.img",
        "boot-nginx-probe.img",
        "boot-nginx-bench.img",
        "boot-nginx-bench-vz-nobuf.img",
        "boot-net-bench.img",
        "boot-net-bench-profile.img",
        "boot-net-bench-pinned.img",
        "boot-net-bench-cpu0.img",
        "boot-net-bench-fast.img",
        "boot-net-bench-switch.img",
        "boot-net-bench-switch-profile.img",
        "boot-net-bench-switch-pinned.img",
        "boot-net-bench-trace.img",
        "boot-net-bench-trace-fast.img",
        "boot-net-bench-trace-switch.img",
        "boot-fast-nginx.img",
        "boot-fast-scale.img",
        "boot-fast-switch.img",
    ] {
        crate::rootfs::check_owners(image, &crate::rootfs::files_of(image), &of_image(image)?)?;
    }
    let count = |group| packages.iter().filter(|p| p.group() == group).count();
    println!(
        "packages ok: {} base, {} add-on, {} F-Stack, {} game, {} net",
        count(Group::Base),
        count(Group::Addon),
        count(Group::Fstack),
        count(Group::Game),
        count(Group::Net)
    );
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
            crate::rootfs::Source::Link(target) => return Ok(target.len() as u64),
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

/// The prefix of the names of the full image built without a package
/// (`cargo xtask image full --without f-stack`).
const WITHOUT: &str = "boot-full-without-";

/// The name of the full image without the package `package`.
pub fn without_image(package: &str) -> String {
    format!("{WITHOUT}{package}.img")
}

/// The package that an image name of `without_image` leaves out.
pub fn without_name(image: &str) -> Option<&str> {
    image.strip_prefix(WITHOUT)?.strip_suffix(".img")
}

/// The packages of `all` without the optional package `name` and without the
/// packages that depend on it, or on what it provides, one after the other.
pub fn without(all: Vec<Package>, name: &str) -> Result<Vec<Package>, String> {
    let first = all
        .iter()
        .find(|p| p.name == name)
        .ok_or_else(|| format!("--without {name}: no such package"))?;
    if first.kind != Kind::Optional {
        return Err(format!(
            "--without {name}: a base package; only an optional one can be left out"
        ));
    }
    let mut gone: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    gone.insert(name.to_string());
    gone.extend(first.provides.iter().cloned());
    loop {
        let more: Vec<&Package> = all
            .iter()
            .filter(|p| !gone.contains(&p.name) && p.depends.iter().any(|d| gone.contains(d)))
            .collect();
        if more.is_empty() {
            break;
        }
        for p in more {
            gone.insert(p.name.clone());
            gone.extend(p.provides.iter().cloned());
        }
    }
    Ok(all
        .into_iter()
        .filter(|p| !gone.contains(&p.name))
        .collect())
}

/// The packages the image `name` holds: the shell image holds the base ones
/// and the add-ons, the images with the network service F-Stack and the
/// network packages too, the image of the probe of F-Stack its own package,
/// the games image the games with the shell's. The other
/// images are probes that list the few files they use and hold no package.
pub fn of_image(name: &str) -> Result<Vec<Package>, String> {
    let of = |groups: &[Group]| -> Result<Vec<Package>, String> {
        Ok(load()?
            .into_iter()
            .filter(|p| groups.contains(&p.group()) && !p.needs_network_device())
            .collect())
    };
    match name {
        // The images of nginx on the stack (`cargo xtask fast-probe nginx`
        // and `cargo xtask net-vz --fast --nginx`) hold the packages of the
        // images with the network and those that need the second device.
        "boot-fast-nginx.img"
        | "boot-fast-nginx-crash.img"
        | "boot-fast-nginx-steps.img"
        | "boot-fast-nginx-vz.img"
        | "boot-fast-nginx-vz-steps.img"
        | "boot-fast-scale.img"
        | "boot-fast-switch.img"
        | "boot-fast-switch-steps.img"
        | "boot-fast-switch-vz.img"
        | "boot-net-bench-switch.img"
        | "boot-net-bench-switch-profile.img"
        | "boot-net-bench-switch-pinned.img"
        | "boot-net-bench-trace-fast.img"
        | "boot-net-bench-trace-switch.img"
        | "boot-net-bench-fast.img" => Ok(load()?
            .into_iter()
            .filter(|p| [Group::Base, Group::Addon, Group::Fstack, Group::Net].contains(&p.group()))
            .collect()),
        // The base image holds the base packages, the full image all of them.
        "boot-base.img" | "boot-pkg-probe.img" => Ok(load()?
            .into_iter()
            .filter(|p| p.kind == Kind::Base)
            .collect()),
        "boot-full.img" => load(),
        other if without_name(other).is_some() => without(load()?, without_name(other).unwrap()),
        "boot-ash-dialog.img" => of(&[Group::Base, Group::Addon]),
        "boot-net.img"
        | "boot-net-its.img"
        | "boot-net-curl-steps.img"
        | "boot-net-tls.img"
        | "boot-net-tls-steps.img"
        | "boot-posix-net-steps.img"
        | "boot-net-vz.img"
        | "boot-net-vz2.img"
        | "boot-net-vz2-static.img"
        | "boot-net-vz-steps.img"
        | "boot-net-vz2-steps.img"
        | "boot-nginx-probe.img"
        | "boot-nginx-probe-steps.img"
        | "boot-fast-probe.img"
        | "boot-fast-probe-steps.img"
        | "boot-fstack-device.img"
        | "boot-fstack-device-steps.img"
        | "boot-fstack-device-dhcp.img"
        | "boot-fast-layer.img"
        | "boot-fast-probe-crash.img"
        | "boot-fast-vz.img"
        | "boot-fast-vz-static.img"
        | "boot-fast-vz-steps.img"
        | "boot-nginx-bench.img"
        | "boot-nginx-bench-nobuf.img"
        | "boot-nginx-bench-vz.img"
        | "boot-nginx-bench-vz-nobuf.img"
        | "boot-net-bench.img"
        | "boot-net-bench-profile.img"
        | "boot-net-bench-pinned.img"
        | "boot-net-bench-cpu0.img"
        | "boot-net-bench-trace.img" => of(&[Group::Base, Group::Addon, Group::Fstack, Group::Net]),
        // The shell's image with the probe of F-Stack runs no network
        // service.
        "boot-fstack-probe.img" => of(&[Group::Base, Group::Addon, Group::Fstack]),
        "boot-doom.img" | "boot-doom-steps.img" => of(&[Group::Base, Group::Addon, Group::Game]),
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
kind = "optional"
image = "shell"
release = "1"
summary = "A demonstration"
url = "https://example.org/demo-1.0.tar.gz"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
license = "MIT"
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

    /// A package `name` of the group in the image with one program of its own.
    fn with(name: &str, kind: Kind, image: Image) -> Package {
        Package {
            name: name.into(),
            kind,
            image,
            files: vec![(format!("/bin/{name}"), format!("elf:{name}"))],
            program: Some(name.into()),
            ..good()
        }
    }

    fn refused(set: &[Package]) -> String {
        validate_set(set, None).unwrap_err()
    }

    #[test]
    fn a_description_reads_back() {
        let p = good();
        assert_eq!((p.name.as_str(), p.version.as_str()), ("demo", "1.0"));
        assert_eq!(
            (p.kind, p.image, p.group()),
            (Kind::Optional, Image::Shell, Group::Addon)
        );
        assert_eq!(
            (p.release.as_str(), p.summary.as_str()),
            ("1", "A demonstration")
        );
        assert_eq!(p.files.len(), 2);
        assert_eq!(p.files[0], ("/bin/demo".to_owned(), "elf:demo".to_owned()));
        assert!(p.depends.is_empty() && p.build_depends.is_empty() && p.notices.is_empty());
    }

    #[test]
    fn the_group_follows_kind_and_image() {
        let g = |k, i| {
            Package {
                kind: k,
                image: i,
                ..good()
            }
            .group()
        };
        assert_eq!(g(Kind::Base, Image::Shell), Group::Base);
        assert_eq!(g(Kind::Optional, Image::Shell), Group::Addon);
        assert_eq!(g(Kind::Base, Image::Fstack), Group::Fstack);
        assert_eq!(g(Kind::Optional, Image::Fstack), Group::Fstack);
        assert_eq!(g(Kind::Base, Image::Games), Group::Game);
        assert_eq!(g(Kind::Base, Image::Net), Group::Net);
        assert_eq!(g(Kind::Optional, Image::Net), Group::Net);
    }

    #[test]
    fn a_description_without_a_required_key_is_refused() {
        for key in [
            "sha256", "license", "version", "url", "build", "kind", "image", "release", "summary",
        ] {
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
    fn the_old_kinds_and_bad_values_of_the_new_keys_are_refused() {
        for old in ["addon", "game", "net"] {
            let text = GOOD.replace("kind = \"optional\"", &format!("kind = \"{old}\""));
            assert!(
                parse(&text, "x")
                    .unwrap_err()
                    .contains("none of base, optional")
            );
        }
        assert!(parse(&GOOD.replace("image = \"shell\"", "image = \"tv\""), "x").is_err());
        let bad = |from: &str, to: &str| {
            let p = parse(&GOOD.replace(from, to), "x").unwrap();
            validate(&p, "x").unwrap_err()
        };
        assert!(bad("release = \"1\"", "release = \"1a\"").contains("release"));
        assert!(
            bad(
                "summary = \"A demonstration\"",
                &format!("summary = \"{}\"", "x".repeat(81))
            )
            .contains("summary")
        );
        assert!(
            bad("summary = \"A demonstration\"", "summary = \"caf\u{e9}\"").contains("summary")
        );
        assert!(bad("build = ", "needs = [\"sound\"]\nbuild = ").contains("needs"));
        assert!(bad("build = ", "notices = [\"LICENSE = tree:x\"]\nbuild = ").contains("notice"));
        assert!(bad("build = ", "notices = [\"A = target:../x\"]\nbuild = ").contains("notice"));
        assert!(bad("build = ", "notices = [\"A = elsewhere:x\"]\nbuild = ").contains("notice"));
        let ok = parse(
            &GOOD.replace(
                "build = ",
                "notices = [\"A = target:x/y\", \"B = tree:z\"]\nbuild = ",
            ),
            "x",
        )
        .unwrap();
        validate(&ok, "x").unwrap();
        assert_eq!(ok.notices[1], ("B".into(), "tree:z".into()));
    }

    #[test]
    fn a_package_without_files_needs_a_package_that_links_it_in() {
        let mut p = good();
        p.files.clear();
        p.program = None;
        assert!(refused(std::slice::from_ref(&p)).contains("installs no file"));
        let mut user = with("user", Kind::Optional, Image::Shell);
        user.build_depends = vec![p.name.clone()];
        assert!(validate_set(&[p.clone(), user], None).is_ok());
        // A runtime dependency on it is the mistake: the note's rule 2.
        let mut user = with("user", Kind::Optional, Image::Shell);
        user.depends = vec![p.name.clone()];
        user.build_depends = vec![p.name.clone()];
        assert!(refused(&[p, user]).contains("a package without files"));
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
        assert!(refused(&[a.clone(), b]).contains("two packages"));
        assert!(validate_set(&[a], None).is_ok());
    }

    #[test]
    fn the_names_in_the_three_lists_must_exist() {
        let mut a = with("a", Kind::Optional, Image::Shell);
        a.depends = vec!["ghost".into()];
        assert!(refused(&[a]).contains("ghost"));
        let mut a = with("a", Kind::Optional, Image::Shell);
        a.build_depends = vec!["ghost".into()];
        assert!(refused(&[a]).contains("ghost"));
    }

    #[test]
    fn provides_never_repeats_a_package_name_or_another_provides() {
        let mut a = with("a", Kind::Optional, Image::Shell);
        let b = with("b", Kind::Optional, Image::Shell);
        a.provides = vec!["b".into()];
        assert!(refused(&[a.clone(), b.clone()]).contains("provides b"));
        a.provides = vec!["x".into()];
        let mut c = with("c", Kind::Optional, Image::Shell);
        c.provides = vec!["x".into()];
        assert!(refused(&[a.clone(), b.clone(), c]).contains("provides x"));
        assert!(validate_set(&[a, b], None).is_ok());
    }

    #[test]
    fn neither_relation_has_a_cycle() {
        let mut a = with("a", Kind::Optional, Image::Shell);
        let mut b = with("b", Kind::Optional, Image::Shell);
        a.depends = vec!["b".into()];
        b.depends = vec!["a".into()];
        assert!(refused(&[a, b]).contains("cycle"));
        let mut a = with("a", Kind::Optional, Image::Shell);
        let mut b = with("b", Kind::Optional, Image::Shell);
        a.build_depends = vec!["b".into()];
        b.build_depends = vec!["a".into()];
        assert!(refused(&[a, b]).contains("cycle"));
    }

    #[test]
    fn base_and_optional_depend_by_the_rules_of_the_note() {
        // A base package depends on base packages only.
        let mut base = with("base", Kind::Base, Image::Shell);
        let other = with("other", Kind::Optional, Image::Shell);
        base.depends = vec!["other".into()];
        assert!(
            refused(&[base.clone(), other.clone()])
                .contains("base package depends on the optional")
        );
        // An optional package never names a base package.
        let mut opt = other;
        base.depends.clear();
        opt.depends = vec!["base".into()];
        assert!(refused(&[base.clone(), opt]).contains("names the base package"));
        // Base on base is allowed.
        let mut second = with("second", Kind::Base, Image::Shell);
        second.depends = vec!["base".into()];
        assert!(validate_set(&[base, second], None).is_ok());
    }

    #[test]
    fn depends_stay_within_the_images() {
        let shell = with("shell", Kind::Optional, Image::Shell);
        let games = with("games", Kind::Optional, Image::Games);
        let fstack = with("fstack", Kind::Optional, Image::Fstack);
        let net = with("net", Kind::Optional, Image::Net);
        let on = |from: &Package, to: &Package| {
            let mut f = from.clone();
            f.depends = vec![to.name.clone()];
            validate_set(&[f, to.clone()], None)
        };
        assert!(on(&shell, &games).is_err());
        assert!(on(&shell, &net).is_err());
        assert!(on(&shell, &fstack).is_err());
        assert!(on(&games, &shell).is_ok());
        assert!(on(&games, &fstack).is_err());
        assert!(on(&fstack, &shell).is_ok());
        assert!(on(&fstack, &games).is_err());
        assert!(on(&net, &shell).is_ok());
        assert!(on(&net, &fstack).is_ok());
        assert!(on(&net, &games).is_err());
    }

    #[test]
    fn a_link_names_a_file_of_the_package_a_dependency_or_the_base() {
        let mut link = good();
        link.files = vec![("/bin/x".into(), "link:y".into())];
        link.program = None;
        let mut own = link.clone();
        own.files.push(("/bin/y".into(), "bytes:y".into()));
        assert!(validate_set(&[own], None).is_ok());
        let target = |kind, name: &str| Package {
            name: name.into(),
            kind,
            files: vec![("/bin/y".into(), "bytes:y".into())],
            program: None,
            ..good()
        };
        // A stranger's file: refused; the dependency's or a base package's: fine.
        assert!(refused(&[link.clone(), target(Kind::Optional, "t")]).contains("links to /bin/y"));
        let mut dependent = link.clone();
        dependent.depends = vec!["t".into()];
        assert!(validate_set(&[dependent, target(Kind::Optional, "t")], None).is_ok());
        assert!(validate_set(&[link, target(Kind::Base, "t")], None).is_ok());
    }

    #[test]
    fn the_order_puts_groups_in_turn_and_builds_links_before_the_package() {
        let mk = |name: &str, kind, build_depends: &[&str]| Package {
            name: name.into(),
            kind,
            build_depends: build_depends.iter().map(|d| (*d).into()).collect(),
            ..good()
        };
        let list = [
            mk("nano", Kind::Optional, &["ncurses"]),
            mk("ncurses", Kind::Optional, &[]),
            mk("busybox", Kind::Base, &["ncurses"]),
            mk("sbase", Kind::Base, &[]),
        ];
        let names: Vec<_> = order(&list).unwrap().into_iter().map(|p| p.name).collect();
        assert_eq!(names, ["sbase", "ncurses", "busybox", "nano"]);
    }

    #[test]
    fn the_games_stay_out_of_the_shell_image() {
        let shell = of_image("boot-ash-dialog.img").unwrap();
        assert!(shell.iter().all(|p| p.group() != Group::Game));
        let doom = of_image("boot-doom.img").unwrap();
        assert!(doom.len() > shell.len());
        assert!(doom.iter().any(|p| p.name == "freedoom"));
    }

    #[test]
    fn the_network_packages_and_fstack_stay_where_the_note_puts_them() {
        let shell = of_image("boot-ash-dialog.img").unwrap();
        assert!(
            shell
                .iter()
                .all(|p| !matches!(p.group(), Group::Net | Group::Fstack))
        );
        let doom = of_image("boot-doom.img").unwrap();
        assert!(
            doom.iter()
                .all(|p| !matches!(p.group(), Group::Net | Group::Fstack))
        );
        let net = of_image("boot-net.img").unwrap();
        for name in ["openssl", "curl", "ca-bundle", "f-stack"] {
            assert!(net.iter().any(|p| p.name == name), "{name}");
        }
        let probe = of_image("boot-fstack-probe.img").unwrap();
        assert!(probe.iter().any(|p| p.name == "f-stack"));
        assert!(probe.iter().all(|p| p.group() != Group::Net));
        // nginx on the stack is in the images with both devices and nowhere
        // else.
        for image in [
            "boot-net.img",
            "boot-fstack-probe.img",
            "boot-fast-layer.img",
        ] {
            let held = of_image(image).unwrap();
            assert!(held.iter().all(|p| p.name != "nginx-fast"), "{image}");
        }
        for image in [
            "boot-fast-nginx.img",
            "boot-fast-nginx-crash.img",
            "boot-fast-nginx-steps.img",
            "boot-fast-nginx-vz.img",
            "boot-fast-nginx-vz-steps.img",
            "boot-fast-scale.img",
            "boot-fast-switch.img",
            "boot-fast-switch-steps.img",
            "boot-fast-switch-vz.img",
            "boot-net-bench-fast.img",
            "boot-net-bench-switch.img",
            "boot-net-bench-switch-profile.img",
            "boot-net-bench-switch-pinned.img",
            "boot-net-bench-trace-fast.img",
            "boot-net-bench-trace-switch.img",
        ] {
            let held = of_image(image).unwrap();
            assert!(held.iter().any(|p| p.name == "nginx-fast"), "{image}");
            assert!(held.iter().any(|p| p.name == "nginx"), "{image}");
        }
    }

    #[test]
    fn the_descriptions_of_the_workspace_are_good() {
        let packages = load().unwrap();
        assert_eq!(packages.len(), 23);
        let get = |n: &str| packages.iter().find(|p| p.name == n).unwrap();
        assert_eq!(get("busybox").group(), Group::Base);
        assert_eq!(get("nano").group(), Group::Addon);
        assert_eq!(get("f-stack").group(), Group::Fstack);
        assert_eq!(get("curl").kind, Kind::Base);
        assert_eq!(get("nginx").build_depends, ["openssl", "pcre2"]);
        // nginx on the stack: F-Stack's package and notices travel with it.
        let fast = get("nginx-fast");
        assert_eq!(fast.group(), Group::Fstack);
        assert_eq!(fast.kind, Kind::Optional);
        assert_eq!(fast.depends, ["f-stack"]);
        assert_eq!(fast.build_depends, ["f-stack", "openssl", "pcre2"]);
        assert_eq!(fast.needs, ["net"]);
        assert!(fast.needs_network_device());
        assert!(get("f-stack").notices.iter().any(|n| n.0 == "NOTICES"));
        assert_eq!(get("doomgeneric").provides, ["doom"]);
        assert_eq!(get("f-stack").notices.len(), 3);
        assert!(packages.iter().all(|p| p.release == "1"));
    }
}
