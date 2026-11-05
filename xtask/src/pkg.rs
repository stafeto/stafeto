// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask pkg-build`: the package files of docs/packages.md built from
//! the descriptions and the outputs of the builds, and the fingerprint of the
//! recipe that says when a package must be built again.
//!
//! A package holds the directories and files its description names (the same
//! `rootfs::package_files` the images are made of, so the bytes are the
//! same), its notices under `/usr/share/licenses/<name>/` (notices.rs) and
//! every missing parent directory. It is written with `pkgfmt`, read back
//! with the code that will read it on the device, and checked against the
//! policy of official packages before it is moved to its place.

use crate::packages::{self, Package};
use crate::rootfs::{self, Source};
use crate::{keys, notices};
use pkgfmt::Package as PackageFile;
use pkgfmt::container::write::{Content, Item, container, sign};
use pkgfmt::manifest::Manifest;
use pkgfmt::meta::Meta;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Paths no package may declare besides the system's own (`is_system`).
const FORBIDDEN: [&str; 4] = ["/etc/pkg", "/dev", "/proc", "/usr/share/licenses/stafeto"];
const DIRECTORY: u32 = bootimg::rootfs::DIRECTORY;
const REGULAR: u32 = bootimg::rootfs::REGULAR;
const SYMLINK: u32 = bootimg::rootfs::SYMLINK;

/// One file or directory of a package before it is written.
pub struct Part {
    pub path: String,
    pub mode: u32,
    pub body: Body,
}

pub enum Body {
    Directory,
    /// `elf` marks the bytes of a program, which the recipe does not hash
    /// (the toolchain stands for them).
    Data {
        bytes: Vec<u8>,
        elf: bool,
    },
    /// The content of the part at this path.
    Same(String),
}

fn sha256_hex(data: &[u8]) -> String {
    let mut buf = [0u8; 64];
    pkgfmt::sha::hex(&pkgfmt::sha::sha256(data), &mut buf).to_string()
}

fn run_output(cmd: &mut Command) -> Result<String, String> {
    let out = cmd.output().map_err(|e| format!("{cmd:?}: {e}"))?;
    if !out.status.success() {
        return Err(format!("{cmd:?}: {}", out.status));
    }
    String::from_utf8(out.stdout).map_err(|e| e.to_string())
}

/// The commit of the tree: the 40 hexadecimal digits of `HEAD`.
pub fn commit() -> Result<String, String> {
    let c = run_output(
        Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(crate::root()),
    )?;
    Ok(c.trim().to_string())
}

/// `0.2` of the version `0.2.0` of the workspace.
pub fn series() -> String {
    let v = env!("CARGO_PKG_VERSION");
    v.split('.').take(2).collect::<Vec<_>>().join(".")
}

/// The time of the tables of the packages and the sources of the archives:
/// the time a run has fixed for its images (`rootfs::set_build_time`), else
/// SOURCE_DATE_EPOCH, else the time of the commit.
///
/// The order inside one run matters: a package written before the run fixed
/// its time keeps the time it had (the clock probe sets the time first).
fn table_time() -> Result<u64, String> {
    // A run that dates its images back dates the packages the same.
    if let Some(fixed) = rootfs::fixed_build_time() {
        return Ok(fixed);
    }
    if let Ok(text) = std::env::var("SOURCE_DATE_EPOCH") {
        return text
            .trim()
            .parse()
            .map_err(|_| format!("SOURCE_DATE_EPOCH={text:?} is no number of seconds"));
    }
    let t = run_output(
        Command::new("git")
            .args(["log", "-1", "--format=%ct"])
            .current_dir(crate::root()),
    )?;
    t.trim().parse().map_err(|_| format!("git log gave {t:?}"))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// ---- the programs ----

/// The linked, stripped ELF file of `program` for a package, copied under
/// `target/pkg/work/<package>/`: the file the image holds, byte for byte.
fn program_bytes(package: &str, program: &str) -> Result<Vec<u8>, String> {
    let entry = crate::PACKAGE_PROGRAMS
        .iter()
        .find(|p| p.0 == program)
        .ok_or_else(|| {
            format!("{package}: no build of the program {program} (PACKAGE_PROGRAMS)")
        })?;
    let built = crate::target_dir()
        .join("libc-so")
        .join("programs")
        .join(crate::dynamic_name(entry.1, entry.3));
    let work = crate::target_dir().join("pkg/work").join(package);
    std::fs::create_dir_all(&work).map_err(|e| format!("{}: {e}", work.display()))?;
    let elf = work.join(program);
    std::fs::copy(&built, &elf).map_err(|e| format!("{}: {e}", built.display()))?;
    let objdump = crate::llvm_tool("llvm-objdump")?;
    crate::disasm::erratum_835769(&elf, &objdump)?;
    crate::disasm::erratum_843419(&elf)?;
    crate::strip_elf(&elf, &crate::llvm_tool("llvm-objcopy")?)?;
    std::fs::read(&elf).map_err(|e| format!("{}: {e}", elf.display()))
}

/// Builds what the packages `selected` need: the scripts of their groups and
/// the dynamic programs.
fn build_outputs(selected: &[&Package]) -> Result<(), String> {
    crate::relibc()?;
    // The scripts in the order of the descriptions (the base first, each
    // after the packages it links in).
    let all = packages::load()?;
    for p in all
        .iter()
        .filter(|p| selected.iter().any(|s| s.name == p.name))
    {
        crate::package_script(p)?;
    }
    let mut names: Vec<&'static str> = Vec::new();
    for p in selected {
        if let Some(program) = &p.program {
            let entry = crate::PACKAGE_PROGRAMS
                .iter()
                .find(|e| e.0 == program)
                .ok_or_else(|| format!("{}: no build of the program {program}", p.name))?;
            names.push(crate::dynamic_name(entry.1, entry.3));
        }
    }
    if !names.is_empty() {
        crate::dynamic_programs(&names)?;
    }
    Ok(())
}

// ---- the parts of a package ----

fn parents(path: &str) -> impl Iterator<Item = String> + '_ {
    path.match_indices('/')
        .skip(1)
        .map(move |(i, _)| path[..i].to_string())
}

/// What a package holds. `build` adds `SOURCE`; without it the parts are
/// what the recipe hashes.
pub fn parts(
    p: &Package,
    all: &[Package],
    build: Option<&notices::Build<'_>>,
) -> Result<Vec<Part>, String> {
    let declared = rootfs::package_files(std::slice::from_ref(p))?;
    for f in &declared {
        if rootfs::is_system(f.path)
            || FORBIDDEN
                .iter()
                .any(|d| f.path == *d || f.path.starts_with(&format!("{d}/")))
        {
            return Err(format!(
                "{}: {} is a path of the system, which no package holds",
                p.name, f.path
            ));
        }
        if f.mode & 0o7000 != 0 {
            return Err(format!("{}: {} has set-ID or sticky bits", p.name, f.path));
        }
    }
    let sources = rootfs::sources(&declared);
    let mut first: Vec<Option<&str>> = vec![None; sources.len()];
    let mut out: Vec<Part> = Vec::new();
    let read_elf = |program: &str| program_bytes(&p.name, program);
    for f in &declared {
        let (mode, body) = match f.source {
            None => (DIRECTORY | f.mode, Body::Directory),
            Some(source) => {
                let at = sources.iter().position(|s| *s == source).expect("listed");
                let kind = if matches!(source, Source::Link(_)) {
                    SYMLINK
                } else {
                    REGULAR
                };
                let body = match first[at] {
                    Some(path) => Body::Same(path.to_string()),
                    None => {
                        first[at] = Some(f.path);
                        Body::Data {
                            bytes: source.bytes(read_elf)?,
                            elf: source.program().is_some(),
                        }
                    }
                };
                (kind | f.mode, body)
            }
        };
        out.push(Part {
            path: f.path.to_string(),
            mode,
            body,
        });
    }
    let mut notice_files = notices::files(p, all, &placeholder())?;
    if let Some(b) = build {
        notice_files.retain(|(path, _)| {
            !path.ends_with("/SOURCE") || path != &format!("{}/SOURCE", notices::directory(&p.name))
        });
        notice_files.push((
            format!("{}/SOURCE", notices::directory(&p.name)),
            notices::source_text(p, all, b).into_bytes(),
        ));
    } else {
        let source = format!("{}/SOURCE", notices::directory(&p.name));
        notice_files.retain(|(path, _)| *path != source);
    }
    for (path, bytes) in notice_files {
        out.push(Part {
            path,
            mode: REGULAR | 0o644,
            body: Body::Data { bytes, elf: false },
        });
    }
    // The directories the notices and the files stand in.
    let mut have: BTreeSet<String> = out.iter().map(|p| p.path.clone()).collect();
    let mut extra = Vec::new();
    for part in &out {
        for dir in parents(&part.path) {
            if have.insert(dir.clone()) {
                extra.push(Part {
                    path: dir,
                    mode: DIRECTORY | 0o755,
                    body: Body::Directory,
                });
            }
        }
    }
    out.extend(extra);
    out.sort_by(|a, b| a.path.cmp(&b.path));
    if out.len() > pkgfmt::container::ENTRIES_MAX {
        return Err(format!(
            "{}: {} entries, over {}",
            p.name,
            out.len(),
            pkgfmt::container::ENTRIES_MAX
        ));
    }
    Ok(out)
}

fn placeholder() -> notices::Build<'static> {
    notices::Build {
        commit: "",
        relibc: None,
        recipe: "",
    }
}

// ---- the recipe ----

/// The `tools/*.py` files a script loads, by their names in its text, and
/// the closure of those. Paths from the root, sorted.
fn script_closure(root: &Path, first: &str) -> Result<Vec<String>, String> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut pending = vec![first.to_string()];
    while let Some(path) = pending.pop() {
        if !seen.insert(path.clone()) {
            continue;
        }
        let text = std::fs::read_to_string(root.join(&path)).map_err(|e| format!("{path}: {e}"))?;
        for name in python_names(&text) {
            let found = format!("tools/{name}");
            if found != path && root.join(&found).is_file() {
                pending.push(found);
            }
        }
    }
    Ok(seen.into_iter().collect())
}

/// The names `x.py` in the text and the modules of its `import` lines.
fn python_names(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    let bytes = text.as_bytes();
    let word = |c: u8| c.is_ascii_alphanumeric() || b"_.-".contains(&c);
    let mut at = 0;
    while let Some(i) = text[at..].find(".py") {
        let end = at + i;
        let after = bytes.get(end + 3).copied();
        let mut start = end;
        while start > 0 && word(bytes[start - 1]) {
            start -= 1;
        }
        if start < end && after.is_none_or(|c| !word(c)) {
            names.push(format!("{}.py", &text[start..end]));
        }
        at = end + 3;
    }
    for line in text.lines() {
        let line = line.trim_start();
        let modules = line.strip_prefix("import ").or_else(|| {
            line.strip_prefix("from ")
                .and_then(|r| r.split(" import").next())
        });
        for m in modules.into_iter().flat_map(|m| m.split(',')) {
            let m = m.split(" as ").next().unwrap_or("").trim();
            if !m.is_empty() && m.bytes().all(word) {
                names.push(format!("{m}.py"));
            }
        }
    }
    names
}

/// The inputs of the recipe of `p` as sorted lines `<kind> <name> <sha256>`.
/// `list` names the files of a directory of the tree (`git ls-files`),
/// `data` the hashes of the files of the package that are no program,
/// `toolchain` the clang and relibc pin of a package with programs and
/// `deps` the recipes of the packages linked in.
pub fn recipe_lines(
    root: &Path,
    list: &dyn Fn(&str) -> Result<Vec<String>, String>,
    p: &Package,
    all: &[Package],
    data: &[(String, String)],
    toolchain: Option<(&str, &str)>,
    deps: &[(String, String)],
) -> Result<Vec<String>, String> {
    let mut lines: Vec<String> = Vec::new();
    let file = |path: &str| -> Result<String, String> {
        let bytes = std::fs::read(root.join(path)).map_err(|e| format!("{path}: {e}"))?;
        Ok(format!("file {path} {}", sha256_hex(&bytes)))
    };
    // 1: the descriptions of the group that one script builds.
    let group: Vec<&Package> = all.iter().filter(|q| q.build == p.build).collect();
    for q in &group {
        lines.push(file(&format!("packages/{}.toml", q.name))?);
    }
    // 2 and 3: the script, what it loads, and their directories.
    let scripts = script_closure(root, &p.build)?;
    let mut dirs: Vec<String> = Vec::new();
    for s in &scripts {
        lines.push(file(s)?);
        if let Some(base) = s
            .strip_prefix("tools/build-")
            .and_then(|n| n.strip_suffix(".py"))
        {
            dirs.push(format!("tools/{base}/"));
        }
    }
    for q in &group {
        dirs.push(format!("ports/{}/", q.name));
    }
    dirs.sort();
    dirs.dedup();
    let mut tracked: BTreeSet<String> = BTreeSet::new();
    for d in &dirs {
        tracked.extend(list(d)?);
    }
    for path in tracked {
        lines.push(file(&path)?);
    }
    // 4: the files that are no programs, by their bytes.
    for (path, digest) in data {
        lines.push(format!("data {path} {digest}"));
    }
    // 5: the toolchain of a package with programs.
    if let Some((clang, pin)) = toolchain {
        lines.push(format!("tool clang {clang}"));
        lines.push(format!("pin relibc {pin}"));
        lines.push(file("tools/build-libc-so.py")?);
        lines.push(file("tools/build-relibc.py")?);
    }
    // 6: the packages linked in.
    for (name, recipe) in deps {
        lines.push(format!("build-depends {name} {recipe}"));
    }
    lines.sort();
    lines.dedup();
    Ok(lines)
}

pub fn recipe_hash(lines: &[String]) -> String {
    let mut text = String::new();
    for l in lines {
        text += l;
        text.push('\n');
    }
    sha256_hex(text.as_bytes())
}

/// The files of the tree under `dir` that git knows. A failure of git stops
/// the build: a recipe made without them would differ from the true one.
fn git_list(dir: &str) -> Result<Vec<String>, String> {
    run_output(
        Command::new("git")
            .args(["ls-files", dir])
            .current_dir(crate::root()),
    )
    .map(|s| s.lines().map(str::to_string).collect())
    .map_err(|e| format!("the inputs of the recipe under {dir}: {e}"))
}

/// The version of the clang that builds relibc and the programs.
fn clang_version() -> Result<String, String> {
    let brew = Path::new("/opt/homebrew/opt/llvm/bin/clang");
    let mut cmd = if brew.exists() {
        Command::new(brew)
    } else {
        Command::new("clang")
    };
    let text = run_output(cmd.arg("--version"))?;
    let first = text.lines().next().unwrap_or("");
    first
        .split("version ")
        .nth(1)
        .and_then(|r| r.split(|c: char| !(c.is_ascii_digit() || c == '.')).next())
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("clang --version gave {first:?}"))
}

/// The recipes (the fingerprint and the lines) of the packages `wanted`,
/// which must hold every package they link in; needs the outputs of the
/// builds for the files that are no programs.
pub fn recipes(
    all: &[Package],
    wanted: &[&Package],
) -> Result<BTreeMap<String, (String, Vec<String>)>, String> {
    let root = crate::root();
    let pin = crate::script_value("tools/build-relibc.py", "COMMIT")?;
    let clang = clang_version()?;
    let mut done: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
    let mut order: Vec<&Package> = wanted.to_vec();
    order.sort_by_key(|p| p.name.clone());
    // Packages linked in come first.
    let mut ready: Vec<&Package> = Vec::new();
    while ready.len() < order.len() {
        let next = order
            .iter()
            .find(|p| {
                !ready.iter().any(|r| r.name == p.name)
                    && p.build_depends
                        .iter()
                        .all(|d| ready.iter().any(|r| r.name == *d))
            })
            .ok_or("build_depends form a cycle")?;
        ready.push(next);
    }
    for p in ready {
        let mut data = Vec::new();
        let mut elf = false;
        for part in parts(p, all, None)? {
            if let Body::Data { bytes, elf: is_elf } = &part.body {
                if *is_elf {
                    elf = true;
                } else {
                    data.push((part.path.clone(), sha256_hex(bytes)));
                }
            }
        }
        let deps: Vec<(String, String)> = p
            .build_depends
            .iter()
            .map(|d| {
                (
                    d.clone(),
                    done.get(d).map(|(h, _)| h.clone()).unwrap_or_default(),
                )
            })
            .collect();
        let toolchain = elf.then_some((clang.as_str(), pin.as_str()));
        let lines = recipe_lines(&root, &git_list, p, all, &data, toolchain, &deps)?;
        done.insert(p.name.clone(), (recipe_hash(&lines), lines));
    }
    Ok(done)
}

// ---- building ----

pub struct Options {
    pub names: Vec<String>,
    pub key: Option<PathBuf>,
    pub cert: Option<PathBuf>,
    pub time: Option<u64>,
    pub out: Option<PathBuf>,
    pub recipe: bool,
    /// Bytes that replace the packages' own at paths of the selected
    /// packages: the package file is a variant for one image (`image_files`).
    pub replace: Vec<(String, Vec<u8>)>,
}

pub struct Built {
    pub package: Package,
    pub path: PathBuf,
    pub size: u64,
    pub entries: usize,
    pub recipe: String,
    /// The inputs the fingerprint hashes.
    pub lines: Vec<String>,
    pub content: u64,
}

/// The packages this run of xtask wrote to `target/pkg/`: an image takes the
/// package files of the run, so that the image, the repository and the
/// index of one run hold the same bytes.
static BUILT: std::sync::Mutex<BTreeSet<String>> = std::sync::Mutex::new(BTreeSet::new());

/// The package files of the layers of an image, as the container of the
/// image holds them: the name (`<name>-<version>-<release>.stpkg`) and the
/// bytes. A package the run has not built is built first (once, with the
/// development key); the package file an image holds is the file of
/// `target/pkg/`, so that its bytes are those of the repository of the run.
/// A package with bytes of its own for the image (`replaced`) is built for
/// the image into `target/pkg/variants/<image>/`.
pub fn image_files(
    image: &str,
    layers: &[rootfs::LayerPackage],
) -> Result<Vec<(String, Vec<u8>)>, String> {
    let built = |name: &str| {
        BUILT
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(name)
    };
    let missing: Vec<String> = layers
        .iter()
        .filter(|l| l.replaced.is_empty() && !built(&l.package.name))
        .map(|l| l.package.name.clone())
        .collect();
    if !missing.is_empty() {
        build(&Options {
            names: missing,
            key: None,
            cert: None,
            time: None,
            out: None,
            recipe: false,
            replace: Vec::new(),
        })?;
    }
    let plain = crate::target_dir().join("pkg");
    let mut files = Vec::new();
    for l in layers {
        let dir = if l.replaced.is_empty() {
            plain.clone()
        } else {
            let dir = plain
                .join("variants")
                .join(image.strip_suffix(".img").unwrap_or(image));
            build(&Options {
                names: vec![l.package.name.clone()],
                key: None,
                cert: None,
                time: None,
                out: Some(dir.clone()),
                recipe: false,
                replace: l
                    .replaced
                    .iter()
                    .map(|(path, bytes)| ((*path).to_string(), bytes.to_vec()))
                    .collect(),
            })?;
            dir
        };
        let name = file_name(&l.package);
        if name.len() > bootimg::NAME_MAX {
            return Err(format!(
                "{name} is over {} bytes: too long for a file of an image",
                bootimg::NAME_MAX
            ));
        }
        let path = dir.join(&name);
        let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        files.push((name, bytes));
    }
    Ok(files)
}

/// The file name of a package.
pub fn file_name(p: &Package) -> String {
    format!("{}.stpkg", notices::stem(p))
}

fn list_or_dash(list: &[String]) -> String {
    if list.is_empty() {
        "-".into()
    } else {
        list.join(" ")
    }
}

/// Builds the packages `names` (all with files if empty).
pub fn build(opts: &Options) -> Result<Vec<Built>, String> {
    let all = packages::load()?;
    let has_files = |p: &Package| !(p.files.is_empty() && p.dirs.is_empty());
    let selected: Vec<&Package> = if opts.names.is_empty() {
        all.iter().filter(|p| has_files(p)).collect()
    } else {
        let mut v = Vec::new();
        for n in &opts.names {
            let p = all
                .iter()
                .find(|p| p.name == *n)
                .ok_or_else(|| format!("no package {n}"))?;
            if !has_files(p) {
                return Err(format!("{n} installs no file: it has no package file"));
            }
            v.push(p);
        }
        v
    };
    let started = std::time::Instant::now();
    // The recipes of linked-in packages come from every package, so the
    // outputs of the builds the selection needs are enough only when the
    // linked-in ones have none of their own data: build for all of them.
    let needed: Vec<&Package> = {
        let mut v: Vec<&Package> = selected.clone();
        let mut i = 0;
        while i < v.len() {
            for d in &v[i].build_depends.clone() {
                if let Some(q) = all.iter().find(|q| q.name == *d)
                    && !v.iter().any(|x| x.name == q.name)
                {
                    v.push(q);
                }
            }
            i += 1;
        }
        v
    };
    build_outputs(&needed)?;
    let recipes = recipes(&all, &needed)?;
    if opts.recipe {
        for p in &selected {
            let (hash, lines) = &recipes[&p.name];
            println!("recipe of {}:", p.name);
            for l in lines {
                println!("  {l}");
            }
            println!("{} {hash}", p.name);
        }
        return Ok(Vec::new());
    }
    let tree = crate::root();
    let signing = keys::signing(opts.key.as_deref(), opts.cert.as_deref(), &tree)?;
    let commit = commit()?;
    let pin = crate::script_value("tools/build-relibc.py", "COMMIT")?;
    let table = table_time()?;
    let out_dir = opts
        .out
        .clone()
        .unwrap_or_else(|| crate::target_dir().join("pkg"));
    std::fs::create_dir_all(&out_dir).map_err(|e| format!("{}: {e}", out_dir.display()))?;
    let (roots, direct) = keys::trust_of(&signing, &tree)?;
    let mut built = Vec::new();
    for p in selected {
        let recipe = recipes[&p.name].0.clone();
        let relibc = format!("pin-{}", &pin[..8]);
        let build = notices::Build {
            commit: &commit,
            relibc: None,
            recipe: &recipe,
        };
        let has_elf = p.files.iter().any(|(_, f)| f.starts_with("elf:"));
        let build = notices::Build {
            relibc: has_elf.then_some(relibc.as_str()),
            ..build
        };
        let mut all_parts = parts(p, &all, Some(&build))?;
        for (path, bytes) in &opts.replace {
            let part = all_parts
                .iter_mut()
                .find(|part| part.path == *path && matches!(part.body, Body::Data { .. }))
                .ok_or_else(|| format!("{}: no file {path} to replace", p.name))?;
            part.body = Body::Data {
                bytes: bytes.clone(),
                elf: false,
            };
        }
        let items: Vec<Item<'_>> = all_parts
            .iter()
            .map(|part| Item {
                path: &part.path,
                mode: part.mode,
                content: match &part.body {
                    Body::Directory => Content::Directory,
                    Body::Data { bytes, .. } => Content::Data(bytes),
                    Body::Same(path) => Content::Same(path),
                },
            })
            .collect();
        let depends = list_or_dash(&p.depends);
        let provides = list_or_dash(&p.provides);
        let needs = list_or_dash(&p.needs);
        let series = series();
        let relibc_field = if has_elf {
            relibc.clone()
        } else {
            "-".to_string()
        };
        let meta = Meta {
            name: &p.name,
            version: &p.version,
            release: &p.release,
            arch: "aarch64",
            series: &series,
            license: &p.license,
            depends: &depends,
            provides: &provides,
            needs: &needs,
            summary: &p.summary,
            url: &p.url,
            sha256: &p.sha256,
            recipe: &recipe,
            commit: &commit,
            relibc: &relibc_field,
            size: 0,
        };
        let covered = container(&meta, &items, table).map_err(|e| format!("{}: {e}", p.name))?;
        let bytes = sign(
            covered,
            &signing.seed,
            signing.key,
            signing.certificate,
            opts.time.unwrap_or_else(now),
        )
        .map_err(|e| format!("{}: {e}", p.name))?;
        // The check on the host is the one the device makes.
        let file = PackageFile::parse(&bytes).map_err(|e| format!("{}: {e}", p.name))?;
        file.check_policy(&p.name)
            .map_err(|e| format!("{}: {e}", p.name))?;
        Manifest::check(&file).map_err(|e| format!("{}: {e}", p.name))?;
        // What the device would do with the file: it must accept it.
        file.verify(
            &pkgfmt::Trust {
                roots: &roots,
                direct: &direct,
            },
            &[],
        )
        .map_err(|e| {
            format!(
                "{}: the signature of the key {} is not accepted: {e}",
                p.name,
                signing.key.as_str()
            )
        })?;
        let path = out_dir.join(file_name(p));
        let temp = path.with_extension("stpkg.part");
        std::fs::write(&temp, &bytes).map_err(|e| format!("{}: {e}", temp.display()))?;
        std::fs::rename(&temp, &path).map_err(|e| format!("{}: {e}", path.display()))?;
        if opts.out.is_none() {
            BUILT
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(p.name.clone());
        }
        println!(
            "{}  {} bytes  {} entries  {} bytes of content  recipe {}",
            path.display(),
            bytes.len(),
            file.rootfs.len(),
            file.meta.size,
            &recipe[..12]
        );
        built.push(Built {
            package: p.clone(),
            path,
            size: bytes.len() as u64,
            entries: file.rootfs.len(),
            lines: recipes[&p.name].1.clone(),
            recipe,
            content: file.meta.size,
        });
    }
    println!(
        "pkg-build: {} packages in {:.0} s",
        built.len(),
        started.elapsed().as_secs_f64()
    );
    Ok(built)
}

fn parse_options(args: &[String]) -> Result<Options, String> {
    let mut o = Options {
        names: Vec::new(),
        key: None,
        cert: None,
        time: None,
        out: None,
        recipe: false,
        replace: Vec::new(),
    };
    let mut i = 0;
    let value = |i: &mut usize| -> Result<String, String> {
        *i += 1;
        args.get(*i)
            .cloned()
            .ok_or_else(|| format!("{} wants a value", args[*i - 1]))
    };
    while i < args.len() {
        match args[i].as_str() {
            "--key" => o.key = Some(value(&mut i)?.into()),
            "--cert" => o.cert = Some(value(&mut i)?.into()),
            "--out" => o.out = Some(value(&mut i)?.into()),
            "--time" => {
                let t = value(&mut i)?;
                o.time = Some(
                    t.parse()
                        .map_err(|_| format!("--time {t}: not a number of seconds"))?,
                );
            }
            "--recipe" => o.recipe = true,
            name if !name.starts_with("--") => o.names.push(name.to_string()),
            other => return Err(format!("{other}: unknown argument")),
        }
        i += 1;
    }
    Ok(o)
}

/// `cargo xtask pkg-build [name...] [--key K.key --cert K.cert] [--time SECONDS] [--out D] [--recipe]`.
pub fn command(args: &[String]) -> Result<(), String> {
    build(&parse_options(args)?).map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("stafeto-pkg-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn package(name: &str, build: &str) -> Package {
        let text = format!(
            "name = \"{name}\"\nversion = \"1\"\nkind = \"optional\"\nimage = \"shell\"\nrelease = \"1\"\nsummary = \"s\"\nurl = \"https://example.org/x.tar.gz\"\nsha256 = \"{}\"\nlicense = \"MIT\"\nbuild = \"{build}\"\nfiles = [\"/bin/{name} = bytes:x\"]\n",
            "ab".repeat(32)
        );
        packages::parse(&text, "x.toml").unwrap()
    }

    fn tree(root: &Path) {
        for (path, text) in [
            ("packages/a.toml", "a"),
            ("packages/b.toml", "b"),
            ("packages/c.toml", "c"),
            (
                "tools/build-a.py",
                "import helper\nsubprocess.run(['tools/build-a2.py'])\n",
            ),
            ("tools/build-a2.py", "print(1)\n"),
            ("tools/build-c.py", "print(2)\n"),
            ("tools/helper.py", "x = 1\n"),
            ("tools/build-libc-so.py", "l"),
            ("tools/build-relibc.py", "r"),
            ("tools/unrelated.py", "x = 2\n"),
            ("tools/a/conf", "setting\n"),
            ("tools/c/conf", "other\n"),
            ("ports/a/note", "n"),
        ] {
            let p = root.join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
    }

    fn walk(root: &Path, dir: &str) -> Vec<String> {
        let mut out = Vec::new();
        let base = root.join(dir);
        if let Ok(read) = std::fs::read_dir(&base) {
            for e in read.flatten() {
                let rel = format!("{dir}{}", e.file_name().to_string_lossy());
                if e.path().is_dir() {
                    out.extend(walk(root, &format!("{rel}/")));
                } else {
                    out.push(rel);
                }
            }
        }
        out
    }

    fn lines(root: &Path, name: &str, build: &str, all: &[Package], data: &str) -> Vec<String> {
        let p = all.iter().find(|p| p.name == name).unwrap();
        let _ = build;
        recipe_lines(
            root,
            &|d| Ok(walk(root, d)),
            p,
            all,
            &[(format!("/bin/{name}"), data.into())],
            None,
            &[],
        )
        .unwrap()
    }

    #[test]
    fn the_script_closure_follows_names_and_imports() {
        let root = scratch("closure");
        tree(&root);
        assert_eq!(
            script_closure(&root, "tools/build-a.py").unwrap(),
            ["tools/build-a.py", "tools/build-a2.py", "tools/helper.py"]
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn one_changed_input_changes_the_recipes_that_name_it_and_no_other() {
        let root = scratch("recipe");
        tree(&root);
        let all = [
            package("a", "tools/build-a.py"),
            package("b", "tools/build-a.py"),
            package("c", "tools/build-c.py"),
        ];
        let before: Vec<String> = ["a", "b", "c"]
            .iter()
            .map(|n| recipe_hash(&lines(&root, n, "", &all, "d")))
            .collect();
        // A file under tools/a/ belongs to the group of a and b only.
        std::fs::write(root.join("tools/a/conf"), "setting \n").unwrap();
        let after: Vec<String> = ["a", "b", "c"]
            .iter()
            .map(|n| recipe_hash(&lines(&root, n, "", &all, "d")))
            .collect();
        assert_ne!(before[0], after[0]);
        assert_ne!(before[1], after[1]);
        assert_eq!(before[2], after[2]);
        // The group of a and b share inputs but not their own data.
        assert_ne!(after[0], after[1]);
        // A byte of the data of c changes c alone.
        let c = recipe_hash(&lines(&root, "c", "", &all, "e"));
        assert_ne!(c, after[2]);
        // A script nobody names changes nothing.
        std::fs::write(root.join("tools/unrelated.py"), "x = 3\n").unwrap();
        assert_eq!(recipe_hash(&lines(&root, "a", "", &all, "d")), after[0]);
        // The toolchain and the linked-in recipes are lines of their own.
        let p = &all[0];
        let with = recipe_lines(
            &root,
            &|d| Ok(walk(&root, d)),
            p,
            &all,
            &[],
            Some(("22.1.2", "abc")),
            &[("z".into(), "r".into())],
        )
        .unwrap();
        assert!(with.contains(&"tool clang 22.1.2".to_string()));
        assert!(with.contains(&"pin relibc abc".to_string()));
        assert!(with.contains(&"build-depends z r".to_string()));
        assert!(with.windows(2).all(|w| w[0] <= w[1]));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_failing_git_stops_the_recipe() {
        let root = scratch("git");
        tree(&root);
        let all = [package("a", "tools/build-a.py")];
        let err = recipe_lines(
            &root,
            &|_| Err("git is gone".to_string()),
            &all[0],
            &all,
            &[],
            None,
            &[],
        )
        .unwrap_err();
        assert!(err.contains("git is gone"));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn parents_of_a_path() {
        assert_eq!(
            parents("/usr/share/licenses/x/LICENSE").collect::<Vec<_>>(),
            [
                "/usr",
                "/usr/share",
                "/usr/share/licenses",
                "/usr/share/licenses/x"
            ]
        );
        assert_eq!(parents("/bin").count(), 0);
    }

    #[test]
    fn the_series_is_the_minor_part() {
        assert_eq!(series().matches('.').count(), 1);
    }
}
