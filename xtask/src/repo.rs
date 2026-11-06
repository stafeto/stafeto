// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask repo`: a repository of the packages in
//! `target/repo/<series>/aarch64/` (docs/packages.md): the `.stpkg` files, the
//! index `INDEX` signed in `INDEX.sig`, the revocation list `revoked` signed
//! in `revoked.sig` and the source archives in `src/`. The index and the
//! packages are signed by the release key (the development one unless
//! `--key` and `--cert` say otherwise), the revocation list by the root.

use crate::packages::{self, Package};
use crate::pkg::{self, Built};
use crate::{keys, notices};
use pkgfmt::index::{self, Entry, Header, Index};
use pkgfmt::sig::{Block, Kind};
use pkgfmt::{Key, Package as PackageFile, Revocation, Trust, revoked, sha};
use std::path::{Path, PathBuf};
use std::process::Command;

const DAY: u64 = 86_400;
/// An index is good for at most this many days (spec 5, 3.7).
const EXPIRES_MAX_DAYS: u64 = 30;

#[derive(Clone)]
pub struct Options {
    pub serial: u64,
    pub expires_days: u64,
    pub sources: bool,
    pub key: Option<PathBuf>,
    pub cert: Option<PathBuf>,
    pub root: Option<PathBuf>,
    pub check: bool,
    pub official: bool,
    pub dir: Option<PathBuf>,
    /// The directory or address of the published index to carry from.
    pub previous: Option<String>,
    /// A directory of package files to write an index for, without a build.
    pub from: Option<PathBuf>,
    /// The release of the storage new files are stored in (`v0.3.0-aarch64`).
    pub storage: Option<String>,
    /// `--serial` was given.
    pub serial_given: bool,
    /// `--check` reads the repository at this address, every file over the
    /// network, and takes no directory.
    pub remote: Option<String>,
    /// Packages whose recipe is changed on purpose (the carrying probe of `pkg-identity`).
    pub perturb: Vec<String>,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            serial: 1,
            expires_days: EXPIRES_MAX_DAYS,
            sources: true,
            key: None,
            cert: None,
            root: None,
            check: false,
            official: false,
            dir: None,
            previous: None,
            from: None,
            storage: None,
            serial_given: false,
            remote: None,
            perturb: Vec::new(),
        }
    }
}

pub fn parse_options(args: &[String]) -> Result<Options, String> {
    let mut o = Options::default();
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        let wants_value = flag != "--no-sources" && flag != "--check" && flag != "--official";
        let value = if wants_value {
            i += 1;
            args.get(i)
                .cloned()
                .ok_or_else(|| format!("{flag} wants a value"))?
        } else {
            String::new()
        };
        match flag {
            "--previous" => o.previous = Some(value),
            "--from" => o.from = Some(value.into()),
            "--storage" => o.storage = Some(value),
            "--remote" => o.remote = Some(value),
            "--serial" => {
                o.serial_given = true;
                o.serial = value
                    .parse()
                    .map_err(|_| format!("--serial {value}: not a number"))?
            }
            "--expires-days" => {
                o.expires_days = value
                    .parse()
                    .map_err(|_| format!("--expires-days {value}: not a number"))?;
                if o.expires_days == 0 || o.expires_days > EXPIRES_MAX_DAYS {
                    return Err(format!(
                        "--expires-days {value}: an index lives 1 to {EXPIRES_MAX_DAYS} days"
                    ));
                }
            }
            "--no-sources" => o.sources = false,
            "--key" => o.key = Some(value.into()),
            "--cert" => o.cert = Some(value.into()),
            "--root" => o.root = Some(value.into()),
            "--dir" => o.dir = Some(value.into()),
            "--check" => o.check = true,
            "--official" => o.official = true,
            other => return Err(format!("{other}: unknown argument")),
        }
        i += 1;
    }
    Ok(o)
}

/// Where the repository of this series is built.
pub fn directory() -> PathBuf {
    crate::target_dir()
        .join("repo")
        .join(pkg::series())
        .join("aarch64")
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn sha_hex(data: &[u8]) -> String {
    let mut buf = [0u8; 64];
    sha::hex(&sha::sha256(data), &mut buf).to_string()
}

/// Makes `dir` ready for a new repository: a directory under `target/` is
/// emptied (it is the tool's own); any other directory must not exist or be
/// empty, so that no option can delete what the tool did not make.
fn prepare(dir: &Path) -> Result<(), String> {
    let target = crate::root().join("target");
    let canonical = |p: &Path| p.canonicalize().ok();
    let under_target = match (canonical(dir), canonical(&target)) {
        (Some(d), Some(t)) => d != t && d.starts_with(&t),
        _ => false,
    };
    if !dir.exists() {
        return Ok(());
    }
    if under_target {
        return std::fs::remove_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()));
    }
    let empty = std::fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .next()
        .is_none();
    if empty {
        Ok(())
    } else {
        Err(format!(
            "{}: the directory is not empty and not under target/; repo deletes only what it made there",
            dir.display()
        ))
    }
}

/// One entry of the index with the text it borrows from.
struct Row {
    name: String,
    version: String,
    digest: String,
    file: String,
    size: u64,
    source: Option<String>,
    provides: Option<String>,
    depends: Option<String>,
    needs: Option<String>,
    license: String,
    recipe: String,
    summary: String,
}

/// Writes `INDEX`, `INDEX.sig`, `revoked` and `revoked.sig` for `rows` into
/// `dir`. The index is signed by the release key; the list is the development
/// root's empty one, or with `--official` the file of `keys/`.
fn write_repository(dir: &Path, rows: &[Row], o: &Options) -> Result<(), String> {
    let tree = crate::root();
    let signing = keys::signing(o.key.as_deref(), o.cert.as_deref(), &tree)?;
    let mut rows: Vec<&Row> = rows.iter().collect();
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    let entries: Vec<Entry<'_>> = rows
        .iter()
        .map(|r| Entry {
            name: &r.name,
            version: &r.version,
            provides: r.provides.as_deref(),
            depends: r.depends.as_deref(),
            needs: r.needs.as_deref(),
            license: &r.license,
            size: r.size,
            sha256: &r.digest,
            recipe: &r.recipe,
            file: &r.file,
            source: r.source.as_deref(),
            summary: &r.summary,
        })
        .collect();
    let signed_at = now();
    let series = pkg::series();
    let header = Header {
        repository: "stafeto",
        series: &series,
        arch: "aarch64",
        serial: o.serial,
        expires: signed_at + o.expires_days * DAY,
    };
    let text = index::write(&header, &entries).map_err(|e| format!("INDEX: {e}"))?;
    let block = Block::sign(
        &signing.seed,
        Kind::Index,
        text.len() as u64,
        sha::sha256(text.as_bytes()),
        signed_at,
        signing.key,
        signing.certificate,
    );
    let (roots, direct) = keys::trust_of(&signing, &tree)?;
    pkgfmt::trust::verify(
        &block,
        Kind::Index,
        &sha::sha256(text.as_bytes()),
        text.len() as u64,
        &Trust {
            roots: &roots,
            direct: &direct,
        },
        &[],
    )
    .map_err(|e| {
        format!(
            "INDEX: the signature of the key {} is not accepted: {e}",
            signing.key.as_str()
        )
    })?;
    std::fs::write(dir.join("INDEX"), &text).map_err(|e| format!("INDEX: {e}"))?;
    std::fs::write(dir.join("INDEX.sig"), block.to_bytes())
        .map_err(|e| format!("INDEX.sig: {e}"))?;
    if o.official {
        // The list of the owner, as the tree keeps it.
        for name in ["revoked", "revoked.sig"] {
            let from = tree.join("keys").join(name);
            std::fs::copy(&from, dir.join(name)).map_err(|e| format!("{}: {e}", from.display()))?;
        }
        return Ok(());
    }
    let dev = keys::dev_keys(&tree)?;
    let list = revoked::write(1, &[]).map_err(|e| format!("revoked: {e}"))?;
    let rblock = Block::sign(
        &dev.root_seed,
        Kind::Revoked,
        list.len() as u64,
        sha::sha256(list.as_bytes()),
        signed_at,
        dev.root.name,
        None,
    );
    std::fs::write(dir.join("revoked"), &list).map_err(|e| format!("revoked: {e}"))?;
    std::fs::write(dir.join("revoked.sig"), rblock.to_bytes())
        .map_err(|e| format!("revoked.sig: {e}"))?;
    Ok(())
}

/// The name of a file that `carried.txt` of a build directory lists: a
/// package carried from an index, with the address of its file and of its
/// source archive (`-` for none), separated by tabs.
pub const CARRIED: &str = "carried.txt";

/// A location an index may hold: a full `https://` address or a relative
/// path that stays below the directory of the index.
fn valid_location(text: &str) -> bool {
    if text.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return false;
    }
    if let Some(rest) = text.strip_prefix("https://") {
        return !rest.is_empty();
    }
    !text.contains("://")
        && !text.starts_with('/')
        && text
            .split('/')
            .all(|p| !p.is_empty() && p != "." && p != "..")
}

/// The packages `carried.txt` of `dir` lists (name of the file, its address,
/// the address of its source archive); none if there is no such file. A
/// line that is not three fields, or an address that is no location, is an
/// error.
pub fn read_carried(
    dir: &Path,
) -> Result<std::collections::BTreeMap<String, (String, Option<String>)>, String> {
    let path = dir.join(CARRIED);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Default::default()),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let mut out = std::collections::BTreeMap::new();
    for (n, line) in text.lines().enumerate() {
        let f: Vec<&str> = line.split('\t').collect();
        let [name, address, source] = f[..] else {
            return Err(format!("{}:{}: not three fields", path.display(), n + 1));
        };
        let source = (source != "-").then_some(source);
        if !valid_location(address) || source.is_some_and(|s| !valid_location(s)) {
            return Err(format!(
                "{}:{}: an address that an index cannot hold",
                path.display(),
                n + 1
            ));
        }
        out.insert(
            name.to_string(),
            (address.to_string(), source.map(str::to_string)),
        );
    }
    Ok(out)
}

/// The address of a file of the new packages in the storage of a release.
fn stored(storage: &str, name: &str) -> String {
    format!("https://github.com/stafeto/packages/releases/download/{storage}/{name}")
}

/// The whole of `repo` for the packages built: the directory.
pub fn make(built: &[Built], all: &[Package], o: &Options) -> Result<PathBuf, String> {
    let tree = crate::root();
    let dir = o.dir.clone().unwrap_or_else(directory);
    prepare(&dir)?;
    std::fs::create_dir_all(dir.join("src")).map_err(|e| format!("{}: {e}", dir.display()))?;
    let commit = pkg::commit()?;
    let relibc = crate::script_value("tools/build-relibc.py", "COMMIT")?;
    let mut rows: Vec<Row> = Vec::new();
    let mut carried_lines = String::new();
    for b in built {
        let name = pkg::file_name(&b.package);
        let bytes = std::fs::read(&b.path).map_err(|e| format!("{}: {e}", b.path.display()))?;
        std::fs::write(dir.join(&name), &bytes).map_err(|e| format!("{name}: {e}"))?;
        let source = match &b.carried {
            Some((_, source)) => source.clone(),
            None if o.sources => notices::source_archive(&b.package, all),
            None => None,
        };
        if b.carried.is_none()
            && let Some(archive) = &source
        {
            let inputs = crate::target_dir()
                .join("pkg/work")
                .join(format!("{}.inputs", b.package.name));
            std::fs::write(&inputs, b.lines.join("\n") + "\n")
                .map_err(|e| format!("{}: {e}", inputs.display()))?;
            crate::run_cmd(
                Command::new("python3")
                    .arg(tree.join("tools/pkg-source.py"))
                    .args([
                        "build",
                        "--name",
                        &b.package.name,
                        "--commit",
                        &commit,
                        "--relibc",
                        &relibc,
                    ])
                    .arg("--out")
                    .arg(dir.join(archive))
                    .arg("--inputs")
                    .arg(&inputs),
            )?;
        }
        let file = PackageFile::parse(&bytes).map_err(|e| format!("{name}: {e}"))?;
        let join = |l: &Vec<String>| (!l.is_empty()).then(|| l.join(" "));
        let (file_field, source_field) = match &b.carried {
            Some((address, source)) => {
                carried_lines.push_str(&format!(
                    "{name}\t{address}\t{}\n",
                    source.as_deref().unwrap_or("-")
                ));
                (address.clone(), source.clone())
            }
            None => (name.clone(), source),
        };
        rows.push(Row {
            name: b.package.name.clone(),
            version: format!("{}-{}", file.meta.version, file.meta.release),
            digest: sha_hex(&bytes),
            file: file_field,
            size: bytes.len() as u64,
            source: source_field,
            provides: join(&b.package.provides),
            depends: join(&b.package.depends),
            needs: join(&b.package.needs),
            license: b.package.license.clone(),
            recipe: b.recipe.clone(),
            summary: b.package.summary.clone(),
        });
    }
    if !carried_lines.is_empty() {
        std::fs::write(dir.join(CARRIED), carried_lines)
            .map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    write_repository(&dir, &rows, o)?;
    Ok(dir)
}

/// `repo --from DIR`: the index of the package files in `DIR`, written next to
/// them without a build. A package listed in `carried.txt` keeps the address
/// of its file; the others get `file` and `source` in the storage `o.storage`
/// (as full addresses) or as plain names.
pub fn from_files(dir: &Path, o: &Options) -> Result<usize, String> {
    let carried = read_carried(dir)?;
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".stpkg"))
        .collect();
    names.sort();
    if names.is_empty() {
        return Err(format!("{}: no .stpkg file", dir.display()));
    }
    let place = |name: &str| match &o.storage {
        Some(storage) => stored(storage, name),
        None => name.to_string(),
    };
    let mut rows = Vec::new();
    for name in &names {
        let bytes = std::fs::read(dir.join(name)).map_err(|e| format!("{name}: {e}"))?;
        let file = PackageFile::parse(&bytes).map_err(|e| format!("{name}: {e}"))?;
        let m = &file.meta;
        let list = |v: &str| (v != "-").then(|| v.to_string());
        let (file_field, source) = match carried.get(name) {
            Some((address, source)) => (address.clone(), source.clone()),
            None => {
                let stem = name.trim_end_matches(".stpkg");
                let archive = format!("src/{stem}-src.tar.xz");
                let source = dir.join(&archive).is_file().then(|| match &o.storage {
                    Some(storage) => stored(storage, &format!("{stem}-src.tar.xz")),
                    None => archive,
                });
                (place(name), source)
            }
        };
        rows.push(Row {
            name: m.name.to_string(),
            version: format!("{}-{}", m.version, m.release),
            digest: sha_hex(&bytes),
            file: file_field,
            size: bytes.len() as u64,
            source,
            provides: list(m.provides),
            depends: list(m.depends),
            needs: list(m.needs),
            license: m.license.to_string(),
            recipe: m.recipe.to_string(),
            summary: m.summary.to_string(),
        });
    }
    write_repository(dir, &rows, o)?;
    Ok(rows.len())
}

/// The size of the packages of the series and of the base ones, in bytes.
pub fn sizes(built: &[Built]) -> (u64, u64) {
    debug_assert!(built.iter().all(|b| b.entries > 0 && b.content <= b.size));
    let total = built.iter().map(|b| b.size).sum();
    let base = built
        .iter()
        .filter(|b| b.package.kind == packages::Kind::Base)
        .map(|b| b.size)
        .sum();
    (total, base)
}

/// The checks of `repo --check` on `dir`: signatures of the index and of
/// the list, and for each entry its file, size, SHA-256, `meta`, signature,
/// policy and source. `roots` are the roots that vouch for the release key.
pub fn check(dir: &Path, roots: &[Key]) -> Result<usize, String> {
    check_with(dir, roots, true)
}

/// `check`; with `sources` false a relative `source` need not be a file of
/// `dir` (a check over the network does not fetch the source archives).
pub fn check_with(dir: &Path, roots: &[Key], sources: bool) -> Result<usize, String> {
    let fail = |what: &str, e: String| format!("{}: {what}: {e}", dir.display());
    let read = |name: &str| std::fs::read(dir.join(name)).map_err(|e| fail(name, e.to_string()));
    let trust = Trust { roots, direct: &[] };
    let list_bytes = read("revoked")?;
    let list_text =
        String::from_utf8(list_bytes.clone()).map_err(|e| fail("revoked", e.to_string()))?;
    let list = revoked::Revoked::parse(&list_text).map_err(|e| fail("revoked", e.to_string()))?;
    let rblock =
        Block::parse(&read("revoked.sig")?).map_err(|e| fail("revoked.sig", e.to_string()))?;
    pkgfmt::trust::verify(
        &rblock,
        Kind::Revoked,
        &sha::sha256(&list_bytes),
        list_bytes.len() as u64,
        &trust,
        &[],
    )
    .map_err(|e| fail("revoked.sig", e.to_string()))?;
    let revocations: Vec<Revocation> = list.entries().collect();
    let index_bytes = read("INDEX")?;
    let index_text =
        String::from_utf8(index_bytes.clone()).map_err(|e| fail("INDEX", e.to_string()))?;
    let index = Index::parse(&index_text).map_err(|e| fail("INDEX", e.to_string()))?;
    let iblock = Block::parse(&read("INDEX.sig")?).map_err(|e| fail("INDEX.sig", e.to_string()))?;
    pkgfmt::trust::verify(
        &iblock,
        Kind::Index,
        &sha::sha256(&index_bytes),
        index_bytes.len() as u64,
        &trust,
        &revocations,
    )
    .map_err(|e| fail("INDEX.sig", e.to_string()))?;
    let mut count = 0;
    for e in index.entries() {
        // A carried package has the address of its file in the index; the
        // build keeps a copy of it by its name.
        let local = if e.file.starts_with("https://") {
            e.file.rsplit('/').next().unwrap_or(e.file)
        } else {
            e.file
        };
        let bytes = read(local)?;
        if bytes.len() as u64 != e.size {
            return Err(fail(
                e.file,
                format!("{} bytes, the index says {}", bytes.len(), e.size),
            ));
        }
        if sha_hex(&bytes) != e.sha256 {
            return Err(fail(e.file, "the SHA-256 differs from the index".into()));
        }
        let file = PackageFile::parse(&bytes).map_err(|e2| fail(e.file, e2.to_string()))?;
        let m = file.meta;
        let same = m.name == e.name
            && format!("{}-{}", m.version, m.release) == e.version
            && m.series == index.header.series
            && m.recipe == e.recipe;
        if !same {
            return Err(fail(
                e.file,
                "meta differs from the entry of the index".into(),
            ));
        }
        file.verify(&trust, &revocations)
            .map_err(|e2| fail(e.file, e2.to_string()))?;
        file.check_policy(e.name)
            .map_err(|e2| fail(e.file, e2.to_string()))?;
        if let Some(source) = e.source
            && sources
            && !source.starts_with("https://")
            && !dir.join(source).is_file()
        {
            return Err(fail(source, "the source archive is missing".into()));
        }
        count += 1;
    }
    Ok(count)
}

/// Fetches the index, its signature, the list of revocations and every package
/// file of the repository at `base` into `dir` and checks them as `check` does.
/// A file that the index names and the server lacks is an error.
fn check_remote(base: &str, dir: &Path, roots: &[Key]) -> Result<usize, String> {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let get = |address: String, name: &str| -> Result<(), String> {
        let bytes =
            crate::carry::fetch(&address)?.ok_or_else(|| format!("{address}: not found"))?;
        std::fs::write(dir.join(name), bytes).map_err(|e| format!("{name}: {e}"))
    };
    for name in ["INDEX", "INDEX.sig", "revoked", "revoked.sig"] {
        get(crate::carry::address_of(base, name), name)?;
    }
    let text = std::fs::read_to_string(dir.join("INDEX")).map_err(|e| format!("INDEX: {e}"))?;
    let index = Index::parse(&text).map_err(|e| format!("INDEX: {e}"))?;
    for e in index.entries() {
        let local = e.file.rsplit('/').next().unwrap_or(e.file);
        get(crate::carry::address_of(base, e.file), local)?;
    }
    check_with(dir, roots, false)
}

/// `cargo xtask repo [--serial N] [--expires-days D] [--no-sources] [--key K.key --cert K.cert] [--check [--official]]`.
pub fn command(args: &[String]) -> Result<(), String> {
    if args.first().map(String::as_str) == Some("resign") {
        return crate::resign::command(&args[1..]);
    }
    run(&parse_options(args)?).map(drop)
}

pub fn run(o: &Options) -> Result<PathBuf, String> {
    let tree = crate::root();
    if o.official && o.root.is_some() {
        return Err("--official takes the roots of keys/ and goes without --root".into());
    }
    if o.from.is_some() && (o.check || o.previous.is_some() || o.dir.is_some()) {
        return Err(
            "--from writes next to the files it reads: no --check, --previous or --dir".into(),
        );
    }
    if o.from.is_some() && !o.serial_given {
        return Err("--from wants --serial: an index with a number a device has seen is refused as a rollback".into());
    }
    if o.storage.is_some() && o.from.is_none() {
        return Err("--storage goes with --from".into());
    }
    if let Some(dir) = &o.from {
        let n = from_files(dir, o)?;
        println!(
            "repo --from: the index of {n} packages in {}",
            dir.display()
        );
        return Ok(dir.clone());
    }
    let roots = match &o.root {
        _ if o.official => keys::official_roots()?,
        Some(path) => {
            let text =
                std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
            vec![
                pkgfmt::keyfile::parse_public(&text)
                    .map_err(|e| format!("{}: {e}", path.display()))?,
            ]
        }
        None => vec![keys::dev_keys(&tree)?.root],
    };
    if let Some(base) = &o.remote {
        if !o.check || o.dir.is_some() {
            return Err("--remote goes with --check and without --dir".into());
        }
        let dir = crate::target_dir().join("repo-remote");
        let n = check_remote(base, &dir, &roots)?;
        println!("repo --check: {n} packages at {base} are whole and signed");
        return Ok(dir);
    }
    if o.check {
        let dir = o.dir.clone().unwrap_or_else(directory);
        let n = check(&dir, &roots)?;
        println!(
            "repo --check: {n} packages in {} are whole and signed",
            dir.display()
        );
        return Ok(dir);
    }
    let started = std::time::Instant::now();
    let built = pkg::build(&pkg::Options {
        key: o.key.clone(),
        cert: o.cert.clone(),
        previous: o.previous.clone(),
        perturb: o.perturb.clone(),
        ..pkg::Options::default()
    })?;
    // The serial after the one of the index carried from, unless given.
    let mut options = o.clone();
    if o.previous.is_some() && !o.serial_given {
        let text = std::fs::read_to_string(crate::carry::directory().join("previous-serial"))
            .map_err(|e| format!("previous-serial: {e}"))?;
        options.serial = text
            .trim()
            .parse::<u64>()
            .map_err(|e| format!("previous-serial: {e}"))?
            + 1;
    }
    let all = packages::load()?;
    let dir = make(&built, &all, &options)?;
    let (total, base) = sizes(&built);
    println!(
        "repo: {} packages in {} ({} bytes of packages, {} of base packages), {:.0} s",
        built.len(),
        dir.display(),
        total,
        base,
        started.elapsed().as_secs_f64()
    );
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkgfmt::cert::{Certificate, PURPOSE_PACKAGES};
    use pkgfmt::container::write::{Content, Item, container, sign};
    use pkgfmt::meta::Meta;
    use pkgfmt::{Name, sig};

    const ROOT: [u8; 32] = [3; 32];
    const RELEASE: [u8; 32] = [4; 32];

    fn n(s: &str) -> Name {
        Name::new(s).unwrap()
    }

    /// A repository of one package made here: its directory and the root key.
    fn repository(tag: &str) -> (PathBuf, Key) {
        let dir = std::env::temp_dir().join(format!("stafeto-repo-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let root = Key {
            name: n("t-root"),
            public: sig::public_key(&ROOT),
        };
        let cert = Certificate::issue(
            &ROOT,
            root.name,
            n("t-release"),
            sig::public_key(&RELEASE),
            PURPOSE_PACKAGES,
            0,
            4_000_000_000,
        );
        let hex = "ab".repeat(32);
        let items = [
            Item {
                path: "/usr",
                mode: 0o040755,
                content: Content::Directory,
            },
            Item {
                path: "/usr/share",
                mode: 0o040755,
                content: Content::Directory,
            },
            Item {
                path: "/usr/share/licenses",
                mode: 0o040755,
                content: Content::Directory,
            },
            Item {
                path: "/usr/share/licenses/demo",
                mode: 0o040755,
                content: Content::Directory,
            },
            Item {
                path: "/usr/share/licenses/demo/LICENSE",
                mode: 0o100644,
                content: Content::Data(b"licence"),
            },
            Item {
                path: "/usr/share/licenses/demo/SOURCE",
                mode: 0o100644,
                content: Content::Data(b"source"),
            },
        ];
        let meta = Meta {
            name: "demo",
            version: "1.0",
            release: "1",
            arch: "aarch64",
            series: "0.2",
            license: "MIT",
            depends: "-",
            provides: "-",
            needs: "-",
            summary: "A demonstration",
            url: "https://example.org/demo.tar.gz",
            sha256: &hex,
            recipe: &hex,
            commit: &"c".repeat(40),
            relibc: "-",
            size: 0,
        };
        let package = sign(
            container(&meta, &items, 0).unwrap(),
            &RELEASE,
            n("t-release"),
            Some(cert.to_bytes()),
            1000,
        )
        .unwrap();
        std::fs::write(dir.join("demo-1.0-1.stpkg"), &package).unwrap();
        let header = Header {
            repository: "stafeto",
            series: "0.2",
            arch: "aarch64",
            serial: 1,
            expires: 5000,
        };
        let digest = sha_hex(&package);
        let entry = Entry {
            name: "demo",
            version: "1.0-1",
            provides: None,
            depends: None,
            needs: None,
            license: "MIT",
            size: package.len() as u64,
            sha256: &digest,
            recipe: &hex,
            file: "demo-1.0-1.stpkg",
            source: None,
            summary: "A demonstration",
        };
        let text = index::write(&header, &[entry]).unwrap();
        let block = Block::sign(
            &RELEASE,
            Kind::Index,
            text.len() as u64,
            sha::sha256(text.as_bytes()),
            1000,
            n("t-release"),
            Some(cert.to_bytes()),
        );
        std::fs::write(dir.join("INDEX"), &text).unwrap();
        std::fs::write(dir.join("INDEX.sig"), block.to_bytes()).unwrap();
        let list = revoked::write(1, &[]).unwrap();
        let rblock = Block::sign(
            &ROOT,
            Kind::Revoked,
            list.len() as u64,
            sha::sha256(list.as_bytes()),
            1000,
            root.name,
            None,
        );
        std::fs::write(dir.join("revoked"), &list).unwrap();
        std::fs::write(dir.join("revoked.sig"), rblock.to_bytes()).unwrap();
        (dir, root)
    }

    #[test]
    fn a_whole_repository_passes_and_a_changed_byte_does_not() {
        let (dir, root) = repository("whole");
        assert_eq!(check(&dir, &[root]).unwrap(), 1);
        // A byte of the package: the SHA-256 of the index no longer fits.
        let path = dir.join("demo-1.0-1.stpkg");
        let good = std::fs::read(&path).unwrap();
        let mut bad = good.clone();
        bad[20] ^= 1;
        std::fs::write(&path, &bad).unwrap();
        assert!(check(&dir, &[root]).unwrap_err().contains("SHA-256"));
        std::fs::write(&path, &good).unwrap();
        // The index changed: its signature does not fit.
        let index = std::fs::read_to_string(dir.join("INDEX")).unwrap();
        std::fs::write(
            dir.join("INDEX"),
            index.replace("summary A demonstration", "summary A demonstratioN"),
        )
        .unwrap();
        assert!(check(&dir, &[root]).unwrap_err().contains("INDEX.sig"));
        std::fs::write(dir.join("INDEX"), index).unwrap();
        // A root other than the one that vouched for the key.
        let stranger = Key {
            name: root.name,
            public: sig::public_key(&[9; 32]),
        };
        assert!(
            check(&dir, &[stranger])
                .unwrap_err()
                .contains("revoked.sig")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_revoked_release_key_fails_the_check() {
        let (dir, root) = repository("revoked");
        let list = revoked::write(
            2,
            &[Revocation {
                name: n("t-release"),
                since: 500,
            }],
        )
        .unwrap();
        let block = Block::sign(
            &ROOT,
            Kind::Revoked,
            list.len() as u64,
            sha::sha256(list.as_bytes()),
            1000,
            root.name,
            None,
        );
        std::fs::write(dir.join("revoked"), &list).unwrap();
        std::fs::write(dir.join("revoked.sig"), block.to_bytes()).unwrap();
        assert!(check(&dir, &[root]).unwrap_err().contains("Revoked"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn repo_deletes_only_what_it_made() {
        let tmp = std::env::temp_dir().join(format!("stafeto-prepare-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        // Missing and empty directories outside target/ are fine.
        assert!(prepare(&tmp.join("new")).is_ok());
        assert!(prepare(&tmp).is_ok());
        // One with files in it, or the tree itself, is refused and kept.
        std::fs::write(tmp.join("precious"), b"x").unwrap();
        assert!(prepare(&tmp).unwrap_err().contains("not empty"));
        assert!(tmp.join("precious").exists());
        assert!(prepare(&crate::root()).is_err());
        assert!(prepare(&crate::root().join("xtask")).is_err());
        std::fs::remove_dir_all(&tmp).unwrap();
        // Under target/ the directory is the tool's own.
        let own = crate::root().join("target").join("prepare-test");
        std::fs::create_dir_all(&own).unwrap();
        std::fs::write(own.join("old"), b"x").unwrap();
        assert!(prepare(&own).is_ok());
        assert!(!own.exists());
    }

    #[test]
    fn the_options_refuse_a_long_life_and_unknown_words() {
        let words = |l: &[&str]| l.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let o = parse_options(&words(&[
            "--serial",
            "7",
            "--no-sources",
            "--expires-days",
            "30",
        ]))
        .unwrap();
        assert_eq!((o.serial, o.sources, o.expires_days), (7, false, 30));
        assert!(parse_options(&words(&["--expires-days", "31"])).is_err());
        assert!(parse_options(&words(&["--expires-days", "0"])).is_err());
        assert!(parse_options(&words(&["--serial"])).is_err());
        assert!(parse_options(&words(&["--verbose"])).is_err());
    }

    #[test]
    fn an_index_from_files_names_the_storage_and_keeps_carried_addresses() {
        let (dir, _) = repository("from");
        std::fs::remove_file(dir.join("INDEX")).unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/demo-1.0-1-src.tar.xz"), b"s").unwrap();
        let o = Options {
            storage: Some("v0.3.0-aarch64".into()),
            serial: 9,
            ..Options::default()
        };
        assert_eq!(from_files(&dir, &o).unwrap(), 1);
        let text = std::fs::read_to_string(dir.join("INDEX")).unwrap();
        let index = Index::parse(&text).unwrap();
        assert_eq!(index.header.serial, 9);
        let entries: Vec<Entry<'_>> = index.entries().collect();
        let base = "https://github.com/stafeto/packages/releases/download/v0.3.0-aarch64";
        assert_eq!(entries[0].name, "demo");
        assert_eq!(entries[0].file, format!("{base}/demo-1.0-1.stpkg"));
        assert_eq!(
            entries[0].source,
            Some(format!("{base}/demo-1.0-1-src.tar.xz").as_str())
        );
        // The index verifies with the development root; without a storage the names stay.
        let dev = keys::dev_keys(&crate::root()).unwrap();
        let iblock = Block::parse(&std::fs::read(dir.join("INDEX.sig")).unwrap()).unwrap();
        assert!(
            pkgfmt::trust::verify(
                &iblock,
                Kind::Index,
                &sha::sha256(text.as_bytes()),
                text.len() as u64,
                &Trust {
                    roots: &[dev.root],
                    direct: &[]
                },
                &[]
            )
            .is_ok()
        );
        from_files(&dir, &Options::default()).unwrap();
        assert!(
            std::fs::read_to_string(dir.join("INDEX"))
                .unwrap()
                .contains("file demo-1.0-1.stpkg")
        );
        // A carried file keeps the address of the index it came from.
        std::fs::write(
            dir.join(CARRIED),
            "demo-1.0-1.stpkg\thttps://stafeto.github.io/packages/0.2/aarch64/demo-1.0-1.stpkg\t-\n",
        )
        .unwrap();
        from_files(&dir, &o).unwrap();
        let text = std::fs::read_to_string(dir.join("INDEX")).unwrap();
        let index = Index::parse(&text).unwrap();
        let entry = index.entries().next().unwrap();
        assert_eq!(
            entry.file,
            "https://stafeto.github.io/packages/0.2/aarch64/demo-1.0-1.stpkg"
        );
        assert_eq!(entry.source, None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_options_of_repo_keep_their_rules() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let o = parse_options(&args(&["--previous", "d", "--serial", "4"])).unwrap();
        assert!(o.serial_given && o.serial == 4 && o.previous.as_deref() == Some("d"));
        assert!(!parse_options(&args(&[])).unwrap().serial_given);
        assert!(
            parse_options(&args(&["--official", "--check"]))
                .unwrap()
                .official
        );
        let bad = |v: &[&str]| run(&parse_options(&args(v)).unwrap()).unwrap_err();
        assert!(bad(&["--from", "x", "--check"]).contains("--from"));
        assert!(bad(&["--storage", "x"]).contains("--from"));
        assert!(bad(&["--from", "x"]).contains("--serial"));
        assert!(parse_options(&args(&["--perturb", "x"])).is_err());
        assert!(bad(&["--official", "--root", "r.pub"]).contains("--official"));
    }

    #[test]
    fn carried_txt_holds_locations_an_index_can_hold() {
        let dir = std::env::temp_dir().join(format!("stafeto-carried-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let put = |text: &str| std::fs::write(dir.join(CARRIED), text).unwrap();
        put("a.stpkg\thttps://h/p/a.stpkg\tsrc/a-src.tar.xz\nb.stpkg\tb.stpkg\t-\n");
        assert_eq!(read_carried(&dir).unwrap().len(), 2);
        for bad in [
            "a.stpkg\thttp://h/a.stpkg\t-\n",
            "a.stpkg\t/etc/passwd\t-\n",
            "a.stpkg\t../a.stpkg\t-\n",
            "a.stpkg\thttps://h/a b\t-\n",
            "a.stpkg\thttps://h/a.stpkg\tfile:///x\n",
            "a.stpkg\thttps://h/a.stpkg\n",
        ] {
            put(bad);
            assert!(read_carried(&dir).is_err(), "{bad}");
        }
        std::fs::remove_file(dir.join(CARRIED)).unwrap();
        assert!(read_carried(&dir).unwrap().is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_check_over_the_network_names_the_file_the_server_lacks() {
        let base = std::env::temp_dir().join(format!("stafeto-remote-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let work = base.join("work");
        let e = check_remote(base.to_str().unwrap(), &work, &[]).unwrap_err();
        assert!(e.contains("INDEX") && e.contains("not found"), "{e}");
        let o = parse_options(&["--check".into(), "--remote".into(), "x".into()]).unwrap();
        assert_eq!(o.remote.as_deref(), Some("x"));
        std::fs::remove_dir_all(&base).unwrap();
    }
}
