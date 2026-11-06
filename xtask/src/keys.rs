// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask keys`: the keys that sign packages (docs/packages.md).
//!
//! * `keys root <name>` and `keys release <name>` make a key pair: the
//!   private key as an unencrypted PKCS#8 PEM `<name>.key` (mode 0600, never
//!   overwritten) and the public line `<name>.pub`; only the public line is
//!   printed.
//! * `keys certify` has a root vouch for a release key: the certificate
//!   `<name>.cert` (pkgfmt::cert).
//! * `keys show <file>` prints what a `.pub`, `.cert`, `.sig` or `.stpkg`
//!   file says. It never opens a private key.
//!
//! A private key is never written into the working tree outside
//! `target/keys/`, where the development keys of `pkg-build` live.

use pkgfmt::cert::{self, Certificate};
use pkgfmt::sig::{Block, Kind};
use pkgfmt::{Key, Name, Revocation, Trust, keyfile, sig, time};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const DAY: u64 = 86_400;
/// The term of a certificate unless `--days` says otherwise: 13 months.
const DEFAULT_DAYS: u64 = 396;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Root,
    Release,
}

impl Role {
    fn word(self) -> &'static str {
        match self {
            Role::Root => "root",
            Role::Release => "release",
        }
    }
}

/// Whether `name` is `...-<role>` or `...-<role>-<digits>`.
fn role_name(name: &str, role: Role) -> bool {
    let word = role.word();
    let tail = |marker: String| name.rfind(&marker).map(|at| &name[at + marker.len()..]);
    let plain = name.ends_with(&format!("-{word}")) && name.len() > word.len() + 1;
    let numbered = tail(format!("-{word}-"))
        .is_some_and(|t| !t.is_empty() && t.bytes().all(|c| c.is_ascii_digit()));
    plain || numbered
}

fn default_dir() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME").ok_or("HOME is not set; give --dir")?;
    Ok(PathBuf::from(home).join(".stafeto-keys"))
}

/// Refuses a directory inside the working tree other than under
/// `target/keys`.
fn check_dir(dir: &Path, root: &Path) -> Result<(), String> {
    let dir = dir
        .canonicalize()
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    let root = root
        .canonicalize()
        .map_err(|e| format!("{}: {e}", root.display()))?;
    if dir.starts_with(&root) && !dir.starts_with(root.join("target").join("keys")) {
        return Err(format!(
            "{}: a private key does not go into the working tree outside target/keys",
            dir.display()
        ));
    }
    Ok(())
}

fn random_seed() -> Result<[u8; 32], String> {
    let mut seed = [0u8; 32];
    let mut f = fs::File::open("/dev/urandom").map_err(|e| format!("/dev/urandom: {e}"))?;
    let n = f
        .read(&mut seed)
        .map_err(|e| format!("/dev/urandom: {e}"))?;
    if n != seed.len() {
        return Err(format!("/dev/urandom gave {n} bytes of {}", seed.len()));
    }
    Ok(seed)
}

fn create_new(path: &Path, mode: u32, data: &[u8]) -> Result<(), String> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(data)
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// A new key pair in `dir` (created with mode 0700 if missing); the public
/// line. Fails when either file exists.
pub fn generate(role: Role, name: &str, dir: &Path, root: &Path) -> Result<String, String> {
    if Name::new(name).is_err() || !role_name(name, role) {
        return Err(format!(
            "{name}: a {0} key is named ...-{0} or ...-{0}-N (lower case, digits and dashes, up to 63 bytes)",
            role.word()
        ));
    }
    // A directory that is not there yet is made closed to other users; one
    // that exists keeps the mode its owner gave it.
    if !dir.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    check_dir(dir, root)?;
    let seed = random_seed()?;
    let pair = Key {
        name: Name::new(name).expect("checked"),
        public: sig::public_key(&seed),
    };
    // The probe: the pair signs and verifies a message before any file is made.
    let probe = sig::sign(&seed, b"stafeto key probe");
    if !sig::verify(&pair.public, b"stafeto key probe", &probe) {
        return Err("the new key does not verify its own signature".into());
    }
    let key_path = dir.join(format!("{name}.key"));
    create_new(&key_path, 0o600, keyfile::private_pem(&seed).as_bytes())?;
    let line = keyfile::public_line(&pair);
    create_new(&dir.join(format!("{name}.pub")), 0o644, line.as_bytes())?;
    Ok(line)
}

/// The development pair `name` in `dir`, made if it does not exist yet; its
/// seed and key.
pub fn load_or_generate(
    role: Role,
    name: &str,
    dir: &Path,
    root: &Path,
) -> Result<([u8; 32], Key), String> {
    if !dir.join(format!("{name}.key")).exists() {
        generate(role, name, dir, root)?;
    }
    let seed = read_private(&dir.join(format!("{name}.key")))?;
    let key = Key {
        name: Name::new(name).map_err(|_| format!("{name}: not a key name"))?,
        public: sig::public_key(&seed),
    };
    Ok((seed, key))
}

/// The keys of the development builds in `target/keys/`: a root and a
/// release key with a certificate from the root, made on first use and
/// renewed when the certificate is gone or over.
pub struct DevKeys {
    pub root_seed: [u8; 32],
    pub root: Key,
    pub release_seed: [u8; 32],
    pub release: Key,
    pub certificate: [u8; cert::SIZE],
}

pub fn dev_keys(tree: &Path) -> Result<DevKeys, String> {
    let dir = tree.join("target").join("keys");
    let (root_seed, root) = load_or_generate(Role::Root, "stafeto-dev-root", &dir, tree)?;
    let (release_seed, release) =
        load_or_generate(Role::Release, "stafeto-dev-release", &dir, tree)?;
    let path = dir.join("stafeto-dev-release.cert");
    let usable = |c: &Certificate| {
        c.key == release.name && c.check_signature(&root.public) && c.not_after > now() + DAY
    };
    let current = fs::read(&path)
        .ok()
        .and_then(|b| Certificate::parse(&b).ok())
        .filter(usable);
    let certificate = match current {
        Some(c) => c,
        None => {
            let from = now() / DAY * DAY;
            let c = Certificate::issue(
                &root_seed,
                root.name,
                release.name,
                release.public,
                cert::PURPOSE_PACKAGES,
                from,
                from + DEFAULT_DAYS * DAY,
            );
            let temp = path.with_extension("cert.tmp");
            let _ = fs::remove_file(&temp);
            create_new(&temp, 0o644, &c.to_bytes())?;
            fs::rename(&temp, &path).map_err(|e| format!("{}: {e}", path.display()))?;
            c
        }
    };
    Ok(DevKeys {
        root_seed,
        root,
        release_seed,
        release,
        certificate: certificate.to_bytes(),
    })
}

/// The key to sign with: `--key K.key --cert K.cert` when given, else the
/// development release key.
pub struct Signing {
    pub seed: [u8; 32],
    pub key: Name,
    pub certificate: Option<[u8; cert::SIZE]>,
}

/// The roots and the direct keys that must accept what `s` signs: the root
/// that issued its certificate (`keys/<issuer>.pub` of the tree when there is
/// such a file, else the root of the development keys), or the key itself
/// when it has no certificate.
pub fn trust_of(s: &Signing, tree: &Path) -> Result<(Vec<Key>, Vec<Key>), String> {
    let Some(bytes) = &s.certificate else {
        let key = Key {
            name: s.key,
            public: sig::public_key(&s.seed),
        };
        return Ok((Vec::new(), vec![key]));
    };
    let c = Certificate::parse(bytes).map_err(|e| format!("certificate: {e}"))?;
    let official = tree.join("keys").join(format!("{}.pub", c.issuer.as_str()));
    if official.is_file() {
        return Ok((vec![read_public(&official)?], Vec::new()));
    }
    let dev = dev_keys(tree)?;
    if dev.root.name != c.issuer {
        return Err(format!(
            "the certificate of {} is issued by {}, which is neither keys/{}.pub nor the development root",
            c.key.as_str(),
            c.issuer.as_str(),
            c.issuer.as_str()
        ));
    }
    Ok((vec![dev.root], Vec::new()))
}

pub fn signing(
    key: Option<&Path>,
    certificate: Option<&Path>,
    tree: &Path,
) -> Result<Signing, String> {
    match (key, certificate) {
        (Some(key), cert_path) => {
            let name = key
                .file_stem()
                .and_then(|s| s.to_str())
                .and_then(|s| Name::new(s).ok())
                .ok_or_else(|| format!("{}: not a key file name", key.display()))?;
            let certificate = match cert_path {
                Some(p) => {
                    let bytes = fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
                    let c =
                        Certificate::parse(&bytes).map_err(|e| format!("{}: {e}", p.display()))?;
                    let seed_public = sig::public_key(&read_private(key)?);
                    if c.key != name || c.public != seed_public {
                        return Err(format!(
                            "{}: the certificate is of {} with another public key than the private key {} has",
                            p.display(),
                            c.key.as_str(),
                            key.display()
                        ));
                    }
                    let mut out = [0u8; cert::SIZE];
                    out.copy_from_slice(&bytes);
                    Some(out)
                }
                // No --cert: the certificate of keys/ that vouches for this very key
                // and covers the present time, if there is one.
                None => match current_release_certificate(tree, now()) {
                    Ok((path, c))
                        if c.key == name && c.public == sig::public_key(&read_private(key)?) =>
                    {
                        let bytes =
                            fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
                        <[u8; cert::SIZE]>::try_from(bytes.as_slice()).ok()
                    }
                    _ => None,
                },
            };
            Ok(Signing {
                seed: read_private(key)?,
                key: name,
                certificate,
            })
        }
        (None, Some(_)) => Err("--cert comes with --key".into()),
        (None, None) => {
            let dev = dev_keys(tree)?;
            Ok(Signing {
                seed: dev.release_seed,
                key: dev.release.name,
                certificate: Some(dev.certificate),
            })
        }
    }
}

fn read_private(path: &Path) -> Result<[u8; 32], String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    keyfile::parse_private(&text).map_err(|_| {
        format!(
            "{}: not an unencrypted PKCS#8 Ed25519 key; convert it with openssl pkey",
            path.display()
        )
    })
}

fn read_public(path: &Path) -> Result<Key, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let key = keyfile::parse_public(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    if stem != key.name.as_str() {
        return Err(format!(
            "{}: the line names {} but the file is named {stem}.pub",
            path.display(),
            key.name.as_str()
        ));
    }
    Ok(key)
}

/// The seconds of `YYYY-MM-DD` at 00:00 UTC.
fn day_start(text: &str) -> Option<u64> {
    time::parse(&format!("{text}T00:00:00Z"))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn purposes_of(list: &str) -> Result<u32, String> {
    let mut bits = 0;
    for word in list.split(',') {
        bits |= match word {
            "packages" => cert::PURPOSE_PACKAGES,
            "elf" => cert::PURPOSE_ELF,
            other => return Err(format!("{other}: the purposes are packages and elf")),
        };
    }
    Ok(bits)
}

fn purpose_words(bits: u32) -> String {
    let mut words = Vec::new();
    if bits & cert::PURPOSE_PACKAGES != 0 {
        words.push("packages");
    }
    if bits & cert::PURPOSE_ELF != 0 {
        words.push("elf");
    }
    words.join(",")
}

fn instant(secs: u64) -> String {
    let mut buf = [0u8; time::TEXT_LEN];
    time::format(secs, &mut buf)
        .unwrap_or("out of range")
        .to_string()
}

pub struct Certify {
    pub root_key: PathBuf,
    pub key: PathBuf,
    pub purposes: u32,
    pub from: u64,
    pub days: u64,
    pub out: Option<PathBuf>,
}

/// Writes the certificate of `Certify::key` signed by `Certify::root_key`;
/// the path and a summary.
pub fn certify(c: &Certify, tree: &Path) -> Result<(PathBuf, String), String> {
    let (issuer, seed) = load_root(&c.root_key, tree)?;
    let key = read_public(&c.key)?;
    if !role_name(key.name.as_str(), Role::Release) {
        return Err(format!(
            "{}: the certified key is a release key",
            key.name.as_str()
        ));
    }
    let not_after = c.from + c.days * DAY;
    let cert = Certificate::issue(
        &seed, issuer, key.name, key.public, c.purposes, c.from, not_after,
    );
    let path = c
        .out
        .clone()
        .unwrap_or_else(|| c.key.with_extension("cert"));
    let temp = path.with_extension("cert.tmp");
    let _ = fs::remove_file(&temp);
    create_new(&temp, 0o644, &cert.to_bytes())?;
    fs::rename(&temp, &path).map_err(|e| format!("{}: {e}", path.display()))?;
    let summary = format!(
        "{} for {} from {} to {}, issued by {}",
        key.name.as_str(),
        purpose_words(c.purposes),
        instant(c.from),
        instant(not_after),
        issuer.as_str()
    );
    Ok((path, summary))
}

/// The name and the seed of the root key file `path`; refused when it is not
/// named like a root or when `keys/<name>.pub` of the tree names another key.
fn load_root(path: &Path, tree: &Path) -> Result<(Name, [u8; 32]), String> {
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let issuer = Name::new(stem).map_err(|_| format!("{}: not a key file name", path.display()))?;
    if !role_name(stem, Role::Root) {
        return Err(format!(
            "{stem}: the issuer is a root key, named ...-root or ...-root-N"
        ));
    }
    let seed = read_private(path)?;
    let official = tree.join("keys").join(format!("{stem}.pub"));
    if official.is_file() {
        let key = read_public(&official)?;
        if key.public != sig::public_key(&seed) {
            return Err(format!(
                "{}: the private key is not the one that keys/{stem}.pub names",
                path.display()
            ));
        }
    }
    Ok((issuer, seed))
}

/// The roots of the official repository: `pkgfmt::OFFICIAL_ROOTS`, the roots
/// baked into `pkg` and `pkgd`. A new root enters by a change of that list
/// (and of the file in `keys/` that it includes), which a review sees; no file
/// that merely lies in `keys/` is trusted.
pub fn official_roots() -> Result<Vec<Key>, String> {
    pkgfmt::official_roots()
        .map(|roots| roots.to_vec())
        .map_err(|e| format!("pkgfmt::OFFICIAL_ROOTS: {e}"))
}

/// The certificate of `keys/*.cert` to sign a release with at `at`: purpose
/// `packages`, term around `at`, the latest start; its file.
pub fn current_release_certificate(tree: &Path, at: u64) -> Result<(PathBuf, Certificate), String> {
    let dir = tree.join("keys");
    let mut best: Option<(PathBuf, Certificate)> = None;
    for entry in fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.extension().is_none_or(|x| x != "cert") {
            continue;
        }
        let bytes = fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let c = Certificate::parse(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
        let fits =
            c.purposes & cert::PURPOSE_PACKAGES != 0 && c.not_before <= at && at <= c.not_after;
        if fits
            && best
                .as_ref()
                .is_none_or(|(_, b)| c.not_before > b.not_before)
        {
            best = Some((path, c));
        }
    }
    best.ok_or_else(|| {
        format!(
            "{}: no certificate for packages covers this time",
            dir.display()
        )
    })
}

pub struct Revoke {
    pub root_key: PathBuf,
    pub init: bool,
    pub key: Option<String>,
    pub since: Option<String>,
    pub list: Option<PathBuf>,
    pub out: Option<PathBuf>,
}

fn write_closed(path: &Path, data: &[u8]) -> Result<(), String> {
    let temp = path.with_extension("tmp");
    let _ = fs::remove_file(&temp);
    create_new(&temp, 0o644, data)?;
    fs::rename(&temp, path).map_err(|e| format!("{}: {e}", path.display()))
}

/// Signs `entries` as the list number `serial` with the root and writes
/// `revoked` and `revoked.sig` into `dir`.
fn write_list(
    dir: &Path,
    seed: &[u8; 32],
    issuer: Name,
    serial: u64,
    entries: &[Revocation],
) -> Result<(), String> {
    let text = pkgfmt::revoked::write(serial, entries).map_err(|e| format!("revoked: {e}"))?;
    let block = Block::sign(
        seed,
        Kind::Revoked,
        text.len() as u64,
        pkgfmt::sha::sha256(text.as_bytes()),
        now(),
        issuer,
        None,
    );
    let public = [Key {
        name: issuer,
        public: sig::public_key(seed),
    }];
    pkgfmt::trust::verify(
        &block,
        Kind::Revoked,
        &pkgfmt::sha::sha256(text.as_bytes()),
        text.len() as u64,
        &Trust {
            roots: &public,
            direct: &[],
        },
        &[],
    )
    .map_err(|e| format!("the new list does not verify: {e}"))?;
    fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    write_closed(&dir.join("revoked"), text.as_bytes())?;
    write_closed(&dir.join("revoked.sig"), &block.to_bytes())
}

/// `keys revoke`: the first list, or the list `F` with one more entry, signed
/// by the root; the summary. `since` is a time or `start` (the start of the
/// term of `keys/<key>.cert`: the time of the leak is unknown, every
/// signature of the key falls).
pub fn revoke(r: &Revoke, tree: &Path) -> Result<String, String> {
    let (issuer, seed) = load_root(&r.root_key, tree)?;
    let default_list = tree.join("keys").join("revoked");
    if r.init {
        if r.key.is_some() || r.since.is_some() || r.list.is_some() {
            return Err("--init takes no --key, --since or --list".into());
        }
        let dir = r.out.clone().unwrap_or_else(|| tree.join("keys"));
        if dir.join("revoked").exists() || dir.join("revoked.sig").exists() {
            return Err(format!(
                "{}: a revocation list is already there",
                dir.display()
            ));
        }
        write_list(&dir, &seed, issuer, 1, &[])?;
        return Ok(format!(
            "an empty revocation list, serial 1, signed by {}\nwritten to {}",
            issuer.as_str(),
            dir.display()
        ));
    }
    let list_path = r.list.clone().unwrap_or(default_list);
    let name = r.key.as_deref().ok_or_else(usage)?;
    let when = r.since.as_deref().ok_or_else(usage)?;
    let key = Name::new(name).map_err(|_| format!("{name}: not a key name"))?;
    if !role_name(name, Role::Release) {
        return Err(format!(
            "{name}: only a release key is revoked; a root changes with a new base"
        ));
    }
    let since = if when == "start" {
        let mut places = vec![tree.join("keys")];
        if let Some(parent) = list_path.parent() {
            places.insert(0, parent.to_path_buf());
        }
        let found = places
            .iter()
            .map(|d| d.join(format!("{name}.cert")))
            .find(|p| p.is_file())
            .ok_or_else(|| format!("{name}: no certificate in keys/ to take the start of the term from; give --since as a time"))?;
        Certificate::parse(&fs::read(&found).map_err(|e| format!("{}: {e}", found.display()))?)
            .map_err(|e| format!("{}: {e}", found.display()))?
            .not_before
    } else {
        let at = time::parse(when)
            .ok_or_else(|| format!("{when}: not a time YYYY-MM-DDThh:mm:ssZ or start"))?;
        if at > now() {
            return Err(format!(
                "{when}: a revocation since a time to come revokes nothing until then; check the year"
            ));
        }
        at
    };
    let text =
        fs::read_to_string(&list_path).map_err(|e| format!("{}: {e}", list_path.display()))?;
    let sig_path = PathBuf::from(format!("{}.sig", list_path.display()));
    let sig_bytes = fs::read(&sig_path).map_err(|e| format!("{}: {e}", sig_path.display()))?;
    let block = Block::parse(&sig_bytes).map_err(|e| format!("{}: {e}", sig_path.display()))?;
    let roots = [Key {
        name: issuer,
        public: sig::public_key(&seed),
    }];
    pkgfmt::trust::verify(
        &block,
        Kind::Revoked,
        &pkgfmt::sha::sha256(text.as_bytes()),
        text.len() as u64,
        &Trust {
            roots: &roots,
            direct: &[],
        },
        &[],
    )
    .map_err(|e| {
        format!(
            "{}: the list is not signed by {}: {e}",
            list_path.display(),
            issuer.as_str()
        )
    })?;
    let list = pkgfmt::revoked::Revoked::parse(&text)
        .map_err(|e| format!("{}: {e}", list_path.display()))?;
    let mut entries: Vec<Revocation> = list.entries().collect();
    if entries.iter().any(|e| e.name == key) {
        return Err(format!("{name}: already in the list"));
    }
    entries.push(Revocation { name: key, since });
    let serial = list
        .serial
        .checked_add(1)
        .ok_or("the serial is at its end")?;
    let dir = r
        .out
        .clone()
        .or_else(|| list_path.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."));
    write_list(&dir, &seed, issuer, serial, &entries)?;
    Ok(format!(
        "{name} revoked since {}, serial {serial}\nwritten to {}",
        instant(since),
        dir.display()
    ))
}

/// What a file says, by its extension.
pub fn show(path: &Path) -> Result<String, String> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    if ext == "key" {
        return Err(format!(
            "{}: a private key; show does not open it",
            path.display()
        ));
    }
    let bytes = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let fail = |e: pkgfmt::Error| format!("{}: {e}", path.display());
    match ext {
        "pub" => {
            let k = pkgfmt::keyfile::parse_public(
                std::str::from_utf8(&bytes).map_err(|_| format!("{}: not text", path.display()))?,
            )
            .map_err(fail)?;
            Ok(format!("public key {}", k.name.as_str()))
        }
        "cert" => Ok(describe_certificate(
            &Certificate::parse(&bytes).map_err(fail)?,
        )),
        "sig" => Ok(describe_block(&pkgfmt::Block::parse(&bytes).map_err(fail)?)),
        "stpkg" => {
            if bytes.len() < pkgfmt::container::TRAILER_SIZE {
                return Err(format!("{}: shorter than the trailer page", path.display()));
            }
            let tail = &bytes[bytes.len() - pkgfmt::container::TRAILER_SIZE..];
            Ok(describe_block(&pkgfmt::Block::parse(tail).map_err(fail)?))
        }
        other => Err(format!(
            "{}: .{other} is not a .pub, .cert, .sig or .stpkg file",
            path.display()
        )),
    }
}

fn describe_certificate(c: &Certificate) -> String {
    format!(
        "certificate of {} for {}\n  term {} to {}\n  issued by {}",
        c.key.as_str(),
        purpose_words(c.purposes),
        instant(c.not_before),
        instant(c.not_after),
        c.issuer.as_str()
    )
}

fn describe_block(b: &pkgfmt::Block) -> String {
    let kind = match b.kind {
        pkgfmt::Kind::Package => "package",
        pkgfmt::Kind::Index => "index",
        pkgfmt::Kind::Revoked => "revocation list",
    };
    let mut out = format!(
        "signature of a {kind}: key {}, signed {}, covers {} bytes",
        b.key.as_str(),
        instant(b.time),
        b.covered
    );
    match b.certificate.as_ref().map(|c| Certificate::parse(c)) {
        Some(Ok(c)) => out.push_str(&format!("\n{}", describe_certificate(&c))),
        Some(Err(e)) => out.push_str(&format!("\n  certificate: {e}")),
        None => out.push_str("\n  no certificate"),
    }
    out
}

fn usage() -> String {
    "usage: cargo xtask keys root <name> [--dir D]
       cargo xtask keys release <name> [--dir D]
       cargo xtask keys certify --root R.key --key K.pub [--purpose packages[,elf]] [--from YYYY-MM-DD] [--days N] [--out F]
       cargo xtask keys revoke --root R.key --init [--out D]
       cargo xtask keys revoke --root R.key --key NAME --since YYYY-MM-DDThh:mm:ssZ|start [--list F] [--out D]
       cargo xtask keys show <file>"
        .into()
}

fn option(args: &[String], flag: &str) -> Result<Option<String>, String> {
    match args.iter().position(|a| a == flag) {
        None => Ok(None),
        Some(i) => args
            .get(i + 1)
            .cloned()
            .map(Some)
            .ok_or_else(|| format!("{flag} wants a value")),
    }
}

fn only_known(args: &[String], known: &[&str]) -> Result<(), String> {
    let mut i = 0;
    while i < args.len() {
        if !known.contains(&args[i].as_str()) {
            return Err(format!("{}: unknown argument\n{}", args[i], usage()));
        }
        i += 2;
    }
    Ok(())
}

pub fn command(args: &[String]) -> Result<(), String> {
    let tree = crate::root();
    match args.first().map(String::as_str) {
        Some(word @ ("root" | "release")) => {
            let role = if word == "root" {
                Role::Root
            } else {
                Role::Release
            };
            let name = args.get(1).ok_or_else(usage)?;
            only_known(&args[2..], &["--dir"])?;
            let dir = match option(&args[2..], "--dir")? {
                Some(d) => PathBuf::from(d),
                None => default_dir()?,
            };
            print!("{}", generate(role, name, &dir, &tree)?);
            Ok(())
        }
        Some("certify") => {
            let rest = &args[1..];
            only_known(
                rest,
                &["--root", "--key", "--purpose", "--from", "--days", "--out"],
            )?;
            let root_key = option(rest, "--root")?.ok_or_else(usage)?;
            let key = option(rest, "--key")?.ok_or_else(usage)?;
            let purposes =
                purposes_of(&option(rest, "--purpose")?.unwrap_or_else(|| "packages".into()))?;
            let from = match option(rest, "--from")? {
                Some(d) => day_start(&d).ok_or_else(|| format!("{d}: not a date YYYY-MM-DD"))?,
                None => now() / DAY * DAY,
            };
            let days = match option(rest, "--days")? {
                Some(d) => d
                    .parse()
                    .map_err(|_| format!("{d}: not a number of days"))?,
                None => DEFAULT_DAYS,
            };
            let (path, summary) = certify(
                &Certify {
                    root_key: root_key.into(),
                    key: key.into(),
                    purposes,
                    from,
                    days,
                    out: option(rest, "--out")?.map(PathBuf::from),
                },
                &tree,
            )?;
            println!("{summary}\nwritten to {}", path.display());
            Ok(())
        }
        Some("revoke") => {
            let rest = &args[1..];
            let init = rest.iter().any(|a| a == "--init");
            let flags: Vec<String> = rest.iter().filter(|a| *a != "--init").cloned().collect();
            only_known(&flags, &["--root", "--key", "--since", "--list", "--out"])?;
            let r = Revoke {
                root_key: option(&flags, "--root")?.ok_or_else(usage)?.into(),
                init,
                key: option(&flags, "--key")?,
                since: option(&flags, "--since")?,
                list: option(&flags, "--list")?.map(PathBuf::from),
                out: option(&flags, "--out")?.map(PathBuf::from),
            };
            println!("{}", revoke(&r, &tree)?);
            Ok(())
        }
        Some("show") => {
            let file = args.get(1).ok_or_else(usage)?;
            println!("{}", show(Path::new(file))?);
            Ok(())
        }
        _ => Err(usage()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkgfmt::{Block, Kind, Trust, trust};
    use std::os::unix::fs::PermissionsExt;

    /// RFC 8410, section 10.3, and its public half.
    const RFC8410_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n-----END PRIVATE KEY-----\n";
    const RFC8410_PUBLIC: &str = "Gb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=";

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("stafeto-keys-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_rfc_8410_key_certifies_a_release_key() {
        let dir = scratch("rfc8410");
        fs::write(dir.join("rfc-root.key"), RFC8410_PEM).unwrap();
        let tree = crate::root();
        let public = generate(Role::Release, "t-release", &dir, &tree).unwrap();
        assert!(public.starts_with("ed25519 "));
        let (path, summary) = certify(
            &Certify {
                root_key: dir.join("rfc-root.key"),
                key: dir.join("t-release.pub"),
                purposes: cert::PURPOSE_PACKAGES,
                from: day_start("2026-11-05").unwrap(),
                days: 396,
                out: None,
            },
            &tree,
        )
        .unwrap();
        assert_eq!(path, dir.join("t-release.cert"));
        assert!(
            summary.contains("2026-11-05T00:00:00Z to 2027-12-06T00:00:00Z"),
            "{summary}"
        );
        let cert = Certificate::parse(&fs::read(&path).unwrap()).unwrap();
        let mut buf = [0u8; 44];
        let root_public = sig::public_key(&keyfile::parse_private(RFC8410_PEM).unwrap());
        assert_eq!(pkgfmt::b64::encode(&root_public, &mut buf), RFC8410_PUBLIC);
        assert!(cert.check_signature(&root_public));
        assert_eq!(cert.issuer.as_str(), "rfc-root");
        assert_eq!(cert.not_after - cert.not_before, 396 * DAY);
        // The certificate verifies a block of the release key against the root.
        let seed = read_private(&dir.join("t-release.key")).unwrap();
        let block = Block::sign(
            &seed,
            Kind::Package,
            1,
            [0; 32],
            day_start("2026-11-06").unwrap(),
            cert.key,
            Some(cert.to_bytes()),
        );
        let roots = [Key {
            name: cert.issuer,
            public: root_public,
        }];
        let signer = trust::verify(
            &block,
            Kind::Package,
            &[0; 32],
            1,
            &Trust {
                roots: &roots,
                direct: &[],
            },
            &[],
        )
        .unwrap();
        assert_eq!(signer.root, Some(cert.issuer));
        // show reads it back.
        let shown = show(&path).unwrap();
        assert!(
            shown.contains("certificate of t-release for packages"),
            "{shown}"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn pairs_are_made_once_with_private_files_closed() {
        let dir = scratch("pair");
        let tree = crate::root();
        let line = generate(Role::Root, "t-root-2", &dir, &tree).unwrap();
        let mode = fs::metadata(dir.join("t-root-2.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(fs::read_to_string(dir.join("t-root-2.pub")).unwrap(), line);
        assert!(!line.contains("PRIVATE"));
        assert!(generate(Role::Root, "t-root-2", &dir, &tree).is_err());
        for (role, name) in [
            (Role::Root, "t-release"),
            (Role::Release, "t-root"),
            (Role::Release, "x"),
            (Role::Root, "Bad-root"),
            (Role::Root, "t-root-x"),
        ] {
            assert!(generate(role, name, &dir, &tree).is_err(), "{name}");
        }
        assert!(
            show(&dir.join("t-root-2.key"))
                .unwrap_err()
                .contains("does not open")
        );
        assert!(
            show(&dir.join("t-root-2.pub"))
                .unwrap()
                .contains("t-root-2")
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_working_tree_is_closed_to_private_keys_except_target_keys() {
        let tree = crate::root();
        let inside = tree.join("target").join("keys-test-inside");
        fs::create_dir_all(&inside).unwrap();
        let err = generate(Role::Root, "t-root", &inside, &tree).unwrap_err();
        fs::remove_dir_all(&inside).unwrap();
        assert!(err.contains("working tree"), "{err}");
        let dev = tree.join("target").join("keys").join("keys-test");
        let _ = fs::remove_dir_all(&dev);
        generate(Role::Root, "t-root", &dev, &tree).unwrap();
        fs::remove_dir_all(&dev).unwrap();
    }

    #[test]
    fn certify_refuses_a_root_that_is_not_the_one_in_the_tree_and_other_shapes() {
        let dir = scratch("refuse");
        let tree = crate::root();
        generate(Role::Release, "t-release", &dir, &tree).unwrap();
        generate(Role::Root, "t-root", &dir, &tree).unwrap();
        let mut c = Certify {
            root_key: dir.join("t-root.key"),
            key: dir.join("t-release.pub"),
            purposes: 1,
            from: 0,
            days: 1,
            out: None,
        };
        certify(&c, &tree).unwrap();
        // The key to certify is a root: refused.
        c.key = dir.join("t-root.pub");
        assert!(certify(&c, &tree).is_err());
        // The issuer is a release key: refused.
        c.key = dir.join("t-release.pub");
        c.root_key = dir.join("t-release.key");
        assert!(certify(&c, &tree).is_err());
        // A private key that is not unencrypted PKCS#8.
        fs::write(
            dir.join("enc-root.key"),
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n",
        )
        .unwrap();
        c.root_key = dir.join("enc-root.key");
        let err = certify(&c, &tree).unwrap_err();
        assert!(
            err.contains("not an unencrypted PKCS#8 Ed25519 key; convert it with openssl pkey"),
            "{err}"
        );
        // A public line that names another key than its file.
        fs::copy(dir.join("t-release.pub"), dir.join("other-release.pub")).unwrap();
        c.root_key = dir.join("t-root.key");
        c.key = dir.join("other-release.pub");
        assert!(certify(&c, &tree).unwrap_err().contains("is named"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_new_key_directory_is_closed_to_other_users() {
        let base = scratch("mode");
        let nested = base.join("a").join("keys");
        generate(Role::Root, "t-root", &nested, &crate::root()).unwrap();
        for d in [&nested, &base.join("a")] {
            assert_eq!(fs::metadata(d).unwrap().permissions().mode() & 0o777, 0o700);
        }
        // An existing directory keeps its mode.
        let open = base.join("open");
        fs::create_dir(&open).unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o755)).unwrap();
        generate(Role::Release, "t-release", &open, &crate::root()).unwrap();
        assert_eq!(
            fs::metadata(&open).unwrap().permissions().mode() & 0o777,
            0o755
        );
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn a_root_named_like_the_official_one_must_be_that_key() {
        let dir = scratch("official");
        let tree = crate::root();
        generate(Role::Root, "stafeto-root-1", &dir, &tree).unwrap();
        generate(Role::Release, "t-release", &dir, &tree).unwrap();
        let err = certify(
            &Certify {
                root_key: dir.join("stafeto-root-1.key"),
                key: dir.join("t-release.pub"),
                purposes: 1,
                from: 0,
                days: 1,
                out: None,
            },
            &tree,
        )
        .unwrap_err();
        assert!(
            err.contains("is not the one that keys/stafeto-root-1.pub names"),
            "{err}"
        );
        assert!(!dir.join("t-release.cert").exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_certificate_of_another_key_is_refused_for_signing() {
        let dir = scratch("signing");
        let tree = crate::root();
        generate(Role::Root, "t-root", &dir, &tree).unwrap();
        generate(Role::Release, "t-release", &dir, &tree).unwrap();
        generate(Role::Release, "t-release-2", &dir, &tree).unwrap();
        let mut c = Certify {
            root_key: dir.join("t-root.key"),
            key: dir.join("t-release.pub"),
            purposes: 1,
            from: 0,
            days: 1,
            out: None,
        };
        certify(&c, &tree).unwrap();
        // The certificate of t-release with the private key of t-release: fine.
        let good = signing(
            Some(&dir.join("t-release.key")),
            Some(&dir.join("t-release.cert")),
            &tree,
        )
        .unwrap();
        assert!(good.certificate.is_some());
        // With the private key of another pair, and with another name: refused.
        fs::copy(dir.join("t-release.cert"), dir.join("t-release-2.cert")).unwrap();
        let err = signing(
            Some(&dir.join("t-release-2.key")),
            Some(&dir.join("t-release-2.cert")),
            &tree,
        )
        .err()
        .unwrap();
        assert!(err.contains("another public key"), "{err}");
        // Same name, another key: a key file t-release.key of a second pair.
        let other = dir.join("other");
        fs::create_dir(&other).unwrap();
        generate(Role::Release, "t-release", &other, &tree).unwrap();
        let err = signing(
            Some(&other.join("t-release.key")),
            Some(&dir.join("t-release.cert")),
            &tree,
        )
        .err()
        .unwrap();
        assert!(err.contains("another public key"), "{err}");
        c.days = 1;
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A tree with `keys/` holding the given public files.
    fn tree_with(tag: &str, files: &[(&str, &str)]) -> PathBuf {
        let tree = scratch(tag);
        fs::create_dir_all(tree.join("keys")).unwrap();
        for (name, text) in files {
            fs::write(tree.join("keys").join(name), text).unwrap();
        }
        tree
    }

    fn parsed(dir: &Path) -> (u64, Vec<(String, u64)>, Block) {
        let text = fs::read_to_string(dir.join("revoked")).unwrap();
        let list = pkgfmt::revoked::Revoked::parse(&text).unwrap();
        let entries = list
            .entries()
            .map(|e| (e.name.as_str().to_string(), e.since))
            .collect();
        let block = Block::parse(&fs::read(dir.join("revoked.sig")).unwrap()).unwrap();
        (list.serial, entries, block)
    }

    fn revoke_args(root: &Path, key: &str, since: &str, list: &Path, out: &Path) -> Revoke {
        Revoke {
            root_key: root.to_path_buf(),
            init: false,
            key: Some(key.into()),
            since: Some(since.into()),
            list: Some(list.to_path_buf()),
            out: Some(out.to_path_buf()),
        }
    }

    #[test]
    fn revoke_starts_a_list_and_adds_entries_with_a_rising_serial() {
        let dir = scratch("revoke");
        let tree = tree_with("revoke-tree", &[]);
        generate(Role::Root, "t-root", &dir, &crate::root()).unwrap();
        let root = dir.join("t-root.key");
        let init = Revoke {
            root_key: root.clone(),
            init: true,
            key: None,
            since: None,
            list: None,
            out: Some(dir.join("a")),
        };
        revoke(&init, &tree).unwrap();
        // A second --init over the same directory is refused.
        assert!(revoke(&init, &tree).unwrap_err().contains("already"));
        let (serial, entries, block) = parsed(&dir.join("a"));
        assert_eq!((serial, entries.len()), (1, 0));
        // The signature is of kind 3 by the root, without a certificate.
        assert_eq!(block.kind, Kind::Revoked);
        assert!(block.certificate.is_none());
        let public = sig::public_key(&read_private(&root).unwrap());
        assert!(block.check_signature(&public));
        let list = dir.join("a").join("revoked");
        revoke(
            &revoke_args(
                &root,
                "t-release-2026",
                "2026-01-10T00:00:00Z",
                &list,
                &dir.join("b"),
            ),
            &tree,
        )
        .unwrap();
        let list_b = dir.join("b").join("revoked");
        let out = revoke(
            &revoke_args(
                &root,
                "t-release-2025",
                "2026-05-01T12:00:00Z",
                &list_b,
                &dir.join("c"),
            ),
            &tree,
        )
        .unwrap();
        assert!(out.contains("serial 3"), "{out}");
        let (serial, entries, block) = parsed(&dir.join("c"));
        assert_eq!(serial, 3);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, "t-release-2025");
        assert_eq!(entries[1], ("t-release-2026".into(), 1768003200));
        // The list verifies with kind 3 and refuses another kind.
        let text = fs::read(dir.join("c").join("revoked")).unwrap();
        let roots = [Key {
            name: Name::new("t-root").unwrap(),
            public,
        }];
        let trust = Trust {
            roots: &roots,
            direct: &[],
        };
        let digest = pkgfmt::sha::sha256(&text);
        assert!(
            pkgfmt::trust::verify(
                &block,
                Kind::Revoked,
                &digest,
                text.len() as u64,
                &trust,
                &[]
            )
            .is_ok()
        );
        assert!(
            pkgfmt::trust::verify(&block, Kind::Index, &digest, text.len() as u64, &trust, &[])
                .is_err()
        );
        // The same name twice, and a root, are refused.
        let again = revoke_args(
            &root,
            "t-release-2026",
            "2026-02-01T00:00:00Z",
            &dir.join("c").join("revoked"),
            &dir.join("d"),
        );
        assert!(revoke(&again, &tree).unwrap_err().contains("already"));
        let a_root = revoke_args(
            &root,
            "t-root",
            "2026-02-01T00:00:00Z",
            &dir.join("c").join("revoked"),
            &dir.join("d"),
        );
        assert!(revoke(&a_root, &tree).is_err());
        assert!(!dir.join("d").exists());
        fs::remove_dir_all(&dir).unwrap();
        fs::remove_dir_all(&tree).unwrap();
    }

    #[test]
    fn revoke_since_start_takes_the_term_of_the_certificate() {
        let dir = scratch("revoke-start");
        let tree = tree_with("revoke-start-tree", &[]);
        let k = crate::root();
        generate(Role::Root, "t-root", &dir, &k).unwrap();
        generate(Role::Release, "t-release-2026", &dir, &k).unwrap();
        certify(
            &Certify {
                root_key: dir.join("t-root.key"),
                key: dir.join("t-release-2026.pub"),
                purposes: cert::PURPOSE_PACKAGES,
                from: day_start("2026-11-05").unwrap(),
                days: 396,
                out: Some(tree.join("keys").join("t-release-2026.cert")),
            },
            &tree,
        )
        .unwrap();
        let root = dir.join("t-root.key");
        revoke(
            &Revoke {
                root_key: root.clone(),
                init: true,
                key: None,
                since: None,
                list: None,
                out: Some(tree.join("keys")),
            },
            &tree,
        )
        .unwrap();
        // Defaults: the list of keys/ of the tree, written back there.
        let out = revoke(
            &Revoke {
                root_key: root.clone(),
                init: false,
                key: Some("t-release-2026".into()),
                since: Some("start".into()),
                list: None,
                out: None,
            },
            &tree,
        )
        .unwrap();
        assert!(
            out.contains("since 2026-11-05T00:00:00Z, serial 2"),
            "{out}"
        );
        let (_, entries, _) = parsed(&tree.join("keys"));
        assert_eq!(entries[0].1, day_start("2026-11-05").unwrap());
        // A key without a certificate in keys/ cannot use start, and a date is fine.
        let none = revoke_args(
            &root,
            "t-release-2024",
            "start",
            &tree.join("keys").join("revoked"),
            &tree.join("keys"),
        );
        assert!(revoke(&none, &tree).unwrap_err().contains("no certificate"));
        let dated = revoke_args(
            &root,
            "t-release-2024",
            "2024-01-01T00:00:00Z",
            &tree.join("keys").join("revoked"),
            &tree.join("keys"),
        );
        assert!(revoke(&dated, &tree).is_ok());
        // A bad time.
        let bad = revoke_args(
            &root,
            "t-release-2023",
            "yesterday",
            &tree.join("keys").join("revoked"),
            &tree.join("keys"),
        );
        assert!(revoke(&bad, &tree).unwrap_err().contains("not a time"));
        fs::remove_dir_all(&dir).unwrap();
        fs::remove_dir_all(&tree).unwrap();
    }

    #[test]
    fn revoke_refuses_another_root_and_a_damaged_list() {
        let dir = scratch("revoke-refuse");
        let tree = tree_with("revoke-refuse-tree", &[]);
        let k = crate::root();
        generate(Role::Root, "t-root", &dir, &k).unwrap();
        let other = dir.join("other");
        fs::create_dir(&other).unwrap();
        generate(Role::Root, "t-root", &other, &k).unwrap();
        generate(Role::Root, "t-root-2", &other, &k).unwrap();
        let mut init = Revoke {
            root_key: dir.join("t-root.key"),
            init: true,
            key: None,
            since: None,
            list: None,
            out: Some(dir.join("a")),
        };
        revoke(&init, &tree).unwrap();
        let list = dir.join("a").join("revoked");
        // The same name with another key: the signature fails.
        let err = revoke(
            &revoke_args(
                &other.join("t-root.key"),
                "t-release",
                "2026-01-01T00:00:00Z",
                &list,
                &dir.join("b"),
            ),
            &tree,
        )
        .unwrap_err();
        assert!(err.contains("not signed by t-root"), "{err}");
        // Another root name: the key is unknown.
        let err = revoke(
            &revoke_args(
                &other.join("t-root-2.key"),
                "t-release",
                "2026-01-01T00:00:00Z",
                &list,
                &dir.join("b"),
            ),
            &tree,
        )
        .unwrap_err();
        assert!(err.contains("not signed by t-root-2"), "{err}");
        // A list whose text changed after the signature.
        let good = fs::read_to_string(&list).unwrap();
        fs::write(&list, good.replace("serial 1", "serial 9")).unwrap();
        let err = revoke(
            &revoke_args(
                &dir.join("t-root.key"),
                "t-release",
                "2026-01-01T00:00:00Z",
                &list,
                &dir.join("b"),
            ),
            &tree,
        )
        .unwrap_err();
        assert!(err.contains("not signed by"), "{err}");
        fs::write(&list, good).unwrap();
        // A damaged signature file.
        let sig_path = dir.join("a").join("revoked.sig");
        let mut bytes = fs::read(&sig_path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&sig_path, bytes).unwrap();
        assert!(
            revoke(
                &revoke_args(
                    &dir.join("t-root.key"),
                    "t-release",
                    "2026-01-01T00:00:00Z",
                    &list,
                    &dir.join("b")
                ),
                &tree
            )
            .is_err()
        );
        // The tree names the root: a private key of another pair under that name is refused.
        fs::copy(dir.join("t-root.pub"), tree.join("keys").join("t-root.pub")).unwrap();
        init.root_key = other.join("t-root.key");
        init.out = Some(dir.join("e"));
        let err = revoke(&init, &tree).unwrap_err();
        assert!(
            err.contains("is not the one that keys/t-root.pub names"),
            "{err}"
        );
        assert!(!dir.join("e").exists());
        // --init does not mix with the other options.
        init.root_key = dir.join("t-root.key");
        init.key = Some("t-release".into());
        assert!(revoke(&init, &tree).is_err());
        fs::remove_dir_all(&dir).unwrap();
        fs::remove_dir_all(&tree).unwrap();
    }

    #[test]
    fn the_rfc_8410_key_is_a_root_for_revoke() {
        let dir = scratch("revoke-rfc");
        let tree = tree_with("revoke-rfc-tree", &[]);
        fs::write(dir.join("rfc-root.key"), RFC8410_PEM).unwrap();
        let init = Revoke {
            root_key: dir.join("rfc-root.key"),
            init: true,
            key: None,
            since: None,
            list: None,
            out: Some(dir.join("a")),
        };
        revoke(&init, &tree).unwrap();
        let (serial, _, block) = parsed(&dir.join("a"));
        assert_eq!(serial, 1);
        assert_eq!(block.key.as_str(), "rfc-root");
        let public = sig::public_key(&keyfile::parse_private(RFC8410_PEM).unwrap());
        assert!(block.check_signature(&public));
        fs::remove_dir_all(&dir).unwrap();
        fs::remove_dir_all(&tree).unwrap();
    }

    #[test]
    fn the_roots_files_of_keys_are_exactly_the_baked_in_roots() {
        // A root file that is not in `OFFICIAL_ROOTS` fails here, so that a
        // key put into keys/ is never trusted unseen.
        let dir = crate::root().join("keys");
        let mut found: Vec<(String, String)> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "pub"))
            .map(|p| {
                (
                    p.file_name().unwrap().to_string_lossy().to_string(),
                    fs::read_to_string(&p).unwrap(),
                )
            })
            .collect();
        found.sort();
        let mut baked: Vec<String> = pkgfmt::OFFICIAL_ROOTS
            .iter()
            .map(|l| l.to_string())
            .collect();
        baked.sort();
        let texts: Vec<String> = found.iter().map(|(_, t)| t.clone()).collect();
        assert_eq!(
            texts,
            baked,
            "keys/*.pub: {:?}",
            found.iter().map(|f| &f.0).collect::<Vec<_>>()
        );
        for (name, text) in &found {
            let key = keyfile::parse_public(text).unwrap();
            assert_eq!(format!("{}.pub", key.name.as_str()), *name);
            assert!(
                role_name(key.name.as_str(), Role::Root),
                "{name} is not a root"
            );
        }
        let roots = official_roots().unwrap();
        assert_eq!(roots.len(), pkgfmt::OFFICIAL_ROOTS.len());
    }

    #[test]
    fn a_certificate_is_trusted_through_the_file_of_its_issuer() {
        let dir = scratch("two-roots");
        let k = crate::root();
        generate(Role::Root, "t-root-1", &dir, &k).unwrap();
        generate(Role::Root, "t-root-2", &dir, &k).unwrap();
        let line = |n: &str| fs::read_to_string(dir.join(format!("{n}.pub"))).unwrap();
        let tree = tree_with(
            "two-roots-tree",
            &[
                ("t-root-1.pub", &line("t-root-1")),
                ("t-root-2.pub", &line("t-root-2")),
            ],
        );
        generate(Role::Release, "t-release", &dir, &k).unwrap();
        certify(
            &Certify {
                root_key: dir.join("t-root-2.key"),
                key: dir.join("t-release.pub"),
                purposes: cert::PURPOSE_PACKAGES,
                from: 0,
                days: 1,
                out: None,
            },
            &tree,
        )
        .unwrap();
        let s = signing(
            Some(&dir.join("t-release.key")),
            Some(&dir.join("t-release.cert")),
            &tree,
        )
        .unwrap();
        let (trusted, direct) = trust_of(&s, &tree).unwrap();
        assert_eq!(trusted.len(), 1);
        assert_eq!(trusted[0].name.as_str(), "t-root-2");
        assert!(direct.is_empty());
        fs::remove_file(tree.join("keys").join("t-root-2.pub")).unwrap();
        assert!(trust_of(&s, &tree).is_err());
        fs::remove_dir_all(&dir).unwrap();
        fs::remove_dir_all(&tree).unwrap();
    }

    #[test]
    fn a_revocation_since_a_time_to_come_is_refused() {
        let dir = scratch("revoke-future");
        let tree = tree_with("revoke-future-tree", &[]);
        generate(Role::Root, "t-root", &dir, &crate::root()).unwrap();
        let root = dir.join("t-root.key");
        let init = Revoke {
            root_key: root.clone(),
            init: true,
            key: None,
            since: None,
            list: None,
            out: Some(dir.join("a")),
        };
        revoke(&init, &tree).unwrap();
        let list = dir.join("a").join("revoked");
        let err = revoke(
            &revoke_args(
                &root,
                "t-release",
                "2999-01-01T00:00:00Z",
                &list,
                &dir.join("b"),
            ),
            &tree,
        )
        .unwrap_err();
        assert!(err.contains("a time to come"), "{err}");
        assert!(!dir.join("b").exists());
        fs::remove_dir_all(&dir).unwrap();
        fs::remove_dir_all(&tree).unwrap();
    }

    #[test]
    fn the_release_certificate_is_the_latest_one_that_covers_the_time() {
        let dir = scratch("current-cert");
        let k = crate::root();
        generate(Role::Root, "t-root", &dir, &k).unwrap();
        let tree = tree_with("current-cert-tree", &[]);
        for (name, from, days, purposes) in [
            ("t-release-2025", "2025-11-01", 396, cert::PURPOSE_PACKAGES),
            ("t-release-2026", "2026-11-01", 396, cert::PURPOSE_PACKAGES),
            ("t-release-2027", "2026-11-03", 396, cert::PURPOSE_ELF),
        ] {
            generate(Role::Release, name, &dir, &k).unwrap();
            certify(
                &Certify {
                    root_key: dir.join("t-root.key"),
                    key: dir.join(format!("{name}.pub")),
                    purposes,
                    from: day_start(from).unwrap(),
                    days,
                    out: Some(tree.join("keys").join(format!("{name}.cert"))),
                },
                &tree,
            )
            .unwrap();
        }
        let at = day_start("2026-11-06").unwrap();
        let (path, c) = current_release_certificate(&tree, at).unwrap();
        assert_eq!(c.key.as_str(), "t-release-2026");
        assert!(path.ends_with("t-release-2026.cert"));
        // Before the second term only the first covers; after the third no one.
        let (_, c) = current_release_certificate(&tree, day_start("2026-10-15").unwrap()).unwrap();
        assert_eq!(c.key.as_str(), "t-release-2025");
        assert!(current_release_certificate(&tree, day_start("2030-01-01").unwrap()).is_err());
        fs::remove_dir_all(&dir).unwrap();
        fs::remove_dir_all(&tree).unwrap();
    }

    #[test]
    fn a_key_without_cert_takes_the_certificate_of_the_tree_that_names_it() {
        let dir = scratch("tree-cert");
        let tree = tree_with("tree-cert-tree", &[]);
        let k = crate::root();
        generate(Role::Root, "t-root", &dir, &k).unwrap();
        generate(Role::Release, "t-release-2026", &dir, &k).unwrap();
        let key = dir.join("t-release-2026.key");
        assert!(
            signing(Some(&key), None, &tree)
                .unwrap()
                .certificate
                .is_none()
        );
        certify(
            &Certify {
                root_key: dir.join("t-root.key"),
                key: dir.join("t-release-2026.pub"),
                purposes: cert::PURPOSE_PACKAGES,
                from: now() / DAY * DAY,
                days: 10,
                out: Some(tree.join("keys").join("t-release-2026.cert")),
            },
            &tree,
        )
        .unwrap();
        assert!(
            signing(Some(&key), None, &tree)
                .unwrap()
                .certificate
                .is_some()
        );
        fs::remove_dir_all(&dir).unwrap();
        fs::remove_dir_all(&tree).unwrap();
    }
}
