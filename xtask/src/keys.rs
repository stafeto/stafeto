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
use pkgfmt::{Key, Name, keyfile, sig, time};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
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
    fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
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
                    Certificate::parse(&bytes).map_err(|e| format!("{}: {e}", p.display()))?;
                    let mut out = [0u8; cert::SIZE];
                    out.copy_from_slice(&bytes);
                    Some(out)
                }
                None => None,
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
    let stem = c
        .root_key
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let issuer =
        Name::new(stem).map_err(|_| format!("{}: not a key file name", c.root_key.display()))?;
    if !role_name(stem, Role::Root) {
        return Err(format!(
            "{stem}: the issuer is a root key, named ...-root or ...-root-N"
        ));
    }
    let seed = read_private(&c.root_key)?;
    let public = sig::public_key(&seed);
    let official = tree.join("keys").join(format!("{stem}.pub"));
    if official.is_file() {
        let key = read_public(&official)?;
        if key.public != public {
            return Err(format!(
                "{}: the private key is not the one that keys/{stem}.pub names",
                c.root_key.display()
            ));
        }
    }
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
}
