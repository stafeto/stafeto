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

pub struct Options {
    pub serial: u64,
    pub expires_days: u64,
    pub sources: bool,
    pub key: Option<PathBuf>,
    pub cert: Option<PathBuf>,
    pub root: Option<PathBuf>,
    pub check: bool,
    pub dir: Option<PathBuf>,
}

pub fn parse_options(args: &[String]) -> Result<Options, String> {
    let mut o = Options {
        serial: 1,
        expires_days: EXPIRES_MAX_DAYS,
        sources: true,
        key: None,
        cert: None,
        root: None,
        check: false,
        dir: None,
    };
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        let wants_value = flag != "--no-sources" && flag != "--check";
        let value = if wants_value {
            i += 1;
            args.get(i)
                .cloned()
                .ok_or_else(|| format!("{flag} wants a value"))?
        } else {
            String::new()
        };
        match flag {
            "--serial" => {
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

/// The whole of `repo` for the packages built: the directory.
pub fn make(built: &[Built], all: &[Package], o: &Options) -> Result<PathBuf, String> {
    let tree = crate::root();
    let dir = o.dir.clone().unwrap_or_else(directory);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).map_err(|e| format!("{}: {e}", dir.display()))?;
    let dev = keys::dev_keys(&tree)?;
    let signing = keys::signing(o.key.as_deref(), o.cert.as_deref(), &tree)?;
    let commit = pkg::commit()?;
    let relibc = crate::script_value("tools/build-relibc.py", "COMMIT")?;
    // The text the entries borrow.
    struct Row {
        version: String,
        digest: String,
        file: String,
        size: u64,
        source: Option<String>,
        provides: Option<String>,
        depends: Option<String>,
        needs: Option<String>,
    }
    let mut rows: Vec<Row> = Vec::new();
    for b in built {
        let name = pkg::file_name(&b.package);
        let bytes = std::fs::read(&b.path).map_err(|e| format!("{}: {e}", b.path.display()))?;
        std::fs::write(dir.join(&name), &bytes).map_err(|e| format!("{name}: {e}"))?;
        let source = if o.sources {
            notices::source_archive(&b.package, all)
        } else {
            None
        };
        if let Some(archive) = &source {
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
        rows.push(Row {
            version: format!("{}-{}", file.meta.version, file.meta.release),
            digest: sha_hex(&bytes),
            file: name,
            size: bytes.len() as u64,
            source,
            provides: join(&b.package.provides),
            depends: join(&b.package.depends),
            needs: join(&b.package.needs),
        });
    }
    let entries: Vec<Entry<'_>> = built
        .iter()
        .zip(&rows)
        .map(|(b, r)| Entry {
            name: &b.package.name,
            version: &r.version,
            provides: r.provides.as_deref(),
            depends: r.depends.as_deref(),
            needs: r.needs.as_deref(),
            license: &b.package.license,
            size: r.size,
            sha256: &r.digest,
            recipe: &b.recipe,
            file: &r.file,
            source: r.source.as_deref(),
            summary: &b.package.summary,
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
    std::fs::write(dir.join("INDEX"), &text).map_err(|e| format!("INDEX: {e}"))?;
    std::fs::write(dir.join("INDEX.sig"), block.to_bytes())
        .map_err(|e| format!("INDEX.sig: {e}"))?;
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
    Ok(dir)
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
        let bytes = read(e.file)?;
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
            && !source.starts_with("https://")
            && !dir.join(source).is_file()
        {
            return Err(fail(source, "the source archive is missing".into()));
        }
        count += 1;
    }
    Ok(count)
}

/// `cargo xtask repo [--serial N] [--expires-days D] [--no-sources] [--key K.key --cert K.cert] [--check]`.
pub fn command(args: &[String]) -> Result<(), String> {
    run(&parse_options(args)?).map(drop)
}

pub fn run(o: &Options) -> Result<PathBuf, String> {
    let tree = crate::root();
    let roots = match &o.root {
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
        names: Vec::new(),
        key: o.key.clone(),
        cert: o.cert.clone(),
        time: None,
        out: None,
        recipe: false,
    })?;
    let all = packages::load()?;
    let dir = make(&built, &all, o)?;
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
}
