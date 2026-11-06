// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Carrying packages from a published index (docs/packages.md): a package
//! whose recipe has not changed since the index of its series was signed
//! keeps the bytes of its file, so that its SHA-256, its signature and its
//! address stay the same. `pkg-build --previous` and `repo --previous` take
//! the index from an address (`https://...`) or a directory.
//!
//! * No index (an answer 404, or no `INDEX` in the directory) means the series
//!   is not published: everything is new and `release` is 1. Any other
//!   failure stops the build: building everything anew in silence would
//!   break the identity of the packages.
//! * The list of revocations and then the index are verified by the roots
//!   given. A package of the index is carried when an entry has the same
//!   recipe, the file has the size and SHA-256 of the entry, its `meta`
//!   says the same and its signature is accepted with the present list. A
//!   package whose key is revoked is built again.
//! * A package with a new recipe takes `release` one above the entry of the
//!   same version, or 1 for a new version or a new name.

use pkgfmt::index::Index;
use pkgfmt::sig::{Block, Kind};
use pkgfmt::{Error, Key, Package as PackageFile, Revocation, Trust, revoked, sha};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

/// An entry of the index that was carried from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrevEntry {
    pub name: String,
    /// The version of the entry without the release.
    pub version: String,
    pub release: String,
    pub recipe: String,
    /// What the new index says in `file`: the full address when the index
    /// came from an address, the entry's own field when it came from a directory.
    pub file: String,
    /// Where the file is read from.
    pub fetch: String,
    pub source: Option<String>,
    pub size: u64,
    pub sha256: String,
}

/// The index a series was last published with.
#[derive(Clone, Debug)]
pub struct Previous {
    pub serial: u64,
    pub entries: Vec<PrevEntry>,
    pub revocations: Vec<Revocation>,
}

/// Bytes at an address or path; `None` for "there is nothing": an answer
/// 404, a missing file. Any other failure is an `Err`.
pub type Fetch<'a> = &'a dyn Fn(&str) -> Result<Option<Vec<u8>>, String>;

/// The fetcher of the tool: `curl` for `https://` (redirects followed, at
/// most 5, nothing but https), a file read for a path.
pub fn fetch(address: &str) -> Result<Option<Vec<u8>>, String> {
    if !address.starts_with("https://") {
        return match std::fs::read(address) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("{address}: {e}")),
        };
    }
    // As the `curl` of the device (apps/pkg/src/fetch.rs): no `~/.curlrc`, https
    // for the first request and for every redirection, TLS 1.2 and above.
    let out = Command::new("curl")
        .args([
            "-q",
            "-sS",
            "-L",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--tlsv1.2",
            "--max-redirs",
            "5",
            "--max-time",
            "300",
            "-w",
            "\n%{http_code}",
            address,
        ])
        .output()
        .map_err(|e| format!("curl {address}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{address}: curl failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let split = out
        .stdout
        .iter()
        .rposition(|&b| b == b'\n')
        .ok_or_else(|| format!("{address}: no status from curl"))?;
    let code = String::from_utf8_lossy(&out.stdout[split + 1..]).to_string();
    match code.as_str() {
        "200" => Ok(Some(out.stdout[..split].to_vec())),
        "404" => Ok(None),
        other => Err(format!("{address}: the answer is {other}")),
    }
}

fn join(base: &str, name: &str) -> String {
    format!("{}/{name}", base.trim_end_matches('/'))
}

/// The full address of a `file` field of an entry.
pub fn address_of(base: &str, file: &str) -> String {
    if file.starts_with("https://") {
        file.to_string()
    } else {
        join(base, file)
    }
}

fn split_version(version: &str) -> Option<(&str, &str)> {
    version.rsplit_once('-')
}

/// What the tree says about the index to carry from, besides its signature.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    /// The time now; an index that expired before it is refused (the index of
    /// a series is signed again every week).
    pub now: u64,
    /// The `serial` of `keys/revoked` of the tree and its entries: the list
    /// next to the index may not be older, and the entries count too.
    pub tree_list: Option<(u64, Vec<Revocation>)>,
    /// The `serial` of the index last published for the series, from
    /// `packages/published-serial.txt`; an older index is a rollback.
    pub min_serial: u64,
    /// The series is frozen in `packages/abi.txt`, so it is published: no index
    /// is a failure of the place it is served from, not a new series.
    pub frozen: bool,
    /// The index is the signed copy that the release of the series carries
    /// (a directory): the place it is kept vouches for its records, so a key
    /// revoked since it signed, the term it has run out and the serial of the
    /// pages do not stop the carrying. The revocations still judge the tail
    /// of every package, which is how a revoked key's packages are built again.
    pub anchored: bool,
}

/// `keys/revoked` of the tree with its signature checked by the official
/// roots: the `serial` and the entries. A missing list is an error unless
/// `optional`.
pub fn tree_revocations(
    tree: &Path,
    optional: bool,
) -> Result<Option<(u64, Vec<Revocation>)>, String> {
    let list_path = tree.join("keys/revoked");
    let sig_path = tree.join("keys/revoked.sig");
    let (Ok(list_bytes), Ok(sig_bytes)) = (std::fs::read(&list_path), std::fs::read(&sig_path))
    else {
        return if optional {
            Ok(None)
        } else {
            Err(format!(
                "{}: the list of revocations is missing",
                list_path.display()
            ))
        };
    };
    let fail = |e: String| format!("{}: {e}", list_path.display());
    let roots = crate::keys::official_roots()?;
    let text = String::from_utf8(list_bytes.clone()).map_err(|e| fail(e.to_string()))?;
    let list = revoked::Revoked::parse(&text).map_err(|e| fail(e.to_string()))?;
    let block = Block::parse(&sig_bytes).map_err(|e| fail(e.to_string()))?;
    pkgfmt::trust::verify(
        &block,
        Kind::Revoked,
        &sha::sha256(&list_bytes),
        list_bytes.len() as u64,
        &Trust {
            roots: &roots,
            direct: &[],
        },
        &[],
    )
    .map_err(|e| fail(e.to_string()))?;
    Ok(Some((list.serial, list.entries().collect())))
}

impl Policy {
    /// The policy of the tree for the index at `base`: for an address the
    /// list of the tree is required, for a directory (a probe) it is used if
    /// it is there.
    pub fn of_tree(tree: &Path, base: &str, series: &str) -> Result<Policy, String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let tree_list = tree_revocations(tree, !base.starts_with("https://"))?;
        let min_serial = match std::fs::read_to_string(tree.join("packages/published-serial.txt")) {
            Ok(text) => text
                .lines()
                .filter_map(|l| l.split_once(' '))
                .find(|(s, _)| *s == series)
                .map_or(Ok(0), |(_, n)| {
                    n.trim()
                        .parse::<u64>()
                        .map_err(|_| format!("published-serial.txt: {n:?} is no serial"))
                })?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
            Err(e) => return Err(format!("packages/published-serial.txt: {e}")),
        };
        let frozen = match std::fs::read_to_string(crate::abi_fingerprint::file_path(tree)) {
            Ok(text) => {
                let f = crate::abi_fingerprint::File::parse(&text)?;
                f.series == series && f.state == crate::abi_fingerprint::State::Frozen
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(format!("packages/abi.txt: {e}")),
        };
        Ok(Policy {
            now,
            tree_list,
            min_serial,
            frozen,
            anchored: !base.starts_with("https://"),
        })
    }
}

/// Loads and verifies the list of revocations and the index at `base`. `None`
/// when the index is not there.
pub fn load(
    base: &str,
    series: &str,
    fetch: Fetch<'_>,
    roots: &[Key],
    policy: &Policy,
) -> Result<Option<Previous>, String> {
    let get = |name: &str| fetch(&join(base, name));
    let Some(index_bytes) = get("INDEX")? else {
        if policy.frozen {
            return Err(format!(
                "{}: no index for the series {series}, which is frozen, so published; the place it is served from has failed",
                join(base, "")
            ));
        }
        return Ok(None);
    };
    let need =
        |name: &str| get(name)?.ok_or_else(|| format!("{}: the file is missing", join(base, name)));
    let fail = |what: &str, e: String| format!("{}: {what}: {e}", join(base, ""));
    let trust = Trust { roots, direct: &[] };
    let list_bytes = need("revoked")?;
    let list_text =
        String::from_utf8(list_bytes.clone()).map_err(|e| fail("revoked", e.to_string()))?;
    let list = revoked::Revoked::parse(&list_text).map_err(|e| fail("revoked", e.to_string()))?;
    let rblock =
        Block::parse(&need("revoked.sig")?).map_err(|e| fail("revoked.sig", e.to_string()))?;
    pkgfmt::trust::verify(
        &rblock,
        Kind::Revoked,
        &sha::sha256(&list_bytes),
        list_bytes.len() as u64,
        &trust,
        &[],
    )
    .map_err(|e| fail("revoked.sig", e.to_string()))?;
    let mut revocations: Vec<Revocation> = list.entries().collect();
    if let Some((serial, entries)) = &policy.tree_list {
        if list.serial < *serial {
            return Err(fail(
                "revoked",
                format!(
                    "serial {} is older than serial {serial} of keys/revoked",
                    list.serial
                ),
            ));
        }
        revocations.extend(entries.iter().copied());
    }
    let text = String::from_utf8(index_bytes.clone()).map_err(|e| fail("INDEX", e.to_string()))?;
    let index = Index::parse(&text).map_err(|e| fail("INDEX", e.to_string()))?;
    let iblock = Block::parse(&need("INDEX.sig")?).map_err(|e| fail("INDEX.sig", e.to_string()))?;
    pkgfmt::trust::verify(
        &iblock,
        Kind::Index,
        &sha::sha256(&index_bytes),
        index_bytes.len() as u64,
        &trust,
        if policy.anchored { &[] } else { &revocations },
    )
    .map_err(|e| fail("INDEX.sig", e.to_string()))?;
    let h = &index.header;
    if h.expires < policy.now && !policy.anchored {
        return Err(fail(
            "INDEX",
            "the index expired; the series is signed again every week, so something has failed"
                .into(),
        ));
    }
    if h.serial < policy.min_serial && !policy.anchored {
        return Err(fail(
            "INDEX",
            format!(
                "serial {} is older than the {} published last",
                h.serial, policy.min_serial
            ),
        ));
    }
    if h.repository != "stafeto" || h.series != series || h.arch != "aarch64" {
        return Err(fail(
            "INDEX",
            format!(
                "the header says {} {} {}, this build is stafeto {series} aarch64",
                h.repository, h.series, h.arch
            ),
        ));
    }
    let remote = base.starts_with("https://");
    let mut entries = Vec::new();
    for e in index.entries() {
        let (version, release) = split_version(e.version)
            .ok_or_else(|| fail("INDEX", format!("{}: version {}", e.name, e.version)))?;
        entries.push(PrevEntry {
            name: e.name.to_string(),
            version: version.to_string(),
            release: release.to_string(),
            recipe: e.recipe.to_string(),
            file: if remote {
                address_of(base, e.file)
            } else {
                e.file.to_string()
            },
            fetch: address_of(base, e.file),
            source: e.source.map(|s| {
                if remote {
                    address_of(base, s)
                } else {
                    s.to_string()
                }
            }),
            size: e.size,
            sha256: e.sha256.to_string(),
        });
    }
    Ok(Some(Previous {
        serial: h.serial,
        entries,
        revocations,
    }))
}

/// A package of the descriptions as the plan sees it.
#[derive(Clone, Copy, Debug)]
pub struct Wanted<'a> {
    pub name: &'a str,
    pub version: &'a str,
    pub recipe: &'a str,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Fate {
    Carried {
        release: String,
        bytes: Vec<u8>,
        /// The address of the file in the index it came from.
        address: String,
        /// The address of its source archive there, if it has one.
        source: Option<String>,
    },
    Built {
        release: String,
        why: &'static str,
    },
}

impl Fate {
    pub fn release(&self) -> &str {
        match self {
            Fate::Carried { release, .. } | Fate::Built { release, .. } => release,
        }
    }
}

#[derive(Debug)]
pub struct Plan {
    pub fates: BTreeMap<String, Fate>,
    /// Names of the index that have no description any more.
    pub leaving: Vec<String>,
}

/// Decides for each wanted package. With no previous index every package is
/// new.
pub fn plan(
    previous: Option<&Previous>,
    wanted: &[Wanted<'_>],
    fetch: Fetch<'_>,
    roots: &[Key],
) -> Result<Plan, String> {
    let mut fates = BTreeMap::new();
    let Some(prev) = previous else {
        for w in wanted {
            fates.insert(
                w.name.to_string(),
                Fate::Built {
                    release: "1".into(),
                    why: "new",
                },
            );
        }
        return Ok(Plan {
            fates,
            leaving: Vec::new(),
        });
    };
    let trust = Trust { roots, direct: &[] };
    for w in wanted {
        let old = prev.entries.iter().find(|e| e.name == w.name);
        let Some(old) = old else {
            fates.insert(
                w.name.to_string(),
                Fate::Built {
                    release: "1".into(),
                    why: "new",
                },
            );
            continue;
        };
        let same_version = old.version == w.version;
        let next_release = || {
            if same_version {
                let n: u64 = old.release.parse().unwrap_or(0);
                (n + 1).to_string()
            } else {
                "1".to_string()
            }
        };
        if old.recipe != w.recipe || !same_version {
            fates.insert(
                w.name.to_string(),
                Fate::Built {
                    release: next_release(),
                    why: "recipe changed",
                },
            );
            continue;
        }
        let bytes = fetch(&old.fetch)?
            .ok_or_else(|| format!("{}: the file of {} is missing", old.fetch, w.name))?;
        if bytes.len() as u64 != old.size {
            return Err(format!(
                "{}: {} bytes, the index says {}",
                old.fetch,
                bytes.len(),
                old.size
            ));
        }
        let mut hex = [0u8; 64];
        if sha::hex(&sha::sha256(&bytes), &mut hex) != old.sha256 {
            return Err(format!("{}: the SHA-256 differs from the index", old.fetch));
        }
        let file = PackageFile::parse(&bytes).map_err(|e| format!("{}: {e}", old.fetch))?;
        let m = &file.meta;
        if m.name != w.name
            || m.version != w.version
            || m.release != old.release
            || m.recipe != w.recipe
        {
            return Err(format!(
                "{}: the meta of the file differs from the entry of the index",
                old.fetch
            ));
        }
        match file.verify(&trust, &prev.revocations) {
            Ok(_) => {
                fates.insert(
                    w.name.to_string(),
                    Fate::Carried {
                        release: old.release.clone(),
                        bytes,
                        address: old.file.clone(),
                        source: old.source.clone(),
                    },
                );
            }
            Err(Error::Revoked) => {
                fates.insert(
                    w.name.to_string(),
                    Fate::Built {
                        release: next_release(),
                        why: "key revoked",
                    },
                );
            }
            Err(e) => return Err(format!("{}: {e}", old.fetch)),
        }
    }
    let leaving = prev
        .entries
        .iter()
        .filter(|e| !wanted.iter().any(|w| w.name == e.name))
        .map(|e| e.name.clone())
        .collect();
    Ok(Plan { fates, leaving })
}

/// Releases the descriptions get from the plan (`packages::load` applies
/// them): the `release` field of a description is a base the plan replaces.
static RELEASES: std::sync::Mutex<BTreeMap<String, String>> =
    std::sync::Mutex::new(BTreeMap::new());

pub fn set_releases(releases: BTreeMap<String, String>) {
    *RELEASES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = releases;
}

pub fn release_of(name: &str) -> Option<String> {
    RELEASES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(name)
        .cloned()
}

/// Where the downloaded files and the serial of the previous index are kept.
pub fn directory() -> std::path::PathBuf {
    crate::target_dir().join("pkg").join("carry")
}

/// Prints one line per package and the leaving ones.
pub fn describe(plan: &Plan, previous: Option<&Previous>, series: &str) -> Vec<String> {
    let mut lines = Vec::new();
    if previous.is_none() {
        lines.push(format!(
            "carry: series {series} is not published, every package is new"
        ));
    }
    for (name, fate) in &plan.fates {
        lines.push(match fate {
            Fate::Carried {
                release, address, ..
            } => {
                let from = address
                    .rsplit_once('/')
                    .map_or(address.as_str(), |(d, _)| d);
                format!("carried {name} -{release} from {from}")
            }
            Fate::Built { release, why } => format!("built {name} -{release} ({why})"),
        });
    }
    for name in &plan.leaving {
        lines.push(format!("carry: {name} leaves the series"));
    }
    lines
}

/// `--previous` for a directory or an address: the roots to verify with are
/// the official ones, and for a directory also the development root.
pub fn roots_for(base: &str, tree: &Path) -> Result<Vec<Key>, String> {
    let mut roots = crate::keys::official_roots()?;
    if !base.starts_with("https://") {
        roots.push(crate::keys::dev_keys(tree)?.root);
    }
    Ok(roots)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use pkgfmt::cert::{Certificate, PURPOSE_PACKAGES};
    use pkgfmt::container::write::{Content, Item, container, sign};
    use pkgfmt::index::{self, Entry, Header};
    use pkgfmt::meta::Meta;
    use pkgfmt::{Name, sig};
    use std::path::PathBuf;

    const ROOT: [u8; 32] = [3; 32];
    const RELEASE: [u8; 32] = [4; 32];

    fn n(s: &str) -> Name {
        Name::new(s).unwrap()
    }

    fn root() -> Key {
        Key {
            name: n("t-root"),
            public: sig::public_key(&ROOT),
        }
    }

    fn hex(data: &[u8]) -> String {
        let mut buf = [0u8; 64];
        sha::hex(&sha::sha256(data), &mut buf).to_string()
    }

    fn package(name: &str, version: &str, release: &str, recipe: &str, key: &str) -> Vec<u8> {
        package_with(name, version, release, recipe, &RELEASE, key, &ROOT)
    }

    /// A package signed by `key` (seed `seed`) with a certificate of `t-root`
    /// (seed `root_seed`).
    pub(crate) fn package_with(
        name: &str,
        version: &str,
        release: &str,
        recipe: &str,
        seed: &[u8; 32],
        key: &str,
        root_seed: &[u8; 32],
    ) -> Vec<u8> {
        let cert = Certificate::issue(
            root_seed,
            n("t-root"),
            n(key),
            sig::public_key(seed),
            PURPOSE_PACKAGES,
            0,
            4_000_000_000,
        );
        let dir_name = format!("/usr/share/licenses/{name}");
        let dirs = [
            "/usr",
            "/usr/share",
            "/usr/share/licenses",
            dir_name.as_str(),
        ];
        let items: Vec<Item<'_>> = dirs
            .iter()
            .map(|path| Item {
                path,
                mode: 0o040755,
                content: Content::Directory,
            })
            .collect();
        let meta = Meta {
            name,
            version,
            release,
            arch: "aarch64",
            series: "0.2",
            license: "MIT",
            depends: "-",
            provides: "-",
            needs: "-",
            summary: "A demonstration",
            url: "https://example.org/demo.tar.gz",
            sha256: &"ab".repeat(32),
            recipe,
            commit: &"c".repeat(40),
            relibc: "-",
            size: 0,
        };
        sign(
            container(&meta, &items, 0).unwrap(),
            seed,
            n(key),
            Some(cert.to_bytes()),
            1000,
        )
        .unwrap()
    }

    /// A repository of `(name, version, release, recipe, key)` in a
    /// directory, with an empty list of revocations (or `revoked`).
    fn repository(
        tag: &str,
        rows: &[(&str, &str, &str, &str, &str)],
        revoked_keys: &[(&str, u64)],
    ) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("stafeto-carry-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut files = Vec::new();
        for (name, version, release, recipe, key) in rows {
            let bytes = package(name, version, release, recipe, key);
            let file = format!("{name}-{version}-{release}.stpkg");
            std::fs::write(dir.join(&file), &bytes).unwrap();
            files.push((
                name.to_string(),
                format!("{version}-{release}"),
                recipe.to_string(),
                file,
                bytes,
            ));
        }
        let digests: Vec<String> = files.iter().map(|f| hex(&f.4)).collect();
        let entries: Vec<Entry<'_>> = files
            .iter()
            .zip(&digests)
            .map(|(f, d)| Entry {
                name: &f.0,
                version: &f.1,
                provides: None,
                depends: None,
                needs: None,
                license: "MIT",
                size: f.4.len() as u64,
                sha256: d,
                recipe: &f.2,
                file: &f.3,
                source: None,
                summary: "A demonstration",
            })
            .collect();
        let header = Header {
            repository: "stafeto",
            series: "0.2",
            arch: "aarch64",
            serial: 7,
            expires: 5000,
        };
        let text = index::write(&header, &entries).unwrap();
        let block = Block::sign(
            &RELEASE,
            Kind::Index,
            text.len() as u64,
            sha::sha256(text.as_bytes()),
            1000,
            n("t-release"),
            Some(
                Certificate::issue(
                    &ROOT,
                    n("t-root"),
                    n("t-release"),
                    sig::public_key(&RELEASE),
                    PURPOSE_PACKAGES,
                    0,
                    4_000_000_000,
                )
                .to_bytes(),
            ),
        );
        std::fs::write(dir.join("INDEX"), &text).unwrap();
        std::fs::write(dir.join("INDEX.sig"), block.to_bytes()).unwrap();
        let revocations: Vec<Revocation> = revoked_keys
            .iter()
            .map(|(k, since)| Revocation {
                name: n(k),
                since: *since,
            })
            .collect();
        let list = revoked::write(1, &revocations).unwrap();
        let rblock = Block::sign(
            &ROOT,
            Kind::Revoked,
            list.len() as u64,
            sha::sha256(list.as_bytes()),
            1000,
            n("t-root"),
            None,
        );
        std::fs::write(dir.join("revoked"), &list).unwrap();
        std::fs::write(dir.join("revoked.sig"), rblock.to_bytes()).unwrap();
        dir
    }

    fn base(dir: &Path) -> String {
        dir.display().to_string()
    }

    fn wanted<'a>(rows: &[(&'a str, &'a str, &'a str)]) -> Vec<Wanted<'a>> {
        rows.iter()
            .map(|(name, version, recipe)| Wanted {
                name,
                version,
                recipe,
            })
            .collect()
    }

    #[test]
    fn unchanged_packages_are_carried_and_changed_ones_get_the_next_release() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let c = "c".repeat(64);
        let dir = repository(
            "plan",
            &[
                ("alpha", "1.0", "3", &a, "t-release"),
                ("beta", "2.0", "1", &b, "t-release"),
                ("gone", "1", "1", &a, "t-release"),
            ],
            &[],
        );
        let prev = load(&base(&dir), "0.2", &fetch, &[root()], &Policy::default())
            .unwrap()
            .unwrap();
        assert_eq!(prev.serial, 7);
        let want = wanted(&[
            ("alpha", "1.0", &a),
            ("beta", "2.0", &c),
            ("fresh", "1", &a),
        ]);
        let plan = plan(Some(&prev), &want, &fetch, &[root()]).unwrap();
        let alpha = std::fs::read(dir.join("alpha-1.0-3.stpkg")).unwrap();
        match &plan.fates["alpha"] {
            Fate::Carried {
                release,
                bytes,
                address,
                ..
            } => {
                assert_eq!(release, "3");
                assert_eq!(bytes, &alpha);
                // The index came from a directory: the entry keeps its own field.
                assert_eq!(address, "alpha-1.0-3.stpkg");
            }
            other => panic!("{other:?}"),
        }
        // The recipe changed: the same version, the next release.
        assert_eq!(
            plan.fates["beta"],
            Fate::Built {
                release: "2".into(),
                why: "recipe changed"
            }
        );
        assert_eq!(
            plan.fates["fresh"],
            Fate::Built {
                release: "1".into(),
                why: "new"
            }
        );
        assert_eq!(plan.leaving, ["gone"]);
        let lines = describe(&plan, Some(&prev), "0.2");
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("carried alpha -3 from "))
        );
        assert!(lines.contains(&"built beta -2 (recipe changed)".to_string()));
        assert!(lines.contains(&"carry: gone leaves the series".to_string()));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_new_version_starts_at_release_1_and_the_version_alone_does_not_carry() {
        let a = "a".repeat(64);
        let dir = repository("version", &[("alpha", "1.0", "4", &a, "t-release")], &[]);
        let prev = load(&base(&dir), "0.2", &fetch, &[root()], &Policy::default())
            .unwrap()
            .unwrap();
        // The same recipe with another version: not carried (the version is
        // part of what the file says), release 1.
        let p = plan(
            Some(&prev),
            &wanted(&[("alpha", "1.1", &a)]),
            &fetch,
            &[root()],
        )
        .unwrap();
        assert_eq!(
            p.fates["alpha"],
            Fate::Built {
                release: "1".into(),
                why: "recipe changed"
            }
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn no_index_means_everything_is_new_and_any_other_failure_stops() {
        let dir = std::env::temp_dir().join(format!("stafeto-carry-none-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(
            load(&base(&dir), "0.2", &fetch, &[root()], &Policy::default())
                .unwrap()
                .is_none()
        );
        let a = "a".repeat(64);
        let p = plan(None, &wanted(&[("alpha", "1", &a)]), &fetch, &[root()]).unwrap();
        assert_eq!(
            p.fates["alpha"],
            Fate::Built {
                release: "1".into(),
                why: "new"
            }
        );
        assert!(
            describe(&p, None, "0.3")[0]
                .contains("series 0.3 is not published, every package is new")
        );
        // A refusal of the network is an error and means nothing about the series.
        let down =
            |_: &str| -> Result<Option<Vec<u8>>, String> { Err("connection refused".into()) };
        assert!(
            load(
                "https://example.org/p",
                "0.2",
                &down,
                &[root()],
                &Policy::default()
            )
            .unwrap_err()
            .contains("connection refused")
        );
        // So is a missing signature next to an index.
        let repo = repository("nosig", &[("alpha", "1", "1", &a, "t-release")], &[]);
        std::fs::remove_file(repo.join("INDEX.sig")).unwrap();
        assert!(
            load(&base(&repo), "0.2", &fetch, &[root()], &Policy::default())
                .unwrap_err()
                .contains("INDEX.sig")
        );
        std::fs::remove_dir_all(&repo).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_package_signed_by_a_revoked_key_is_built_again() {
        let a = "a".repeat(64);
        let dir = repository(
            "revoked",
            &[
                ("alpha", "1", "2", &a, "t-release"),
                ("beta", "1", "1", &a, "t-release"),
            ],
            &[("t-release", 500)],
        );
        // The index is signed at 1000 by the same key: the list refuses it.
        let err = load(&base(&dir), "0.2", &fetch, &[root()], &Policy::default()).unwrap_err();
        assert!(err.contains("INDEX.sig"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
        // A list that revokes the key from a later time than the index leaves the
        // index good and the packages signed after that time refused.
        let dir = repository(
            "late",
            &[("alpha", "1", "2", &a, "t-release")],
            &[("t-release", 1000)],
        );
        let err = load(&base(&dir), "0.2", &fetch, &[root()], &Policy::default()).unwrap_err();
        assert!(err.contains("INDEX.sig"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
        // The index was signed before `since` and stays valid; the package is
        // signed at the time the key falls. Build the repository, then rewrite
        // the list so that the package falls and the index does not.
        let dir = repository("split", &[("alpha", "1", "2", &a, "t-release")], &[]);
        let prev = load(&base(&dir), "0.2", &fetch, &[root()], &Policy::default())
            .unwrap()
            .unwrap();
        let mut prev = prev;
        prev.revocations = vec![Revocation {
            name: n("t-release"),
            since: 1000,
        }];
        let p = plan(
            Some(&prev),
            &wanted(&[("alpha", "1", &a)]),
            &fetch,
            &[root()],
        )
        .unwrap();
        assert_eq!(
            p.fates["alpha"],
            Fate::Built {
                release: "3".into(),
                why: "key revoked"
            }
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_damaged_file_or_a_foreign_root_stops_the_carry() {
        let a = "a".repeat(64);
        let dir = repository("damage", &[("alpha", "1", "1", &a, "t-release")], &[]);
        let other = Key {
            name: n("t-root"),
            public: sig::public_key(&[9; 32]),
        };
        assert!(load(&base(&dir), "0.2", &fetch, &[other], &Policy::default()).is_err());
        assert!(
            load(&base(&dir), "0.3", &fetch, &[root()], &Policy::default())
                .unwrap_err()
                .contains("this build is stafeto 0.3")
        );
        let prev = load(&base(&dir), "0.2", &fetch, &[root()], &Policy::default())
            .unwrap()
            .unwrap();
        let path = dir.join("alpha-1-1.stpkg");
        let mut bytes = std::fs::read(&path).unwrap();
        let at = bytes.len() / 2;
        bytes[at] ^= 1;
        std::fs::write(&path, &bytes).unwrap();
        let err = plan(
            Some(&prev),
            &wanted(&[("alpha", "1", &a)]),
            &fetch,
            &[root()],
        )
        .unwrap_err();
        assert!(err.contains("SHA-256 differs"), "{err}");
        std::fs::remove_file(&path).unwrap();
        let err = plan(
            Some(&prev),
            &wanted(&[("alpha", "1", &a)]),
            &fetch,
            &[root()],
        )
        .unwrap_err();
        assert!(err.contains("missing"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn addresses_resolve_against_the_index() {
        assert_eq!(
            address_of("https://h/p/0.3/aarch64", "a.stpkg"),
            "https://h/p/0.3/aarch64/a.stpkg"
        );
        assert_eq!(
            address_of("https://h/p/0.3/aarch64/", "a.stpkg"),
            "https://h/p/0.3/aarch64/a.stpkg"
        );
        assert_eq!(
            address_of("https://h/p", "https://other/x/a.stpkg"),
            "https://other/x/a.stpkg"
        );
        assert_eq!(address_of("/tmp/d", "a.stpkg"), "/tmp/d/a.stpkg");
    }

    #[test]
    fn the_releases_of_the_plan_are_given_to_the_descriptions() {
        set_releases(BTreeMap::from([("zzz-test".to_string(), "5".to_string())]));
        assert_eq!(release_of("zzz-test").as_deref(), Some("5"));
        assert_eq!(release_of("other"), None);
        set_releases(BTreeMap::new());
    }

    #[test]
    fn an_expired_index_an_older_serial_and_an_older_list_are_refused() {
        let a = "a".repeat(64);
        let dir = repository("policy", &[("alpha", "1", "1", &a, "t-release")], &[]);
        let ok = |p: &Policy| load(&base(&dir), "0.2", &fetch, &[root()], p);
        // The index expires at 5000 and has the serial 7, the list the serial 1.
        assert!(
            ok(&Policy {
                now: 4000,
                ..Policy::default()
            })
            .unwrap()
            .is_some()
        );
        let err = ok(&Policy {
            now: 6000,
            ..Policy::default()
        })
        .unwrap_err();
        assert!(err.contains("expired"), "{err}");
        let err = ok(&Policy {
            min_serial: 8,
            ..Policy::default()
        })
        .unwrap_err();
        assert!(err.contains("older than the 8"), "{err}");
        assert!(
            ok(&Policy {
                min_serial: 7,
                ..Policy::default()
            })
            .is_ok()
        );
        let err = ok(&Policy {
            tree_list: Some((2, Vec::new())),
            ..Policy::default()
        })
        .unwrap_err();
        assert!(err.contains("older than serial 2 of keys/revoked"), "{err}");
        // The entries of the list of the tree count: the index is signed at 1000.
        let revoked = vec![Revocation {
            name: n("t-release"),
            since: 500,
        }];
        let err = ok(&Policy {
            tree_list: Some((1, revoked)),
            ..Policy::default()
        })
        .unwrap_err();
        assert!(err.contains("INDEX.sig"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_signed_copy_of_a_release_carries_after_its_key_is_revoked_and_its_term_has_run_out() {
        let a = "a".repeat(64);
        let dir = repository("anchored", &[("alpha", "1", "1", &a, "t-release")], &[]);
        let leak = Policy {
            now: 6000,
            min_serial: 8,
            tree_list: Some((
                1,
                vec![Revocation {
                    name: n("t-release"),
                    since: 500,
                }],
            )),
            ..Policy::default()
        };
        assert!(load(&base(&dir), "0.2", &fetch, &[root()], &leak).is_err());
        let anchored = Policy {
            anchored: true,
            ..leak
        };
        let previous = load(&base(&dir), "0.2", &fetch, &[root()], &anchored)
            .unwrap()
            .unwrap();
        assert_eq!(previous.entries.len(), 1);
        // The list still stands for the packages: one signed by the revoked key is built again.
        assert_eq!(previous.revocations.len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn no_index_for_a_frozen_series_is_a_failure() {
        let dir = std::env::temp_dir().join(format!("stafeto-carry-frozen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let frozen = Policy {
            frozen: true,
            ..Policy::default()
        };
        let err = load(&base(&dir), "0.2", &fetch, &[root()], &frozen).unwrap_err();
        assert!(err.contains("frozen"), "{err}");
        assert!(
            load(&base(&dir), "0.2", &fetch, &[root()], &Policy::default())
                .unwrap()
                .is_none()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
