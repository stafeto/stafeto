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
//! * The recipe is the fast path. When it differs and the version is the same,
//!   the package is still carried if what it installs equals what the file of
//!   the index installs: the manifest lines (without `SOURCE`) and the `meta`
//!   fields (without `recipe`, `commit`, `release` and `size`). Otherwise it is
//!   built, and the plan names the first path or field that differs.

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
    /// What the package would install; `None` when the package may not be
    /// carried by content (a variant for an image: `replace`, `remove`).
    pub content: Option<&'a Installed>,
}

/// The `meta` fields that stay out of the comparison of content: they change
/// with every build (`recipe`, `commit`, `release`) or hold the length of
/// `SOURCE` (`size`).
pub const META_VOLATILE: [&str; 4] = ["recipe", "commit", "release", "size"];

/// What a package installs: the lines of its `manifest` (without the line of
/// `SOURCE`) and its `meta` fields (without `META_VOLATILE`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Installed {
    /// `(path, line)` sorted by path.
    pub manifest: Vec<(String, String)>,
    /// `(key, value)` in the order of the file.
    pub meta: Vec<(&'static str, String)>,
}

/// One line of a manifest, as `pkgfmt::manifest::line` writes it (without the
/// newline).
fn manifest_text(e: &pkgfmt::manifest::ManifestEntry<'_>) -> String {
    let digest = match &e.sha256 {
        None => "-".to_string(),
        Some(d) => {
            let mut buf = [0u8; 64];
            sha::hex(d, &mut buf).to_string()
        }
    };
    format!(
        "{digest} {} {:06o} {} {}",
        e.size,
        e.mode,
        if e.elf { "elf" } else { "-" },
        e.path
    )
}

impl Installed {
    /// `meta` and the manifest lines `(path, line)`; the line of `SOURCE` is dropped.
    pub fn new(meta: &pkgfmt::meta::Meta<'_>, lines: Vec<(String, String)>) -> Installed {
        let source = format!("/usr/share/licenses/{}/SOURCE", meta.name);
        let mut manifest: Vec<(String, String)> = lines
            .into_iter()
            .filter(|(path, _)| *path != source)
            .collect();
        manifest.sort();
        let fields: [(&'static str, &str); 16] = [
            ("name", meta.name),
            ("version", meta.version),
            ("release", meta.release),
            ("arch", meta.arch),
            ("series", meta.series),
            ("license", meta.license),
            ("depends", meta.depends),
            ("provides", meta.provides),
            ("needs", meta.needs),
            ("summary", meta.summary),
            ("url", meta.url),
            ("sha256", meta.sha256),
            ("recipe", meta.recipe),
            ("commit", meta.commit),
            ("relibc", meta.relibc),
            ("size", ""),
        ];
        let meta = fields
            .into_iter()
            .filter(|(k, _)| !META_VOLATILE.contains(k))
            .map(|(k, v)| (k, v.to_string()))
            .collect();
        Installed { manifest, meta }
    }

    /// What the file of a package installs.
    pub fn of_file(file: &PackageFile<'_>) -> Installed {
        let lines = file
            .manifest
            .entries()
            .map(|e| (e.path.to_string(), manifest_text(&e)))
            .collect();
        Installed::new(&file.meta, lines)
    }

    /// The first difference from `old`: a path of the manifest (in the order
    /// of the paths) or else a field of `meta`; `None` when the content is equal.
    pub fn first_difference(&self, old: &Installed) -> Option<String> {
        self.differences(old).into_iter().next()
    }

    /// Every difference from `old`: the paths of the manifest in the order of
    /// the paths, then the fields of `meta` (`meta <key>`).
    pub fn differences(&self, old: &Installed) -> Vec<String> {
        let mut found = Vec::new();
        let mut new_it = self.manifest.iter().peekable();
        let mut old_it = old.manifest.iter().peekable();
        loop {
            match (new_it.peek(), old_it.peek()) {
                (None, None) => break,
                (Some((p, _)), None) => {
                    found.push(format!("{p} (added)"));
                    new_it.next();
                }
                (None, Some((p, _))) => {
                    found.push(format!("{p} (removed)"));
                    old_it.next();
                }
                (Some((np, nl)), Some((op, ol))) => match np.cmp(op) {
                    std::cmp::Ordering::Less => {
                        found.push(format!("{np} (added)"));
                        new_it.next();
                    }
                    std::cmp::Ordering::Greater => {
                        found.push(format!("{op} (removed)"));
                        old_it.next();
                    }
                    std::cmp::Ordering::Equal => {
                        if nl != ol {
                            found.push(np.to_string());
                        }
                        new_it.next();
                        old_it.next();
                    }
                },
            }
        }
        for ((key, new), (_, old)) in self.meta.iter().zip(&old.meta) {
            if new != old {
                found.push(format!("meta {key}"));
            }
        }
        found
    }
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
        /// The recipe differs and the content is equal.
        same_content: bool,
        /// The recipe of the entry, which is also the one in the `meta` of the
        /// file: a carried package keeps it (even when the recipe of the tree
        /// differs), so that the next build compares the content again and
        /// the `meta` of the file still says what the index says.
        recipe: String,
    },
    Built {
        release: String,
        why: &'static str,
        /// The first path or field that differs, when the content was compared.
        diff: Option<String>,
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

/// The file of an entry of the index with its size and SHA-256 checked.
fn anchor_bytes(old: &PrevEntry, fetch: Fetch<'_>) -> Result<Vec<u8>, String> {
    let bytes = fetch(&old.fetch)?
        .ok_or_else(|| format!("{}: the file of {} is missing", old.fetch, old.name))?;
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
    Ok(bytes)
}

/// The `meta` of the file says what the entry of the index says.
fn check_anchor(
    file: &PackageFile<'_>,
    old: &PrevEntry,
    w: &Wanted<'_>,
    at: &str,
) -> Result<(), String> {
    let m = &file.meta;
    if m.name != w.name
        || m.version != w.version
        || m.release != old.release
        || m.recipe != old.recipe
    {
        return Err(format!(
            "{at}: the meta of the file differs from the entry of the index"
        ));
    }
    Ok(())
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
                    diff: None,
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
                    diff: None,
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
        let recipe_same = old.recipe == w.recipe;
        // The recipe is the fast path. A new version is built without a
        // look at the file; so is a new recipe of a package that may not be
        // carried by content.
        let content = if recipe_same { None } else { w.content };
        if !same_version || (!recipe_same && content.is_none()) {
            fates.insert(
                w.name.to_string(),
                Fate::Built {
                    release: next_release(),
                    why: "recipe changed",
                    diff: None,
                },
            );
            continue;
        }
        let bytes = anchor_bytes(old, fetch)?;
        let file = PackageFile::parse(&bytes).map_err(|e| format!("{}: {e}", old.fetch))?;
        check_anchor(&file, old, w, &old.fetch)?;
        match file.verify(&trust, &prev.revocations) {
            Ok(_) => {
                let diff = content.and_then(|c| c.first_difference(&Installed::of_file(&file)));
                if let Some(diff) = diff {
                    fates.insert(
                        w.name.to_string(),
                        Fate::Built {
                            release: next_release(),
                            why: "content changed",
                            diff: Some(diff),
                        },
                    );
                } else {
                    fates.insert(
                        w.name.to_string(),
                        Fate::Carried {
                            release: old.release.clone(),
                            bytes,
                            address: old.file.clone(),
                            source: old.source.clone(),
                            same_content: !recipe_same,
                            recipe: old.recipe.clone(),
                        },
                    );
                }
            }
            Err(Error::Revoked) => {
                fates.insert(
                    w.name.to_string(),
                    Fate::Built {
                        release: next_release(),
                        why: "key revoked",
                        diff: None,
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
                release,
                address,
                same_content,
                ..
            } => {
                let from = address
                    .rsplit_once('/')
                    .map_or(address.as_str(), |(d, _)| d);
                let label = if *same_content {
                    "carried, same content"
                } else {
                    "carried"
                };
                format!("{label} {name} -{release} from {from}")
            }
            Fate::Built { release, why, diff } => match diff {
                Some(d) => format!("built {name} -{release} ({why}: first difference {d})"),
                None => format!("built {name} -{release} ({why})"),
            },
        });
    }
    for name in &plan.leaving {
        lines.push(format!("carry: {name} leaves the series"));
    }
    lines
}

/// Whether `new` is a lower version than `old`, both being numbers separated
/// by dots (`1.30.7`). A version of another shape (a commit, a date with
/// letters) is never called lower: changing it needs a changed recipe, which
/// a built package has anyway.
pub fn version_lowers(new: &str, old: &str) -> bool {
    let numbers =
        |v: &str| -> Option<Vec<u64>> { v.split('.').map(|p| p.parse::<u64>().ok()).collect() };
    match (numbers(new), numbers(old)) {
        (Some(new), Some(old)) => new < old,
        _ => false,
    }
}

/// The `relibc` field of the `meta` of each carried package that has programs
/// (`-` is a package without any).
pub fn carried_relibc(plan: &Plan) -> Result<BTreeMap<String, String>, String> {
    let mut found = BTreeMap::new();
    for (name, fate) in &plan.fates {
        if let Fate::Carried { bytes, .. } = fate {
            let file = PackageFile::parse(bytes).map_err(|e| format!("{name}: {e}"))?;
            if file.meta.relibc != "-" {
                found.insert(name.clone(), file.meta.relibc.to_string());
            }
        }
    }
    Ok(found)
}

/// What a packages-only update refuses (docs/release.md), one line each; an
/// empty list lets the update go on. `is_base` tells a package of kind base,
/// `pin` is the `relibc` field the tree gives to a package with programs
/// (`pin-<8 hex digits>`) and `carried` the same field of the carried packages.
pub fn packages_only_refusals(
    plan: &Plan,
    previous: &Previous,
    wanted: &[Wanted<'_>],
    is_base: &dyn Fn(&str) -> bool,
    pin: &str,
    carried: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut lines = Vec::new();
    let built: Vec<(&String, &Fate)> = plan
        .fates
        .iter()
        .filter(|(_, f)| matches!(f, Fate::Built { .. }))
        .collect();
    if built.is_empty() {
        lines.push("no package is built: there is nothing to update".to_string());
    }
    for (name, fate) in &built {
        let Fate::Built { why, diff, .. } = fate else {
            continue;
        };
        let why = match diff {
            Some(d) => format!("{why}: first difference {d}"),
            None => why.to_string(),
        };
        if why == "new" {
            lines.push(format!(
                "{name} is new in the series: a package is added by a release of the system"
            ));
        }
        if is_base(name) {
            lines.push(format!(
                "{name} is a base package and would be built ({why}): base packages are in both images and pkg does not replace them; a drift of the tools (tool clang, pin relibc) belongs in a release of the system"
            ));
        }
        let old = previous.entries.iter().find(|e| e.name == **name);
        let new = wanted.iter().find(|w| w.name == name.as_str());
        if let (Some(old), Some(new)) = (old, new)
            && version_lowers(new.version, &old.version)
        {
            lines.push(format!(
                "{name} goes from {} down to {}: a package of a series never goes back; the next update raises the release or the version",
                old.version, new.version
            ));
        }
    }
    for name in &plan.leaving {
        lines.push(format!(
            "{name} leaves the series: a package is removed by a release of the system"
        ));
    }
    for (name, relibc) in carried {
        if relibc != pin {
            lines.push(format!(
                "{name} is carried with relibc {relibc} and the tree pins {pin}: a package links the relibc of its series"
            ));
        }
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
        package_files(
            name,
            version,
            release,
            recipe,
            seed,
            key,
            root_seed,
            &Shape::default(),
        )
    }

    /// What a test package holds beyond the directories of its licenses.
    pub(crate) struct Shape<'a> {
        pub files: Vec<(&'a str, &'a [u8])>,
        pub source: Option<&'a [u8]>,
        pub license: &'a str,
        pub depends: &'a str,
        pub relibc: &'a str,
        pub commit: &'a str,
    }

    impl Default for Shape<'_> {
        fn default() -> Self {
            Shape {
                files: Vec::new(),
                source: None,
                license: "MIT",
                depends: "-",
                relibc: "-",
                commit: "cccccccccccccccccccccccccccccccccccccccc",
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn package_files(
        name: &str,
        version: &str,
        release: &str,
        recipe: &str,
        seed: &[u8; 32],
        key: &str,
        root_seed: &[u8; 32],
        shape: &Shape<'_>,
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
            "/usr/bin",
            "/usr/share",
            "/usr/share/licenses",
            dir_name.as_str(),
        ];
        let source_path = format!("{dir_name}/SOURCE");
        let mut items: Vec<Item<'_>> = dirs
            .iter()
            .map(|path| Item {
                path,
                mode: 0o040755,
                content: Content::Directory,
            })
            .collect();
        for (path, bytes) in &shape.files {
            items.push(Item {
                path,
                mode: 0o100644,
                content: Content::Data(bytes),
            });
        }
        if let Some(bytes) = shape.source {
            items.push(Item {
                path: &source_path,
                mode: 0o100644,
                content: Content::Data(bytes),
            });
        }
        let meta = Meta {
            name,
            version,
            release,
            arch: "aarch64",
            series: "0.2",
            license: shape.license,
            depends: shape.depends,
            provides: "-",
            needs: "-",
            summary: "A demonstration",
            url: "https://example.org/demo.tar.gz",
            sha256: &"ab".repeat(32),
            recipe,
            commit: shape.commit,
            relibc: shape.relibc,
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
        let made: Vec<(&str, &str, &str, &str, Vec<u8>)> = rows
            .iter()
            .map(|(name, version, release, recipe, key)| {
                (
                    *name,
                    *version,
                    *release,
                    *recipe,
                    package(name, version, release, recipe, key),
                )
            })
            .collect();
        repository_of(tag, &made, revoked_keys)
    }

    /// The same with the files given.
    fn repository_of(
        tag: &str,
        rows: &[(&str, &str, &str, &str, Vec<u8>)],
        revoked_keys: &[(&str, u64)],
    ) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("stafeto-carry-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut files = Vec::new();
        for (name, version, release, recipe, bytes) in rows {
            let bytes = bytes.clone();
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
                content: None,
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
                why: "recipe changed",
                diff: None
            }
        );
        assert_eq!(
            plan.fates["fresh"],
            Fate::Built {
                release: "1".into(),
                why: "new",
                diff: None
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
                why: "recipe changed",
                diff: None
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
                why: "new",
                diff: None
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
                why: "key revoked",
                diff: None
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
    fn entry(name: &str, version: &str) -> PrevEntry {
        PrevEntry {
            name: name.into(),
            version: version.into(),
            release: "1".into(),
            recipe: "r".into(),
            file: format!("{name}.stpkg"),
            fetch: format!("{name}.stpkg"),
            source: None,
            size: 1,
            sha256: "s".into(),
        }
    }

    fn only(
        fates: &[(&str, Fate)],
        old: &[(&str, &str)],
        leaving: &[&str],
        wanted_rows: &[(&str, &str)],
        carried: &[(&str, &str)],
    ) -> Vec<String> {
        let plan = Plan {
            fates: fates
                .iter()
                .map(|(n, f)| {
                    let f = match f {
                        Fate::Built { release, why, diff } => Fate::Built {
                            release: release.clone(),
                            why,
                            diff: diff.clone(),
                        },
                        Fate::Carried { .. } => unreachable!(),
                    };
                    (n.to_string(), f)
                })
                .collect(),
            leaving: leaving.iter().map(|s| s.to_string()).collect(),
        };
        let previous = Previous {
            serial: 2,
            entries: old.iter().map(|(n, v)| entry(n, v)).collect(),
            revocations: Vec::new(),
        };
        let rows: Vec<(&str, &str, &str)> =
            wanted_rows.iter().map(|(n, v)| (*n, *v, "r")).collect();
        let carried = carried
            .iter()
            .map(|(n, r)| (n.to_string(), r.to_string()))
            .collect();
        packages_only_refusals(
            &plan,
            &previous,
            &wanted(&rows),
            &|n| n == "busybox",
            "pin-aaaaaaaa",
            &carried,
        )
    }

    fn built(why: &'static str) -> Fate {
        Fate::Built {
            release: "2".into(),
            why,
            diff: None,
        }
    }

    #[test]
    fn a_packages_only_update_goes_on_with_a_rebuilt_package_and_nothing_else_changed() {
        let none = only(
            &[("nginx", built("recipe changed"))],
            &[("nginx", "1.30.6"), ("curl", "8.0")],
            &[],
            &[("nginx", "1.30.7"), ("curl", "8.0")],
            &[("curl", "pin-aaaaaaaa")],
        );
        assert!(none.is_empty(), "{none:?}");
        // A key revoked is a reason to build again, and the same version is no downgrade.
        let revoked = only(
            &[("nginx", built("key revoked"))],
            &[("nginx", "1.30.7")],
            &[],
            &[("nginx", "1.30.7")],
            &[],
        );
        assert!(revoked.is_empty(), "{revoked:?}");
    }

    #[test]
    fn a_packages_only_update_with_nothing_built_is_refused() {
        let lines = only(&[], &[("nginx", "1")], &[], &[("nginx", "1")], &[]);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("nothing to update"));
    }

    #[test]
    fn a_packages_only_update_refuses_a_base_package() {
        let lines = only(
            &[
                ("busybox", built("recipe changed")),
                ("nginx", built("recipe changed")),
            ],
            &[("busybox", "1.37"), ("nginx", "1.30.6")],
            &[],
            &[("busybox", "1.37"), ("nginx", "1.30.7")],
            &[],
        );
        assert_eq!(lines.len(), 1);
        assert!(lines[0].starts_with("busybox is a base package"));
    }

    #[test]
    fn a_packages_only_update_refuses_a_package_that_is_new() {
        let lines = only(
            &[("nginx", built("recipe changed")), ("fresh", built("new"))],
            &[("nginx", "1.30.6")],
            &[],
            &[("nginx", "1.30.7"), ("fresh", "1")],
            &[],
        );
        assert_eq!(lines.len(), 1);
        assert!(lines[0].starts_with("fresh is new in the series"));
    }

    #[test]
    fn a_packages_only_update_refuses_a_package_that_leaves() {
        let lines = only(
            &[("nginx", built("recipe changed"))],
            &[("nginx", "1.30.6"), ("gone", "1")],
            &["gone"],
            &[("nginx", "1.30.7")],
            &[],
        );
        assert_eq!(lines.len(), 1);
        assert!(lines[0].starts_with("gone leaves the series"));
    }

    #[test]
    fn a_packages_only_update_refuses_a_lower_version() {
        let lines = only(
            &[("nginx", built("recipe changed"))],
            &[("nginx", "1.30.7")],
            &[],
            &[("nginx", "1.30.6")],
            &[],
        );
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("down to 1.30.6"));
        assert!(version_lowers("1.9", "1.10"));
        assert!(version_lowers("1.30.6", "1.30.7"));
        assert!(!version_lowers("1.30.7", "1.30.7"));
        assert!(!version_lowers("1.31", "1.30.9"));
        // The version of a commit changes with the recipe and is no number.
        assert!(!version_lowers("e257a095", "f00ba4aa"));
        assert!(!version_lowers("1.0", "e257a095"));
    }

    #[test]
    fn a_packages_only_update_refuses_a_carried_package_with_another_relibc() {
        let lines = only(
            &[("nginx", built("recipe changed"))],
            &[("nginx", "1.30.6"), ("curl", "8.0")],
            &[],
            &[("nginx", "1.30.7"), ("curl", "8.0")],
            &[("curl", "pin-bbbbbbbb")],
        );
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("curl is carried with relibc pin-bbbbbbbb"));
    }

    #[test]
    fn every_refusal_gets_its_own_line() {
        let lines = only(
            &[("busybox", built("recipe changed"))],
            &[("busybox", "1.37"), ("gone", "1"), ("curl", "8")],
            &["gone"],
            &[("busybox", "1.36")],
            &[("curl", "pin-bbbbbbbb")],
        );
        assert_eq!(lines.len(), 4, "{lines:?}");
    }

    #[test]
    fn the_relibc_of_a_carried_package_is_read_from_its_meta() {
        let dir = repository(
            "relibc",
            &[("alpha", "1.0", "1", &"a".repeat(64), "t-release")],
            &[],
        );
        let prev = load(&base(&dir), "0.2", &fetch, &[root()], &Policy::default())
            .unwrap()
            .unwrap();
        let recipe = "a".repeat(64);
        let want = wanted(&[("alpha", "1.0", &recipe)]);
        let plan = plan(Some(&prev), &want, &fetch, &[root()]).unwrap();
        // The synthetic package has no programs: no relibc, nothing to compare.
        assert!(carried_relibc(&plan).unwrap().is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // ---- carrying by content ----

    fn pk(name: &str, version: &str, release: &str, recipe: &str, shape: &Shape<'_>) -> Vec<u8> {
        package_files(
            name,
            version,
            release,
            recipe,
            &RELEASE,
            "t-release",
            &ROOT,
            shape,
        )
    }

    /// The anchor repository holds `alpha-1.0-3` made from `old`; the tree
    /// wants `version` with `new_recipe` and what `new` installs.
    fn scenario(
        tag: &str,
        old: &Shape<'_>,
        new: &Shape<'_>,
        version: &str,
        key_revoked: bool,
    ) -> (Plan, Previous, PathBuf, Vec<u8>) {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let anchor = pk("alpha", "1.0", "3", &a, old);
        // A directory of its own: the tests run in parallel, and the tags of
        // the older tests (`relibc`, `plan`) must not meet these.
        let dir = repository_of(
            &format!("scenario-{tag}"),
            &[("alpha", "1.0", "3", &a, anchor.clone())],
            if key_revoked {
                &[("t-release", 0)]
            } else {
                &[]
            },
        );
        let policy = Policy {
            anchored: key_revoked,
            ..Policy::default()
        };
        let prev = load(&base(&dir), "0.2", &fetch, &[root()], &policy)
            .unwrap()
            .unwrap();
        // The candidate: the version of the tree, another recipe and release.
        let candidate = pk("alpha", version, "9", &b, new);
        let file = PackageFile::parse(&candidate).unwrap();
        let content = Installed::of_file(&file);
        let want = [Wanted {
            name: "alpha",
            version,
            recipe: &b,
            content: Some(&content),
        }];
        let plan = plan(Some(&prev), &want, &fetch, &[root()]).unwrap();
        (plan, prev, dir, anchor)
    }

    fn data_shape<'a>(byte: &'a [u8], source: &'a [u8]) -> Shape<'a> {
        Shape {
            files: vec![
                ("/usr/bin/alpha", byte),
                ("/usr/share/licenses/alpha/COPYING", b"mit"),
            ],
            source: Some(source),
            ..Shape::default()
        }
    }

    #[test]
    fn a_new_recipe_with_the_same_content_is_carried_with_the_file_of_the_anchor() {
        // Another SOURCE text (commit, release, recipe in it) and another commit.
        let old = data_shape(b"\x7fELF one", b"source of release 3");
        let new = Shape {
            commit: "dddddddddddddddddddddddddddddddddddddddd",
            ..data_shape(b"\x7fELF one", b"source of the new commit")
        };
        let (plan, prev, dir, anchor) = scenario("same-content", &old, &new, "1.0", false);
        match &plan.fates["alpha"] {
            Fate::Carried {
                release,
                bytes,
                address,
                same_content,
                recipe,
                ..
            } => {
                assert_eq!(release, "3");
                // Rule 3: the entry of the next index keeps the recipe of the
                // anchor, which the file says in its meta.
                assert_eq!(recipe, &"a".repeat(64));
                assert_ne!(recipe, &"b".repeat(64));
                let file = PackageFile::parse(bytes).unwrap();
                assert_eq!(file.meta.recipe, recipe.as_str());
                assert_eq!(bytes, &anchor);
                assert_eq!(address, "alpha-1.0-3.stpkg");
                assert!(same_content);
            }
            other => panic!("{other:?}"),
        }
        let lines = describe(&plan, Some(&prev), "0.2");
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].starts_with("carried, same content alpha -3 from "),
            "{lines:?}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_recipe_is_the_first_path_and_needs_no_content() {
        // The same recipe carries even when the candidate differs in everything.
        let a = "a".repeat(64);
        let anchor = pk("alpha", "1.0", "3", &a, &data_shape(b"one", b"s"));
        let dir = repository_of("recipe-first", &[("alpha", "1.0", "3", &a, anchor)], &[]);
        let prev = load(&base(&dir), "0.2", &fetch, &[root()], &Policy::default())
            .unwrap()
            .unwrap();
        let other = Installed {
            manifest: vec![("/x".into(), "line".into())],
            meta: Vec::new(),
        };
        let want = [Wanted {
            name: "alpha",
            version: "1.0",
            recipe: &a,
            content: Some(&other),
        }];
        let p = plan(Some(&prev), &want, &fetch, &[root()]).unwrap();
        assert!(matches!(
            p.fates["alpha"],
            Fate::Carried {
                same_content: false,
                ..
            }
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn one_byte_of_a_program_builds_the_package_again_and_names_the_path() {
        let old = data_shape(b"\x7fELF one", b"s");
        let new = data_shape(b"\x7fELF two", b"s");
        let (plan, prev, dir, _) = scenario("byte", &old, &new, "1.0", false);
        assert_eq!(
            plan.fates["alpha"],
            Fate::Built {
                release: "4".into(),
                why: "content changed",
                diff: Some("/usr/bin/alpha".into())
            }
        );
        let lines = describe(&plan, Some(&prev), "0.2");
        assert_eq!(
            lines,
            ["built alpha -4 (content changed: first difference /usr/bin/alpha)"]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_added_or_a_removed_file_builds_the_package_again() {
        let old = data_shape(b"one", b"s");
        let mut more = data_shape(b"one", b"s");
        more.files.push(("/usr/bin/zeta", b"z"));
        let (plan, _, dir, _) = scenario("added", &old, &more, "1.0", false);
        assert!(matches!(
            &plan.fates["alpha"],
            Fate::Built { diff: Some(d), .. } if d == "/usr/bin/zeta (added)"
        ));
        std::fs::remove_dir_all(&dir).unwrap();
        let mut fewer = data_shape(b"one", b"s");
        fewer.files.remove(1);
        let (plan, _, dir, _) = scenario("removed", &old, &fewer, "1.0", false);
        assert!(matches!(
            &plan.fates["alpha"],
            Fate::Built { diff: Some(d), .. }
                if d == "/usr/share/licenses/alpha/COPYING (removed)"
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn another_depends_or_license_or_relibc_builds_the_package_again() {
        let old = data_shape(b"one", b"s");
        let depends = Shape {
            depends: "beta",
            ..data_shape(b"one", b"s")
        };
        let license = Shape {
            license: "GPL-2.0-only",
            ..data_shape(b"one", b"s")
        };
        let relibc = Shape {
            relibc: "pin-aaaaaaaa",
            ..data_shape(b"one", b"s")
        };
        for (tag, new, field) in [
            ("depends", depends, "meta depends"),
            ("license", license, "meta license"),
            ("relibc", relibc, "meta relibc"),
        ] {
            let (plan, _, dir, _) = scenario(tag, &old, &new, "1.0", false);
            assert!(
                matches!(&plan.fates["alpha"], Fate::Built { release, diff: Some(d), .. }
                    if release == "4" && d == field),
                "{tag}: {:?}",
                plan.fates["alpha"]
            );
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    #[test]
    fn another_version_is_built_without_a_comparison() {
        let shape = data_shape(b"one", b"s");
        let (plan, _, dir, _) = scenario("version-content", &shape, &shape, "1.1", false);
        assert_eq!(
            plan.fates["alpha"],
            Fate::Built {
                release: "1".into(),
                why: "recipe changed",
                diff: None
            }
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_package_without_content_is_not_carried_by_content() {
        // A variant for an image: the tree gives no content.
        let a = "a".repeat(64);
        let anchor = pk("alpha", "1.0", "3", &a, &data_shape(b"one", b"s"));
        let dir = repository_of("variant", &[("alpha", "1.0", "3", &a, anchor)], &[]);
        let prev = load(&base(&dir), "0.2", &fetch, &[root()], &Policy::default())
            .unwrap()
            .unwrap();
        let b = "b".repeat(64);
        let p = plan(
            Some(&prev),
            &wanted(&[("alpha", "1.0", &b)]),
            &fetch,
            &[root()],
        )
        .unwrap();
        assert_eq!(
            p.fates["alpha"],
            Fate::Built {
                release: "4".into(),
                why: "recipe changed",
                diff: None
            }
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_revoked_key_builds_the_package_again_even_when_the_content_is_equal() {
        let shape = data_shape(b"one", b"s");
        let (plan, _, dir, _) = scenario("revoked-content", &shape, &shape, "1.0", true);
        assert_eq!(
            plan.fates["alpha"],
            Fate::Built {
                release: "4".into(),
                why: "key revoked",
                diff: None
            }
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_damaged_file_of_the_anchor_stops_the_comparison() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let shape = data_shape(b"one", b"s");
        let anchor = pk("alpha", "1.0", "3", &a, &shape);
        let dir = repository_of("damaged-content", &[("alpha", "1.0", "3", &a, anchor)], &[]);
        let prev = load(&base(&dir), "0.2", &fetch, &[root()], &Policy::default())
            .unwrap()
            .unwrap();
        let path = dir.join("alpha-1.0-3.stpkg");
        let mut bytes = std::fs::read(&path).unwrap();
        let at = bytes.len() / 2;
        bytes[at] ^= 1;
        std::fs::write(&path, &bytes).unwrap();
        let candidate = pk("alpha", "1.0", "9", &b, &shape);
        let content = Installed::of_file(&PackageFile::parse(&candidate).unwrap());
        let want = [Wanted {
            name: "alpha",
            version: "1.0",
            recipe: &b,
            content: Some(&content),
        }];
        let err = plan(Some(&prev), &want, &fetch, &[root()]).unwrap_err();
        assert!(err.contains("SHA-256"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn no_volatile_field_of_meta_counts_and_every_other_field_does() {
        let shape = data_shape(b"one", b"s");
        let bytes = pk("alpha", "1.0", "3", &"a".repeat(64), &shape);
        let file = PackageFile::parse(&bytes).unwrap();
        let old = Installed::of_file(&file);
        let hash: &'static str = Box::leak("e".repeat(64).into_boxed_str());
        let m = &file.meta;
        let make = |f: &dyn Fn(&mut pkgfmt::meta::Meta<'_>)| {
            let mut meta = pkgfmt::meta::Meta { ..*m };
            f(&mut meta);
            let lines = file
                .manifest
                .entries()
                .map(|e| (e.path.to_string(), manifest_text(&e)))
                .collect();
            Installed::new(&meta, lines)
        };
        // The four volatile fields.
        assert_eq!(make(&|x| x.recipe = hash).first_difference(&old), None);
        assert_eq!(
            make(&|x| x.commit = &hash[..40]).first_difference(&old),
            None
        );
        assert_eq!(make(&|x| x.release = "77").first_difference(&old), None);
        assert_eq!(make(&|x| x.size = 123_456).first_difference(&old), None);
        // Every other field.
        type Change<'c> = &'c dyn Fn(&mut pkgfmt::meta::Meta<'_>);
        let cases: [(&str, Change<'_>); 12] = [
            ("name", &|x| x.name = "other"),
            ("version", &|x| x.version = "2.0"),
            ("arch", &|x| x.arch = "x86_64"),
            ("series", &|x| x.series = "0.9"),
            ("license", &|x| x.license = "BSD-2-Clause"),
            ("depends", &|x| x.depends = "beta"),
            ("provides", &|x| x.provides = "beta"),
            ("needs", &|x| x.needs = "beta"),
            ("summary", &|x| x.summary = "Another"),
            ("url", &|x| x.url = "https://example.org/other.tar.gz"),
            ("sha256", &|x| x.sha256 = hash),
            ("relibc", &|x| x.relibc = "pin-12345678"),
        ];
        for (key, change) in cases {
            if key == "name" {
                // The name also moves the path of SOURCE, which comes first.
                assert!(make(change).first_difference(&old).is_some());
                continue;
            }
            assert_eq!(
                make(change).first_difference(&old),
                Some(format!("meta {key}")),
                "{key}"
            );
        }
    }

    #[test]
    fn the_line_of_source_never_counts() {
        let a = pk(
            "alpha",
            "1.0",
            "3",
            &"a".repeat(64),
            &data_shape(b"one", b"x"),
        );
        let b = pk(
            "alpha",
            "1.0",
            "3",
            &"a".repeat(64),
            &data_shape(b"one", b"much longer text"),
        );
        let (ca, cb) = (
            Installed::of_file(&PackageFile::parse(&a).unwrap()),
            Installed::of_file(&PackageFile::parse(&b).unwrap()),
        );
        assert_eq!(ca, cb);
        assert!(ca.manifest.iter().all(|(p, _)| !p.ends_with("/SOURCE")));
    }

    #[test]
    fn a_base_package_with_the_same_content_is_no_refusal_and_one_with_other_bytes_is() {
        let carried = |same_content| Fate::Carried {
            release: "1".into(),
            bytes: Vec::new(),
            address: "busybox.stpkg".into(),
            source: None,
            same_content,
            recipe: "r".into(),
        };
        let previous = Previous {
            serial: 2,
            entries: vec![entry("busybox", "1.37"), entry("nginx", "1.30.6")],
            revocations: Vec::new(),
        };
        let rows = [("busybox", "1.37", "r"), ("nginx", "1.30.7", "r")];
        let want = wanted(&rows);
        let nginx = Fate::Built {
            release: "2".into(),
            why: "recipe changed",
            diff: None,
        };
        let plan = Plan {
            fates: [
                ("busybox".to_string(), carried(true)),
                ("nginx".to_string(), nginx),
            ]
            .into_iter()
            .collect(),
            leaving: Vec::new(),
        };
        let lines = packages_only_refusals(
            &plan,
            &previous,
            &want,
            &|n| n == "busybox",
            "pin-aaaaaaaa",
            &BTreeMap::new(),
        );
        assert!(lines.is_empty(), "{lines:?}");
        let plan = Plan {
            fates: [(
                "busybox".to_string(),
                Fate::Built {
                    release: "2".into(),
                    why: "content changed",
                    diff: Some("/bin/busybox".into()),
                },
            )]
            .into_iter()
            .collect(),
            leaving: Vec::new(),
        };
        let lines = packages_only_refusals(
            &plan,
            &previous,
            &want,
            &|n| n == "busybox",
            "pin-aaaaaaaa",
            &BTreeMap::new(),
        );
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("first difference /bin/busybox"));
    }
}
