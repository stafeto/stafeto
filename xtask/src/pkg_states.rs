// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The states of the repositories of `cargo xtask pkg-probe` (pk4-design R17): directories
//! under `target/pkg-probe/states/` that the mirror serves one at a time, the official
//! repository in eight of them and the repository `games` in one. The numbers are the
//! `serial` of each index.
//!
//! | State | What it holds |
//! |---|---|
//! | `good` (2) | `doomgeneric`, `freedoom`, `hello` 1.0 (exit 42), `app` (needs `lib`), `lib` |
//! | `tampered` (2) | the same `INDEX` byte for byte, one byte of the file of `hello` changed |
//! | `long` (2) | the same `INDEX`, the file of `hello` a page longer than the entry says |
//! | `old` (1) | a good index with a smaller number |
//! | `expired` (3) | a good signature, `expires` half a minute ago |
//! | `foreign` (4) | `good` and `alien`, a package signed by a key nobody trusts |
//! | `next` (5) | `good`, but `hello` 2.0 |
//! | `stolen` (6) | `next`, signed by the key of the repository `games` |
//! | `absolute` (7) | `next`, but the files of Doom are at full addresses in the `store` tree of the mirror (`/store/v0.0.0-aarch64/`), and the file of `doomgeneric` answers 302 to `/store/moved/` |
//!
//! `games` (serial 1, the key `games-1`): `hello-games` (exit 42) signed by that key and
//! `sneaky`, signed by the release key of the official repository, which `games` does not trust.
//! The index of every state is signed by the development release key (with the certificate of
//! the development root) except `stolen` and `games`, which the key of `games` signs.

use crate::store_probe::{self, Options, Signer, TINY};
use crate::{keys, pkg};
use pkgfmt::index::{self, Header, Index};
use pkgfmt::sig::{Block, Kind};
use pkgfmt::{Name, sha, sig};
use std::path::{Path, PathBuf};

const DAY: u64 = 86_400;
/// The seeds of the keys of the probe: `games` trusts its own, the guest is given the file of
/// `bad` for a repository whose server the guest does not trust.
pub const GAMES_SEED: u8 = 0x47;
pub const BAD_SEED: u8 = 0x42;
const ALIEN_SEED: u8 = 0x66;
pub const GAMES_KEY: &str = "games-1";
pub const BAD_KEY: &str = "bad-1";

/// A record of an index and the file that holds the package.
#[derive(Clone)]
struct Rec {
    name: String,
    version: String,
    depends: Option<String>,
    license: String,
    size: u64,
    sha256: String,
    file: String,
    summary: String,
    provides: Option<String>,
    needs: Option<String>,
    source: Option<String>,
    recipe: String,
    path: PathBuf,
}

/// What an index says of itself and who signs it.
struct Head<'a> {
    repository: &'a str,
    serial: u64,
    signed_at: u64,
    expires: u64,
    seed: [u8; 32],
    key: Name,
    certificate: Option<[u8; pkgfmt::cert::SIZE]>,
}

/// The directories of the states.
pub struct States {
    pub good: PathBuf,
    pub tampered: PathBuf,
    pub long: PathBuf,
    pub old: PathBuf,
    pub expired: PathBuf,
    pub foreign: PathBuf,
    pub next: PathBuf,
    pub stolen: PathBuf,
    pub absolute: PathBuf,
    pub games: PathBuf,
    /// The tree the mirror serves under `/store`: `v0.0.0-aarch64` and `moved`.
    pub store: PathBuf,
    /// The lines (`/from /to`) the mirror redirects by.
    pub redirects: String,
}

/// The directory of the storage of the state `absolute` under `/store`.
pub const STORAGE: &str = "v0.0.0-aarch64";

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn hex(bytes: &[u8]) -> String {
    let mut buf = [0u8; 64];
    sha::hex(&sha::sha256(bytes), &mut buf).to_string()
}

/// The records of the index of `dir`, each with the path of its file there.
fn records_of(dir: &Path) -> Result<Vec<Rec>, String> {
    let text = std::fs::read_to_string(dir.join("INDEX")).map_err(|e| e.to_string())?;
    let index = Index::parse(&text).map_err(|e| format!("INDEX: {e}"))?;
    Ok(index
        .entries()
        .map(|e| Rec {
            name: e.name.into(),
            version: e.version.into(),
            depends: e.depends.map(String::from),
            license: e.license.into(),
            size: e.size,
            sha256: e.sha256.into(),
            file: e.file.into(),
            summary: e.summary.into(),
            provides: e.provides.map(String::from),
            needs: e.needs.map(String::from),
            source: e.source.map(String::from),
            recipe: e.recipe.into(),
            path: dir.join(e.file),
        })
        .collect())
}

/// A record of a package file the probe made, kept in `files`.
fn record(
    files: &Path,
    name: &str,
    version: &str,
    depends: Option<&str>,
    bytes: &[u8],
) -> Result<Rec, String> {
    let file = format!("{name}-{version}-1.stpkg");
    let path = files.join(&file);
    std::fs::write(&path, bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(Rec {
        name: name.into(),
        version: format!("{version}-1"),
        depends: depends.map(String::from),
        license: "MIT".into(),
        size: bytes.len() as u64,
        sha256: hex(bytes),
        file,
        summary: "A package of the package probe".into(),
        provides: None,
        needs: None,
        source: None,
        recipe: "1".repeat(64),
        path,
    })
}

/// `dir` with the index of `recs` and its signature, the files linked to where they are kept, and
/// the list of revocations of `revoked` (the official repository's, which every state of it shares).
fn compose(
    dir: &Path,
    recs: &[Rec],
    head: &Head<'_>,
    revoked: Option<&Path>,
) -> Result<PathBuf, String> {
    if dir.exists() {
        std::fs::remove_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let entries: Vec<index::Entry<'_>> = recs
        .iter()
        .map(|r| index::Entry {
            name: &r.name,
            version: &r.version,
            provides: r.provides.as_deref(),
            depends: r.depends.as_deref(),
            needs: r.needs.as_deref(),
            license: &r.license,
            size: r.size,
            sha256: &r.sha256,
            recipe: &r.recipe,
            file: &r.file,
            source: r.source.as_deref(),
            summary: &r.summary,
        })
        .collect();
    let series = pkg::series();
    let text = index::write(
        &Header {
            repository: head.repository,
            series: &series,
            arch: "aarch64",
            serial: head.serial,
            expires: head.expires,
        },
        &entries,
    )
    .map_err(|e| format!("INDEX: {e}"))?;
    let block = Block::sign(
        &head.seed,
        Kind::Index,
        text.len() as u64,
        sha::sha256(text.as_bytes()),
        head.signed_at,
        head.key,
        head.certificate,
    );
    write(dir, "INDEX", text.as_bytes())?;
    write(dir, "INDEX.sig", &block.to_bytes())?;
    link_files(dir, recs)?;
    if let Some(from) = revoked {
        for name in ["revoked", "revoked.sig"] {
            let bytes = std::fs::read(from.join(name)).map_err(|e| format!("{name}: {e}"))?;
            write(dir, name, &bytes)?;
        }
    }
    Ok(dir.to_path_buf())
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(dir.join(name), bytes).map_err(|e| format!("{name}: {e}"))
}

fn link_files(dir: &Path, recs: &[Rec]) -> Result<(), String> {
    for r in recs {
        // A file at a full address is served from the store tree.
        if r.file.starts_with("https://") {
            continue;
        }
        let to = dir.join(&r.file);
        let _ = std::fs::remove_file(&to);
        std::os::unix::fs::symlink(&r.path, &to).map_err(|e| format!("{}: {e}", to.display()))?;
    }
    Ok(())
}

/// A state that has the index of `like` byte for byte and files of its own for `changed`.
fn copy_of(
    dir: &Path,
    like: &Path,
    recs: &[Rec],
    changed: &str,
    bytes: &[u8],
) -> Result<PathBuf, String> {
    if dir.exists() {
        std::fs::remove_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for name in ["INDEX", "INDEX.sig", "revoked", "revoked.sig"] {
        let from = std::fs::read(like.join(name)).map_err(|e| format!("{name}: {e}"))?;
        write(dir, name, &from)?;
    }
    let others: Vec<Rec> = recs.iter().filter(|r| r.name != changed).cloned().collect();
    link_files(dir, &others)?;
    let file = recs
        .iter()
        .find(|r| r.name == changed)
        .ok_or_else(|| format!("no record {changed}"))?;
    write(dir, &file.file, bytes)?;
    Ok(dir.to_path_buf())
}

/// The key of a repository of the probe: its name and its public key line.
pub fn key_file(name: &str, seed: u8) -> Result<String, String> {
    store_probe::repository_key(name, seed)
}

/// All the states, under `states/`. `doom` is the directory of a repository that holds the packages
/// of Doom (`repo::make`), whose files the states link.
pub fn make(states: &Path, doom: &Path, origin: &str) -> Result<States, String> {
    let dev = keys::dev_keys(&crate::root())?;
    let dev_signer = Signer {
        seed: &dev.release_seed,
        key: &dev.release,
        certificate: Some(dev.certificate),
    };
    let alien_seed = [ALIEN_SEED; 32];
    let alien_key = pkgfmt::Key {
        name: Name::new("alien-key").map_err(|e| e.to_string())?,
        public: sig::public_key(&alien_seed),
    };
    let alien_signer = Signer {
        seed: &alien_seed,
        key: &alien_key,
        certificate: None,
    };
    let games_seed = [GAMES_SEED; 32];
    let games_key = pkgfmt::Key {
        name: Name::new(GAMES_KEY).map_err(|e| e.to_string())?,
        public: sig::public_key(&games_seed),
    };
    let games_signer = Signer {
        seed: &games_seed,
        key: &games_key,
        certificate: None,
    };
    let hello_program = store_probe::hello_elf()?;
    let files = states.join("files");
    std::fs::create_dir_all(&files).map_err(|e| e.to_string())?;
    let version = |v: &str| Options {
        version: Some(v.into()),
        ..Options::default()
    };
    let make_record = |name: &str,
                       v: &str,
                       depends: Option<&str>,
                       program: &[u8],
                       signer: Signer<'_>|
     -> Result<Rec, String> {
        let options = Options {
            depends: depends.map(String::from),
            ..version(v)
        };
        let bytes = store_probe::package(name, program, signer, &[], &options)?;
        record(&files, name, v, depends, &bytes)
    };
    let hello1 = make_record("hello", "1.0", None, &hello_program, dev_signer)?;
    let hello2 = make_record("hello", "2.0", None, &hello_program, dev_signer)?;
    let app = make_record("app", "1.0", Some("lib"), TINY, dev_signer)?;
    let lib = make_record("lib", "1.0", None, TINY, dev_signer)?;
    let alien = make_record("alien", "1.0", None, TINY, alien_signer)?;
    let hello_games = make_record("hello-games", "1.0", None, &hello_program, games_signer)?;
    let sneaky = make_record("sneaky", "1.0", None, TINY, dev_signer)?;

    let doom_records = records_of(doom)?;
    let with = |extra: &[&Rec]| -> Vec<Rec> {
        let mut all = doom_records.clone();
        all.extend(extra.iter().map(|r| (*r).clone()));
        all
    };
    let t = now();
    let official = |serial: u64, signed_at: u64, expires: u64| Head {
        repository: "stafeto",
        serial,
        signed_at,
        expires,
        seed: dev.release_seed,
        key: dev.release.name,
        certificate: Some(dev.certificate),
    };
    let good_records = with(&[&hello1, &app, &lib]);
    let good = compose(
        &states.join("good"),
        &good_records,
        &official(2, t, t + 30 * DAY),
        Some(doom),
    )?;
    let hello_file = std::fs::read(&hello1.path).map_err(|e| e.to_string())?;
    let mut flipped = hello_file.clone();
    // A byte of the program, inside the covered part: the signature of the file is the old one
    // and the SHA-256 of the file is not the one of the index.
    let at = flipped
        .windows(4)
        .position(|w| w == b"\x7fELF")
        .ok_or("no program in hello")?
        + 24;
    flipped[at] ^= 1;
    let tampered = copy_of(
        &states.join("tampered"),
        &good,
        &good_records,
        "hello",
        &flipped,
    )?;
    let mut longer = hello_file;
    longer.extend_from_slice(&[0u8; 4096]);
    let long = copy_of(&states.join("long"), &good, &good_records, "hello", &longer)?;
    let old = compose(
        &states.join("old"),
        &good_records,
        &official(1, t, t + 30 * DAY),
        Some(doom),
    )?;
    let expired = compose(
        &states.join("expired"),
        &good_records,
        // Signed a minute ago (the certificate of the release key holds from the start of today)
        // and good until half a minute ago.
        &official(3, t - 60, t - 30),
        Some(doom),
    )?;
    let foreign = compose(
        &states.join("foreign"),
        &with(&[&hello1, &app, &lib, &alien]),
        &official(4, t, t + 30 * DAY),
        Some(doom),
    )?;
    let next_records = with(&[&hello2, &app, &lib]);
    let next = compose(
        &states.join("next"),
        &next_records,
        &official(5, t, t + 30 * DAY),
        Some(doom),
    )?;
    let stolen = compose(
        &states.join("stolen"),
        &next_records,
        &Head {
            repository: "stafeto",
            serial: 6,
            signed_at: t,
            expires: t + 30 * DAY,
            seed: games_seed,
            key: games_key.name,
            certificate: None,
        },
        Some(doom),
    )?;
    let games = compose(
        &states.join("games"),
        &[hello_games, sneaky],
        &Head {
            repository: "games",
            serial: 1,
            signed_at: t,
            expires: t + 30 * DAY,
            seed: games_seed,
            key: games_key.name,
            certificate: None,
        },
        None,
    )?;
    // The state `absolute`: the files of Doom at full addresses of the second directory of
    // the mirror, one of them (`doomgeneric`) behind a redirect to a third.
    let store = states.join("store");
    for sub in [STORAGE, "moved"] {
        let dir = store.join(sub);
        if dir.exists() {
            std::fs::remove_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let mut redirects = String::new();
    let mut absolute_records = Vec::new();
    for r in &next_records {
        let mut r = r.clone();
        if doom_records.iter().any(|d| d.name == r.name) {
            let place = if r.name == "doomgeneric" {
                redirects.push_str(&format!("/store/{STORAGE}/{0} /store/moved/{0}\n", r.file));
                "moved"
            } else {
                STORAGE
            };
            let to = store.join(place).join(&r.file);
            std::os::unix::fs::symlink(&r.path, &to)
                .map_err(|e| format!("{}: {e}", to.display()))?;
            r.file = format!("{origin}/store/{STORAGE}/{}", r.file);
        }
        absolute_records.push(r);
    }
    let absolute = compose(
        &states.join("absolute"),
        &absolute_records,
        &official(7, t, t + 30 * DAY),
        Some(doom),
    )?;
    Ok(States {
        absolute,
        store,
        redirects,
        good,
        tampered,
        long,
        old,
        expired,
        foreign,
        next,
        stolen,
        games,
    })
}
