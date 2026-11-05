// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The settings blob that `repo add`, `repo remove` and `repo save` send (pk4-design R5, R6):
//! the lines of `/etc/pkg/repositories` and the keys of the owner's repositories, kept as the
//! blob `STAFSET1` holds them. The rules are those of `config` and of the service
//! (services/pkgd/src/settings.rs), so a blob made here is one the service takes. Nothing
//! here reads a file or asks the service: the bytes come in and the bytes and the lines go out.
//!
//! A key is added only from a file the owner brings, never from the repository, and trusts
//! its own repository alone. A key is not changed and a repository is not removed while a
//! package installed from it stands: after a restart the service would check that package by
//! the new key or by none.

use crate::config::{self, Line, LineError, OFFICIAL, OWN_MAX, Rule};
use crate::output::Installed;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use pkgfmt::{Key, b64, keyfile, sha};
use proto_pkg::blob::{self, Blob};

const REPOSITORIES: &str = "repositories";
const KEYS: &str = "keys/";
const SUFFIX: &str = ".pub";

/// Why a command on the repositories is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The name is not 1 to 31 characters of `[a-z0-9-]`.
    Name(String),
    /// The name of the official repository.
    Official(String),
    /// An address that is not https.
    NotHttps(String),
    /// The file is not `ed25519 <base64> <name>`.
    Key(String),
    /// More repositories of the owner's than the store holds.
    TooMany,
    /// A package that stands installed from the repository.
    Installed { repository: String, package: String },
    /// No such repository of the owner's.
    Unknown(String),
}

impl Refusal {
    pub fn line(&self) -> String {
        match self {
            Refusal::Name(name) => {
                format!("pkg: {name}: a repository name is 1 to 31 characters of a-z, 0-9 and -")
            }
            Refusal::Official(name) => {
                format!("pkg: {name}: the name is the official repository's")
            }
            Refusal::NotHttps(address) => format!("pkg: {address}: not https"),
            Refusal::Key(file) => {
                format!("pkg: {file}: not a key file (ed25519 <base64 of 32 bytes> <name>)")
            }
            Refusal::TooMany => format!("pkg: more than {OWN_MAX} repositories"),
            Refusal::Installed {
                repository,
                package,
            } => format!("pkg: {repository}: {package} is installed from it; pkg remove it first"),
            Refusal::Unknown(name) => format!("pkg: {name}: no such repository"),
        }
    }
}

/// The settings: the owner's lines in their order and the keys by repository name.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Settings {
    pub lines: Vec<Line>,
    pub keys: Vec<(String, Key)>,
}

/// `SHA256:<base64 of the SHA-256 of the 32 bytes, without the padding>`, as OpenSSH writes the
/// fingerprint of a key.
pub fn fingerprint(key: &Key) -> String {
    let mut buf = [0u8; 44];
    let text = b64::encode(&sha::sha256(&key.public), &mut buf);
    format!("SHA256:{}", text.trim_end_matches('='))
}

/// The line `repo add` prints once a key is trusted.
pub fn added_line(name: &str, key: &Key) -> String {
    format!(
        "{name}: key {} {}, trusted for {name} only",
        key.name.as_str(),
        fingerprint(key)
    )
}

fn key_line(key: &Key) -> String {
    let mut buf = [0u8; 44];
    format!(
        "ed25519 {} {}\n",
        b64::encode(&key.public, &mut buf),
        key.name.as_str()
    )
}

/// The blob of `files`: the signature, the version, the count, then each file's name and bytes.
/// (`proto_pkg::blob::write` is for the host; the program has no use of the feature that holds it.)
fn blob_of(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&blob::MAGIC);
    out.extend_from_slice(&blob::VERSION.to_le_bytes());
    out.extend_from_slice(&(files.len() as u32).to_le_bytes());
    for (name, data) in files {
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(data);
    }
    out
}

fn name_ok(name: &str) -> bool {
    name.len() <= 31 && pkgfmt::Name::new(name).is_ok()
}

fn stem(file: &[u8]) -> Option<&str> {
    let text = core::str::from_utf8(file).ok()?;
    text.strip_prefix(KEYS)?.strip_suffix(SUFFIX)
}

impl Settings {
    /// The settings a blob holds; a blob that is empty or not a blob is no settings.
    pub fn from_blob(bytes: &[u8]) -> Result<Settings, LineError> {
        let Ok(blob) = Blob::parse(bytes) else {
            return Ok(Settings::default());
        };
        let mut settings = Settings::default();
        for f in blob.files() {
            if f.name == REPOSITORIES.as_bytes() {
                let text = core::str::from_utf8(f.data).map_err(|_| LineError {
                    line: 1,
                    rule: Rule::Shape,
                })?;
                settings.lines = config::parse_repositories(text)?;
            } else if let Some(name) = stem(f.name)
                && let Some(key) = config::key_from_file(f.data)
            {
                settings.keys.push((name.to_string(), key));
            }
        }
        Ok(settings)
    }

    /// The text of `repositories`; empty when the owner has no line.
    pub fn repositories(&self) -> String {
        let mut text = String::new();
        for line in &self.lines {
            match line {
                Line::Add { name, address } => text.push_str(&format!("{name} {address}\n")),
                Line::Disable { name } => text.push_str(&format!("disable {name}\n")),
            }
        }
        text
    }

    /// The blob: `repositories` when there is a line, then the key files. No file at all is a
    /// blob of no files, which the service takes and which shows nothing at `/etc/pkg`.
    pub fn to_blob(&self) -> Vec<u8> {
        let text = self.repositories();
        let keys: Vec<(String, String)> = self
            .keys
            .iter()
            .map(|(name, key)| (format!("{KEYS}{name}{SUFFIX}"), key_line(key)))
            .collect();
        let mut files: Vec<(&str, &[u8])> = Vec::new();
        if !text.is_empty() {
            files.push((REPOSITORIES, text.as_bytes()));
        }
        for (name, data) in &keys {
            files.push((name, data.as_bytes()));
        }
        blob_of(&files)
    }

    fn key_of(&self, name: &str) -> Option<&Key> {
        self.keys.iter().find(|(n, _)| n == name).map(|(_, k)| k)
    }

    fn own_count(&self) -> usize {
        self.lines
            .iter()
            .filter(|l| matches!(l, Line::Add { .. }))
            .count()
    }

    /// `repo add <name> <address> <key file>`: the key of `key_file` (its text) trusts `name`
    /// alone. An existing repository gets the address and the key; a new key while a package
    /// stands installed from it is refused.
    pub fn add(
        &mut self,
        name: &str,
        address: &str,
        key_file: &str,
        installed: &[Installed],
    ) -> Result<Key, Refusal> {
        if !name_ok(name) {
            return Err(Refusal::Name(name.into()));
        }
        if name == OFFICIAL {
            return Err(Refusal::Official(name.into()));
        }
        let probe = format!("{name} {address}\n");
        match config::parse_repositories(&probe) {
            Err(LineError {
                rule: Rule::NotHttps,
                ..
            }) => return Err(Refusal::NotHttps(address.into())),
            Err(_) => return Err(Refusal::NotHttps(address.into())),
            Ok(_) => {}
        }
        let key = keyfile::parse_public(key_file).map_err(|_| Refusal::Key(name.into()))?;
        let address = address.trim_end_matches('/').to_string();
        let known = self
            .lines
            .iter()
            .any(|l| matches!(l, Line::Add { name: n, .. } if n == name));
        if !known && self.own_count() >= OWN_MAX {
            return Err(Refusal::TooMany);
        }
        if self
            .key_of(name)
            .is_some_and(|old| old.public != key.public)
        {
            held_by(name, installed)?;
        }
        self.lines
            .retain(|l| !matches!(l, Line::Disable { name: n } if n == name));
        match self
            .lines
            .iter_mut()
            .find(|l| matches!(l, Line::Add { name: n, .. } if n == name))
        {
            Some(Line::Add { address: old, .. }) => *old = address,
            _ => self.lines.push(Line::Add {
                name: name.into(),
                address,
            }),
        }
        self.keys.retain(|(n, _)| n != name);
        self.keys.push((name.into(), key));
        Ok(key)
    }

    /// `repo remove <name>`: the line and the key go, unless a package of the repository stands.
    pub fn remove(&mut self, name: &str, installed: &[Installed]) -> Result<(), Refusal> {
        if name == OFFICIAL {
            return Err(Refusal::Official(name.into()));
        }
        let has = self
            .lines
            .iter()
            .any(|l| matches!(l, Line::Add { name: n, .. } if n == name))
            || self.key_of(name).is_some();
        if !has {
            return Err(Refusal::Unknown(name.into()));
        }
        held_by(name, installed)?;
        self.lines.retain(|l| match l {
            Line::Add { name: n, .. } | Line::Disable { name: n } => n != name,
        });
        self.keys.retain(|(n, _)| n != name);
        Ok(())
    }

    /// `repo save`: the settings of the files of `/etc/pkg` (the text of `repositories`, if
    /// there is one, and the text of the key file of each repository it names). A line that
    /// breaks the rules is named by its number; a repository without a good key file by its name (the service wants a key for every line, a disabled one too).
    pub fn from_files(
        repositories: Option<&str>,
        key_files: &[(String, Option<String>)],
    ) -> Result<Settings, String> {
        let file = "/etc/pkg/repositories";
        let lines = match repositories {
            Some(text) => config::parse_repositories(text).map_err(|e| e.text(file))?,
            None => Vec::new(),
        };
        let mut settings = Settings {
            lines,
            keys: Vec::new(),
        };
        for line in settings.lines.clone() {
            let Line::Add { name, .. } = line else {
                continue;
            };
            let path = format!("/etc/pkg/keys/{name}.pub");
            let text = key_files
                .iter()
                .find(|(n, _)| *n == name)
                .and_then(|(_, t)| t.as_deref())
                .ok_or_else(|| format!("pkg: {path}: no key file for the repository {name}"))?;
            let key = keyfile::parse_public(text).map_err(|_| Refusal::Key(path.clone()).line())?;
            settings.keys.push((name, key));
        }
        Ok(settings)
    }

    /// The names whose key files `repo save` and the check read: those of the lines.
    pub fn names(repositories: Option<&str>) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for text in repositories.into_iter().flat_map(str::lines) {
            if let Some(name) = text.split(' ').next().filter(|n| *n != "disable")
                && !out.iter().any(|o| o == name)
                && name_ok(name)
            {
                out.push(name.into());
            }
        }
        out
    }
}

fn held_by(name: &str, installed: &[Installed]) -> Result<(), Refusal> {
    match installed
        .iter()
        .find(|i| !i.in_image() && i.repository == name)
    {
        Some(i) => Err(Refusal::Installed {
            repository: name.into(),
            package: i.name.clone(),
        }),
        None => Ok(()),
    }
}

/// The names of the key files and of the lines a blob names, for the check of `/etc/pkg`:
/// every one of them is read from the files.
pub fn watched(blob_bytes: &[u8], repositories: Option<&str>) -> Vec<String> {
    let mut names = Settings::names(repositories);
    if let Ok(blob) = Blob::parse(blob_bytes) {
        for f in blob.files() {
            let own = if f.name == REPOSITORIES.as_bytes() {
                core::str::from_utf8(f.data)
                    .ok()
                    .map(|t| Settings::names(Some(t)))
                    .unwrap_or_default()
            } else {
                stem(f.name)
                    .map(|s| alloc::vec![s.to_string()])
                    .unwrap_or_default()
            };
            for n in own {
                if !names.contains(&n) {
                    names.push(n);
                }
            }
        }
    }
    names
}

/// Whether the files of `/etc/pkg` (the bytes of `repositories` if present; the key file of each
/// watched name if present) are not what the saved blob holds. A name with no key file in
/// either place does not differ.
pub fn differs(
    blob_bytes: &[u8],
    repositories: Option<&[u8]>,
    keys: &[(String, Option<Vec<u8>>)],
) -> bool {
    let saved = Blob::parse(blob_bytes).ok();
    let held = |name: &str| {
        saved
            .iter()
            .flat_map(|b| b.files())
            .find(|f| f.name == name.as_bytes())
            .map(|f| f.data)
    };
    if held(REPOSITORIES) != repositories {
        return true;
    }
    keys.iter()
        .any(|(name, data)| held(&format!("{KEYS}{name}{SUFFIX}")) != data.as_deref())
}

/// The line that says the files and the saved settings part.
pub const DIFFERS_LINE: &str =
    "pkg: /etc/pkg differs from the saved settings; pkg repo save keeps it, a reboot drops it";

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use pkgfmt::Name;

    fn key(name: &str, byte: u8) -> Key {
        Key {
            name: Name::new(name).unwrap(),
            public: [byte; 32],
        }
    }

    fn file(k: &Key) -> String {
        key_line(k)
    }

    fn held(name: &str, repository: &str) -> Installed {
        Installed {
            name: name.into(),
            version: "1.0-1".into(),
            sha256: [0; 32],
            flags: 1,
            repository: repository.into(),
            provides: vec![],
            depends: vec![],
        }
    }

    #[test]
    fn the_blob_is_the_one_the_protocol_writes() {
        let files: [(&str, &[u8]); 2] =
            [("repositories", b"a https://h/x\n"), ("keys/a.pub", b"k")];
        assert_eq!(blob_of(&files), blob::write(&files));
        assert_eq!(blob_of(&[]), blob::write(&[]));
    }

    #[test]
    fn the_fingerprint_is_the_openssh_form_of_the_sha256() {
        // The key of RFC 8410: its SHA-256 is fixed, the form has no padding.
        let mut raw = [0u8; 33];
        b64::decode("Gb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=", &mut raw).unwrap();
        let k = Key {
            name: Name::new("games-1").unwrap(),
            public: raw[..32].try_into().unwrap(),
        };
        let f = fingerprint(&k);
        assert!(f.starts_with("SHA256:"));
        assert_eq!(f.len(), 7 + 43);
        assert!(!f.contains('='));
        assert_eq!(
            added_line("games", &k),
            format!("games: key games-1 {f}, trusted for games only")
        );
    }

    #[test]
    fn an_added_repository_is_a_blob_the_service_takes_and_this_reads_back() {
        let mut s = Settings::default();
        let k = key("games-1", 7);
        s.add(
            "games",
            "https://10.0.2.2:8443/games/0.2/aarch64/",
            &file(&k),
            &[],
        )
        .unwrap();
        assert_eq!(
            s.repositories(),
            "games https://10.0.2.2:8443/games/0.2/aarch64\n"
        );
        let bytes = s.to_blob();
        // The service's own rules take it.
        pkgd::settings::Settings::parse(&bytes).unwrap();
        let back = Settings::from_blob(&bytes).unwrap();
        assert_eq!(back, s);
        assert_eq!(back.keys[0].1.public, [7; 32]);
    }

    #[test]
    fn a_name_an_address_or_a_key_that_breaks_a_rule_is_refused() {
        let mut s = Settings::default();
        let k = file(&key("k", 1));
        for bad in ["", "Games", "a b", &"a".repeat(32)] {
            assert!(
                matches!(s.add(bad, "https://h/x", &k, &[]), Err(Refusal::Name(_))),
                "{bad:?}"
            );
        }
        assert_eq!(
            s.add("stafeto", "https://h/x", &k, &[]),
            Err(Refusal::Official("stafeto".into()))
        );
        let e = s
            .add("plain", "http://10.0.2.2:8080/x", &k, &[])
            .unwrap_err();
        assert_eq!(e.line(), "pkg: http://10.0.2.2:8080/x: not https");
        assert!(matches!(
            s.add("g", "https://h/x", "ed25519 !!! k\n", &[]),
            Err(Refusal::Key(_))
        ));
        assert!(matches!(
            s.add("g", "https://h/x", "ed25519 AAAA k", &[]),
            Err(Refusal::Key(_))
        ));
        assert_eq!(s, Settings::default());
    }

    #[test]
    fn fifteen_repositories_are_the_most_and_a_known_one_may_be_added_again() {
        let mut s = Settings::default();
        let k = file(&key("k", 1));
        for i in 0..15 {
            s.add(&format!("r{i}"), "https://h/x", &k, &[]).unwrap();
        }
        assert_eq!(s.add("more", "https://h/x", &k, &[]), Err(Refusal::TooMany));
        s.add("r3", "https://other/x", &k, &[]).unwrap();
        assert_eq!(s.lines.len(), 15);
        pkgd::settings::Settings::parse(&s.to_blob()).unwrap();
    }

    #[test]
    fn a_key_is_not_changed_while_a_package_stands_installed_from_the_repository() {
        let mut s = Settings::default();
        s.add("games", "https://h/x", &file(&key("a", 1)), &[])
            .unwrap();
        let stands = [held("hello-games", "games"), held("x", "stafeto")];
        let e = s
            .add("games", "https://h/x", &file(&key("b", 2)), &stands)
            .unwrap_err();
        assert_eq!(
            e.line(),
            "pkg: games: hello-games is installed from it; pkg remove it first"
        );
        assert_eq!(s.keys[0].1.public, [1; 32]);
        // The same key again, or a key while nothing stands, is allowed.
        s.add("games", "https://h/y", &file(&key("a", 1)), &stands)
            .unwrap();
        s.add(
            "games",
            "https://h/y",
            &file(&key("b", 2)),
            &[held("x", "stafeto")],
        )
        .unwrap();
        assert_eq!(s.keys[0].1.public, [2; 32]);
    }

    #[test]
    fn a_repository_is_removed_with_its_key_unless_a_package_stands() {
        let mut s = Settings::default();
        s.add("games", "https://h/x", &file(&key("a", 1)), &[])
            .unwrap();
        s.add("tools", "https://h/y", &file(&key("b", 2)), &[])
            .unwrap();
        let stands = [held("hello-games", "games")];
        assert_eq!(
            s.remove("games", &stands).unwrap_err().line(),
            "pkg: games: hello-games is installed from it; pkg remove it first"
        );
        assert_eq!(
            s.remove("nobody", &[]),
            Err(Refusal::Unknown("nobody".into()))
        );
        assert_eq!(
            s.remove("stafeto", &[]),
            Err(Refusal::Official("stafeto".into()))
        );
        s.remove("tools", &stands).unwrap();
        assert_eq!(s.repositories(), "games https://h/x\n");
        assert_eq!(s.keys.len(), 1);
        s.remove("games", &[]).unwrap();
        // No file at all: a blob of no files, which the service takes.
        let bytes = s.to_blob();
        assert_eq!(Blob::parse(&bytes).unwrap().count, 0);
        pkgd::settings::Settings::parse(&bytes).unwrap();
    }

    #[test]
    fn a_line_of_a_note_is_not_sent_and_save_names_the_line_it_refuses() {
        // Breakage 28: a note line in `repositories` is refused here, by its number.
        let e = Settings::from_files(
            Some("games https://h/x\n# a note\n"),
            &[("games".into(), Some(file(&key("a", 1))))],
        )
        .unwrap_err();
        assert_eq!(
            e,
            "pkg: /etc/pkg/repositories: line 2: not \"<name> <https address>\" or \"disable <name>\""
        );
        // The blob that goes to the service has no note, and the service says so too.
        let blob = blob::write(&[("repositories", b"games https://h/x\n# a note\n")]);
        assert!(pkgd::settings::Settings::parse(&blob).is_err());
    }

    #[test]
    fn save_reads_the_files_and_needs_a_key_for_every_repository() {
        let k = file(&key("a", 1));
        let s = Settings::from_files(
            Some("games https://h/x\ndisable stafeto\n"),
            &[("games".into(), Some(k.clone()))],
        )
        .unwrap();
        assert_eq!(s.keys.len(), 1);
        pkgd::settings::Settings::parse(&s.to_blob()).unwrap();
        let e = Settings::from_files(Some("games https://h/x\n"), &[("games".into(), None)])
            .unwrap_err();
        assert_eq!(
            e,
            "pkg: /etc/pkg/keys/games.pub: no key file for the repository games"
        );
        let e = Settings::from_files(
            Some("games https://h/x\n"),
            &[("games".into(), Some("junk\n".into()))],
        )
        .unwrap_err();
        assert!(e.contains("not a key file"));
        assert_eq!(
            Settings::from_files(None, &[]).unwrap(),
            Settings::default()
        );
        assert_eq!(
            Settings::names(Some("games https://h/x\ndisable tools\n")),
            ["games"]
        );
    }

    #[test]
    fn the_files_of_etc_pkg_are_compared_with_the_blob() {
        let mut s = Settings::default();
        s.add("games", "https://h/x", &file(&key("a", 1)), &[])
            .unwrap();
        let bytes = s.to_blob();
        let text = s.repositories();
        let kf = key_line(&key("a", 1));
        let names = watched(&bytes, Some(&text));
        assert_eq!(names, ["games"]);
        let keys =
            |data: Option<&str>| vec![("games".to_string(), data.map(|d| d.as_bytes().to_vec()))];
        assert!(!differs(&bytes, Some(text.as_bytes()), &keys(Some(&kf))));
        assert!(differs(
            &bytes,
            Some(b"games https://h/z\n"),
            &keys(Some(&kf))
        ));
        assert!(differs(&bytes, Some(text.as_bytes()), &keys(Some("other"))));
        assert!(differs(&bytes, None, &keys(Some(&kf))));
        // No settings, no files: nothing differs; a file the owner made does.
        let empty = Settings::default().to_blob();
        assert!(!differs(&empty, None, &[]));
        assert!(differs(&empty, Some(b"games https://h/x\n"), &[]));
        // A line that names a repository the blob lacks is watched too.
        assert_eq!(watched(&empty, Some("tools https://h/y\n")), ["tools"]);
    }
}
