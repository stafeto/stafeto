// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The repositories (pk4-design R5). The official one is the line of
//! `/etc/pkg/official`; the owner's are the lines of `repositories` in the
//! settings blob, by the rules the package service applies to it
//! (services/pkgd/src/settings.rs) so that one file is read the same way
//! by both. The addresses of the files of a repository come from the address
//! of its index and the `file` and `source` fields of its entries: https
//! alone, no way up the tree.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use pkgfmt::{Key, Name, keyfile};

/// The name of the official repository.
pub const OFFICIAL: &str = "stafeto";
/// The owner's repositories at most: the table of the store holds 16, the
/// official one has the first place.
pub const OWN_MAX: usize = 15;

/// One repository, in the order `pkg` asks them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Repository {
    pub name: String,
    /// The address of the directory that holds `INDEX`, without a slash at the end.
    pub address: String,
    /// The key an owner's repository is trusted by; the official one is
    /// trusted by the roots baked in at the build.
    pub key: Option<Key>,
}

impl Repository {
    pub fn is_official(&self) -> bool {
        self.name == OFFICIAL
    }
}

/// What a line of a file of settings breaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    /// Not `<name> <https address>`, nor `disable <name>`, and no other words.
    Shape,
    /// A name that is not 1 to 63 bytes of `[a-z0-9-]`; 31 at most for a repository.
    Name,
    /// The official name for an owner's repository.
    Official,
    /// An address without `https://` or without anything after it.
    NotHttps,
    /// More repositories than the table of the store holds.
    TooMany,
}

/// A line that breaks a rule, counted from 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LineError {
    pub line: usize,
    pub rule: Rule,
}

impl LineError {
    /// The line of the refusal, for the file `file` (`pkg: <file>: line 2: ...`).
    pub fn text(&self, file: &str) -> String {
        let what = match self.rule {
            Rule::Shape => "not \"<name> <https address>\" or \"disable <name>\"",
            Rule::Name => "a name is 1 to 31 characters of a-z, 0-9 and -",
            Rule::Official => "the name stafeto is the official repository's",
            Rule::NotHttps => "the address does not start with https://",
            Rule::TooMany => "more than 15 repositories",
        };
        alloc::format!("pkg: {file}: line {}: {what}", self.line)
    }
}

/// A line of `repositories`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Line {
    Add { name: String, address: String },
    Disable { name: String },
}

fn name_ok(name: &str) -> bool {
    name.len() <= 31 && Name::new(name).is_ok()
}

fn https_ok(address: &str) -> bool {
    address.starts_with("https://") && address.len() > "https://".len()
}

/// The lines of `repositories`: each `<name> <https address>` or `disable
/// <name>` with one space between, no empty line and no note.
pub fn parse_repositories(text: &str) -> Result<Vec<Line>, LineError> {
    let mut lines = Vec::new();
    let mut own = 0;
    for (n, text) in text.lines().enumerate() {
        let fail = |rule| LineError { line: n + 1, rule };
        let mut words = text.split(' ');
        match (words.next(), words.next(), words.next()) {
            (Some("disable"), Some(name), None) => {
                if !name_ok(name) {
                    return Err(fail(Rule::Name));
                }
                lines.push(Line::Disable { name: name.into() });
            }
            (Some(name), Some(address), None) => {
                if !name_ok(name) {
                    return Err(fail(Rule::Name));
                }
                if name == OFFICIAL {
                    return Err(fail(Rule::Official));
                }
                if !https_ok(address) {
                    return Err(fail(Rule::NotHttps));
                }
                own += 1;
                if own > OWN_MAX {
                    return Err(fail(Rule::TooMany));
                }
                lines.push(Line::Add {
                    name: name.into(),
                    address: address.trim_end_matches('/').into(),
                });
            }
            _ => return Err(fail(Rule::Shape)),
        }
    }
    Ok(lines)
}

/// `/etc/pkg/official`: one line `stafeto <https address>`.
pub fn parse_official(text: &str) -> Result<Repository, LineError> {
    let fail = |rule| LineError { line: 1, rule };
    let mut lines = text.lines();
    let line = lines.next().ok_or(fail(Rule::Shape))?;
    if lines.next().is_some() {
        return Err(LineError {
            line: 2,
            rule: Rule::Shape,
        });
    }
    match line.split(' ').collect::<Vec<_>>()[..] {
        [OFFICIAL, address] if https_ok(address) => Ok(Repository {
            name: OFFICIAL.into(),
            address: address.trim_end_matches('/').into(),
            key: None,
        }),
        [OFFICIAL, _] => Err(fail(Rule::NotHttps)),
        [_, _] => Err(fail(Rule::Official)),
        _ => Err(fail(Rule::Shape)),
    }
}

/// The repositories in the order they are asked: the official one (unless a
/// line says `disable stafeto`), then the owner's from the top down. `key_of`
/// gives the key of an owner's repository (`keys/<name>.pub` of the blob); a
/// repository without one is left out and named in the second list.
pub fn order(
    official: Option<Repository>,
    lines: &[Line],
    key_of: impl Fn(&str) -> Option<Key>,
) -> (Vec<Repository>, Vec<String>) {
    let disabled = |name: &str| {
        lines
            .iter()
            .any(|l| matches!(l, Line::Disable { name: n } if n == name))
    };
    let mut out = Vec::new();
    let mut keyless = Vec::new();
    if let Some(official) = official.filter(|o| !disabled(&o.name)) {
        out.push(official);
    }
    for line in lines {
        let Line::Add { name, address } = line else {
            continue;
        };
        if disabled(name) || out.iter().any(|r| r.name == *name) {
            continue;
        }
        match key_of(name) {
            Some(key) => out.push(Repository {
                name: name.clone(),
                address: address.clone(),
                key: Some(key),
            }),
            None => keyless.push(name.clone()),
        }
    }
    (out, keyless)
}

/// The key file `keys/<name>.pub` of the settings blob, as a key.
pub fn key_from_file(data: &[u8]) -> Option<Key> {
    keyfile::parse_public(core::str::from_utf8(data).ok()?).ok()
}

/// The settings blob as the owner's repositories: the lines of `repositories`
/// and the keys of the blob. An empty blob (no file of the owner's) is no
/// repository.
pub fn from_blob(
    blob: &[u8],
    official: Option<Repository>,
) -> Result<(Vec<Repository>, Vec<String>), LineError> {
    let Ok(blob) = proto_pkg::blob::Blob::parse(blob) else {
        return Ok((official.into_iter().collect(), Vec::new()));
    };
    let lines = match blob.files().find(|f| f.name == b"repositories") {
        Some(f) => parse_repositories(core::str::from_utf8(f.data).map_err(|_| LineError {
            line: 1,
            rule: Rule::Shape,
        })?)?,
        None => Vec::new(),
    };
    let key_of = |name: &str| {
        let file = alloc::format!("keys/{name}.pub");
        blob.files()
            .find(|f| f.name == file.as_bytes())
            .and_then(|f| key_from_file(f.data))
    };
    Ok(order(official, &lines, key_of))
}

/// Why an address is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Address {
    NotHttps,
    /// A path that goes up, starts with a slash, or holds an empty part, or a character no address has.
    BadPath,
}

/// The address of the file `file` of a repository whose index is in `base`:
/// a full `https://` address as it is, a relative name under `base`. Another
/// scheme, a path that leaves the directory and a name with a space or a
/// control character are refused.
pub fn locate(base: &str, file: &str) -> Result<String, Address> {
    if !https_ok(base) {
        return Err(Address::NotHttps);
    }
    if file.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err(Address::BadPath);
    }
    if file.starts_with("https://") {
        return if file.len() > "https://".len() {
            Ok(file.to_string())
        } else {
            Err(Address::BadPath)
        };
    }
    if file.contains("://") {
        return Err(Address::NotHttps);
    }
    if file.starts_with('/')
        || file
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
    {
        return Err(Address::BadPath);
    }
    Ok(alloc::format!("{}/{file}", base.trim_end_matches('/')))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn rule(text: &str) -> (usize, Rule) {
        let e = parse_repositories(text).unwrap_err();
        (e.line, e.rule)
    }

    fn key(name: &str) -> Key {
        Key {
            name: Name::new(name).unwrap(),
            public: [3; 32],
        }
    }

    #[test]
    fn the_official_line_is_the_name_and_an_https_address() {
        let r = parse_official("stafeto https://stafeto.github.io/packages/0.3/aarch64\n").unwrap();
        assert_eq!(r.name, "stafeto");
        assert_eq!(r.address, "https://stafeto.github.io/packages/0.3/aarch64");
        assert!(r.is_official() && r.key.is_none());
        let slash = parse_official("stafeto https://a.example/x/\n").unwrap();
        assert_eq!(slash.address, "https://a.example/x");
        assert_eq!(
            parse_official("stafeto http://a.example\n")
                .unwrap_err()
                .rule,
            Rule::NotHttps
        );
        assert_eq!(
            parse_official("other https://a.example\n")
                .unwrap_err()
                .rule,
            Rule::Official
        );
        assert_eq!(parse_official("").unwrap_err().rule, Rule::Shape);
        assert_eq!(parse_official("stafeto\n").unwrap_err().rule, Rule::Shape);
        assert_eq!(
            parse_official("stafeto https://a\nstafeto https://b\n")
                .unwrap_err()
                .line,
            2
        );
    }

    #[test]
    fn lines_of_repositories_and_disable() {
        let lines = parse_repositories("games https://g.example/x\ndisable stafeto\n").unwrap();
        assert_eq!(
            lines,
            vec![
                Line::Add {
                    name: "games".into(),
                    address: "https://g.example/x".into()
                },
                Line::Disable {
                    name: "stafeto".into()
                },
            ]
        );
        assert_eq!(parse_repositories("").unwrap(), vec![]);
    }

    #[test]
    fn each_rule_of_a_line_has_its_number_and_its_text() {
        // A note, an empty line, two spaces, http, a long name, the official name.
        assert_eq!(rule("# a note\n"), (1, Rule::Shape));
        assert_eq!(rule("# note\n"), (1, Rule::Name));
        assert_eq!(rule("games https://g.example\n\n"), (2, Rule::Shape));
        assert_eq!(rule("games  https://g.example\n"), (1, Rule::Shape));
        assert_eq!(rule("games https://g.example extra\n"), (1, Rule::Shape));
        assert_eq!(rule("games http://g.example\n"), (1, Rule::NotHttps));
        assert_eq!(rule("games https://\n"), (1, Rule::NotHttps));
        assert_eq!(
            rule(&alloc::format!("{} https://g.example\n", "a".repeat(32))),
            (1, Rule::Name)
        );
        assert_eq!(rule("Games https://g.example\n"), (1, Rule::Name));
        assert_eq!(rule("stafeto https://g.example\n"), (1, Rule::Official));
        assert_eq!(rule("disable\n"), (1, Rule::Shape));
        assert_eq!(rule("disable A\n"), (1, Rule::Name));
        let error = parse_repositories("a https://x\nb http://y\n").unwrap_err();
        assert_eq!(
            error.text("/etc/pkg/repositories"),
            "pkg: /etc/pkg/repositories: line 2: the address does not start with https://"
        );
    }

    #[test]
    fn a_sixteenth_repository_of_the_owner_is_one_too_many() {
        let many = |n: usize| {
            (0..n)
                .map(|i| alloc::format!("r{i} https://r{i}.example\n"))
                .collect::<String>()
        };
        assert_eq!(parse_repositories(&many(15)).unwrap().len(), 15);
        assert_eq!(rule(&many(16)), (16, Rule::TooMany));
    }

    #[test]
    fn the_official_repository_comes_first_and_disable_leaves_one_out() {
        let official = parse_official("stafeto https://o.example/x\n").unwrap();
        let lines = parse_repositories("b https://b.example\na https://a.example\n").unwrap();
        let (order_of, keyless) = order(Some(official.clone()), &lines, |n| Some(key(n)));
        let names: Vec<&str> = order_of.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["stafeto", "b", "a"]);
        assert!(keyless.is_empty());
        assert!(order_of[1].key.is_some() && order_of[0].key.is_none());
        let lines = parse_repositories(
            "disable stafeto\nb https://b.example\ndisable b\nc https://c.example\n",
        )
        .unwrap();
        let (order_of, _) = order(Some(official.clone()), &lines, |n| Some(key(n)));
        let names: Vec<&str> = order_of.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["c"]);
        // A repository without a key in the blob is left out, and named.
        let lines = parse_repositories("b https://b.example\n").unwrap();
        let (order_of, keyless) = order(Some(official), &lines, |_| None);
        assert_eq!(order_of.len(), 1);
        assert_eq!(keyless, ["b"]);
    }

    #[test]
    fn the_blob_gives_the_repositories_with_their_keys() {
        let line = keyfile::public_line(&key("games-1"));
        let repositories = b"games https://g.example/games\n";
        let blob = proto_pkg::blob::write(&[
            ("keys/games.pub", line.as_bytes()),
            ("repositories", repositories),
        ]);
        let official = parse_official("stafeto https://o.example\n").unwrap();
        let (list, keyless) = from_blob(&blob, Some(official.clone())).unwrap();
        assert!(keyless.is_empty());
        assert_eq!(list.len(), 2);
        assert_eq!(list[1].name, "games");
        assert_eq!(list[1].key, Some(key("games-1")));
        // No blob at all: the official repository alone.
        let (list, _) = from_blob(&[], Some(official)).unwrap();
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn a_file_of_a_repository_is_under_its_directory_and_stays_there() {
        let base = "https://m.example:8443/0.3/aarch64";
        assert_eq!(
            locate(base, "doom-1.stpkg").unwrap(),
            "https://m.example:8443/0.3/aarch64/doom-1.stpkg"
        );
        assert_eq!(
            locate("https://m.example/x/", "src/a.tar.xz").unwrap(),
            "https://m.example/x/src/a.tar.xz"
        );
        assert_eq!(
            locate(base, "https://cdn.example/a.stpkg").unwrap(),
            "https://cdn.example/a.stpkg"
        );
        assert_eq!(locate(base, "http://cdn.example/a"), Err(Address::NotHttps));
        assert_eq!(locate(base, "ftp://cdn.example/a"), Err(Address::NotHttps));
        assert_eq!(locate(base, "../a"), Err(Address::BadPath));
        assert_eq!(locate(base, "a/../b"), Err(Address::BadPath));
        assert_eq!(locate(base, "/a"), Err(Address::BadPath));
        assert_eq!(locate(base, "a//b"), Err(Address::BadPath));
        assert_eq!(locate(base, "a b"), Err(Address::BadPath));
        assert_eq!(locate("http://m.example", "a"), Err(Address::NotHttps));
    }
}
