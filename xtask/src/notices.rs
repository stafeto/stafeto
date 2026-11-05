// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The notices of a package (docs/packages.md): the directory
//! `/usr/share/licenses/<name>/` it carries holds its licence text
//! (`LICENSE`), a note of where its exact source is and how it was built
//! (`SOURCE`), the files its description names (`notices`) and, for each
//! package linked into it, a directory of that package's notices. The texts
//! come from the outputs of the builds, without the network. The functions
//! that write the notice files of the images take their licence texts from
//! `licence_text` too.

use crate::packages::{self, Package};
use std::path::PathBuf;

/// The directory of the licences of a package.
pub fn directory(name: &str) -> String {
    format!("/usr/share/licenses/{name}")
}

fn read(path: PathBuf) -> Result<Vec<u8>, String> {
    std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))
}

fn version(name: &str) -> Result<String, String> {
    packages::value(name, "version")
}

/// The licence text of the package `name`, from the outputs of its build.
pub fn licence_text(name: &str) -> Result<Vec<u8>, String> {
    let target = crate::target_dir();
    match name {
        "busybox" => read(target.join("busybox/source/LICENSE")),
        "bash" => read(target.join(format!("bash/bash-{}/COPYING", version(name)?))),
        "nano" => read(target.join(format!("nano/nano-{}/COPYING", version(name)?))),
        "htop" => read(target.join(format!("htop/htop-{}/COPYING", version(name)?))),
        "ncdu" => read(target.join(format!("ncdu/ncdu-{}/COPYING", version(name)?))),
        "doomgeneric" => read(target.join(format!(
            "doomgeneric/doomgeneric-{}/LICENSE",
            version(name)?
        ))),
        "freedoom" => {
            read(target.join(format!("freedoom/freedoom-{}/COPYING.txt", version(name)?)))
        }
        "f-stack" => read(target.join("f-stack/LICENSE")),
        "openssl" => read(target.join(format!("openssl/openssl-{}/LICENSE.txt", version(name)?))),
        "curl" => read(target.join(format!("curl/curl-{}/COPYING", version(name)?))),
        "pcre2" => read(target.join(format!("nginx/pcre2-{}/LICENCE.md", version(name)?))),
        "nginx" | "nginx-fast" => {
            read(target.join(format!("nginx/nginx-{}/LICENSE", version(name)?)))
        }
        "ca-bundle" => {
            let mut text = read(crate::root().join("tools/ca-bundle/MPL-2.0.txt"))?;
            text.extend_from_slice(b"\n\nThe header of the file:\n\n");
            let data = read(target.join("ca-bundle/ca-certificates.crt"))?;
            text.extend(
                data.split_inclusive(|&b| b == b'\n')
                    .take_while(|l| l.starts_with(b"##"))
                    .flatten()
                    .copied(),
            );
            Ok(text)
        }
        other => ready_utility_text(other),
    }
}

/// The licence of a utility BusyBox's build links from its own source
/// (tools/build-ready-utils.py): the licence file its row of
/// `target/ready-utils/manifest` names, then the sections of
/// `target/ready-utils/notices` that start with the package's name.
fn ready_utility_text(name: &str) -> Result<Vec<u8>, String> {
    let work = crate::target_dir().join("ready-utils");
    let manifest = std::fs::read_to_string(work.join("manifest")).map_err(|e| {
        format!("{name}: ready-utils/manifest: {e}: python3 tools/build-busybox.py writes it")
    })?;
    let row = manifest
        .lines()
        .map(|l| l.split('\t').collect::<Vec<_>>())
        .find(|f| f.first() == Some(&name))
        .ok_or_else(|| format!("{name}: no licence source is known for this package"))?;
    let file = row
        .get(4)
        .copied()
        .ok_or_else(|| format!("{name}: a bad row in ready-utils/manifest"))?;
    let mut text = Vec::new();
    if file != "-" {
        text.extend(read(work.join(file))?);
    }
    let notices = std::fs::read_to_string(work.join("notices"))
        .map_err(|e| format!("ready-utils/notices: {e}"))?;
    let header = format!("==== {name} ");
    let mut inside = false;
    let mut found = false;
    for line in notices.split_inclusive('\n') {
        if line.starts_with("==== ") {
            inside = line.starts_with(&header);
            found |= inside;
            if inside && !text.is_empty() {
                text.extend_from_slice(b"\n");
            }
        }
        if inside {
            text.extend_from_slice(line.as_bytes());
        }
    }
    if file == "-" && !found {
        return Err(format!(
            "{name}: ready-utils/manifest has no licence file and ready-utils/notices no section for it"
        ));
    }
    Ok(text)
}

/// Whether the licence of the package, or of one it links in, is a GPL
/// licence: such a package comes with a source archive.
pub fn needs_source(p: &Package, all: &[Package]) -> bool {
    let gpl = |q: &Package| q.license.contains("GPL");
    gpl(p)
        || p.build_depends
            .iter()
            .filter_map(|d| all.iter().find(|q| q.name == *d))
            .any(gpl)
}

/// The first eight characters of a version made of a commit hash, else the
/// version.
pub fn short_version(version: &str) -> String {
    if version.len() == 40 && version.bytes().all(|b| b.is_ascii_hexdigit()) {
        version[..8].to_string()
    } else {
        version.to_string()
    }
}

/// `<name>-<short version>-<release>`: the stem of the package file and of
/// its source archive.
pub fn stem(p: &Package) -> String {
    format!("{}-{}-{}", p.name, short_version(&p.version), p.release)
}

/// The name of the source archive in the repository, if the package has one.
pub fn source_archive(p: &Package, all: &[Package]) -> Option<String> {
    needs_source(p, all).then(|| format!("src/{}-src.tar.xz", stem(p)))
}

/// What a package says of where its source is and how it was built.
pub struct Build<'a> {
    /// The commit of stafeto that builds it.
    pub commit: &'a str,
    /// The pin of relibc, when the package holds a program.
    pub relibc: Option<&'a str>,
    pub recipe: &'a str,
}

/// The file `SOURCE`.
pub fn source_text(p: &Package, all: &[Package], b: &Build<'_>) -> String {
    let mut out = format!(
        "{} {}-{}, licence {}.\nSource: {}\nSHA-256 of the source: {}\n\
         Built by {} of https://github.com/stafeto/stafeto at commit {}; the recipe {} names its inputs.\n",
        p.name, p.version, p.release, p.license, p.url, p.sha256, p.build, b.commit, b.recipe
    );
    let linked: Vec<String> = p
        .build_depends
        .iter()
        .filter_map(|d| all.iter().find(|q| q.name == *d))
        .map(|d| format!("{} {} ({})", d.name, d.version, d.license))
        .collect();
    if !linked.is_empty() {
        out += &format!(
            "Linked into it: {}; their notices are in the directories of this one.\n",
            linked.join(", ")
        );
    }
    if let Some(relibc) = b.relibc {
        out += &format!(
            "Linked with relibc https://github.com/stafeto/relibc at commit {relibc}; the notices of the system are in /usr/share/licenses/stafeto/.\n"
        );
    }
    if let Some(source) = source_archive(p, all) {
        out += &format!(
            "The corresponding source: {source} next to this package in its repository.\n"
        );
    }
    out
}

/// A notice file named by a description: its bytes.
fn notice_file(from: &str) -> Result<Vec<u8>, String> {
    let (kind, path) = from
        .split_once(':')
        .ok_or_else(|| format!("{from}: no kind"))?;
    match kind {
        "target" => read(crate::target_dir().join(path)),
        "tree" => read(crate::root().join(path)),
        other => Err(format!("{from}: {other} is none of target, tree")),
    }
}

/// The notice files of the package: the path under
/// `/usr/share/licenses/<name>/` and the bytes. Its own `LICENSE`, `SOURCE`
/// and `notices`, then for each package linked in (`build_depends`) its
/// `LICENSE` and `notices` in a directory of that name.
pub fn files(
    p: &Package,
    all: &[Package],
    b: &Build<'_>,
) -> Result<Vec<(String, Vec<u8>)>, String> {
    let base = directory(&p.name);
    let mut out = vec![
        (format!("{base}/LICENSE"), licence_text(&p.name)?),
        (
            format!("{base}/SOURCE"),
            source_text(p, all, b).into_bytes(),
        ),
    ];
    for (name, from) in &p.notices {
        out.push((format!("{base}/{name}"), notice_file(from)?));
    }
    for d in &p.build_depends {
        let Some(dep) = all.iter().find(|q| q.name == *d) else {
            continue;
        };
        out.push((format!("{base}/{d}/LICENSE"), licence_text(d)?));
        for (name, from) in &dep.notices {
            out.push((format!("{base}/{d}/{name}"), notice_file(from)?));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(name: &str, license: &str) -> Package {
        let text = format!(
            "name = \"{name}\"\nversion = \"e257a09527062bfb986b6e5e0780839b6cbd5b71\"\nkind = \"optional\"\nimage = \"shell\"\nrelease = \"2\"\nsummary = \"s\"\nurl = \"https://example.org/x.tar.gz\"\nsha256 = \"{}\"\nlicense = \"{license}\"\nbuild = \"tools/build-x.py\"\nfiles = [\"/bin/x = bytes:x\"]\n",
            "ab".repeat(32)
        );
        packages::parse(&text, "x.toml").unwrap()
    }

    #[test]
    fn short_versions_and_stems() {
        assert_eq!(
            short_version("e257a09527062bfb986b6e5e0780839b6cbd5b71"),
            "e257a095"
        );
        assert_eq!(short_version("1.37.0"), "1.37.0");
        assert_eq!(stem(&package("doom", "MIT")), "doom-e257a095-2");
    }

    #[test]
    fn gpl_packages_and_those_that_link_them_come_with_source() {
        let gpl = package("a", "GPL-2.0-or-later");
        let mut user = package("b", "MIT");
        user.build_depends = vec!["a".into()];
        let free = package("c", "MIT");
        let all = [gpl.clone(), user.clone(), free.clone()];
        assert!(needs_source(&gpl, &all));
        assert!(needs_source(&user, &all));
        assert!(!needs_source(&free, &all));
        assert_eq!(
            source_archive(&user, &all).unwrap(),
            "src/b-e257a095-2-src.tar.xz"
        );
    }

    #[test]
    fn the_source_note_names_what_it_should() {
        let gpl = package("a", "GPL-2.0-or-later");
        let mut user = package("b", "MIT");
        user.build_depends = vec!["a".into()];
        let all = [gpl, user.clone()];
        let build = Build {
            commit: &"1".repeat(40),
            relibc: Some("pin-0a1b2c3d"),
            recipe: &"2".repeat(64),
        };
        let text = source_text(&user, &all, &build);
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[0].starts_with("b e257a09527062bfb986b6e5e0780839b6cbd5b71-2, licence MIT."));
        assert_eq!(lines[1], "Source: https://example.org/x.tar.gz");
        assert!(lines[3].starts_with(
            "Built by tools/build-x.py of https://github.com/stafeto/stafeto at commit 111"
        ));
        assert!(lines[4].starts_with(
            "Linked into it: a e257a09527062bfb986b6e5e0780839b6cbd5b71 (GPL-2.0-or-later);"
        ));
        assert!(
            lines[5].contains("relibc https://github.com/stafeto/relibc at commit pin-0a1b2c3d")
        );
        assert!(lines[6].starts_with("The corresponding source: src/b-e257a095-2-src.tar.xz"));
        let plain = source_text(
            &all[0],
            &all,
            &Build {
                relibc: None,
                ..build
            },
        );
        assert!(!plain.contains("Linked"));
    }
}
