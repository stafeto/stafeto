// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Which packages an `install` puts on the disk (pk4-design R9). The pool is
//! the records of the accepted indexes of the enabled repositories, in the
//! order of the repositories, and the packages already installed (the disk
//! and the image). There are no versions: in a series a name has one record.
//!
//! A name `x` is looked for so: a package installed under the name `x` or
//! that provides `x` closes it, nothing is downloaded; else the first
//! repository that has a package named `x`; else the packages that provide
//! `x`, which must be one. A package's own name is stronger than another's
//! `provides`. `repository/x` looks in that repository alone.
//!
//! The packages to receive are the requested one and those of its
//! dependencies that are not installed, the dependencies first. They are one
//! group of the package service: all are installed or none, at most
//! `GROUP_MAX` (4).

use crate::output::{Installed, short};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use pkgfmt::index::Entry;
use pkgfmt::sha;
use proto_pkg::{ENTRY_DEPENDENCY, ENTRY_IMAGE};

/// The most new packages one group of the package service holds.
pub const GROUP_MAX: usize = 4;

/// A record of an accepted index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub repository: String,
    pub name: String,
    /// `<version>-<release>`.
    pub version: String,
    pub provides: Vec<String>,
    pub depends: Vec<String>,
    pub needs: Vec<String>,
    pub size: u64,
    pub sha256: [u8; 32],
    pub file: String,
    pub source: Option<String>,
    pub license: String,
    pub summary: String,
}

impl Candidate {
    /// The record `e` of the index of `repository`; None for a SHA-256 that is no hex.
    pub fn new(repository: &str, e: &Entry<'_>) -> Option<Candidate> {
        let words = |v: Option<&str>| {
            v.map(|v| pkgfmt::meta::list(v).map(String::from).collect())
                .unwrap_or_default()
        };
        Some(Candidate {
            repository: repository.into(),
            name: e.name.into(),
            version: e.version.into(),
            provides: words(e.provides),
            depends: words(e.depends),
            needs: words(e.needs),
            size: e.size,
            sha256: sha::unhex(e.sha256)?,
            file: e.file.into(),
            source: e.source.map(String::from),
            license: e.license.into(),
            summary: e.summary.into(),
        })
    }

    pub fn available(&self) -> crate::output::Available {
        crate::output::Available {
            repository: self.repository.clone(),
            name: self.name.clone(),
            version: self.version.clone(),
            sha256: self.sha256,
            provides: self.provides.clone(),
            summary: self.summary.clone(),
        }
    }
}

/// Why a request cannot be met.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fault {
    /// No repository has the name.
    NoName(String),
    /// More than one package provides the name.
    Ambiguous {
        name: String,
        providers: Vec<String>,
    },
    /// A dependency of a package that no repository has.
    Needs { package: String, missing: String },
    /// A dependency that leads back to itself: the names on the way.
    Cycle(Vec<String>),
    /// More new packages than a group holds.
    TooMany(String),
    /// `repository/x` names a repository that is not enabled.
    NoRepository(String),
}

impl Fault {
    pub fn line(&self) -> String {
        match self {
            Fault::NoName(name) => format!("pkg: {name}: no repository has it"),
            Fault::Ambiguous { name, providers } => {
                format!(
                    "pkg: {name}: provided by {}; name one",
                    providers.join(", ")
                )
            }
            Fault::Needs { package, missing } => {
                format!("pkg: {package}: needs {missing}, which no repository has")
            }
            Fault::Cycle(path) => format!(
                "pkg: {}: dependency cycle {}",
                path.first().map_or("", String::as_str),
                path.join(" -> ")
            ),
            Fault::TooMany(name) => format!(
                "pkg: {name}: needs more than {GROUP_MAX} new packages at once; install some of its dependencies first"
            ),
            Fault::NoRepository(name) => format!("pkg: {name}: no such repository"),
        }
    }
}

/// One package of a plan: the record in the pool and the mark of the world.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Item {
    pub candidate: usize,
    /// Installed by request: the requested package (the dependencies are marked as dependencies).
    pub world: bool,
}

/// What an `install` of a name comes to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Already there: `name version`, in the image or on the disk.
    Present {
        name: String,
        version: String,
        image: bool,
    },
    /// Installed as a dependency: it is marked as installed by request, nothing is downloaded.
    Promote { name: String, version: String },
    /// Packages to receive, dependencies first, the requested one last; and
    /// the lines about installed packages the index has another record of.
    Install {
        items: Vec<Item>,
        notes: Vec<String>,
    },
}

/// The installed package that closes `name`: its own name first, then a `provides`.
fn closed<'a>(installed: &'a [Installed], name: &str) -> Option<&'a Installed> {
    installed.iter().find(|i| i.name == name).or_else(|| {
        installed
            .iter()
            .find(|i| i.provides.iter().any(|p| p == name))
    })
}

/// The record that answers `name` in the pool, by the rules of the module;
/// `only` limits it to a repository.
fn find(pool: &[Candidate], name: &str, only: Option<&str>) -> Result<usize, Fault> {
    let in_scope = |c: &Candidate| only.is_none_or(|r| c.repository == r);
    if let Some(at) = pool.iter().position(|c| in_scope(c) && c.name == name) {
        return Ok(at);
    }
    let mut providers: Vec<usize> = Vec::new();
    for (at, c) in pool.iter().enumerate() {
        if in_scope(c)
            && c.provides.iter().any(|p| p == name)
            && !providers.iter().any(|&o| pool[o].name == c.name)
        {
            providers.push(at);
        }
    }
    match providers[..] {
        [] => Err(Fault::NoName(name.into())),
        [one] => Ok(one),
        _ => Err(Fault::Ambiguous {
            name: name.into(),
            providers: providers.iter().map(|&at| pool[at].name.clone()).collect(),
        }),
    }
}

struct Walk<'a> {
    pool: &'a [Candidate],
    installed: &'a [Installed],
    items: Vec<Item>,
    notes: Vec<String>,
    stack: Vec<usize>,
}

impl Walk<'_> {
    fn visit(&mut self, at: usize) -> Result<(), Fault> {
        if self.items.iter().any(|i| i.candidate == at) {
            return Ok(());
        }
        let c = &self.pool[at];
        if let Some(start) = self.stack.iter().position(|&s| self.pool[s].name == c.name) {
            let mut path: Vec<String> = self.stack[start..]
                .iter()
                .map(|&s| self.pool[s].name.clone())
                .collect();
            path.push(c.name.clone());
            return Err(Fault::Cycle(path));
        }
        self.stack.push(at);
        for dep in &c.depends {
            if let Some(have) = closed(self.installed, dep) {
                self.note(have);
                continue;
            }
            let next = match find(self.pool, dep, None) {
                Ok(next) => next,
                Err(Fault::NoName(_)) => {
                    return Err(Fault::Needs {
                        package: c.name.clone(),
                        missing: dep.clone(),
                    });
                }
                Err(other) => return Err(other),
            };
            self.visit(next)?;
        }
        self.stack.pop();
        self.items.push(Item {
            candidate: at,
            world: false,
        });
        Ok(())
    }

    /// An installed package the index has another record of stays as it is.
    fn note(&mut self, have: &Installed) {
        if have.in_image() {
            return;
        }
        let Some(c) = self
            .pool
            .iter()
            .find(|c| c.name == have.name && c.repository == have.repository)
        else {
            return;
        };
        if c.sha256 != have.sha256 {
            self.notes.push(format!(
                "{}: installed {}, the index has {}; pkg upgrade replaces it",
                have.name,
                short(&have.version),
                short(&c.version)
            ));
        }
    }
}

/// A step of receiving a group: the package, whether it is of the world, and whether it is the
/// last of the group (the service attaches the whole group at the end of the last).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Step {
    pub candidate: usize,
    pub world: bool,
    pub end: bool,
}

/// The steps of a plan: one group, which ends at the last package.
pub fn steps(items: &[Item]) -> Vec<Step> {
    items
        .iter()
        .enumerate()
        .map(|(n, i)| Step {
            candidate: i.candidate,
            world: i.world,
            end: n + 1 == items.len(),
        })
        .collect()
}

/// The version a package's `meta` names: the index says `<version>-<release>`, the service compares
/// the version of the record with the `version` line of `meta`, which has no release.
pub fn meta_version(version: &str) -> &str {
    version.rsplit_once('-').map_or(version, |(v, _)| v)
}

/// The record INSTALL_BEGIN carries for `c`: what the index says of the package (never what
/// was received: the service compares the bytes with it), the repository it comes from, and
/// the mark of the world for the requested package.
pub fn begin(c: &Candidate, world: bool) -> proto_pkg::Begin<'_> {
    proto_pkg::Begin {
        name: c.name.as_bytes(),
        version: meta_version(&c.version).as_bytes(),
        size: c.size,
        sha256: c.sha256,
        repository: c.repository.as_bytes(),
        flags: if world { proto_pkg::BEGIN_WORLD } else { 0 },
    }
}

/// What `install request` comes to against `pool` and `installed`.
pub fn install(
    request: &str,
    pool: &[Candidate],
    installed: &[Installed],
) -> Result<Outcome, Fault> {
    let (only, name) = match request.split_once('/') {
        Some((repository, name)) => (Some(repository), name),
        None => (None, request),
    };
    if let Some(repository) = only
        && !pool.iter().any(|c| c.repository == repository)
    {
        return Err(Fault::NoRepository(repository.into()));
    }
    if let Some(have) = closed(installed, name) {
        let version = short(&have.version);
        return Ok(if have.flags & ENTRY_IMAGE != 0 {
            Outcome::Present {
                name: have.name.clone(),
                version,
                image: true,
            }
        } else if have.flags & ENTRY_DEPENDENCY != 0 {
            Outcome::Promote {
                name: have.name.clone(),
                version,
            }
        } else {
            Outcome::Present {
                name: have.name.clone(),
                version,
                image: false,
            }
        });
    }
    let at = find(pool, name, only)?;
    let mut walk = Walk {
        pool,
        installed,
        items: Vec::new(),
        notes: Vec::new(),
        stack: Vec::new(),
    };
    walk.visit(at)?;
    if walk.items.len() > GROUP_MAX {
        return Err(Fault::TooMany(name.to_string()));
    }
    if let Some(last) = walk.items.last_mut() {
        last.world = true;
    }
    Ok(Outcome::Install {
        items: walk.items,
        notes: walk.notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn c(repository: &str, name: &str, provides: &[&str], depends: &[&str]) -> Candidate {
        Candidate {
            repository: repository.into(),
            name: name.into(),
            version: "1.0-1".into(),
            provides: provides.iter().map(|s| s.to_string()).collect(),
            depends: depends.iter().map(|s| s.to_string()).collect(),
            needs: vec![],
            size: 100,
            sha256: [name.len() as u8; 32],
            file: format!("{name}.stpkg"),
            source: None,
            license: "MIT".into(),
            summary: "s".into(),
        }
    }

    fn have(name: &str, flags: u32, repository: &str) -> Installed {
        Installed {
            name: name.into(),
            version: "1.0-1".into(),
            sha256: [name.len() as u8; 32],
            flags,
            repository: repository.into(),
            provides: vec![],
            depends: vec![],
        }
    }

    fn names(pool: &[Candidate], items: &[Item]) -> Vec<String> {
        items
            .iter()
            .map(|i| pool[i.candidate].name.clone())
            .collect()
    }

    fn plan(pool: &[Candidate], installed: &[Installed], name: &str) -> (Vec<String>, Vec<Item>) {
        match install(name, pool, installed).unwrap() {
            Outcome::Install { items, .. } => (names(pool, &items), items),
            other => panic!("{other:?}"),
        }
    }

    fn doom_pool() -> Vec<Candidate> {
        vec![
            c("stafeto", "doomgeneric", &["doom"], &["freedoom"]),
            c("stafeto", "freedoom", &[], &[]),
            c("stafeto", "hello", &[], &[]),
        ]
    }

    #[test]
    fn doom_comes_by_provides_with_its_dependency_first() {
        let pool = doom_pool();
        let (order, items) = plan(&pool, &[], "doom");
        assert_eq!(order, ["freedoom", "doomgeneric"]);
        // The requested one is of the world, the dependency is not.
        assert_eq!(
            items.iter().map(|i| i.world).collect::<Vec<_>>(),
            [false, true]
        );
        // The name of the package itself gives the same.
        assert_eq!(plan(&pool, &[], "doomgeneric").0, order);
    }

    #[test]
    fn a_name_of_a_package_is_stronger_than_a_provides() {
        let pool = vec![
            c("stafeto", "other", &["hello"], &[]),
            c("stafeto", "hello", &[], &[]),
        ];
        assert_eq!(plan(&pool, &[], "hello").0, ["hello"]);
    }

    #[test]
    fn two_providers_are_ambiguous_and_none_is_no_name() {
        let pool = vec![
            c("stafeto", "a", &["x"], &[]),
            c("stafeto", "b", &["x"], &[]),
        ];
        let e = install("x", &pool, &[]).unwrap_err();
        assert_eq!(e.line(), "pkg: x: provided by a, b; name one");
        assert_eq!(
            install("nothing", &pool, &[]).unwrap_err().line(),
            "pkg: nothing: no repository has it"
        );
        // One package that lists the name twice is one provider.
        let pool = vec![c("stafeto", "a", &["x"], &[]), c("games", "a", &["x"], &[])];
        assert!(install("x", &pool, &[]).is_ok());
    }

    #[test]
    fn a_dependency_no_repository_has_is_named() {
        let pool = vec![c("stafeto", "doomgeneric", &["doom"], &["freedoom"])];
        assert_eq!(
            install("doom", &pool, &[]).unwrap_err().line(),
            "pkg: doomgeneric: needs freedoom, which no repository has"
        );
    }

    #[test]
    fn a_cycle_is_named_by_its_way() {
        let pool = vec![
            c("stafeto", "a", &[], &["b"]),
            c("stafeto", "b", &[], &["c"]),
            c("stafeto", "c", &[], &["a"]),
        ];
        let e = install("a", &pool, &[]).unwrap_err();
        assert_eq!(e.line(), "pkg: a: dependency cycle a -> b -> c -> a");
        let own = vec![c("stafeto", "a", &[], &["a"])];
        assert_eq!(
            install("a", &own, &[]).unwrap_err().line(),
            "pkg: a: dependency cycle a -> a"
        );
    }

    #[test]
    fn dependencies_come_before_the_packages_that_need_them() {
        // d needs b and c, which need a; each package once.
        let pool = vec![
            c("stafeto", "d", &[], &["b", "c"]),
            c("stafeto", "b", &[], &["a"]),
            c("stafeto", "c", &[], &["a"]),
            c("stafeto", "a", &[], &[]),
        ];
        let (order, _) = plan(&pool, &[], "d");
        assert_eq!(order, ["a", "b", "c", "d"]);
        for (n, name) in order.iter().enumerate() {
            let p = pool.iter().find(|p| p.name == *name).unwrap();
            for dep in &p.depends {
                assert!(order[..n].contains(dep), "{dep} before {name}");
            }
        }
    }

    #[test]
    fn a_group_holds_four_new_packages_and_not_five() {
        let chain = |n: usize| -> Vec<Candidate> {
            (0..n)
                .map(|i| {
                    let dep = format!("p{}", i + 1);
                    let deps: Vec<&str> = if i + 1 < n {
                        vec![dep.as_str()]
                    } else {
                        vec![]
                    };
                    c("stafeto", &format!("p{i}"), &[], &deps)
                })
                .collect()
        };
        let four = chain(4);
        assert_eq!(plan(&four, &[], "p0").0.len(), 4);
        let five = chain(5);
        assert_eq!(
            install("p0", &five, &[]).unwrap_err().line(),
            "pkg: p0: needs more than 4 new packages at once; install some of its dependencies first"
        );
        // Install the first dependency of the five: four remain, the group fits.
        let held = [have("p4", 0, "stafeto")];
        assert_eq!(plan(&five, &held, "p0").0.len(), 4);
    }

    #[test]
    fn an_installed_dependency_is_skipped_and_the_index_that_changed_is_told() {
        let pool = doom_pool();
        let same = [have("freedoom", ENTRY_DEPENDENCY, "stafeto")];
        assert_eq!(plan(&pool, &same, "doom").0, ["doomgeneric"]);
        // The disk has freedoom with another SHA-256 than the index: it stays, and the line says so.
        let mut older = have("freedoom", ENTRY_DEPENDENCY, "stafeto");
        older.sha256 = [0; 32];
        older.version = "0.13.0-1".into();
        match install("doom", &pool, &[older]).unwrap() {
            Outcome::Install { items, notes } => {
                assert_eq!(names(&pool, &items), ["doomgeneric"]);
                assert_eq!(
                    notes,
                    ["freedoom: installed 0.13.0-1, the index has 1.0-1; pkg upgrade replaces it"]
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_package_that_is_there_closes_the_name() {
        let pool = doom_pool();
        let mut image = have("doomgeneric", ENTRY_IMAGE, "stafeto");
        image.provides = vec!["doom".into()];
        assert_eq!(
            install("doom", &pool, &[image]).unwrap(),
            Outcome::Present {
                name: "doomgeneric".into(),
                version: "1.0-1".into(),
                image: true
            }
        );
        let disk = have("hello", 1, "stafeto");
        assert_eq!(
            install("hello", &pool, &[disk]).unwrap(),
            Outcome::Present {
                name: "hello".into(),
                version: "1.0-1".into(),
                image: false
            }
        );
        // A package that is there as a dependency is marked by request, with no download.
        let dependency = have("freedoom", ENTRY_DEPENDENCY, "stafeto");
        assert_eq!(
            install("freedoom", &pool, &[dependency]).unwrap(),
            Outcome::Promote {
                name: "freedoom".into(),
                version: "1.0-1".into()
            }
        );
    }

    #[test]
    fn the_first_repository_wins_and_a_prefix_names_one() {
        let pool = vec![
            c("stafeto", "hello", &[], &[]),
            c("games", "hello", &[], &[]),
            c("games", "only-here", &[], &[]),
        ];
        let (_, items) = plan(&pool, &[], "hello");
        assert_eq!(pool[items[0].candidate].repository, "stafeto");
        let (_, items) = plan(&pool, &[], "games/hello");
        assert_eq!(pool[items[0].candidate].repository, "games");
        assert_eq!(
            install("stafeto/only-here", &pool, &[]).unwrap_err().line(),
            "pkg: only-here: no repository has it"
        );
        assert_eq!(
            install("nowhere/hello", &pool, &[]).unwrap_err().line(),
            "pkg: nowhere: no such repository"
        );
    }

    #[test]
    fn a_plan_is_one_group_that_ends_at_its_last_package() {
        let pool = doom_pool();
        let Outcome::Install { items, .. } = install("doom", &pool, &[]).unwrap() else {
            panic!("an installation");
        };
        let steps = steps(&items);
        assert_eq!(steps.len(), 2);
        assert_eq!(
            steps.iter().map(|s| (s.world, s.end)).collect::<Vec<_>>(),
            [(false, false), (true, true)]
        );
        assert_eq!(
            steps.iter().filter(|s| s.end).count(),
            1,
            "one end for the group"
        );
        // A group of one package ends at it.
        let one = [Item {
            candidate: 2,
            world: true,
        }];
        assert_eq!(super::steps(&one)[0].end, true);
    }

    #[test]
    fn the_version_of_meta_has_no_release() {
        assert_eq!(meta_version("2.0-1"), "2.0");
        assert_eq!(
            meta_version("e257a09527062bfb986b6e5e0780839b6cbd5b71-1"),
            "e257a09527062bfb986b6e5e0780839b6cbd5b71"
        );
        // A version that has dashes keeps them but for the release.
        assert_eq!(meta_version("2026-10-20-1"), "2026-10-20");
        assert_eq!(meta_version("1.0"), "1.0");
    }

    #[test]
    fn begin_carries_the_record_of_the_index() {
        let mut hello = c("games", "hello", &[], &[]);
        hello.version = "2.0-1".into();
        hello.size = 4096;
        hello.sha256 = [7; 32];
        let record = begin(&hello, true);
        assert_eq!(record.name, b"hello");
        // The version of `meta`, with no release.
        assert_eq!(record.version, b"2.0");
        assert_eq!(record.size, 4096);
        assert_eq!(record.sha256, [7; 32]);
        assert_eq!(record.repository, b"games");
        assert_eq!(record.flags, proto_pkg::BEGIN_WORLD);
        assert_eq!(begin(&hello, false).flags, 0);
    }

    #[test]
    fn a_record_is_made_from_an_entry_of_the_index() {
        let entry = Entry {
            name: "doomgeneric",
            version: "e257a09527062bfb986b6e5e0780839b6cbd5b71-1",
            provides: Some("doom"),
            depends: Some("freedoom"),
            needs: Some("display input"),
            license: "GPL-2.0-or-later",
            size: 495_616,
            sha256: &"ab".repeat(32),
            recipe: &"c".repeat(64),
            file: "doomgeneric.stpkg",
            source: Some("src/doomgeneric.tar.xz"),
            summary: "Doom engine",
        };
        let got = Candidate::new("stafeto", &entry).unwrap();
        assert_eq!(got.provides, ["doom"]);
        assert_eq!(got.depends, ["freedoom"]);
        assert_eq!(got.needs, ["display", "input"]);
        assert_eq!(got.sha256, [0xab; 32]);
        let bad = Entry {
            sha256: "zz",
            ..entry
        };
        assert!(Candidate::new("stafeto", &bad).is_none());
    }
}
