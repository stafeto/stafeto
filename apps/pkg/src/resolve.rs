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
use proto_pkg::{ENTRY_DEPENDENCY, ENTRY_IMAGE, ENTRY_REVOKED, ENTRY_WORLD, REMOVE_MAX};

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

/// The place in `installed` of the package that answers `name`: its own name first, then a `provides`.
fn closed_at(installed: &[Installed], name: &str) -> Option<usize> {
    installed.iter().position(|i| i.name == name).or_else(|| {
        installed
            .iter()
            .position(|i| i.provides.iter().any(|p| p == name))
    })
}

/// Why a removal is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RemoveFault {
    NotInstalled(String),
    InImage(String),
    /// A package that stays needs the named one: `package` is needed by `by`.
    NeededBy {
        package: String,
        by: String,
    },
}

impl RemoveFault {
    pub fn line(&self) -> String {
        match self {
            RemoveFault::NotInstalled(name) => format!("pkg: {name}: not installed"),
            RemoveFault::InImage(name) => format!("pkg: {name}: part of the image"),
            RemoveFault::NeededBy { package, by } => {
                format!("pkg: {package}: needed by {by}")
            }
        }
    }
}

/// What a removal comes to: the places in the list of installed packages of what goes, dependents
/// before the packages they need, and which of them were asked for. The rest go because nothing
/// that stays needs them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemovePlan {
    pub order: Vec<usize>,
    pub named: Vec<usize>,
}

impl RemovePlan {
    /// The names a REMOVE takes at a time (`REMOVE_MAX`), in the order of the plan: a package
    /// goes in the same request as, or after, the packages that need it, so every state between
    /// two requests is one the service accepts.
    pub fn batches(&self) -> Vec<Vec<usize>> {
        self.order
            .chunks(REMOVE_MAX as usize)
            .map(<[usize]>::to_vec)
            .collect()
    }
}

/// `pkg remove names`: the named packages and the packages of the disk that the world that
/// stays no longer needs (the world is the packages not marked as dependencies, less the named
/// ones; what it needs is the closure of its `depends`). With no name, the packages nothing needs.
pub fn remove(names: &[String], installed: &[Installed]) -> Result<RemovePlan, RemoveFault> {
    let mut named: Vec<usize> = Vec::new();
    for name in names {
        let at =
            closed_at(installed, name).ok_or_else(|| RemoveFault::NotInstalled(name.clone()))?;
        if installed[at].in_image() {
            return Err(RemoveFault::InImage(installed[at].name.clone()));
        }
        if !named.contains(&at) {
            named.push(at);
        }
    }
    let n = installed.len();
    let mut keep = alloc::vec![false; n];
    // (package, the package that needs it); the roots are the world that stays.
    let mut work: Vec<(usize, Option<usize>)> = (0..n)
        .rev()
        .filter(|&i| {
            !installed[i].in_image()
                && installed[i].flags & ENTRY_DEPENDENCY == 0
                && !named.contains(&i)
        })
        .map(|i| (i, None))
        .collect();
    while let Some((at, by)) = work.pop() {
        if let (true, Some(by)) = (named.contains(&at), by) {
            return Err(RemoveFault::NeededBy {
                package: installed[at].name.clone(),
                by: installed[by].name.clone(),
            });
        }
        if keep[at] {
            continue;
        }
        keep[at] = true;
        for dep in installed[at].depends.iter().rev() {
            if let Some(d) = closed_at(installed, dep)
                && !installed[d].in_image()
            {
                work.push((d, Some(at)));
            }
        }
    }
    let gone: Vec<usize> = (0..n)
        .filter(|&i| !installed[i].in_image() && !keep[i])
        .collect();
    // Dependents first: the reverse of the order that puts every package after what it needs.
    let mut seen: Vec<usize> = Vec::new();
    let mut post: Vec<usize> = Vec::new();
    for &g in &gone {
        postorder(g, installed, &gone, &mut seen, &mut post);
    }
    post.reverse();
    Ok(RemovePlan { order: post, named })
}

fn postorder(
    at: usize,
    installed: &[Installed],
    gone: &[usize],
    seen: &mut Vec<usize>,
    out: &mut Vec<usize>,
) {
    if seen.contains(&at) {
        return;
    }
    seen.push(at);
    for dep in &installed[at].depends {
        if let Some(d) = closed_at(installed, dep)
            && gone.contains(&d)
        {
            postorder(d, installed, gone, seen, out);
        }
    }
    out.push(at);
}

/// One package of the disk the index has another build of: the packages to receive (the new
/// dependencies first, the package last, which keeps the world flag the old one had) and the place of
/// the old one in the list of installed packages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Replacement {
    pub installed: usize,
    pub items: Vec<Item>,
}

/// What `pkg upgrade` comes to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UpgradePlan {
    pub replacements: Vec<Replacement>,
    /// Lines about packages the index of their repository does not have: they stay.
    pub kept: Vec<String>,
    /// Lines of refusals; the exit code is 1 when there is one.
    pub refused: Vec<String>,
}

/// `pkg upgrade names` (all of the disk when none): a package whose repository's index has another
/// SHA-256 for its name is replaced (the same repository, never another's). A package of the
/// image never is. The same SHA-256 changes nothing and downloads nothing.
pub fn upgrade(names: &[String], pool: &[Candidate], installed: &[Installed]) -> UpgradePlan {
    let mut plan = UpgradePlan::default();
    let mut targets: Vec<usize> = Vec::new();
    if names.is_empty() {
        targets.extend((0..installed.len()).filter(|&i| !installed[i].in_image()));
    }
    for name in names {
        match closed_at(installed, name) {
            None => plan
                .refused
                .push(RemoveFault::NotInstalled(name.clone()).line()),
            Some(at) if installed[at].in_image() => plan
                .refused
                .push(RemoveFault::InImage(installed[at].name.clone()).line()),
            Some(at) if !targets.contains(&at) => targets.push(at),
            Some(_) => {}
        }
    }
    for at in targets {
        let have = &installed[at];
        let Some(found) = pool
            .iter()
            .position(|c| c.name == have.name && c.repository == have.repository)
        else {
            plan.kept.push(format!(
                "{}: not in the index of {}, kept",
                have.name, have.repository
            ));
            continue;
        };
        if pool[found].sha256 == have.sha256 {
            if have.flags & ENTRY_REVOKED != 0 {
                plan.refused.push(format!(
                    "pkg: {}: signed by a revoked key and the index has no other build",
                    have.name
                ));
            }
            continue;
        }
        let mut walk = Walk {
            pool,
            installed,
            items: Vec::new(),
            notes: Vec::new(),
            stack: Vec::new(),
        };
        if let Err(fault) = walk.visit(found) {
            plan.refused.push(fault.line());
            continue;
        }
        if walk.items.len() > GROUP_MAX {
            plan.refused.push(Fault::TooMany(have.name.clone()).line());
            continue;
        }
        let mut items = walk.items;
        if let Some(last) = items.last_mut() {
            last.world = have.flags & ENTRY_WORLD != 0;
        }
        plan.replacements.push(Replacement {
            installed: at,
            items,
        });
    }
    plan
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
        assert!(super::steps(&one)[0].end);
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

    fn disk(name: &str, flags: u32, depends: &[&str]) -> Installed {
        let mut i = have(name, flags, "stafeto");
        i.depends = depends.iter().map(|s| s.to_string()).collect();
        i
    }

    fn gone(plan: &RemovePlan, installed: &[Installed]) -> Vec<String> {
        plan.order
            .iter()
            .map(|&i| installed[i].name.clone())
            .collect()
    }

    fn doom_disk() -> Vec<Installed> {
        vec![
            have("busybox", ENTRY_IMAGE, "stafeto"),
            disk("doomgeneric", ENTRY_WORLD, &["freedoom"]),
            disk("freedoom", ENTRY_DEPENDENCY, &[]),
        ]
    }

    #[test]
    fn removing_doom_removes_its_dependency_that_nothing_else_needs() {
        let held = doom_disk();
        let plan = remove(&["doom".to_string()], &{
            let mut h = held.clone();
            h[1].provides = vec!["doom".into()];
            h
        })
        .unwrap();
        // The requested one first, the package it needed after it.
        assert_eq!(gone(&plan, &held), ["doomgeneric", "freedoom"]);
        assert_eq!(plan.named, [1]);
        assert_eq!(plan.batches(), [vec![1, 2]]);
    }

    #[test]
    fn a_package_the_world_that_stays_needs_is_named_with_the_package_that_needs_it() {
        let held = doom_disk();
        let e = remove(&["freedoom".to_string()], &held).unwrap_err();
        assert_eq!(e.line(), "pkg: freedoom: needed by doomgeneric");
        // Two packages, the second needs the first by a dependency chain: the nearest is named.
        let chain = vec![
            disk("top", ENTRY_WORLD, &["mid"]),
            disk("mid", ENTRY_DEPENDENCY, &["low"]),
            disk("low", ENTRY_DEPENDENCY, &[]),
        ];
        assert_eq!(
            remove(&["low".to_string()], &chain).unwrap_err().line(),
            "pkg: low: needed by mid"
        );
        // Both named: nothing that stays needs them.
        let both = remove(&["top".to_string(), "mid".to_string()], &chain).unwrap();
        assert_eq!(gone(&both, &chain), ["top", "mid", "low"]);
    }

    #[test]
    fn the_world_stays_and_a_package_asked_for_is_not_a_dependency_that_goes() {
        // `lib` was asked for after `app` pulled it in: it is of the world, and `app` may go alone.
        let held = vec![
            disk("app", ENTRY_WORLD, &["lib"]),
            disk("lib", ENTRY_WORLD, &[]),
        ];
        let plan = remove(&["app".to_string()], &held).unwrap();
        assert_eq!(gone(&plan, &held), ["app"]);
        // Without the flag, `lib` goes with `app` (the removal of a package of the world drops what
        // only it needed).
        let held = vec![
            disk("app", ENTRY_WORLD, &["lib"]),
            disk("lib", ENTRY_DEPENDENCY, &[]),
        ];
        assert_eq!(
            gone(&remove(&["app".to_string()], &held).unwrap(), &held),
            ["app", "lib"]
        );
        // And `lib` alone is refused while `app` stands.
        assert_eq!(
            remove(&["lib".to_string()], &held).unwrap_err().line(),
            "pkg: lib: needed by app"
        );
    }

    #[test]
    fn a_dependency_two_packages_need_stays_until_both_go() {
        let held = vec![
            disk("a", ENTRY_WORLD, &["shared"]),
            disk("b", ENTRY_WORLD, &["shared"]),
            disk("shared", ENTRY_DEPENDENCY, &[]),
        ];
        assert_eq!(
            gone(&remove(&["a".to_string()], &held).unwrap(), &held),
            ["a"]
        );
        let both = remove(&["a".to_string(), "b".to_string()], &held).unwrap();
        let order = gone(&both, &held);
        assert_eq!(order.len(), 3);
        // The package two others need goes after both.
        assert_eq!(order[2], "shared");
    }

    #[test]
    fn the_image_and_the_unknown_are_refused_by_name() {
        let held = doom_disk();
        assert_eq!(
            remove(&["busybox".to_string()], &held).unwrap_err().line(),
            "pkg: busybox: part of the image"
        );
        assert_eq!(
            remove(&["doom".to_string()], &held).unwrap_err().line(),
            "pkg: doom: not installed"
        );
    }

    #[test]
    fn a_removal_of_more_than_eight_goes_in_requests_with_the_dependents_first() {
        // A chain of ten: p0 of the world needs p1, which needs p2, and so on.
        let held: Vec<Installed> = (0..10)
            .map(|i| {
                let next = format!("p{}", i + 1);
                let deps: Vec<&str> = if i < 9 { vec![next.as_str()] } else { vec![] };
                disk(
                    &format!("p{i}"),
                    if i == 0 {
                        ENTRY_WORLD
                    } else {
                        ENTRY_DEPENDENCY
                    },
                    &deps,
                )
            })
            .collect();
        let plan = remove(&["p0".to_string()], &held).unwrap();
        assert_eq!(plan.order, (0..10).collect::<Vec<_>>());
        let batches = plan.batches();
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].len(), 8);
        assert_eq!(batches[1], [8, 9]);
        // Each request leaves only a state the service accepts: nothing that stays needs what went.
        let mut went: Vec<usize> = Vec::new();
        for batch in &batches {
            went.extend(batch);
            for &i in &went {
                for (j, other) in held.iter().enumerate() {
                    if !went.contains(&j) {
                        assert!(!other.depends.contains(&held[i].name), "{j} needs {i}");
                    }
                }
            }
        }
    }

    #[test]
    fn nothing_named_removes_the_dependencies_nothing_needs() {
        let held = vec![
            disk("app", ENTRY_WORLD, &["lib"]),
            disk("lib", ENTRY_DEPENDENCY, &[]),
            disk("old", ENTRY_DEPENDENCY, &[]),
        ];
        let plan = remove(&[], &held).unwrap();
        assert_eq!(gone(&plan, &held), ["old"]);
        assert!(remove(&[], &doom_disk()).unwrap().order.is_empty());
    }

    fn newer(c: &mut Candidate, byte: u8) {
        c.sha256 = [byte; 32];
        c.version = "2.0-1".into();
    }

    fn pair() -> (Vec<Candidate>, Vec<Installed>) {
        let pool = doom_pool();
        let mut held = vec![
            have("doomgeneric", ENTRY_WORLD, "stafeto"),
            have("freedoom", ENTRY_DEPENDENCY, "stafeto"),
        ];
        // The records of the disk are those of the pool.
        for h in &mut held {
            h.sha256 = pool.iter().find(|c| c.name == h.name).unwrap().sha256;
        }
        (pool, held)
    }

    #[test]
    fn upgrade_replaces_only_a_package_whose_sha256_differs_in_its_own_index() {
        let (mut pool, held) = pair();
        let plan = upgrade(&[], &pool, &held);
        // The same SHA-256 everywhere: nothing, no download.
        assert_eq!(plan, UpgradePlan::default());
        newer(&mut pool[0], 9);
        let plan = upgrade(&[], &pool, &held);
        assert_eq!(plan.replacements.len(), 1);
        assert_eq!(plan.replacements[0].installed, 0);
        assert_eq!(names(&pool, &plan.replacements[0].items), ["doomgeneric"]);
        // Breakage 19: freedoom, with the same SHA-256, is not in the plan.
        assert!(plan.replacements.iter().all(|r| r.installed != 1));
    }

    #[test]
    fn upgrade_keeps_the_flag_of_the_world_the_package_had() {
        let (mut pool, mut held) = pair();
        newer(&mut pool[0], 9);
        newer(&mut pool[1], 6);
        let plan = upgrade(&[], &pool, &held);
        let world = |r: &Replacement| r.items.last().unwrap().world;
        assert_eq!(plan.replacements.len(), 2);
        assert!(world(&plan.replacements[0]));
        assert!(!world(&plan.replacements[1]));
        // Breakage 20: a dependency stays a dependency, a request stays a request.
        held[0].flags = ENTRY_WORLD | ENTRY_REVOKED;
        assert!(world(&upgrade(&[], &pool, &held).replacements[0]));
    }

    #[test]
    fn upgrade_receives_the_new_dependencies_of_the_new_record_in_one_group() {
        let (mut pool, held) = pair();
        newer(&mut pool[0], 9);
        pool[0].depends = vec!["freedoom".into(), "extra".into()];
        pool.push(c("stafeto", "extra", &[], &[]));
        let plan = upgrade(&["doom".to_string()], &pool, &held);
        // `doom` is a provides of the new record only: the installed one has none, so it is not found.
        assert_eq!(plan.refused, ["pkg: doom: not installed"]);
        let plan = upgrade(&["doomgeneric".to_string()], &pool, &held);
        let r = &plan.replacements[0];
        assert_eq!(names(&pool, &r.items), ["extra", "doomgeneric"]);
        assert_eq!(
            r.items.iter().map(|i| i.world).collect::<Vec<_>>(),
            [false, true]
        );
        let steps = steps(&r.items);
        assert_eq!(steps.iter().filter(|s| s.end).count(), 1);
    }

    #[test]
    fn upgrade_takes_the_record_of_the_repository_the_package_came_from() {
        let (mut pool, mut held) = pair();
        // Another repository has another build of the name: not the one to take.
        let mut other = c("games", "freedoom", &[], &[]);
        other.sha256 = [1; 32];
        pool.push(other);
        assert_eq!(upgrade(&[], &pool, &held), UpgradePlan::default());
        // A package whose repository's index lacks it stays, with a line.
        held.push(have("hello-games", 1, "games"));
        let plan = upgrade(&[], &pool, &held);
        assert_eq!(plan.kept, ["hello-games: not in the index of games, kept"]);
        assert!(plan.replacements.is_empty());
    }

    #[test]
    fn upgrade_never_touches_the_image_and_names_what_it_cannot() {
        let (mut pool, mut held) = pair();
        pool.push(c("stafeto", "busybox", &[], &[]));
        held.push(have("busybox", ENTRY_IMAGE, "stafeto"));
        newer(pool.last_mut().unwrap(), 5);
        assert_eq!(upgrade(&[], &pool, &held), UpgradePlan::default());
        let plan = upgrade(&["busybox".to_string(), "nobody".to_string()], &pool, &held);
        assert_eq!(
            plan.refused,
            [
                "pkg: busybox: part of the image",
                "pkg: nobody: not installed"
            ]
        );
    }

    #[test]
    fn a_revoked_package_is_replaced_by_another_build_and_refused_without_one() {
        let (mut pool, mut held) = pair();
        held[1].flags |= ENTRY_REVOKED;
        let plan = upgrade(&[], &pool, &held);
        assert_eq!(
            plan.refused,
            ["pkg: freedoom: signed by a revoked key and the index has no other build"]
        );
        newer(&mut pool[1], 7);
        let plan = upgrade(&[], &pool, &held);
        assert!(plan.refused.is_empty());
        assert_eq!(plan.replacements.len(), 1);
    }
}
