// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The package tool `pkg` (pk4-design R1): a program of the system over the
//! POSIX layer. It asks the package service through the session the start
//! gives, downloads with `/bin/curl` as a child, and decides nothing itself:
//! the decisions are in the library (`pkg::config`, `verify`, `resolve`,
//! `fetch`, `output`, `faults`), which `cargo test -p pkg` tests on the host.
//! This part makes the calls and prints what the library says.
//!
//! The output goes to descriptor 1, the lines of refusals (`pkg: ...`) to
//! descriptor 2. Exit codes: 0, 1 for a refused operation, 2 for a bad command line.

#![no_std]
#![no_main]

extern crate alloc;

mod client;
mod spawn;
mod sys;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use client::{Client, cell};
use core::ffi::{c_char, c_int};
use pkg::config::{self, Repository};
use pkg::faults::{self, Detail};
use pkg::fetch::{self, Verdict};
use pkg::output::{self, Available, Installed};
use pkg::resolve::{self, Candidate, Outcome};
use pkg::settings::{self, Settings};
use pkg::verify::{self, Serial, stamp};
use pkg::{EXIT_OK, EXIT_REFUSED, EXIT_USAGE, USAGE, baked};
use pkgfmt::index::Index;
use pkgfmt::{Key, Revocation, Trust, keyfile};
use proto_pkg as p;
use proto_wire::Status;
use rt::abi::Error;

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;

#[global_allocator]
static ALLOCATOR: sys::Malloc = sys::Malloc;

const OFFICIAL_FILE: &str = "/etc/pkg/official";
const ROOTS_FILE: &str = "/etc/pkg/keys/stafeto.pub";
const CACHE: &str = "/var/cache/pkg";
const LICENSES: &str = "/usr/share/licenses";
/// The bytes of a block of the store, which the counts of STATUS are in.
const BLOCK_BYTES: u64 = 4096;

/// A refusal: the line for the standard error.
type Line = String;

#[unsafe(no_mangle)]
extern "C" fn main(argc: isize, argv: *mut *mut c_char, envp: *mut *mut c_char) -> c_int {
    // SAFETY: the C start gives `argc` strings and a NULL-terminated environment.
    let (args, env) = unsafe { (sys::arguments(argc, argv), sys::environment(envp)) };
    let code = run(&args[1.min(args.len())..], &env);
    code as c_int
}

fn run(args: &[String], env: &[(String, String)]) -> i32 {
    let Some((command, rest)) = args.split_first() else {
        sys::err(USAGE);
        return EXIT_USAGE;
    };
    let result = match command.as_str() {
        "install" if !rest.is_empty() => with_tool(env, |t| t.install(rest)),
        "update" if rest.is_empty() => with_tool(env, |t| t.update()),
        "list" if rest.is_empty() || rest == ["--all"] => {
            with_tool(env, |t| t.list(!rest.is_empty()))
        }
        "info" if rest.len() == 1 => with_tool(env, |t| t.info(&rest[0])),
        "search" if rest.len() == 1 => with_tool(env, |t| t.search(&rest[0])),
        "check" if rest.is_empty() => with_tool_raw(env, |t| t.check()),
        "remove" if !rest.is_empty() => with_tool(env, |t| t.remove(rest)),
        "upgrade" => with_tool(env, |t| t.upgrade(rest)),
        "repo" => match rest.iter().map(String::as_str).collect::<Vec<_>>()[..] {
            ["add", name, address, key] => with_tool(env, |t| t.repo_add(name, address, key)),
            ["remove", name] => with_tool(env, |t| t.repo_remove(name)),
            ["list"] => with_tool(env, |t| t.repo_list()),
            ["save"] => with_tool_raw(env, |t| t.repo_save()),
            _ => {
                sys::err(pkg::USAGE_REPO);
                return EXIT_USAGE;
            }
        },
        _ => {
            sys::err(USAGE);
            return EXIT_USAGE;
        }
    };
    let code = match result {
        Ok(code) => code,
        Err(line) => {
            sys::err(&line);
            EXIT_REFUSED
        }
    };
    if spawn::unwaited() {
        sys::err("pkg: a child process ended and was not waited for");
        return EXIT_REFUSED;
    }
    code
}

/// The line of a refusal of the service, or of its end.
fn service(status: Status, subject: &str, d: &Detail<'_>) -> Line {
    match status {
        Status::Kernel(Error::PeerClosed) => faults::SERVICE_GONE.into(),
        Status::Unknown(code) => faults::line(code, subject, d),
        other => format!("pkg: {subject}: unexpected answer of the package service ({other:?})"),
    }
}

/// `f` over a tool, after the check that `/etc/pkg` is what was saved (a line to the standard
/// error when it is not; the exit code does not change).
fn with_tool(
    env: &[(String, String)],
    f: impl FnOnce(&mut Tool) -> Result<i32, Line>,
) -> Result<i32, Line> {
    with_tool_raw(env, |t| {
        if t.etc_differs() == Some(true) {
            sys::err(settings::DIFFERS_LINE);
        }
        f(t)
    })
}

fn with_tool_raw(
    env: &[(String, String)],
    f: impl FnOnce(&mut Tool) -> Result<i32, Line>,
) -> Result<i32, Line> {
    let client = match Client::open() {
        Err(()) => return Err(faults::NO_SERVICE.into()),
        Ok(Err(status)) => return Err(service(status, "the package service", &Detail::default())),
        Ok(Ok(client)) => client,
    };
    let roots = baked::ROOTS
        .iter()
        .filter_map(|line| keyfile::parse_public(line).ok())
        .collect::<Vec<Key>>();
    let proxy: Vec<(&str, &str)> = env.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    let mut tool = Tool {
        client,
        roots,
        curl_env: fetch::environment(proxy),
        repos: Vec::new(),
    };
    f(&mut tool)
}

/// An index that passed the checks, with the records it holds.
struct Fresh {
    repository: Repository,
    candidates: Vec<Candidate>,
}

struct Tool {
    client: Client,
    roots: Vec<Key>,
    curl_env: Vec<String>,
    repos: Vec<Repository>,
}

impl Tool {
    /// The repositories: the official line and the owner's from the settings.
    fn load_repositories(&mut self) -> Result<(), Line> {
        let text = sys::read_file(OFFICIAL_FILE, 4096)
            .and_then(|b| String::from_utf8(b).ok())
            .ok_or_else(|| format!("pkg: {OFFICIAL_FILE}: cannot read it"))?;
        let official = config::parse_official(&text).map_err(|e| e.text(OFFICIAL_FILE))?;
        let blob = self
            .client
            .settings()
            .map_err(|s| service(s, "the settings", &Detail::default()))?;
        let (repos, keyless) = config::from_blob(&blob, Some(official))
            .map_err(|e| e.text("/etc/pkg/repositories"))?;
        for name in keyless {
            sys::err(&format!("pkg: {name}: no key in the settings; skipped"));
        }
        self.repos = repos;
        Ok(())
    }

    fn clock_text(&self) -> String {
        stamp(sys::now())
    }

    /// `url` into memory: at most `max` bytes, exactly `exact` when that is known.
    fn download(&self, url: &str, max: u64, exact: Option<u64>) -> Result<Vec<u8>, Line> {
        let mut child = spawn::start(&fetch::argv(url, max), &self.curl_env)?;
        let mut bytes: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 8192];
        let mut over = false;
        loop {
            let n = child.read(&mut chunk);
            if n == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..n]);
            if bytes.len() as u64 > max {
                over = true;
                break;
            }
        }
        let code = child.finish(over);
        if over {
            return Err(format!("pkg: {url}: larger than {max} bytes"));
        }
        let verdict = fetch::verdict(code, bytes.len() as u64, exact);
        match verdict {
            Verdict::Whole => Ok(bytes),
            v => Err(fetch::failure(
                v,
                url,
                url,
                exact.unwrap_or(max),
                &self.clock_text(),
            )),
        }
    }

    fn trust_of<'a>(&'a self, r: &'a Repository) -> (Vec<Key>, Vec<Key>) {
        match &r.key {
            Some(key) => (Vec::new(), alloc::vec![*key]),
            None => (self.roots.clone(), Vec::new()),
        }
    }

    /// The revocation list of the official repository: downloaded, checked against the
    /// roots, given to the service. The entries that bind the index.
    fn revocations(&self, r: &Repository, quiet: bool) -> Result<Vec<Revocation>, Line> {
        let base = &r.address;
        let list = self.download(&format!("{base}/revoked"), fetch::REVOKED_MAX, None)?;
        let block = self.download(
            &format!("{base}/revoked.sig"),
            fetch::BLOCK_LEN,
            Some(fetch::BLOCK_LEN),
        )?;
        let got = verify::revocations(&list, &block, &self.roots).map_err(|f| f.line(&r.name))?;
        match self.client.revoked_set(&list, &block) {
            Ok(()) => {}
            Err(Status::Unknown(p::ROLLBACK)) => {
                return Err(verify::Fault::Rollback {
                    what: "revocation list",
                    serial: got.serial,
                    held: None,
                }
                .line(&r.name));
            }
            Err(s) => return Err(service(s, &r.name, &Detail::default())),
        }
        // The accepted list stays beside the index, so the cache is checked with it again.
        self.cache(r, &[("revoked", &list), ("revoked.sig", &block)]);
        if !quiet {
            sys::out(&format!(
                "{}: revocation list {} accepted",
                r.name, got.serial
            ));
        }
        Ok(got.entries)
    }

    /// One repository by the steps of R7: its list of revocations (the official one), its
    /// index and signature, the checks, the serial given to the service, the cache.
    /// The line `fetching ... ok (...)` is the progress; a refusal is returned.
    fn refresh(&self, r: &Repository, update: bool) -> Result<Fresh, Line> {
        let entries = if r.is_official() {
            self.revocations(r, !update)?
        } else {
            Vec::new()
        };
        let url = format!("{}/INDEX", r.address);
        sys::out_part(&format!("fetching {url} ... "));
        let got = self.index_of(r, &url, &entries);
        let (data, accepted, held) = match got {
            Ok(got) => got,
            Err(line) => {
                sys::out("failed");
                return Err(line);
            }
        };
        let was = if update {
            format!(", was {held}")
        } else {
            String::new()
        };
        sys::out(&format!(
            "ok (serial {}, signed by {}{was})",
            accepted.serial, accepted.key
        ));
        let text = core::str::from_utf8(&data).map_err(|_| format!("pkg: {}: not text", r.name))?;
        let index =
            Index::parse(text).map_err(|_| format!("pkg: {}: not a valid index", r.name))?;
        let candidates: Vec<Candidate> = index
            .entries()
            .filter_map(|e| Candidate::new(&r.name, &e))
            .collect();
        if update {
            sys::out(&format!(
                "{}: serial {}, was {held}, {} packages, expires {}",
                r.name,
                accepted.serial,
                candidates.len(),
                stamp(accepted.expires)
            ));
        }
        Ok(Fresh {
            repository: r.clone(),
            candidates,
        })
    }

    /// The index and its signature, checked; the serial taken by the service. The
    /// bytes of the index, what it says of itself and the serial held before.
    fn index_of(
        &self,
        r: &Repository,
        url: &str,
        entries: &[Revocation],
    ) -> Result<(Vec<u8>, verify::Accepted, u64), Line> {
        let data = self.download(url, fetch::INDEX_MAX, None)?;
        let sig_url = format!("{}/INDEX.sig", r.address);
        let sig = self.download(&sig_url, fetch::BLOCK_LEN, Some(fetch::BLOCK_LEN))?;
        let (roots, direct) = self.trust_of(r);
        let accepted = verify::index(
            &data,
            &sig,
            &r.name,
            baked::SERIES,
            &Trust {
                roots: &roots,
                direct: &direct,
            },
            entries,
            sys::now(),
        )
        .map_err(|f| f.line(&r.name))?;
        let held = self
            .client
            .serial(&r.name)
            .map_err(|s| service(s, &r.name, &Detail::default()))?;
        match verify::serial(accepted.serial, held) {
            Serial::Older => {
                return Err(verify::Fault::Rollback {
                    what: "index",
                    serial: accepted.serial,
                    held: Some(held),
                }
                .line(&r.name));
            }
            Serial::Same => {}
            Serial::Newer => match self.client.serial_set(&r.name, accepted.serial) {
                Ok(()) => {}
                // Another pkg raised the number between the two requests.
                Err(Status::Unknown(p::ROLLBACK)) => {
                    return Err(verify::Fault::Rollback {
                        what: "index",
                        serial: accepted.serial,
                        held: None,
                    }
                    .line(&r.name));
                }
                Err(s) => return Err(service(s, &r.name, &Detail::default())),
            },
        }
        self.cache(r, &[("INDEX", &data), ("INDEX.sig", &sig)]);
        Ok((data, accepted, held))
    }

    /// The files of the cache of a repository, each made whole (written beside and renamed); a
    /// failure is told and the old file stays.
    fn cache(&self, r: &Repository, files: &[(&str, &Vec<u8>)]) {
        let dir = format!("{CACHE}/{}", r.name);
        sys::make_directories(&dir);
        for (file, bytes) in files {
            if !sys::replace_file(&format!("{dir}/{file}"), bytes) {
                sys::err(&format!("pkg: {dir}/{file}: cannot write the cache"));
            }
        }
    }

    /// Every repository in its order: the ones that pass, and the refusals printed.
    fn refresh_all(&mut self, update: bool) -> Result<(Vec<Fresh>, usize), Line> {
        self.load_repositories()?;
        let mut fresh = Vec::new();
        let mut refused = 0;
        for r in self.repos.clone() {
            match self.refresh(&r, update) {
                Ok(f) => fresh.push(f),
                Err(line) => {
                    sys::err(&line);
                    refused += 1;
                }
            }
        }
        Ok((fresh, refused))
    }

    fn require_root(&self) -> Result<(), Line> {
        if sys::is_root() {
            Ok(())
        } else {
            Err(faults::DENIED.into())
        }
    }

    fn update(&mut self) -> Result<i32, Line> {
        self.require_root()?;
        self.client
            .status()
            .map_err(|s| service(s, "the store", &Detail::default()))?;
        let (_, refused) = self.refresh_all(true)?;
        Ok(pkg::exit_of_reading(refused))
    }

    /// The installed packages with the `provides` and `depends` of their `meta`.
    fn installed(&self) -> Result<Vec<Installed>, Line> {
        self.client
            .status()
            .map_err(|s| service(s, "the store", &Detail::default()))?;
        let mut list = self
            .client
            .list()
            .map_err(|s| service(s, "the store", &Detail::default()))?;
        for i in &mut list {
            let Ok(text) = self.client.meta(&i.name) else {
                continue;
            };
            if let Ok(meta) = pkgfmt::meta::Meta::parse(&text) {
                // The record of the store has the version of `meta`; the index and the lines
                // of `pkg` say `<version>-<release>`.
                i.version = format!("{}-{}", meta.version, meta.release);
                i.provides = pkgfmt::meta::list(meta.provides)
                    .map(String::from)
                    .collect();
                i.depends = pkgfmt::meta::list(meta.depends).map(String::from).collect();
            }
        }
        Ok(list)
    }

    fn install(&mut self, names: &[String]) -> Result<i32, Line> {
        self.require_root()?;
        let installed_before = self.installed()?;
        let (fresh, refused) = self.refresh_all(false)?;
        // A refused repository refuses the whole command: no name is decided among the others.
        if !pkg::may_change_the_store(refused) {
            return Ok(EXIT_REFUSED);
        }
        let pool: Vec<Candidate> = fresh.iter().flat_map(|f| f.candidates.clone()).collect();
        let mut installed = installed_before;
        let mut failed = false;
        for name in names {
            match self.install_one(name, &pool, &installed, &fresh) {
                Ok(()) => installed = self.installed()?,
                Err(line) => {
                    sys::err(&line);
                    failed = true;
                }
            }
        }
        Ok(if failed { EXIT_REFUSED } else { EXIT_OK })
    }

    fn install_one(
        &self,
        request: &str,
        pool: &[Candidate],
        installed: &[Installed],
        fresh: &[Fresh],
    ) -> Result<(), Line> {
        let outcome = resolve::install(request, pool, installed).map_err(|f| f.line())?;
        let (items, notes) = match outcome {
            Outcome::Present {
                name,
                version,
                image,
            } => {
                let how = if image {
                    "part of the image"
                } else {
                    "installed"
                };
                sys::out(&format!("{request}: {name} {version} is {how}"));
                return Ok(());
            }
            Outcome::Promote { name, version } => {
                self.client
                    .world_set(&name, true)
                    .map_err(|s| service(s, &name, &Detail::default()))?;
                sys::out(&format!("{name} {version}: now installed by request"));
                return Ok(());
            }
            Outcome::Install { items, notes } => (items, notes),
        };
        for note in &notes {
            sys::out(note);
        }
        let chosen: Vec<(&Candidate, bool)> = items
            .iter()
            .map(|i| (&pool[i.candidate], i.world))
            .collect();
        let shown: Vec<(&str, &str)> = chosen
            .iter()
            .map(|(c, _)| (c.name.as_str(), c.version.as_str()))
            .collect();
        let bytes: u64 = chosen.iter().map(|(c, _)| c.size).sum();
        sys::out(&output::plan(&shown, bytes));
        for (c, _) in &chosen {
            if !c.needs.is_empty() {
                sys::out(&format!("{} needs {}", c.name, c.needs.join(" ")));
            }
        }
        let mut last = None;
        for step in resolve::steps(&items) {
            let c = &pool[step.candidate];
            let repo = fresh
                .iter()
                .find(|f| f.repository.name == c.repository)
                .map(|f| &f.repository)
                .ok_or_else(|| format!("pkg: {}: no such repository", c.repository))?;
            if let Err(line) = self.receive(c, repo, step, None, &mut last) {
                if let Some(receipt) = last {
                    self.client.cancel(receipt);
                }
                return Err(line);
            }
        }
        let done: Vec<(&str, &str, bool)> = chosen
            .iter()
            .map(|(c, w)| (c.name.as_str(), c.version.as_str(), *w))
            .collect();
        sys::out(&output::installed_line(request, &done));
        Ok(())
    }

    /// One package of a group: BEGIN with the record of the index, the bytes from curl into
    /// FEED, COMMIT. `last` keeps the receipt, which a failure cancels.
    fn receive(
        &self,
        c: &Candidate,
        repo: &Repository,
        step: resolve::Step,
        head: Option<String>,
        last: &mut Option<u32>,
    ) -> Result<(), Line> {
        let url = config::locate(&repo.address, &c.file).map_err(|_| {
            format!(
                "pkg: {}: the file name {:?} is not an address under the repository",
                c.name, c.file
            )
        })?;
        sys::out_part(&match head {
            Some(head) => format!("{head}... "),
            None => format!(
                "{} {}: {} ... ",
                c.name,
                output::short(&c.version),
                output::megabytes(c.size)
            ),
        });
        let detail = Detail {
            size: c.size,
            repository: &repo.name,
            ..Detail::default()
        };
        let record = resolve::begin(c, step.world);
        let receipt = self.client.begin(&record).map_err(|s| {
            sys::out("failed");
            self.refusal(s, &c.name, &detail)
        })?;
        *last = Some(receipt);
        if let Err(line) = self.stream(&url, c, receipt) {
            sys::out("failed");
            return Err(line);
        }
        self.client.commit(receipt, step.end).map_err(|s| {
            sys::out("failed");
            self.refusal(s, &c.name, &detail)
        })?;
        sys::out("ok");
        Ok(())
    }

    /// The refusal of the service, with the free space it may name.
    fn refusal(&self, s: Status, subject: &str, d: &Detail<'_>) -> Line {
        let mut d = *d;
        if matches!(s, Status::Unknown(p::NO_SPACE))
            && let Ok(stat) = self.client.status()
        {
            d.free = stat.free * BLOCK_BYTES;
        }
        service(s, subject, &d)
    }

    /// The package file from curl into the cells of the buffer, a FEED for each cell
    /// that is full and one for the rest. The bytes are counted here: more than the
    /// size stops curl, fewer after a clean end is refused. curl is waited for on
    /// every path.
    fn stream(&self, url: &str, c: &Candidate, receipt: u32) -> Result<(), Line> {
        let mut child = spawn::start(&fetch::argv(url, c.size), &self.curl_env)?;
        let (mut total, mut next) = (0u64, 0u32);
        let mut verdict = None;
        let mut fed = Ok(());
        loop {
            let mut filled = 0usize;
            while filled < p::CELL_BYTES as usize {
                // SAFETY: the cell is in the mapped buffer and `room` bytes of it are free.
                let n = unsafe {
                    child.read_into(cell(next).add(filled), p::CELL_BYTES as usize - filled)
                };
                if n == 0 {
                    break;
                }
                filled += n;
                if !fetch::fits(total, filled, c.size) {
                    break;
                }
            }
            if filled == 0 {
                break;
            }
            if !fetch::fits(total, filled, c.size) {
                verdict = Some(Verdict::TooMany);
                break;
            }
            if let Err(s) = self.client.feed(receipt, next, filled as u32) {
                fed = Err(s);
                break;
            }
            total += filled as u64;
            next = (next + 1) % p::CELLS;
        }
        let stop = verdict.is_some() || fed.is_err();
        let code = child.finish(stop);
        if let Err(s) = fed {
            let d = Detail {
                size: c.size,
                ..Detail::default()
            };
            return Err(service(s, &c.name, &d));
        }
        let verdict = verdict.unwrap_or_else(|| fetch::verdict(code, total, Some(c.size)));
        match verdict {
            Verdict::Whole => Ok(()),
            v => Err(fetch::failure(v, url, &c.name, c.size, &self.clock_text())),
        }
    }

    /// `pkg remove`: the named packages and the dependencies nothing needs any more, in as few
    /// requests as the service takes.
    fn remove(&mut self, names: &[String]) -> Result<i32, Line> {
        self.require_root()?;
        let installed = self.installed()?;
        let plan = resolve::remove(names, &installed).map_err(|f| f.line())?;
        self.take_away(&plan, &installed)?;
        Ok(EXIT_OK)
    }

    /// The packages of `plan` go, batch by batch, and the line of the removal is printed.
    fn take_away(&self, plan: &resolve::RemovePlan, installed: &[Installed]) -> Result<(), Line> {
        for batch in plan.batches() {
            let names: Vec<&str> = batch.iter().map(|&i| installed[i].name.as_str()).collect();
            self.client
                .remove(&names)
                .map_err(|s| service(s, names[0], &Detail::default()))?;
        }
        let gone: Vec<(&str, &str, bool)> = plan
            .order
            .iter()
            .map(|&i| {
                (
                    installed[i].name.as_str(),
                    installed[i].version.as_str(),
                    !plan.named.contains(&i),
                )
            })
            .collect();
        if !gone.is_empty() {
            sys::out(&output::removed_line(&gone));
        }
        Ok(())
    }

    /// `pkg upgrade`: a package whose own repository's index has another SHA-256 is replaced, with
    /// the flag of the world it had; then the dependencies nothing needs any more go. A refused
    /// repository refuses the whole command, as for `install`.
    fn upgrade(&mut self, names: &[String]) -> Result<i32, Line> {
        self.require_root()?;
        let installed = self.installed()?;
        let (fresh, refused) = self.refresh_all(false)?;
        if !pkg::may_change_the_store(refused) {
            return Ok(EXIT_REFUSED);
        }
        let pool: Vec<Candidate> = fresh.iter().flat_map(|f| f.candidates.clone()).collect();
        let plan = resolve::upgrade(names, &pool, &installed);
        for line in &plan.kept {
            sys::out(line);
        }
        let mut failed = !plan.refused.is_empty();
        for line in &plan.refused {
            sys::err(line);
        }
        let mut done = 0;
        for r in &plan.replacements {
            let old = &installed[r.installed];
            let mut last = None;
            let mut went = Ok(());
            for step in resolve::steps(&r.items) {
                let c = &pool[step.candidate];
                let head = step
                    .end
                    .then(|| output::upgrading(&old.name, &old.version, &c.version, c.size));
                let Some(repo) = fresh
                    .iter()
                    .find(|f| f.repository.name == c.repository)
                    .map(|f| &f.repository)
                else {
                    went = Err(format!("pkg: {}: no such repository", c.repository));
                    break;
                };
                went = self.receive(c, repo, step, head, &mut last);
                if went.is_err() {
                    break;
                }
            }
            match went {
                Ok(()) => done += 1,
                Err(line) => {
                    if let Some(receipt) = last {
                        self.client.cancel(receipt);
                    }
                    sys::err(&line);
                    failed = true;
                }
            }
        }
        if done > 0 {
            // A new record may need fewer packages than the old one did.
            let now = self.installed()?;
            let orphans = resolve::remove(&[], &now).map_err(|f| f.line())?;
            self.take_away(&orphans, &now)?;
        } else if plan.kept.is_empty() && !failed {
            sys::out("nothing to upgrade");
        }
        Ok(if failed { EXIT_REFUSED } else { EXIT_OK })
    }

    /// The settings the service holds, as the blob and as settings.
    fn saved(&self) -> Result<(Vec<u8>, Settings), Line> {
        let blob = self
            .client
            .settings()
            .map_err(|s| service(s, "the settings", &Detail::default()))?;
        let settings = Settings::from_blob(&blob).map_err(|e| e.text("/etc/pkg/repositories"))?;
        Ok((blob, settings))
    }

    fn save(&self, settings: &Settings) -> Result<(), Line> {
        self.client
            .settings_set(&settings.to_blob())
            .map_err(|s| service(s, "/etc/pkg/repositories", &Detail::default()))
    }

    /// `pkg repo add <name> <address> <key file>`: the key is the one the file holds, which the
    /// owner brought; it is never fetched from the repository. It trusts this repository alone.
    fn repo_add(&mut self, name: &str, address: &str, key_path: &str) -> Result<i32, Line> {
        self.require_root()?;
        let text = sys::read_file(key_path, 4096)
            .and_then(|b| String::from_utf8(b).ok())
            .ok_or_else(|| format!("pkg: {key_path}: cannot read it"))?;
        let installed = self.installed()?;
        let (_, mut settings) = self.saved()?;
        let key = settings
            .add(name, address, &text, &installed)
            .map_err(|r| match r {
                settings::Refusal::Key(_) => settings::Refusal::Key(key_path.into()).line(),
                other => other.line(),
            })?;
        self.save(&settings)?;
        sys::out(&settings::added_line(name, &key));
        Ok(EXIT_OK)
    }

    /// `pkg repo remove <name>`: the line and the key go at once, unless a package of it stands.
    fn repo_remove(&mut self, name: &str) -> Result<i32, Line> {
        self.require_root()?;
        let installed = self.installed()?;
        let (_, mut settings) = self.saved()?;
        settings.remove(name, &installed).map_err(|r| r.line())?;
        self.save(&settings)?;
        sys::out(&format!("{name}: removed"));
        Ok(EXIT_OK)
    }

    /// `pkg repo list`: the official repository, then the owner's with the fingerprints.
    fn repo_list(&mut self) -> Result<i32, Line> {
        let text = sys::read_file(OFFICIAL_FILE, 4096)
            .and_then(|b| String::from_utf8(b).ok())
            .ok_or_else(|| format!("pkg: {OFFICIAL_FILE}: cannot read it"))?;
        let official = config::parse_official(&text).map_err(|e| e.text(OFFICIAL_FILE))?;
        let (_, settings) = self.saved()?;
        let off = |name: &str| {
            settings
                .lines
                .iter()
                .any(|l| matches!(l, config::Line::Disable { name: n } if n == name))
        };
        let roots: Vec<&str> = self.roots.iter().map(|k| k.name.as_str()).collect();
        sys::out(&output::repository(
            &official.name,
            &official.address,
            &format!("roots {}", roots.join(" ")),
            off(&official.name),
        ));
        for line in &settings.lines {
            let config::Line::Add { name, address } = line else {
                continue;
            };
            let trust = settings
                .keys
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, k)| format!("key {} {}", k.name.as_str(), settings::fingerprint(k)))
                .unwrap_or_else(|| "no key".into());
            sys::out(&output::repository(name, address, &trust, off(name)));
        }
        Ok(EXIT_OK)
    }

    /// `pkg repo save`: the files of `/etc/pkg` the owner edited become the saved settings.
    fn repo_save(&mut self) -> Result<i32, Line> {
        self.require_root()?;
        let text = sys::read_file("/etc/pkg/repositories", 65_536)
            .map(|b| {
                String::from_utf8(b).map_err(|_| "pkg: /etc/pkg/repositories: not text".to_string())
            })
            .transpose()?;
        let keys: Vec<(String, Option<String>)> = Settings::names(text.as_deref())
            .into_iter()
            .map(|n| {
                let file = sys::read_file(&format!("/etc/pkg/keys/{n}.pub"), 4096)
                    .and_then(|b| String::from_utf8(b).ok());
                (n, file)
            })
            .collect();
        let settings = Settings::from_files(text.as_deref(), &keys)?;
        self.save(&settings)?;
        let n = settings
            .lines
            .iter()
            .filter(|l| matches!(l, config::Line::Add { .. }))
            .count();
        sys::out(&format!("saved {n} repositories"));
        Ok(EXIT_OK)
    }

    /// Whether the files of `/etc/pkg` differ from the saved settings; None when that cannot be told.
    fn etc_differs(&self) -> Option<bool> {
        let blob = self.client.settings().ok()?;
        let text = sys::read_file("/etc/pkg/repositories", 65_536);
        let as_text = text.as_deref().and_then(|b| core::str::from_utf8(b).ok());
        let keys: Vec<(String, Option<Vec<u8>>)> = settings::watched(&blob, as_text)
            .into_iter()
            .map(|n| {
                let file = sys::read_file(&format!("/etc/pkg/keys/{n}.pub"), 4096);
                (n, file)
            })
            .collect();
        Some(settings::differs(&blob, text.as_deref(), &keys))
    }

    fn list(&mut self, all: bool) -> Result<i32, Line> {
        let installed = self.installed()?;
        let (available, refused) = if all {
            let c = self.cached()?;
            (c.0, c.3)
        } else {
            (Vec::new(), 0)
        };
        for line in output::list(&installed, &available, all) {
            sys::out(&line);
        }
        Ok(pkg::exit_of_reading(refused))
    }

    /// The records of the cached indexes, checked again: every repository's `INDEX` and
    /// `INDEX.sig` of the last `update`, and whether any was there.
    fn cached(&mut self) -> Result<(Vec<Available>, Vec<Candidate>, bool, usize), Line> {
        self.load_repositories()?;
        let mut found = false;
        let mut refused = 0;
        let mut candidates = Vec::new();
        for r in &self.repos {
            let dir = format!("{CACHE}/{}", r.name);
            let (Some(data), Some(sig)) = (
                sys::read_file(&format!("{dir}/INDEX"), fetch::INDEX_MAX as usize + 1),
                sys::read_file(&format!("{dir}/INDEX.sig"), 4096),
            ) else {
                continue;
            };
            found = true;
            let (roots, direct) = self.trust_of(r);
            let entries = if r.is_official() {
                match (
                    sys::read_file(&format!("{dir}/revoked"), fetch::REVOKED_MAX as usize + 1),
                    sys::read_file(&format!("{dir}/revoked.sig"), 4096),
                ) {
                    (Some(list), Some(block)) => {
                        match verify::revocations(&list, &block, &self.roots) {
                            Ok(got) => got.entries,
                            Err(f) => {
                                sys::err(&f.line(&r.name));
                                refused += 1;
                                continue;
                            }
                        }
                    }
                    _ => Vec::new(),
                }
            } else {
                Vec::new()
            };
            let checked = verify::index(
                &data,
                &sig,
                &r.name,
                baked::SERIES,
                &Trust {
                    roots: &roots,
                    direct: &direct,
                },
                &entries,
                sys::now(),
            );
            if let Err(f) = checked {
                sys::err(&f.line(&r.name));
                refused += 1;
                continue;
            }
            let Some(text) = core::str::from_utf8(&data).ok() else {
                continue;
            };
            let Ok(index) = Index::parse(text) else {
                continue;
            };
            candidates.extend(index.entries().filter_map(|e| Candidate::new(&r.name, &e)));
        }
        Ok((
            candidates.iter().map(Candidate::available).collect(),
            candidates,
            found,
            refused,
        ))
    }

    fn search(&mut self, word: &str) -> Result<i32, Line> {
        let (available, _, found, refused) = self.cached()?;
        if !found {
            return Err("pkg: no index yet; pkg update".into());
        }
        let installed = self.installed()?;
        for line in output::search(word, &available, &installed) {
            sys::out(&line);
        }
        Ok(pkg::exit_of_reading(refused))
    }

    fn info(&mut self, name: &str) -> Result<i32, Line> {
        let installed = self.installed()?;
        let have = installed.iter().find(|i| i.name == name).or_else(|| {
            installed
                .iter()
                .find(|i| i.provides.iter().any(|p| p == name))
        });
        if let Some(i) = have {
            let text = self
                .client
                .meta(&i.name)
                .map_err(|s| service(s, &i.name, &Detail::default()))?;
            let meta = pkgfmt::meta::Meta::parse(&text)
                .map_err(|_| format!("pkg: {}: the package's meta is not valid", i.name))?;
            let dir = format!("{LICENSES}/{}", i.name);
            let mut notices = Vec::new();
            let mut source = String::new();
            for file in ["LICENSE", "SOURCE"] {
                if let Some(bytes) = sys::read_file(&format!("{dir}/{file}"), 65_536) {
                    notices.push(format!("{dir}/{file}"));
                    if file == "SOURCE" {
                        source = String::from_utf8_lossy(&bytes).into_owned();
                    }
                }
            }
            let state = if i.in_image() {
                "part of the image"
            } else if i.flags & p::ENTRY_DEPENDENCY != 0 {
                "installed (dependency)"
            } else {
                "installed (by request)"
            };
            let words =
                |v: &str| -> Vec<String> { pkgfmt::meta::list(v).map(String::from).collect() };
            let mut sha = [0u8; 64];
            let hex = pkgfmt::sha::hex(&i.sha256, &mut sha);
            for line in output::info(&output::Info {
                name: meta.name,
                version: &format!("{}-{}", meta.version, meta.release),
                provides: &words(meta.provides),
                depends: &words(meta.depends),
                needs: &words(meta.needs),
                license: meta.license,
                summary: meta.summary,
                repository: &i.repository,
                state,
                size: meta.size,
                sha256: hex,
                notices: &notices,
                source: &source,
            }) {
                sys::out(&line);
            }
            return Ok(EXIT_OK);
        }
        let (_, candidates, found, refused) = self.cached()?;
        if !found {
            return Err(format!(
                "pkg: {name}: not installed, and no index yet; pkg update"
            ));
        }
        let at = candidates
            .iter()
            .position(|c| c.name == name)
            .or_else(|| {
                candidates
                    .iter()
                    .position(|c| c.provides.iter().any(|p| p == name))
            })
            .ok_or_else(|| format!("pkg: {name}: no repository has it"))?;
        let c = &candidates[at];
        let mut sha = [0u8; 64];
        let hex = pkgfmt::sha::hex(&c.sha256, &mut sha);
        for line in output::info(&output::Info {
            name: &c.name,
            version: &c.version,
            provides: &c.provides,
            depends: &c.depends,
            needs: &c.needs,
            license: &c.license,
            summary: &c.summary,
            repository: &c.repository,
            state: "available",
            size: c.size,
            sha256: hex,
            notices: &[],
            source: c.source.as_deref().unwrap_or(""),
        }) {
            sys::out(&line);
        }
        Ok(pkg::exit_of_reading(refused))
    }

    fn check(&mut self) -> Result<i32, Line> {
        let stat = self
            .client
            .status()
            .map_err(|s| service(s, "the store", &Detail::default()))?;
        let list = self
            .client
            .list()
            .map_err(|s| service(s, "the store", &Detail::default()))?;
        let image = list.iter().filter(|i| i.in_image()).count() as u32;
        let revoked = list
            .iter()
            .filter(|i| i.flags & p::ENTRY_REVOKED != 0)
            .count() as u32;
        let names: Vec<String> = self
            .roots
            .iter()
            .map(|k| k.name.as_str().to_string())
            .collect();
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        let (lines, mut well) = output::check(&output::Check {
            generation: stat.generation,
            blocks: stat.blocks,
            free: stat.free,
            block_bytes: BLOCK_BYTES,
            flags: stat.flags,
            disk: list.len() as u32 - image,
            image,
            revoked,
            roots: &names,
        });
        for line in lines {
            sys::out(&line);
        }
        match self.etc_differs() {
            Some(false) => sys::out("settings saved"),
            Some(true) => {
                sys::err(settings::DIFFERS_LINE);
                well = false;
            }
            None => {}
        }
        // The file of the roots shows people what the build trusts; it must be that.
        let baked: String = baked::ROOTS.concat();
        match sys::read_file(ROOTS_FILE, 4096) {
            Some(file) if file == baked.as_bytes() => {}
            _ => {
                sys::err(&format!(
                    "pkg: {ROOTS_FILE} is not the roots this build trusts"
                ));
                well = false;
            }
        }
        Ok(if well { EXIT_OK } else { EXIT_REFUSED })
    }
}
