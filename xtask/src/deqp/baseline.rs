// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The sets of dEQP cases, the baseline of the same Mesa and the same
//! VK-GL-CTS on Linux (`cargo xtask deqp-reference`, files
//! `tests/deqp/baseline/<set>.txt`), the list of departures
//! (`tests/deqp/departures.txt`) and the comparison of a run on stafeto with
//! them: a case that passes on Linux and does not pass on stafeto without a
//! line in the departures fails the run (plan G8, 7.3 and 7.4).

use super::CaseResult;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// The modules of VK-GL-CTS the guest has a program for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Module {
    Egl,
    Gles2,
    Gles3,
    Gles31,
}

impl Module {
    pub const ALL: [Module; 4] = [Module::Egl, Module::Gles2, Module::Gles3, Module::Gles31];

    /// The name of the module on the command line and in a set name.
    pub const fn name(self) -> &'static str {
        match self {
            Module::Egl => "egl",
            Module::Gles2 => "gles2",
            Module::Gles3 => "gles3",
            Module::Gles31 => "gles31",
        }
    }

    /// The package of the guest program (`tests/deqp*`), and the name of the
    /// module of VK-GL-CTS (`deqp-<name>`).
    pub const fn package(self) -> &'static str {
        match self {
            Module::Egl => "deqp-egl",
            Module::Gles2 => "deqp-gles2",
            Module::Gles3 => "deqp-gles3",
            Module::Gles31 => "deqp-gles31",
        }
    }

    /// The prefix of the names of its cases.
    pub const fn prefix(self) -> &'static str {
        match self {
            Module::Egl => "dEQP-EGL.",
            Module::Gles2 => "dEQP-GLES2.",
            Module::Gles3 => "dEQP-GLES3.",
            Module::Gles31 => "dEQP-GLES31.",
        }
    }

    pub fn of_case(case: &str) -> Option<Module> {
        [Module::Gles31, Module::Gles3, Module::Gles2, Module::Egl]
            .into_iter()
            .find(|m| case.starts_with(m.prefix()))
    }

    /// The command-line arguments every run of the module takes, on stafeto
    /// and on Linux alike, so the two runs ask the same of Mesa: no window (a
    /// surface in a pbuffer, as the CI of Mesa runs them), the configuration
    /// of that CI, and a log with no images and no shader sources, which a
    /// failing case would write in kilobytes of text.
    pub fn arguments(self) -> &'static [&'static str] {
        match self {
            Module::Egl => &[
                "--deqp-log-images=disable",
                "--deqp-log-shader-sources=disable",
            ],
            Module::Gles2 | Module::Gles3 | Module::Gles31 => &[
                "--deqp-surface-type=pbuffer",
                "--deqp-surface-width=256",
                "--deqp-surface-height=256",
                "--deqp-gl-config-name=rgba8888d24s8ms0",
                "--deqp-visibility=hidden",
                "--deqp-log-images=disable",
                "--deqp-log-shader-sources=disable",
            ],
        }
    }
}

/// The platform of dEQP that makes the baseline on Linux (plan 7.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// GLES contexts over EGL pbuffers; no `eglu::Platform`, so no deqp-egl.
    Surfaceless,
    /// deqp-egl with a native window of `nullptr`: the groups without windows.
    Nullws,
    /// deqp-egl on an X server (Xvfb): the groups with windows.
    X11Egl,
}

impl Target {
    /// The value of `DEQP_TARGET` of CMake.
    pub const fn cmake_name(self) -> &'static str {
        match self {
            Target::Surfaceless => "surfaceless",
            Target::Nullws => "nullws",
            Target::X11Egl => "x11_egl",
        }
    }
}

/// What a set gives to `deqp-smoke`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Smoke {
    /// Nothing.
    Skip,
    /// The first passing case of the set (a set of windows: its run in ci
    /// would be long, and one case shows the compositor works).
    One,
    /// One passing case of each group of the names.
    Groups,
}

/// A set of cases: the unit of a run on Linux (a probe of 60 minutes), of a
/// baseline file and of a run in the guest.
pub struct Set {
    pub name: &'static str,
    pub module: Module,
    /// The platform of the baseline.
    pub target: Target,
    /// The patterns of `--deqp-case`.
    pub patterns: &'static [&'static str],
    /// What the set gives to `deqp-smoke`.
    pub smoke: Smoke,
    /// Patterns (globs, `**` crosses dots) of groups that the run in the guest
    /// thins to one case in four, in the order of names. The baseline holds
    /// every case, and the comparison takes the cases that ran.
    pub sample: &'static [&'static str],
}

const fn set(
    name: &'static str,
    module: Module,
    target: Target,
    patterns: &'static [&'static str],
    smoke: Smoke,
) -> Set {
    Set {
        name,
        module,
        target,
        patterns,
        smoke,
        sample: &[],
    }
}

/// The groups of the plan (7.4), in sets that a probe of Linux runs in a
/// piece.
pub const SETS: &[Set] = &[
    set(
        "egl.info",
        Module::Egl,
        Target::Nullws,
        &["dEQP-EGL.info.*"],
        Smoke::Groups,
    ),
    set(
        "egl.context",
        Module::Egl,
        Target::Nullws,
        &[
            "dEQP-EGL.functional.create_context.*",
            "dEQP-EGL.functional.create_context_ext.*",
        ],
        Smoke::Groups,
    ),
    // The queries of a context take a window or a pbuffer and a current
    // context, so they have the baseline with windows.
    set(
        "egl.query",
        Module::Egl,
        Target::X11Egl,
        &["dEQP-EGL.functional.query_context.*"],
        Smoke::Groups,
    ),
    set(
        "egl.config",
        Module::Egl,
        Target::Nullws,
        &[
            "dEQP-EGL.functional.query_config.*",
            "dEQP-EGL.functional.choose_config.*",
        ],
        Smoke::Groups,
    ),
    set(
        "egl.sync",
        Module::Egl,
        Target::X11Egl,
        &[
            "dEQP-EGL.functional.fence_sync.*",
            "dEQP-EGL.functional.reusable_sync.*",
            "dEQP-EGL.functional.wait_sync.*",
        ],
        Smoke::Groups,
    ),
    set(
        "egl.api",
        Module::Egl,
        Target::Nullws,
        &[
            "dEQP-EGL.functional.surfaceless_context.*",
            "dEQP-EGL.functional.client_extensions.*",
            "dEQP-EGL.functional.get_proc_address.*",
        ],
        Smoke::Groups,
    ),
    // The negative API takes windows (create_window_surface, wait_native), so
    // its baseline is the one with windows.
    set(
        "egl.negative",
        Module::Egl,
        Target::X11Egl,
        &["dEQP-EGL.functional.negative_api.*"],
        Smoke::Groups,
    ),
    set(
        "egl.surface",
        Module::Egl,
        Target::X11Egl,
        &[
            "dEQP-EGL.functional.create_surface.*",
            "dEQP-EGL.functional.query_surface.*",
        ],
        Smoke::One,
    ),
    set(
        "egl.swap",
        Module::Egl,
        Target::X11Egl,
        &[
            "dEQP-EGL.functional.swap_buffers.*",
            "dEQP-EGL.functional.swap_buffers_with_damage.*",
            "dEQP-EGL.functional.buffer_age.*",
            "dEQP-EGL.functional.preserve_swap.*",
            "dEQP-EGL.functional.make_current.*",
        ],
        Smoke::One,
    ),
    set(
        "gles2.basic",
        Module::Gles2,
        Target::Surfaceless,
        &[
            "dEQP-GLES2.functional.prerequisite.*",
            "dEQP-GLES2.functional.implementation_limits.*",
            "dEQP-GLES2.functional.color_clear.*",
            "dEQP-GLES2.functional.depth_stencil_clear.*",
        ],
        Smoke::Groups,
    ),
    set(
        "gles2.buffer",
        Module::Gles2,
        Target::Surfaceless,
        &["dEQP-GLES2.functional.buffer.*"],
        Smoke::Groups,
    ),
    set(
        "gles2.texture",
        Module::Gles2,
        Target::Surfaceless,
        &[
            "dEQP-GLES2.functional.texture.format.*",
            "dEQP-GLES2.functional.texture.size.*",
        ],
        Smoke::Groups,
    ),
    Set {
        sample: &["dEQP-GLES2.functional.shaders.conversions.**"],
        ..set(
            "gles2.shaders1",
            Module::Gles2,
            Target::Surfaceless,
            &[
                "dEQP-GLES2.functional.shaders.operator.*",
                "dEQP-GLES2.functional.shaders.constants.*",
                "dEQP-GLES2.functional.shaders.conversions.*",
            ],
            Smoke::Groups,
        )
    },
    Set {
        sample: &["dEQP-GLES2.functional.shaders.swizzles.**"],
        ..set(
            "gles2.shaders2",
            Module::Gles2,
            Target::Surfaceless,
            &[
                "dEQP-GLES2.functional.shaders.functions.*",
                "dEQP-GLES2.functional.shaders.swizzles.*",
                "dEQP-GLES2.functional.shaders.struct.*",
            ],
            Smoke::Groups,
        )
    },
    Set {
        sample: &[
            "dEQP-GLES2.functional.fragment_ops.blend.**",
            "dEQP-GLES2.functional.fragment_ops.depth_stencil.**",
            "dEQP-GLES2.functional.fragment_ops.random.**",
            "dEQP-GLES2.functional.fragment_ops.interaction.**",
        ],
        ..set(
            "gles2.fragops",
            Module::Gles2,
            Target::Surfaceless,
            &["dEQP-GLES2.functional.fragment_ops.*"],
            Smoke::Groups,
        )
    },
    set(
        "gles2.raster",
        Module::Gles2,
        Target::Surfaceless,
        &[
            "dEQP-GLES2.functional.rasterization.*",
            "dEQP-GLES2.functional.vertex_arrays.*",
        ],
        Smoke::Groups,
    ),
    set(
        "gles3.basic",
        Module::Gles3,
        Target::Surfaceless,
        &[
            "dEQP-GLES3.functional.prerequisite.*",
            "dEQP-GLES3.functional.implementation_limits.*",
        ],
        Smoke::Groups,
    ),
    set(
        "gles3.shaders",
        Module::Gles3,
        Target::Surfaceless,
        &["dEQP-GLES3.functional.shaders.operator.*"],
        Smoke::Groups,
    ),
    set(
        "gles3.texture",
        Module::Gles3,
        Target::Surfaceless,
        &["dEQP-GLES3.functional.texture.format.*"],
        Smoke::Groups,
    ),
    set(
        "gles3.buffers",
        Module::Gles3,
        Target::Surfaceless,
        &[
            "dEQP-GLES3.functional.transform_feedback.basic_types.*",
            "dEQP-GLES3.functional.ubo.single_basic_type.*",
        ],
        Smoke::Groups,
    ),
    set(
        "gles31.compute",
        Module::Gles31,
        Target::Surfaceless,
        &["dEQP-GLES31.functional.compute.basic.*"],
        Smoke::Skip,
    ),
];

/// The cases of a set that the guest runs: every case, except that the groups
/// of `sample` give one case in four in the order of names (the first, the
/// fifth, ...).
pub fn sampled(set: &Set, cases: &[String]) -> Vec<String> {
    let mut sorted: Vec<&String> = cases.iter().collect();
    sorted.sort();
    let mut counts = vec![0usize; set.sample.len()];
    let mut kept = Vec::new();
    for case in sorted {
        match set.sample.iter().position(|p| glob(p, case)) {
            Some(group) => {
                if counts[group].is_multiple_of(4) {
                    kept.push(case.clone());
                }
                counts[group] += 1;
            }
            None => kept.push(case.clone()),
        }
    }
    kept
}

pub fn find_set(name: &str) -> Option<&'static Set> {
    SETS.iter().find(|s| s.name == name)
}

/// The sets a word of the command line names: a set, a module (`gles2` is
/// every set of that module) or `all`.
pub fn sets_of(word: &str) -> Result<Vec<&'static Set>, String> {
    if word == "all" {
        return Ok(SETS.iter().collect());
    }
    if let Some(set) = find_set(word) {
        return Ok(vec![set]);
    }
    let by_module: Vec<&Set> = SETS.iter().filter(|s| s.module.name() == word).collect();
    if by_module.is_empty() {
        let names: Vec<&str> = SETS.iter().map(|s| s.name).collect();
        return Err(format!(
            "no set or module {word:?}; sets: {}; modules: egl gles2 gles3 gles31; or all",
            names.join(" ")
        ));
    }
    Ok(by_module)
}

/// Whether a status of the log counts as a pass: the same statuses as `tally`.
pub fn passes(status: &str) -> bool {
    matches!(status, "Pass" | "QualityWarning" | "CompatibilityWarning")
}

/// A baseline file: the status of each case on Linux.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Baseline {
    pub cases: BTreeMap<String, String>,
    /// The file says it is not the output of a probe of a runner.
    pub provisional: bool,
}

/// The text of a baseline file: `#` lines (what made it), then one line a
/// case, `NAME STATUS`.
pub fn format_baseline(header: &[String], results: &[CaseResult]) -> String {
    let mut sorted: Vec<&CaseResult> = results.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let mut text = String::new();
    for line in header {
        text.push_str("# ");
        text.push_str(line);
        text.push('\n');
    }
    for r in sorted {
        text.push_str(&format!("{} {}\n", r.name, r.status));
    }
    text
}

pub fn parse_baseline(text: &str) -> Result<Baseline, String> {
    let mut baseline = Baseline::default();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(comment) = line.strip_prefix('#') {
            if comment.trim_start().starts_with("provisional:") {
                baseline.provisional = true;
            }
            continue;
        }
        let mut words = line.split_whitespace();
        let (Some(name), Some(status), None) = (words.next(), words.next(), words.next()) else {
            return Err(format!(
                "baseline line {}: {line:?} is not `NAME STATUS`",
                n + 1
            ));
        };
        if baseline
            .cases
            .insert(name.to_owned(), status.to_owned())
            .is_some()
        {
            return Err(format!("baseline line {}: {name} twice", n + 1));
        }
    }
    Ok(baseline)
}

/// The baseline of a set, if its file exists.
pub fn load_baseline(dir: &Path, set: &Set) -> Result<Option<Baseline>, String> {
    let path = dir.join(format!("{}.txt", set.name));
    match std::fs::read_to_string(&path) {
        Ok(text) => parse_baseline(&text)
            .map(Some)
            .map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Whether `text` matches `pattern`: `*` stands for any run of characters but
/// a dot (so it stays in one group of the names), `**` for any run at all.
pub fn glob(pattern: &str, text: &str) -> bool {
    fn go(p: &[u8], t: &[u8]) -> bool {
        match p.split_first() {
            None => t.is_empty(),
            Some((b'*', rest)) => {
                let (deep, rest) = match rest.split_first() {
                    Some((b'*', more)) => (true, more),
                    _ => (false, rest),
                };
                let mut at = 0;
                loop {
                    if go(rest, &t[at..]) {
                        return true;
                    }
                    if at == t.len() || (!deep && t[at] == b'.') {
                        return false;
                    }
                    at += 1;
                }
            }
            Some((c, rest)) => t.first() == Some(c) && go(rest, &t[1..]),
        }
    }
    go(pattern.as_bytes(), text.as_bytes())
}

/// The kind of difference a departure stands for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// The layer of POSIX under Mesa.
    Posix,
    /// Mesa or its platform for stafeto.
    Mesa,
    /// The windows (the composition service, the window manager).
    Window,
    /// The configurations the platform offers.
    Config,
    /// The test platform or the runner.
    Harness,
}

impl Class {
    fn parse(word: &str) -> Option<Class> {
        Some(match word {
            "posix" => Class::Posix,
            "mesa" => Class::Mesa,
            "window" => Class::Window,
            "config" => Class::Config,
            "harness" => Class::Harness,
            _ => return None,
        })
    }
}

/// One line of the departures: a case (or a pattern with `*`) on which stafeto
/// differs from Linux, the status it ends with, the kind of the difference,
/// why, and the step that returns it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Departure {
    pub pattern: String,
    pub status: String,
    pub class: Class,
    pub reason: String,
    pub step: String,
}

impl Departure {
    fn matches(&self, case: &str) -> bool {
        glob(&self.pattern, case)
    }

    /// A line of one case.
    fn exact(&self) -> bool {
        !self.pattern.contains('*')
    }
}

/// Whether a step names a step of the plan: `none` (the plan keeps the
/// difference), `M` and a number (a step of the window manager) or `G` with a
/// step of the graphics plan, as `G8.7`.
pub fn step_is_valid(step: &str) -> bool {
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if step == "none" {
        return true;
    }
    if let Some(n) = step.strip_prefix('M') {
        return digits(n);
    }
    step.strip_prefix('G')
        .and_then(|rest| rest.split_once('.'))
        .is_some_and(|(a, b)| digits(a) && digits(b))
}

/// The statuses a log can hold (the status codes of dEQP).
const STATUSES: &[&str] = &[
    "Pass",
    "Fail",
    "QualityWarning",
    "CompatibilityWarning",
    "Pending",
    "NotSupported",
    "ResourceError",
    "InternalError",
    "Crash",
    "Timeout",
    "Waiver",
];

/// The departures: lines `CASE | STATUS | CLASS | REASON | STEP`; `#` lines
/// and blank lines are comments. STATUS is the status stafeto ends with
/// (usually `NotSupported`): another status on that case is a regression.
pub fn parse_departures(text: &str) -> Result<Vec<Departure>, String> {
    let mut list: Vec<Departure> = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let at = n + 1;
        let parts: Vec<&str> = line.split('|').map(str::trim).collect();
        let [pattern, status, class, reason, step] = parts[..] else {
            return Err(format!(
                "departures line {at}: {line:?} is not `CASE | STATUS | CLASS | REASON | STEP`"
            ));
        };
        if [pattern, status, class, reason, step]
            .iter()
            .any(|f| f.is_empty())
        {
            return Err(format!("departures line {at}: an empty field"));
        }
        if pattern.contains(char::is_whitespace) || !pattern.starts_with("dEQP-") {
            return Err(format!(
                "departures line {at}: {pattern:?} is not a case name or a pattern of names"
            ));
        }
        if !STATUSES.contains(&status) || passes(status) {
            return Err(format!(
                "departures line {at}: {status:?} is not a status that departs from a pass"
            ));
        }
        let class = Class::parse(class).ok_or_else(|| {
            format!("departures line {at}: the class {class:?} is none of posix, mesa, window, config, harness")
        })?;
        if !step_is_valid(step) {
            return Err(format!(
                "departures line {at}: the step {step:?} is none, M<n> or G<n>.<m>"
            ));
        }
        if list.iter().any(|d| d.pattern == pattern) {
            return Err(format!("departures line {at}: {pattern} twice"));
        }
        list.push(Departure {
            pattern: pattern.to_owned(),
            status: status.to_owned(),
            class,
            reason: reason.to_owned(),
            step: step.to_owned(),
        });
    }
    Ok(list)
}

/// What the comparison found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Comparison {
    /// Cases that pass on Linux and do not pass here without a departure that
    /// names their status (or have no result at all), and cases that fail on
    /// Linux and crash here.
    pub regressions: Vec<String>,
    /// Departures of cases that now pass, or (after a full run) lines that
    /// cover no case though they match cases that pass on Linux: the step
    /// returned them, and the line must go.
    pub stale: Vec<String>,
    /// Cases the departures cover: case, step.
    pub departed: Vec<(String, String)>,
    /// How many cases each departure covered, in the order of the list.
    pub covered: Vec<(String, usize)>,
    /// Cases that ran and the baseline does not know.
    pub unknown: Vec<String>,
    /// Cases compared (those that pass on Linux, or crash here).
    pub checked: usize,
}

impl Comparison {
    pub fn is_ok(&self) -> bool {
        self.regressions.is_empty() && self.stale.is_empty() && self.unknown.is_empty()
    }
}

/// Statuses that end a case with no verdict: where Linux has a plain failure
/// they are still a difference.
fn is_breakdown(status: &str) -> bool {
    matches!(status, "Crash" | "Timeout" | "InternalError")
}

/// Compares the results of `expected` cases on stafeto with their status on
/// Linux. A case that passes on Linux must pass here, or a departure names it
/// with the status it ends with; a case that fails on Linux must not crash,
/// time out or end in an internal error here unless a departure names that;
/// a departure of a case that passes here is stale; a case with no result
/// counts as a failure. With `full` (a run of every case of the sets) a
/// pattern that matches cases passing on Linux and covered none is stale too.
pub fn compare(
    baseline: &BTreeMap<String, String>,
    expected: &[String],
    results: &[CaseResult],
    departures: &[Departure],
    full: bool,
) -> Comparison {
    let mut out = Comparison::default();
    let by_name: BTreeMap<&str, &str> = results
        .iter()
        .map(|r| (r.name.as_str(), r.status.as_str()))
        .collect();
    let names: BTreeSet<&str> = expected
        .iter()
        .map(String::as_str)
        .chain(results.iter().map(|r| r.name.as_str()))
        .collect();
    let mut covered = vec![0usize; departures.len()];
    let mut matched_passing = vec![0usize; departures.len()];
    for case in names {
        let Some(linux) = baseline.get(case) else {
            out.unknown.push(case.to_owned());
            continue;
        };
        let here = by_name.get(case).copied();
        let departure = departures.iter().position(|d| d.matches(case));
        if let Some(d) = departure
            && passes(linux)
        {
            matched_passing[d] += 1;
        }
        let here_passes = here.is_some_and(passes);
        if !passes(linux) {
            // A failure on Linux asks nothing of stafeto but an end of the
            // case: no crash, timeout or internal error, unless a line says so.
            if let Some(h) = here.filter(|h| is_breakdown(h)) {
                out.checked += 1;
                match departure.filter(|&d| departures[d].status == h) {
                    Some(d) => {
                        covered[d] += 1;
                        out.departed
                            .push((case.to_owned(), departures[d].step.clone()));
                    }
                    None => out.regressions.push(format!(
                        "{case}: Linux {linux}, stafeto {h} (a failure on Linux must not end like that)"
                    )),
                }
            }
            continue;
        }
        out.checked += 1;
        match (here_passes, departure) {
            (true, Some(d)) if departures[d].exact() => out.stale.push(case.to_owned()),
            (true, _) => {}
            (false, Some(d)) => {
                let h = here.unwrap_or("no result");
                if h == departures[d].status {
                    covered[d] += 1;
                    out.departed
                        .push((case.to_owned(), departures[d].step.clone()));
                } else {
                    out.regressions.push(format!(
                        "{case}: Linux {linux}, stafeto {h}, the departure says {}",
                        departures[d].status
                    ));
                }
            }
            (false, None) => out.regressions.push(format!(
                "{case}: Linux {linux}, stafeto {}",
                here.unwrap_or("no result")
            )),
        }
    }
    for (d, dep) in departures.iter().enumerate() {
        out.covered.push((dep.pattern.clone(), covered[d]));
        if full && covered[d] == 0 && matched_passing[d] > 0 && !dep.exact() {
            out.stale.push(format!(
                "{}: matches {} cases that pass on Linux and covers none",
                dep.pattern, matched_passing[d]
            ));
        }
    }
    out
}

/// The lines of a smoke list: case names, `#` lines and blank lines aside.
pub fn parse_smoke(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_owned)
        .collect()
}

/// The cases for `deqp-smoke` out of the passing cases of the baselines of the
/// sets that give groups (`Smoke::Groups`): one case of each group of the names
/// cut at the deepest level that gives no more than `most` groups (the first
/// case of the group in the order of names); the departed cases are left out.
pub fn select_smoke(passing: &BTreeSet<String>, most: usize) -> Vec<String> {
    let mut best: Vec<String> = Vec::new();
    for depth in 2..12 {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut picked = Vec::new();
        for case in passing {
            let key: Vec<&str> = case.split('.').take(depth).collect();
            if seen.insert(key.join(".")) {
                picked.push(case.clone());
            }
        }
        if picked.len() > most {
            break;
        }
        best = picked;
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(name: &str, status: &str) -> CaseResult {
        CaseResult {
            name: name.to_owned(),
            status: status.to_owned(),
        }
    }

    fn base(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(n, s)| ((*n).to_owned(), (*s).to_owned()))
            .collect()
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    fn deps(text: &str) -> Vec<Departure> {
        parse_departures(text).unwrap()
    }

    const A: &str = "dEQP-EGL.info.version";
    const B: &str = "dEQP-EGL.info.vendor";
    const C: &str = "dEQP-EGL.functional.create_context.rgb565_window";

    #[test]
    fn a_pass_on_linux_that_is_not_supported_here_is_a_regression() {
        let linux = base(&[(A, "Pass"), (B, "Pass")]);
        let ran = [result(A, "Pass"), result(B, "NotSupported")];
        let c = compare(&linux, &names(&[A, B]), &ran, &[], true);
        assert_eq!(c.regressions.len(), 1);
        assert!(c.regressions[0].starts_with(B));
        assert!(c.regressions[0].contains("NotSupported"));
        assert!(!c.is_ok());
        assert_eq!(c.checked, 2);
    }

    #[test]
    fn a_fail_on_linux_asks_only_that_the_case_ends() {
        let linux = base(&[(A, "Fail"), (B, "NotSupported"), (C, "Crash")]);
        let ran = [
            result(A, "Pass"),
            result(B, "Fail"),
            result(C, "NotSupported"),
        ];
        let c = compare(&linux, &names(&[A, B, C]), &ran, &[], true);
        assert!(c.is_ok(), "{c:?}");
        // No case passes on Linux and none broke down here: none is compared.
        assert_eq!(c.checked, 0);
    }

    #[test]
    fn a_crash_timeout_or_internal_error_where_linux_fails_is_a_regression_unless_named() {
        let linux = base(&[(A, "Fail"), (B, "Fail"), (C, "Fail")]);
        let ran = [
            result(A, "Crash"),
            result(B, "Timeout"),
            result(C, "InternalError"),
        ];
        let c = compare(&linux, &names(&[A, B, C]), &ran, &[], true);
        assert_eq!(c.regressions.len(), 3, "{c:?}");
        assert_eq!(c.checked, 3);
        let named = deps(&format!(
            "{A} | Crash | posix | the heap ends | G8.7\n{B} | NotSupported | mesa | other | none\n"
        ));
        let c = compare(&linux, &names(&[A, B, C]), &ran, &named, false);
        // A is named with its status; B's line says another status.
        assert_eq!(c.regressions.len(), 2, "{c:?}");
        assert!(c.departed.contains(&(A.to_owned(), "G8.7".to_owned())));
    }

    #[test]
    fn a_departure_covers_its_case_with_its_status_only() {
        let linux = base(&[(A, "Pass"), (B, "Pass"), (C, "Pass")]);
        let ran = [
            result(A, "NotSupported"),
            result(B, "Pass"),
            result(C, "NotSupported"),
        ];
        let d = deps(&format!(
            "{A} | NotSupported | harness | no EGL 1.5 string | G8.3\ndEQP-EGL.functional.** | NotSupported | window | one window at a time | M1\n"
        ));
        let c = compare(&linux, &names(&[A, B, C]), &ran, &d, true);
        assert!(c.is_ok(), "{c:?}");
        assert_eq!(c.departed.len(), 2);
        assert!(c.departed.contains(&(A.to_owned(), "G8.3".to_owned())));
        assert!(c.departed.contains(&(C.to_owned(), "M1".to_owned())));
        assert_eq!(c.covered[1].1, 1);
        // The same case ending in another status is a regression.
        let ran = [
            result(A, "Fail"),
            result(B, "Pass"),
            result(C, "ResourceError"),
        ];
        let c = compare(&linux, &names(&[A, B, C]), &ran, &d, true);
        assert_eq!(c.regressions.len(), 2, "{c:?}");
        assert!(c.regressions[0].contains("the departure says NotSupported"));
    }

    #[test]
    fn a_departure_of_a_case_that_passes_is_stale() {
        let linux = base(&[(A, "Pass")]);
        let d = deps(&format!(
            "{A} | NotSupported | harness | was wrong | G8.7\n"
        ));
        let c = compare(&linux, &names(&[A]), &[result(A, "Pass")], &d, false);
        assert_eq!(c.stale, [A]);
        assert!(!c.is_ok());
    }

    #[test]
    fn a_pattern_that_covers_nothing_after_a_full_run_is_stale() {
        let linux = base(&[(A, "Pass"), (B, "Pass")]);
        let ran = [result(A, "Pass"), result(B, "Pass")];
        let d = deps("dEQP-EGL.info.* | NotSupported | config | some | M1\n");
        // A partial run (the smoke list) cannot tell.
        assert!(compare(&linux, &names(&[A, B]), &ran, &d, false).is_ok());
        let c = compare(&linux, &names(&[A, B]), &ran, &d, true);
        assert_eq!(c.stale.len(), 1);
        assert!(c.stale[0].contains("covers none"));
        // A pattern that matches no case that passes on Linux is not judged here.
        let d = deps("dEQP-EGL.other.* | NotSupported | config | some | M1\n");
        assert!(compare(&linux, &names(&[A, B]), &ran, &d, true).is_ok());
    }

    #[test]
    fn a_case_that_never_ran_counts_as_a_failure_and_an_unknown_one_is_an_error() {
        let linux = base(&[(A, "Pass")]);
        let c = compare(&linux, &names(&[A]), &[], &[], true);
        assert_eq!(c.regressions.len(), 1);
        assert!(c.regressions[0].contains("no result"));
        let both = [result(A, "Pass"), result(B, "Pass")];
        let c = compare(&linux, &names(&[A]), &both, &[], true);
        assert_eq!(c.unknown, [B]);
        assert!(!c.is_ok());
    }

    #[test]
    fn warnings_pass_on_both_sides() {
        let linux = base(&[(A, "QualityWarning")]);
        let ran = [result(A, "CompatibilityWarning")];
        assert!(compare(&linux, &names(&[A]), &ran, &[], true).is_ok());
        let ran = [result(A, "Waiver")];
        assert_eq!(
            compare(&linux, &names(&[A]), &ran, &[], true)
                .regressions
                .len(),
            1
        );
    }

    #[test]
    fn a_pattern_has_stars_that_stop_at_a_dot_and_double_stars_that_do_not() {
        assert!(glob("a*", "abc"));
        assert!(glob("a*", "a"));
        assert!(glob("*c", "abc"));
        assert!(glob("a*c", "ac"));
        assert!(glob("a*c", "abbc"));
        assert!(glob("a*b*c", "a1b2c"));
        assert!(glob("abc", "abc"));
        assert!(!glob("abc", "abcd"));
        assert!(!glob("a*c", "abcd"));
        assert!(!glob("a*b*c", "a1c2b"));
        assert!(glob("a*bc", "abcbc"));
        assert!(!glob("ab*", "a"));
        // One star stays in one group of the names.
        assert!(!glob("g.*.rgb565_*", "g.a.b.rgb565_x"));
        assert!(glob("g.*.rgb565_*", "g.a.rgb565_x"));
        assert!(!glob("g.*", "g.a.b"));
        assert!(glob("g.**", "g.a.b"));
        assert!(glob("g.**.x", "g.a.b.x"));
        assert!(glob("**", ""));
    }

    #[test]
    fn departures_have_five_fields_a_status_a_class_and_a_step() {
        let ok = "dEQP-EGL.info.* | NotSupported | config | why | none\n";
        assert_eq!(deps(ok)[0].class, Class::Config);
        for bad in [
            "dEQP-EGL.info.version | NotSupported | config | why\n",
            "dEQP-EGL.info.version | NotSupported | config | why | \n",
            "info.version | NotSupported | config | why | M1\n",
            "dEQP-EGL.info.version | Pass | config | why | M1\n",
            "dEQP-EGL.info.version | Maybe | config | why | M1\n",
            "dEQP-EGL.info.version | NotSupported | kernel | why | M1\n",
            "dEQP-EGL.info.version | NotSupported | config | why | open\n",
            "dEQP-EGL.info.version | NotSupported | config | why | never\n",
            "dEQP-EGL.info.version | NotSupported | config | why | G8\n",
            "dEQP-EGL.info.version | NotSupported | config | why | M\n",
            "dEQP-EGL.info.version | NotSupported | config | a | M1\ndEQP-EGL.info.version | Fail | mesa | b | M1\n",
        ] {
            assert!(parse_departures(bad).is_err(), "{bad}");
        }
        for step in ["none", "M1", "M12", "G8.7", "G10.12"] {
            assert!(step_is_valid(step), "{step}");
        }
        assert!(parse_departures("# c\n\n").unwrap().is_empty());
    }

    #[test]
    fn a_baseline_round_trips_and_says_when_it_is_provisional() {
        let header = [
            "provisional: made in a container".to_owned(),
            "mesa 26.3.1".to_owned(),
        ];
        let text = format_baseline(&header, &[result(B, "Fail"), result(A, "Pass")]);
        let parsed = parse_baseline(&text).unwrap();
        assert!(parsed.provisional);
        assert_eq!(parsed.cases[A], "Pass");
        assert_eq!(parsed.cases[B], "Fail");
        assert!(text.find(B).unwrap() < text.find(A).unwrap());
        assert!(!parse_baseline("# mesa\nA Pass\n").unwrap().provisional);
        assert!(parse_baseline("A\n").is_err());
        assert!(parse_baseline("A Pass\nA Fail\n").is_err());
    }

    #[test]
    fn the_sets_have_unique_names_and_patterns_of_their_module() {
        let mut seen = BTreeSet::new();
        for s in SETS {
            assert!(seen.insert(s.name), "{} twice", s.name);
            assert!(s.name.starts_with(s.module.name()));
            assert!(!s.patterns.is_empty());
            for p in s.patterns {
                assert!(p.starts_with(s.module.prefix()), "{p}");
            }
            // deqp-egl needs eglu::Platform, which surfaceless has not.
            assert_eq!(s.module == Module::Egl, s.target != Target::Surfaceless);
        }
        assert_eq!(Module::of_case("dEQP-GLES31.a.b"), Some(Module::Gles31));
        assert_eq!(Module::of_case("dEQP-GLES3.a.b"), Some(Module::Gles3));
        assert_eq!(Module::of_case("dEQP-VK.a"), None);
    }

    #[test]
    fn a_word_names_sets() {
        assert_eq!(sets_of("egl.info").unwrap().len(), 1);
        assert!(sets_of("gles2").unwrap().len() > 3);
        assert_eq!(sets_of("all").unwrap().len(), SETS.len());
        assert!(sets_of("gles9").is_err());
    }

    #[test]
    fn a_sampled_group_gives_one_case_in_four_in_the_order_of_names() {
        let set = Set {
            sample: &["g.big.**"],
            ..set(
                "x",
                Module::Gles2,
                Target::Surfaceless,
                &["g.*"],
                Smoke::Skip,
            )
        };
        let mut cases: Vec<String> = (0..10).map(|n| format!("g.big.c{n}")).collect();
        cases.extend((0..3).map(|n| format!("g.small.c{n}")));
        cases.reverse();
        let kept = sampled(&set, &cases);
        assert_eq!(
            kept,
            [
                "g.big.c0",
                "g.big.c4",
                "g.big.c8",
                "g.small.c0",
                "g.small.c1",
                "g.small.c2"
            ]
        );
        // A set with no sample runs every case.
        let all = Set { sample: &[], ..set };
        assert_eq!(sampled(&all, &cases).len(), 13);
    }

    #[test]
    fn the_sample_of_gles2_is_the_groups_of_the_coordinator() {
        let mut thinned: Vec<&str> = SETS.iter().flat_map(|s| s.sample.iter().copied()).collect();
        thinned.sort_unstable();
        assert_eq!(
            thinned,
            [
                "dEQP-GLES2.functional.fragment_ops.blend.**",
                "dEQP-GLES2.functional.fragment_ops.depth_stencil.**",
                "dEQP-GLES2.functional.fragment_ops.interaction.**",
                "dEQP-GLES2.functional.fragment_ops.random.**",
                "dEQP-GLES2.functional.shaders.conversions.**",
                "dEQP-GLES2.functional.shaders.swizzles.**",
            ]
        );
    }

    #[test]
    fn smoke_takes_the_first_case_of_each_group_at_the_deepest_level_that_fits() {
        let passing: BTreeSet<String> = [
            "dEQP-GLES2.functional.a.x1",
            "dEQP-GLES2.functional.a.x2",
            "dEQP-GLES2.functional.b.y1",
            "dEQP-GLES2.functional.b.y2",
            "dEQP-GLES2.functional.b.z.w1",
            "dEQP-GLES2.functional.b.z.w2",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        // Depth 4 gives a and b (2 groups) and depth 5 gives x1, x2, y1, y2, z
        // (5 groups): the deepest level with at most 4 is depth 4.
        let four = select_smoke(&passing, 4);
        assert_eq!(
            four,
            ["dEQP-GLES2.functional.a.x1", "dEQP-GLES2.functional.b.y1"]
        );
        assert_eq!(select_smoke(&passing, 100).len(), 6);
    }

    #[test]
    fn a_smoke_list_drops_comments() {
        assert_eq!(parse_smoke("# x\n\nA\n B \n"), ["A", "B"]);
    }
}
