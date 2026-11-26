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

/// A set of cases: the unit of a run on Linux (a probe of 60 minutes), of a
/// baseline file and of a run in the guest.
pub struct Set {
    pub name: &'static str,
    pub module: Module,
    /// The platform of the baseline.
    pub target: Target,
    /// The patterns of `--deqp-case`.
    pub patterns: &'static [&'static str],
    /// Whether the set gives cases to `deqp-smoke` (a set whose cases need a
    /// window of the composition service cannot run in the probe image).
    pub smoke: bool,
}

const fn set(
    name: &'static str,
    module: Module,
    target: Target,
    patterns: &'static [&'static str],
    smoke: bool,
) -> Set {
    Set {
        name,
        module,
        target,
        patterns,
        smoke,
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
        true,
    ),
    set(
        "egl.context",
        Module::Egl,
        Target::Nullws,
        &[
            "dEQP-EGL.functional.create_context.*",
            "dEQP-EGL.functional.create_context_ext.*",
            "dEQP-EGL.functional.query_context.*",
        ],
        true,
    ),
    set(
        "egl.config",
        Module::Egl,
        Target::Nullws,
        &[
            "dEQP-EGL.functional.query_config.*",
            "dEQP-EGL.functional.choose_config.*",
        ],
        true,
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
        false,
    ),
    set(
        "egl.api",
        Module::Egl,
        Target::Nullws,
        &[
            "dEQP-EGL.functional.negative_api.*",
            "dEQP-EGL.functional.surfaceless_context.*",
            "dEQP-EGL.functional.client_extensions.*",
            "dEQP-EGL.functional.get_proc_address.*",
        ],
        true,
    ),
    set(
        "egl.surface",
        Module::Egl,
        Target::X11Egl,
        &[
            "dEQP-EGL.functional.create_surface.*",
            "dEQP-EGL.functional.query_surface.*",
        ],
        false,
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
        false,
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
        true,
    ),
    set(
        "gles2.buffer",
        Module::Gles2,
        Target::Surfaceless,
        &["dEQP-GLES2.functional.buffer.*"],
        true,
    ),
    set(
        "gles2.texture",
        Module::Gles2,
        Target::Surfaceless,
        &[
            "dEQP-GLES2.functional.texture.format.*",
            "dEQP-GLES2.functional.texture.size.*",
        ],
        true,
    ),
    set(
        "gles2.shaders1",
        Module::Gles2,
        Target::Surfaceless,
        &[
            "dEQP-GLES2.functional.shaders.operator.*",
            "dEQP-GLES2.functional.shaders.constants.*",
            "dEQP-GLES2.functional.shaders.conversions.*",
        ],
        true,
    ),
    set(
        "gles2.shaders2",
        Module::Gles2,
        Target::Surfaceless,
        &[
            "dEQP-GLES2.functional.shaders.functions.*",
            "dEQP-GLES2.functional.shaders.swizzles.*",
            "dEQP-GLES2.functional.shaders.struct.*",
        ],
        true,
    ),
    set(
        "gles2.fragops",
        Module::Gles2,
        Target::Surfaceless,
        &["dEQP-GLES2.functional.fragment_ops.*"],
        true,
    ),
    set(
        "gles2.raster",
        Module::Gles2,
        Target::Surfaceless,
        &[
            "dEQP-GLES2.functional.rasterization.*",
            "dEQP-GLES2.functional.vertex_arrays.*",
        ],
        true,
    ),
    set(
        "gles3.basic",
        Module::Gles3,
        Target::Surfaceless,
        &[
            "dEQP-GLES3.functional.prerequisite.*",
            "dEQP-GLES3.functional.implementation_limits.*",
        ],
        true,
    ),
    set(
        "gles3.shaders",
        Module::Gles3,
        Target::Surfaceless,
        &["dEQP-GLES3.functional.shaders.operator.*"],
        true,
    ),
    set(
        "gles3.texture",
        Module::Gles3,
        Target::Surfaceless,
        &["dEQP-GLES3.functional.texture.format.*"],
        true,
    ),
    set(
        "gles3.buffers",
        Module::Gles3,
        Target::Surfaceless,
        &[
            "dEQP-GLES3.functional.transform_feedback.basic_types.*",
            "dEQP-GLES3.functional.ubo.single_basic_type.*",
        ],
        true,
    ),
    set(
        "gles31.compute",
        Module::Gles31,
        Target::Surfaceless,
        &["dEQP-GLES31.functional.compute.basic.*"],
        false,
    ),
];

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

/// Whether `text` matches `pattern`, where `*` stands for any run of
/// characters (none included).
pub fn glob(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    let (first, rest) = (parts[0], &parts[1..]);
    let Some(mut tail) = text.strip_prefix(first) else {
        return false;
    };
    let Some((last, middle)) = rest.split_last() else {
        return tail.is_empty();
    };
    for part in middle {
        match tail.find(part) {
            Some(at) => tail = &tail[at + part.len()..],
            None => return false,
        }
    }
    tail.len() >= last.len() && tail.ends_with(last)
}

/// One line of the departures: a case (or a pattern with `*`) that passes
/// on Linux and does not on stafeto, why, and the step that returns it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Departure {
    pub pattern: String,
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

/// The departures: lines `CASE | REASON | STEP` (the step names the plan step
/// that returns the case, `none` for a difference the plan keeps, or `open` for
/// one the review has to place); `#` lines and blank lines are comments.
pub fn parse_departures(text: &str) -> Result<Vec<Departure>, String> {
    let mut list: Vec<Departure> = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split('|').map(str::trim).collect();
        let [pattern, reason, step] = parts[..] else {
            return Err(format!(
                "departures line {}: {line:?} is not `CASE | REASON | STEP`",
                n + 1
            ));
        };
        if pattern.is_empty() || reason.is_empty() || step.is_empty() {
            return Err(format!("departures line {}: an empty field", n + 1));
        }
        if pattern.contains(char::is_whitespace) || !pattern.starts_with("dEQP-") {
            return Err(format!(
                "departures line {}: {pattern:?} is not a case name or a pattern of names",
                n + 1
            ));
        }
        if list.iter().any(|d| d.pattern == pattern) {
            return Err(format!("departures line {}: {pattern} twice", n + 1));
        }
        list.push(Departure {
            pattern: pattern.to_owned(),
            reason: reason.to_owned(),
            step: step.to_owned(),
        });
    }
    Ok(list)
}

/// What the comparison found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Comparison {
    /// Cases that pass on Linux, do not pass here and have no departure (or
    /// have no result at all).
    pub regressions: Vec<String>,
    /// Exact departures of cases that now pass: the step already returned
    /// them, and the line must go.
    pub stale: Vec<String>,
    /// Cases the departures cover: case, step.
    pub departed: Vec<(String, String)>,
    /// Cases that ran and the baseline does not know.
    pub unknown: Vec<String>,
    /// Cases compared.
    pub checked: usize,
}

impl Comparison {
    pub fn is_ok(&self) -> bool {
        self.regressions.is_empty() && self.stale.is_empty() && self.unknown.is_empty()
    }
}

/// Compares the results of `expected` cases on stafeto with their status on
/// Linux. A case that passes on Linux must pass here, or a departure names
/// it; a departure of a case that passes here is stale; a case with no result
/// counts as a failure.
pub fn compare(
    baseline: &BTreeMap<String, String>,
    expected: &[String],
    results: &[CaseResult],
    departures: &[Departure],
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
    for case in names {
        let Some(linux) = baseline.get(case) else {
            out.unknown.push(case.to_owned());
            continue;
        };
        out.checked += 1;
        let here = by_name.get(case).copied();
        let departure = departures.iter().find(|d| d.matches(case));
        let here_passes = here.is_some_and(passes);
        if !passes(linux) {
            continue;
        }
        match (here_passes, departure) {
            (true, Some(d)) if d.exact() => out.stale.push(case.to_owned()),
            (true, _) => {}
            (false, Some(d)) => out.departed.push((case.to_owned(), d.step.clone())),
            (false, None) => out.regressions.push(format!(
                "{case}: Linux {linux}, stafeto {}",
                here.unwrap_or("no result")
            )),
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

/// Cases the smoke list leaves out: they need a native window, the image of
/// dEQP runs no composition service, and the framework ends its process on the
/// resource error that follows (each such case costs a start of the program).
pub const SMOKE_EXCLUDED: &[&str] = &[
    "dEQP-EGL.functional.negative_api.create_window_surface",
    "dEQP-EGL.functional.negative_api.wait_native",
];

/// The cases for `deqp-smoke` out of the passing cases of the baselines: one
/// case of each group of the names cut at the deepest level that gives no more
/// than `most` groups (the first case of the group in the order of names).
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

    const A: &str = "dEQP-EGL.info.version";
    const B: &str = "dEQP-EGL.info.vendor";
    const C: &str = "dEQP-EGL.functional.create_context.rgb565_window";

    #[test]
    fn a_pass_on_linux_that_is_not_supported_here_is_a_regression() {
        let linux = base(&[(A, "Pass"), (B, "Pass")]);
        let ran = [result(A, "Pass"), result(B, "NotSupported")];
        let c = compare(&linux, &names(&[A, B]), &ran, &[]);
        assert_eq!(c.regressions.len(), 1);
        assert!(c.regressions[0].starts_with(B));
        assert!(c.regressions[0].contains("NotSupported"));
        assert!(!c.is_ok());
    }

    #[test]
    fn a_fail_on_linux_is_no_regression_wherever_it_ends_here() {
        let linux = base(&[(A, "Fail"), (B, "NotSupported"), (C, "Crash")]);
        let ran = [
            result(A, "Pass"),
            result(B, "Fail"),
            result(C, "NotSupported"),
        ];
        let c = compare(&linux, &names(&[A, B, C]), &ran, &[]);
        assert!(c.is_ok(), "{c:?}");
        assert_eq!(c.checked, 3);
    }

    #[test]
    fn a_departure_covers_its_case_and_a_pattern_covers_many() {
        let linux = base(&[(A, "Pass"), (B, "Pass"), (C, "Pass")]);
        let ran = [
            result(A, "Fail"),
            result(B, "Pass"),
            result(C, "NotSupported"),
        ];
        let d = parse_departures(&format!(
            "{A} | no EGL 1.5 string | G8.3\ndEQP-EGL.functional.* | one window at a time | M1\n"
        ))
        .unwrap();
        let c = compare(&linux, &names(&[A, B, C]), &ran, &d);
        assert!(c.is_ok(), "{c:?}");
        assert_eq!(c.departed.len(), 2);
        assert!(c.departed.contains(&(A.to_owned(), "G8.3".to_owned())));
        assert!(c.departed.contains(&(C.to_owned(), "M1".to_owned())));
    }

    #[test]
    fn a_pattern_has_stars_anywhere() {
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
        assert!(!glob("a*bc", "abc1bc2"));
        assert!(glob("a*bc", "abcbc"));
        assert!(!glob("ab*", "a"));
        let d =
            parse_departures("dEQP-EGL.functional.*.rgb565_* | no 16-bit configuration | none\n")
                .unwrap();
        assert!(d[0].matches("dEQP-EGL.functional.create_context.rgb565_depth_stencil"));
        assert!(!d[0].matches("dEQP-EGL.functional.create_context.rgba8888_depth_stencil"));
    }

    #[test]
    fn a_departure_of_a_case_that_passes_is_stale() {
        let linux = base(&[(A, "Pass")]);
        let d = parse_departures(&format!("{A} | was wrong | G8.7\n")).unwrap();
        let c = compare(&linux, &names(&[A]), &[result(A, "Pass")], &d);
        assert_eq!(c.stale, [A]);
        assert!(!c.is_ok());
        // A pattern may cover cases that pass: it is never stale.
        let d = parse_departures("dEQP-EGL.info.* | some | M1\n").unwrap();
        assert!(compare(&linux, &names(&[A]), &[result(A, "Pass")], &d).is_ok());
    }

    #[test]
    fn a_case_that_never_ran_counts_as_a_failure_and_an_unknown_one_is_an_error() {
        let linux = base(&[(A, "Pass")]);
        let c = compare(&linux, &names(&[A]), &[], &[]);
        assert_eq!(c.regressions.len(), 1);
        assert!(c.regressions[0].contains("no result"));
        let c = compare(
            &linux,
            &names(&[A]),
            &[result(A, "Pass"), result(B, "Pass")],
            &[],
        );
        assert_eq!(c.unknown, [B]);
        assert!(!c.is_ok());
    }

    #[test]
    fn warnings_pass_on_both_sides() {
        let linux = base(&[(A, "QualityWarning")]);
        let c = compare(
            &linux,
            &names(&[A]),
            &[result(A, "CompatibilityWarning")],
            &[],
        );
        assert!(c.is_ok());
        let c = compare(&linux, &names(&[A]), &[result(A, "Waiver")], &[]);
        assert_eq!(c.regressions.len(), 1);
    }

    #[test]
    fn departures_have_three_fields_and_unique_cases() {
        assert!(parse_departures("dEQP-EGL.info.version | why\n").is_err());
        assert!(parse_departures("dEQP-EGL.info.version | why | \n").is_err());
        assert!(parse_departures("info.version | why | M1\n").is_err());
        assert!(
            parse_departures("dEQP-EGL.info.version | a | M1\ndEQP-EGL.info.version | b | M1\n")
                .is_err()
        );
        let ok = parse_departures("# c\n\ndEQP-EGL.info.* | a | M1\n").unwrap();
        assert_eq!(ok.len(), 1);
        assert_eq!(ok[0].step, "M1");
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
