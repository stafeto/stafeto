// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Tests of the text of the workflows in `.github/workflows/` (docs/release.md).
//! The secrets of the release live in the environment `packages`, and only two
//! jobs of the release may name them: the one that signs holds the release
//! key, the one that makes the drafts holds the token. The jobs that run
//! the code of the packages hold neither. Until the owner has made the
//! environment and the series is published, the jobs that publish and sign
//! again do nothing and end green. No tool reads YAML here, so the tests read
//! the text: a job starts at a line of two spaces and a name under `jobs:`.

#![cfg(test)]

use std::collections::BTreeMap;

fn workflow(name: &str) -> String {
    let path = crate::root().join(".github/workflows").join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn names() -> Vec<String> {
    let mut found: Vec<String> = std::fs::read_dir(crate::root().join(".github/workflows"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".yml"))
        .collect();
    found.sort();
    found
}

/// The jobs of a workflow: name to the text of the job.
fn jobs(text: &str) -> BTreeMap<String, String> {
    let mut found: BTreeMap<String, String> = BTreeMap::new();
    let mut current: Option<String> = None;
    let mut inside = false;
    for line in text.lines() {
        if line == "jobs:" {
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        if !line.starts_with(' ') && !line.is_empty() {
            break;
        }
        if let Some(name) = line
            .strip_prefix("  ")
            .and_then(|l| l.strip_suffix(':'))
            .filter(|n| !n.starts_with(' ') && !n.starts_with('#') && !n.is_empty())
        {
            current = Some(name.to_string());
            found.insert(name.to_string(), String::new());
        } else if let Some(job) = &current {
            let entry = found.get_mut(job).unwrap();
            entry.push_str(line);
            entry.push('\n');
        }
    }
    found
}

/// The lines of the text that are not comments.
fn code(text: &str) -> String {
    text.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

fn has_environment(job: &str) -> bool {
    code(job)
        .lines()
        .any(|l| l.trim() == "environment: packages")
}

fn secrets_named(job: &str) -> Vec<String> {
    let mut found = Vec::new();
    for name in ["PACKAGES_TOKEN", "RELEASE_SIGNING_KEY"] {
        if code(job).contains(name) {
            found.push(name.to_string());
        }
    }
    found
}

#[test]
fn no_workflow_passes_its_secrets_on_or_runs_with_the_secrets_of_a_pull_request() {
    for name in names() {
        let text = code(&workflow(&name));
        assert!(!text.contains("secrets: inherit"), "{name}");
        assert!(!text.contains("pull_request_target"), "{name}");
    }
}

#[test]
fn a_secret_of_the_release_is_named_only_in_a_job_of_the_environment_packages() {
    for name in names() {
        for (job, body) in jobs(&workflow(&name)) {
            if !secrets_named(&body).is_empty() {
                assert!(
                    has_environment(&body),
                    "{name}: {job} names a secret outside the environment packages"
                );
            }
        }
    }
}

#[test]
fn the_release_key_is_in_the_signing_job_and_the_token_in_the_draft_job_alone() {
    let release = jobs(&workflow("release.yml"));
    assert_eq!(
        release.keys().map(String::as_str).collect::<Vec<_>>(),
        ["build", "ci", "draft", "sign"]
    );
    assert_eq!(secrets_named(&release["sign"]), ["RELEASE_SIGNING_KEY"]);
    assert_eq!(secrets_named(&release["draft"]), ["PACKAGES_TOKEN"]);
    for job in ["ci", "build"] {
        assert!(secrets_named(&release[job]).is_empty(), "{job}");
        assert!(!has_environment(&release[job]), "{job}");
        assert!(!code(&release[job]).contains("secrets."), "{job}");
    }
    // The signing job builds nothing but xtask, before the key is written,
    // and removes the key whatever happens.
    let sign = code(&release["sign"]);
    let built = sign.find("cargo build -p xtask").expect("xtask is built");
    let written = sign
        .find("RELEASE_SIGNING_KEY: ${{")
        .expect("the key is read");
    assert!(built < written);
    assert!(sign.contains("if: always()") && sign.contains("rm -rf \"$RUNNER_TEMP/keys\""));
    assert!(!sign.contains("cache"), "a clean machine restores no cache");
    assert!(
        !sign.contains("tools/build-"),
        "the signing job builds no package"
    );
    // The token is in the one step that makes the storage release.
    assert!(!code(&release["draft"]).contains("PACKAGES_TOKEN: ${{ secrets.RELEASE"));
}

#[test]
fn the_ci_job_of_the_release_is_called_with_no_secret() {
    let ci = &jobs(&workflow("release.yml"))["ci"];
    assert!(ci.contains("uses: ./.github/workflows/ci.yml"));
    assert!(!ci.contains("secrets"));
    assert!(!ci.contains("with:"));
    assert!(ci.contains("contents: read"));
}

#[test]
fn the_dry_run_makes_no_draft_and_the_tag_makes_both() {
    let text = workflow("release.yml");
    assert!(code(&text).contains("workflow_dispatch:"));
    let release = jobs(&text);
    assert!(release["draft"].contains("if: github.event_name == 'push'"));
    assert!(release["draft"].contains("contents: write"));
    for job in ["ci", "build", "sign"] {
        assert!(!release[job].contains("contents: write"), "{job}");
        assert!(!release[job].contains("gh release create"), "{job}");
    }
    // A suffix is a pre-release, and its packages are not stored.
    assert!(release["draft"].contains("needs.build.outputs.final == 'true'"));
    assert!(release["draft"].contains("--prerelease"));
}

#[test]
fn the_build_job_refuses_a_series_it_would_build_as_new_by_mistake() {
    let build = &jobs(&workflow("release.yml"))["build"];
    assert!(build.contains("tools/pages.py previous"));
    assert!(build.contains("cargo xtask release-build"));
    assert!(build.contains("timeout-minutes: 120"));
}

#[test]
fn the_token_check_is_started_by_hand_alone() {
    let text = code(&workflow("packages-token.yml"));
    assert!(text.contains("workflow_dispatch:"));
    for trigger in ["push:", "pull_request:", "schedule:", "release:"] {
        assert!(!text.contains(trigger), "{trigger}");
    }
    assert!(has_environment(&jobs(&text)["token"]));
    assert!(text.contains("gh release delete"));
}
