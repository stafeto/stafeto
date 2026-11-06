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
    let built = sign
        .find("cargo build --locked -p xtask")
        .expect("xtask is built");
    let written = sign
        .find("RELEASE_SIGNING_KEY: ${{")
        .expect("the key is read");
    assert!(built < written);
    assert!(sign.contains("if: always()") && sign.contains("rm -rf \"$RUNNER_TEMP/keys\""));
    assert!(!sign.contains("cache"), "a clean machine restores no cache");
    assert!(sign.contains("cargo build --locked -p xtask"));
    // Nothing the build job made reaches a shell of this job or any value in it: xtask
    // reads the files in their strict form before the key is there.
    assert!(
        sign.find("cargo xtask release-check")
            .expect("the files are checked")
            < written
    );
    for word in [
        "cat target",
        "$(<",
        "read ",
        "needs.build.outputs",
        "previous-serial",
        "source target",
        ". target",
    ] {
        assert!(
            !sign.contains(word),
            "the signing job must not use {word:?}"
        );
    }
    assert!(
        sign.contains("--serial-after"),
        "the serial is that of the published index"
    );
    assert!(!code(&release["draft"]).contains("needs.build.outputs"));
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
    assert!(release["draft"].contains("env.FINAL == 'true'"));
    assert!(release["draft"].contains("--prerelease"));
}

#[test]
fn the_build_job_refuses_a_series_it_would_build_as_new_by_mistake() {
    let build = &jobs(&workflow("release.yml"))["build"];
    assert!(build.contains("tools/pages.py previous"));
    assert!(
        build.contains("repos/stafeto/stafeto/releases"),
        "the records come from the release copy"
    );
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

/// The steps of a job: the text of each, from its `- ` line on.
fn steps(job: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for line in job.lines() {
        if line.starts_with("      - ") {
            found.push(String::new());
        }
        if let Some(step) = found.last_mut() {
            step.push_str(line);
            step.push('\n');
        }
    }
    found
}

#[test]
fn nothing_publishes_or_signs_again_before_the_owner_has_made_the_environment_and_a_series() {
    let text = workflow("publish-packages.yml");
    let all = jobs(&text);
    assert_eq!(
        all.keys().map(String::as_str).collect::<Vec<_>>(),
        ["gate", "publish"]
    );
    // The gate looks at public facts only.
    let gate = &all["gate"];
    assert!(
        !has_environment(gate)
            && secrets_named(gate).is_empty()
            && !code(gate).contains("secrets.")
    );
    assert!(gate.contains("tools/pages.py gate"));
    // The job with the secrets runs only when the gate says so, and each of its
    // steps but the checkout and the check of the secrets waits for them.
    let publish = &all["publish"];
    assert!(has_environment(publish));
    assert!(publish.contains("needs: gate"));
    assert!(publish.contains("if: needs.gate.outputs.go == 'true'"));
    assert!(
        publish.contains("group: packages-pages") && publish.contains("cancel-in-progress: false")
    );
    let mut waits = 0;
    for step in steps(publish) {
        let guarded = step.contains("steps.secrets.outputs.ok == 'true'");
        let free = step.contains("uses: actions/checkout@") || step.contains("id: secrets");
        assert!(
            guarded || free,
            "a step runs before the secrets are known:\n{step}"
        );
        waits += usize::from(guarded);
    }
    assert!(waits >= 6);
    // Once the gate has said go, an empty secret fails the run: the owner gets the letter.
    let check = steps(publish)
        .into_iter()
        .find(|s| s.contains("id: secrets"))
        .unwrap();
    assert!(check.contains("::error::") && check.contains("exit 1") && !check.contains("ok=false"));
}

#[test]
fn the_publication_runs_for_a_release_without_a_suffix_and_the_week_for_the_pages() {
    let text = code(&workflow("publish-packages.yml"));
    assert!(text.contains("types: [published]"));
    assert!(text.contains("cron: \"17 3 * * 1\""));
    assert!(text.contains("- keys/revoked") && text.contains("- keys/revoked.sig"));
    // The storage release is published only after its attachments are checked against the signed index.
    let at = |needle: &str| text.find(needle).unwrap_or_else(|| panic!("{needle}"));
    assert!(at("pages.py verify-storage") < at("draft=false"));
    assert!(at("draft=false") < at("pages.py check-addresses"));
    assert!(at("pages.py check-addresses") < at("pages.py publish"));
    assert!(at("pages.py publish") < at("repo --check --official --remote"));
    // The key leaves the machine whatever happens.
    assert!(text.contains("if: always() && steps.secrets.outputs.ok == 'true'"));
    assert!(text.contains("--min-certificate-days 35"));
    // A storage release of more than 30 files is listed in full.
    assert!(
        text.contains(
            "gh api --paginate \"repos/stafeto/packages/releases/$id/assets?per_page=100\""
        )
    );
    // The weekly signature and the one of a release follow the signed copy of a release.
    assert!(text.contains("--releases releases.json --anchors anchors"));
    assert!(text.contains("resign --index copy/INDEX --anchor copy/INDEX"));
}

#[test]
fn every_action_is_pinned_by_the_commit_it_was_read_at() {
    let mut roots = vec![crate::root().join(".github/actions/setup/action.yml")];
    roots.extend(
        names()
            .iter()
            .map(|n| crate::root().join(".github/workflows").join(n)),
    );
    for path in roots {
        for line in std::fs::read_to_string(&path).unwrap().lines() {
            let Some(at) = line
                .trim()
                .strip_prefix("- uses: ")
                .or_else(|| line.trim().strip_prefix("uses: "))
            else {
                continue;
            };
            if at.starts_with("./") {
                continue;
            }
            let (name, pin) = at
                .split_once('@')
                .unwrap_or_else(|| panic!("{}: {at}", path.display()));
            let sha = pin.split_whitespace().next().unwrap();
            assert!(
                sha.len() == 40
                    && sha.bytes().all(|b| b.is_ascii_hexdigit())
                    && pin.contains(" # v"),
                "{}: {name} is not pinned by a full commit with a version comment",
                path.display()
            );
        }
    }
}

#[test]
fn the_owner_is_told_to_guard_the_tags_and_main_before_a_secret_goes_into_the_environment() {
    // The environment lets in any run on a tag v*, and anyone with the right to write can set a
    // tag on a commit of a branch of theirs: the rulesets are what keeps the secrets safe.
    let text = std::fs::read_to_string(crate::root().join("docs/release.md")).unwrap();
    let at = |needle: &str| {
        text.find(needle)
            .unwrap_or_else(|| panic!("docs/release.md lacks {needle:?}"))
    };
    assert!(at("refs/tags/v*") < at("gh secret set RELEASE_SIGNING_KEY"));
    assert!(text.contains("\"type\": \"creation\"") && text.contains("refs/heads/main"));
}
