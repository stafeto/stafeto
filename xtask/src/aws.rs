// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `cargo xtask aws`: the disk of the EFI loader on a t4g.small in eu-central-1,
//! with the guards of a session that may run unattended. The `aws` CLI does
//! the calls (profile `stafeto`, region eu-central-1, no SDK); the answers are
//! read as text through `--query`.
//!
//! The guards: every resource a command creates is written to the journal of
//! the session before the call (the intent) and after it (the identifier); it
//! carries the tags `project=stafeto` and `session=<id>` from the call that
//! creates it; before any delete, stop or terminate the resource is looked up
//! in the journals and its tags are read, and a resource whose `project` tag
//! is not `stafeto`, or whose `session` tag names no session whose journal
//! holds it, is left alone; only `t4g.small` and `t4g.nano` run, with credits
//! `standard`; at most four instances of the project live at once (a try-out
//! session allows two); the security group of a
//! session has no rule in and none out, so nothing reaches the instances from
//! outside and the console is the only way to look at them.

use crate::{Artifacts, Variant, build, data_image, efi};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const PROFILE: &str = "stafeto";
const REGION: &str = "eu-central-1";
/// The only instance types a command starts: the machine under test, and the
/// smallest type of the same family for the Linux neighbour that reads the
/// firmware's tables.
const ALLOWED_TYPES: [&str; 2] = ["t4g.small", "t4g.nano"];
const MAX_LIVE: usize = 4;
const BLOCK: usize = 512 * 1024;
/// The value of `Launch::extra_snapshot` that attaches an empty 1 GiB volume as /dev/sdf.
const BLANK_SDF: &str = "blank";
/// The value of `Launch::extra_snapshot` that leaves the data volume of the image out
/// (`--no-data-volume`): /dev/sdf is mapped to no device, so the instance has one NVMe volume.
const NO_DEVICE: &str = "none";
/// The prefix of a `Launch::extra_snapshot` value that gives the data volume of the image a larger
/// size (`--data-volume-size`): the mapping names the device and the size and EC2 keeps the
/// snapshot of the image's own mapping, so the volume still comes from it.
const SIZE_PREFIX: &str = "size=";
/// The smallest data volume: the snapshot of the data image is 2 GiB.
const DATA_VOLUME_MIN_GIB: u32 = 2;
/// The largest data volume `--data-volume-size` accepts. The cap protects the monthly budget
/// (gp3 is billed per GiB-month); EC2 itself allows far larger volumes.
const DATA_VOLUME_MAX_GIB: u32 = 32;
/// The largest blank volume `--blank-volume` accepts. The cap protects the monthly budget, as the
/// cap of the data volume does.
const BLANK_VOLUME_MAX_GIB: u32 = 32;
/// The price of gp3 in USD per GiB-month in eu-central-1 (unverified, as the prices above: it
/// only sizes the estimate the try-out command prints).
const PRICE_GP3_GIB_MONTH: f64 = 0.0952;
/// The device a blank volume of `--blank-volume` is attached as (the image's data volume has /dev/sdf).
const BLANK_DEVICE: &str = "/dev/sdg";

/// The `Launch::extra_snapshot` value for a data volume of `gib` GiB.
fn sized(gib: u32) -> String {
    format!("{SIZE_PREFIX}{gib}")
}

/// A whole number of GiB from `min` to `max`, the value of the option `name`.
fn parse_gib(name: &str, text: &str, min: u32, max: u32) -> Result<u32, String> {
    text.parse::<u32>()
        .ok()
        .filter(|n| (min..=max).contains(n))
        .ok_or_else(|| format!("{name} takes a whole number of GiB from {min} to {max}"))
}

/// The hourly charge of the volumes a try-out launch adds, from their sizes in GiB.
fn volume_rate(gibs: &[u32]) -> f64 {
    f64::from(gibs.iter().sum::<u32>()) * PRICE_GP3_GIB_MONTH / 730.0
}

/// The mapping the image registers for /dev/sdf: a volume made from the snapshot of the data
/// image (`cargo xtask data-image`: the table and the file system `datafs` mounts), 2 GiB as the
/// snapshot is, that goes away with the instance. A fresh EBS volume reads as random bytes past its
/// first 4 KiB, so `datafs` would never take an empty one for blank: the image brings the volume
/// made.
fn data_volume_mapping(snapshot: &str) -> String {
    format!(
        "DeviceName=/dev/sdf,Ebs={{SnapshotId={snapshot},VolumeType=gp3,DeleteOnTermination=true}}"
    )
}

/// The mapping a launch gives /dev/sdf besides the image's own: an empty 1 GiB volume, a volume
/// made from a snapshot, or no device at all.
fn launch_mapping(extra: &str) -> String {
    match extra {
        NO_DEVICE => "DeviceName=/dev/sdf,NoDevice=".to_string(),
        sized if sized.starts_with(SIZE_PREFIX) => {
            format!(
                "DeviceName=/dev/sdf,Ebs={{VolumeSize={},VolumeType=gp3,DeleteOnTermination=true}}",
                &sized[SIZE_PREFIX.len()..]
            )
        }
        BLANK_SDF => {
            "DeviceName=/dev/sdf,Ebs={VolumeSize=1,VolumeType=gp3,DeleteOnTermination=true}"
                .to_string()
        }
        snapshot => format!(
            "DeviceName=/dev/sdf,Ebs={{SnapshotId={snapshot},VolumeType=gp3,DeleteOnTermination=true}}"
        ),
    }
}
/// The on-demand price of a t4g.small in eu-central-1 in USD per hour, as the
/// price list showed it when this was written (unverified: it only sizes the
/// estimate the commands print).
const PRICE_SMALL: f64 = 0.0184;
/// The charge of one public IPv4 address in USD per hour (unverified, as the price above).
const PRICE_IPV4: f64 = 0.005;
/// How long a try-out instance is meant to live, in hours, when `--lifetime-hours` does not say.
const TRY_LIFETIME_HOURS: u64 = 2;

const USAGE: &str = "usage: xtask aws check
       xtask aws image [--layered] [--dump] [--marks] [--its-int] [--its-align-4k] [--disk FILE] [--ena-break-aenq] [--ena-break-exit] [--session S]
       xtask aws boot --ami AMI [--type T] [--end TEXT] [--timeout SECONDS] [--serial SECONDS] [--stop] [--try [--lifetime-hours N]] [--no-data-volume | --data-volume-size GIB] [--blank-volume GIB] [--session S]
       xtask aws dump [--session S] [--all]
       xtask aws neighbour [--snapshot SNAP | --blank-sdf] [--session S]
       xtask aws pair --ami AMI [--count N] [--internet] [--serial SECONDS] [--delay S] [--gap S] [--session S]
       xtask aws clean --session S [--keep-image]
       xtask aws sweep [--remove]
       (sweep lists every resource tagged project=stafeto; --remove deletes the ones in a journal, a tagged resource in no journal is listed, refused and left for you to remove by hand)";

// ---- the CLI -------------------------------------------------------------------

/// Hides the identifiers the reports must not carry: account numbers (twelve
/// digits), the ids of instances, images, volumes, snapshots and groups, and IPv4
/// addresses.
pub fn redact(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let is_hex = |c: u8| c.is_ascii_digit() || (b'a'..=b'f').contains(&c);
    let prefixes: [(&str, usize); 7] = [
        ("key-", 17),
        ("ami-", 17),
        ("snap-", 17),
        ("vol-", 17),
        ("sg-", 17),
        ("i-", 17),
        ("eni-", 17),
    ];
    'outer: while i < b.len() {
        let boundary = i == 0 || !b[i - 1].is_ascii_alphanumeric();
        if boundary {
            for (p, n) in prefixes {
                if text[i..].starts_with(p)
                    && b.len() >= i + p.len() + n
                    && b[i + p.len()..i + p.len() + n].iter().all(|c| is_hex(*c))
                    && (b.len() == i + p.len() + n || !b[i + p.len() + n].is_ascii_alphanumeric())
                {
                    let _ = write!(out, "{p}...");
                    i += p.len() + n;
                    continue 'outer;
                }
            }
            if (i == 0 || b[i - 1] != b'.')
                && let Some(n) = ipv4_len(&text[i..])
            {
                out.push_str("<ip>");
                i += n;
                continue;
            }
            if b.len() >= i + 12
                && b[i..i + 12].iter().all(u8::is_ascii_digit)
                && (b.len() == i + 12 || !b[i + 12].is_ascii_alphanumeric())
            {
                out.push_str("<account>");
                i += 12;
                continue;
            }
        }
        let ch = text[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// The length of the dotted quad (four decimal numbers of at most three digits, 0 to 255)
/// that starts `text`, if one does and no digit or dot continues it.
fn ipv4_len(text: &str) -> Option<usize> {
    let b = text.as_bytes();
    let mut at = 0;
    for part in 0..4 {
        let digits = b[at..].iter().take_while(|c| c.is_ascii_digit()).count();
        if digits == 0 || digits > 3 || text[at..at + digits].parse::<u16>().ok()? > 255 {
            return None;
        }
        at += digits;
        if part < 3 {
            if b.get(at) != Some(&b'.') {
                return None;
            }
            at += 1;
        }
    }
    match b.get(at) {
        Some(c)
            if c.is_ascii_digit()
                || *c == b'.' && b.get(at + 1).is_some_and(u8::is_ascii_digit) =>
        {
            None
        }
        _ => Some(at),
    }
}

/// The program that runs the calls: `aws`, or a fake of the host tests.
#[cfg(test)]
static CLI: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

fn cli() -> PathBuf {
    #[cfg(test)]
    if let Some(p) = CLI.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        return p;
    }
    PathBuf::from("aws")
}

fn aws_cmd(args: &[&str]) -> Command {
    let mut c = Command::new(cli());
    c.args(["--profile", PROFILE, "--region", REGION, "--output", "text"])
        .args(args)
        .env("AWS_PAGER", "");
    c
}

/// One `aws` call; the answer's text, trimmed. An error carries the CLI's own
/// message whole (redacted), so a denied permission reads as it came.
fn aws(args: &[&str]) -> Result<String, String> {
    let o = aws_cmd(args)
        .output()
        .map_err(|e| format!("aws: {e} (is the AWS CLI installed?)"))?;
    if o.status.success() {
        Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
    } else {
        Err(redact(&format!(
            "aws {}: {}",
            args.iter().take(2).copied().collect::<Vec<_>>().join(" "),
            String::from_utf8_lossy(&o.stderr).trim()
        )))
    }
}

fn aws_s(args: &[String]) -> Result<String, String> {
    aws(&args.iter().map(String::as_str).collect::<Vec<_>>())
}

// ---- the session and its journal --------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Instance,
    Volume,
    Snapshot,
    Image,
    Group,
    Key,
}

impl Kind {
    /// The order of removal: a group cannot go while an instance holds it, a snapshot while an
    /// image uses it.
    fn rank(self) -> u8 {
        match self {
            Kind::Instance => 0,
            Kind::Image => 1,
            Kind::Volume => 2,
            Kind::Snapshot => 3,
            Kind::Key => 4,
            Kind::Group => 5,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Kind::Instance => "instance",
            Kind::Volume => "volume",
            Kind::Snapshot => "snapshot",
            Kind::Image => "image",
            Kind::Group => "group",
            Kind::Key => "key",
        }
    }
    fn parse(s: &str) -> Option<Kind> {
        [
            Kind::Instance,
            Kind::Volume,
            Kind::Snapshot,
            Kind::Image,
            Kind::Group,
            Kind::Key,
        ]
        .into_iter()
        .find(|k| k.name() == s)
    }
}

pub struct Session {
    id: String,
    dir: PathBuf,
}

fn aws_dir() -> PathBuf {
    crate::target_dir().join("aws")
}

impl Session {
    fn open(id: Option<String>) -> Result<Session, String> {
        let id = match id {
            Some(id) => id,
            None => {
                let o = Command::new("date")
                    .arg("+%Y%m%d-%H%M%S")
                    .output()
                    .map_err(|e| e.to_string())?;
                String::from_utf8_lossy(&o.stdout).trim().to_string()
            }
        };
        if id.is_empty() || !id.chars().all(|c| c.is_ascii_digit() || c == '-') {
            return Err(format!(
                "the session id {id:?} has other characters than digits and dashes"
            ));
        }
        let dir = aws_dir().join(&id);
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        Ok(Session { id, dir })
    }

    fn ledger(&self) -> PathBuf {
        self.dir.join("ledger.tsv")
    }

    fn note(&self, state: &str, kind: Kind, id: &str) -> Result<(), String> {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.ledger())
            .map_err(|e| format!("ledger: {e}"))?;
        writeln!(f, "{state}\t{}\t{id}", kind.name()).map_err(|e| format!("ledger: {e}"))
    }

    /// Resources this session created and has not deleted, in creation order.
    fn live(&self) -> Vec<(Kind, String)> {
        live_of(&self.ledger())
    }

    fn tags(&self, resource: &str) -> String {
        format!(
            "ResourceType={resource},Tags=[{{Key=project,Value=stafeto}},{{Key=session,Value={}}}]",
            self.id
        )
    }

    fn tag_spec(&self, resources: &[&str]) -> Vec<String> {
        // One option with several values: a repeated option keeps its last
        // value only, and the earlier resources would go untagged.
        std::iter::once("--tag-specifications".to_string())
            .chain(resources.iter().map(|r| self.tags(r)))
            .collect()
    }
}

fn live_of(ledger: &Path) -> Vec<(Kind, String)> {
    let text = std::fs::read_to_string(ledger).unwrap_or_default();
    let mut live: Vec<(Kind, String)> = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        let [state, kind, id] = f[..] else { continue };
        let Some(kind) = Kind::parse(kind) else {
            continue;
        };
        match state {
            "created" => live.push((kind, id.to_string())),
            "deleted" => live.retain(|(k, i)| !(*k == kind && i == id)),
            _ => {}
        }
    }
    live
}

/// Every journal under target/aws: what any session left, with the id of the session whose
/// journal holds it.
fn all_live() -> Vec<(String, Kind, String)> {
    let mut all = Vec::new();
    if let Ok(dirs) = std::fs::read_dir(aws_dir()) {
        for d in dirs.flatten() {
            let session = d.file_name().to_string_lossy().into_owned();
            all.extend(
                live_of(&d.path().join("ledger.tsv"))
                    .into_iter()
                    .map(|(k, i)| (session.clone(), k, i)),
            );
        }
    }
    all
}

/// The tag value `key` of `resource`, empty if there is none.
fn tag_of(resource: &str, key: &str) -> Result<String, String> {
    let t = aws(&[
        "ec2",
        "describe-tags",
        "--filters",
        &format!("Name=resource-id,Values={resource}"),
        &format!("Name=key,Values={key}"),
        "--query",
        "Tags[0].Value",
    ])?;
    Ok(if t == "None" { String::new() } else { t })
}

/// The verdict of the guard, from the journals (session id, kind, id) and the two tags the
/// resource carries (empty when it has none): the resource is in a journal, its `project` tag is
/// `stafeto`, and its `session` tag is the id of a session whose journal holds it.
fn guard_verdict(
    journals: &[(String, Kind, String)],
    kind: Kind,
    id: &str,
    project: &str,
    session: &str,
) -> Result<(), String> {
    let holders: Vec<&str> = journals
        .iter()
        .filter(|(_, k, i)| *k == kind && i == id)
        .map(|(s, _, _)| s.as_str())
        .collect();
    if holders.is_empty() {
        return Err(format!(
            "{} {} is not in any session journal: left alone",
            kind.name(),
            redact(id)
        ));
    }
    if project != "stafeto" {
        return Err(format!(
            "{} {} lacks the tag project=stafeto: left alone",
            kind.name(),
            redact(id)
        ));
    }
    if !holders.contains(&session) {
        return Err(format!(
            "{} {} has a session tag that matches no journal holding it: left alone",
            kind.name(),
            redact(id)
        ));
    }
    Ok(())
}

/// The guard before any delete, stop or terminate: `guard_verdict` with the tags read from EC2.
fn guard(kind: Kind, id: &str) -> Result<(), String> {
    let journals = all_live();
    if !journals.iter().any(|(_, k, i)| *k == kind && i == id) {
        return guard_verdict(&journals, kind, id, "", "");
    }
    let project = tag_of(id, "project")?;
    let session = tag_of(id, "session")?;
    guard_verdict(&journals, kind, id, &project, &session)
}

/// Whether an error of a `describe-*` call says that the resource is gone:
/// the codes of EC2 end in `.NotFound`. Every other error (expired
/// credentials, throttling, a denied call) says nothing about the resource.
fn is_not_found(error: &str) -> bool {
    error.contains(".NotFound")
}

/// What a `describe-*` answer says of a resource: it lives, or it is gone.
fn lives(answer: Result<String, String>) -> Result<bool, String> {
    match answer {
        Ok(s) => Ok(s != "terminated" && s != "deleted"),
        Err(e) if is_not_found(&e) => Ok(false),
        Err(e) => Err(e),
    }
}

fn exists(kind: Kind, id: &str) -> Result<bool, String> {
    let (cmd, ids, q) = match kind {
        Kind::Instance => (
            "describe-instances",
            "--instance-ids",
            "Reservations[0].Instances[0].State.Name",
        ),
        Kind::Volume => ("describe-volumes", "--volume-ids", "Volumes[0].State"),
        Kind::Snapshot => ("describe-snapshots", "--snapshot-ids", "Snapshots[0].State"),
        Kind::Image => ("describe-images", "--image-ids", "Images[0].State"),
        Kind::Group => (
            "describe-security-groups",
            "--group-ids",
            "SecurityGroups[0].GroupId",
        ),
        Kind::Key => (
            "describe-key-pairs",
            "--key-pair-ids",
            "KeyPairs[0].KeyPairId",
        ),
    };
    lives(aws(&["ec2", cmd, ids, id, "--query", q]))
}

fn delete(s: &Session, kind: Kind, id: &str) -> Result<(), String> {
    if !exists(kind, id)? {
        return s.note("deleted", kind, id);
    }
    guard(kind, id)?;
    match kind {
        Kind::Instance => {
            aws(&["ec2", "terminate-instances", "--instance-ids", id])?;
            aws(&["ec2", "wait", "instance-terminated", "--instance-ids", id])?;
        }
        Kind::Volume => {
            aws(&["ec2", "delete-volume", "--volume-id", id])?;
        }
        Kind::Snapshot => {
            aws(&["ec2", "delete-snapshot", "--snapshot-id", id])?;
        }
        Kind::Image => {
            aws(&["ec2", "deregister-image", "--image-id", id])?;
        }
        Kind::Key => {
            aws(&["ec2", "delete-key-pair", "--key-pair-id", id])?;
        }
        Kind::Group => {
            // A group of the pair names itself in its rules: they go first (a closed
            // group has none of this kind, and the calls then say so, which is no matter).
            for what in [
                "revoke-security-group-ingress",
                "revoke-security-group-egress",
            ] {
                let _ = aws(&[
                    "ec2",
                    what,
                    "--group-id",
                    id,
                    "--ip-permissions",
                    &self_rule(id),
                ]);
            }
            aws(&["ec2", "delete-security-group", "--group-id", id])?;
        }
    }
    println!("deleted {} {}", kind.name(), redact(id));
    s.note("deleted", kind, id)
}

/// Deletes `id` and merges a failed delete into `result`, loudly: an
/// instance that stays alive costs money and must not pass unnoticed.
fn release<T>(s: &Session, kind: Kind, id: &str, result: Result<T, String>) -> Result<T, String> {
    match delete(s, kind, id) {
        Ok(()) => result,
        Err(e) => {
            eprintln!(
                "NOT REMOVED: {} {} is still there ({e}); run `xtask aws clean --session {}`",
                kind.name(),
                redact(id),
                s.id
            );
            match result {
                Ok(_) => Err(format!(
                    "{} {} was not removed: {e}",
                    kind.name(),
                    redact(id)
                )),
                Err(r) => Err(format!(
                    "{r}; and {} {} was not removed: {e}",
                    kind.name(),
                    redact(id)
                )),
            }
        }
    }
}

/// The journal of `s` in reverse order, instances first: a group cannot go
/// while an instance holds it, a snapshot while an image uses it.
fn clean_order(mut live: Vec<(Kind, String)>, keep_image: bool) -> Vec<(Kind, String)> {
    live.reverse();
    live.sort_by_key(|(k, _)| k.rank());
    if keep_image {
        // The image and the snapshots it is made from stay, so a second launch needs no
        // second build.
        live.retain(|(k, _)| !matches!(k, Kind::Image | Kind::Snapshot));
    }
    live
}

/// Removes what the session made. With `keep_image` the image and its snapshots stay (and stay
/// in the journal, so a later `clean` without the option removes them).
fn clean(s: &Session, keep_image: bool) -> Result<(), String> {
    let mut failed = Vec::new();
    // Volumes the session made whose journal line is missing.
    match adopt_volumes(s) {
        Ok(found) if !found.is_empty() => {
            println!(
                "clean: {} volumes found by their tags and journaled",
                found.len()
            );
        }
        Ok(_) => {}
        Err(e) => {
            eprintln!("clean: the lookup of volumes by tag failed: {e}");
            failed.push(e);
        }
    }
    for (kind, id) in clean_order(s.live(), keep_image) {
        if let Err(e) = delete(s, kind, &id) {
            eprintln!("clean: {e}");
            failed.push(e);
        }
    }
    if failed.is_empty() {
        if keep_image {
            println!("clean: the image and its snapshots are kept");
        }
        for f in ["address", "try-key", "try-key.pub"] {
            let _ = std::fs::remove_file(s.dir.join(f));
        }
        Ok(())
    } else {
        Err(format!("{} resources were not removed", failed.len()))
    }
}

// ---- what lives -------------------------------------------------------------------

fn tagged(q: &str, what: &[&str], filters: &[&str]) -> Result<Vec<String>, String> {
    let mut args = vec!["ec2"];
    args.extend(what);
    args.extend(["--filters", "Name=tag:project,Values=stafeto"]);
    args.extend(filters);
    args.extend(["--query", q]);
    Ok(aws(&args)?.split_whitespace().map(String::from).collect())
}

/// Every resource of the project that exists, by kind, whoever made it.
fn project_resources() -> Result<Vec<(Kind, String)>, String> {
    let mut all = Vec::new();
    let live_states =
        "Name=instance-state-name,Values=pending,running,stopping,stopped,shutting-down";
    for i in tagged(
        "Reservations[].Instances[].InstanceId",
        &["describe-instances"],
        &[live_states],
    )? {
        all.push((Kind::Instance, i));
    }
    for v in tagged("Volumes[].VolumeId", &["describe-volumes"], &[])? {
        all.push((Kind::Volume, v));
    }
    let snaps = aws(&[
        "ec2",
        "describe-snapshots",
        "--owner-ids",
        "self",
        "--filters",
        "Name=tag:project,Values=stafeto",
        "--query",
        "Snapshots[].SnapshotId",
    ])?;
    for s in snaps.split_whitespace() {
        all.push((Kind::Snapshot, s.to_string()));
    }
    let imgs = aws(&[
        "ec2",
        "describe-images",
        "--owners",
        "self",
        "--filters",
        "Name=tag:project,Values=stafeto",
        "--query",
        "Images[].ImageId",
    ])?;
    for i in imgs.split_whitespace() {
        all.push((Kind::Image, i.to_string()));
    }
    for g in tagged(
        "SecurityGroups[].GroupId",
        &["describe-security-groups"],
        &[],
    )? {
        all.push((Kind::Group, g));
    }
    let keys = aws(&[
        "ec2",
        "describe-key-pairs",
        "--filters",
        "Name=tag:project,Values=stafeto",
        "--query",
        "KeyPairs[].KeyPairId",
    ])?;
    for k in keys.split_whitespace() {
        all.push((Kind::Key, k.to_string()));
    }
    Ok(all)
}

fn live_instances() -> Result<usize, String> {
    Ok(project_resources()?
        .iter()
        .filter(|(k, _)| *k == Kind::Instance)
        .count())
}

/// `sweep`: lists what the project has and, with `--remove`, removes the part
/// that is in a journal (the guard of every delete), then lists again. The
/// exit is an error while anything remains. A tagged resource that is in no journal is listed,
/// its delete is refused by the guard, and it has to be removed by hand.
fn sweep(args: &[String]) -> Result<(), String> {
    let remove = args.iter().any(|a| a == "--remove");
    let mut found = project_resources()?;
    if remove {
        let s = Session::open(Some("0".into()))?;
        let mut order = found.clone();
        order.sort_by_key(|(k, _)| k.rank());
        for (kind, id) in order {
            if let Err(e) = delete(&s, kind, &id) {
                eprintln!("sweep: {e}");
            }
        }
        found = project_resources()?;
    }
    for kind in [
        Kind::Instance,
        Kind::Volume,
        Kind::Snapshot,
        Kind::Image,
        Kind::Key,
        Kind::Group,
    ] {
        let ids: Vec<String> = found
            .iter()
            .filter(|(k, _)| *k == kind)
            .map(|(_, i)| redact(i))
            .collect();
        println!("{}: {} {}", kind.name(), ids.len(), ids.join(" "));
    }
    print_try_instances();
    if found.is_empty() {
        println!("sweep: nothing tagged project=stafeto is left");
        Ok(())
    } else {
        Err(format!("sweep: {} resources remain", found.len()))
    }
}

// ---- launching ---------------------------------------------------------------------

fn default_subnet() -> Result<(String, String), String> {
    let r = aws(&[
        "ec2",
        "describe-subnets",
        "--filters",
        "Name=default-for-az,Values=true",
        &format!("Name=availability-zone,Values={}", zone()),
        "--query",
        "Subnets[0].[SubnetId,VpcId]",
    ])?;
    let f: Vec<&str> = r.split_whitespace().collect();
    match f[..] {
        [s, v] => Ok((s.to_string(), v.to_string())),
        _ => Err(format!("no default subnet in {}", zone())),
    }
}

/// The zone the instances start in: `eu-central-1a`, or the letter `a`, `b` or `c` in
/// `STAFETO_AWS_ZONE` (a zone that has no capacity for the type answers
/// InsufficientInstanceCapacity; the next launch may name another).
fn zone() -> String {
    match std::env::var("STAFETO_AWS_ZONE").as_deref() {
        Ok(z @ ("a" | "b" | "c")) => format!("{REGION}{z}"),
        _ => format!("{REGION}a"),
    }
}

/// The session's group: no rule in, none out.
fn closed_group(s: &Session) -> Result<String, String> {
    if let Some((_, g)) = s.live().into_iter().find(|(k, _)| *k == Kind::Group) {
        return Ok(g);
    }
    let (_, vpc) = default_subnet()?;
    s.note("intent", Kind::Group, "stafeto-closed")?;
    let mut args: Vec<String> = ["ec2", "create-security-group", "--group-name"]
        .map(String::from)
        .to_vec();
    args.push(format!("stafeto-closed-{}", s.id));
    args.extend(
        [
            "--description",
            "stafeto: closed both ways",
            "--vpc-id",
            &vpc,
        ]
        .map(String::from),
    );
    args.extend(s.tag_spec(&["security-group"]));
    args.extend(["--query", "GroupId"].map(String::from));
    let g = aws_s(&args)?;
    s.note("created", Kind::Group, &g)?;
    aws(&[
        "ec2",
        "revoke-security-group-egress",
        "--group-id",
        &g,
        "--ip-permissions",
        "IpProtocol=-1,IpRanges=[{CidrIp=0.0.0.0/0}]",
    ])?;
    Ok(g)
}

// ---- the try-out session ---------------------------------------------------------------------

/// The TCP ports the try-out group opens, and only to the operator's address.
const TRY_PORTS: [u16; 4] = [22, 80, 443, 8080];
/// What the try-out instance may start towards the internet: HTTPS for `pkg`, and DNS. The
/// answers to the operator's connections are return traffic of the group's state; DHCP is
/// link-local and no group filters it.
const TRY_EGRESS: [(&str, u16); 3] = [("tcp", 443), ("tcp", 53), ("udp", 53)];
/// The most instances the project may have alive when a try-out session starts one.
const TRY_MAX_LIVE: usize = 2;

/// The `/32` block of an address as `checkip` printed it. Anything that is no single IPv4
/// address, and the unspecified address, gives an error: no rule is ever made from a guess.
fn operator_cidr(text: &str) -> Result<String, String> {
    let ip: std::net::Ipv4Addr = text
        .trim()
        .parse()
        .map_err(|_| "the public address of this host could not be read".to_string())?;
    if ip.is_unspecified() || ip.is_broadcast() {
        return Err("the public address of this host could not be read".into());
    }
    Ok(format!("{ip}/32"))
}

/// The public address of this host, as the AWS check service sees it.
fn operator_address() -> Result<String, String> {
    let o = Command::new("curl")
        .args([
            "-4",
            "-fsS",
            "--max-time",
            "15",
            "https://checkip.amazonaws.com",
        ])
        .output()
        .map_err(|e| format!("curl: {e}"))?;
    if !o.status.success() {
        return Err(format!(
            "the public address of this host could not be found (checkip failed: {})",
            String::from_utf8_lossy(&o.stderr).trim()
        ));
    }
    operator_cidr(&String::from_utf8_lossy(&o.stdout))
}

/// An inbound rule of the try-out group: one TCP port from one block.
fn try_ingress_rule(port: u16, cidr: &str) -> String {
    format!("IpProtocol=tcp,FromPort={port},ToPort={port},IpRanges=[{{CidrIp={cidr}}}]")
}

/// An outbound rule of the try-out group: one port to any address.
fn try_egress_rule((protocol, port): (&str, u16)) -> String {
    format!("IpProtocol={protocol},FromPort={port},ToPort={port},IpRanges=[{{CidrIp=0.0.0.0/0}}]")
}

/// Whether the rows of a `describe-security-groups` answer (protocol, from, to, number of
/// IPv4 ranges, the first range, numbers of IPv6 ranges, prefix lists and group pairs; one
/// rule per line) are exactly the rules `want` gives, each for `cidr` only.
fn rules_are(text: &str, want: &[(&str, u16)], cidr: &str) -> bool {
    let mut rows: Vec<Vec<&str>> = text
        .lines()
        .map(|l| l.split_whitespace().collect())
        .collect();
    rows.sort();
    let mut expected: Vec<Vec<String>> = want
        .iter()
        .map(|(p, n)| {
            let n = n.to_string();
            [*p, &n, &n, "1", cidr, "0", "0", "0"]
                .map(String::from)
                .to_vec()
        })
        .collect();
    expected.sort();
    rows.len() == expected.len()
        && rows
            .iter()
            .zip(&expected)
            .all(|(r, e)| r.len() == e.len() && r.iter().zip(e).all(|(a, b)| a == b))
}

const RULE_COLUMNS: &str = "[IpProtocol,FromPort,ToPort,length(IpRanges),IpRanges[0].CidrIp,length(Ipv6Ranges),length(PrefixListIds),length(UserIdGroupPairs)]";

/// The guard of the try-out group: it lets in the four TCP ports from `cidr` and nothing
/// else, and out the three of `TRY_EGRESS` only.
fn assert_try(group: &str, cidr: &str) -> Result<(), String> {
    let ingress = aws(&[
        "ec2",
        "describe-security-groups",
        "--group-ids",
        group,
        "--query",
        &format!("SecurityGroups[0].IpPermissions[].{RULE_COLUMNS}"),
    ])?;
    let ports: Vec<(&str, u16)> = TRY_PORTS.iter().map(|p| ("tcp", *p)).collect();
    if !rules_are(&ingress, &ports, cidr) {
        return Err(format!(
            "group {} lets in more than the four ports from the operator's address: no instance starts in it",
            redact(group)
        ));
    }
    let egress = aws(&[
        "ec2",
        "describe-security-groups",
        "--group-ids",
        group,
        "--query",
        &format!("SecurityGroups[0].IpPermissionsEgress[].{RULE_COLUMNS}"),
    ])?;
    if !rules_are(&egress, &TRY_EGRESS, "0.0.0.0/0") {
        return Err(format!(
            "group {} lets out more than HTTPS and DNS: no instance starts in it",
            redact(group)
        ));
    }
    Ok(())
}

/// The first id a lookup by name and by the session's tags gives. The tags are part of the
/// question: a resource of the same name that lacks either of them is never taken.
fn adopt(
    s: &Session,
    kind: Kind,
    what: &[&str],
    name_filter: &str,
    query: &str,
) -> Result<Option<String>, String> {
    let mut args = vec!["ec2"];
    args.extend(what);
    let session = format!("Name=tag:session,Values={}", s.id);
    args.extend([
        "--filters",
        name_filter,
        "Name=tag:project,Values=stafeto",
        &session,
    ]);
    args.extend(["--query", query]);
    let found = aws(&args)?;
    match found.split_whitespace().next() {
        Some(id) if id != "None" => {
            if !s.live().iter().any(|(k, i)| *k == kind && i == id) {
                s.note("created", kind, id)?;
            }
            Ok(Some(id.to_string()))
        }
        _ => Ok(None),
    }
}

/// `adopt`, with the error of the failed call that made the lookup necessary kept.
fn adopt_after(
    s: &Session,
    kind: Kind,
    what: &[&str],
    name_filter: &str,
    query: &str,
    e: String,
) -> Result<String, String> {
    match adopt(s, kind, what, name_filter, query) {
        Ok(Some(id)) => Ok(id),
        Ok(None) => Err(e),
        Err(look) => Err(format!(
            "{e}; and the lookup of a {} it may have made failed: {look}; run `xtask aws clean --session {}`",
            kind.name(),
            s.id
        )),
    }
}

/// The id of the session's try-out group in the journal: the live group whose name is
/// `name`.
fn named_group(s: &Session, name: &str) -> Result<Option<String>, String> {
    for (_, g) in s.live().into_iter().filter(|(k, _)| *k == Kind::Group) {
        let n = aws(&[
            "ec2",
            "describe-security-groups",
            "--group-ids",
            &g,
            "--query",
            "SecurityGroups[0].GroupName",
        ])?;
        if n == name {
            return Ok(Some(g));
        }
    }
    Ok(None)
}

/// An existing try-out group is the group of this operator's address. When its four rules
/// are all for another block, the address has changed since it was made.
fn assert_try_address(s: &Session, group: &str, cidr: &str) -> Result<(), String> {
    let ingress = aws(&[
        "ec2",
        "describe-security-groups",
        "--group-ids",
        group,
        "--query",
        &format!("SecurityGroups[0].IpPermissions[].{RULE_COLUMNS}"),
    ])?;
    let ports: Vec<(&str, u16)> = TRY_PORTS.iter().map(|p| ("tcp", *p)).collect();
    let other = ingress
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(4))
        .unwrap_or("");
    if other != cidr && rules_are(&ingress, &ports, other) {
        return Err(format!(
            "the address of this host changed since the group of session {} was made: run `xtask aws clean --session {}` and start again",
            s.id, s.id
        ));
    }
    Ok(())
}

/// The session's group of the try-out: the four ports from `cidr`, HTTPS and DNS out.
fn try_group(s: &Session, cidr: &str) -> Result<String, String> {
    let name = format!("stafeto-try-{}", s.id);
    let by_name = format!("Name=group-name,Values={name}");
    if let Some(g) = named_group(s, &name)? {
        assert_try_address(s, &g, cidr)?;
        return Ok(g);
    }
    // A call of an earlier run may have made the group and died before its line.
    if let Some(g) = adopt(
        s,
        Kind::Group,
        &["describe-security-groups"],
        &by_name,
        "SecurityGroups[].GroupId",
    )? {
        assert_try_address(s, &g, cidr)?;
        return Ok(g);
    }
    let (_, vpc) = default_subnet()?;
    s.note("intent", Kind::Group, "stafeto-try")?;
    let mut args: Vec<String> = ["ec2", "create-security-group", "--group-name"]
        .map(String::from)
        .to_vec();
    args.push(format!("stafeto-try-{}", s.id));
    args.extend(
        [
            "--description",
            "stafeto: try-out, four ports from the operator",
            "--vpc-id",
            &vpc,
        ]
        .map(String::from),
    );
    args.extend(s.tag_spec(&["security-group"]));
    args.extend(["--query", "GroupId"].map(String::from));
    let g = match aws_s(&args) {
        Ok(g) => {
            s.note("created", Kind::Group, &g)?;
            g
        }
        Err(e) => {
            return adopt_after(
                s,
                Kind::Group,
                &["describe-security-groups"],
                &by_name,
                "SecurityGroups[].GroupId",
                e,
            );
        }
    };
    aws(&[
        "ec2",
        "revoke-security-group-egress",
        "--group-id",
        &g,
        "--ip-permissions",
        "IpProtocol=-1,IpRanges=[{CidrIp=0.0.0.0/0}]",
    ])?;
    for port in TRY_PORTS {
        aws(&[
            "ec2",
            "authorize-security-group-ingress",
            "--group-id",
            &g,
            "--ip-permissions",
            &try_ingress_rule(port, cidr),
        ])?;
    }
    for rule in TRY_EGRESS {
        aws(&[
            "ec2",
            "authorize-security-group-egress",
            "--group-id",
            &g,
            "--ip-permissions",
            &try_egress_rule(rule),
        ])?;
    }
    Ok(g)
}

/// The session's key pair: an ed25519 key made in the session's directory (the private part
/// stays there and is never printed) and its public part imported under the session's tags.
/// The name of the key pair is returned.
fn try_key(s: &Session) -> Result<String, String> {
    let name = format!("stafeto-try-{}", s.id);
    if s.live().iter().any(|(k, _)| *k == Kind::Key) {
        return Ok(name);
    }
    let by_name = format!("Name=key-name,Values={name}");
    // A call of an earlier run may have made the key pair and died before its line.
    let adopted = adopt(
        s,
        Kind::Key,
        &["describe-key-pairs"],
        &by_name,
        "KeyPairs[].KeyPairId",
    )?;
    let key = s.dir.join("try-key");
    if let Some(id) = adopted {
        // The pair of an earlier run holds the public key of that run. When the local key was
        // lost or made again, the pair is replaced, or the instance would take a key nobody here
        // holds.
        let ours = local_fingerprint(&key)?;
        let theirs = aws(&[
            "ec2",
            "describe-key-pairs",
            "--key-pair-ids",
            &id,
            "--query",
            "KeyPairs[0].KeyFingerprint",
        ])?;
        if same_fingerprint(&ours, &theirs) {
            return Ok(name);
        }
        println!(
            "try-out: the key pair of the session holds another key than the local one: replacing it"
        );
        delete(s, Kind::Key, &id)?;
    }
    local_fingerprint(&key)?;
    s.note("intent", Kind::Key, &name)?;
    let mut args: Vec<String> = [
        "ec2",
        "import-key-pair",
        "--key-name",
        &name,
        "--public-key-material",
    ]
    .map(String::from)
    .to_vec();
    args.push(format!("fileb://{}.pub", key.display()));
    args.extend(s.tag_spec(&["key-pair"]));
    args.extend(["--query", "KeyPairId"].map(String::from));
    match aws_s(&args) {
        Ok(id) => s.note("created", Kind::Key, &id)?,
        Err(e) => {
            adopt_after(
                s,
                Kind::Key,
                &["describe-key-pairs"],
                &by_name,
                "KeyPairs[].KeyPairId",
                e,
            )?;
        }
    }
    Ok(name)
}

/// The SHA256 fingerprint of the public key `key.pub`, made first when `key` does not exist.
fn local_fingerprint(key: &Path) -> Result<String, String> {
    if !key.exists() {
        let st = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "stafeto-try", "-f"])
            .arg(key)
            .status()
            .map_err(|e| e.to_string())?;
        if !st.success() {
            return Err("ssh-keygen failed".into());
        }
    }
    let pubkey = format!("{}.pub", key.display());
    let o = Command::new("ssh-keygen")
        .args(["-l", "-E", "sha256", "-f", &pubkey])
        .output()
        .map_err(|e| e.to_string())?;
    if !o.status.success() {
        let name = Path::new(&pubkey)
            .file_name()
            .map_or(String::new(), |n| n.to_string_lossy().into_owned());
        return Err(format!("ssh-keygen -l failed on the public key {name}"));
    }
    fingerprint_field(&String::from_utf8_lossy(&o.stdout))
        .ok_or_else(|| "ssh-keygen -l printed no fingerprint".to_string())
}

/// The fingerprint in a line of `ssh-keygen -l`: `256 SHA256:xxxx comment (ED25519)`.
fn fingerprint_field(line: &str) -> Option<String> {
    line.split_whitespace().nth(1).map(String::from)
}

/// Whether two SHA256 fingerprints name one key: EC2 writes the digest as base64 with the
/// padding, `ssh-keygen` as `SHA256:` and base64 without it.
fn same_fingerprint(a: &str, b: &str) -> bool {
    let plain = |f: &str| {
        f.trim()
            .trim_start_matches("SHA256:")
            .trim_end_matches('=')
            .to_string()
    };
    !plain(a).is_empty() && plain(a) == plain(b)
}

/// The public IPv4 address of a running instance, once EC2 has it; the caller writes it to
/// the session's directory and prints it redacted only.
fn public_address(id: &str) -> Result<String, String> {
    for _ in 0..60 {
        let a = aws(&[
            "ec2",
            "describe-instances",
            "--instance-ids",
            id,
            "--query",
            "Reservations[0].Instances[0].PublicIpAddress",
        ])?;
        if a.parse::<std::net::Ipv4Addr>().is_ok() {
            return Ok(a);
        }
        std::thread::sleep(Duration::from_secs(3));
    }
    Err("the instance has no public address".into())
}

/// The guard that no group of an instance lets anything in.
fn assert_closed(group: &str) -> Result<(), String> {
    let r = aws(&[
        "ec2",
        "describe-security-groups",
        "--group-ids",
        group,
        "--query",
        "length(SecurityGroups[0].IpPermissions)",
    ])?;
    if r == "0" {
        Ok(())
    } else {
        Err(format!(
            "group {} has inbound rules: no instance starts in it",
            redact(group)
        ))
    }
}

fn neighbour_ami() -> Result<String, String> {
    aws(&[
        "ec2",
        "describe-images",
        "--owners",
        "amazon",
        "--filters",
        "Name=name,Values=al2023-ami-2023*-arm64",
        "Name=architecture,Values=arm64",
        "Name=state,Values=available",
        "--query",
        "sort_by(Images,&CreationDate)[-1].ImageId",
    ])
}

struct Launch<'a> {
    ami: &'a str,
    ty: &'a str,
    user_data: Option<&'a Path>,
    extra_snapshot: Option<&'a str>,
    /// A group of the caller (the pair's, whose rules it has checked); the closed group of
    /// the session when none.
    group: Option<&'a str>,
    /// The interface gets a public address (the one session that reaches the internet).
    public_ip: bool,
    /// The address in the subnet the interface takes, when the caller fixes it.
    private_ip: Option<&'a str>,
    /// The key pair the instance gets (`--key-name`): the try-out session's.
    key_name: Option<&'a str>,
    /// The instance gets the tag `expires` with this UTC time: the end of its meant life.
    expires: Option<&'a str>,
}

/// Starts one instance with every guard; the journal has it and its volumes.
fn launch(s: &Session, l: &Launch) -> Result<(String, Instant), String> {
    if !ALLOWED_TYPES.contains(&l.ty) {
        return Err(format!(
            "instance type {} is not allowed (only {ALLOWED_TYPES:?})",
            l.ty
        ));
    }
    let live = live_instances()?;
    if live >= MAX_LIVE {
        return Err(format!(
            "{live} instances of the project are alive: the limit is {MAX_LIVE}"
        ));
    }
    let group = match l.group {
        Some(g) => g.to_string(),
        None => {
            let g = closed_group(s)?;
            assert_closed(&g)?;
            g
        }
    };
    let (subnet, _) = default_subnet()?;
    let nic = nic_spec(&subnet, &group, l.public_ip, l.private_ip);
    let mut args: Vec<String> = [
        "ec2",
        "run-instances",
        "--image-id",
        l.ami,
        "--instance-type",
        l.ty,
        "--count",
        "1",
    ]
    .map(String::from)
    .to_vec();
    args.extend(
        [
            "--credit-specification",
            "CpuCredits=standard",
            "--metadata-options",
            "HttpTokens=required",
        ]
        .map(String::from),
    );
    args.extend(
        [
            "--instance-initiated-shutdown-behavior",
            "stop",
            "--network-interfaces",
        ]
        .map(String::from),
    );
    args.push(nic);
    let mut spec = s.tag_spec(&["instance", "volume", "network-interface"]);
    if let Some(at) = l.expires {
        for v in spec
            .iter_mut()
            .filter(|v| v.starts_with("ResourceType=instance,"))
        {
            *v = format!("{},{{Key=expires,Value={at}}}]", v.trim_end_matches(']'));
        }
    }
    args.extend(spec);
    if let Some(extra) = l.extra_snapshot {
        args.extend(["--block-device-mappings".to_string(), launch_mapping(extra)]);
    }
    if let Some(k) = l.key_name {
        args.extend(["--key-name".to_string(), k.to_string()]);
    }
    if let Some(u) = l.user_data {
        args.extend(["--user-data".to_string(), format!("file://{}", u.display())]);
    }
    // The token makes a repeated call the same call, and lets a call that
    // failed after AWS made the instance find it again.
    let token = client_token(s);
    args.extend(["--client-token".to_string(), token.clone()]);
    args.extend(["--query", "Instances[0].InstanceId"].map(String::from));
    s.note("intent", Kind::Instance, l.ty)?;
    let id = match aws_s(&args) {
        Ok(id) => id,
        Err(e) => {
            // The call may have made the instance before it failed: look it up
            // by its token, journal it and remove it.
            let found = aws(&[
                "ec2",
                "describe-instances",
                "--filters",
                &format!("Name=client-token,Values={token}"),
                "Name=instance-state-name,Values=pending,running,stopping,stopped,shutting-down",
                "--query",
                "Reservations[].Instances[].InstanceId",
            ]);
            return match found {
                Ok(ids) => {
                    let mut result = Err(e);
                    for id in ids.split_whitespace() {
                        s.note("created", Kind::Instance, id)?;
                        result = release(s, Kind::Instance, id, result);
                    }
                    result
                }
                Err(look) => Err(format!(
                    "{e}; and the lookup of an instance it may have made failed: {look}; \
                     look for client token {token} (session {})",
                    s.id
                )),
            };
        }
    };
    let started = Instant::now();
    s.note("created", Kind::Instance, &id)?;
    let volumes = aws(&[
        "ec2",
        "describe-instances",
        "--instance-ids",
        &id,
        "--query",
        "Reservations[0].Instances[0].BlockDeviceMappings[].Ebs.VolumeId",
    ]);
    let noted = volumes.and_then(|vs| {
        vs.split_whitespace()
            .try_for_each(|v| s.note("created", Kind::Volume, v))
    });
    if let Err(e) = noted {
        // Nothing after the creation may leave the instance running.
        return release(s, Kind::Instance, &id, Err(e));
    }
    println!("started a {} ({})", l.ty, redact(&id));
    Ok((id, started))
}

/// The `--network-interfaces` value of an instance.
fn nic_spec(subnet: &str, group: &str, public_ip: bool, private_ip: Option<&str>) -> String {
    let mut nic = format!(
        "DeviceIndex=0,SubnetId={subnet},AssociatePublicIpAddress={public_ip},Groups={group}"
    );
    if let Some(ip) = private_ip {
        nic.push_str(&format!(",PrivateIpAddress={ip}"));
    }
    nic
}

/// A token for one call of `run-instances`: the session and the clock.
fn client_token(s: &Session) -> String {
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("stafeto-{}-{ns}", s.id)
}

fn state(id: &str) -> Result<String, String> {
    aws(&[
        "ec2",
        "describe-instances",
        "--instance-ids",
        id,
        "--query",
        "Reservations[0].Instances[0].State.Name",
    ])
}

fn console(id: &str) -> Result<String, String> {
    let t = aws(&[
        "ec2",
        "get-console-output",
        "--instance-id",
        id,
        "--latest",
        "--query",
        "Output",
    ])?;
    Ok(if t == "None" {
        String::new()
    } else {
        t.replace('\r', "")
    })
}

struct Watched {
    text: String,
    ended: bool,
    state: String,
}

/// Reads the console every 5 s until `end` shows in it, the instance is no
/// longer running, or `timeout` has passed.
fn watch(id: &str, end: Option<&str>, timeout: Duration, log: &Path) -> Result<Watched, String> {
    let start = Instant::now();
    let mut text = String::new();
    loop {
        let st = state(id)?;
        match console(id) {
            Ok(t) if !t.is_empty() => text = t,
            Ok(_) => {}
            Err(e) => eprintln!("console: {e}"),
        }
        let ended = end.is_some_and(|e| text.contains(e));
        let gone = !matches!(st.as_str(), "pending" | "running");
        if ended || gone || start.elapsed() > timeout {
            let _ = std::fs::write(log, &text);
            return Ok(Watched {
                text,
                ended,
                state: st,
            });
        }
        std::thread::sleep(Duration::from_secs(5));
    }
}

fn print_console(text: &str) {
    println!("--- console output (identifiers redacted) ---");
    for l in text.lines() {
        println!("{}", redact(l));
    }
    println!("--- end of console output ---");
}

/// Seconds since the epoch as `YYYY-MM-DDTHH:MM:SSZ`.
fn utc_stamp(epoch: u64) -> String {
    let (days, rem) = ((epoch / 86400) as i64, epoch % 86400);
    // The civil date of a day count (the algorithm of H. Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// The epoch seconds of the first 19 characters of a UTC stamp (`YYYY-MM-DDTHH:MM:SS`, what
/// `utc_stamp` and the CLI's `LaunchTime` begin with).
fn parse_stamp(text: &str) -> Option<u64> {
    let b = text.as_bytes();
    let num = |from: usize, len: usize| -> Option<i64> { text.get(from..from + len)?.parse().ok() };
    if b.len() < 19
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let (y, m, d) = (num(0, 4)?, num(5, 2)?, num(8, 2)?);
    let (hh, mm, ss) = (num(11, 2)?, num(14, 2)?, num(17, 2)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    let y = y - i64::from(m <= 2);
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86400 + hh * 3600 + mm * 60 + ss).ok()
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// `1h05m` for a number of seconds.
fn span(secs: u64) -> String {
    format!("{}h{:02}m", secs / 3600, secs % 3600 / 60)
}

/// One line per row of the try-out instances (id, launch time, `expires` tag; tab separated,
/// one instance per line): its age, and whether it is past its `expires`.
fn try_report(rows: &str, now: u64) -> Vec<String> {
    rows.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            let [id, launched, expires] = f[..] else {
                return None;
            };
            let age = parse_stamp(launched)
                .map_or("unknown".to_string(), |t| span(now.saturating_sub(t)));
            let end = match parse_stamp(expires) {
                Some(e) if e < now => format!("PAST expires {expires} by {}", span(now - e)),
                Some(e) => format!("expires {expires} (in {})", span(e - now)),
                None => format!("expires {expires} (unreadable)"),
            };
            Some(format!("try-out instance {}: age {age}, {end}", redact(id)))
        })
        .collect()
}

/// Prints the try-out instances of the project with their age and their `expires`. The
/// lifetime is not enforced by this command: an instance past it is for `clean`.
fn print_try_instances() {
    let rows = aws(&[
        "ec2",
        "describe-instances",
        "--filters",
        "Name=tag:project,Values=stafeto",
        "Name=tag-key,Values=expires",
        "Name=instance-state-name,Values=pending,running,stopping,stopped",
        "--query",
        "Reservations[].Instances[].[InstanceId,LaunchTime,Tags[?Key==`expires`]|[0].Value]",
    ]);
    match rows {
        Ok(rows) => {
            let lines = try_report(&rows, now_epoch());
            if lines.is_empty() {
                println!("try-out instances: none");
            }
            for l in lines {
                println!("{l}");
            }
        }
        Err(e) => println!("try-out instances: the list failed: {e}"),
    }
}

fn cost(spent: Duration, per_hour: f64) -> f64 {
    spent.as_secs_f64() / 3600.0 * per_hour
}

// ---- the image ------------------------------------------------------------------------

fn sha256(bytes: &[u8]) -> Result<[u8; 32], String> {
    let mut c = Command::new("shasum")
        .args(["-a", "256"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("shasum: {e}"))?;
    c.stdin
        .take()
        .unwrap()
        .write_all(bytes)
        .map_err(|e| e.to_string())?;
    let o = c.wait_with_output().map_err(|e| e.to_string())?;
    let hex = String::from_utf8_lossy(&o.stdout);
    let hex = hex.split_whitespace().next().unwrap_or("");
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(2 * i..2 * i + 2).ok_or("short digest")?, 16)
            .map_err(|e| e.to_string())?;
    }
    Ok(out)
}

pub fn base64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                s.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

/// The disk as a snapshot through the EBS direct API: the blocks that are not
/// all zero, 512 KiB each, with their SHA-256. Needs no bucket and no import
/// role; it does not work with default encryption (`check` says so).
fn direct_snapshot(s: &Session, disk: &Path, what: &str) -> Result<String, String> {
    let mut file = std::fs::File::open(disk).map_err(|e| format!("{}: {e}", disk.display()))?;
    let len = file
        .metadata()
        .map_err(|e| format!("{}: {e}", disk.display()))?
        .len() as usize;
    let gib = len.div_ceil(1 << 30);
    let mut args: Vec<String> = ["ebs", "start-snapshot", "--volume-size"]
        .map(String::from)
        .to_vec();
    args.push(gib.to_string());
    args.extend(["--description".to_string(), format!("stafeto {what}")]);
    args.extend(
        [
            "--tags",
            "Key=project,Value=stafeto",
            &format!("Key=session,Value={}", s.id),
        ]
        .map(String::from),
    );
    args.extend(["--query", "SnapshotId"].map(String::from));
    s.note("intent", Kind::Snapshot, what)?;
    let snap = aws_s(&args)?;
    s.note("created", Kind::Snapshot, &snap)?;
    let tmp = s.dir.join("block.bin");
    let mut sent = 0;
    // One block at a time: the data image is 2 GiB of mostly zeros.
    let mut buf = vec![0u8; BLOCK];
    for index in 0..len.div_ceil(BLOCK) {
        let take = BLOCK.min(len - index * BLOCK);
        buf.fill(0);
        file.read_exact(&mut buf[..take])
            .map_err(|e| format!("{}: {e}", disk.display()))?;
        if buf.iter().all(|b| *b == 0) {
            continue;
        }
        let full = buf.clone();
        std::fs::write(&tmp, &full).map_err(|e| e.to_string())?;
        let sum = base64(&sha256(&full)?);
        aws(&[
            "ebs",
            "put-snapshot-block",
            "--snapshot-id",
            &snap,
            "--block-index",
            &index.to_string(),
            "--block-data",
            tmp.to_str().unwrap(),
            "--data-length",
            &BLOCK.to_string(),
            "--checksum",
            &sum,
            "--checksum-algorithm",
            "SHA256",
        ])?;
        sent += 1;
    }
    let _ = std::fs::remove_file(&tmp);
    aws(&[
        "ebs",
        "complete-snapshot",
        "--snapshot-id",
        &snap,
        "--changed-blocks-count",
        &sent.to_string(),
    ])?;
    aws(&["ec2", "wait", "snapshot-completed", "--snapshot-ids", &snap])?;
    println!(
        "snapshot {} from {sent} blocks of {} KiB",
        redact(&snap),
        BLOCK / 1024
    );
    Ok(snap)
}

/// Registers the image: the disk's snapshot as the root, and the data image's as /dev/sdf.
fn register(s: &Session, snap: &str, data: &str, name: &str) -> Result<String, String> {
    let mut args: Vec<String> = [
        "ec2",
        "register-image",
        "--name",
        name,
        "--architecture",
        "arm64",
        "--virtualization-type",
        "hvm",
        "--boot-mode",
        "uefi",
        "--ena-support",
        "--imds-support",
        "v2.0",
        "--root-device-name",
        "/dev/sda1",
    ]
    .map(String::from)
    .to_vec();
    args.extend([
        "--block-device-mappings".to_string(),
        format!(
            "DeviceName=/dev/sda1,Ebs={{SnapshotId={snap},VolumeType=gp3,DeleteOnTermination=true}}"
        ),
        // The data volume: made from the snapshot of the data image, and gone with the instance.
        data_volume_mapping(data),
    ]);
    args.extend(s.tag_spec(&["image"]));
    args.extend(["--query", "ImageId"].map(String::from));
    s.note("intent", Kind::Image, name)?;
    let ami = aws_s(&args)?;
    s.note("created", Kind::Image, &ami)?;
    Ok(ami)
}

/// The disk of one flavour: the loader with `features`, the kernel and boot
/// image of `variant`.
fn make_disk(features: &[&str], variant: Variant, out: &Path) -> Result<Artifacts, String> {
    let a = build(variant)?;
    let a = Artifacts {
        boot_image: crate::aws_boot_image()?,
        ..a
    };
    let loader = efi::build_loader(features)?;
    efi::make_disk(&loader, &a, out)?;
    Ok(a)
}

fn image(args: &[String]) -> Result<(), String> {
    let dump = args.iter().any(|a| a == "--dump");
    let marks = args.iter().any(|a| a == "--marks");
    let broken = args.iter().any(|a| a == "--ena-break-aenq");
    let exits = args.iter().any(|a| a == "--ena-break-exit");
    if broken || exits {
        // Read once, where the program list of the image is made.
        // SAFETY: xtask is single-threaded here, before the image is built.
        unsafe { std::env::set_var("STAFETO_ENA_BREAK", if exits { "exit" } else { "1" }) };
    }
    // The layered root with the measurement of it (`layer-time`): the image has the layer service,
    // the program and its lower files, and the data volume holds a layer of 8,192 names.
    let layered = args.iter().any(|a| a == "--layered");
    if layered {
        // Read once, where the program list of the image is made.
        // SAFETY: xtask is single-threaded here, before the image is built.
        unsafe {
            std::env::set_var("STAFETO_LAYERED_ROOT", "1");
            std::env::set_var("STAFETO_LAYER_TIME", "1");
        }
    }
    let its_align = args.iter().any(|a| a == "--its-align-4k");
    let its_int = its_align || args.iter().any(|a| a == "--its-int");
    // A disk built before: registered as it is, nothing is built.
    let old_disk = flag(args, "--disk").map(PathBuf::from);
    let s = Session::open(flag(args, "--session"))?;
    let mut features = Vec::new();
    if dump {
        features.push("dump");
    }
    let variant = if marks {
        features.push("early-marks");
        Variant::EarlyMarks
    } else if its_align {
        // The self-test image with the queue and the property table on the
        // 4 KiB and 8 KiB blocks of before the fix.
        Variant::ItsIntAlign4k
    } else if its_int {
        // The kernel runs the self-test of the ITS before init starts and
        // prints one line for each CPU's LPI (`its-int:` in the console).
        Variant::ItsInt
    } else {
        Variant::Normal
    };
    let disk = old_disk.clone().unwrap_or_else(|| s.dir.join("disk.raw"));
    let t = Instant::now();
    if old_disk.is_none() {
        // The image check of the try-out gates the registration: a failure stops the build.
        crate::net_try::gate_aws_image(&crate::aws_boot_image()?)?;
        make_disk(&features, variant, &disk)?;
        println!("disk built in {:.1} s", t.elapsed().as_secs_f64());
    }
    let t = Instant::now();
    let flavour = if old_disk.is_some() {
        "old-disk"
    } else if layered {
        "layered"
    } else if its_align {
        "its-align4k"
    } else if dump {
        "dump"
    } else if marks {
        "marks"
    } else if exits {
        "ena-exit"
    } else if broken {
        "ena-break"
    } else if its_int {
        "its-int"
    } else {
        "plain"
    };
    // The data volume, made offline by the code of the first boot of datafs (no AWS call yet).
    let data_file = s.dir.join("data.raw");
    if layered {
        // The volume of the steps probe: 8,192 names in the live layer, the size of the data volume.
        data_image::make_layer_steps_volume(&data_file, data_image::DEFAULT_SIZE)?;
    } else {
        data_image::make(&data_file, data_image::DEFAULT_SIZE)?;
    }
    let snap = direct_snapshot(&s, &disk, flavour)?;
    let data_snap = direct_snapshot(&s, &data_file, "data")?;
    let ami = register(
        &s,
        &snap,
        &data_snap,
        &format!("stafeto-{flavour}-{}", s.id),
    )?;
    println!(
        "image {} registered in {:.1} s; session {}",
        redact(&ami),
        t.elapsed().as_secs_f64(),
        s.id
    );
    // The id goes to a file the next command reads: the log shows it redacted.
    std::fs::write(s.dir.join(format!("ami-{flavour}.txt")), &ami).map_err(|e| e.to_string())?;
    Ok(())
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

// ---- check -----------------------------------------------------------------------------

fn check() -> Result<(), String> {
    aws(&["sts", "get-caller-identity", "--query", "UserId"])
        .map_err(|e| format!("credentials: {e}"))?;
    println!("credentials: ok (profile {PROFILE}, region {REGION})");
    let enc = aws(&[
        "ec2",
        "get-ebs-encryption-by-default",
        "--query",
        "EbsEncryptionByDefault",
    ])?;
    println!(
        "EBS encryption by default: {enc} ({})",
        if enc == "False" {
            "the direct EBS API path is open"
        } else {
            "the direct EBS API path needs KMS rights: use the import path"
        }
    );
    let serial = aws(&[
        "ec2",
        "get-serial-console-access-status",
        "--query",
        "SerialConsoleAccessEnabled",
    ])?;
    println!("serial console access: {serial}");
    let (subnet, _) = default_subnet()?;
    println!("default subnet: {}", subnet.len() > 3);
    let ami = neighbour_ami()?;
    println!("neighbour image found: {}", ami.starts_with("ami-"));
    let (subnet, _) = default_subnet()?;
    let dry = aws_cmd(&[
        "ec2",
        "run-instances",
        "--dry-run",
        "--image-id",
        &ami,
        "--instance-type",
        "t4g.small",
        "--subnet-id",
        &subnet,
        "--credit-specification",
        "CpuCredits=standard",
    ])
    .output()
    .map_err(|e| e.to_string())?;
    let err = String::from_utf8_lossy(&dry.stderr);
    println!(
        "run-instances dry run: {}",
        if err.contains("DryRunOperation") {
            "permitted".to_string()
        } else {
            redact(err.trim())
        }
    );
    let found = project_resources()?;
    println!("resources of the project that exist: {}", found.len());
    print_try_instances();
    println!("types allowed: {ALLOWED_TYPES:?}, at most {MAX_LIVE} live, credits standard");
    Ok(())
}

// ---- boot --------------------------------------------------------------------------------

fn boot(args: &[String]) -> Result<(), String> {
    let ami = flag(args, "--ami").ok_or("boot needs --ami")?;
    let ty = flag(args, "--type").unwrap_or_else(|| "t4g.small".into());
    let end = flag(args, "--end");
    let timeout = flag(args, "--timeout")
        .and_then(|t| t.parse().ok())
        .unwrap_or(300);
    let stop = args.iter().any(|a| a == "--stop");
    let try_out = args.iter().any(|a| a == "--try");
    // One launch without the data volume: the instance shows the fallback of the image.
    let no_data = args.iter().any(|a| a == "--no-data-volume");
    let data_size = match flag(args, "--data-volume-size") {
        None => None,
        Some(_) if no_data => {
            return Err("--data-volume-size does not go with --no-data-volume".into());
        }
        Some(n) => Some(parse_gib(
            "--data-volume-size",
            &n,
            DATA_VOLUME_MIN_GIB,
            DATA_VOLUME_MAX_GIB,
        )?),
    };
    let data_mapping = data_size.map(sized);
    // A blank volume besides the data volume: made, tagged, journaled and attached as /dev/sdg.
    let blank = flag(args, "--blank-volume")
        .map(|n| parse_gib("--blank-volume", &n, 1, BLANK_VOLUME_MAX_GIB))
        .transpose()?;
    if try_out && stop {
        return Err("--try keeps the instance running: it does not go with --stop".into());
    }
    let lifetime = match flag(args, "--lifetime-hours") {
        None => TRY_LIFETIME_HOURS,
        Some(h) => h
            .parse::<u64>()
            .ok()
            .filter(|h| (1..=72).contains(h))
            .ok_or("--lifetime-hours takes a whole number from 1 to 72")?,
    };
    let expires = try_out.then(|| utc_stamp(now_epoch() + lifetime * 3600));
    let s = Session::open(flag(args, "--session"))?;
    // The try-out session: the key pair, the group open to this host alone, a public address.
    let (group, key) = if try_out {
        let live = live_instances()?;
        if live >= TRY_MAX_LIVE {
            return Err(format!(
                "{live} instances of the project are alive: a try-out session allows {TRY_MAX_LIVE}"
            ));
        }
        let cidr = operator_address()?;
        let key = try_key(&s)?;
        let g = try_group(&s, &cidr)?;
        assert_try(&g, &cidr)?;
        println!("try-out: key pair and group of session {} are ready", s.id);
        (Some(g), Some(key))
    } else {
        (None, None)
    };
    let (id, started) = launch(
        &s,
        &Launch {
            ami: &ami,
            ty: &ty,
            user_data: None,
            extra_snapshot: if no_data {
                Some(NO_DEVICE)
            } else {
                data_mapping.as_deref()
            },
            group: group.as_deref(),
            public_ip: try_out,
            private_ip: None,
            key_name: key.as_deref(),
            expires: expires.as_deref(),
        },
    )?;
    let result = (|| {
        if let Some(gib) = blank {
            attach_blank_volume(&s, &id, gib)?;
        }
        if try_out {
            // The address goes to the session's directory for the commands that follow and
            // to no log.
            let a = public_address(&id)?;
            std::fs::write(s.dir.join("address"), format!("{a}\n"))
                .map_err(|e| format!("address: {e}"))?;
            println!("public address {}", redact(&a));
        }
        // The MAC of the instance's interface, to compare with the one the
        // device reports: the last three octets only.
        match eni_mac(&id) {
            Ok(mac) => println!("interface mac ..:..:..:{}", last_octets(&mac)),
            Err(e) => println!("interface mac: {e}"),
        }
        let mut serial_text: Option<(u64, String)> = None;
        if let Some(n) = flag(args, "--serial").and_then(|n| n.parse().ok()) {
            for _ in 0..40 {
                if state(&id)? == "running" {
                    break;
                }
                std::thread::sleep(Duration::from_secs(3));
            }
            match serial(&s, &id, n) {
                Ok(t) => serial_text = Some((n, t)),
                Err(e) => println!("serial console: {e}"),
            }
        }
        let log = s.dir.join("console.log");
        let w = watch(&id, end.as_deref(), Duration::from_secs(timeout), &log)?;
        if let Some((n, t)) = &serial_text {
            // The serial capture starts when the connection is made. The console has the
            // start of the boot, so the two are printed as one text.
            let full = boot_text(&w.text, t);
            let _ = std::fs::write(s.dir.join("boot.log"), &full);
            println!(
                "--- console output and serial console, first {n} s (identifiers redacted) ---"
            );
            for l in full.lines() {
                println!("{}", redact(l));
            }
            println!("--- end of console output and serial console ---");
        } else {
            print_console(&w.text);
        }
        println!(
            "boot ended: marker {}, instance state {} after {:.0} s",
            if w.ended { "seen" } else { "not seen" },
            w.state,
            started.elapsed().as_secs_f64()
        );
        if stop {
            guard(Kind::Instance, &id)?;
            aws(&["ec2", "stop-instances", "--instance-ids", &id, "--force"])?;
            aws(&["ec2", "wait", "instance-stopped", "--instance-ids", &id])?;
            println!("instance stopped, volume kept");
        }
        Ok(())
    })();
    let result = if !(stop || try_out) || result.is_err() {
        release(&s, Kind::Instance, &id, result)
    } else {
        result
    };
    if try_out && result.is_ok() {
        println!(
            "the try-out instance stays up until `xtask aws clean --session {}` terminates it; meant to expire at {} (this is a tag: nothing enforces it yet)",
            s.id,
            expires.as_deref().unwrap_or("")
        );
        let volumes = volume_rate(&[data_size, blank].into_iter().flatten().collect::<Vec<_>>());
        let rate = PRICE_SMALL + PRICE_IPV4 + volumes;
        let part = if volumes > 0.0 {
            format!(" and the volumes {volumes:.4}")
        } else {
            String::new()
        };
        println!(
            "it costs {rate:.4} USD per hour, {:.2} USD per day, while it runs (the instance {PRICE_SMALL}, the public IPv4 address {PRICE_IPV4}{part})",
            rate * 24.0
        );
        return result;
    }
    println!(
        "estimated cost of this instance: {:.3} USD",
        cost(started.elapsed(), PRICE_SMALL)
    );
    result
}

/// The request that makes the blank volume of a session: gp3, `gib` GiB, in `zone`, with the
/// tags of the session so that the guard, `clean` and `sweep` take it.
fn blank_volume_args(s: &Session, zone: &str, gib: u32, instance: &str) -> Vec<String> {
    let mut args: Vec<String> = [
        "ec2",
        "create-volume",
        "--volume-type",
        "gp3",
        "--availability-zone",
        zone,
        "--size",
    ]
    .map(String::from)
    .to_vec();
    args.push(gib.to_string());
    args.extend(s.tag_spec(&["volume"]));
    // One blank volume per instance: a repeated call is the same call and finds the volume
    // the first one made.
    args.extend([
        "--client-token".to_string(),
        format!("stafeto-vol-{}-{instance}", s.id),
    ]);
    args.extend(["--query", "VolumeId"].map(String::from));
    args
}

/// The volumes of the session that EC2 has, journaled when the journal lacks them: a call that
/// made a volume and died before its line leaves one that `clean` and the guard would not see.
/// Returns the ids it journaled.
fn adopt_volumes(s: &Session) -> Result<Vec<String>, String> {
    let session = format!("Name=tag:session,Values={}", s.id);
    let found = aws(&[
        "ec2",
        "describe-volumes",
        "--filters",
        "Name=tag:project,Values=stafeto",
        &session,
        "Name=status,Values=creating,available,in-use,error",
        "--query",
        "Volumes[].VolumeId",
    ])?;
    let mut added = Vec::new();
    for id in found.split_whitespace().filter(|i| *i != "None") {
        if !s.live().iter().any(|(k, i)| *k == Kind::Volume && i == id) {
            s.note("created", Kind::Volume, id)?;
            added.push(id.to_string());
        }
    }
    Ok(added)
}

/// The mapping that makes a volume go with its instance.
fn blank_delete_with_instance() -> String {
    format!("DeviceName={BLANK_DEVICE},Ebs={{DeleteOnTermination=true}}")
}

/// Makes a blank volume of `gib` GiB in the zone of the instance and attaches it as /dev/sdg.
/// The journal has the intent before the call and the id after it; a volume that cannot be
/// attached is deleted again.
fn attach_blank_volume(s: &Session, instance: &str, gib: u32) -> Result<(), String> {
    aws(&[
        "ec2",
        "wait",
        "instance-running",
        "--instance-ids",
        instance,
    ])?;
    let zone = aws(&[
        "ec2",
        "describe-instances",
        "--instance-ids",
        instance,
        "--query",
        "Reservations[0].Instances[0].Placement.AvailabilityZone",
    ])?;
    let args = blank_volume_args(s, zone.trim(), gib, instance);
    s.note("intent", Kind::Volume, "blank")?;
    let vol = match aws_s(&args) {
        Ok(v) => v,
        Err(e) => {
            // The call may have made the volume before it failed: journal what the session has
            // and remove it.
            return match adopt_volumes(s) {
                Ok(found) => {
                    let mut result = Err(e);
                    for v in found {
                        result = release(s, Kind::Volume, &v, result);
                    }
                    result
                }
                Err(look) => Err(format!(
                    "{e}; and the lookup of a volume it may have made failed: {look}; run `xtask aws clean --session {}`",
                    s.id
                )),
            };
        }
    };
    s.note("created", Kind::Volume, &vol)?;
    let mut attach_called = false;
    let attached = (|| {
        aws(&["ec2", "wait", "volume-available", "--volume-ids", &vol])?;
        aws(&[
            "ec2",
            "attach-volume",
            "--volume-id",
            &vol,
            "--instance-id",
            instance,
            "--device",
            BLANK_DEVICE,
        ])?;
        attach_called = true;
        aws(&["ec2", "wait", "volume-in-use", "--volume-ids", &vol])?;
        aws(&[
            "ec2",
            "modify-instance-attribute",
            "--instance-id",
            instance,
            "--block-device-mappings",
            &blank_delete_with_instance(),
        ])
    })();
    match attached {
        Ok(_) => {
            println!(
                "attached a blank volume of {gib} GiB as {BLANK_DEVICE} ({})",
                redact(&vol)
            );
            Ok(())
        }
        Err(e) => {
            if attach_called {
                // A volume that is in use cannot be deleted: detach it and wait first.
                let _ = aws(&["ec2", "detach-volume", "--volume-id", &vol, "--force"]);
                let _ = aws(&["ec2", "wait", "volume-available", "--volume-ids", &vol]);
            }
            release(s, Kind::Volume, &vol, Err(e))
        }
    }
}

/// The MAC address of the first interface of the instance, as EC2 has it.
fn eni_mac(id: &str) -> Result<String, String> {
    let q = "Reservations[0].Instances[0].NetworkInterfaces[0].MacAddress";
    Ok(aws(&[
        "ec2",
        "describe-instances",
        "--instance-ids",
        id,
        "--query",
        q,
        "--output",
        "text",
    ])?
    .trim()
    .to_string())
}

/// The last three octets of a MAC address, `aa:bb:cc:dd:ee:ff` giving `dd:ee:ff`.
fn last_octets(mac: &str) -> String {
    let octets: Vec<&str> = mac.split(':').collect();
    octets[octets.len().saturating_sub(3)..].join(":")
}

// ---- the serial console -----------------------------------------------------------------

/// `aws boot --serial SECONDS`: the EC2 Serial Console through SSH with a
/// key made for the session; the text goes to `serial.log`. The host key is
/// taken on first use into the session's own known_hosts.
fn serial(s: &Session, id: &str, seconds: u64) -> Result<String, String> {
    // What is typed, and when (seconds after the connection): a line end to
    // wake the prompt, the command, a line end again.
    let script = [
        (seconds.saturating_sub(40), "\r".to_string()),
        (
            seconds.saturating_sub(30),
            "echo stafeto-ok; uname -a\r".to_string(),
        ),
        (seconds.saturating_sub(15), "\r".to_string()),
    ];
    serial_typing(s, id, seconds, &script)
}

/// The serial console of `id` for `seconds`, typing each `(second, text)` of `script` at its
/// second after the connection; what came is the text returned.
fn serial_typing(
    s: &Session,
    id: &str,
    seconds: u64,
    script: &[(u64, String)],
) -> Result<String, String> {
    let key = s.dir.join("serial");
    if !key.exists() {
        let st = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .status()
            .map_err(|e| e.to_string())?;
        if !st.success() {
            return Err("ssh-keygen failed".into());
        }
    }
    aws(&[
        "ec2-instance-connect",
        "send-serial-console-ssh-public-key",
        "--instance-id",
        id,
        "--serial-port",
        "0",
        "--ssh-public-key",
        &format!("file://{}.pub", key.display()),
    ])?;
    let log = s.dir.join("serial.log");
    let err = s.dir.join("serial.err");
    let out = std::fs::File::create(&log).map_err(|e| e.to_string())?;
    let errf = std::fs::File::create(&err).map_err(|e| e.to_string())?;
    let mut ssh = Command::new("ssh")
        .args(["-tt", "-v", "-i"])
        .arg(&key)
        .args([
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=30",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
        ])
        .arg(format!(
            "UserKnownHostsFile={}",
            s.dir.join("known_hosts").display()
        ))
        .arg(format!(
            "{id}.port0@serial-console.ec2-instance-connect.{REGION}.aws"
        ))
        .stdin(Stdio::piped())
        .stdout(out)
        .stderr(errf)
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut stdin = ssh.stdin.take();
    let mut next = 0;
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(seconds) {
        if ssh.try_wait().map_err(|e| e.to_string())?.is_some() {
            break;
        }
        if next < script.len()
            && start.elapsed() >= Duration::from_secs(script[next].0)
            && let Some(w) = stdin.as_mut()
        {
            let _ = w.write_all(script[next].1.as_bytes());
            let _ = w.flush();
            next += 1;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    drop(stdin);
    let _ = ssh.kill();
    let _ = ssh.wait();
    let mut text = std::fs::read_to_string(&log).unwrap_or_default();
    let e = std::fs::read_to_string(&err).unwrap_or_default();
    // The stages of the connection, to tell where a failure stands.
    for l in e.lines().filter(|l| {
        l.contains("Authenticated")
            || l.contains("Connection established")
            || l.contains("denied")
            || l.contains("Permission")
            || l.contains("closed")
            || l.contains("Host key")
    }) {
        let _ = writeln!(text, "[ssh] {}", redact(l));
    }
    Ok(text)
}

// ---- the neighbour and the dump ---------------------------------------------------------------

const NEIGHBOUR_SCRIPT: &str = r##"#!/bin/bash
# stafeto neighbour: prints what a Linux sees of the firmware to the console, as
# gzip and base64 records, a few at a time so that a poll of the last 64 KiB sees each.
exec 2>/dev/null
O=/dev/console
sent=0
emit() {
  local name="$1"
  { echo "STAFETO-BEGIN $name"; gzip -9 -c | base64 -w 160; echo "STAFETO-END $name"; } > $O
  sent=$((sent + 1))
  if [ $((sent % 4)) -eq 0 ]; then sleep 15; fi
}
sleep 20
for f in /sys/firmware/acpi/tables/*; do
  [ -f "$f" ] && emit "acpi-$(basename $f)" < "$f"
done
cat /proc/iomem | emit iomem.txt
cat /proc/interrupts | emit interrupts.txt
dmesg | grep -iE 'gic|its|ttyS|serial|arch_timer|acpi: |SPCR|PCI|psci|smccc|EFI|memory:|Booting|NUMA|MADT|IORT' | emit dmesg-firmware.txt
for d in /sys/bus/pci/devices/*; do
  echo "$(basename $d) vendor=$(cat $d/vendor) device=$(cat $d/device) class=$(cat $d/class)"
  cat $d/resource
done | emit pci.txt
for i in $(seq 1 30); do [ -b /dev/nvme1n1p1 ] && break; sleep 2; done
if [ -b /dev/nvme1n1p1 ]; then
  mkdir -p /mnt/esp && mount -o ro -t vfat /dev/nvme1n1p1 /mnt/esp
  for f in /mnt/esp/stafeto/dump/*; do [ -f "$f" ] && emit "dump-$(basename $f)" < "$f"; done
  ls -l /mnt/esp/stafeto /mnt/esp/stafeto/dump 2>&1 | emit esp-listing.txt
fi
# One line per NVMe controller: the PCI address, the model, the serial (the EBS volume
# id), and bytes 3072..3104 of Identify Controller (the vendor area where EBS writes the
# device name), read by nvme-cli or, without it, by one admin ioctl through python3.
idctrl() {
  if command -v nvme > /dev/null && nvme id-ctrl "$1" --raw-binary > /tmp/idc 2> /dev/null && [ "$(stat -c %s /tmp/idc)" -ge 3104 ]; then
    echo nvme-cli; return 0
  fi
  if command -v python3 > /dev/null && python3 - "$1" > /tmp/idc <<'PY' 2> /dev/null
import array, fcntl, struct, sys
buf = array.array('B', bytes(4096))
addr, _ = buf.buffer_info()
cmd = struct.pack('BBHIIIQQIIIIIIIIII', 6, 0, 0, 0, 0, 0, 0, addr, 0, 4096, 1, 0, 0, 0, 0, 0, 0, 0)
cmd = bytearray(cmd)
fcntl.ioctl(open(sys.argv[1], 'rb'), 0xC0484E41, cmd)
sys.stdout.buffer.write(buf.tobytes())
PY
  then
    echo python-ioctl; return 0
  fi
  echo none; return 1
}
{
  echo "# tools: nvme=$(command -v nvme) ebsnvme-id=$(command -v ebsnvme-id) python3=$(command -v python3)"
  for c in /sys/class/nvme/nvme*; do
    n=$(basename $c)
    m=$(idctrl /dev/$n)
    hex=$(dd if=/tmp/idc bs=1 skip=3072 count=32 2> /dev/null | od -An -v -tx1 | tr -d ' \n')
    ebs=$(command -v ebsnvme-id > /dev/null && ebsnvme-id -b /dev/${n}n1 2> /dev/null)
    echo "$n pci=$(basename $(readlink -f $c/device)) model=$(tr -s ' ' < $c/model | sed 's/ *$//' | tr ' ' '_') serial=$(tr -d ' ' < $c/serial) method=$m name_hex=$hex ebsnvme_id=$ebs"
    rm -f /tmp/idc
  done
} | emit nvme-map.txt
sleep 20
echo STAFETO-NEIGHBOUR-DONE > $O
sleep 300
"##;

/// The base64 text of one line of a record, or `None` for a line that has none. A kernel
/// message or a login prompt shares the console with the record: a line of such text
/// has no base64 part, and a record line cut by a kernel message (`AAAA[   12.3] text`)
/// gives the characters before the message. The gzip check of the whole record settles
/// whether what was kept is right.
fn record_fragment(line: &str) -> Option<&str> {
    let is64 = |c: char| c.is_ascii_alphanumeric() || "+/=".contains(c);
    if line.chars().all(is64) {
        return Some(line);
    }
    let end = line.find(|c: char| !is64(c))?;
    (end > 0 && line[end..].starts_with('[')).then(|| &line[..end])
}

/// Joins the records `STAFETO-BEGIN name` ... `STAFETO-END name` of a console
/// text into (name, base64 text) and decodes them. Lines of other text between the
/// two markers are skipped; a record the gzip check refuses is dropped.
fn records(text: &str) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut name: Option<String> = None;
    let mut body = String::new();
    for line in text.lines() {
        let line = line.trim();
        // A marker can follow other text on its line (a prompt without a line end).
        if let Some(at) = line.find("STAFETO-BEGIN ") {
            name = Some(line[at + "STAFETO-BEGIN ".len()..].trim().to_string());
            body.clear();
        } else if let Some(at) = line.find("STAFETO-END ") {
            let n = line[at + "STAFETO-END ".len()..].trim();
            if name.as_deref() == Some(n)
                && let Some(bytes) = unbase64(&body).and_then(|b| gunzip(&b))
            {
                out.insert(n.to_string(), bytes);
            }
            name = None;
        } else if name.is_some()
            && let Some(part) = record_fragment(line)
        {
            body.push_str(part);
        }
    }
    out
}

/// The text of a boot from the full console (`get-console-output`, which holds the
/// start) and the serial capture (which starts when the connection is made and
/// carries what was typed): the console, then the serial lines that follow what the
/// console already has. The longest run of console lines at its end that begins the serial
/// capture is the overlap.
fn boot_text(console: &str, serial: &str) -> String {
    let c: Vec<&str> = console.lines().map(str::trim_end).collect();
    let s: Vec<&str> = serial.lines().map(str::trim_end).collect();
    let overlap = (0..=c.len().min(s.len()))
        .rev()
        .find(|&n| c[c.len() - n..] == s[..n])
        .unwrap_or(0);
    let mut out: Vec<&str> = c;
    if overlap == 0 && !s.is_empty() && !out.is_empty() {
        out.push("--- the serial capture begins here ---");
    }
    out.extend(&s[overlap..]);
    let mut text = out.join("\n");
    text.push('\n');
    text
}

fn unbase64(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for c in s.bytes().filter(|c| *c != b'=') {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn gunzip(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut c = Command::new("gunzip")
        .arg("-c")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdin = c.stdin.take()?;
    let data = bytes.to_vec();
    let feeder = std::thread::spawn(move || {
        let _ = stdin.write_all(&data);
    });
    let o = c.wait_with_output().ok()?;
    let _ = feeder.join();
    o.status.success().then_some(o.stdout)
}

/// Matches the lines of `nvme-map.txt` (one per controller: `nvmeN pci=.. model=.. serial=..
/// method=.. name_hex=..`) with the instance's block device mappings (`DEVICE<TAB>vol-ID` per
/// line, as `describe-instances` prints them) and the root device name. The answer has one line
/// per controller with the PCI address, the role (`root`, `sdf`, the device name, or `unknown`),
/// the model, the method and the name field as hex and ASCII; no volume id is in it.
fn nvme_summary(map: &str, mappings: &str, root: &str) -> String {
    let devices: Vec<(&str, String)> = mappings
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            Some((f.next()?, f.next()?.replace('-', "")))
        })
        .collect();
    let mut out = String::new();
    for line in map.lines().filter(|l| !l.starts_with('#')) {
        let field = |k: &str| {
            line.split_whitespace()
                .find_map(|w| w.strip_prefix(k).and_then(|v| v.strip_prefix('=')))
                .unwrap_or("")
        };
        let serial = field("serial");
        let role = match devices
            .iter()
            .find(|(_, v)| !serial.is_empty() && *v == serial)
        {
            Some((d, _)) if *d == root => "root".to_string(),
            Some((d, _)) => d.rsplit('/').next().unwrap_or(d).to_string(),
            None => "unknown".to_string(),
        };
        let hex = field("name_hex");
        let ascii: String = (0..hex.len() / 2)
            .filter_map(|i| u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok())
            .map(|b| match b {
                0 => '.',
                0x20..=0x7e => b as char,
                _ => '?',
            })
            .collect();
        let _ = writeln!(
            out,
            "pci={} role={} model={} method={} name_hex={} name_ascii={}",
            field("pci"),
            role,
            field("model"),
            field("method"),
            hex,
            ascii
        );
    }
    out
}

fn neighbour(args: &[String]) -> Result<(), String> {
    let snapshot = if args.iter().any(|a| a == "--blank-sdf") {
        Some(BLANK_SDF.to_string())
    } else {
        flag(args, "--snapshot")
    };
    let s = Session::open(flag(args, "--session"))?;
    let script = s.dir.join("neighbour.sh");
    std::fs::write(&script, NEIGHBOUR_SCRIPT).map_err(|e| e.to_string())?;
    let ami = neighbour_ami()?;
    let (id, started) = launch(
        &s,
        &Launch {
            ami: &ami,
            ty: "t4g.small",
            user_data: Some(&script),
            extra_snapshot: snapshot.as_deref(),
            group: None,
            public_ip: false,
            private_ip: None,
            key_name: None,
            expires: None,
        },
    )?;
    let result = (|| {
        let out = s.dir.join("neighbour");
        std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
        let start = Instant::now();
        let mut got: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        loop {
            std::thread::sleep(Duration::from_secs(10));
            let text = console(&id).unwrap_or_default();
            for (k, v) in records(&text) {
                got.insert(k, v);
            }
            if text.contains("STAFETO-NEIGHBOUR-DONE") || start.elapsed() > Duration::from_secs(900)
            {
                let _ = std::fs::write(s.dir.join("neighbour-console.log"), &text);
                break;
            }
        }
        for (k, v) in &got {
            std::fs::write(out.join(k), v).map_err(|e| e.to_string())?;
        }
        println!(
            "neighbour: {} records: {:?}",
            got.len(),
            got.keys().collect::<Vec<_>>()
        );
        if let Some(map) = got.get("nvme-map.txt") {
            let mappings = aws(&[
                "ec2",
                "describe-instances",
                "--instance-ids",
                &id,
                "--query",
                "Reservations[0].Instances[0].BlockDeviceMappings[].[DeviceName,Ebs.VolumeId]",
                "--output",
                "text",
            ])?;
            let root = aws(&[
                "ec2",
                "describe-instances",
                "--instance-ids",
                &id,
                "--query",
                "Reservations[0].Instances[0].RootDeviceName",
            ])?;
            let summary = nvme_summary(&String::from_utf8_lossy(map), &mappings, &root);
            std::fs::write(out.join("nvme-map-summary.txt"), &summary)
                .map_err(|e| e.to_string())?;
            println!("--- nvme map (no ids) ---\n{summary}--- end of nvme map ---");
        } else {
            println!("neighbour: no nvme-map.txt record arrived");
        }
        Ok(())
    })();
    let result = release(&s, Kind::Instance, &id, result);
    println!(
        "estimated cost of the neighbour: {:.3} USD",
        cost(started.elapsed(), PRICE_SMALL)
    );
    result
}

/// `aws dump`: the loader with `dump` on a t4g.small writes the firmware's
/// tables and memory map to its ESP and stops; the volume is copied to a
/// snapshot and read by a neighbour of the same type, which prints it, and the
/// tables its own Linux sees, to its console.
///
/// One step per call (the image, the dump run, the neighbour), each resuming
/// the session named by `--session`, so that a call stays inside the time a
/// foreground command may take; `--all` runs the steps in one call.
fn dump(args: &[String]) -> Result<(), String> {
    let all = args.iter().any(|a| a == "--all");
    let s = Session::open(flag(args, "--session"))?;
    let id_arg = ["--session".to_string(), s.id.clone()];
    if !s.dir.join("ami-dump.txt").exists() {
        image(&[vec!["--dump".to_string()], id_arg.to_vec()].concat())?;
        if !all {
            println!("next: xtask aws dump --session {}", s.id);
            return Ok(());
        }
    }
    let snap_file = s.dir.join("dump-snapshot.txt");
    if !snap_file.exists() {
        dump_run(&s)?;
        if !all {
            println!("next: xtask aws dump --session {}", s.id);
            return Ok(());
        }
    }
    let snap = std::fs::read_to_string(&snap_file).map_err(|e| e.to_string())?;
    neighbour(
        &[
            vec!["--snapshot".to_string(), snap.trim().to_string()],
            id_arg.to_vec(),
        ]
        .concat(),
    )?;
    println!(
        "session {}: results under target/aws/{}/neighbour",
        s.id, s.id
    );
    Ok(())
}

/// The loader's dump run: the console, then a snapshot of the stopped volume.
fn dump_run(s: &Session) -> Result<(), String> {
    let ami = std::fs::read_to_string(s.dir.join("ami-dump.txt")).map_err(|e| e.to_string())?;
    let (id, started) = launch(
        s,
        &Launch {
            ami: ami.trim(),
            ty: "t4g.small",
            user_data: None,
            extra_snapshot: None,
            group: None,
            public_ip: false,
            private_ip: None,
            key_name: None,
            expires: None,
        },
    )?;
    let snap = (|| {
        let w = watch(
            &id,
            Some("efi-loader: dump written"),
            Duration::from_secs(300),
            &s.dir.join("console.log"),
        )?;
        print_console(&w.text);
        if !w.ended {
            return Err("the loader wrote no dump within 300 s".to_string());
        }
        guard(Kind::Instance, &id)?;
        aws(&["ec2", "stop-instances", "--instance-ids", &id, "--force"])?;
        aws(&["ec2", "wait", "instance-stopped", "--instance-ids", &id])?;
        let vol = aws(&[
            "ec2",
            "describe-instances",
            "--instance-ids",
            &id,
            "--query",
            "Reservations[0].Instances[0].BlockDeviceMappings[0].Ebs.VolumeId",
        ])?;
        guard(Kind::Volume, &vol)?;
        let mut args: Vec<String> = [
            "ec2",
            "create-snapshot",
            "--volume-id",
            &vol,
            "--description",
            "stafeto dump",
        ]
        .map(String::from)
        .to_vec();
        args.extend(s.tag_spec(&["snapshot"]));
        args.extend(["--query", "SnapshotId"].map(String::from));
        s.note("intent", Kind::Snapshot, "dump copy")?;
        let snap = aws_s(&args)?;
        s.note("created", Kind::Snapshot, &snap)?;
        aws(&["ec2", "wait", "snapshot-completed", "--snapshot-ids", &snap])?;
        Ok(snap)
    })();
    let snap = release(s, Kind::Instance, &id, snap);
    println!(
        "estimated cost of the dump instance: {:.3} USD",
        cost(started.elapsed(), PRICE_SMALL)
    );
    let snap = snap?;
    std::fs::write(s.dir.join("dump-snapshot.txt"), snap).map_err(|e| e.to_string())
}

// ---- the pair: stafeto and a Linux neighbour in one group ---------------------------------------

/// What the one session that reaches the internet opens on the way out, besides the
/// group itself: the ports of `wget` and of the name server (the answer to a request is
/// return traffic of the group's state, nothing comes in from outside).
const INTERNET_EGRESS: [(&str, u16); 3] = [("tcp", 80), ("tcp", 443), ("udp", 53)];

/// The rule of the group for itself, all protocols: the pair talks to each other.
fn self_rule(group: &str) -> String {
    format!("IpProtocol=-1,UserIdGroupPairs=[{{GroupId={group}}}]")
}

/// The rule of the internet session for one of `INTERNET_EGRESS`.
fn internet_rule((protocol, port): (&str, u16)) -> String {
    format!("IpProtocol={protocol},FromPort={port},ToPort={port},IpRanges=[{{CidrIp=0.0.0.0/0}}]")
}

/// The session's group of the pair: inbound and outbound only to its own members. With
/// `internet` the way out also lets TCP 80 and 443 and UDP 53 go to any address; nothing
/// comes in from outside in either form.
fn pair_group(s: &Session, internet: bool) -> Result<String, String> {
    if let Some((_, g)) = s.live().into_iter().find(|(k, _)| *k == Kind::Group) {
        return Ok(g);
    }
    let (_, vpc) = default_subnet()?;
    s.note("intent", Kind::Group, "stafeto-pair")?;
    let mut args: Vec<String> = ["ec2", "create-security-group", "--group-name"]
        .map(String::from)
        .to_vec();
    args.push(format!("stafeto-pair-{}", s.id));
    args.extend(
        [
            "--description",
            "stafeto: the pair talks to each other",
            "--vpc-id",
            &vpc,
        ]
        .map(String::from),
    );
    args.extend(s.tag_spec(&["security-group"]));
    args.extend(["--query", "GroupId"].map(String::from));
    let g = aws_s(&args)?;
    s.note("created", Kind::Group, &g)?;
    aws(&[
        "ec2",
        "revoke-security-group-egress",
        "--group-id",
        &g,
        "--ip-permissions",
        "IpProtocol=-1,IpRanges=[{CidrIp=0.0.0.0/0}]",
    ])?;
    aws(&[
        "ec2",
        "authorize-security-group-ingress",
        "--group-id",
        &g,
        "--ip-permissions",
        &self_rule(&g),
    ])?;
    aws(&[
        "ec2",
        "authorize-security-group-egress",
        "--group-id",
        &g,
        "--ip-permissions",
        &self_rule(&g),
    ])?;
    if internet {
        for rule in INTERNET_EGRESS {
            aws(&[
                "ec2",
                "authorize-security-group-egress",
                "--group-id",
                &g,
                "--ip-permissions",
                &internet_rule(rule),
            ])?;
        }
    }
    Ok(g)
}

/// The guard of the pair's group: every rule in names the group itself (no address range),
/// and every rule out names the group or, in the internet session, one of
/// `INTERNET_EGRESS` for all addresses.
fn assert_pair(group: &str, internet: bool) -> Result<(), String> {
    let inbound = aws(&[
        "ec2",
        "describe-security-groups",
        "--group-ids",
        group,
        "--query",
        "SecurityGroups[0].IpPermissions[].[length(IpRanges),length(Ipv6Ranges),length(PrefixListIds),length(UserIdGroupPairs)]",
    ])?;
    let nums: Vec<&str> = inbound.split_whitespace().collect();
    if nums.chunks(4).any(|c| c[..3].iter().any(|n| *n != "0")) || nums.len() != 4 {
        return Err(format!(
            "group {} lets something in other than its own members: no instance starts in it",
            redact(group)
        ));
    }
    let wide = aws(&[
        "ec2",
        "describe-security-groups",
        "--group-ids",
        group,
        "--query",
        "SecurityGroups[0].IpPermissionsEgress[?length(IpRanges) > `0` || length(Ipv6Ranges) > `0`].[IpProtocol,FromPort,ToPort]",
    ])?;
    let found: Vec<&str> = wide.split_whitespace().collect();
    let allowed: Vec<String> = if internet {
        INTERNET_EGRESS
            .iter()
            .flat_map(|(p, n)| [p.to_string(), n.to_string(), n.to_string()])
            .collect()
    } else {
        Vec::new()
    };
    let mut triples: Vec<&[&str]> = found.chunks(3).collect();
    triples.sort();
    let mut want: Vec<Vec<&str>> = allowed
        .chunks(3)
        .map(|c| c.iter().map(String::as_str).collect())
        .collect();
    want.sort();
    if !found.len().is_multiple_of(3)
        || triples.len() != want.len()
        || triples.iter().zip(&want).any(|(a, b)| *a != b.as_slice())
    {
        return Err(format!(
            "group {} lets more out than the pair needs: no instance starts in it",
            redact(group)
        ));
    }
    Ok(())
}

/// The neighbour's address in the subnet: the host 200 of the network the CIDR block names
/// (the subnet is at least a /24: the default ones are a /20), so that stafeto can be told
/// where it is before the neighbour exists.
fn neighbour_address(cidr: &str) -> Result<String, String> {
    let (net, bits) = cidr
        .split_once('/')
        .ok_or_else(|| format!("{cidr:?} is no block"))?;
    let bits: u8 = bits.parse().map_err(|_| format!("{cidr:?} is no block"))?;
    let o: Vec<&str> = net.split('.').collect();
    if o.len() != 4 || bits > 24 || o.iter().any(|x| x.parse::<u8>().is_err()) {
        return Err(format!("{cidr:?} is no block of at least 254 hosts"));
    }
    Ok(format!("{}.{}.{}.200", o[0], o[1], o[2]))
}

/// What the neighbour does as its user data: serves a page on port 8080 for stafeto's `wget`,
/// pings stafeto and fetches its page with `curl`, every 15 s, and says what it got on its
/// console in lines that begin with `NEIGHBOUR-`.
fn pair_neighbour_script(stafetos: &[String]) -> String {
    let list = stafetos.join(" ");
    format!(
        r#"#!/bin/bash
exec 2>/dev/null
O=/dev/console
HOSTS="{list}"
mkdir -p /srv/n
echo stafeto-neighbour-page > /srv/n/index.html
(cd /srv/n && python3 -m http.server 8080 --bind 0.0.0.0 > /dev/null 2>&1 &)
echo "NEIGHBOUR-START" > $O
sleep 45
for i in $(seq 1 60); do
  k=0
  for STAF in $HOSTS; do
    k=$((k + 1))
    p=$(ping -c 3 -W 2 $STAF | grep -E 'transmitted|rtt' | tr '\n' ' ')
    echo "NEIGHBOUR-PING $i host$k $p" > $O
    c=$(curl -m 5 -s -o /tmp/page -w '%{{http_code}}' http://$STAF/)
    echo "NEIGHBOUR-CURL $i host$k $c $(head -c 80 /tmp/page | tr -d '\r\n')" > $O
  done
  sleep 15
done
echo "NEIGHBOUR-DONE" > $O
"#
    )
}

/// The lines stafeto is typed, each at its second after the serial connection: the page it
/// serves, a fetch from the neighbour's page and, in the internet session, from the internet.
/// `@NEIGHBOUR@` is the neighbour's address.
fn pair_commands(internet: bool) -> Vec<String> {
    let mut c = vec![
        "echo stafeto-pair-start".to_string(),
        "echo stafeto-httpd-ok > /tmp/index.html; httpd -p 80 -h /tmp &".to_string(),
        "wget -T 10 -O - http://@NEIGHBOUR@:8080/".to_string(),
    ];
    if internet {
        c.push("wget -T 20 -O - http://example.com/".to_string());
    }
    c.push("echo stafeto-pair-done".to_string());
    c
}

/// The typed lines at their seconds: the first after `delay`, then one every `gap`, each
/// with the neighbour's address put in and a line end after it.
fn typed(commands: &[String], neighbour: &str, delay: u64, gap: u64) -> Vec<(u64, String)> {
    let mut out = vec![(delay.saturating_sub(10), "\r".to_string())];
    for (i, c) in commands.iter().enumerate() {
        out.push((
            delay + gap * i as u64,
            format!("{}\r", c.replace("@NEIGHBOUR@", neighbour)),
        ));
    }
    out
}

fn instance_ip(id: &str) -> Result<String, String> {
    aws(&[
        "ec2",
        "describe-instances",
        "--instance-ids",
        id,
        "--query",
        "Reservations[0].Instances[0].PrivateIpAddress",
    ])
}

fn subnet_cidr() -> Result<String, String> {
    let (subnet, _) = default_subnet()?;
    aws(&[
        "ec2",
        "describe-subnets",
        "--subnet-ids",
        &subnet,
        "--query",
        "Subnets[0].CidrBlock",
    ])
}

/// `aws pair`: stafeto and an Amazon Linux neighbour in the pair's group. The neighbour serves
/// a page and pings and fetches stafeto's; stafeto, typed through the serial console, serves a
/// page, fetches the neighbour's and, with `--internet`, example.com. The consoles of both are
/// printed (identifiers and addresses hidden), both instances end, and the group goes.
fn pair(args: &[String]) -> Result<(), String> {
    let ami = flag(args, "--ami").ok_or("pair needs --ami")?;
    let internet = args.iter().any(|a| a == "--internet");
    let count: usize = flag(args, "--count")
        .and_then(|n| n.parse().ok())
        .unwrap_or(1)
        .clamp(1, 3);
    let seconds: u64 = flag(args, "--serial")
        .and_then(|n| n.parse().ok())
        .unwrap_or(330);
    let delay: u64 = flag(args, "--delay")
        .and_then(|n| n.parse().ok())
        .unwrap_or(90);
    let gap: u64 = flag(args, "--gap")
        .and_then(|n| n.parse().ok())
        .unwrap_or(25);
    let s = Session::open(flag(args, "--session"))?;
    let group = pair_group(&s, internet)?;
    assert_pair(&group, internet)?;
    let mut stafetos: Vec<(String, Instant)> = Vec::new();
    let mut neighbour: Option<(String, Instant)> = None;
    let result = (|| {
        for _ in 0..count {
            stafetos.push(launch(
                &s,
                &Launch {
                    ami: &ami,
                    ty: "t4g.small",
                    user_data: None,
                    extra_snapshot: None,
                    group: Some(&group),
                    public_ip: internet,
                    private_ip: None,
                    key_name: None,
                    expires: None,
                },
            )?);
        }
        let mut ips = Vec::new();
        for (sid, _) in &stafetos {
            match eni_mac(sid) {
                Ok(mac) => println!("interface mac ..:..:..:{}", last_octets(&mac)),
                Err(e) => println!("interface mac: {e}"),
            }
            ips.push(instance_ip(sid)?);
        }
        let nip = neighbour_address(&subnet_cidr()?)?;
        let script = s.dir.join("pair-neighbour.sh");
        std::fs::write(&script, pair_neighbour_script(&ips)).map_err(|e| e.to_string())?;
        let nami = neighbour_ami()?;
        neighbour = Some(launch(
            &s,
            &Launch {
                ami: &nami,
                ty: "t4g.small",
                user_data: Some(&script),
                extra_snapshot: None,
                group: Some(&group),
                public_ip: false,
                private_ip: Some(&nip),
                key_name: None,
                expires: None,
            },
        )?);
        let nid = neighbour
            .as_ref()
            .map(|(i, _)| i.clone())
            .unwrap_or_default();
        for (sid, _) in &stafetos {
            for _ in 0..40 {
                if state(sid)? == "running" {
                    break;
                }
                std::thread::sleep(Duration::from_secs(3));
            }
        }
        let commands = pair_commands(internet);
        let typing = typed(&commands, &nip, delay, gap);
        // The serial consoles of all the instances at once, one thread each.
        let texts: Vec<Result<String, String>> = std::thread::scope(|scope| {
            let handles: Vec<_> = stafetos
                .iter()
                .map(|(sid, _)| {
                    let (s, typing) = (&s, &typing);
                    scope.spawn(move || serial_typing(s, sid, seconds, typing))
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap_or_else(|_| Err("serial thread".into())))
                .collect()
        });
        for (k, t) in texts.iter().enumerate() {
            println!("--- stafeto {}, serial console, {seconds} s ---", k + 1);
            match t {
                Ok(text) => text.lines().for_each(|l| println!("{}", redact(l))),
                Err(e) => println!("serial: {e}"),
            }
            println!("--- end of serial console ---");
        }
        let begun = Instant::now();
        let mut ntext = String::new();
        loop {
            if let Ok(t) = console(&nid)
                && !t.is_empty()
            {
                ntext = t;
            }
            let got = ntext
                .lines()
                .filter(|l| l.contains("NEIGHBOUR-CURL") && l.contains(" 200 "))
                .count();
            if got >= count || begun.elapsed() > Duration::from_secs(120) {
                break;
            }
            std::thread::sleep(Duration::from_secs(10));
        }
        println!("--- neighbour, console lines ---");
        for l in ntext.lines().filter(|l| l.contains("NEIGHBOUR-")) {
            println!("{}", redact(l));
        }
        println!("--- end of neighbour ---");
        for (k, (sid, _)) in stafetos.iter().enumerate() {
            let sconsole = console(sid).unwrap_or_default();
            let _ = std::fs::write(s.dir.join(format!("console-{}.log", k + 1)), &sconsole);
            println!("--- stafeto {} console (its, ena, net lines) ---", k + 1);
            for l in sconsole.lines().filter(|l| {
                l.contains("its-int")
                    || l.contains("ena:")
                    || l.starts_with("net:")
                    || l.contains("iidr")
            }) {
                println!("{}", redact(l));
            }
            println!("--- end of console ---");
        }
        Ok(())
    })();
    let mut result = result;
    if let Some((nid, nstart)) = neighbour {
        result = release(&s, Kind::Instance, &nid, result);
        println!(
            "estimated cost of the neighbour: {:.3} USD",
            cost(nstart.elapsed(), PRICE_SMALL)
        );
    }
    for (sid, started) in stafetos {
        result = release(&s, Kind::Instance, &sid, result);
        println!(
            "estimated cost of a stafeto: {:.3} USD",
            cost(started.elapsed(), PRICE_SMALL)
        );
    }
    result
}

pub fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("pair") => pair(&args[1..]),
        Some("check") => check(),
        Some("image") => image(&args[1..]),
        Some("boot") => boot(&args[1..]),
        Some("dump") => dump(&args[1..]),
        Some("neighbour") => neighbour(&args[1..]),
        Some("clean") => {
            let id = flag(args, "--session").ok_or("clean needs --session")?;
            clean(
                &Session::open(Some(id))?,
                args.iter().any(|a| a == "--keep-image"),
            )
        }
        Some("sweep") => sweep(&args[1..]),
        _ => Err(USAGE.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_image_maps_sdf_to_the_snapshot_of_the_data_image() {
        assert_eq!(
            data_volume_mapping("snap-0123456789abcdef1"),
            "DeviceName=/dev/sdf,Ebs={SnapshotId=snap-0123456789abcdef1,VolumeType=gp3,DeleteOnTermination=true}"
        );
        // The size comes from the snapshot: no VolumeSize in the mapping.
        assert!(!data_volume_mapping("snap-1").contains("VolumeSize"));
        // The data image is the 2 GiB the snapshot is made with.
        assert_eq!(data_image::DEFAULT_SIZE, 2 << 30);
    }

    #[test]
    fn a_launch_maps_sdf_to_a_blank_volume_a_snapshot_or_no_device() {
        assert_eq!(
            launch_mapping(BLANK_SDF),
            "DeviceName=/dev/sdf,Ebs={VolumeSize=1,VolumeType=gp3,DeleteOnTermination=true}"
        );
        assert_eq!(
            launch_mapping("snap-0123"),
            "DeviceName=/dev/sdf,Ebs={SnapshotId=snap-0123,VolumeType=gp3,DeleteOnTermination=true}"
        );
        // The same device name as the image's data volume, so it replaces that mapping.
        assert_eq!(launch_mapping(NO_DEVICE), "DeviceName=/dev/sdf,NoDevice=");
        assert!(data_volume_mapping("snap-1").starts_with("DeviceName=/dev/sdf,"));
    }

    #[test]
    fn the_nvme_map_names_the_root_and_the_data_volume_without_their_ids() {
        let pad = "00".repeat(29);
        let map = format!(
            "# tools: nvme=/usr/sbin/nvme\n\
             nvme0 pci=0000:00:1f.0 model=Amazon_Elastic_Block_Store serial=vol0aaaa method=nvme-cli name_hex=736466{pad}\n\
             nvme1 pci=0000:00:04.0 model=Amazon_Elastic_Block_Store serial=vol0bbbb method=python-ioctl name_hex=7876646100{}\n\
             nvme2 pci=0000:00:09.0 model=Other serial=x method=none name_hex=\n",
            "00".repeat(27)
        );
        let maps = "/dev/xvda\tvol-0bbbb\n/dev/sdf\tvol-0aaaa\n";
        let s = nvme_summary(&map, maps, "/dev/xvda");
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("pci=0000:00:1f.0 role=sdf model=Amazon_Elastic_Block_Store method=nvme-cli name_hex=736466"));
        assert!(lines[0].ends_with(&format!("name_ascii=sdf{}", ".".repeat(29))));
        assert!(lines[1].contains("pci=0000:00:04.0 role=root "));
        assert!(lines[1].contains("name_ascii=xvda"));
        assert!(lines[2].contains("role=unknown"));
        assert!(!s.contains("vol"));
    }

    #[test]
    fn a_mac_is_cut_to_its_last_three_octets() {
        assert_eq!(last_octets("06:1b:2c:3d:4e:5f"), "3d:4e:5f");
        assert_eq!(last_octets("4e:5f"), "4e:5f");
        assert_eq!(last_octets(""), "");
    }

    #[test]
    fn redact_hides_identifiers_and_accounts() {
        let t = "i-0123456789abcdef0 ami-0123456789abcdef0 snap-0123456789abcdef0 123456789012 x";
        assert_eq!(redact(t), "i-... ami-... snap-... <account> x");
        assert_eq!(redact("1234567890123"), "1234567890123");
        assert_eq!(redact("vol-0123456789abcdef0z"), "vol-0123456789abcdef0z");
    }

    #[test]
    fn addresses_are_hidden_and_other_numbers_are_not() {
        assert_eq!(
            redact("lease 10.1.2.3/20 gw 172.31.0.1."),
            "lease <ip>/20 gw <ip>."
        );
        assert_eq!(
            redact("version 0.10 and 1.2.3 and 300.1.1.1"),
            "version 0.10 and 1.2.3 and 300.1.1.1"
        );
        assert_eq!(redact("1.2.3.4.5"), "1.2.3.4.5");
        assert_eq!(
            redact("ena: caps 0x3028 dma_width 48"),
            "ena: caps 0x3028 dma_width 48"
        );
    }

    #[test]
    fn the_pair_rules_name_the_group_itself_and_the_internet_ones_three_ports() {
        assert_eq!(
            self_rule("sg-1"),
            "IpProtocol=-1,UserIdGroupPairs=[{GroupId=sg-1}]"
        );
        let rules: Vec<String> = INTERNET_EGRESS.iter().map(|r| internet_rule(*r)).collect();
        assert_eq!(rules.len(), 3);
        assert!(rules[2].starts_with("IpProtocol=udp,FromPort=53,ToPort=53,"));
        // No rule for the way in has an address range: the one rule is the group's own.
        assert!(!self_rule("sg-1").contains("CidrIp"));
    }

    #[test]
    fn the_neighbours_address_is_the_200th_host_of_the_subnets_network() {
        assert_eq!(neighbour_address("172.31.0.0/20").unwrap(), "172.31.0.200");
        assert_eq!(neighbour_address("10.0.5.0/24").unwrap(), "10.0.5.200");
        assert!(neighbour_address("10.0.5.0/28").is_err());
        assert!(neighbour_address("nonsense").is_err());
    }

    #[test]
    fn the_neighbour_script_carries_the_address_it_is_given_and_says_its_lines_on_the_console() {
        let t = pair_neighbour_script(&["172.31.9.9".to_string(), "172.31.9.10".to_string()]);
        assert!(t.contains("HOSTS=\"172.31.9.9 172.31.9.10\""));
        assert!(t.starts_with("#!/bin/bash"));
        for word in [
            "NEIGHBOUR-PING",
            "NEIGHBOUR-CURL",
            "http.server 8080",
            "NEIGHBOUR-DONE",
        ] {
            assert!(t.contains(word), "{word}");
        }
    }

    #[test]
    fn the_typed_lines_follow_each_other_by_the_gap_and_name_the_neighbour() {
        let c = pair_commands(true);
        assert!(c.iter().any(|l| l.contains("example.com")));
        assert!(
            !pair_commands(false)
                .iter()
                .any(|l| l.contains("example.com"))
        );
        let t = typed(&c, "172.31.0.200", 90, 25);
        assert_eq!(t[0], (80, "\r".to_string()));
        assert_eq!(t[1].0, 90);
        assert_eq!(t[2].0, 115);
        assert!(t[3].1.contains("http://172.31.0.200:8080/"));
        assert!(t.iter().all(|(_, l)| l.ends_with('\r')));
    }

    #[test]
    fn the_nic_of_an_instance_names_the_group_the_public_address_and_the_fixed_one() {
        assert_eq!(
            nic_spec("subnet-1", "sg-1", false, None),
            "DeviceIndex=0,SubnetId=subnet-1,AssociatePublicIpAddress=false,Groups=sg-1"
        );
        assert!(
            nic_spec("subnet-1", "sg-1", true, Some("10.0.0.200"))
                .ends_with("AssociatePublicIpAddress=true,Groups=sg-1,PrivateIpAddress=10.0.0.200")
        );
    }

    #[test]
    fn base64_matches_the_known_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(unbase64("Zm9vYmFy").unwrap(), b"foobar");
        assert_eq!(unbase64("Zm8=").unwrap(), b"fo");
    }

    #[test]
    fn the_journal_lists_what_was_created_and_not_deleted() {
        let dir = std::env::temp_dir().join(format!("stafeto-aws-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let s = Session {
            id: "1".into(),
            dir: dir.clone(),
        };
        s.note("intent", Kind::Instance, "t4g.small").unwrap();
        s.note("created", Kind::Instance, "i-1").unwrap();
        s.note("created", Kind::Volume, "vol-1").unwrap();
        s.note("deleted", Kind::Instance, "i-1").unwrap();
        assert_eq!(s.live(), vec![(Kind::Volume, "vol-1".to_string())]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn records_are_rebuilt_from_a_console_with_noise() {
        let mut c = Command::new("gzip")
            .arg("-c")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        c.stdin.take().unwrap().write_all(b"hi\n").unwrap();
        let gz = c.wait_with_output().unwrap().stdout;
        let text = format!(
            "boot noise\nSTAFETO-BEGIN a\n{}\nSTAFETO-END a\nmore\nSTAFETO-BEGIN b\nkernel: text\nSTAFETO-END b\n",
            base64(&gz)
        );
        let r = records(&text);
        assert_eq!(r.get("a").map(Vec::as_slice), Some(&b"hi\n"[..]));
        assert!(!r.contains_key("b"));
    }

    fn gzip_of(data: &[u8]) -> String {
        let mut c = Command::new("gzip")
            .arg("-c")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        c.stdin.take().unwrap().write_all(data).unwrap();
        base64(&c.wait_with_output().unwrap().stdout)
    }

    #[test]
    fn a_record_survives_kernel_lines_and_a_login_prompt_between_its_lines() {
        let payload: Vec<u8> = (0..400u32).map(|i| (i * 7 % 251) as u8).collect();
        let b = gzip_of(&payload);
        let (x, rest) = b.split_at(b.len() / 3);
        let (y, z) = rest.split_at(rest.len() / 2);
        let text = format!(
            "STAFETO-BEGIN r\n{x}\n[   12.345678] ena 0000:00:05.0: link up\n{y}\nip-10-0-0-1 login: \n{z}\nSTAFETO-END r\n"
        );
        assert_eq!(records(&text).get("r"), Some(&payload));
    }

    #[test]
    fn a_record_line_cut_by_a_kernel_message_keeps_both_halves() {
        let payload = b"the firmware tables\n".repeat(20);
        let b = gzip_of(&payload);
        let (x, y) = b.split_at(b.len() / 2);
        let text =
            format!("STAFETO-BEGIN r\n{x}[   13.5] random: crng init done\n{y}\nSTAFETO-END r\n");
        assert_eq!(records(&text).get("r"), Some(&payload));
    }

    #[test]
    fn a_marker_after_text_without_a_line_end_still_counts() {
        let b = gzip_of(b"hi\n");
        let text = format!("login: STAFETO-BEGIN r\n{b}\n[ 1.0] msg STAFETO-END r\n");
        assert_eq!(
            records(&text).get("r").map(Vec::as_slice),
            Some(&b"hi\n"[..])
        );
    }

    #[test]
    fn a_damaged_record_is_dropped_and_the_next_one_is_kept() {
        let good = gzip_of(b"ok\n");
        let text = format!(
            "STAFETO-BEGIN a\nAAAAAAAA login: BBBB\nSTAFETO-END a\nSTAFETO-BEGIN b\n{good}\nSTAFETO-END b\n"
        );
        let r = records(&text);
        assert!(!r.contains_key("a"));
        assert_eq!(r.get("b").map(Vec::as_slice), Some(&b"ok\n"[..]));
    }

    #[test]
    fn the_boot_text_joins_the_console_start_and_the_serial_tail() {
        let console = "EFI stub: Booting\nstafeto: kernel up\nnet: ena ready\n";
        let serial = "net: ena ready\nstafeto-ok\n[ssh] Authenticated\n";
        assert_eq!(
            boot_text(console, serial),
            "EFI stub: Booting\nstafeto: kernel up\nnet: ena ready\nstafeto-ok\n[ssh] Authenticated\n"
        );
        // No overlap: both are kept and the join is marked.
        assert_eq!(
            boot_text("a\nb\n", "c\n"),
            "a\nb\n--- the serial capture begins here ---\nc\n"
        );
        assert_eq!(boot_text("", "c\n"), "c\n");
        assert_eq!(boot_text("a\n", ""), "a\n");
    }

    #[test]
    fn the_boot_text_is_redacted_line_by_line_when_printed() {
        let t = boot_text("i-0123456789abcdef0 up\n", "");
        let shown: Vec<String> = t.lines().map(redact).collect();
        assert!(!shown.join("\n").contains("0123456789abcdef0"));
    }

    #[test]
    fn one_tag_option_covers_every_resource() {
        let s = Session {
            id: "7".into(),
            dir: PathBuf::new(),
        };
        let t = s.tag_spec(&["instance", "volume"]);
        assert_eq!(t.iter().filter(|a| *a == "--tag-specifications").count(), 1);
        assert_eq!(t.len(), 3);
        assert!(t[1].contains("project") && t[2].starts_with("ResourceType=volume"));
    }

    #[test]
    fn the_operators_address_becomes_a_single_host_block() {
        assert_eq!(operator_cidr("203.0.113.7\n").unwrap(), "203.0.113.7/32");
        assert!(operator_cidr("").is_err());
        assert!(operator_cidr("<html>error</html>").is_err());
        assert!(operator_cidr("0.0.0.0").is_err());
        assert!(operator_cidr("1.2.3.4/0").is_err());
        assert!(operator_cidr("::1").is_err());
    }

    #[test]
    fn the_try_out_rules_open_four_tcp_ports_to_one_block() {
        assert_eq!(
            try_ingress_rule(8080, "203.0.113.7/32"),
            "IpProtocol=tcp,FromPort=8080,ToPort=8080,IpRanges=[{CidrIp=203.0.113.7/32}]"
        );
        assert_eq!(TRY_PORTS, [22, 80, 443, 8080]);
        let all: String = TRY_PORTS
            .iter()
            .map(|p| try_ingress_rule(*p, "203.0.113.7/32"))
            .collect();
        assert!(!all.contains("0.0.0.0/0"));
        assert_eq!(
            try_egress_rule(("udp", 53)),
            "IpProtocol=udp,FromPort=53,ToPort=53,IpRanges=[{CidrIp=0.0.0.0/0}]"
        );
    }

    #[test]
    fn the_guard_of_the_try_out_group_takes_the_four_rules_and_nothing_else() {
        let cidr = "203.0.113.7/32";
        let good = "tcp\t22\t22\t1\t203.0.113.7/32\t0\t0\t0\n\
                    tcp\t80\t80\t1\t203.0.113.7/32\t0\t0\t0\n\
                    tcp\t443\t443\t1\t203.0.113.7/32\t0\t0\t0\n\
                    tcp\t8080\t8080\t1\t203.0.113.7/32\t0\t0\t0";
        let ports: Vec<(&str, u16)> = TRY_PORTS.iter().map(|p| ("tcp", *p)).collect();
        assert!(rules_are(good, &ports, cidr));
        assert!(!rules_are(
            &good.replace("203.0.113.7/32", "0.0.0.0/0"),
            &ports,
            cidr
        ));
        assert!(!rules_are(&good.replace("\t0\n", "\t1\n"), &ports, cidr));
        assert!(!rules_are(
            &good.replace("tcp\t22\t22", "tcp\t23\t23"),
            &ports,
            cidr
        ));
        assert!(!rules_are("", &ports, cidr));
        let extra = format!("{good}\ntcp\t9\t9\t1\t203.0.113.7/32\t0\t0\t0");
        assert!(!rules_are(&extra, &ports, cidr));
        let out = "tcp\t443\t443\t1\t0.0.0.0/0\t0\t0\t0\n\
                   udp\t53\t53\t1\t0.0.0.0/0\t0\t0\t0\n\
                   tcp\t53\t53\t1\t0.0.0.0/0\t0\t0\t0";
        assert!(rules_are(out, &TRY_EGRESS, "0.0.0.0/0"));
        assert!(!rules_are(
            &out.replace("443", "80"),
            &TRY_EGRESS,
            "0.0.0.0/0"
        ));
    }

    #[test]
    fn key_pair_ids_and_addresses_of_the_try_out_are_hidden() {
        assert_eq!(redact("key-0123456789abcdef0 gone"), "key-... gone");
        assert_eq!(
            redact("public address 203.0.113.7 ssh root@203.0.113.7"),
            "public address <ip> ssh root@<ip>"
        );
        assert_eq!(Kind::parse("key"), Some(Kind::Key));
        assert!(Kind::Key.rank() < Kind::Group.rank());
    }

    #[test]
    fn a_launch_with_a_key_pair_names_it() {
        with_fake(&[], |s, dir| {
            launch(
                s,
                &Launch {
                    ami: "ami-0123456789abcdef0",
                    ty: "t4g.small",
                    user_data: None,
                    extra_snapshot: None,
                    group: Some("sg-0123456789abcdef0"),
                    public_ip: true,
                    private_ip: None,
                    key_name: Some("stafeto-try-1"),
                    expires: None,
                },
            )
            .unwrap();
            let c = calls(dir);
            assert!(c.contains("--key-name stafeto-try-1"), "{c}");
            assert!(c.contains("AssociatePublicIpAddress=true"), "{c}");
        });
    }

    // ---- a fake CLI ----------------------------------------------------

    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    const FAKE: &str = r#"#!/bin/sh
d="$(cat "$(dirname "$0")/datadir")"
echo "$*" >> "$d/calls"
case "$*" in
 *start-snapshot*)
   [ -f "$d/ledgerpath" ] && { echo "--- start-snapshot"; cat "$(cat "$d/ledgerpath")"; } >> "$d/ledger_at_snapshot"
   n=$(cat "$d/snapn" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$d/snapn"
   echo snap-0123456789abcdef$n ;;
 *put-snapshot-block*|*complete-snapshot*|*snapshot-completed*) ;;
 *register-image*)
   [ -f "$d/ledgerpath" ] && cp "$(cat "$d/ledgerpath")" "$d/ledger_at_register"
   echo ami-0123456789abcdef0 ;;
 *run-instances*)
   touch "$d/created"
   if [ -f "$d/run_fails" ]; then echo "An error occurred (RequestLimitExceeded) when calling the RunInstances operation" >&2; exit 254; fi
   echo i-0123456789abcdef0 ;;
 *create-volume*)
   [ -f "$d/ledgerpath" ] && cp "$(cat "$d/ledgerpath")" "$d/ledger_at_volume"
   if [ -f "$d/volume_create_fails" ]; then echo vol-0123456789abcdef7 > "$d/tagged_volumes"; echo "An error occurred (RequestLimitExceeded) when calling the CreateVolume operation" >&2; exit 254; fi
   echo vol-0123456789abcdef9 ;;
 *client-token*) if [ -f "$d/created" ]; then echo i-0123456789abcdef0; fi ;;
 *terminate-instances*)
   if [ -f "$d/terminate_fails" ]; then echo "An error occurred (Throttling) when calling the TerminateInstances operation" >&2; exit 254; fi
   touch "$d/terminated" ;;
 *BlockDeviceMappings*)
   if [ -f "$d/volume_fails" ]; then echo "An error occurred (Throttling) when calling the DescribeInstances operation" >&2; exit 254; fi
   echo vol-0123456789abcdef0 ;;
 *State.Name*)
   if [ -f "$d/describe_fails" ]; then echo "An error occurred (ExpiredToken) when calling the DescribeInstances operation" >&2; exit 254; fi
   if [ -f "$d/gone" ]; then echo "An error occurred (InvalidInstanceID.NotFound) when calling the DescribeInstances operation" >&2; exit 254; fi
   if [ -f "$d/terminated" ]; then echo terminated; else echo running; fi ;;
 *describe-tags*Values=session*)
   if [ -f "$d/tag_other_session" ]; then echo 0000-0; else basename "$(dirname "$(cat "$d/ledgerpath")")"; fi ;;
 *describe-tags*) echo stafeto ;;
 *GroupName*) cat "$d/groupname" 2>/dev/null ;;
 *Name=group-name*) if [ -f "$d/group_exists" ]; then echo sg-0123456789abcdef1; fi ;;
 *IpPermissionsEgress*) cat "$d/egress_rows" 2>/dev/null ;;
 *'IpPermissions[]'*) cat "$d/ingress_rows" 2>/dev/null ;;
 *KeyFingerprint*) cat "$d/fingerprint" 2>/dev/null ;;
 *modify-instance-attribute*)
   if [ -f "$d/modify_fails" ]; then echo "An error occurred (Throttling) when calling the ModifyInstanceAttribute operation" >&2; exit 254; fi ;;
 *'Volumes[].VolumeId'*) cat "$d/tagged_volumes" 2>/dev/null ;;
 *Placement*) echo eu-central-1a ;;
 *delete-key-pair*) rm -f "$d/key_exists" ;;
 *describe-key-pairs*) if [ -f "$d/key_exists" ]; then echo key-0123456789abcdef0; fi ;;
 *import-key-pair*)
   [ -f "$d/ledgerpath" ] && cp "$(cat "$d/ledgerpath")" "$d/ledger_at_import"
   if [ -f "$d/import_fails" ]; then touch "$d/key_exists"; echo "An error occurred (InvalidKeyPair.Duplicate) when calling the ImportKeyPair operation" >&2; exit 254; fi
   echo key-0123456789abcdef0 ;;
 *describe-subnets*) echo "subnet-1 vpc-1" ;;
 *create-security-group*)
   [ -f "$d/ledgerpath" ] && cp "$(cat "$d/ledgerpath")" "$d/ledger_at_create"
   if [ -f "$d/create_fails" ]; then touch "$d/group_exists"; echo "An error occurred (InvalidGroup.Duplicate) when calling the CreateSecurityGroup operation" >&2; exit 254; fi
   echo sg-0123456789abcdef0 ;;
 *length*) echo 0 ;;
esac
exit 0
"#;

    /// The fake CLI is written and made executable once per test process, before any test
    /// runs it, and is never opened for writing again. A test that wrote the script and ran
    /// it while other test threads forked children could hit ETXTBSY on Linux: a child forked
    /// meanwhile holds the write descriptor of the script across its exec. The script reads
    /// the directory of the running test from the file `datadir` beside it (a data file, not
    /// the executable), so each test still has files of its own.
    fn fake_cli(data: &Path) -> PathBuf {
        static SCRIPT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
        let script = SCRIPT.get_or_init(|| {
            let bin =
                std::env::temp_dir().join(format!("stafeto-fake-aws-bin-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&bin);
            std::fs::create_dir_all(&bin).unwrap();
            let script = bin.join("aws");
            std::fs::write(&script, FAKE).unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
            script
        });
        std::fs::write(script.with_file_name("datadir"), data.display().to_string()).unwrap();
        script.clone()
    }

    /// A session of its own under the journals, and a fake `aws` that
    /// behaves as the files in its directory say; `f` runs with the lock.
    fn with_fake(flags: &[&str], f: impl FnOnce(&Session, &Path)) {
        let _lock = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("stafeto-fake-aws-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let script = fake_cli(&dir);
        for flag in flags {
            std::fs::write(dir.join(flag), "").unwrap();
        }
        *CLI.lock().unwrap() = Some(script);
        let s = Session::open(Some(format!("9999-{}", std::process::id()))).unwrap();
        let _ = std::fs::remove_file(s.ledger());
        std::fs::write(dir.join("ledgerpath"), s.ledger().display().to_string()).unwrap();
        f(&s, &dir);
        *CLI.lock().unwrap() = None;
        let _ = std::fs::remove_dir_all(&s.dir);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn calls(dir: &Path) -> String {
        std::fs::read_to_string(dir.join("calls")).unwrap_or_default()
    }

    fn launch_small(s: &Session) -> Result<(String, Instant), String> {
        launch(
            s,
            &Launch {
                ami: "ami-0123456789abcdef0",
                ty: "t4g.small",
                user_data: None,
                extra_snapshot: None,
                group: None,
                public_ip: false,
                private_ip: None,
                key_name: None,
                expires: None,
            },
        )
    }

    #[test]
    fn only_a_not_found_error_says_a_resource_is_gone() {
        assert_eq!(lives(Ok("running".into())), Ok(true));
        assert_eq!(lives(Ok("terminated".into())), Ok(false));
        assert_eq!(
            lives(Err(
                "aws ec2 describe-volumes: An error occurred (InvalidVolume.NotFound)".into()
            )),
            Ok(false)
        );
        for other in [
            "ExpiredToken",
            "Throttling",
            "UnauthorizedOperation",
            "a network error",
        ] {
            assert!(lives(Err(format!("aws ec2: {other}"))).is_err(), "{other}");
        }
    }

    #[test]
    fn a_failed_describe_keeps_the_resource_in_the_journal() {
        with_fake(&["describe_fails"], |s, _| {
            s.note("created", Kind::Instance, "i-0123456789abcdef0")
                .unwrap();
            let e = delete(s, Kind::Instance, "i-0123456789abcdef0").unwrap_err();
            assert!(e.contains("ExpiredToken"), "{e}");
            assert_eq!(s.live().len(), 1, "still journaled");
        });
        with_fake(&["gone"], |s, _| {
            s.note("created", Kind::Instance, "i-0123456789abcdef0")
                .unwrap();
            delete(s, Kind::Instance, "i-0123456789abcdef0").unwrap();
            assert!(s.live().is_empty(), "a NotFound journals the delete");
        });
    }

    #[test]
    fn a_run_instances_that_fails_after_the_instance_exists_removes_it() {
        with_fake(&["run_fails"], |s, dir| {
            let e = launch_small(s).unwrap_err();
            assert!(e.contains("RequestLimitExceeded"), "{e}");
            let c = calls(dir);
            assert!(c.contains("--client-token stafeto-9999-"), "{c}");
            assert!(
                c.contains("Name=client-token,Values=stafeto-9999-"),
                "looked up by token"
            );
            assert!(c.contains("terminate-instances"), "terminated");
            assert!(s.live().iter().all(|(k, _)| *k != Kind::Instance));
        });
    }

    #[test]
    fn a_failed_volume_query_removes_the_instance() {
        with_fake(&["volume_fails"], |s, dir| {
            let e = launch_small(s).unwrap_err();
            assert!(e.contains("Throttling"), "{e}");
            assert!(calls(dir).contains("terminate-instances"));
            assert!(s.live().iter().all(|(k, _)| *k != Kind::Instance));
        });
    }

    #[test]
    fn a_failed_terminate_is_reported_and_the_instance_stays_in_the_journal() {
        with_fake(&["volume_fails", "terminate_fails"], |s, _| {
            let e = launch_small(s).unwrap_err();
            assert!(e.contains("was not removed"), "{e}");
            assert!(
                s.live().iter().any(|(k, _)| *k == Kind::Instance),
                "clean can still find it"
            );
        });
    }

    #[test]
    fn the_image_uploads_two_snapshots_and_registers_sdf_from_the_second() {
        with_fake(&[], |s, dir| {
            // A root disk and a data image of two blocks and a few, zeros between.
            let root = dir.join("root.raw");
            let data = dir.join("data.raw");
            let mut bytes = vec![0u8; 3 * BLOCK];
            bytes[0] = 1;
            bytes[2 * BLOCK + 5] = 2;
            std::fs::write(&root, &bytes).unwrap();
            data_image::make(&data, 16 << 20).unwrap();
            let first = direct_snapshot(s, &root, "plain").unwrap();
            let second = direct_snapshot(s, &data, "data").unwrap();
            assert_eq!(first, "snap-0123456789abcdef1");
            assert_eq!(second, "snap-0123456789abcdef2");
            let ami = register(s, &first, &second, "stafeto-plain-9999").unwrap();
            assert_eq!(ami, "ami-0123456789abcdef0");
            let c = calls(dir);
            // Zero blocks are not sent: two of the root's three, and the data image's few.
            let blocks: Vec<&str> = c
                .lines()
                .filter(|l| l.contains("put-snapshot-block"))
                .collect();
            assert!(
                blocks
                    .iter()
                    .filter(|l| l.contains("--snapshot-id snap-0123456789abcdef1"))
                    .count()
                    == 2,
                "{c}"
            );
            assert!(
                blocks
                    .iter()
                    .any(|l| l.contains("--snapshot-id snap-0123456789abcdef2")),
                "{c}"
            );
            // Both snapshots carry the tags and the second one is 1 GiB at least.
            for l in c.lines().filter(|l| l.contains("start-snapshot")) {
                assert!(l.contains("Key=project,Value=stafeto"), "{l}");
                assert!(l.contains("Key=session,Value=9999-"), "{l}");
            }
            let register_line = c.lines().find(|l| l.contains("register-image")).unwrap();
            assert!(
                register_line.contains(
                    "DeviceName=/dev/sda1,Ebs={SnapshotId=snap-0123456789abcdef1,VolumeType=gp3,DeleteOnTermination=true}"
                ),
                "{register_line}"
            );
            assert!(
                register_line.contains(
                    "DeviceName=/dev/sdf,Ebs={SnapshotId=snap-0123456789abcdef2,VolumeType=gp3,DeleteOnTermination=true}"
                ),
                "{register_line}"
            );
            // The journal: each snapshot has its intent before the call and its id after, and the
            // image its intent before the registration.
            let at_snapshot = ledger_copy(dir, "ledger_at_snapshot");
            let first_call = at_snapshot.split("--- start-snapshot").nth(1).unwrap();
            assert!(
                first_call.contains("intent\tsnapshot\tplain"),
                "{at_snapshot}"
            );
            assert!(!first_call.contains("created"), "{at_snapshot}");
            let second_call = at_snapshot.split("--- start-snapshot").nth(2).unwrap();
            assert!(second_call.contains("created\tsnapshot\tsnap-0123456789abcdef1"));
            assert!(second_call.contains("intent\tsnapshot\tdata"));
            assert!(!second_call.contains("created\tsnapshot\tsnap-0123456789abcdef2"));
            let at_register = ledger_copy(dir, "ledger_at_register");
            assert!(at_register.contains("created\tsnapshot\tsnap-0123456789abcdef2"));
            assert!(at_register.contains("intent\timage"));
            assert!(!at_register.contains("created\timage"));
            let live = s.live();
            assert_eq!(
                live.iter().filter(|(k, _)| *k == Kind::Snapshot).count(),
                2,
                "clean and sweep find both"
            );
            assert!(live.contains(&(Kind::Image, ami)));
        });
    }

    #[test]
    fn a_launch_that_works_journals_the_instance_and_its_volume() {
        with_fake(&[], |s, _| {
            let (id, _) = launch_small(s).unwrap();
            assert_eq!(id, "i-0123456789abcdef0");
            let live = s.live();
            assert!(live.iter().any(|(k, _)| *k == Kind::Instance));
            assert!(live.iter().any(|(k, _)| *k == Kind::Volume));
        });
    }

    fn ledger_copy(dir: &Path, name: &str) -> String {
        std::fs::read_to_string(dir.join(name)).unwrap_or_default()
    }

    const BOTH_TAGS: [&str; 2] = [
        "Name=tag:project,Values=stafeto",
        "Name=tag:session,Values=9999-",
    ];

    #[test]
    fn the_try_group_is_journaled_before_it_is_made_and_made_with_the_tags() {
        with_fake(&[], |s, dir| {
            let g = try_group(s, "203.0.113.7/32").unwrap();
            assert_eq!(g, "sg-0123456789abcdef0");
            let at_create = ledger_copy(dir, "ledger_at_create");
            assert!(at_create.contains("intent\tgroup"), "{at_create}");
            assert!(!at_create.contains("created"), "{at_create}");
            assert!(s.live().contains(&(Kind::Group, g)));
            let c = calls(dir);
            assert!(c.contains("Key=project,Value=stafeto"), "{c}");
            assert!(c.contains("Key=session,Value=9999-"), "{c}");
            assert_eq!(c.matches("authorize-security-group-ingress").count(), 4);
        });
    }

    #[test]
    fn a_group_that_exists_with_both_tags_is_adopted_and_journaled() {
        with_fake(&["group_exists"], |s, dir| {
            let g = try_group(s, "203.0.113.7/32").unwrap();
            assert_eq!(g, "sg-0123456789abcdef1");
            let c = calls(dir);
            assert!(!c.contains("create-security-group"), "{c}");
            for tag in BOTH_TAGS {
                assert!(c.contains(tag), "{tag}: {c}");
            }
            assert!(
                c.contains("Name=group-name,Values=stafeto-try-9999-"),
                "{c}"
            );
            assert!(s.live().contains(&(Kind::Group, g)));
        });
    }

    #[test]
    fn a_create_that_fails_after_the_group_exists_adopts_it() {
        with_fake(&["create_fails"], |s, dir| {
            let g = try_group(s, "203.0.113.7/32").unwrap();
            assert_eq!(g, "sg-0123456789abcdef1");
            assert!(s.live().contains(&(Kind::Group, g)));
            assert_eq!(
                calls(dir).matches("Name=group-name").count(),
                2,
                "looked up twice"
            );
        });
    }

    #[test]
    fn a_session_with_a_closed_group_gets_a_try_group_of_its_own() {
        with_fake(&[], |s, dir| {
            s.note("created", Kind::Group, "sg-0123456789abcdef9")
                .unwrap();
            std::fs::write(dir.join("groupname"), "stafeto-closed-9999\n").unwrap();
            let g = try_group(s, "203.0.113.7/32").unwrap();
            assert_eq!(g, "sg-0123456789abcdef0");
            assert!(calls(dir).contains("create-security-group"));
        });
    }

    #[test]
    fn a_try_group_of_another_address_says_the_address_changed() {
        with_fake(&[], |s, dir| {
            s.note("created", Kind::Group, "sg-0123456789abcdef9")
                .unwrap();
            std::fs::write(dir.join("groupname"), format!("stafeto-try-{}\n", s.id)).unwrap();
            let rows: String = TRY_PORTS
                .iter()
                .map(|p| format!("tcp {p} {p} 1 203.0.113.9/32 0 0 0\n"))
                .collect();
            std::fs::write(dir.join("ingress_rows"), &rows).unwrap();
            let e = try_group(s, "203.0.113.7/32").unwrap_err();
            assert!(e.contains("address of this host changed"), "{e}");
            assert!(e.contains("clean --session"), "{e}");
            // The same address gives the group back.
            assert_eq!(
                try_group(s, "203.0.113.9/32").unwrap(),
                "sg-0123456789abcdef9"
            );
        });
    }

    #[test]
    fn the_try_key_is_journaled_before_it_is_imported_and_imported_with_the_tags() {
        with_fake(&[], |s, dir| {
            let name = try_key(s).unwrap();
            assert_eq!(name, format!("stafeto-try-{}", s.id));
            let at_import = ledger_copy(dir, "ledger_at_import");
            assert!(at_import.contains("intent\tkey"), "{at_import}");
            assert!(!at_import.contains("created"), "{at_import}");
            assert!(s.live().iter().any(|(k, _)| *k == Kind::Key));
            let c = calls(dir);
            assert!(c.contains("ResourceType=key-pair,Tags=[{Key=project,Value=stafeto},{Key=session,Value=9999-"), "{c}");
            assert!(s.dir.join("try-key").exists());
        });
    }

    /// A local key pair in the session's directory, and the fingerprint EC2 would show for it
    /// (the padded form EC2 uses) in the fake's answer.
    fn seed_local_key(s: &Session, dir: &Path) {
        let fp = local_fingerprint(&s.dir.join("try-key")).unwrap();
        std::fs::write(
            dir.join("fingerprint"),
            format!("{}=\n", fp.trim_start_matches("SHA256:")),
        )
        .unwrap();
    }

    #[test]
    fn a_key_pair_that_exists_with_both_tags_is_adopted() {
        with_fake(&["key_exists"], |s, dir| {
            seed_local_key(s, dir);
            try_key(s).unwrap();
            let c = calls(dir);
            assert!(!c.contains("import-key-pair"), "{c}");
            for tag in BOTH_TAGS {
                assert!(c.contains(tag), "{tag}: {c}");
            }
            assert!(s.live().iter().any(|(k, _)| *k == Kind::Key));
        });
        with_fake(&["import_fails"], |s, dir| {
            seed_local_key(s, dir);
            try_key(s).unwrap();
            assert!(s.live().iter().any(|(k, _)| *k == Kind::Key));
        });
    }

    #[test]
    fn an_adopted_key_pair_with_another_fingerprint_is_replaced() {
        with_fake(&["key_exists"], |s, dir| {
            local_fingerprint(&s.dir.join("try-key")).unwrap();
            std::fs::write(
                dir.join("fingerprint"),
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
            )
            .unwrap();
            try_key(s).unwrap();
            let c = calls(dir);
            assert!(c.contains("delete-key-pair"), "{c}");
            assert!(c.contains("import-key-pair"), "{c}");
            assert!(s.live().iter().any(|(k, _)| *k == Kind::Key));
        });
    }

    #[test]
    fn fingerprints_compare_without_the_prefix_and_the_padding() {
        assert_eq!(
            fingerprint_field("256 SHA256:abcDEF+/12 stafeto-try (ED25519)\n").as_deref(),
            Some("SHA256:abcDEF+/12")
        );
        assert!(same_fingerprint("SHA256:abcDEF+/12", "abcDEF+/12="));
        assert!(same_fingerprint("abcDEF+/12=\n", "SHA256:abcDEF+/12"));
        assert!(!same_fingerprint("SHA256:abcDEF+/12", "abcDEF+/13="));
        assert!(!same_fingerprint("", ""));
    }

    fn two_journals() -> Vec<(String, Kind, String)> {
        vec![
            ("20260101-000001".into(), Kind::Volume, "vol-1".into()),
            ("20260101-000002".into(), Kind::Volume, "vol-2".into()),
            ("20260101-000002".into(), Kind::Instance, "i-2".into()),
        ]
    }

    #[test]
    fn the_guard_checks_the_journal_the_project_tag_and_the_session_tag() {
        let j = two_journals();
        assert!(guard_verdict(&j, Kind::Volume, "vol-1", "stafeto", "20260101-000001").is_ok());
        let e = guard_verdict(&j, Kind::Volume, "vol-9", "stafeto", "20260101-000001").unwrap_err();
        assert!(e.contains("not in any session journal"), "{e}");
        let e = guard_verdict(&j, Kind::Volume, "vol-1", "other", "20260101-000001").unwrap_err();
        assert!(e.contains("project=stafeto"), "{e}");
        // The session tag of another session's journal, or none, leaves the resource alone.
        for tag in ["20260101-000002", "", "20260101"] {
            let e = guard_verdict(&j, Kind::Volume, "vol-1", "stafeto", tag).unwrap_err();
            assert!(e.contains("session tag"), "{tag}: {e}");
        }
        // The kind is part of the question.
        assert!(guard_verdict(&j, Kind::Instance, "vol-1", "stafeto", "20260101-000001").is_err());
    }

    #[test]
    fn the_guard_takes_a_resource_held_by_the_session_its_tag_names() {
        let mut j = two_journals();
        j.push(("20260101-000001".into(), Kind::Instance, "i-2".into()));
        assert!(guard_verdict(&j, Kind::Instance, "i-2", "stafeto", "20260101-000001").is_ok());
        assert!(guard_verdict(&j, Kind::Instance, "i-2", "stafeto", "20260101-000002").is_ok());
    }

    #[test]
    fn the_guard_refuses_a_delete_when_the_session_tag_names_another_session() {
        with_fake(&["tag_other_session"], |s, _| {
            // The session tag names another session than the one whose journal holds the
            // volume: the delete is refused.
            s.note("created", Kind::Volume, "vol-0123456789abcdef0")
                .unwrap();
            let e = guard(Kind::Volume, "vol-0123456789abcdef0").unwrap_err();
            assert!(e.contains("session tag"), "{e}");
        });
    }

    #[test]
    fn the_header_states_the_limit_the_code_has() {
        assert_eq!(MAX_LIVE, 4);
        let header = include_str!("aws.rs")
            .lines()
            .skip_while(|l| !l.starts_with("//!"))
            .take_while(|l| l.starts_with("//!"))
            .collect::<String>();
        assert!(header.contains("at most four instances"), "{header}");
        assert!(header.contains("`session` tag"), "{header}");
    }

    #[test]
    fn the_volume_options_take_whole_gib_up_to_their_caps() {
        assert_eq!(
            parse_gib(
                "--data-volume-size",
                "8",
                DATA_VOLUME_MIN_GIB,
                DATA_VOLUME_MAX_GIB
            ),
            Ok(8)
        );
        assert_eq!(
            parse_gib(
                "--data-volume-size",
                "32",
                DATA_VOLUME_MIN_GIB,
                DATA_VOLUME_MAX_GIB
            ),
            Ok(32)
        );
        for bad in ["1", "0", "-3", "abc", "", "33", "16384", "2.5"] {
            assert!(
                parse_gib(
                    "--data-volume-size",
                    bad,
                    DATA_VOLUME_MIN_GIB,
                    DATA_VOLUME_MAX_GIB
                )
                .is_err(),
                "{bad}"
            );
        }
        assert_eq!(
            parse_gib("--blank-volume", "1", 1, BLANK_VOLUME_MAX_GIB),
            Ok(1)
        );
        assert_eq!(
            parse_gib("--blank-volume", "32", 1, BLANK_VOLUME_MAX_GIB),
            Ok(32)
        );
        assert!(parse_gib("--blank-volume", "33", 1, BLANK_VOLUME_MAX_GIB).is_err());
        assert!(parse_gib("--blank-volume", "0", 1, BLANK_VOLUME_MAX_GIB).is_err());
    }

    #[test]
    fn a_larger_data_volume_names_the_size_and_no_snapshot() {
        assert_eq!(
            launch_mapping(&sized(8)),
            "DeviceName=/dev/sdf,Ebs={VolumeSize=8,VolumeType=gp3,DeleteOnTermination=true}"
        );
        assert!(!launch_mapping(&sized(8)).contains("SnapshotId"));
    }

    #[test]
    fn the_blank_volume_request_has_the_zone_the_size_and_both_tags() {
        with_fake(&[], |s, _| {
            let a = blank_volume_args(s, "eu-central-1a", 4, "i-0123456789abcdef0");
            let line = a.join(" ");
            assert!(
                line.starts_with(
                    "ec2 create-volume --volume-type gp3 --availability-zone eu-central-1a --size 4"
                ),
                "{line}"
            );
            assert!(
                line.contains(
                    "ResourceType=volume,Tags=[{Key=project,Value=stafeto},{Key=session,Value=9999-"
                ),
                "{line}"
            );
            assert!(line.contains("--client-token stafeto-vol-9999-"), "{line}");
            assert!(line.contains("-i-0123456789abcdef0"), "{line}");
            assert_eq!(
                blank_delete_with_instance(),
                "DeviceName=/dev/sdg,Ebs={DeleteOnTermination=true}"
            );
        });
    }

    #[test]
    fn a_blank_volume_is_journaled_before_the_call_and_attached_as_sdg() {
        with_fake(&[], |s, dir| {
            attach_blank_volume(s, "i-0123456789abcdef0", 3).unwrap();
            let at_create = ledger_copy(dir, "ledger_at_volume");
            assert!(at_create.contains("intent\tvolume\tblank"), "{at_create}");
            assert!(!at_create.contains("created\tvolume"), "{at_create}");
            assert!(
                s.live()
                    .contains(&(Kind::Volume, "vol-0123456789abcdef9".into()))
            );
            let c = calls(dir);
            assert!(
                c.contains("--availability-zone eu-central-1a --size 3"),
                "{c}"
            );
            assert!(
                c.contains("attach-volume --volume-id vol-0123456789abcdef9 --instance-id i-0123456789abcdef0 --device /dev/sdg"),
                "{c}"
            );
            assert!(
                c.contains(
                    "--block-device-mappings DeviceName=/dev/sdg,Ebs={DeleteOnTermination=true}"
                ),
                "{c}"
            );
        });
    }

    #[test]
    fn a_failed_create_volume_journals_and_removes_a_volume_it_made() {
        with_fake(&["volume_create_fails"], |s, dir| {
            let e = attach_blank_volume(s, "i-0123456789abcdef0", 3).unwrap_err();
            assert!(e.contains("RequestLimitExceeded"), "{e}");
            let c = calls(dir);
            assert!(c.contains("Name=tag:session,Values=9999-"), "{c}");
            assert!(
                c.contains("delete-volume --volume-id vol-0123456789abcdef7"),
                "{c}"
            );
            assert!(s.live().is_empty(), "journaled and deleted: {:?}", s.live());
        });
    }

    #[test]
    fn clean_finds_a_tagged_volume_that_no_journal_line_names() {
        with_fake(&[], |s, dir| {
            std::fs::write(dir.join("tagged_volumes"), "vol-0123456789abcdef7\n").unwrap();
            assert!(s.live().is_empty());
            clean(s, false).unwrap();
            let c = calls(dir);
            assert!(
                c.contains("delete-volume --volume-id vol-0123456789abcdef7"),
                "{c}"
            );
            assert!(s.live().is_empty());
        });
    }

    #[test]
    fn a_blank_volume_that_cannot_be_marked_for_deletion_is_detached_before_the_delete() {
        with_fake(&["modify_fails"], |s, dir| {
            let e = attach_blank_volume(s, "i-0123456789abcdef0", 3).unwrap_err();
            assert!(e.contains("Throttling"), "{e}");
            let c = calls(dir);
            let at = |what: &str| c.find(what).unwrap_or_else(|| panic!("{what}: {c}"));
            assert!(at("detach-volume") < at("delete-volume"), "{c}");
            assert!(s.live().is_empty());
        });
    }

    #[test]
    fn a_failed_attach_deletes_the_volume_without_a_detach() {
        let calls_of = |c: &str| c.contains("detach-volume");
        with_fake(&[], |s, dir| {
            attach_blank_volume(s, "i-0123456789abcdef0", 3).unwrap();
            assert!(!calls_of(&calls(dir)));
        });
    }

    #[test]
    fn the_try_out_estimate_adds_the_volumes() {
        assert_eq!(volume_rate(&[]), 0.0);
        let one = volume_rate(&[10]);
        assert!((one - 10.0 * PRICE_GP3_GIB_MONTH / 730.0).abs() < 1e-12);
        assert!((volume_rate(&[4, 6]) - one).abs() < 1e-12);
    }

    #[test]
    fn clean_keeps_the_image_and_its_snapshots_when_asked() {
        let live = vec![
            (Kind::Snapshot, "snap-1".to_string()),
            (Kind::Image, "ami-1".to_string()),
            (Kind::Group, "sg-1".to_string()),
            (Kind::Instance, "i-1".to_string()),
            (Kind::Volume, "vol-1".to_string()),
        ];
        let all = clean_order(live.clone(), false);
        assert_eq!(all.len(), 5);
        assert_eq!(all[0].0, Kind::Instance);
        let kept = clean_order(live, true);
        let kinds: Vec<Kind> = kept.iter().map(|(k, _)| *k).collect();
        assert_eq!(kinds, [Kind::Instance, Kind::Volume, Kind::Group]);
    }

    #[test]
    fn clean_with_keep_image_leaves_the_image_in_the_journal() {
        with_fake(&["gone"], |s, _| {
            s.note("created", Kind::Image, "ami-0123456789abcdef0")
                .unwrap();
            s.note("created", Kind::Snapshot, "snap-0123456789abcdef1")
                .unwrap();
            s.note("created", Kind::Instance, "i-0123456789abcdef0")
                .unwrap();
            clean(s, true).unwrap();
            let live = s.live();
            assert_eq!(live.len(), 2, "{live:?}");
            assert!(
                live.iter()
                    .all(|(k, _)| matches!(k, Kind::Image | Kind::Snapshot))
            );
        });
    }

    #[test]
    fn clean_removes_the_local_key_files() {
        with_fake(&[], |s, _| {
            try_key(s).unwrap();
            assert!(s.dir.join("try-key.pub").exists());
            s.note("deleted", Kind::Key, "key-0123456789abcdef0")
                .unwrap();
            clean(s, false).unwrap();
            assert!(!s.dir.join("try-key").exists());
            assert!(!s.dir.join("try-key.pub").exists());
        });
    }

    #[test]
    fn the_instance_alone_gets_the_expires_tag() {
        with_fake(&[], |s, dir| {
            let l = Launch {
                ami: "ami-0123456789abcdef0",
                ty: "t4g.small",
                user_data: None,
                extra_snapshot: None,
                group: Some("sg-0123456789abcdef0"),
                public_ip: true,
                private_ip: None,
                key_name: None,
                expires: Some("2026-11-17T12:00:00Z"),
            };
            launch(s, &l).unwrap();
            let c = calls(dir);
            assert!(c.contains("ResourceType=instance,Tags=[{Key=project,Value=stafeto},{Key=session,Value=9999-"), "{c}");
            assert!(
                c.contains("{Key=expires,Value=2026-11-17T12:00:00Z}]"),
                "{c}"
            );
            assert_eq!(c.matches("Key=expires").count(), 1, "{c}");
        });
    }

    #[test]
    fn stamps_round_trip_and_the_report_says_past_or_not() {
        assert_eq!(utc_stamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc_stamp(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(
            parse_stamp("2023-11-14T22:13:20+00:00"),
            Some(1_700_000_000)
        );
        assert_eq!(parse_stamp(&utc_stamp(1_784_000_123)), Some(1_784_000_123));
        assert_eq!(parse_stamp("None"), None);
        let now = 1_700_000_000;
        let rows = format!(
            "i-0123456789abcdef0\t{}\t{}\ni-0123456789abcdef1\t{}\t{}\n",
            utc_stamp(now - 3 * 3600),
            utc_stamp(now - 3600),
            utc_stamp(now - 600),
            utc_stamp(now + 7200 - 600)
        );
        let r = try_report(&rows, now);
        assert_eq!(r.len(), 2);
        assert!(
            r[0].contains("i-...") && r[0].contains("age 3h00m") && r[0].contains("PAST"),
            "{}",
            r[0]
        );
        assert!(
            r[1].contains("age 0h10m") && r[1].contains("(in 1h50m)"),
            "{}",
            r[1]
        );
    }

    #[test]
    fn only_the_two_types_of_the_note_are_allowed() {
        assert!(ALLOWED_TYPES.contains(&"t4g.small"));
        assert!(!ALLOWED_TYPES.contains(&"m6g.large"));
    }
}
