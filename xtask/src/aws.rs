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
//! in the journals and its tags are read, and a resource without both is left
//! alone; only `t4g.small` and `t4g.nano` run, with credits `standard`; at
//! most two instances of the project live at once; the security group of a
//! session has no rule in and none out, so nothing reaches the instances from
//! outside and the console is the only way to look at them.

use crate::{Artifacts, Variant, build, efi};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Write as _;
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
/// The on-demand price of a t4g.small in eu-central-1 in USD per hour, as the
/// price list showed it when this was written (unverified: it only sizes the
/// estimate the commands print).
const PRICE_SMALL: f64 = 0.0184;

const USAGE: &str = "usage: xtask aws check
       xtask aws image [--dump] [--marks] [--its-int] [--its-align-4k] [--disk FILE] [--ena-break-aenq] [--ena-break-exit] [--session S]
       xtask aws boot --ami AMI [--type T] [--end TEXT] [--timeout SECONDS] [--serial SECONDS] [--stop] [--session S]
       xtask aws dump [--session S] [--all]
       xtask aws neighbour [--snapshot SNAP] [--session S]
       xtask aws pair --ami AMI [--count N] [--internet] [--serial SECONDS] [--delay S] [--gap S] [--session S]
       xtask aws clean --session S
       xtask aws sweep [--remove]";

// ---- the CLI -------------------------------------------------------------------

/// Hides the identifiers the reports must not carry: account numbers (twelve
/// digits), the ids of instances, images, volumes, snapshots and groups, and IPv4
/// addresses.
pub fn redact(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let is_hex = |c: u8| c.is_ascii_digit() || (b'a'..=b'f').contains(&c);
    let prefixes: [(&str, usize); 6] = [
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
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Instance => "instance",
            Kind::Volume => "volume",
            Kind::Snapshot => "snapshot",
            Kind::Image => "image",
            Kind::Group => "group",
        }
    }
    fn parse(s: &str) -> Option<Kind> {
        [
            Kind::Instance,
            Kind::Volume,
            Kind::Snapshot,
            Kind::Image,
            Kind::Group,
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

/// Every journal under target/aws: what any session left.
fn all_live() -> Vec<(Kind, String)> {
    let mut all = Vec::new();
    if let Ok(dirs) = std::fs::read_dir(aws_dir()) {
        for d in dirs.flatten() {
            all.extend(live_of(&d.path().join("ledger.tsv")));
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

/// The guard before any delete, stop or terminate: the resource is in a
/// journal of this machine and carries `project=stafeto`.
fn guard(kind: Kind, id: &str) -> Result<(), String> {
    if !all_live().iter().any(|(k, i)| *k == kind && i == id) {
        return Err(format!(
            "{} {} is not in any session journal: left alone",
            kind.name(),
            redact(id)
        ));
    }
    if tag_of(id, "project")? != "stafeto" {
        return Err(format!(
            "{} {} lacks the tag project=stafeto: left alone",
            kind.name(),
            redact(id)
        ));
    }
    Ok(())
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
fn clean(s: &Session) -> Result<(), String> {
    let mut live = s.live();
    live.reverse();
    let rank = |k: Kind| match k {
        Kind::Instance => 0,
        Kind::Image => 1,
        Kind::Volume => 2,
        Kind::Snapshot => 3,
        Kind::Group => 4,
    };
    live.sort_by_key(|(k, _)| rank(*k));
    let mut failed = Vec::new();
    for (kind, id) in live {
        if let Err(e) = delete(s, kind, &id) {
            eprintln!("clean: {e}");
            failed.push(e);
        }
    }
    if failed.is_empty() {
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
/// exit is an error while anything remains.
fn sweep(args: &[String]) -> Result<(), String> {
    let remove = args.iter().any(|a| a == "--remove");
    let mut found = project_resources()?;
    if remove {
        let s = Session::open(Some("0".into()))?;
        let mut order = found.clone();
        order.sort_by_key(|(k, _)| match k {
            Kind::Instance => 0,
            Kind::Image => 1,
            Kind::Volume => 2,
            Kind::Snapshot => 3,
            Kind::Group => 4,
        });
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
        Kind::Group,
    ] {
        let ids: Vec<String> = found
            .iter()
            .filter(|(k, _)| *k == kind)
            .map(|(_, i)| redact(i))
            .collect();
        println!("{}: {} {}", kind.name(), ids.len(), ids.join(" "));
    }
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
    args.extend(s.tag_spec(&["instance", "volume", "network-interface"]));
    if let Some(snap) = l.extra_snapshot {
        args.extend([
            "--block-device-mappings".to_string(),
            format!("DeviceName=/dev/sdf,Ebs={{SnapshotId={snap},VolumeType=gp3,DeleteOnTermination=true}}"),
        ]);
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
    let data = std::fs::read(disk).map_err(|e| format!("{}: {e}", disk.display()))?;
    let gib = data.len().div_ceil(1 << 30);
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
    for (index, block) in data.chunks(BLOCK).enumerate() {
        if block.iter().all(|b| *b == 0) {
            continue;
        }
        let mut full = block.to_vec();
        full.resize(BLOCK, 0);
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

fn register(s: &Session, snap: &str, name: &str) -> Result<String, String> {
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
        make_disk(&features, variant, &disk)?;
        println!("disk built in {:.1} s", t.elapsed().as_secs_f64());
    }
    let t = Instant::now();
    let flavour = if old_disk.is_some() {
        "old-disk"
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
    let snap = direct_snapshot(&s, &disk, flavour)?;
    let ami = register(&s, &snap, &format!("stafeto-{flavour}-{}", s.id))?;
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
    let s = Session::open(flag(args, "--session"))?;
    let (id, started) = launch(
        &s,
        &Launch {
            ami: &ami,
            ty: &ty,
            user_data: None,
            extra_snapshot: None,
            group: None,
            public_ip: false,
            private_ip: None,
        },
    )?;
    let result = (|| {
        // The MAC of the instance's interface, to compare with the one the
        // device reports: the last three octets only.
        match eni_mac(&id) {
            Ok(mac) => println!("interface mac ..:..:..:{}", last_octets(&mac)),
            Err(e) => println!("interface mac: {e}"),
        }
        if let Some(n) = flag(args, "--serial").and_then(|n| n.parse().ok()) {
            for _ in 0..40 {
                if state(&id)? == "running" {
                    break;
                }
                std::thread::sleep(Duration::from_secs(3));
            }
            match serial(&s, &id, n) {
                Ok(t) => {
                    println!("--- serial console, first {n} s ---");
                    for l in t.lines() {
                        println!("{}", redact(l));
                    }
                    println!("--- end of serial console ---");
                }
                Err(e) => println!("serial console: {e}"),
            }
        }
        let log = s.dir.join("console.log");
        let w = watch(&id, end.as_deref(), Duration::from_secs(timeout), &log)?;
        print_console(&w.text);
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
    let result = if !stop || result.is_err() {
        release(&s, Kind::Instance, &id, result)
    } else {
        result
    };
    println!(
        "estimated cost of this instance: {:.3} USD",
        cost(started.elapsed(), PRICE_SMALL)
    );
    result
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

const NEIGHBOUR_SCRIPT: &str = r#"#!/bin/bash
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
sleep 20
echo STAFETO-NEIGHBOUR-DONE > $O
sleep 300
"#;

/// Joins the records `STAFETO-BEGIN name` ... `STAFETO-END name` of a console
/// text into (name, base64 text) and decodes them.
fn records(text: &str) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut name: Option<String> = None;
    let mut body = String::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(n) = line.strip_prefix("STAFETO-BEGIN ") {
            name = Some(n.trim().to_string());
            body.clear();
        } else if let Some(n) = line.strip_prefix("STAFETO-END ") {
            if name.as_deref() == Some(n.trim())
                && let Some(bytes) = unbase64(&body).and_then(|b| gunzip(&b))
            {
                out.insert(n.trim().to_string(), bytes);
            }
            name = None;
        } else if name.is_some()
            && line
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c))
        {
            body.push_str(line);
        } else if name.is_some() {
            // Kernel or service text interleaved with the record: the record is lost.
            name = None;
        }
    }
    out
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

fn neighbour(args: &[String]) -> Result<(), String> {
    let snapshot = flag(args, "--snapshot");
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
            clean(&Session::open(Some(id))?)
        }
        Some("sweep") => sweep(&args[1..]),
        _ => Err(USAGE.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // ---- a fake CLI ----------------------------------------------------

    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    const FAKE: &str = r#"#!/bin/sh
d="$(dirname "$0")"
echo "$*" >> "$d/calls"
case "$*" in
 *run-instances*)
   touch "$d/created"
   if [ -f "$d/run_fails" ]; then echo "An error occurred (RequestLimitExceeded) when calling the RunInstances operation" >&2; exit 254; fi
   echo i-0123456789abcdef0 ;;
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
 *describe-tags*) echo stafeto ;;
 *describe-subnets*) echo "subnet-1 vpc-1" ;;
 *create-security-group*) echo sg-0123456789abcdef0 ;;
 *length*) echo 0 ;;
esac
exit 0
"#;

    /// A session of its own under the journals, and a fake `aws` that
    /// behaves as the files in its directory say; `f` runs with the lock.
    fn with_fake(flags: &[&str], f: impl FnOnce(&Session, &Path)) {
        let _lock = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("stafeto-fake-aws-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("aws");
        std::fs::write(&script, FAKE).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        for flag in flags {
            std::fs::write(dir.join(flag), "").unwrap();
        }
        *CLI.lock().unwrap() = Some(script);
        let s = Session::open(Some(format!("9999-{}", std::process::id()))).unwrap();
        let _ = std::fs::remove_file(s.ledger());
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
    fn a_launch_that_works_journals_the_instance_and_its_volume() {
        with_fake(&[], |s, _| {
            let (id, _) = launch_small(s).unwrap();
            assert_eq!(id, "i-0123456789abcdef0");
            let live = s.live();
            assert!(live.iter().any(|(k, _)| *k == Kind::Instance));
            assert!(live.iter().any(|(k, _)| *k == Kind::Volume));
        });
    }

    #[test]
    fn only_the_two_types_of_the_note_are_allowed() {
        assert!(ALLOWED_TYPES.contains(&"t4g.small"));
        assert!(!ALLOWED_TYPES.contains(&"m6g.large"));
    }
}
