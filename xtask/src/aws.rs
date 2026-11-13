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
const MAX_LIVE: usize = 2;
const BLOCK: usize = 512 * 1024;
/// The on-demand price of a t4g.small in eu-central-1 in USD per hour, as the
/// price list showed it when this was written (unverified: it only sizes the
/// estimate the commands print).
const PRICE_SMALL: f64 = 0.0184;

const USAGE: &str = "usage: xtask aws check
       xtask aws image [--dump] [--marks] [--session S]
       xtask aws boot --ami AMI [--type T] [--end TEXT] [--timeout SECONDS] [--serial SECONDS] [--stop] [--session S]
       xtask aws dump [--session S] [--all]
       xtask aws neighbour [--snapshot SNAP] [--session S]
       xtask aws clean --session S
       xtask aws sweep [--remove]";

// ---- the CLI -------------------------------------------------------------------

/// Hides the identifiers the reports must not carry: account numbers (twelve
/// digits), and the ids of instances, images, volumes, snapshots and groups.
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

fn aws_cmd(args: &[&str]) -> Command {
    let mut c = Command::new("aws");
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
        resources
            .iter()
            .flat_map(|r| ["--tag-specifications".to_string(), self.tags(r)])
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

fn exists(kind: Kind, id: &str) -> bool {
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
    match aws(&["ec2", cmd, ids, id, "--query", q]) {
        Ok(s) => s != "terminated" && s != "deleted",
        Err(_) => false,
    }
}

fn delete(s: &Session, kind: Kind, id: &str) -> Result<(), String> {
    if !exists(kind, id) {
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
            aws(&["ec2", "delete-security-group", "--group-id", id])?;
        }
    }
    println!("deleted {} {}", kind.name(), redact(id));
    s.note("deleted", kind, id)
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
        "Name=availability-zone,Values=eu-central-1a",
        "--query",
        "Subnets[0].[SubnetId,VpcId]",
    ])?;
    let f: Vec<&str> = r.split_whitespace().collect();
    match f[..] {
        [s, v] => Ok((s.to_string(), v.to_string())),
        _ => Err("no default subnet in eu-central-1a".into()),
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
    let group = closed_group(s)?;
    assert_closed(&group)?;
    let (subnet, _) = default_subnet()?;
    let nic =
        format!("DeviceIndex=0,SubnetId={subnet},AssociatePublicIpAddress=false,Groups={group}");
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
    args.extend(["--query", "Instances[0].InstanceId"].map(String::from));
    s.note("intent", Kind::Instance, l.ty)?;
    let id = aws_s(&args)?;
    let started = Instant::now();
    s.note("created", Kind::Instance, &id)?;
    for v in aws(&[
        "ec2",
        "describe-instances",
        "--instance-ids",
        &id,
        "--query",
        "Reservations[0].Instances[0].BlockDeviceMappings[].Ebs.VolumeId",
    ])?
    .split_whitespace()
    {
        s.note("created", Kind::Volume, v)?;
    }
    println!("started a {} ({})", l.ty, redact(&id));
    Ok((id, started))
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
    let loader = efi::build_loader(features)?;
    efi::make_disk(&loader, &a, out)?;
    Ok(a)
}

fn image(args: &[String]) -> Result<(), String> {
    let dump = args.iter().any(|a| a == "--dump");
    let marks = args.iter().any(|a| a == "--marks");
    let s = Session::open(flag(args, "--session"))?;
    let mut features = Vec::new();
    if dump {
        features.push("dump");
    }
    let variant = if marks {
        features.push("early-marks");
        Variant::EarlyMarks
    } else {
        Variant::Normal
    };
    let disk = s.dir.join("disk.raw");
    let t = Instant::now();
    make_disk(&features, variant, &disk)?;
    println!("disk built in {:.1} s", t.elapsed().as_secs_f64());
    let t = Instant::now();
    let flavour = if dump {
        "dump"
    } else if marks {
        "marks"
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
        },
    )?;
    let result = (|| {
        if let Some(n) = flag(args, "--serial").and_then(|n| n.parse().ok()) {
            aws(&["ec2", "wait", "instance-running", "--instance-ids", &id])?;
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
    if !stop || result.is_err() {
        let _ = delete(&s, Kind::Instance, &id);
    }
    println!(
        "estimated cost of this instance: {:.3} USD",
        cost(started.elapsed(), PRICE_SMALL)
    );
    result
}

// ---- the serial console -----------------------------------------------------------------

/// `aws boot --serial SECONDS`: the EC2 Serial Console through SSH with a
/// key made for the session; the text goes to `serial.log`. The host key is
/// taken on first use into the session's own known_hosts.
fn serial(s: &Session, id: &str, seconds: u64) -> Result<String, String> {
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
    let out = std::fs::File::create(&log).map_err(|e| e.to_string())?;
    let mut ssh = Command::new("ssh")
        .args(["-tt", "-i"])
        .arg(&key)
        .args([
            "-o",
            "IdentitiesOnly=yes",
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
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(seconds) {
        if ssh.try_wait().map_err(|e| e.to_string())?.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    let _ = ssh.kill();
    let _ = ssh.wait();
    Ok(std::fs::read_to_string(&log).unwrap_or_default())
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
    let _ = delete(&s, Kind::Instance, &id);
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
    let _ = delete(s, Kind::Instance, &id);
    println!(
        "estimated cost of the dump instance: {:.3} USD",
        cost(started.elapsed(), PRICE_SMALL)
    );
    let snap = snap?;
    std::fs::write(s.dir.join("dump-snapshot.txt"), snap).map_err(|e| e.to_string())
}

pub fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
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
    fn redact_hides_identifiers_and_accounts() {
        let t = "i-0123456789abcdef0 ami-0123456789abcdef0 snap-0123456789abcdef0 123456789012 x";
        assert_eq!(redact(t), "i-... ami-... snap-... <account> x");
        assert_eq!(redact("1234567890123"), "1234567890123");
        assert_eq!(redact("vol-0123456789abcdef0z"), "vol-0123456789abcdef0z");
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
    fn only_the_two_types_of_the_note_are_allowed() {
        assert!(ALLOWED_TYPES.contains(&"t4g.small"));
        assert!(!ALLOWED_TYPES.contains(&"m6g.large"));
    }
}
