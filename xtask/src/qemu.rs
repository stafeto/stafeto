// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Running QEMU with a deadline and judging its console output.

use std::io::{Read, Write};
use std::ops::Range;
use std::path::Path;
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Console on stdio, no window, no monitor: for runs whose output is parsed.
pub const HEADLESS: &[&str] = &["-display", "none", "-serial", "stdio", "-monitor", "none"];

/// Virtual time counts instructions, one per 2^4 ns, which at the 62.5 MHz
/// of the counter is one per tick; with `sleep=off` it jumps to the next
/// timer deadline while the CPU sleeps in `wfi`. Every run of a kernel
/// then sees the same times, whatever the host does. An idle kernel with
/// no deadline stops time and hangs.
pub const ICOUNT: &[&str] = &["-icount", "shift=4,sleep=off"];

/// A QEMU machine type with its options, a CPU model and an accelerator.
pub struct Machine {
    /// How xtask's lines of results name the machine.
    pub name: &'static str,
    pub machine: &'static str,
    pub cpu: &'static str,
    pub memory: &'static str,
    /// `-accel`: `tcg`, QEMU's own emulation, or `hvf` with its GIC
    /// pinned (HVF_V3, HVF_V2).
    pub accel: &'static str,
}

impl Machine {
    /// Whether the machine runs under HVF, where an address with no device
    /// reads as 0 (hvf_verdict).
    pub fn is_hvf(&self) -> bool {
        self.accel.starts_with("hvf")
    }

    /// How the kernel on this machine reaches PSCI, as its boot report
    /// names it: through SMC when it is entered at EL2
    /// (`virtualization=on`), through HVC otherwise.
    pub fn psci(&self) -> &'static str {
        if self.machine.contains("virtualization=on") {
            "Smc"
        } else {
            "Hvc"
        }
    }

    /// `memory` in bytes: a count of MiB with `M` or of GiB with `G`.
    pub fn ram(&self) -> u64 {
        let (count, unit) = self.memory.split_at(self.memory.len() - 1);
        let count: u64 = count.parse().expect("a count of MiB or GiB");
        match unit {
            "M" => count << 20,
            "G" => count << 30,
            _ => panic!("{}: not in M or G", self.memory),
        }
    }
}

/// The machine of the spec: the kernel is entered at EL1, PSCI goes through HVC.
pub const VIRT: Machine = Machine {
    name: "512M",
    machine: "virt,gic-version=2",
    cpu: "cortex-a72",
    memory: "512M",
    accel: "tcg",
};

/// The kernel is entered at EL2, as on the PinePhone's Cortex-A53; PSCI then
/// goes through SMC.
pub const VIRT_EL2: Machine = Machine {
    name: "EL2",
    machine: "virt,gic-version=2,virtualization=on",
    cpu: "cortex-a53",
    memory: "512M",
    accel: "tcg",
};

/// The spec machine with 2 GiB and the PinePhone's Cortex-A53: RAM spans
/// two GiBs, and the second one is not in the boot page tables. The A53
/// reports a VIPT instruction cache, so the kernel tests take that path of
/// the cache maintenance too; the kernel is entered at EL1 and PSCI goes
/// through HVC, as on VIRT.
pub const VIRT_2G: Machine = Machine {
    name: "2G",
    machine: "virt,gic-version=2",
    cpu: "cortex-a53",
    memory: "2G",
    accel: "tcg",
};

/// The spec machine with QEMU's GICv3 in place of the GICv2 (spec 9, 15.2):
/// the kernel takes the version from the device tree.
pub const VIRT_V3: Machine = Machine {
    name: "GICv3",
    machine: "virt,gic-version=3",
    cpu: "cortex-a72",
    memory: "512M",
    accel: "tcg",
};

/// VIRT_EL2 with the GICv3: head.S opens the GICv3 system registers to EL1
/// before it drops there.
pub const VIRT_EL2_V3: Machine = Machine {
    name: "EL2 GICv3",
    machine: "virt,gic-version=3,virtualization=on",
    cpu: "cortex-a53",
    memory: "512M",
    accel: "tcg",
};

/// The spec machine under HVF on Apple silicon (spec 14, 15.2) with
/// Apple's GICv3 in the macOS kernel. kernel-irqchip is pinned: its
/// default depends on the version of the `virt` machine. The kernel is
/// entered at EL1; the entry at EL2 is the TCG machines' to check.
pub const HVF_V3: Machine = Machine {
    name: "HVF GICv3",
    machine: "virt,gic-version=3",
    cpu: "host",
    memory: "512M",
    accel: "hvf,kernel-irqchip=on",
};

/// The spec machine under HVF with QEMU's GICv2, which HVF allows only
/// with kernel-irqchip off: the GICv2 driver on a real processor's caches
/// and barriers, as the PinePhone's GIC-400 will have them.
pub const HVF_V2: Machine = Machine {
    name: "HVF GICv2",
    machine: "virt,gic-version=2",
    cpu: "host",
    memory: "512M",
    accel: "hvf,kernel-irqchip=off",
};

/// The machines a command may name by their `name`.
pub const MACHINES: [&Machine; 7] = [
    &VIRT,
    &VIRT_EL2,
    &VIRT_2G,
    &VIRT_V3,
    &VIRT_EL2_V3,
    &HVF_V3,
    &HVF_V2,
];

/// The machine of MACHINES named `name`, VIRT when there is no name.
pub fn machine(name: Option<&String>) -> Result<&'static Machine, String> {
    let Some(name) = name else {
        return Ok(&VIRT);
    };
    MACHINES
        .into_iter()
        .find(|m| m.name == name)
        .ok_or_else(|| {
            let names: Vec<_> = MACHINES.iter().map(|m| m.name).collect();
            format!("no machine {name:?}; machines: {names:?}")
        })
}

/// The Virtio entropy device every run has (services/virtio-rng): modern
/// virtio-mmio, as the Virtio PCI of Apple VZ is, pinned to the transport
/// init's table names, 31 (`entropy.rs`), whatever other devices a run
/// adds. An idle device raises no interrupt, and a driver only the images
/// of the entropy probes start.
pub const ENTROPY: &[&str] = &[
    "-global",
    "virtio-mmio.force-legacy=false",
    "-device",
    "virtio-rng-device,bus=virtio-mmio-bus.31",
];

pub fn args(m: &Machine, kernel: &Path, boot_image: Option<&Path>) -> Vec<String> {
    let mut a: Vec<String> = [
        "-machine", m.machine, "-accel", m.accel, "-cpu", m.cpu, "-m", m.memory,
    ]
    .iter()
    .chain(ENTROPY)
    .chain(&["-kernel"])
    .map(|s| s.to_string())
    .collect();
    a.push(kernel.display().to_string());
    if let Some(b) = boot_image {
        a.push("-initrd".into());
        a.push(b.display().to_string());
    }
    a
}

pub fn command(m: &Machine, kernel: &Path, boot_image: Option<&Path>) -> Command {
    let mut c = Command::new("qemu-system-aarch64");
    c.args(args(m, kernel, boot_image));
    c
}

#[derive(Debug, Clone)]
pub struct Outcome {
    pub lines: Vec<String>,
    pub status: Option<ExitStatus>,
    pub timed_out: bool,
    pub stopped_on_marker: bool,
}

/// What a run's child reads on its stdin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Input {
    /// /dev/null: with `-serial stdio` QEMU puts a terminal on its stdin
    /// into raw mode, and a killed QEMU cannot restore it.
    Null,
    /// A pipe that `Run::send` writes to: QEMU hands its bytes to the
    /// PL011 as the FIFO has room, and the end of the pipe does not stop
    /// it.
    Pipe,
}

/// The bytes a run printed so far, as they came, and where the next
/// search starts: a search looks only after the text the last one found,
/// so an answer is not taken from the echo of its command or from what
/// came before.
#[derive(Clone, Debug)]
pub struct Transcript {
    bytes: Vec<u8>,
    from: usize,
}

impl Transcript {
    pub fn new(bytes: &[u8]) -> Transcript {
        Transcript {
            bytes: bytes.to_vec(),
            from: 0,
        }
    }

    fn extend(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    /// Whether `what` comes after the last text found; the next search
    /// starts after it. A prompt, which no newline ends, is found too.
    pub fn find(&mut self, what: &str) -> bool {
        let what = what.as_bytes();
        let found = self.bytes[self.from..]
            .windows(what.len().max(1))
            .position(|w| w == what);
        if let Some(at) = found {
            self.from += at + what.len();
        }
        found.is_some()
    }

    /// Whether the bytes `what` came anywhere, before the last text found
    /// too; the next search starts where it did.
    pub fn seen(&self, what: &[u8]) -> bool {
        self.bytes.windows(what.len().max(1)).any(|w| w == what)
    }

    /// The first whole line that `wanted` takes, a CR before its LF cut,
    /// among those that start after the last text found; the next search
    /// starts after its LF.
    pub fn find_line(&mut self, wanted: impl Fn(&str) -> bool) -> Option<String> {
        let mut start = self.from;
        if start > 0 && self.bytes[start - 1] != b'\n' {
            start += self.bytes[start..].iter().position(|&b| b == b'\n')? + 1;
        }
        while let Some(len) = self.bytes[start..].iter().position(|&b| b == b'\n') {
            let bytes = &self.bytes[start..start + len];
            let line = String::from_utf8_lossy(bytes.strip_suffix(b"\r").unwrap_or(bytes));
            start += len + 1;
            if wanted(&line) {
                self.from = start;
                return Some(line.into_owned());
            }
        }
        None
    }

    /// The lines so far, a CR before each LF cut; the last too, when no
    /// LF ended it yet.
    pub fn lines(&self) -> Vec<String> {
        let mut lines: Vec<String> = self
            .bytes
            .split(|&b| b == b'\n')
            .map(|l| String::from_utf8_lossy(l.strip_suffix(b"\r").unwrap_or(l)).into_owned())
            .collect();
        if lines.last().is_some_and(String::is_empty) {
            lines.pop();
        }
        lines
    }
}

/// What came of a wait for output.
enum Wait {
    Came,
    Deadline,
    /// The reader ended: the child closed its stdout.
    Ended,
}

/// How a run ended.
enum End {
    /// Its child exited, with this status.
    Exited(ExitStatus),
    TimedOut,
    /// Stopped on the line of this place.
    Marker(usize),
    /// Stopped by the caller.
    Stopped,
}

/// A running child, QEMU as a rule, whose stdout a thread reads in pieces
/// of bytes as they come: `expect` waits for a text, a prompt with no
/// newline among them, and `send` types a line; each line that ends is
/// echoed with no CR; `stop` is the one way to end it (spec 14).
pub struct Run {
    child: Child,
    stdin: Option<ChildStdin>,
    reader: Option<JoinHandle<()>>,
    /// The reader of the child's stderr when this thread keeps its
    /// output (out.rs): its text joins the job's output at the end.
    errors: Option<JoinHandle<String>>,
    pieces: mpsc::Receiver<Vec<u8>>,
    /// The reader sets it as it ends: the test of `stop` looks at it.
    #[cfg(test)]
    ended: Arc<AtomicBool>,
    transcript: Transcript,
    /// The lines that ended so far, a CR before the LF cut, and where the
    /// line that has not ended starts.
    lines: Vec<String>,
    line_start: usize,
    echo: Box<dyn FnMut(&str)>,
}

impl Run {
    /// Starts `cmd` with `input` on its stdin; each line echoes on
    /// xtask's stdout.
    pub fn start(cmd: Command, input: Input) -> Result<Run, String> {
        Run::start_with(cmd, input, Box::new(|line| println!("{line}")))
    }

    /// `start`, with each line echoed to `echo`.
    fn start_with(
        mut cmd: Command,
        input: Input,
        echo: Box<dyn FnMut(&str)>,
    ) -> Result<Run, String> {
        let stdin = match input {
            Input::Null => Stdio::null(),
            Input::Pipe => Stdio::piped(),
        };
        let keep = crate::out::capturing();
        let mut child = cmd
            .stdin(stdin)
            .stdout(Stdio::piped())
            .stderr(if keep {
                Stdio::piped()
            } else {
                Stdio::inherit()
            })
            .spawn()
            .map_err(|e| format!("{cmd:?}: {e}"))?;
        let errors = child.stderr.take().map(|mut stderr| {
            std::thread::spawn(move || {
                let mut text = Vec::new();
                let _ = stderr.read_to_end(&mut text);
                String::from_utf8_lossy(&text).into_owned()
            })
        });
        let mut stdout = child.stdout.take().expect("stdout is piped");
        let (tx, pieces) = mpsc::channel();
        #[cfg(test)]
        let ended = Arc::new(AtomicBool::new(false));
        #[cfg(test)]
        let done = Arc::clone(&ended);
        let reader = std::thread::spawn(move || {
            let mut buf = [0; 4096];
            // A read error ends the output as its end does.
            while let Ok(n @ 1..) = stdout.read(&mut buf) {
                if tx.send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
            #[cfg(test)]
            done.store(true, Ordering::Release);
        });
        Ok(Run {
            stdin: child.stdin.take(),
            child,
            reader: Some(reader),
            errors,
            pieces,
            #[cfg(test)]
            ended,
            transcript: Transcript::new(&[]),
            lines: Vec::new(),
            line_start: 0,
            echo,
        })
    }

    /// Takes in a piece of output: the lines it ends are kept and echoed.
    fn take(&mut self, piece: &[u8]) {
        self.transcript.extend(piece);
        let bytes = &self.transcript.bytes;
        while let Some(len) = bytes[self.line_start..].iter().position(|&b| b == b'\n') {
            let raw = &bytes[self.line_start..self.line_start + len];
            let line = String::from_utf8_lossy(raw.strip_suffix(b"\r").unwrap_or(raw));
            (self.echo)(&line);
            self.lines.push(line.into_owned());
            self.line_start += len + 1;
        }
    }

    /// The line that no LF ended yet, if there are bytes of it: it ends
    /// with the output, and is kept and echoed.
    fn end_line(&mut self) {
        let bytes = &self.transcript.bytes;
        if self.line_start < bytes.len() {
            let raw = &bytes[self.line_start..];
            let line = String::from_utf8_lossy(raw.strip_suffix(b"\r").unwrap_or(raw));
            (self.echo)(&line);
            self.lines.push(line.into_owned());
            self.line_start = bytes.len();
        }
    }

    /// Waits for the next piece of output until `deadline`.
    fn wait(&mut self, deadline: Instant) -> Wait {
        let left = deadline.saturating_duration_since(Instant::now());
        match self.pieces.recv_timeout(left) {
            Ok(piece) => {
                self.take(&piece);
                Wait::Came
            }
            Err(mpsc::RecvTimeoutError::Timeout) => Wait::Deadline,
            Err(mpsc::RecvTimeoutError::Disconnected) => Wait::Ended,
        }
    }

    /// Waits up to `timeout` for `what` after the last text found
    /// (Transcript::find): an error that names it and the last lines when
    /// it did not come.
    pub fn expect(&mut self, what: &str, timeout: Duration) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        while !self.transcript.find(what) {
            self.wait_on(deadline, &format!("{what:?}"))?;
        }
        Ok(())
    }

    /// Waits up to `timeout` for a whole line that `wanted` takes after the
    /// last text found (Transcript::find_line), which `what` names in the
    /// error when it did not come; gives the line.
    pub fn expect_line(
        &mut self,
        what: &str,
        wanted: impl Fn(&str) -> bool,
        timeout: Duration,
    ) -> Result<String, String> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(line) = self.transcript.find_line(&wanted) {
                return Ok(line);
            }
            self.wait_on(deadline, what)?;
        }
    }

    /// One wait of `expect` or `expect_line` for `what`; an error shows
    /// the last lines, the one no LF ended yet among them.
    fn wait_on(&mut self, deadline: Instant, what: &str) -> Result<(), String> {
        match self.wait(deadline) {
            Wait::Came => Ok(()),
            Wait::Deadline => Err(format!(
                "timed out waiting for {what}; last lines: {:?}",
                tail(&self.transcript.lines())
            )),
            Wait::Ended => Err(format!(
                "the output ended before {what}; last lines: {:?}",
                tail(&self.transcript.lines())
            )),
        }
    }

    /// The lines that ended so far, a CR before the LF cut.
    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    /// Waits up to `timeout` for the whole line `line` anywhere in the
    /// output, before the last text found too; the next search still
    /// starts where it did.
    pub fn expect_seen(&mut self, line: &str, timeout: Duration) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        while !self.lines.iter().any(|l| l == line) {
            self.wait_on(deadline, &format!("{line:?} anywhere"))?;
        }
        Ok(())
    }

    /// Types `line` and a CR, as Enter sends it, into the pipe of the
    /// child's stdin.
    pub fn send(&mut self, line: &str) -> Result<(), String> {
        let stdin = self
            .stdin
            .as_mut()
            .ok_or("the run has no pipe on its stdin")?;
        stdin
            .write_all(format!("{line}\r").as_bytes())
            .and_then(|()| stdin.flush())
            .map_err(|e| format!("typing {line:?}: {e}"))
    }

    /// Waits up to `timeout` for the bytes `what` anywhere in the output,
    /// as they are: the output of a client may come before a line of the
    /// kernel's log that was found already.
    pub fn expect_bytes(&mut self, what: &[u8], timeout: Duration) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        while !self.transcript.seen(what) {
            self.wait_on(
                deadline,
                &format!("{:?} anywhere", String::from_utf8_lossy(what)),
            )?;
        }
        Ok(())
    }

    /// Types `bytes` as they are, with no Enter after them.
    pub fn type_raw(&mut self, bytes: &[u8]) -> Result<(), String> {
        let stdin = self
            .stdin
            .as_mut()
            .ok_or("the run has no pipe on its stdin")?;
        stdin
            .write_all(bytes)
            .and_then(|()| stdin.flush())
            .map_err(|e| format!("typing {bytes:?}: {e}"))
    }

    /// Stops the run: its child is killed unless it exited, and the reader
    /// ends with the output and is joined; gives the lines.
    pub fn stop(self) -> Outcome {
        self.end(End::Stopped)
    }

    /// The one way a run ends: the child, unless it `Exited`, is killed and
    /// waited for; its stdin closes; the reader ends with the child's
    /// output and is joined; the output it read is taken in. A run stopped
    /// on a marker keeps its lines up to the marker's.
    fn end(mut self, end: End) -> Outcome {
        let status = match end {
            End::Exited(status) => Some(status),
            _ => {
                let _ = self.child.kill();
                let _ = self.child.wait();
                None
            }
        };
        drop(self.stdin.take());
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        if let Some(Ok(text)) = self.errors.take().map(JoinHandle::join) {
            crate::out::write(&text, true);
        }
        while let Ok(piece) = self.pieces.try_recv() {
            self.take(&piece);
        }
        self.end_line();
        let mut lines = self.transcript.lines();
        if let End::Marker(at) = end {
            lines.truncate(at + 1);
        }
        Outcome {
            lines,
            status,
            timed_out: matches!(end, End::TimedOut),
            stopped_on_marker: matches!(end, End::Marker(_)),
        }
    }
}

/// Runs `cmd` with /dev/null on its stdin (Input::Null), echoing and
/// collecting its lines, until a line contains `stop_marker`, where the
/// lines end, until the child exits, or until `timeout` passes (Run).
pub fn run_until(
    cmd: Command,
    timeout: Duration,
    stop_marker: Option<&str>,
) -> Result<Outcome, String> {
    run_until_staged(cmd, timeout, stop_marker, None)
}

/// A limit on one stage of a run: once a line contains `after`, a line that
/// contains `until` must come within `within` of the clock of the host, or
/// the run is cut as timed out. The probes that a broken service leaves
/// waiting (a starved guest cannot say so itself) fail in `within` and not
/// at the end of the whole run.
#[derive(Clone, Copy)]
pub struct Stage<'a> {
    pub after: &'a str,
    pub until: &'a str,
    pub within: Duration,
}

/// `run_until` with an optional stage limit.
pub fn run_until_staged(
    cmd: Command,
    timeout: Duration,
    stop_marker: Option<&str>,
    stage: Option<Stage<'_>>,
) -> Result<Outcome, String> {
    let mut run = Run::start(cmd, Input::Null)?;
    let deadline = Instant::now() + timeout;
    let mut stage_deadline: Option<Instant> = None;
    let mut checked = 0;
    loop {
        if let Some(marker) = stop_marker
            && let Some(at) = run.lines[checked..].iter().position(|l| l.contains(marker))
        {
            return Ok(run.end(End::Marker(checked + at)));
        }
        if let Some(stage) = stage {
            for line in &run.lines[checked..] {
                if line.contains(stage.until) {
                    stage_deadline = None;
                } else if line.contains(stage.after) {
                    stage_deadline = Some(Instant::now() + stage.within);
                }
            }
        }
        checked = run.lines.len();
        let limit = stage_deadline.map_or(deadline, |at| at.min(deadline));
        match run.wait(limit) {
            Wait::Came => {}
            Wait::Deadline => return Ok(run.end(End::TimedOut)),
            Wait::Ended if run.line_start < run.transcript.bytes.len() => run.end_line(),
            Wait::Ended => break,
        }
    }
    // The output ended, but the child may still run: its exit is polled
    // so that the deadline still holds.
    loop {
        if let Some(status) = run.child.try_wait().map_err(|e| e.to_string())? {
            return Ok(run.end(End::Exited(status)));
        }
        if Instant::now() >= deadline {
            return Ok(run.end(End::TimedOut));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn tail(lines: &[String]) -> &[String] {
    &lines[lines.len().saturating_sub(10)..]
}

/// A run xtask stopped on its last line, which is `line` whole
/// (run_until): the machine still ran, so the run has no exit status. No
/// line has KERNEL PANIC.
pub fn expect_stopped_on(o: &Outcome, line: &str) -> Result<(), String> {
    if !o.stopped_on_marker || o.lines.last().is_none_or(|l| l != line) {
        return Err(format!(
            "QEMU was not stopped on {line:?}; last lines: {:?}",
            tail(&o.lines)
        ));
    }
    match o.lines.iter().find(|l| l.contains("KERNEL PANIC")) {
        Some(panic) => Err(format!("the kernel panicked: {panic}")),
        None => Ok(()),
    }
}

/// Some line must be `line`, whole.
pub fn expect_line(o: &Outcome, line: &str) -> Result<(), String> {
    if o.lines.iter().any(|l| l == line) {
        Ok(())
    } else {
        Err(format!(
            "no line is {line:?}; last lines: {:?}",
            tail(&o.lines)
        ))
    }
}

/// Some line must contain `marker`.
pub fn expect_marker(o: &Outcome, marker: &str) -> Result<(), String> {
    if o.lines.iter().any(|l| l.contains(marker)) {
        Ok(())
    } else {
        Err(format!(
            "kernel never printed {marker:?}; last lines: {:?}",
            tail(&o.lines)
        ))
    }
}

/// The first number after `prefix` on the first line that contains it,
/// anywhere in the line.
pub fn number_after(lines: &[String], prefix: &str) -> Option<u64> {
    let rest = lines
        .iter()
        .find_map(|l| l.find(prefix).map(|i| &l[i + prefix.len()..]))?;
    let digits: String = rest
        .trim_start()
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// The hex value starting at `line[at + 2..]` (right after a `0x`).
fn hex_at(line: &str, at: usize) -> Option<u64> {
    let digits: String = line[at + 2..]
        .chars()
        .take_while(char::is_ascii_hexdigit)
        .collect();
    u64::from_str_radix(&digits, 16).ok()
}

/// The address after `ELR=0x` on the kernel's panic line, if any.
fn elr_in_panic(lines: &[String]) -> Option<u64> {
    let line = lines.iter().find(|l| l.contains("ELR=0x"))?;
    hex_at(line, line.find("ELR=0x")? + "ELR=".len())
}

/// Addresses on backtrace frame lines (`kcore::backtrace`'s `  #N  0x...`).
fn backtrace_addresses(lines: &[String]) -> Vec<u64> {
    lines
        .iter()
        .filter(|l| l.trim_start().starts_with('#'))
        .filter_map(|l| l.find("0x").and_then(|at| hex_at(l, at)))
        .collect()
}

/// The backtrace must name the interrupted instruction (its `ELR`) and at
/// least one caller above it: proof that exception entry recorded a frame
/// linking the fault into the backtrace, beyond the panic handler's own
/// frames (which a backtrace prints regardless of that record).
pub fn backtrace_names_the_fault(lines: &[String]) -> Result<(), String> {
    let elr = elr_in_panic(lines).ok_or("no panic line with ELR=0x...")?;
    let frames = backtrace_addresses(lines);
    let at = frames
        .iter()
        .position(|&a| a == elr)
        .ok_or_else(|| format!("ELR {elr:#x} is not in the backtrace: {frames:#x?}"))?;
    if at + 1 >= frames.len() {
        return Err(format!("ELR {elr:#x} is the last frame in the backtrace"));
    }
    Ok(())
}

/// The address range of the function `name` in `llvm-nm -C --print-size`
/// output (lines of address, size, type and name).
pub fn symbol_range(nm: &str, name: &str) -> Option<Range<u64>> {
    nm.lines().find_map(|l| {
        let mut f = l.splitn(4, ' ');
        let (addr, size, _kind, sym) = (f.next()?, f.next()?, f.next()?, f.next()?);
        if sym != name {
            return None;
        }
        let addr = u64::from_str_radix(addr, 16).ok()?;
        Some(addr..addr + u64::from_str_radix(size, 16).ok()?)
    })
}

/// Rust module paths that must never reach the shipped image (spec 3.4):
/// the kernel's own tests and the hooks that call them.
const TEST_MODULES: [&str; 2] = ["kernel::ktest", "kernel::testpoint"];

/// The lines of `llvm-nm -C` output that name a symbol in a test module
/// (TEST_MODULES), matched as a substring so a closure or a generic
/// instantiation of a test function is caught too.
pub fn test_symbols(nm: &str) -> Vec<&str> {
    nm.lines()
        .filter(|l| TEST_MODULES.iter().any(|m| l.contains(m)))
        .collect()
}

/// The report of a stack overflow in the recursive function `f`: the
/// panic line's ELR lies in `f`, and the backtrace shows the ELR and, above
/// it, more frames of `f`. Those frames come from the kernel stack, while the
/// report runs on the emergency stack: proof that the walk crossed over.
pub fn overflow_report_names(lines: &[String], f: Range<u64>) -> Result<(), String> {
    let elr = elr_in_panic(lines).ok_or("no panic line with ELR=0x...")?;
    if !f.contains(&elr) {
        return Err(format!("ELR {elr:#x} is outside the recursion {f:#x?}"));
    }
    let frames = backtrace_addresses(lines);
    let at = frames
        .iter()
        .position(|&a| a == elr)
        .ok_or_else(|| format!("ELR {elr:#x} is not in the backtrace: {frames:#x?}"))?;
    if !frames[at + 1..].iter().any(|a| f.contains(a)) {
        return Err(format!(
            "the backtrace has no frames of the recursion above the ELR: {frames:#x?}"
        ));
    }
    Ok(())
}

/// QEMU must have finished before the deadline: the error says it timed
/// out and gives the last lines.
pub fn expect_not_timed_out(o: &Outcome) -> Result<(), String> {
    if o.timed_out {
        Err(format!("QEMU timed out; last lines: {:?}", tail(&o.lines)))
    } else {
        Ok(())
    }
}

/// The machine must power itself off before the deadline, with status 0.
pub fn expect_powered_off(o: &Outcome) -> Result<(), String> {
    expect_not_timed_out(o)?;
    match o.status {
        Some(s) if s.success() => Ok(()),
        other => Err(format!("QEMU exit status {other:?}")),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestReport {
    pub passed: Vec<String>,
    pub failed: Vec<(String, String)>,
    /// Failures the run counted itself (`failed=<n>`).
    pub done: Option<u32>,
    /// Tests the run says it has (`total=<n>`), when it says so.
    pub total: Option<u32>,
}

/// Reads `TEST <name> ok`, `TEST <name> FAIL <why>` and
/// `TESTS DONE [total=<n>] failed=<n>` lines.
pub fn parse_report(lines: &[String]) -> TestReport {
    let mut r = TestReport {
        passed: Vec::new(),
        failed: Vec::new(),
        done: None,
        total: None,
    };
    for line in lines {
        if let Some(rest) = line.strip_prefix("TEST ") {
            let mut parts = rest.splitn(3, ' ');
            let name = parts.next().unwrap_or_default().to_string();
            match parts.next() {
                Some("ok") => r.passed.push(name),
                Some("FAIL") => r
                    .failed
                    .push((name, parts.next().unwrap_or_default().to_string())),
                _ => {}
            }
        } else if let Some(rest) = line.strip_prefix("TESTS DONE ") {
            for field in rest.split_whitespace() {
                if let Some(n) = field.strip_prefix("total=") {
                    r.total = n.parse().ok();
                } else if let Some(n) = field.strip_prefix("failed=") {
                    r.done = n.parse().ok();
                }
            }
        }
    }
    r
}

/// A run that ends with init's exit with `code` (spec 7.9, 15.2): the
/// output has exactly one line with KERNEL PANIC, the line after it is
/// exactly `init exited with code <code>`, both come after the first line
/// that starts with `after`, and the machine powered itself off in time
/// with status 0.
pub fn expect_init_exit(o: &Outcome, after: &str, code: u64) -> Result<(), String> {
    expect_powered_off(o)?;
    let panics: Vec<usize> = o
        .lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.contains("KERNEL PANIC"))
        .map(|(i, _)| i)
        .collect();
    let &[at] = &panics[..] else {
        return Err(format!(
            "{} lines with KERNEL PANIC, one expected; last lines: {:?}",
            panics.len(),
            tail(&o.lines)
        ));
    };
    let exit = format!("init exited with code {code}");
    match o.lines.get(at + 1) {
        Some(line) if *line == exit => {}
        other => {
            return Err(format!(
                "the kernel panicked with {other:?} after {:?}, {exit:?} expected",
                o.lines[at]
            ));
        }
    }
    match o.lines.iter().position(|l| l.starts_with(after)) {
        Some(start) if start < at => Ok(()),
        Some(_) => Err(format!("the kernel panicked before {after:?}")),
        None => Err(format!(
            "no line starts with {after:?}; last lines: {:?}",
            tail(&o.lines)
        )),
    }
}

/// A run of tests in QEMU finished in time with status 0, or xtask
/// stopped it on a line (run_until), some tests passed, none failed, and
/// the run said so in its `TESTS DONE` line. A panic powers the machine
/// off with status 0 as well (spec 14), so with no `exit` any line with
/// KERNEL PANIC fails the run; a run of the test init ends with the panic
/// of init's exit, and `exit` is its expected code (expect_init_exit after
/// `TESTS DONE`). Failed tests are named first: the test init exits with
/// their count.
pub fn verdict(o: &Outcome, r: &TestReport, exit: Option<u64>) -> Result<(), String> {
    expect_not_timed_out(o)?;
    if !r.failed.is_empty() {
        return Err(format!("{} test(s) failed: {:?}", r.failed.len(), r.failed));
    }
    match exit {
        Some(code) => expect_init_exit(o, "TESTS DONE ", code)?,
        None => {
            if let Some(panic) = o.lines.iter().find(|l| l.contains("KERNEL PANIC")) {
                return Err(format!("the kernel panicked: {panic}"));
            }
        }
    }
    match r.done {
        Some(0) => {}
        Some(n) => return Err(format!("the run reported {n} failed test(s)")),
        None => {
            return Err(format!(
                "no TESTS DONE line; last lines: {:?}",
                tail(&o.lines)
            ));
        }
    }
    if r.passed.is_empty() {
        return Err("no tests ran".into());
    }
    match o.status {
        Some(s) if s.success() => Ok(()),
        None if o.stopped_on_marker => Ok(()),
        other => Err(format!("QEMU exit status {other:?}")),
    }
}

/// As `verdict`, for a run that counts its tests: it prints
/// `TESTS DONE total=<n> ...`, and each of the n passed once. A test line
/// that went missing in the output fails the run.
pub fn counted_verdict(o: &Outcome, r: &TestReport, exit: Option<u64>) -> Result<(), String> {
    verdict(o, r, exit)?;
    let total = r.total.ok_or("the run never said how many tests it has")?;
    let mut names = r.passed.clone();
    names.sort();
    names.dedup();
    if names.len() != r.passed.len() {
        return Err(format!("a test passed twice: {:?}", r.passed));
    }
    if r.passed.len() != total as usize {
        return Err(format!(
            "{} of {total} tests reported: {:?}",
            r.passed.len(),
            r.passed
        ));
    }
    Ok(())
}

/// The test of the test init that fails under HVF, and its reason: QEMU
/// under HVF reads an address with no device as 0 and injects no
/// external abort (spec 7.9), so the child reading a window on a hole does
/// not fault.
pub const HOLE_TEST: &str = "window_over_a_hole_faults_only_its_process";
pub const HOLE_READS_ZERO: &str = "the child read the hole and did not fault";

/// As `counted_verdict`, for a run of the test init under HVF (spec
/// 15.2): HOLE_TEST fails with HOLE_READS_ZERO, the run counts that one
/// failure, every other test passes once, and init exits with 1, its
/// count of failures. Any other failure, another reason, or HOLE_TEST
/// passing fails the run: a QEMU that starts to inject the abort shows up
/// here.
pub fn hvf_verdict(o: &Outcome, r: &TestReport) -> Result<(), String> {
    let hole = (HOLE_TEST.to_string(), HOLE_READS_ZERO.to_string());
    if r.failed != [hole] || r.done != Some(1) {
        return Err(format!(
            "under HVF only {HOLE_TEST} fails, with {HOLE_READS_ZERO:?}; this run failed {:?}, counting {:?}",
            r.failed, r.done
        ));
    }
    let mut all = r.clone();
    all.passed.push(HOLE_TEST.to_string());
    all.failed.clear();
    all.done = Some(0);
    counted_verdict(o, &all, Some(1))
}

/// Why `cargo xtask hvf` cannot run here, if it cannot (spec 14): the host
/// must be macOS on Apple silicon (`os`, `arch` as std::env::consts gives
/// them), `sysctl -n kern.hv_support` must print 1, which a Mac in a
/// virtual machine without nested virtualization does not, and
/// `qemu-system-aarch64 -accel help` must run and list hvf.
pub fn hvf_host(os: &str, arch: &str, hv_support: &str, accels: &str) -> Result<(), String> {
    if (os, arch) != ("macos", "aarch64") {
        return Err(format!("this is {os} on {arch}"));
    }
    if hv_support.trim() != "1" {
        return Err("kern.hv_support is not 1".into());
    }
    if accels.trim().is_empty() {
        return Err("qemu-system-aarch64 did not run".into());
    }
    if !accels.lines().any(|l| l.trim() == "hvf") {
        return Err("qemu-system-aarch64 -accel help lists no hvf".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    fn sh(script: &str) -> Command {
        let mut c = Command::new("sh");
        c.args(["-c", script]);
        c
    }

    #[test]
    fn args_select_the_spec_machine_and_boot_image() {
        let a = args(&VIRT, Path::new("k.img"), Some(Path::new("b.img")));
        let joined = a.join(" ");
        assert!(joined.contains("-machine virt,gic-version=2"));
        assert!(!joined.contains("virtualization"));
        assert!(joined.contains("-cpu cortex-a72"));
        assert!(joined.contains("-m 512M"));
        assert!(joined.contains("-kernel k.img"));
        assert!(joined.contains("-initrd b.img"));
        assert!(
            joined.contains("-global virtio-mmio.force-legacy=false -device virtio-rng-device,bus=virtio-mmio-bus.31")
        );
        assert!(
            !args(&VIRT, Path::new("k.elf"), None)
                .join(" ")
                .contains("-initrd")
        );
    }

    #[test]
    fn commands_find_machines_by_name() {
        assert_eq!(machine(None).map(|m| m.name), Ok(VIRT.name));
        let el2 = String::from("EL2");
        assert_eq!(machine(Some(&el2)).map(|m| m.machine), Ok(VIRT_EL2.machine));
        assert!(machine(Some(&String::from("el2"))).is_err());
        let mut names: Vec<_> = MACHINES.iter().map(|m| m.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), MACHINES.len(), "two machines share a name");
    }

    #[test]
    fn two_gib_machine_asks_for_2g() {
        let joined = args(&VIRT_2G, Path::new("k.img"), None).join(" ");
        assert!(joined.contains("-m 2G"));
        assert!(joined.contains("-cpu cortex-a53"));
        assert!(!joined.contains("virtualization"));
    }

    #[test]
    fn gicv3_machines_ask_for_gic_version_3() {
        let joined = args(&VIRT_V3, Path::new("k.img"), None).join(" ");
        assert!(joined.contains("-machine virt,gic-version=3 "));
        assert!(joined.contains("-cpu cortex-a72"));
        assert!(joined.contains("-m 512M"));
        let joined = args(&VIRT_EL2_V3, Path::new("k.img"), None).join(" ");
        assert!(joined.contains("-machine virt,gic-version=3,virtualization=on"));
        assert!(joined.contains("-cpu cortex-a53"));
    }

    #[test]
    fn hvf_machines_pin_the_irqchip() {
        let v3 = args(&HVF_V3, Path::new("k.img"), None).join(" ");
        assert!(v3.contains("-machine virt,gic-version=3 -accel hvf,kernel-irqchip=on "));
        let v2 = args(&HVF_V2, Path::new("k.img"), None).join(" ");
        assert!(v2.contains("-machine virt,gic-version=2 -accel hvf,kernel-irqchip=off "));
        for m in [&HVF_V3, &HVF_V2] {
            let a = args(m, Path::new("k.img"), None).join(" ");
            assert!(m.is_hvf());
            assert!(a.contains("-cpu host -m 512M"));
            assert!(!a.contains("virtualization"));
        }
        for m in [&VIRT, &VIRT_EL2, &VIRT_2G, &VIRT_V3, &VIRT_EL2_V3] {
            assert!(!m.is_hvf(), "{}", m.name);
            assert!(
                args(m, Path::new("k.img"), None)
                    .join(" ")
                    .contains("-accel tcg ")
            );
        }
    }

    #[test]
    fn hvf_needs_macos_on_apple_silicon() {
        let accels = "Accelerators supported in QEMU binary:\ntcg\nhvf\n";
        assert_eq!(hvf_host("macos", "aarch64", "1\n", accels), Ok(()));
        for (os, arch) in [
            ("linux", "aarch64"),
            ("macos", "x86_64"),
            ("linux", "x86_64"),
        ] {
            assert!(hvf_host(os, arch, "1\n", accels).is_err(), "{os} {arch}");
        }
        for hv in ["0\n", ""] {
            assert!(hvf_host("macos", "aarch64", hv, accels).is_err(), "{hv:?}");
        }
        let tcg_only = "Accelerators supported in QEMU binary:\ntcg\n";
        assert!(hvf_host("macos", "aarch64", "1\n", tcg_only).is_err());
        assert_eq!(
            hvf_host("macos", "aarch64", "1\n", ""),
            Err("qemu-system-aarch64 did not run".into())
        );
    }

    #[test]
    fn hvf_verdict_accepts_only_the_hole() {
        let hole = format!("TEST {HOLE_TEST} FAIL {HOLE_READS_ZERO}");
        let run = |l: &[&str]| {
            let o = finished(&[l, &exit_panic(1)[..]].concat());
            hvf_verdict(&o, &parse_report(&o.lines))
        };
        let with_hole = ["TEST a ok", &hole, "TESTS DONE total=2 failed=1"];
        assert_eq!(run(&with_hole), Ok(()));
        for reason in [
            "the child faulted twice",
            "the child did not end with a fault",
        ] {
            let other = format!("TEST {HOLE_TEST} FAIL {reason}");
            assert!(run(&["TEST a ok", &other, "TESTS DONE total=2 failed=1"]).is_err());
        }
        assert!(run(&["TEST a FAIL x", &hole, "TESTS DONE total=2 failed=2"]).is_err());
        assert!(run(&["TEST a ok", &hole, "TESTS DONE total=2 failed=2"]).is_err());
        let hole_passes = format!("TEST {HOLE_TEST} ok");
        assert!(run(&["TEST a ok", &hole_passes, "TESTS DONE total=2 failed=0"]).is_err());
        assert!(run(&["TEST a ok", &hole, "TESTS DONE total=3 failed=1"]).is_err());
        assert!(
            run(&[
                "TEST a ok",
                &hole,
                "TESTS DONE total=2 failed=1",
                "KERNEL PANIC: x"
            ])
            .is_err()
        );
        let exits_with_0 = finished(&[&with_hole[..], &exit_panic(0)[..]].concat());
        assert!(hvf_verdict(&exits_with_0, &parse_report(&exits_with_0.lines)).is_err());
    }

    #[test]
    fn number_after_reads_the_first_number() {
        let l = lines(&["boot", "frames     1987 MiB free"]);
        assert_eq!(number_after(&l, "frames "), Some(1987));
    }

    #[test]
    fn number_after_finds_the_prefix_inside_a_line() {
        let l = lines(&["[0.1] frames     12 MiB free"]);
        assert_eq!(number_after(&l, "frames "), Some(12));
    }

    #[test]
    fn number_after_needs_the_prefix_and_a_number() {
        assert_eq!(number_after(&lines(&["boot"]), "frames "), None);
        assert_eq!(number_after(&lines(&["frames none"]), "frames "), None);
    }

    #[test]
    fn backtrace_names_the_fault_accepts_the_elr_with_a_caller_above_it() {
        let l = lines(&[
            "unexpected exception EL1h sync: unknown or undefined instruction (EC 0x0) ESR=0x2000000 ELR=0xffffffffc00017c0 FAR=0x0",
            "backtrace (look up: lldb -b -o 'image lookup -a ADDR' target/stafeto-probe.elf):",
            "  #0  0xffffffffc0001204",
            "  #4  0xffffffffc00017c0",
            "  #5  0xffffffffc0002378",
        ]);
        assert!(backtrace_names_the_fault(&l).is_ok());
    }

    #[test]
    fn backtrace_names_the_fault_rejects_a_missing_elr() {
        let l = lines(&[
            "unexpected exception EL1h sync: ... ELR=0xffffffffc00017c0 FAR=0x0",
            "backtrace (look up: ...):",
            "  #0  0xffffffffc0001204",
            "  #1  0xffffffffc0002438",
        ]);
        assert!(backtrace_names_the_fault(&l).is_err());
    }

    #[test]
    fn backtrace_names_the_fault_rejects_the_elr_as_the_last_frame() {
        let l = lines(&[
            "unexpected exception EL1h sync: ... ELR=0xffffffffc00017c0 FAR=0x0",
            "backtrace (look up: ...):",
            "  #0  0xffffffffc0001204",
            "  #4  0xffffffffc00017c0",
        ]);
        assert!(backtrace_names_the_fault(&l).is_err());
    }

    const NM: &str = "\
ffffffffc0003a0c 0000000000000014 t kernel::arch::aarch64::probe::recurse
ffffffffc00042f0 0000000000000438 T handle_exception
ffffffffc0009000 T __text_end
";

    #[test]
    fn powered_off_needs_an_exit_in_time_with_status_zero() {
        let off = Outcome {
            lines: vec![],
            status: Some(ExitStatus::from_raw(0)),
            timed_out: false,
            stopped_on_marker: false,
        };
        assert!(expect_powered_off(&off).is_ok());
        let failed = Outcome {
            status: Some(ExitStatus::from_raw(1 << 8)),
            ..off.clone()
        };
        assert!(expect_powered_off(&failed).is_err());
        let hung = Outcome {
            status: None,
            timed_out: true,
            ..off
        };
        assert!(expect_powered_off(&hung).is_err());
    }

    #[test]
    fn symbol_range_reads_address_and_size() {
        assert_eq!(
            symbol_range(NM, "handle_exception"),
            Some(0xffff_ffff_c000_42f0..0xffff_ffff_c000_4728)
        );
    }

    #[test]
    fn symbol_range_needs_the_whole_name_and_a_size() {
        assert_eq!(symbol_range(NM, "recurse"), None);
        assert_eq!(symbol_range(NM, "__text_end"), None);
        assert_eq!(symbol_range(NM, "kernel_main"), None);
    }

    const NM_WITH_TEST_MODULES: &str = "\
ffffffffc00042f0 0000000000000438 T handle_exception
ffffffffc0009000 T kernel::attestation::not_a_test_module
ffffffffc0001000 t core::ptr::drop_glue::<kernel::ktest::TestSpace>
ffffffffc0001100 t kernel::ktest::calls::with_used_quota
ffffffffc0001200 t kernel::testpoint::skip_brk
";

    #[test]
    fn test_symbols_finds_ktest_and_testpoint_module_paths() {
        let found = test_symbols(NM_WITH_TEST_MODULES);
        assert_eq!(found.len(), 3);
        assert!(
            found
                .iter()
                .all(|l| l.contains("kernel::ktest") || l.contains("kernel::testpoint"))
        );
    }

    #[test]
    fn test_symbols_ignores_names_that_merely_contain_test() {
        assert!(test_symbols(NM).is_empty());
        assert!(
            test_symbols("ffffffffc0009000 T kernel::attestation::not_a_test_module\n").is_empty()
        );
    }

    const RECURSE: std::ops::Range<u64> = 0xffff_ffff_c000_3a0c..0xffff_ffff_c000_3a20;

    fn overflow_report(elr: &str, frames: &[&str]) -> Vec<String> {
        let mut l = vec![
            "kernel stack overflow: no room for the trap frame at SP 0xffffffffc001fef0"
                .to_string(),
            format!(
                "unexpected exception EL1h sync: data abort in the kernel (EC 0x25) ESR=0x96000047 ELR={elr} FAR=0xffffffffc001ff70"
            ),
            "backtrace (look up: lldb -b -o 'image lookup -a ADDR' target/stafeto-overflow.elf):"
                .to_string(),
        ];
        l.extend(
            frames
                .iter()
                .enumerate()
                .map(|(i, f)| format!("  #{i:<2} {f}")),
        );
        l
    }

    #[test]
    fn overflow_report_accepts_the_elr_in_the_recursion_with_more_of_it_above() {
        let l = overflow_report(
            "0xffffffffc0003a10",
            &[
                "0xffffffffc0004400",
                "0xffffffffc0003a10",
                "0xffffffffc0003a18",
            ],
        );
        assert!(overflow_report_names(&l, RECURSE).is_ok());
    }

    #[test]
    fn overflow_report_rejects_an_elr_outside_the_recursion() {
        let l = overflow_report(
            "0xffffffffc0004400",
            &["0xffffffffc0004400", "0xffffffffc0003a18"],
        );
        assert!(overflow_report_names(&l, RECURSE).is_err());
    }

    #[test]
    fn overflow_report_rejects_an_elr_missing_from_the_backtrace() {
        let l = overflow_report("0xffffffffc0003a10", &["0xffffffffc0003a18"]);
        assert!(overflow_report_names(&l, RECURSE).is_err());
    }

    #[test]
    fn overflow_report_rejects_a_backtrace_that_stops_at_the_elr() {
        let l = overflow_report(
            "0xffffffffc0003a10",
            &[
                "0xffffffffc0004400",
                "0xffffffffc0003a10",
                "0xffffffffc0004800",
            ],
        );
        assert!(overflow_report_names(&l, RECURSE).is_err());
    }

    #[test]
    fn el2_args_turn_on_virtualization_on_a_cortex_a53() {
        let a = args(&VIRT_EL2, Path::new("k.img"), Some(Path::new("b.img")));
        let joined = a.join(" ");
        assert!(joined.contains("-machine virt,gic-version=2,virtualization=on"));
        assert!(joined.contains("-cpu cortex-a53"));
        assert!(joined.contains("-m 512M"));
        assert!(joined.contains("-kernel k.img"));
        assert!(joined.contains("-initrd b.img"));
    }

    #[test]
    fn collects_output_of_a_finished_process() {
        let o = run_until(sh("echo one; echo two"), Duration::from_secs(5), None).unwrap();
        assert!(!o.timed_out && !o.stopped_on_marker);
        assert_eq!(o.lines, ["one", "two"]);
        assert!(o.status.unwrap().success());
    }

    #[test]
    fn child_stdin_is_the_null_device() {
        // QEMU's `-serial stdio` puts a terminal on its stdin into raw mode,
        // and a killed QEMU never restores it, so the child must not inherit
        // the caller's stdin. This catches a regression whenever the test
        // runner's own stdin is not /dev/null, as in a terminal.
        let o = run_until(
            sh("if [ /dev/stdin -ef /dev/null ]; then echo null; else echo inherited; fi"),
            Duration::from_secs(5),
            None,
        )
        .unwrap();
        assert_eq!(o.lines, ["null"]);
    }

    #[test]
    fn kills_a_process_that_outlives_the_deadline() {
        let start = Instant::now();
        let o = run_until(
            sh("echo started; exec sleep 10"),
            Duration::from_millis(300),
            None,
        )
        .unwrap();
        assert!(o.timed_out);
        assert!(start.elapsed() < Duration::from_secs(5));
        assert!(expect_stopped_on(&o, "started").is_err());
    }

    #[test]
    fn stops_on_the_marker() {
        let start = Instant::now();
        let o = run_until(
            sh("echo booting; echo 'KERNEL PANIC: no device tree'; exec sleep 10"),
            Duration::from_secs(20),
            Some("no device tree"),
        )
        .unwrap();
        assert!(o.stopped_on_marker && !o.timed_out);
        assert!(start.elapsed() < Duration::from_secs(5));
        assert!(expect_marker(&o, "no device tree").is_ok());
    }

    /// Spec 13.4, 15.2: init lives on, so a run of the normal build and
    /// of init's test table ends when xtask stops QEMU on its line; such a
    /// run has no exit status. A run that was not stopped, stopped on
    /// another line or with a panic in it fails.
    #[test]
    fn a_run_stopped_on_its_line_needs_no_exit_status() {
        let stopped = |l: &[&str]| Outcome {
            lines: lines(l),
            status: None,
            timed_out: false,
            stopped_on_marker: true,
        };
        let started = stopped(&["boot complete", "init: services started"]);
        assert_eq!(
            expect_stopped_on(&started, "init: services started"),
            Ok(())
        );
        assert!(expect_stopped_on(&started, "services started").is_err());
        assert!(expect_stopped_on(&started, "boot complete").is_err());
        let off = Outcome {
            status: Some(ExitStatus::from_raw(0)),
            stopped_on_marker: false,
            ..started.clone()
        };
        assert!(expect_stopped_on(&off, "init: services started").is_err());
        let panicked = stopped(&["KERNEL PANIC: boom", "init: services started"]);
        assert!(expect_stopped_on(&panicked, "init: services started").is_err());
        let judge = |o: &Outcome| counted_verdict(o, &parse_report(&o.lines), None);
        let done = stopped(&["TEST a ok", "TESTS DONE total=1 failed=0"]);
        assert_eq!(judge(&done), Ok(()));
        let failed = stopped(&["TEST a FAIL x", "TESTS DONE total=1 failed=1"]);
        assert!(judge(&failed).is_err());
        let crashed = stopped(&[
            "TEST a ok",
            "KERNEL PANIC: boom",
            "TESTS DONE total=1 failed=0",
        ]);
        assert!(judge(&crashed).is_err());
        let exit = Outcome {
            stopped_on_marker: false,
            ..done.clone()
        };
        assert!(judge(&exit).is_err());
    }

    #[test]
    fn survives_non_utf8_output() {
        let start = Instant::now();
        let o = run_until(
            sh("printf 'bad \\377 byte\\n'; echo after; exec sleep 10"),
            Duration::from_millis(300),
            None,
        )
        .unwrap();
        assert!(o.timed_out);
        assert!(start.elapsed() < Duration::from_secs(5));
        assert!(o.lines.iter().any(|l| l.starts_with("bad ")));
        assert!(o.lines.iter().any(|l| l == "after"));
    }

    #[test]
    fn marker_must_appear() {
        let o = Outcome {
            lines: vec!["booting".into()],
            status: None,
            timed_out: true,
            stopped_on_marker: false,
        };
        assert!(expect_marker(&o, "no device tree").is_err());
    }

    fn lines(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn report_collects_passes_failures_and_total() {
        let r = parse_report(&lines(&[
            "stafeto 0.1.0 booting",
            "TEST a ok",
            "TEST b FAIL memory is not 512 MiB",
            "TESTS DONE failed=1",
        ]));
        assert_eq!(r.passed, ["a"]);
        assert_eq!(
            r.failed,
            [("b".to_string(), "memory is not 512 MiB".to_string())]
        );
        assert_eq!(r.done, Some(1));
    }

    #[test]
    fn verdict_accepts_a_clean_run() {
        let o = Outcome {
            lines: lines(&["TEST a ok", "TESTS DONE failed=0"]),
            status: Some(ExitStatus::from_raw(0)),
            timed_out: false,
            stopped_on_marker: false,
        };
        assert!(verdict(&o, &parse_report(&o.lines), None).is_ok());
    }

    #[test]
    fn verdict_rejects_failures_hangs_crashes_and_empty_runs() {
        let base = Outcome {
            lines: vec![],
            status: Some(ExitStatus::from_raw(0)),
            timed_out: false,
            stopped_on_marker: false,
        };
        let with = |l: &[&str]| Outcome {
            lines: lines(l),
            ..base.clone()
        };
        let failed = with(&["TEST a FAIL x", "TESTS DONE failed=1"]);
        assert!(verdict(&failed, &parse_report(&failed.lines), None).is_err());
        let hung = Outcome {
            timed_out: true,
            status: None,
            ..with(&["TEST a ok"])
        };
        assert!(verdict(&hung, &parse_report(&hung.lines), None).is_err());
        let crashed = with(&["TEST a ok", "KERNEL PANIC: boom"]);
        assert!(verdict(&crashed, &parse_report(&crashed.lines), None).is_err());
        let empty = with(&["TESTS DONE failed=0"]);
        assert!(verdict(&empty, &parse_report(&empty.lines), None).is_err());
        let bad_status = Outcome {
            status: Some(ExitStatus::from_raw(1 << 8)),
            ..with(&["TEST a ok", "TESTS DONE failed=0"])
        };
        assert!(verdict(&bad_status, &parse_report(&bad_status.lines), None).is_err());
    }

    /// Spec 14: a run that timed out fails with a text that says so and
    /// gives its last lines, the ten last and no other.
    #[test]
    fn verdict_names_a_hang() {
        let mut shown: Vec<String> = (1..=12).map(|i| format!("TEST t{i} ok")).collect();
        shown.push("init: services started".into());
        let hung = Outcome {
            lines: shown.clone(),
            status: None,
            timed_out: true,
            stopped_on_marker: false,
        };
        let why = verdict(&hung, &parse_report(&hung.lines), None).unwrap_err();
        assert!(why.contains("timed out"), "{why}");
        assert!(why.contains("init: services started"), "{why}");
        assert!(
            why.contains("TEST t4 ok") && !why.contains("TEST t3 ok"),
            "{why}"
        );
    }

    /// A run with failed tests fails with a text that names each of them
    /// and its reason.
    #[test]
    fn verdict_names_the_failed_tests() {
        let o = finished(&[
            "TEST a ok",
            "TEST window_is_checked FAIL the page was open",
            "TEST b ok",
            "TEST log_counts_what_it_lost FAIL 5 lost, 6 expected",
            "TESTS DONE total=4 failed=2",
        ]);
        let why = verdict(&o, &parse_report(&o.lines), None).unwrap_err();
        for named in [
            "2 test(s) failed",
            "window_is_checked",
            "the page was open",
            "log_counts_what_it_lost",
            "5 lost, 6 expected",
        ] {
            assert!(why.contains(named), "{named:?} is not in {why}");
        }
        assert!(!why.contains("\"a\""), "{why}");
    }

    /// The output of a shell dialog: the prompt, a command's echo and its
    /// answer, the next prompt.
    const DIALOG: &[u8] =
        b"boot complete\r\nstafeto> echo hello stafeto\r\nhello stafeto\r\nstafeto> ";

    /// Spec 14: the answer to a command is looked for after the command
    /// was typed, so its echo and what came before do not count.
    #[test]
    fn an_answer_is_looked_for_after_its_command() {
        let mut t = Transcript::new(DIALOG);
        assert!(t.find("stafeto> "));
        assert!(t.find("echo hello stafeto\r\n"));
        assert_eq!(
            t.find_line(|l| l == "hello stafeto"),
            Some("hello stafeto".into())
        );
        assert!(t.find("stafeto> "));
        // With no answer, the echo of the command does not pass for it.
        let unanswered = b"stafeto> echo hello stafeto\r\nstafeto> ";
        let mut t = Transcript::new(unanswered);
        assert!(t.find("echo hello stafeto\r\n"));
        assert!(!t.find("hello stafeto"));
        assert_eq!(t.find_line(|l| l.ends_with("hello stafeto")), None);
        // A line that starts before the text found is no whole line after
        // it.
        let mut t = Transcript::new(b"up 1.5 s\r\nup 2.0 s\r\n");
        assert!(t.find("up 1"));
        assert_eq!(
            t.find_line(|l| l.starts_with("up ")),
            Some("up 2.0 s".into())
        );
    }

    /// Spec 14: the prompt comes with no newline after it and is found all
    /// the same; the lines end with it.
    #[test]
    fn a_prompt_needs_no_newline() {
        let mut t = Transcript::new(DIALOG);
        assert!(t.find("hello stafeto\r\nstafeto> "));
        assert!(!t.find("stafeto> "), "one prompt is found once");
        assert_eq!(t.find_line(|_| true), None);
        assert_eq!(
            t.lines(),
            [
                "boot complete",
                "stafeto> echo hello stafeto",
                "hello stafeto",
                "stafeto> "
            ]
        );
    }

    /// Each line of a run echoes as it ends, with no CR (spec 14); the
    /// lines of the outcome have none either.
    #[test]
    fn echo_drops_the_carriage_return() {
        let echoed = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let sink = std::rc::Rc::clone(&echoed);
        let echo = Box::new(move |line: &str| sink.borrow_mut().push(line.to_string()));
        let script = sh("printf 'one\\r\\ntwo\\r\\nprompt> '");
        let mut run = Run::start_with(script, Input::Null, echo).unwrap();
        run.expect("prompt> ", Duration::from_secs(5)).unwrap();
        let o = run.stop();
        assert_eq!(*echoed.borrow(), ["one", "two", "prompt> "]);
        assert_eq!(o.lines, ["one", "two", "prompt> "]);
    }

    /// Spec 14: `stop` kills the child and joins the thread that reads
    /// it, whose pipe the kill closed; a line typed into the pipe of its
    /// stdin comes back from `cat`.
    #[test]
    fn stopping_a_run_joins_its_reader() {
        let start = Instant::now();
        let mut run = Run::start(sh("echo ready; exec cat"), Input::Pipe).unwrap();
        run.expect("ready\n", Duration::from_secs(5)).unwrap();
        run.send("ping").unwrap();
        run.expect("ping\r", Duration::from_secs(5)).unwrap();
        let ended = Arc::clone(&run.ended);
        assert!(!ended.load(Ordering::Acquire), "cat still runs");
        let o = run.stop();
        assert!(ended.load(Ordering::Acquire), "the reader was not joined");
        assert_eq!(o.lines, ["ready", "ping"]);
        assert!(!o.timed_out && !o.stopped_on_marker && o.status.is_none());
        assert!(start.elapsed() < Duration::from_secs(5));
        // A run with /dev/null on its stdin has nothing to type into.
        let mut quiet = Run::start(sh("exec cat"), Input::Null).unwrap();
        assert!(quiet.send("x").is_err());
        let _ = quiet.stop();
    }

    #[test]
    fn verdict_needs_the_tests_done_line() {
        let cut = finished(&["TEST a ok", "TEST b ok"]);
        assert!(verdict(&cut, &parse_report(&cut.lines), None).is_err());
        let done = finished(&["TEST a ok", "TEST b ok", "TESTS DONE failed=0"]);
        assert!(verdict(&done, &parse_report(&done.lines), None).is_ok());
    }

    /// A panic powers the machine off with status 0 (spec 14), so only its
    /// line tells it from a clean end.
    #[test]
    fn verdict_rejects_a_panic_after_the_report() {
        for panic in [
            "KERNEL PANIC: panicked at kernel/src/ktest.rs:1:1:",
            "KERNEL PANIC while panicking; parking",
        ] {
            let o = finished(&["TEST a ok", "TESTS DONE failed=0", "", panic]);
            assert!(
                verdict(&o, &parse_report(&o.lines), None).is_err(),
                "{panic}"
            );
        }
    }

    fn finished(l: &[&str]) -> Outcome {
        Outcome {
            lines: lines(l),
            status: Some(ExitStatus::from_raw(0)),
            timed_out: false,
            stopped_on_marker: false,
        }
    }

    /// The lines the kernel prints when init exits with `code` (spec
    /// 7.9): an empty line, the panic with its place, the message, and
    /// the start of the backtrace.
    fn exit_panic(code: u64) -> [&'static str; 4] {
        let exit = match code {
            0 => "init exited with code 0",
            1 => "init exited with code 1",
            2 => "init exited with code 2",
            _ => panic!("no line for code {code}"),
        };
        [
            "",
            "KERNEL PANIC: panicked at kernel/src/process/mod.rs:724:42:",
            exit,
            "backtrace (look up: lldb -b -o 'image lookup -a ADDR' target/stafeto.elf):",
        ]
    }

    /// A report of one passed test, then `after`.
    fn run_of(after: &[&str]) -> Outcome {
        finished(&[&["TEST a ok", "TESTS DONE total=1 failed=0"][..], after].concat())
    }

    /// Spec 7.9, 15.2: the test init ends its run with its exit, a panic
    /// whose next line names the code, and a run with the code expected
    /// passes; another code, a machine that did not power itself off, or
    /// a hang fails it.
    #[test]
    fn init_exit_ends_a_run_with_its_code() {
        let judge = |o: &Outcome, code| counted_verdict(o, &parse_report(&o.lines), Some(code));
        let exits = run_of(&exit_panic(0));
        assert_eq!(judge(&exits, 0), Ok(()));
        assert!(judge(&exits, 1).is_err());
        assert_eq!(judge(&run_of(&exit_panic(1)), 1), Ok(()));
        assert!(judge(&run_of(&exit_panic(2)), 0).is_err());
        let failing = Outcome {
            status: Some(ExitStatus::from_raw(1 << 8)),
            ..exits.clone()
        };
        assert!(judge(&failing, 0).is_err());
        let hung = Outcome {
            status: None,
            timed_out: true,
            ..exits.clone()
        };
        assert!(judge(&hung, 0).is_err());
    }

    /// Spec 7.9, 14: only the panic of init's exit ends a run. A panic of
    /// another kind, a second panic after the exit, and a panic that ends
    /// the kernel tests (no exit expected) each fail the run.
    #[test]
    fn another_panic_still_fails_a_run() {
        let judge = |o: &Outcome, exit| counted_verdict(o, &parse_report(&o.lines), exit);
        let other = run_of(&[
            "",
            "KERNEL PANIC: panicked at kernel/src/sched.rs:1:1:",
            "no thread to run",
        ]);
        assert!(judge(&other, Some(0)).is_err());
        let twice = run_of(
            &[
                &exit_panic(0)[..],
                &["KERNEL PANIC while panicking; parking"],
            ]
            .concat(),
        );
        assert!(judge(&twice, Some(0)).is_err());
        assert!(judge(&run_of(&exit_panic(0)), None).is_err());
    }

    /// Spec 7.9: a run with no report ends with init's exit after its
    /// own line, and only a machine that powered itself off in time
    /// passes.
    #[test]
    fn init_exit_is_judged_after_its_line() {
        let refused = "init: table refused: the connections make a cycle: a -> b -> a";
        let run = finished(&[&[refused][..], &exit_panic(2)].concat());
        let after = "init: table refused: ";
        assert_eq!(expect_init_exit(&run, after, 2), Ok(()));
        assert!(expect_init_exit(&run, after, 0).is_err());
        assert!(expect_init_exit(&run, "init: services started", 2).is_err());
        let early = finished(&[&exit_panic(2)[..], &[refused]].concat());
        assert!(expect_init_exit(&early, after, 2).is_err());
        let failing = Outcome {
            status: Some(ExitStatus::from_raw(1 << 8)),
            ..run.clone()
        };
        assert!(expect_init_exit(&failing, after, 2).is_err());
        let hung = Outcome {
            status: None,
            timed_out: true,
            ..run.clone()
        };
        assert!(expect_init_exit(&hung, after, 2).is_err());
    }

    /// Spec 15.2: the exit ends a run only after the report; a panic
    /// before `TESTS DONE`, or with no `TESTS DONE` at all, fails it.
    #[test]
    fn a_panic_before_tests_done_fails_the_run() {
        let judge = |o: &Outcome| counted_verdict(o, &parse_report(&o.lines), Some(0));
        let early = finished(
            &[
                &["TEST a ok"][..],
                &exit_panic(0),
                &["TESTS DONE total=1 failed=0"],
            ]
            .concat(),
        );
        assert!(judge(&early).is_err());
        let cut = finished(&[&["TEST a ok"][..], &exit_panic(0)].concat());
        assert!(judge(&cut).is_err());
    }

    #[test]
    fn report_reads_the_total_of_a_counted_run() {
        let r = parse_report(&lines(&["TEST a ok", "TESTS DONE total=2 failed=1"]));
        assert_eq!((r.total, r.done), (Some(2), Some(1)));
        let uncounted = parse_report(&lines(&["TESTS DONE failed=0"]));
        assert_eq!((uncounted.total, uncounted.done), (None, Some(0)));
    }

    #[test]
    fn counted_verdict_needs_every_test_once() {
        let clean = finished(&["TEST a ok", "TEST b ok", "TESTS DONE total=2 failed=0"]);
        assert!(counted_verdict(&clean, &parse_report(&clean.lines), None).is_ok());
        let lost = finished(&["TEST a ok", "TESTS DONE total=2 failed=0"]);
        assert!(counted_verdict(&lost, &parse_report(&lost.lines), None).is_err());
        let twice = finished(&["TEST a ok", "TEST a ok", "TESTS DONE total=2 failed=0"]);
        assert!(counted_verdict(&twice, &parse_report(&twice.lines), None).is_err());
        let uncounted = finished(&["TEST a ok", "TESTS DONE failed=0"]);
        assert!(counted_verdict(&uncounted, &parse_report(&uncounted.lines), None).is_err());
        let failed = finished(&["TEST a ok", "TEST b FAIL x", "TESTS DONE total=2 failed=1"]);
        assert!(counted_verdict(&failed, &parse_report(&failed.lines), None).is_err());
    }

    #[test]
    fn a_line_must_match_whole() {
        let o = finished(&["TEST a ok", "\u{0}debug_write stops at its length###"]);
        assert!(expect_line(&o, "TEST a ok").is_ok());
        assert!(expect_line(&o, "TEST a").is_err());
        assert!(expect_line(&o, "debug_write stops at its length").is_err());
    }
}
