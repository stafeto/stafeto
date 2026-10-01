// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The kernel log read from the host (spec 3.2, 16.3): what the kernel
//! says before it knows its port, a panic before the device tree among
//! it, stays in the ring of its log, in the kernel's image in RAM. A QEMU
//! run with a monitor on a local TCP port (`monitor_args`) lets xtask
//! save that RAM
//! (`pmemsave`) and find the records in it (`texts`): records of
//! abi::LOG_RECORD bytes, the time, the kind (text of a program or of the
//! kernel), the length, the mark of shown, zeros, then the text and zeros
//! after it (kcore::log::Record), one after another in the ring.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Where QEMU `virt` puts the kernel's image (G4), and the RAM xtask saves
/// from it: the image, its .bss with the ring, and room to spare.
pub const KERNEL_PA: u64 = 0x4020_0000;
pub const SAVED: u64 = 0x10_0000;

const RECORD: usize = abi::LOG_RECORD;
const TEXT_AT: usize = abi::LOG_TEXT_AT;

/// A free local TCP port for a monitor: one the system gave and let go.
pub fn free_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    listener
        .local_addr()
        .map(|a| a.port())
        .map_err(|e| e.to_string())
}

/// QEMU's arguments for a monitor on the local TCP port `port`, which
/// `save` connects to.
pub fn monitor_args(port: u16) -> Vec<String> {
    vec![
        "-monitor".into(),
        format!("tcp:127.0.0.1:{port},server=on,wait=off"),
    ]
}

/// The record at the start of `bytes`, if it reads as one: its time and
/// its text.
fn record(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let r = bytes.get(..RECORD)?;
    let time = u64::from_le_bytes(r[..8].try_into().ok()?);
    let (kind, len, shown) = (r[abi::LOG_KIND_AT], r[abi::LOG_LEN_AT] as usize, r[10]);
    let kinds = [abi::LOG_TEXT_KIND, abi::LOG_KERNEL_KIND];
    let text = &r[TEXT_AT..TEXT_AT + len.min(abi::LOG_TEXT)];
    let ok = time != 0
        && kinds.contains(&kind)
        && (1..=abi::LOG_TEXT).contains(&len)
        && shown <= 1
        && r[11..TEXT_AT].iter().all(|&b| b == 0)
        && r[TEXT_AT + len..].iter().all(|&b| b == 0)
        && text
            .iter()
            .all(|&b| b == b'\n' || b == b'\t' || (0x20..0x7f).contains(&b));
    ok.then_some((time, text))
}

/// The texts of the kernel log's records in `ram`, oldest first: a run of
/// at least two records one after another, at 8-byte steps, read as the
/// ring; the longest such run is taken.
pub fn texts(ram: &[u8]) -> Vec<Vec<u8>> {
    let mut best: Vec<(u64, Vec<u8>)> = Vec::new();
    for start in (0..ram.len().saturating_sub(RECORD)).step_by(8) {
        let mut run = Vec::new();
        let mut at = start;
        while let Some((time, text)) = ram.get(at..).and_then(record) {
            run.push((time, text.to_vec()));
            at += RECORD;
        }
        if run.len() >= 2 && run.len() > best.len() {
            best = run;
        }
    }
    best.sort_by_key(|(time, _)| *time);
    best.into_iter().map(|(_, text)| text).collect()
}

/// The text of the log in `ram`, its records joined.
pub fn text(ram: &[u8]) -> String {
    String::from_utf8_lossy(&texts(ram).concat()).into_owned()
}

/// Saves SAVED bytes of RAM from KERNEL_PA through the monitor on `port`
/// into `to`, a file in QEMU's working directory, and gives them. The
/// name stays short: the monitor echoes each byte of a command with the
/// escapes of its line editor.
pub fn save(port: u16, to: &Path) -> Result<Vec<u8>, String> {
    let name = to
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("a dump needs a file name")?;
    let mut monitor =
        TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("monitor: {e}"))?;
    monitor
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(to);
    let command = format!("pmemsave {KERNEL_PA:#x} {SAVED:#x} {name}\n");
    monitor
        .write_all(command.as_bytes())
        .map_err(|e| format!("monitor: {e}"))?;
    // The banner's prompt, then the prompt after the command.
    let mut seen = Vec::new();
    let mut buf = [0; 256];
    while seen.windows(7).filter(|w| w == b"(qemu) ").count() < 2 {
        let n = monitor
            .read(&mut buf)
            .map_err(|e| format!("monitor: {e}"))?;
        if n == 0 {
            break;
        }
        seen.extend_from_slice(&buf[..n]);
    }
    std::fs::read(to).map_err(|e| format!("{}: {e}", to.display()))
}

/// Runs `cmd`, QEMU with the arguments of `monitor_args` for `port`, in
/// the directory of `dump`, and reads the kernel log from its RAM every
/// 200 ms until its text holds `marker` or `timeout` passes; QEMU is
/// killed then. Gives the text.
pub fn wait_for(
    mut cmd: Command,
    port: u16,
    dump: &Path,
    marker: &str,
    timeout: Duration,
) -> Result<String, String> {
    if let Some(dir) = dump.parent() {
        cmd.current_dir(dir);
    }
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("qemu: {e}"))?;
    let deadline = Instant::now() + timeout;
    let mut text = String::new();
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
        if let Ok(ram) = save(port, dump) {
            text = self::text(&ram);
            if text.contains(marker) {
                break;
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    if text.contains(marker) {
        Ok(text)
    } else {
        Err(format!(
            "the kernel log in RAM never held {marker:?}; it held {text:?}"
        ))
    }
}

/// A path for a run's dump under `dir`.
pub fn path(dir: &Path, name: &str) -> PathBuf {
    dir.join(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put(ram: &mut [u8], at: usize, time: u64, kind: u8, text: &[u8]) {
        let r = &mut ram[at..at + RECORD];
        r[..8].copy_from_slice(&time.to_le_bytes());
        r[abi::LOG_KIND_AT] = kind;
        r[abi::LOG_LEN_AT] = text.len() as u8;
        r[TEXT_AT..TEXT_AT + text.len()].copy_from_slice(text);
    }

    /// The records of a ring in RAM come back in the order of their times,
    /// whatever their places, and bytes around them that read as no
    /// record are skipped.
    #[test]
    fn records_of_the_ring_come_back_in_their_order() {
        let mut ram = vec![0xA5u8; 4096];
        let ring = 1000;
        ram[ring..ring + 4 * RECORD].fill(0);
        put(
            &mut ram,
            ring,
            30,
            abi::LOG_KERNEL_KIND,
            b"KERNEL PANIC: no device ",
        );
        put(
            &mut ram,
            ring + RECORD,
            40,
            abi::LOG_KERNEL_KIND,
            b"tree in x0\n",
        );
        put(
            &mut ram,
            ring + 2 * RECORD,
            10,
            abi::LOG_KERNEL_KIND,
            b"stafeto 0.1.0 booting\n",
        );
        put(&mut ram, ring + 3 * RECORD, 20, abi::LOG_TEXT_KIND, b"x\n");
        assert_eq!(
            text(&ram),
            "stafeto 0.1.0 booting\nx\nKERNEL PANIC: no device tree in x0\n"
        );
        // A record whose length leaves bytes after its text is no record.
        ram[ring + 3 * RECORD + TEXT_AT + 2] = b'y';
        assert_eq!(texts(&ram).len(), 3);
        assert!(texts(&[0; 4096]).is_empty());
    }
}
