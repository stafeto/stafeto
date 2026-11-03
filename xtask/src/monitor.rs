// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! QEMU's monitor (HMP) over a socket, for the probes that look at the
//! screen and press keys: `-monitor unix:PATH,server=on,wait=off` makes
//! QEMU listen, `Monitor::connect` talks to it. `screendump` writes the
//! screen as a PPM file (QEMU takes it with `-display none` too), which
//! `Ppm` reads and takes the CRC-32 of the colours; `sendkey` presses keys
//! as the guest's keyboard device sees them. The CRC is the one the guest
//! computes over the red, green and blue bytes of its own frame, so the
//! two are equal when the screen shows what the guest drew.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

/// The prompt QEMU prints when a command is done.
const PROMPT: &[u8] = b"\r\n(qemu) ";
/// The first prompt, after the banner, has no line before it.
const FIRST_PROMPT: &[u8] = b"(qemu) ";

/// A connection to the monitor of a running QEMU.
pub struct Monitor {
    stream: UnixStream,
}

impl Monitor {
    /// Connects to the socket at `path` and reads the banner up to the first
    /// prompt. The socket appears when QEMU starts, so a refusal or a
    /// missing file is tried again until `timeout`.
    pub fn connect(path: &Path, timeout: Duration) -> Result<Monitor, String> {
        let deadline = Instant::now() + timeout;
        let stream = loop {
            match UnixStream::connect(path) {
                Ok(stream) => break stream,
                Err(e) if Instant::now() >= deadline => {
                    return Err(format!("the monitor at {}: {e}", path.display()));
                }
                Err(_) => std::thread::sleep(Duration::from_millis(50)),
            }
        };
        let mut monitor = Monitor { stream };
        monitor.read_to_prompt(FIRST_PROMPT, timeout)?;
        Ok(monitor)
    }

    /// Reads until the output ends with `prompt`; the text up to it.
    fn read_to_prompt(&mut self, prompt: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
        let deadline = Instant::now() + timeout;
        let mut text = Vec::new();
        let mut chunk = [0; 4096];
        while !text.ends_with(prompt) {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(format!(
                    "the monitor gave no prompt in {timeout:?}; it said {:?}",
                    String::from_utf8_lossy(&text)
                ));
            }
            self.stream
                .set_read_timeout(Some(left))
                .map_err(|e| e.to_string())?;
            match self.stream.read(&mut chunk) {
                Ok(0) => return Err("the monitor closed".to_owned()),
                Ok(n) => text.extend_from_slice(&chunk[..n]),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(e) => return Err(format!("the monitor: {e}")),
            }
        }
        text.truncate(text.len() - prompt.len());
        Ok(text)
    }

    /// Runs the command `line` and gives what it printed: the echo of the
    /// line, which the monitor's line editor sends back with its cursor
    /// movements, is left out.
    pub fn command(&mut self, line: &str, timeout: Duration) -> Result<String, String> {
        self.stream
            .write_all(format!("{line}\n").as_bytes())
            .map_err(|e| format!("the monitor: {e}"))?;
        let text = self.read_to_prompt(PROMPT, timeout)?;
        Ok(printed(&text))
    }

    /// `screendump` to `file`, read back as a picture. QEMU names an error
    /// in the monitor's output; a file it did not write is one too.
    pub fn screendump(&mut self, file: &Path) -> Result<Ppm, String> {
        let _ = std::fs::remove_file(file);
        let said = self.command(
            &format!("screendump {}", file.display()),
            Duration::from_secs(10),
        )?;
        if !said.trim().is_empty() {
            return Err(format!("screendump: {}", said.trim()));
        }
        let bytes = std::fs::read(file).map_err(|e| format!("{}: {e}", file.display()))?;
        Ppm::parse(&bytes)
    }

    /// `sendkey KEY`, the key held for `hold` when there is one (QEMU's
    /// milliseconds, 100 by default). A QEMU key name: `ret`, `esc`, `up`,
    /// `left`, `ctrl`, `a`, or a combination with `-`.
    pub fn sendkey(&mut self, key: &str, hold: Option<u32>) -> Result<(), String> {
        let line = match hold {
            Some(ms) => format!("sendkey {key} {ms}"),
            None => format!("sendkey {key}"),
        };
        let said = self.command(&line, Duration::from_secs(10))?;
        if !said.trim().is_empty() {
            return Err(format!("sendkey {key}: {}", said.trim()));
        }
        Ok(())
    }

    /// Several `sendkey`, `pause` apart (a guest that draws a menu on the
    /// emulated processor needs time between the keys).
    pub fn sendkeys(&mut self, keys: &[&str], pause: Duration) -> Result<(), String> {
        for (i, key) in keys.iter().enumerate() {
            if i > 0 {
                std::thread::sleep(pause);
            }
            self.sendkey(key, None)?;
        }
        Ok(())
    }
}

/// What the monitor printed for a command, without the echo of the line:
/// its text starts after the last carriage return and line feed of the
/// echo; the echo itself ends with an erase to the end of the line, then
/// `\r\n`.
fn printed(text: &[u8]) -> String {
    let after_echo = text
        .windows(2)
        .position(|w| w == b"\r\n")
        .map_or(&text[..0], |at| &text[at + 2..]);
    String::from_utf8_lossy(after_echo).into_owned()
}

/// A picture of QEMU's `screendump`: P6, 8 bits a colour.
#[derive(Debug, PartialEq, Eq)]
pub struct Ppm {
    pub width: usize,
    pub height: usize,
    /// Red, green and blue of each point, line after line.
    pub rgb: Vec<u8>,
}

impl Ppm {
    /// Reads a binary PPM: the magic `P6`, the width, the height and the
    /// largest colour value 255 as decimal numbers separated by white space
    /// (comments from `#` to the end of the line allowed), one white-space
    /// byte, then the points.
    pub fn parse(bytes: &[u8]) -> Result<Ppm, String> {
        let mut at = 0;
        let token = |at: &mut usize| -> Result<String, String> {
            loop {
                match bytes.get(*at) {
                    Some(b'#') => {
                        while bytes.get(*at).is_some_and(|&b| b != b'\n') {
                            *at += 1;
                        }
                    }
                    Some(b) if b.is_ascii_whitespace() => *at += 1,
                    Some(_) => break,
                    None => return Err("a PPM that ends in its header".to_owned()),
                }
            }
            let start = *at;
            while bytes.get(*at).is_some_and(|b| !b.is_ascii_whitespace()) {
                *at += 1;
            }
            Ok(String::from_utf8_lossy(&bytes[start..*at]).into_owned())
        };
        if token(&mut at)? != "P6" {
            return Err("not a binary PPM (P6)".to_owned());
        }
        let number = |text: String, what: &str| -> Result<usize, String> {
            text.parse()
                .map_err(|_| format!("the PPM's {what}: {text:?}"))
        };
        let width = number(token(&mut at)?, "width")?;
        let height = number(token(&mut at)?, "height")?;
        let max = number(token(&mut at)?, "largest value")?;
        if max != 255 {
            return Err(format!("a PPM of largest value {max}, 255 expected"));
        }
        // One white-space byte ends the header.
        at += 1;
        let len = width
            .checked_mul(height)
            .and_then(|n| n.checked_mul(3))
            .ok_or("a PPM of absurd size")?;
        let rgb = bytes
            .get(at..)
            .filter(|rest| rest.len() == len)
            .ok_or_else(|| {
                format!(
                    "a PPM of {width}x{height} wants {len} bytes of points, {} came",
                    bytes.len().saturating_sub(at)
                )
            })?;
        Ok(Ppm {
            width,
            height,
            rgb: rgb.to_vec(),
        })
    }

    /// The CRC-32 of the red, green and blue bytes of the points in order.
    pub fn crc32(&self) -> u32 {
        crc32(&self.rgb)
    }

    /// How many different colours the picture has.
    pub fn colours(&self) -> usize {
        let mut seen = std::collections::HashSet::new();
        seen.extend(self.rgb.as_chunks::<3>().0.iter().copied());
        seen.len()
    }

    /// The share of points, in thousandths, in which this picture differs
    /// from `other`'s; all of them when the sizes differ.
    pub fn differs_from(&self, other: &Ppm) -> usize {
        if self.width != other.width || self.height != other.height {
            return 1000;
        }
        let points = self.width * self.height;
        let different = self
            .rgb
            .as_chunks::<3>()
            .0
            .iter()
            .zip(other.rgb.as_chunks::<3>().0)
            .filter(|(a, b)| a != b)
            .count();
        (different * 1000).checked_div(points).unwrap_or(0)
    }
}

/// The CRC-32 of IEEE 802.3: the polynomial 0xEDB88320 reflected, the
/// start value and the final exclusive or 0xFFFFFFFF.
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in bytes {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                0xEDB8_8320 ^ (crc >> 1)
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ppm(width: usize, height: usize, rgb: &[u8]) -> Vec<u8> {
        let mut bytes = format!("P6\n{width} {height}\n255\n").into_bytes();
        bytes.extend_from_slice(rgb);
        bytes
    }

    #[test]
    fn crc32_of_the_check_string_is_the_standards() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn a_ppm_is_read_with_its_size_and_points() {
        let rgb = [1, 2, 3, 4, 5, 6];
        let p = Ppm::parse(&ppm(2, 1, &rgb)).expect("a PPM");
        assert_eq!((p.width, p.height), (2, 1));
        assert_eq!(p.rgb, rgb);
        assert_eq!(p.crc32(), crc32(&rgb));
    }

    #[test]
    fn a_ppm_with_comments_and_odd_white_space_is_read() {
        let mut bytes = b"P6\n# QEMU\n2\t1 # a comment\n255\n".to_vec();
        bytes.extend_from_slice(&[9; 6]);
        let p = Ppm::parse(&bytes).expect("a PPM");
        assert_eq!((p.width, p.height, p.rgb.len()), (2, 1, 6));
    }

    #[test]
    fn a_bad_ppm_is_refused() {
        assert!(Ppm::parse(b"P5\n1 1\n255\n\0").is_err());
        assert!(Ppm::parse(&ppm(2, 2, &[0; 11])).is_err(), "short");
        assert!(Ppm::parse(&ppm(2, 2, &[0; 13])).is_err(), "long");
        assert!(Ppm::parse(b"P6\n2 2\n").is_err(), "header only");
        assert!(Ppm::parse(b"P6\n2 2\n65535\n").is_err(), "16 bits");
        assert!(Ppm::parse(b"").is_err());
        assert!(Ppm::parse(&ppm(usize::MAX, 2, &[])).is_err());
    }

    #[test]
    fn colours_count_the_different_points() {
        let p = Ppm::parse(&ppm(2, 2, &[1, 1, 1, 1, 1, 1, 2, 2, 2, 3, 3, 3])).expect("a PPM");
        assert_eq!(p.colours(), 3);
    }

    #[test]
    fn the_difference_of_two_pictures_is_in_thousandths() {
        let a = Ppm::parse(&ppm(2, 2, &[0; 12])).expect("a PPM");
        let mut rgb = [0; 12];
        rgb[3] = 1;
        let b = Ppm::parse(&ppm(2, 2, &rgb)).expect("a PPM");
        assert_eq!(a.differs_from(&a), 0);
        assert_eq!(a.differs_from(&b), 250);
        let c = Ppm::parse(&ppm(1, 1, &[0; 3])).expect("a PPM");
        assert_eq!(a.differs_from(&c), 1000);
    }

    /// A monitor that speaks as QEMU's does: the banner and a prompt, the
    /// line editor's echo of each command, its output, the prompt again.
    fn fake_qemu(
        name: &str,
        ppm: Vec<u8>,
    ) -> (std::path::PathBuf, std::thread::JoinHandle<Vec<String>>) {
        use std::io::{BufRead, BufReader};
        use std::os::unix::net::UnixListener;
        let path = std::env::temp_dir().join(format!(
            "stafeto-monitor-test-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind");
        let file = path.with_extension("ppm");
        let thread = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut out = stream.try_clone().expect("clone");
            out.write_all(b"QEMU 11.1.2 monitor - type 'help' for more information\r\n(qemu) ")
                .expect("banner");
            let mut seen = Vec::new();
            for line in BufReader::new(stream).lines() {
                let line = line.expect("a line");
                // Echo with cursor movements, as the line editor does.
                out.write_all(format!("{line}\x1b[K\r\n").as_bytes())
                    .expect("echo");
                if let Some(target) = line.strip_prefix("screendump ") {
                    std::fs::write(target, &ppm).expect("the picture");
                } else if line.contains("bogus") {
                    out.write_all(b"unknown command: 'bogus'\r\n")
                        .expect("error");
                }
                out.write_all(b"(qemu) ").expect("prompt");
                seen.push(line);
                if seen.len() == 3 {
                    break;
                }
            }
            let _ = std::fs::remove_file(&file);
            seen
        });
        (path, thread)
    }

    #[test]
    fn the_monitor_takes_a_screenshot_and_keys() {
        let (path, server) = fake_qemu("shot", ppm(1, 1, &[7, 8, 9]));
        let mut m = Monitor::connect(&path, Duration::from_secs(5)).expect("connect");
        let shot = m
            .screendump(&path.with_extension("ppm"))
            .expect("a screenshot");
        assert_eq!(shot.rgb, [7, 8, 9]);
        m.sendkey("ret", None).expect("sendkey");
        let said = m
            .command("bogus", Duration::from_secs(5))
            .expect("a command");
        assert_eq!(said, "unknown command: 'bogus'");
        assert_eq!(
            server.join().expect("server"),
            [
                format!("screendump {}", path.with_extension("ppm").display()),
                "sendkey ret".to_owned(),
                "bogus".to_owned()
            ]
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_command_the_monitor_refuses_is_an_error_of_sendkey() {
        let (path, server) = fake_qemu("bogus", ppm(1, 1, &[0; 3]));
        let mut m = Monitor::connect(&path, Duration::from_secs(5)).expect("connect");
        let refused = m.sendkey("bogus", None).unwrap_err();
        assert!(refused.contains("unknown command"), "{refused}");
        m.sendkey("a", Some(500)).expect("sendkey");
        m.sendkeys(&["b"], Duration::ZERO).expect("sendkeys");
        assert_eq!(
            server.join().expect("server"),
            ["sendkey bogus", "sendkey a 500", "sendkey b"]
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_echo_of_the_line_is_not_the_output() {
        // What the line editor sends for "info" and what a command prints.
        let echo = b"i\x1b[K\x1b[Din\x1b[K\x1b[D\x1b[Dinf\x1b[K\r\n";
        assert_eq!(printed(echo), "");
        let with_output = [&echo[..], b"unknown command: 'bogus'\r\n"].concat();
        assert_eq!(printed(&with_output), "unknown command: 'bogus'\r\n");
    }
}
