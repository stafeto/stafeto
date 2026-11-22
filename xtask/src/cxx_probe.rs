// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The C++ probe (tests/cxx-probe): a static C++ program on relibc with the
//! libc++, libc++abi and libunwind of tools/build-libcxx.py, in the image of
//! the POSIX process probe (its loader serves the `fork` of the terminate
//! checks). The program prints one line per check with the value it computed;
//! `verdict` compares the lines with the expected ones and the order of the
//! destructors at exit.

use crate::{
    BOOT_PROFILE, INIT_STACK_SIZE, ImageProgram, PIPE_STACK_SIZE, RAMFS_STACK_SIZE, Variant, build,
    build_boot_image, qemu, run_until,
};
use std::time::Duration;

/// The stack of the probe's main thread: libc++'s streams, locales and the
/// unwinder use more than a C program does.
const PROBE_STACK_SIZE: u32 = 256 * 1024;

/// The probe's image: the services of the POSIX process probe, with the
/// C++ probe as its probe program.
pub const PROGRAMS: [ImageProgram; 9] = [
    ("init", "init", INIT_STACK_SIZE, &["table-cxx-probe"]),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &[]),
    ("pipe", "pipe", PIPE_STACK_SIZE, &[]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &[],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    ("cxx-probe", "cxx-probe", PROBE_STACK_SIZE, &[]),
    ("loader", "loader", 0, &[]),
    (
        "virtio-rng",
        "virtio-rng",
        crate::entropy::RNG_STACK_SIZE,
        &[],
    ),
    (
        "entropy",
        "entropy",
        crate::entropy::ENTROPY_STACK_SIZE,
        &[],
    ),
];

const ENDED: &str = "init: cxx-probe ended: exit code 0, not restarted";
const TIMEOUT: Duration = Duration::from_secs(240);
/// The prefix of the probe's lines.
const PREFIX: &str = "cxx-probe: ";

/// The lines of the probe in the order it prints them (the standard output
/// and the error stream of one thread of the program are one sequence on the
/// console). The last seven are the end of the program: the local static
/// object of `main` goes with `main`'s frame; exit then destroys the
/// thread-local objects of the main thread, and the functions of `atexit` and
/// the destructors of static objects in the reverse order of their
/// registration (an atexit function is one of them).
pub const LINES: &[&str] = &[
    "static constructors ran before main: 2, string a static string of the library",
    "exception through 5 frames: from the fifth frame code 42, 6 destructors ran",
    "caught as std::exception: inner",
    "rethrown and caught as MyError: code 1",
    "catch-all caught an int",
    "exception through qsort_r: code 77 after 3 comparisons",
    "exception_ptr rethrown: held in an exception_ptr",
    "nested exception: effect because cause",
    "new of a huge size throws bad_alloc: 1",
    "dynamic_cast up 1 cross 1 down 1 unrelated 0",
    "typeid of a Shape* to a Disc: disc equal 1, a Shape: equal 1, bad_cast 1",
    "type names: i 4Disc",
    "iostream cout 42 2.5 ff true",
    "ostringstream: 3.142 -7 text",
    "istringstream: 12 3.5 word",
    "iostream cerr line",
    "locale C: isalpha(a) 1 isdigit(a) 0 toupper(q) Q ispunct(!) 1 isspace(tab) 1",
    "numpunct facet of the program: 1'234'567",
    "to_string 3.500000 -12, stod 2500, stof 0.25, stold 1.5",
    "from_chars 62.5 (1), to_chars 0.1",
    "std::locale of an unknown name throws runtime_error: 1",
    "std::locale(\"C\") name C",
    "exception thrown by a signal handler caught after raise: code 5",
    "terminate handler ran for an uncaught exception",
    "uncaught exception ends in std::terminate: child exit 7",
    "the default terminate aborts: signal 6",
    "4 threads with a mutex: total 1000",
    "exception handed from a thread through a promise: code 9",
    "std::async result 42",
    "condition_variable wait_for timeout 1 after at least 40 ms 1",
    "condition_variable notified before the deadline: 1",
    "thread_local destructors after 3 threads: 3, their plain values 24",
    "std::atomic::wait woken by notify_one: 40",
    "std::latch released 3 threads",
    "std::barrier 5 rounds of 3 threads: 15",
    "counting_semaphore acquired 1 1, a third timed out 1",
    "ok",
    "static destructor third, a local static (constructed 3)",
    "main thread_local destructor ran",
    "atexit handler two",
    "static destructor function static (constructed 4)",
    "atexit handler one",
    "static destructor second (constructed 2)",
    "static destructor first (constructed 1)",
    "the program ended with status 0",
];

/// What is wrong with the lines of a run, or `Ok`: a check that failed
/// names itself, and every other difference names the first line that
/// differs from the expected sequence.
pub fn verdict(lines: &[String]) -> Result<(), String> {
    if let Some(failed) = lines
        .iter()
        .find(|l| l.starts_with("cxx-probe: check failed"))
    {
        return Err(failed.clone());
    }
    let seen: Vec<&str> = lines
        .iter()
        .filter_map(|l| l.strip_prefix(PREFIX))
        .collect();
    for (at, expected) in LINES.iter().enumerate() {
        match seen.get(at) {
            Some(line) if line == expected => {}
            Some(line) => {
                return Err(format!(
                    "line {} of the probe is {line:?}, {expected:?} expected",
                    at + 1
                ));
            }
            None => return Err(format!("the probe stopped before {expected:?}")),
        }
    }
    if let Some(extra) = seen.get(LINES.len()) {
        return Err(format!("the probe printed {extra:?} after its last line"));
    }
    if !lines.iter().any(|l| l == ENDED) {
        return Err(format!("init never printed {ENDED:?}"));
    }
    Ok(())
}

/// The types of the program headers of the ELF file `bytes` (64 bits, little endian).
fn program_header_types(bytes: &[u8]) -> Result<Vec<u32>, String> {
    let short = || "the file is no ELF program".to_owned();
    if bytes.get(..4) != Some(b"\x7fELF") || bytes.get(4) != Some(&2) {
        return Err(short());
    }
    let word = |at: usize, len: usize| -> Result<u64, String> {
        let field = bytes.get(at..at + len).ok_or_else(short)?;
        Ok(field.iter().rev().fold(0, |n, b| n << 8 | u64::from(*b)))
    };
    let (offset, size, count) = (word(32, 8)?, word(54, 2)?, word(56, 2)?);
    (0..count)
        .map(|i| word((offset + i * size) as usize, 4).map(|t| t as u32))
        .collect()
}

/// The program header of the exception tables (`PT_GNU_EH_FRAME`): libunwind
/// finds the unwind rows of a static program through it.
const PT_GNU_EH_FRAME: u32 = 0x6474_e550;

/// Fails when the program is linked without the header of its unwind tables:
/// every exception would end the program.
pub fn require_eh_frame_header(bytes: &[u8]) -> Result<(), String> {
    if program_header_types(bytes)?.contains(&PT_GNU_EH_FRAME) {
        Ok(())
    } else {
        Err("cxx-probe has no PT_GNU_EH_FRAME header: its exceptions cannot unwind".to_owned())
    }
}

/// `cargo xtask cxx-probe`.
pub fn probe(machine: &qemu::Machine) -> Result<(), String> {
    crate::libcxx()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-cxx-probe.img", &PROGRAMS, BOOT_PROFILE)?;
    let elf = crate::cargo_output(
        &crate::target_dir(),
        crate::PROGRAM_TARGET,
        BOOT_PROFILE,
        "cxx-probe",
    );
    require_eh_frame_header(&std::fs::read(&elf).map_err(|e| format!("{}: {e}", elf.display()))?)?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    // Stops on any end of the probe, so that a failure shows at once.
    let output = run_until(cmd, TIMEOUT, Some("init: cxx-probe ended"), &kernel.elf)?;
    verdict(&output.lines).map_err(|e| format!("cxx-probe on {}: {e}", machine.name))?;
    println!(
        "cxx-probe on {}: exceptions through five frames, a C frame and a signal handler, RTTI, threads, thread_local destructors, waits by address, iostreams, locales, static constructors and terminate: ok",
        machine.name
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run() -> Vec<String> {
        let mut lines: Vec<String> = LINES.iter().map(|l| format!("{PREFIX}{l}")).collect();
        lines.insert(3, "libc++abi: a line of another prefix".to_owned());
        lines.push(ENDED.to_owned());
        lines
    }

    #[test]
    fn the_expected_run_passes() {
        assert_eq!(verdict(&run()), Ok(()));
    }

    #[test]
    fn a_failed_check_names_itself() {
        let mut lines = run();
        lines.insert(
            5,
            "cxx-probe: check failed at line 9: x == 1 (errno 0)".to_owned(),
        );
        assert!(verdict(&lines).unwrap_err().contains("check failed"));
    }

    #[test]
    fn a_missing_line_a_changed_value_and_an_extra_line_are_refused() {
        let mut lines = run();
        let at = lines
            .iter()
            .position(|l| l.contains("exception through qsort_r"))
            .unwrap();
        lines.remove(at);
        assert!(verdict(&lines).unwrap_err().contains("qsort_r"));
        let mut lines = run();
        let at = lines
            .iter()
            .position(|l| l.contains("main thread_local destructor"))
            .unwrap();
        lines[at] = "cxx-probe: main thread_local destructor ran twice".to_owned();
        assert!(verdict(&lines).unwrap_err().contains("expected"));
        let mut lines = run();
        let end = lines.len() - 1;
        lines.insert(end, "cxx-probe: one more".to_owned());
        assert!(verdict(&lines).unwrap_err().contains("after its last line"));
    }

    #[test]
    fn the_order_of_the_destructors_at_exit_is_checked() {
        let mut lines = run();
        let first = lines
            .iter()
            .position(|l| l.contains("static destructor second"))
            .unwrap();
        lines.swap(first, first + 1);
        assert!(verdict(&lines).unwrap_err().contains("expected"));
    }

    #[test]
    fn a_run_that_init_never_ended_is_refused() {
        let mut lines = run();
        lines.pop();
        assert!(verdict(&lines).unwrap_err().contains("init never printed"));
    }

    /// An ELF header of 64 bits with the given types of program headers.
    fn elf_with(types: &[u32]) -> Vec<u8> {
        let mut bytes = vec![0u8; 64 + 56 * types.len()];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&(types.len() as u16).to_le_bytes());
        for (i, t) in types.iter().enumerate() {
            let at = 64 + 56 * i;
            bytes[at..at + 4].copy_from_slice(&t.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn a_program_without_the_eh_frame_header_is_refused() {
        assert_eq!(
            require_eh_frame_header(&elf_with(&[1, PT_GNU_EH_FRAME, 7])),
            Ok(())
        );
        assert!(
            require_eh_frame_header(&elf_with(&[1, 7]))
                .unwrap_err()
                .contains("PT_GNU_EH_FRAME")
        );
        assert!(require_eh_frame_header(b"not an elf file at all").is_err());
    }
}
