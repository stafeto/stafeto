// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The output of xtask. A thread that runs a job (jobs.rs) keeps what it
//! prints and the output of the commands it runs in a buffer, which the
//! job's end hands over whole; every other thread writes to the terminal
//! as the macros of std do. The macros below take the place of std's
//! `print`, `println`, `eprint` and `eprintln` in every module.

use std::cell::{Cell, RefCell};
use std::io::Write;

thread_local! {
    static BUFFER: RefCell<Option<String>> = const { RefCell::new(None) };
    static ORDER: Cell<usize> = const { Cell::new(0) };
}

/// Writes `text` to the buffer of this thread when it has one, else to
/// stdout (`error` false) or stderr.
pub fn write(text: &str, error: bool) {
    let kept = BUFFER.with(|buffer| match buffer.borrow_mut().as_mut() {
        Some(buffer) => {
            buffer.push_str(text);
            true
        }
        None => false,
    });
    if !kept {
        // A closed terminal is no reason to stop a run.
        if error {
            let _ = std::io::stderr().write_all(text.as_bytes());
        } else {
            let _ = std::io::stdout().write_all(text.as_bytes());
        }
    }
}

/// Whether this thread keeps its output.
pub fn capturing() -> bool {
    BUFFER.with(|buffer| buffer.borrow().is_some())
}

/// The place of the job this thread runs among the jobs of its run; 0
/// outside a job. Measurements are kept in this order (measure.rs).
pub fn order() -> usize {
    ORDER.with(Cell::get)
}

/// Runs `f` as the job number `order`, keeping its output: the result of
/// `f` and the output.
pub fn capture<T>(order: usize, f: impl FnOnce() -> T) -> (T, String) {
    BUFFER.with(|buffer| *buffer.borrow_mut() = Some(String::new()));
    ORDER.with(|o| o.set(order));
    let result = f();
    ORDER.with(|o| o.set(0));
    let text = BUFFER.with(|buffer| buffer.borrow_mut().take().unwrap_or_default());
    (result, text)
}

macro_rules! print {
    ($($arg:tt)*) => { $crate::out::write(&format!($($arg)*), false) };
}

macro_rules! println {
    () => { $crate::out::write("\n", false) };
    ($($arg:tt)*) => { $crate::out::write(&format!("{}\n", format_args!($($arg)*)), false) };
}

macro_rules! eprintln {
    () => { $crate::out::write("\n", true) };
    ($($arg:tt)*) => { $crate::out::write(&format!("{}\n", format_args!($($arg)*)), true) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_job_keeps_its_output_and_its_place() {
        assert!(!capturing());
        let (answer, text) = capture(3, || {
            println!("line {}", 1);
            print!("part");
            eprintln!("; error");
            assert_eq!(order(), 3);
            7
        });
        assert_eq!(answer, 7);
        assert_eq!(text, "line 1\npart; error\n");
        assert!(!capturing());
        assert_eq!(order(), 0);
    }
}
