// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Scripts of a layer of the user. The loader runs ELF programs of the lower set and nothing else
//! (a script of the lower set is ENOEXEC, which a shell answers by running it itself), and no
//! program runs from a layer of the user (`layer::check_exec`). A script that starts with `#!` in a
//! layer of the user does run: this layer reads the line through the layered root, checks the right
//! to execute the file, and runs the interpreter with the arguments the line gives, then the path
//! of the script, then the program's own arguments (the Linux rule, one optional argument).
//!
//! The interpreter's path goes where every program's does: through `layer::check_exec`, so an
//! interpreter that the layers delete is ENOENT, one that lies in a layer of the user is EACCES (an
//! interpreter that is itself a script is ENOEXEC from the loader: one level only), and a lower one
//! is opened by the loader at its canonical path. The loader takes `libc.so` and the other
//! libraries of a dynamic program from the lower set alone, whatever the layers hold.

use crate::constants::{O_CLOEXEC, O_RDONLY};

pub use posix_fs::script::{HEAD, Line, parse};

/// The script a program of a layer of the user is: its head and the line in it.
pub struct Script {
    head: [u8; HEAD],
    length: usize,
    line: Line,
}

impl Script {
    pub fn interpreter(&self) -> &[u8] {
        self.line.interpreter(&self.head[..self.length])
    }

    pub fn argument(&self) -> Option<&[u8]> {
        self.line.argument(&self.head[..self.length])
    }
}

/// The script at `abs` (a name of a layer of the user), when the caller may execute it and it starts
/// with `#!`. EACCES for a file the caller may not execute and for an ELF file (no program runs
/// from a layer of the user); ENOEXEC for any other file with the execute bit that is no script
/// (a shell's fallback then runs it), and for a line that has no interpreter or a cut one; the
/// errno of the layer, the open and the read otherwise (EINTR and EIO stay what they are).
pub fn read(abs: &crate::layer::Abs) -> Result<Script, i32> {
    crate::layer::may_run_script(abs)?;
    let fd = crate::open(abs.bytes(), O_RDONLY | O_CLOEXEC)?;
    let mut head = [0u8; HEAD];
    let mut length = 0;
    let got = loop {
        match crate::read(fd, &mut head[length..]) {
            Ok(0) => break Ok(()),
            Ok(n) => {
                length += n;
                if length == HEAD || head[..length].contains(&b'\n') {
                    break Ok(());
                }
            }
            Err(errno) => break Err(errno),
        }
    };
    let _ = crate::close(fd);
    got?;
    if head[..length].starts_with(b"\x7fELF") {
        return Err(crate::constants::EACCES);
    }
    let line = parse(&head[..length]).ok_or(crate::constants::ENOEXEC)?;
    Ok(Script { head, length, line })
}
