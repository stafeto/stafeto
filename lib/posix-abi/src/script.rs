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

use crate::constants::{ENOENT, O_CLOEXEC, O_RDONLY};

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

/// The script at `path` (an absolute path of a layer of the user, `abs` for the layer service),
/// when the caller may execute it and it starts with `#!`. EACCES for a file that is no script or
/// that the caller may not execute, the errno of the open and the read otherwise.
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
    let line = parse(&head[..length]).ok_or(crate::constants::EACCES)?;
    // A name the layers made vanish between the check and the open is not found.
    if line.interpreter(&head[..length]).is_empty() {
        return Err(ENOENT);
    }
    Ok(Script { head, length, line })
}
