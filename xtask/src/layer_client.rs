// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The mark of the layer client in the programs of a layered image. Every POSIX program of an image
//! whose table has the layer service must send the paths of the root to it: the feature `layer` of
//! `posix-crt` (`tools/layer-features.txt`) puts the symbol `stafeto_layer_client` into a static
//! program and into `libc.so`, which the dynamic programs share. A program built without the feature
//! would serve the root from the file service alone, and its writes would meet the guard of that
//! service. `llvm-nm` reads the symbol in each program before it is put in the image.

use std::path::Path;
use std::process::Command;

/// The symbol `posix_abi::layer` defines.
pub const SYMBOL: &str = "stafeto_layer_client";

/// Whether the output of `llvm-nm` lists `SYMBOL` as defined (a line `<address> <kind> <name>` whose
/// kind is not `U`).
pub fn lists(nm: &str) -> bool {
    nm.lines().any(|line| {
        let mut words = line.split_whitespace();
        matches!(
            (words.next(), words.next(), words.next(), words.next()),
            (Some(_), Some(kind), Some(SYMBOL), None) if kind != "U" && kind != "u"
        )
    })
}

/// `path` defines the symbol: in its symbol table when it is a static program, in its dynamic one
/// (`libc.so`) when `dynamic`.
pub fn check(path: &Path, dynamic: bool) -> Result<(), String> {
    let mut cmd = Command::new(crate::llvm_tool("llvm-nm")?);
    cmd.arg("--defined-only");
    if dynamic {
        cmd.arg("-D");
    }
    let output = cmd
        .arg(path)
        .output()
        .map_err(|e| format!("llvm-nm: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "llvm-nm {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    if lists(&String::from_utf8_lossy(&output.stdout)) {
        return Ok(());
    }
    Err(format!(
        "{}: no {SYMBOL}: the program is built without the feature `layer` of posix-crt, in an image that has the layer service",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The symbol is found as a defined one in any section, and an undefined reference, a longer
    /// name and a name that only contains it are not the mark. (The planted fault: `lists` true for
    /// every output.)
    #[test]
    fn the_mark_is_a_defined_symbol_of_that_name() {
        assert!(lists("0000000000210a08 D stafeto_layer_client\n"));
        assert!(lists(
            "0000000000211000 r stafeto_layer_client\n0000 T main\n"
        ));
        assert!(lists("0000000000210a08 B stafeto_layer_client"));
        assert!(!lists("                 U stafeto_layer_client\n"));
        assert!(!lists("0000000000210a08 D stafeto_layer_client_more\n"));
        assert!(!lists("0000000000210a08 D not_stafeto_layer_client\n"));
        assert!(!lists(""));
        assert!(!lists("0000000000210a08 T main\n"));
    }
}
