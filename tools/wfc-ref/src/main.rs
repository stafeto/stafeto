// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Writes the CRCs of the frames of scenes A and B to `target/wfc/ref.txt`
//! (and to the standard output), the host's answer that `cargo xtask
//! wfc-probe` compares the guest's screen with.

fn main() {
    let [a, b] = wfc_ref::crcs();
    let text = format!("scene A crc {a:08x}\nscene B crc {b:08x}\n");
    print!("{text}");
    if std::fs::create_dir_all("target/wfc").is_ok() {
        let _ = std::fs::write("target/wfc/ref.txt", &text);
    }
}
