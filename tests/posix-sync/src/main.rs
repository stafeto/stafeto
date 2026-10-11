// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

#![no_std]
#![no_main]

#[used]
static CRT: extern "C" fn(u64) -> u64 = posix_crt::crt_main;

unsafe extern "C" {
    fn sync_at_full_pool(file: i32, directory: i32) -> i32;
}

// Each nested callback runs outside the descriptor lock. Sixteen real
// pipes retain both distinct endpoints after their local descriptors close.
#[inline(never)]
fn fill_pairs(remaining: u32, file: i32, directory: i32) -> Result<(), i32> {
    if remaining == 0 {
        // SAFETY: the C checker calls public synchronization on live descriptors.
        let result = unsafe { sync_at_full_pool(file, directory) };
        return if result == 0 { Ok(()) } else { Err(-result) };
    }
    let ends = posix_abi::pipe2(0)?;
    let result = posix_abi::shared::held(ends[0] as u32, |_, _| {
        posix_abi::close(ends[0])?;
        posix_abi::shared::held(ends[1] as u32, |_, _| {
            posix_abi::close(ends[1])?;
            fill_pairs(remaining - 1, file, directory)
        })
    });
    // Failure cleanup may encounter already closed local endpoints.
    let _ = posix_abi::close(ends[0]);
    let _ = posix_abi::close(ends[1]);
    result
}

/// Fill the actual ordinary I/O pool with32 distinct retained pipe endpoints.
#[unsafe(no_mangle)]
pub extern "C" fn sync_full_io(file: i32, directory: i32) -> i32 {
    fill_pairs(16, file, directory).map_or_else(|errno| -errno, |()| 0)
}
