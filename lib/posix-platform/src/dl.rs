// SPDX-License-Identifier: GPL-3.0-or-later WITH GCC-exception-3.1
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! `dlsym` of the global scope (spec 2, 3.12.5). relibc's `dlsym` hands the
//! program headers of the program and the address of libc.so (the loader's
//! auxiliary vector gives both) to `stafeto_dlsym`, which searches the
//! defined symbols of the program and then those of libc.so with
//! `dynlink::lookup`. relibc's own dynamic linker is not involved: it reads
//! `LD_LIBRARY_PATH` and `LD_BIND_NOW`, which a set-ID program must not
//! obey, and there is no state here to lock.

use core::ffi::c_char;
use dynlink::{Fault, Memory, NAME_MAX, PHDR_SIZE, Role};

/// The memory of this process: the modules are mapped and linked, and the
/// reads lie in their segments (`dynlink` checks that before it asks).
struct Own;

impl Memory for Own {
    fn read(&self, address: u64, out: &mut [u8]) -> Result<(), Fault> {
        // SAFETY: see Own.
        unsafe {
            core::ptr::copy_nonoverlapping(address as *const u8, out.as_mut_ptr(), out.len())
        };
        Ok(())
    }

    fn write(&mut self, _: u64, _: &[u8]) -> Result<(), Fault> {
        Err(Fault)
    }
}

const STT_TLS: u8 = 6;

/// The address of the defined symbol `name` in the module whose program
/// headers are `phnum` records at `phdr`.
fn find(role: Role, phdr: usize, phnum: usize, name: &[u8]) -> Option<usize> {
    if phdr == 0 || phnum == 0 || phnum > 64 {
        return None;
    }
    // SAFETY: the headers of a module the loader mapped.
    let headers = unsafe { core::slice::from_raw_parts(phdr as *const u8, phnum * PHDR_SIZE) };
    let module = dynlink::module(role, headers, 0, &Own).ok()?;
    let symbol = dynlink::lookup(&module, &Own, name).ok()??;
    if symbol.kind == STT_TLS {
        return None;
    }
    symbol.address(module.bias).ok().map(|a| a as usize)
}

/// The address of `name` in the global scope: the program, then libc.so; 0
/// for none. `phdr` and `phnum` are the program's headers (`AT_PHDR`,
/// `AT_PHNUM`), `base` is the ELF header of libc.so (`AT_BASE`, 0 for a
/// static program, which has no table to search).
///
/// # Safety
/// `name` is a NUL-terminated string; `phdr`, `phnum` and `base` come from the
/// loader's vector.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn stafeto_dlsym(
    name: *const c_char,
    phdr: usize,
    phnum: usize,
    base: usize,
) -> usize {
    if base == 0 || name.is_null() {
        return 0;
    }
    let mut length = 0;
    // SAFETY: the caller's string; the walk stops one byte past the longest
    // name `dynlink` accepts.
    while length <= NAME_MAX && unsafe { *name.add(length) } != 0 {
        length += 1;
    }
    if length > NAME_MAX {
        return 0;
    }
    // SAFETY: as above.
    let name = unsafe { core::slice::from_raw_parts(name.cast::<u8>(), length) };
    if let Some(found) = find(Role::Program, phdr, phnum, name) {
        return found;
    }
    // SAFETY: libc.so's ELF header: e_phoff at 32, e_phnum at 56.
    let (off, num) = unsafe {
        let header = base as *const u8;
        (
            header.add(32).cast::<u64>().read_unaligned() as usize,
            header.add(56).cast::<u16>().read_unaligned() as usize,
        )
    };
    find(Role::Library, base.wrapping_add(off), num, name).unwrap_or(0)
}
