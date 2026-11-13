// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The firmware's sources of random bytes, read before ExitBootServices for
//! `/chosen/rng-seed` (stafeto-design tasks/2026-11-13-entropy-trust.md):
//! `EFI_RNG_PROTOCOL`, the Arm SMCCC TRNG (DEN0098) through the PSCI conduit
//! of the FADT, and the `RNDR` register when `ID_AA64ISAR0_EL1.RNDR` says
//! the CPU has it. Whatever is found is mixed by `firmware_tree::seed::mix`.
//! Nothing here prints or keeps a byte: the caller names the sources.

use alloc::vec::Vec;
use core::arch::asm;
use firmware_tree::seed;
use uefi::boot;
use uefi::proto::rng::Rng;

/// `EFI_RNG_PROTOCOL.GetRNG`, the default algorithm, 64 bytes. None when no
/// handle has the protocol or the call fails.
fn efi_rng() -> Option<Vec<u8>> {
    let handle = boot::get_handle_for_protocol::<Rng>().ok()?;
    let mut rng = boot::open_protocol_exclusive::<Rng>(handle).ok()?;
    let mut bytes = alloc::vec![0u8; seed::SEED_BYTES];
    rng.get_rng(None, &mut bytes).ok()?;
    Some(bytes)
}

/// SMCCC function numbers of the TRNG interface (Arm DEN0098 1.0, 2.1).
const TRNG_VERSION: u64 = 0x8400_0050;
const TRNG_RND64: u64 = 0xC400_0053;
/// The bits one TRNG_RND64 gives at most: x1 to x3.
const TRNG_BITS: u64 = 192;
/// TRNG_RND64 calls at most: NO_ENTROPY (-3) comes and goes.
const TRNG_CALLS: usize = 8;
/// The calls that make the 72 bytes of three full answers.
const TRNG_WANTED: usize = 3;

/// An SMCCC call through the conduit (1 HVC, 2 SMC): x0 to x3 back. The
/// loader runs at EL1 under the firmware, where HVC is the call to the
/// hypervisor; at EL2 PSCI goes through SMC and the FADT says so.
fn call(conduit: u8, function: u64, x1: u64) -> Option<[u64; 4]> {
    let (mut x0, mut x1, mut x2, mut x3) = (function, x1, 0u64, 0u64);
    // SAFETY: an SMCCC call takes x0 to x3 and may clobber x4 to x17, which
    // `clobber_abi` names; it touches no memory of the loader.
    unsafe {
        match conduit {
            1 => asm!(
                "hvc #0",
                inout("x0") x0, inout("x1") x1, inout("x2") x2, inout("x3") x3,
                clobber_abi("C"),
                options(nostack)
            ),
            2 => asm!(
                "smc #0",
                inout("x0") x0, inout("x1") x1, inout("x2") x2, inout("x3") x3,
                clobber_abi("C"),
                options(nostack)
            ),
            _ => return None,
        }
    }
    Some([x0, x1, x2, x3])
}

/// The SMCCC TRNG: TRNG_VERSION first (a negative answer, NOT_SUPPORTED,
/// says there is none), then TRNG_RND64 for 192 bits, up to TRNG_CALLS
/// times, until TRNG_WANTED answers came. The bytes of the answers that
/// came, if any.
fn trng(conduit: u8) -> Option<Vec<u8>> {
    let version = call(conduit, TRNG_VERSION, 0)?;
    if (version[0] as u32 as i32) < 0 {
        return None;
    }
    let mut bytes = Vec::new();
    let mut answers = 0;
    for _ in 0..TRNG_CALLS {
        let Some(r) = call(conduit, TRNG_RND64, TRNG_BITS) else {
            break;
        };
        // x0 is 0 for success, negative for NOT_SUPPORTED, INVALID_PARAMETERS
        // and NO_ENTROPY.
        if r[0] != 0 {
            continue;
        }
        for word in &r[1..] {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        answers += 1;
        if answers == TRNG_WANTED {
            break;
        }
    }
    (!bytes.is_empty()).then_some(bytes)
}

/// `ID_AA64ISAR0_EL1.RNDR` (bits 63:60) is not zero.
fn has_rndr() -> bool {
    let isar0: u64;
    // SAFETY: a read of an ID register at EL1.
    unsafe { asm!("mrs {}, id_aa64isar0_el1", out(reg) isar0, options(nomem, nostack)) };
    (isar0 >> 60) & 0xf != 0
}

/// `RNDR`: 64 bytes in words, each tried a few times (the register fails
/// with Z set when the generator has none ready), when the CPU has it.
fn rndr() -> Option<Vec<u8>> {
    if !has_rndr() {
        return None;
    }
    let mut bytes = Vec::new();
    for _ in 0..seed::SEED_BYTES / 8 {
        let mut word = None;
        for _ in 0..16 {
            let (value, failed): (u64, u64);
            // SAFETY: RNDR is S3_3_C2_C4_0; it sets NZCV to 0b0100 when it
            // gave no number, and the flags are read at once.
            unsafe {
                asm!(
                    "mrs {value}, s3_3_c2_c4_0",
                    "cset {failed}, eq",
                    value = out(reg) value,
                    failed = out(reg) failed,
                    options(nomem, nostack)
                )
            };
            if failed == 0 {
                word = Some(value);
                break;
            }
        }
        bytes.extend_from_slice(&word?.to_le_bytes());
    }
    Some(bytes)
}

/// What the sources gave: the seed (64 bytes, None when no source counted)
/// and the names of the sources that counted, in the order they were read.
pub struct Found {
    pub seed: Option<[u8; seed::SEED_BYTES]>,
    pub sources: Vec<&'static str>,
}

/// Reads every source (the conduit is the FADT's: 0 none, 1 HVC, 2 SMC) and
/// mixes the ones that count. The bytes of each source are erased once mixed.
pub fn collect(conduit: u8) -> Found {
    let mut gathered: Vec<(&'static str, Vec<u8>)> = Vec::new();
    if let Some(bytes) = efi_rng() {
        gathered.push(("efi-rng", bytes));
    }
    if let Some(bytes) = trng(conduit) {
        gathered.push(("smccc-trng", bytes));
    }
    if let Some(bytes) = rndr() {
        gathered.push(("rndr", bytes));
    }
    let mut sources = Vec::new();
    let mut counted: Vec<&[u8]> = Vec::new();
    for (name, bytes) in &gathered {
        if seed::counts(bytes) {
            sources.push(*name);
            counted.push(bytes);
        }
    }
    let seed = seed::mix(&counted);
    for (_, bytes) in gathered.iter_mut() {
        posix_random::erase(bytes);
    }
    Found { seed, sources }
}
