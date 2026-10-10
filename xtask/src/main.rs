// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Build, run and test stafeto. Usage: `cargo xtask <command>`.

#[macro_use]
mod out;

#[cfg(test)]
mod change_release_reply_tests;
mod coverage;
#[cfg(test)]
#[path = "../../tests/posix-threads/src/futex_deadline.rs"]
mod futex_deadline;
#[cfg(test)]
#[path = "../../tests/posix-threads/src/futex_watchdog.rs"]
mod futex_watchdog;
#[cfg(test)]
mod lock_driver_tests;
#[cfg(test)]
mod lock_fields_tests;
#[cfg(test)]
#[path = "../../lib/posix-abi/src/relibc/lifetime.rs"]
mod owner_lifetime;

mod disasm;
mod entropy;
mod image;
mod jobs;
mod measure;
mod native_scopes;
mod ostest;
mod qemu;
mod ring;
mod rootfs;
mod rtbench;
mod rtbench2;
mod rtbench_check;
mod stubs;
mod symbolize;
mod vz;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio, exit};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

const KERNEL_TARGET: &str = "aarch64-unknown-none-softfloat";
/// Spec 14: programs, which run at EL0, are built for this target.
const PROGRAM_TARGET: &str = "aarch64-unknown-none";
/// The stack of init's first thread, in bytes, which init's program asks
/// the kernel for (lib/bootimg); the size is ours.
const INIT_STACK_SIZE: u32 = 64 * 1024;
/// The stack of a child of the test init (tests/child), which its loader
/// maps (rt::loader).
const CHILD_STACK_SIZE: u32 = 16 * 1024;
/// The main stack of a POSIX program: its requests on its files run on its
/// own stack, under the lock of the layer, with no file worker.
const POSIX_STACK_SIZE: u32 = 64 * 1024;
/// The stack of a test service (tests/svc), which init's loader maps.
const SVC_STACK_SIZE: u32 = 16 * 1024;
/// The stack of the RAM file service: its start reads the table of the boot
/// image (services/ramfs/src/tree.rs) on top of the start data, and its
/// loop holds the table of its sessions.
const RAMFS_STACK_SIZE: u32 = 48 * 1024;
/// The pipe service's stack: its state (the pipes, the long operations,
/// the clones) lies in its `.bss`, and a request copies up to 1 KiB.
const PIPE_STACK_SIZE: u32 = 32 * 1024;
/// The stacks of the UART driver (services/uart) and of the shell
/// (apps/shell), which init's loader maps.
const UART_STACK_SIZE: u32 = 16 * 1024;
const SHELL_STACK_SIZE: u32 = 16 * 1024;
/// The terminal service's stack: its state lies in its `.bss`, and a
/// request copies up to 1 KiB.
const TTY_STACK_SIZE: u32 = 32 * 1024;
/// A program of a boot image: its file's name in the image, the package
/// that builds it for EL0, the size of its stack and the features of the
/// package it builds with.
type ImageProgram = (&'static str, &'static str, u32, &'static [&'static str]);
/// The programs of the boot image of the normal build, of the test init's
/// runs, of the runs of init's test table and of the two tables init
/// refuses (spec 15.2). Init comes first (spec 13.1). The driver of the
/// image that ships has the method CRASH in subproject 1 (spec 13.5).
const BOOT_PROGRAMS: [ImageProgram; 3] = [
    ("init", "init", INIT_STACK_SIZE, &[]),
    ("uart", "uart", UART_STACK_SIZE, &["crash"]),
    ("shell", "shell", SHELL_STACK_SIZE, &[]),
];
/// The boot image of Apple VZ: init with its VZ table, the driver of the
/// Virtio console with CRASH, as the image that ships on QEMU, and the shell.
const VZ_PROGRAMS: [ImageProgram; 3] = [
    ("init", "init", INIT_STACK_SIZE, &["vz"]),
    (
        "virtio-console",
        "virtio-console",
        UART_STACK_SIZE,
        &["crash"],
    ),
    ("shell", "shell", SHELL_STACK_SIZE, &[]),
];
const RTBENCH_PROGRAMS: [ImageProgram; 1] = [("init", "rtbench", INIT_STACK_SIZE, &[])];
/// rtbench 2 (rtbench2.rs): the POSIX benchmark with the RAM files, the
/// process and clock services, the service of long operations (`svc`,
/// role `l`, under the name `uart`), the load, and the PL011's driver for
/// the console; the loader, which starts the benchmark's children from the
/// files of the image (5c); the pipe service and BusyBox, whose `ls` and
/// `cat` are the stages of S22 (5e).
const RTBENCH_POSIX_PROGRAMS: [ImageProgram; 14] = [
    ("init", "init", INIT_STACK_SIZE, &["table-rtbench-posix"]),
    ("uart", "uart", UART_STACK_SIZE, &[]),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &[]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &[],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    ("svc", "test-svc", SVC_STACK_SIZE, &[]),
    ("tty", "tty", 32 * 1024, &[]),
    ("rtbench-load", "rtbench-load", CHILD_STACK_SIZE, &[]),
    ("rtbench-posix", "rtbench-posix", 64 * 1024, &[]),
    ("loader", "loader", 0, &[]),
    ("pipe", "pipe", PIPE_STACK_SIZE, &[]),
    ("busybox-probe", "busybox-probe", 0, &["applets"]),
    ("virtio-rng", "virtio-rng", entropy::RNG_STACK_SIZE, &[]),
    ("entropy", "entropy", entropy::ENTROPY_STACK_SIZE, &[]),
];
/// rtbench 2 on Apple VZ: the Virtio console's driver for the console.
const RTBENCH_POSIX_VZ_PROGRAMS: [ImageProgram; 14] = [
    ("init", "init", INIT_STACK_SIZE, &["table-rtbench-posix-vz"]),
    ("virtio-console", "virtio-console", UART_STACK_SIZE, &[]),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &[]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &[],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    ("svc", "test-svc", SVC_STACK_SIZE, &[]),
    ("tty", "tty", 32 * 1024, &[]),
    ("rtbench-load", "rtbench-load", CHILD_STACK_SIZE, &[]),
    ("rtbench-posix", "rtbench-posix", 64 * 1024, &[]),
    ("loader", "loader", 0, &[]),
    ("pipe", "pipe", PIPE_STACK_SIZE, &[]),
    ("busybox-probe", "busybox-probe", 0, &["applets"]),
    ("virtio-rng", "virtio-rng", entropy::RNG_STACK_SIZE, &[]),
    ("entropy", "entropy", entropy::ENTROPY_STACK_SIZE, &[]),
];
const EXT4RO_PROGRAMS: [ImageProgram; 1] = [("init", "ext4ro-probe", INIT_STACK_SIZE, &[])];
const RAMFS_PROGRAMS: [ImageProgram; 3] = [
    ("init", "init", INIT_STACK_SIZE, &["table-ramfs"]),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &[]),
    ("ramfs-probe", "ramfs-probe", CHILD_STACK_SIZE, &[]),
];
const POSIX_FILES_PROGRAMS: [ImageProgram; 5] = [
    ("init", "init", INIT_STACK_SIZE, &["table-posix-files"]),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &[]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &[],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    (
        "posix-files",
        "posix-procs",
        POSIX_STACK_SIZE,
        &["files", "names-loss"],
    ),
];
const LOADER_ABORT_PROGRAMS: [ImageProgram; 6] = [
    (
        "init",
        "init",
        INIT_STACK_SIZE,
        &["table-posix-files", "loader-abort"],
    ),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &["auth-probe"]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &[],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    (
        "posix-files",
        "posix-procs",
        POSIX_STACK_SIZE,
        &["loader-abort"],
    ),
    ("loader", "loader", 0, &["auth-probe"]),
];
const IMAGE_GATES_PROGRAMS: [ImageProgram; 6] = [
    (
        "init",
        "init",
        INIT_STACK_SIZE,
        &["table-posix-files", "loader-abort"],
    ),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &["image-gates"]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &["image-probe"],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    (
        "posix-files",
        "posix-procs",
        POSIX_STACK_SIZE,
        &["image-gates"],
    ),
    ("loader", "loader", 0, &["image-gates"]),
];
const RAMFS_GC_PROGRAMS: [ImageProgram; 5] = [
    ("init", "init", INIT_STACK_SIZE, &["table-posix-files"]),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &["auth-probe", "steps"]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &[],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    ("posix-files", "ramfs-gc", POSIX_STACK_SIZE, &[]),
];
const RAMFS_CLEANUP_PROGRAMS: [ImageProgram; 7] = [
    (
        "init",
        "init",
        INIT_STACK_SIZE,
        &["table-posix-files", "ramfs-cleanup"],
    ),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &["auth-probe"]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &[],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    (
        "posix-files",
        "posix-procs",
        POSIX_STACK_SIZE,
        &["auth-probe"],
    ),
    ("ramfs-holder", "ramfs-holder", CHILD_STACK_SIZE, &[]),
    ("loader", "loader", 0, &[]),
];
const POSIX_ABI_PROGRAMS: [ImageProgram; 7] = [
    ("init", "init", INIT_STACK_SIZE, &["table-posix-abi"]),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &[]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &[],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    ("posix-clock-peer", "posix-clock-peer", 32 * 1024, &[]),
    ("posix-abi-probe", "posix-abi-probe", POSIX_STACK_SIZE, &[]),
    ("svc", "test-svc", SVC_STACK_SIZE, &[]),
];
/// The POSIX ABI image whose process service ends before it registers:
/// each POSIX process fails its load (`posix_orphans`).
const POSIX_ORPHAN_PROGRAMS: [ImageProgram; 7] = [
    ("init", "init", INIT_STACK_SIZE, &["table-posix-abi"]),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &[]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &["exit-early"],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    ("posix-clock-peer", "posix-clock-peer", 32 * 1024, &[]),
    ("posix-abi-probe", "posix-abi-probe", POSIX_STACK_SIZE, &[]),
    ("svc", "test-svc", SVC_STACK_SIZE, &[]),
];
const POSIX_THREAD_PROGRAMS: [ImageProgram; 7] = [
    ("init", "init", INIT_STACK_SIZE, &["table-posix-abi"]),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &[]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &["adoption-refusals"],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    ("posix-clock-peer", "posix-clock-peer", 32 * 1024, &[]),
    (
        "posix-abi-probe",
        "posix-thread-probe",
        POSIX_STACK_SIZE,
        &[],
    ),
    ("svc", "test-svc", SVC_STACK_SIZE, &[]),
];
const POSIX_CANCEL_INPUT_PROGRAMS: [ImageProgram; 6] = [
    ("init", "init", INIT_STACK_SIZE, &["table-posix-dialog"]),
    ("uart", "uart", UART_STACK_SIZE, &[]),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &[]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &[],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    (
        "posix-probe",
        "posix-thread-probe",
        POSIX_STACK_SIZE,
        &["cancel-input"],
    ),
];
/// The image of console-restart-vz: init watches the old DMA object of
/// the driver that ended (`dma-watch`).
const VZ_WATCH_PROGRAMS: [ImageProgram; 3] = [
    ("init", "init", INIT_STACK_SIZE, &["vz", "dma-watch"]),
    (
        "virtio-console",
        "virtio-console",
        UART_STACK_SIZE,
        &["crash"],
    ),
    ("shell", "shell", SHELL_STACK_SIZE, &[]),
];
/// The image of console-early-exit-vz: the first instance of the driver
/// ends after BAR 1, with decoding off (`exit-before-decoding`).
const VZ_EARLY_PROGRAMS: [ImageProgram; 3] = [
    ("init", "init", INIT_STACK_SIZE, &["vz"]),
    (
        "virtio-console",
        "virtio-console",
        UART_STACK_SIZE,
        &["crash", "exit-before-decoding"],
    ),
    ("shell", "shell", SHELL_STACK_SIZE, &[]),
];
/// rtbench on Apple VZ: a client of init, beside the Virtio console's
/// driver, which shows its lines.
const RTBENCH_VZ_PROGRAMS: [ImageProgram; 3] = [
    ("init", "init", INIT_STACK_SIZE, &["table-rtbench-vz"]),
    ("virtio-console", "virtio-console", UART_STACK_SIZE, &[]),
    ("rtbench", "rtbench", INIT_STACK_SIZE, &[]),
];
/// The POSIX images of Apple VZ: those of QEMU with init's VZ tables and
/// the Virtio console's driver in place of the PL011's.
const POSIX_VZ_CANCEL_INPUT_PROGRAMS: [ImageProgram; 6] = [
    ("init", "init", INIT_STACK_SIZE, &["table-posix-dialog-vz"]),
    ("virtio-console", "virtio-console", UART_STACK_SIZE, &[]),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &[]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &[],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    (
        "posix-probe",
        "posix-thread-probe",
        POSIX_STACK_SIZE,
        &["cancel-input"],
    ),
];
const POSIX_SHARED_PROGRAMS: [ImageProgram; 7] = [
    ("init", "init", INIT_STACK_SIZE, &["table-posix-abi"]),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &[]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &[],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    ("posix-clock-peer", "posix-clock-peer", 32 * 1024, &[]),
    (
        "posix-abi-probe",
        "posix-shared-probe",
        POSIX_STACK_SIZE,
        &[],
    ),
    ("svc", "test-svc", SVC_STACK_SIZE, &[]),
];
const POSIX_TLS_PROGRAMS: [ImageProgram; 1] = [("init", "posix-tls-probe", INIT_STACK_SIZE, &[])];
const POSIX_INPUT_PROGRAMS: [ImageProgram; 6] = [
    ("init", "init", INIT_STACK_SIZE, &["table-posix-dialog"]),
    ("uart", "uart", SVC_STACK_SIZE, &[]),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &[]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &[],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    (
        "posix-probe",
        "posix-shared-probe",
        POSIX_STACK_SIZE,
        &["input-probe"],
    ),
];
const POSIX_VZ_INPUT_PROGRAMS: [ImageProgram; 6] = [
    ("init", "init", INIT_STACK_SIZE, &["table-posix-dialog-vz"]),
    ("virtio-console", "virtio-console", UART_STACK_SIZE, &[]),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &[]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &[],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    (
        "posix-probe",
        "posix-shared-probe",
        POSIX_STACK_SIZE,
        &["input-probe"],
    ),
];
/// The probe of the terminal in C (tests/posix-tty, xtask posix-tty): the
/// console's driver, the terminal service, the RAM files, the pipes, the
/// process and clock services, the loader (the probe forks) and the probe.
const POSIX_TTY_PROGRAMS: [ImageProgram; 10] = [
    ("init", "init", INIT_STACK_SIZE, &["table-posix-tty"]),
    ("uart", "uart", UART_STACK_SIZE, &[]),
    ("tty", "tty", TTY_STACK_SIZE, &["trust-probe"]),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &[]),
    ("pipe", "pipe", PIPE_STACK_SIZE, &[]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &["tty-probe"],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    ("loader", "loader", 0, &[]),
    ("posix-tty", "posix-tty", POSIX_STACK_SIZE, &[]),
    ("posix-tty-suid", "posix-tty", POSIX_STACK_SIZE, &[]),
];
const POSIX_TTY_STEPS_PROGRAMS: [ImageProgram; 10] = {
    let mut programs = POSIX_TTY_PROGRAMS;
    programs[2].3 = &["trust-probe", "steps"];
    programs[5].3 = &["tty-probe", "steps"];
    programs
};
/// Full terminal control steps with sixteen live POSIX clients over a PTY.
const POSIX_TTY_CONTROL_PROGRAMS: [ImageProgram; 10] = {
    let mut programs = POSIX_TTY_STEPS_PROGRAMS;
    programs[2].3 = &["quiet-steps"];
    programs[5].3 = &["tty-probe"];
    programs[8].3 = &["quiet-control"];
    programs[9].3 = &["quiet-control"];
    programs
};
/// The same over the Virtio console's driver on Apple VZ (xtask
/// posix-tty-vz).
const POSIX_TTY_VZ_PROGRAMS: [ImageProgram; 10] = [
    ("init", "init", INIT_STACK_SIZE, &["table-posix-tty-vz"]),
    ("virtio-console", "virtio-console", UART_STACK_SIZE, &[]),
    ("tty", "tty", TTY_STACK_SIZE, &["trust-probe"]),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &[]),
    ("pipe", "pipe", PIPE_STACK_SIZE, &[]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &["tty-probe"],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    ("loader", "loader", 0, &[]),
    ("posix-tty", "posix-tty", POSIX_STACK_SIZE, &[]),
    ("posix-tty-suid", "posix-tty", POSIX_STACK_SIZE, &[]),
];
const POSIX_INTERRUPT_PROGRAMS: [ImageProgram; 6] = [
    ("init", "init", INIT_STACK_SIZE, &["table-posix-dialog"]),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &[]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &[],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    ("uart", "uart", UART_STACK_SIZE, &[]),
    (
        "posix-probe",
        "posix-shared-probe",
        POSIX_STACK_SIZE,
        &["interrupt-probe"],
    ),
];
const POSIX_VZ_INTERRUPT_PROGRAMS: [ImageProgram; 6] = [
    ("init", "init", INIT_STACK_SIZE, &["table-posix-dialog-vz"]),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &[]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &[],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    ("virtio-console", "virtio-console", UART_STACK_SIZE, &[]),
    (
        "posix-probe",
        "posix-shared-probe",
        POSIX_STACK_SIZE,
        &["interrupt-probe"],
    ),
];
const POSIX_VZ_THREAD_PROGRAMS: [ImageProgram; 8] = [
    ("init", "init", INIT_STACK_SIZE, &["table-posix-abi-vz"]),
    ("virtio-console", "virtio-console", UART_STACK_SIZE, &[]),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &[]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &["adoption-refusals"],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    ("posix-clock-peer", "posix-clock-peer", 32 * 1024, &[]),
    (
        "posix-abi-probe",
        "posix-thread-probe",
        POSIX_STACK_SIZE,
        &[],
    ),
    ("svc", "test-svc", SVC_STACK_SIZE, &[]),
];
/// The first C program on relibc (5a′) and the services it needs.
const RELIBC_PROGRAMS: [ImageProgram; 5] = [
    ("init", "init", INIT_STACK_SIZE, &["table-relibc"]),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &[]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &[],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    ("relibc-hello", "relibc-hello", POSIX_STACK_SIZE, &[]),
];
/// The probe of POSIX processes (5b) and the services it needs, the loader
/// and BusyBox with its applets, which the table of files names (5c): the
/// probe's children are files of it.
const POSIX_PROCS_PROGRAMS: [ImageProgram; 10] = [
    ("init", "init", INIT_STACK_SIZE, &["table-posix-procs"]),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &[]),
    ("pipe", "pipe", PIPE_STACK_SIZE, &[]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &[],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    (
        "posix-procs",
        "posix-procs",
        POSIX_STACK_SIZE,
        &["pending-open", "names-probe"],
    ),
    // Pieces of 64 KiB: the probe's forks copy regions past one piece.
    ("loader", "loader", 0, &["small-pieces"]),
    ("busybox-probe", "busybox-probe", 0, &["applets"]),
    ("virtio-rng", "virtio-rng", entropy::RNG_STACK_SIZE, &[]),
    ("entropy", "entropy", entropy::ENTROPY_STACK_SIZE, &[]),
];
/// Lifetime observations exist only in this dedicated image.
const POSIX_LIFETIMES_PROGRAMS: [ImageProgram; 10] = {
    let mut programs = POSIX_PROCS_PROGRAMS;
    programs[1].3 = &["lifetime-probe", "steps"];
    programs[3].3 = &["lifetime-probe"];
    programs[5].3 = &["lifetime-probe"];
    programs
};
const POSIX_LOCK_RING_PROGRAMS: [ImageProgram; 10] = {
    let mut programs = POSIX_LIFETIMES_PROGRAMS;
    programs[0].3 = &["table-posix-lock-ring"];
    programs
};
const POSIX_NAMES_PROGRAMS: [ImageProgram; 10] = {
    let mut programs = POSIX_PROCS_PROGRAMS;
    programs[1].3 = &["signal-probe"];
    programs
};
const POSIX_NATIVE_SCOPE_PROGRAMS: [ImageProgram; 11] = {
    let mut programs = [POSIX_PROCS_PROGRAMS[0]; 11];
    let mut index = 0;
    while index < POSIX_PROCS_PROGRAMS.len() {
        programs[index] = POSIX_PROCS_PROGRAMS[index];
        index += 1;
    }
    programs[5].3 = &["pending-open", "native-scopes-launcher"];
    programs[10] = (
        "posix-thread-probe",
        "posix-thread-probe",
        POSIX_STACK_SIZE,
        &[],
    );
    programs
};

const POSIX_VZ_NATIVE_SCOPE_PROGRAMS: [ImageProgram; 12] = {
    let mut programs = [POSIX_NATIVE_SCOPE_PROGRAMS[0]; 12];
    let mut index = 0;
    while index < POSIX_NATIVE_SCOPE_PROGRAMS.len() {
        programs[index] = POSIX_NATIVE_SCOPE_PROGRAMS[index];
        index += 1;
    }
    programs[0].3 = &["table-posix-native-vz"];
    programs[11] = ("virtio-console", "virtio-console", UART_STACK_SIZE, &[]);
    programs
};

/// The probe of the longest step of the process service (xtask
/// process-steps): the probe in its steps mode, and the process service
/// that prints each new longest step.
const POSIX_STEPS_PROGRAMS: [ImageProgram; 9] = [
    ("init", "init", INIT_STACK_SIZE, &["table-posix-steps"]),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &["steps"]),
    ("pipe", "pipe", PIPE_STACK_SIZE, &["steps"]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &["steps"],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    (
        "posix-procs",
        "posix-procs",
        POSIX_STACK_SIZE,
        &["change-steps"],
    ),
    ("loader", "loader", 0, &["steps"]),
    ("virtio-rng", "virtio-rng", 32 * 1024, &["steps"]),
    ("entropy", "entropy", 32 * 1024, &["steps"]),
];
/// The threads of relibc (5a′) and the services they need.
const RELIBC_THREADS_PROGRAMS: [ImageProgram; 5] = [
    ("init", "init", INIT_STACK_SIZE, &["table-relibc-threads"]),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &[]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &[],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    ("relibc-threads", "relibc-threads", POSIX_STACK_SIZE, &[]),
];
const BUSYBOX_PROGRAMS: [ImageProgram; 5] = [
    ("init", "init", INIT_STACK_SIZE, &["table-busybox"]),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &[]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &[],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    ("busybox-probe", "busybox-probe", POSIX_STACK_SIZE, &[]),
];
const ASH_PROGRAMS: [ImageProgram; 5] = [
    ("init", "init", INIT_STACK_SIZE, &["table-busybox"]),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &[]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &[],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    (
        "busybox-probe",
        "busybox-probe",
        POSIX_STACK_SIZE,
        &["ash-probe"],
    ),
];
/// The dialog: BusyBox's launcher mode starts `/bin/ash` from its file
/// through the process service and the loader, the way every child starts
/// (5d); the files of /bin are BusyBox's applets build.
const ASH_INTERACTIVE_PROGRAMS: [ImageProgram; 11] = [
    ("init", "init", INIT_STACK_SIZE, &["table-busybox-dialog"]),
    ("uart", "uart", UART_STACK_SIZE, &[]),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &[]),
    ("pipe", "pipe", PIPE_STACK_SIZE, &[]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &[],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    ("loader", "loader", 0, &[]),
    (
        "busybox-probe",
        "busybox-probe",
        POSIX_STACK_SIZE,
        &["ash-interactive"],
    ),
    ("tty", "tty", TTY_STACK_SIZE, &[]),
    ("virtio-rng", "virtio-rng", entropy::RNG_STACK_SIZE, &[]),
    ("entropy", "entropy", entropy::ENTROPY_STACK_SIZE, &[]),
];
/// The probe of the terminal service (xtask tty): the PL011's driver, the
/// service, which prints each new longest step, and the probe.
const TTY_PROGRAMS: [ImageProgram; 4] = [
    ("init", "init", INIT_STACK_SIZE, &["table-tty"]),
    ("uart", "uart", UART_STACK_SIZE, &[]),
    ("tty", "tty", TTY_STACK_SIZE, &[]),
    ("tty-probe", "tty-probe", SVC_STACK_SIZE, &[]),
];
/// The measure of the service's steps (xtask tty, under -icount): the
/// service prints each new longest step, the probe drives it, and its
/// program is the quiet driver too.
const TTY_STEPS_PROGRAMS: [ImageProgram; 3] = [
    ("init", "init", INIT_STACK_SIZE, &["table-tty-steps"]),
    ("tty", "tty", TTY_STACK_SIZE, &["steps"]),
    // The chain of 255 clones and the replies asked of it need more than
    // the 16 KB of the other probes.
    ("tty-probe", "tty-probe", 2 * SVC_STACK_SIZE, &[]),
];
/// The same over the Virtio console's driver on Apple VZ (xtask tty-vz).
const TTY_VZ_PROGRAMS: [ImageProgram; 4] = [
    ("init", "init", INIT_STACK_SIZE, &["table-tty-vz"]),
    ("virtio-console", "virtio-console", UART_STACK_SIZE, &[]),
    ("tty", "tty", TTY_STACK_SIZE, &[]),
    ("tty-probe", "tty-probe", SVC_STACK_SIZE, &[]),
];
const LS_PROGRAMS: [ImageProgram; 5] = [
    ("init", "init", INIT_STACK_SIZE, &["table-busybox"]),
    ("ramfs", "ramfs", RAMFS_STACK_SIZE, &[]),
    (
        "posix-process-service",
        "posix-process-service",
        64 * 1024,
        &[],
    ),
    ("posix-clock-service", "posix-clock-service", 64 * 1024, &[]),
    (
        "busybox-probe",
        "busybox-probe",
        POSIX_STACK_SIZE,
        &["ls-probe"],
    ),
];
const TEST_PROGRAMS: [ImageProgram; 2] = [
    ("init", "test-init", INIT_STACK_SIZE, &[]),
    ("child", "test-child", CHILD_STACK_SIZE, &[]),
];
const SVC_PROGRAMS: [ImageProgram; 2] = [
    ("init", "init", INIT_STACK_SIZE, &["table-test"]),
    ("svc", "test-svc", SVC_STACK_SIZE, &[]),
];
const CYCLE_PROGRAMS: [ImageProgram; 2] = [
    ("init", "init", INIT_STACK_SIZE, &["table-cycle"]),
    ("svc", "test-svc", SVC_STACK_SIZE, &[]),
];
const CEILING_PROGRAMS: [ImageProgram; 2] = [
    ("init", "init", INIT_STACK_SIZE, &["table-ceiling"]),
    ("svc", "test-svc", SVC_STACK_SIZE, &[]),
];
/// The profiles the programs of those boot images build with (spec 5.4,
/// 15.2): the image that ships with `--release`, the test images with
/// `checked`, the strict build of rt.
const BOOT_PROFILE: Profile = Profile::Release;
const TEST_PROFILE: Profile = Profile::Checked;
/// Spec 3.4: the kernel image file stays under 200 KB: the build that
/// ships and the probes built from it.
const KERNEL_LIMIT: u64 = 200 * 1024;
/// The builds with the kernel tests carry the tests' programs, fixtures
/// and judges besides the kernel, and spec 3.4 does not bound them; a
/// limit of their own still catches a runaway growth.
const TEST_KERNEL_LIMIT: u64 = 512 * 1024;
const BOOT_TIMEOUT: Duration = Duration::from_secs(30);
/// The crowd of the steps probe under -icount, on the host's clock.
const STEPS_TIMEOUT: Duration = Duration::from_secs(600);
const TEST_TIMEOUT: Duration = Duration::from_secs(60);
/// The probe of the departed process in the steps run, on the host's clock
/// (a few seconds when it passes).
const GONE_PROBE_TIMEOUT: Duration = Duration::from_secs(60);
/// The overflow probe's recursive function, as `llvm-nm -C` names it.
const OVERFLOW_PROBE_FN: &str = "kernel::arch::aarch64::probe::recurse";
/// Tests only the `icount` build has, where virtual time counts
/// instructions and a stall of the host changes nothing: the check that the
/// run is under -icount; the measurements of portions, calls, round trips
/// and paths (spec 15.3); the tests that depend on how much of a quantum is
/// left or on where a timer fires, which only -icount makes repeatable;
/// and the teardown of a big process in hundreds of portions with
/// interrupts between them.
const ICOUNT_TESTS: [&str; 17] = [
    "virtual_time_counts_instructions",
    "memory_portions_are_measured",
    "teardown_portions_are_measured",
    "timer_firing_is_measured",
    "lone_round_robin_thread_is_not_switched",
    "preempted_rr_thread_resumes_before_its_peer",
    "fast_path_arms_the_timer",
    "teardown_yields_to_a_pending_interrupt",
    "thread_exit_after_channel_close_is_measured",
    "thread_exit_notice_is_measured",
    "ipc_round_trip_is_measured",
    "long_call_yields_to_a_pending_interrupt",
    "interrupt_path_is_measured",
    "device_windows_are_measured",
    "upcall_calls_are_measured",
    "process_kill_with_a_level_is_measured",
    "suspension_paths_are_measured",
];
/// The rows of the line of `ipc_round_trip_is_measured`, in its order
/// (spec 15.3).
const ROUND_TRIP_ROWS: [&str; 6] = ["null", "switch", "fast", "slow", "buffer", "handles"];
/// The rows of the line of `memory_portions_are_measured`, in its order
/// (spec 15.3).
const MEMORY_PORTION_ROWS: [&str; 11] = [
    "create",
    "create_high",
    "map",
    "map_exec",
    "unmap",
    "protect",
    "protect_exec",
    "release",
    "first_map",
    "dma_create",
    "dma_release",
];
/// The rows of the line of `timer_firing_is_measured`, in its order (spec
/// 15.3).
const TIMER_PORTION_ROWS: [&str; 4] = ["interrupt", "fire", "set", "timers_8192"];
/// The rows of the line of `interrupt_path_is_measured`, in its order
/// (spec 15.3).
const INTERRUPT_PATH_ROWS: [&str; 4] = ["driver", "bind", "ack", "portion"];
/// The rows of the line of `device_windows_are_measured`, in its order
/// (spec 15.3).
const WINDOW_ROWS: [&str; 3] = ["create", "map", "release"];
/// The rows of the line of `upcall_calls_are_measured`, in its order
/// (spec 15.3).
const UPCALL_ROWS: [&str; 5] = ["interrupt", "bind", "control", "request", "return"];
/// The rows of the line of `teardown_portions_are_measured`, in its order
/// (spec 15.3): the term B of the out-of-tree measurement is the longest of them.
const TEARDOWN_ROWS: [&str; 10] = [
    "buffers",
    "shell",
    "end_call",
    "threads_ready",
    "teardown_threads",
    "child_threads",
    "session_buffers",
    "session_handles",
    "teardown_any",
    "threads",
];
/// Scoped direct-control, pick + park and continuation measurements.
const SUSPENSION_ROWS: [&str; 6] = [
    "control_stop_no_queue",
    "control_stop_cancel",
    "pick_park_selected",
    "control_continue",
    "resume_64",
    "longest_portion",
];
/// The rows of the line of the test init's `normal_build_costs`, in its
/// order: the costs of the build that ships (spec 15.3).
const NORMAL_BUILD_ROWS: [&str; 5] = ["null", "clock", "yield", "notify", "round_trip"];
/// The line the shell of the normal build says once it connected to the
/// UART driver (spec 13.6): the driver registered, its output goes by
/// interrupts, and the shell's session works. The system lives on after
/// it, and xtask stops a boot on it.
const SHELL_CONNECTED: &str = "shell: connected to uart; type help for the commands";
/// Init's line once the first start of each record is done (spec 13.4).
const SERVICES_STARTED: &str = "init: services started";
/// The line of the UART driver at its start (spec 13.5).
const UART_LINE: &str = "uart: pl011 at 0x9000000, line 33";
/// The shell's prompt, with no newline after it.
const PROMPT: &str = "stafeto> ";
/// The lines of `crash uart` (spec 13.6): the shell's before its CRASH,
/// its line once it connected to the new instance of the driver, and its
/// line through debug_write once init marked the driver broken.
const CRASHING: &str = "shell: crashing uart";
const RECONNECTED: &str = "shell: uart restarted; connected again";
const BROKEN: &str = "shell: uart is broken; no console left";
/// The start of the kernel's line of a program fault (spec 7.9) for the
/// load from address 0 of the driver's CRASH, and of init's line of the
/// driver's end (spec 16.2).
const DRIVER_FAULT: &str = "process fault: data abort from EL0 (EC 0x24) ESR=0x";
const UART_ENDED: &str = "init: uart ended: ";
/// The lines of the shell's `help`, each whole (spec 13.6).
const HELP_LINES: [&str; 8] = [
    "help        list the commands",
    "echo WORDS  print the words",
    "uptime      the time since boot",
    "ps          the services and their state",
    "mem         the memory of each process",
    "bench       the round trip of a request and the latencies",
    "trace       show kernel events since the last trace",
    "crash uart  crash the UART driver; init restarts it",
];
/// The bytes of the line the console dialog types while `bench` runs:
/// past the driver's ring of input (256 bytes), a READ (64) and the FIFO.
const TYPED_AHEAD: usize = 400;
/// How long a step of the console dialog waits for its answer; its first,
/// the driver's line, waits BOOT_TIMEOUT.
const DIALOG_STEP: Duration = Duration::from_secs(10);
/// The names of the records of init's test table (services/init, feature
/// `table-test`), which the init that ships does not carry.
const TEST_TABLE_NAMES: [&str; 11] = [
    "sink", "echo", "slow", "device", "crash", "silent", "mute", "checker", "private", "hog",
    "oneshot",
];
/// Names of TEST_TABLE_NAMES that are words of init's own lines too: a
/// service that goes silent (`<name> went silent, killed from level ...`),
/// which the init that ships carries since its table has a service.
const INIT_WORDS: [&str; 1] = ["silent"];
/// The start of the line init prints when the client `checker` of its
/// test table ends, and the whole line: its policy is never (spec 13.4).
/// xtask stops QEMU on it.
const CHECKER_END: &str = "init: checker ended: ";
const CHECKER_ENDED: &str = "init: checker ended: exit code 0, not restarted";
/// Init's decisions on five failures in a row of a service that always
/// restarts, in their order (spec 13.4, 16.2): four restarts, each pause
/// twice the one before, then the mark of a broken service. `crash` of
/// its test table fails so, and the UART driver under `crash uart`.
const CRASH_DECISIONS: [&str; 5] = [
    "restarts in 100 ms",
    "restarts in 200 ms",
    "restarts in 400 ms",
    "restarts in 800 ms",
    "broken: 5 failures in 60 s",
];
/// The lines init prints when its watchdog finds a service silent (spec
/// 13.4, 16.2), in their order: `mute`, which never registers, killed from
/// one above its ceiling of 30 four times and then broken, and `silent`,
/// killed from one above its ceiling of 32 and restarted.
const SILENT_KILLED: [&str; 6] = [
    "init: mute went silent, killed from level 31; restarts in 100 ms",
    "init: mute went silent, killed from level 31; restarts in 200 ms",
    "init: mute went silent, killed from level 31; restarts in 400 ms",
    "init: mute went silent, killed from level 31; restarts in 800 ms",
    "init: mute went silent, killed from level 31; broken: 5 failures in 60 s",
    "init: silent went silent, killed from level 33; restarts in 100 ms",
];
/// Where RAM starts on QEMU's `virt`.
const VIRT_RAM: u64 = 0x4000_0000;
/// The kernel's lines of the GIC on QEMU's GICv2 and GICv3 (spec 9).
const GIC_V2_LINE: &str = "gic        v2 distributor 0x8000000, cpu interface 0x8010000";
const GIC_V3_LINE: &str = "gic        v3 distributor 0x8000000, redistributor 0x80a0000";
/// The frequency of the counter of Apple's processors (CNTFRQ_EL0), which
/// HVF passes on.
const HVF_HZ: u64 = 24_000_000;
/// Lines of a run of the test init (tests/init) besides its TEST lines,
/// each whole: a formatted line longer than one debug_write, all 64 bytes
/// of x2-x9 in one debug_write, the bytes of a debug_write's length and no
/// more, and the kernel's line for the fault of a child with no code (spec
/// 7.9, 15.2), and the panics of the strict children on BAD_HANDLE, which
/// name the call (spec 5.4).
const TEST_INIT_LINES: [&str; 6] = [
    "init prints from EL0 in pieces of at most 64 bytes: this line takes 2 of them",
    "test init: debug_write prints all 64 bytes of x2 to x9 in order",
    "debug_write stops at its length",
    "process fault: instruction abort from EL0 (EC 0x20) ESR=0x82000007 FAR=0x1000 ELR=0x1000",
    "BAD_HANDLE from Notify",
    "BAD_HANDLE from HandleClose",
];
/// The children of the test init that fault with a line of the kernel on
/// the port (spec 7.9): the child with no code of
/// `child_fault_reason_reaches_the_parent` and the children with code of
/// the tests of faults, of `wfi` with the fault before it, of an orphan
/// that faults and of a load through a device window on a hole. The child
/// of `a_kernel_line_fills_records_in_turn` faults behind a window over
/// the console's page, and its line stays in the kernel log (spec 3.2).
const CHILD_FAULTS: usize = 13;
/// The panic of a child (tests/child, Role::Panic): rt prints where it
/// panicked, then this message on a line of its own (spec 13.2).
const CHILD_PANIC_AT: &str = "panic: panicked at tests/child/src/main.rs:";
const CHILD_PANIC: &str = "the child panics on purpose";
/// Where xtask's own programs (`raw_init`) start: lld's first address.
const RAW_INIT_ENTRY: u64 = 0x20_0000;
/// `ldr x0, [x0]`: init starts with x0 = 0, so this loads from page 0,
/// which nothing maps.
const LDR_X0_X0: u32 = 0xF940_0000;
/// `adr x1, .+0x1000`: x1 = the page after the code, raw_init's
/// read-only page.
const ADR_X1_NEXT_PAGE: u32 = 0x1000_8001;
/// `str x0, [x1]`.
const STR_X0_X1: u32 = 0xF900_0020;
/// `b .+0x1000`: a branch to the page after the code.
const B_NEXT_PAGE: u32 = 0x1400_0400;
/// init kills its own process: x0 = abi::INIT_PROCESS, then process_kill,
/// which does not return; if it did, the load through x0 would fault.
const KILL_ITSELF: [u32; 4] = [
    movz_x0(abi::INIT_PROCESS.0 as u16),
    movk_x0_lsl16((abi::INIT_PROCESS.0 >> 16) as u16),
    svc(abi::Call::ProcessKill.number()),
    LDR_X0_X0,
];
const _: () = assert!(
    abi::INIT_PROCESS.0 >> 32 == 0,
    "INIT_PROCESS takes two moves"
);
/// Tests the test init has (tests/init): its own count in `TESTS DONE`
/// could drop a test with the line.
const INIT_TESTS: u32 = 229;
/// The lines of the test init's
/// `window_over_the_console_sends_debug_write_to_the_log` (spec 3.2): the
/// first, written behind a window over the console's page, goes into the
/// kernel log alone and never reaches the port; the second, written once
/// the window went, comes whole.
const LOG_BEHIND: &str = "log marker: behind the window";
const LOG_IN_FRONT: &str = "log marker: in front of the window";
/// The rows of the test init's line `log ticks:` under -icount (spec
/// 15.3): a debug_write of 64 bytes into the kernel log and a read of a
/// full batch of it.
const LOG_ROWS: [&str; 2] = ["write", "take"];
/// The page of the PL011 of QEMU `virt`, the console's port.
const CONSOLE_PA: u64 = 0x0900_0000;
/// Tests the client `checker` of init's test table has (tests/svc).
const SVC_TESTS: u32 = 27;
/// What init prints for each table it refuses (services/init, features
/// `table-cycle` and `table-ceiling`), each line whole.
const REFUSED: [(&str, &[ImageProgram], &str); 2] = [
    (
        "boot-cycle.img",
        &CYCLE_PROGRAMS,
        "init: table refused: the connections make a cycle: a -> b -> a",
    ),
    (
        "boot-ceiling.img",
        &CEILING_PROGRAMS,
        "init: table refused: low at priority 40 is below the ceiling 50 of its client high",
    ),
];
/// A data segment bigger than the biggest memory object (abi::MAX_MEMORY)
/// by a page.
const HUGE_DATA: u64 = abi::MAX_MEMORY + bootimg::PAGE_SIZE;

/// A cargo profile of the programs of a boot image: `release`, or
/// `checked`, release with debug assertions (Cargo.toml), where BAD_HANDLE
/// from a typed call of rt or a drop panics (spec 5.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Profile {
    Release,
    Checked,
}

impl Profile {
    /// The arguments of `cargo build` that pick the profile.
    fn args(self) -> &'static [&'static str] {
        match self {
            Profile::Release => &["--release"],
            Profile::Checked => &["--profile", "checked"],
        }
    }

    /// The directory of its builds under target_dir() and a triple.
    fn dir(self) -> &'static str {
        match self {
            Profile::Release => "release",
            Profile::Checked => "checked",
        }
    }
}

/// Kernel builds xtask makes; each keeps its own ELF and image under target_dir().
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Variant {
    Normal,
    Test,
    Baseline,
    Trace,
    TraceNormal,
    /// The kernel tests with those that need QEMU's `-icount` (qemu::ICOUNT).
    TestIcount,
    FaultProbe,
    OverflowProbe,
}

impl Variant {
    const ALL: [Variant; 6] = [
        Variant::Normal,
        Variant::TraceNormal,
        Variant::Test,
        Variant::TestIcount,
        Variant::FaultProbe,
        Variant::OverflowProbe,
    ];

    fn feature(self) -> Option<&'static str> {
        match self {
            Variant::Normal => None,
            Variant::Test => Some("ktest"),
            Variant::Baseline => Some("baseline"),
            Variant::Trace => Some("trace-test"),
            Variant::TraceNormal => Some("trace"),
            Variant::TestIcount => Some("icount"),
            Variant::FaultProbe => Some("fault-probe"),
            Variant::OverflowProbe => Some("overflow-probe"),
        }
    }

    /// The limit of its image file, and where the limit comes from.
    fn limit(self) -> (u64, &'static str) {
        match self {
            Variant::Normal
            | Variant::TraceNormal
            | Variant::FaultProbe
            | Variant::OverflowProbe => (KERNEL_LIMIT, "spec 3.4"),
            Variant::Test | Variant::Baseline | Variant::Trace | Variant::TestIcount => {
                (TEST_KERNEL_LIMIT, "test builds")
            }
        }
    }

    fn stem(self) -> &'static str {
        match self {
            Variant::Normal => "stafeto",
            Variant::Test => "stafeto-ktest",
            Variant::Baseline => "stafeto-baseline",
            Variant::Trace => "stafeto-trace",
            Variant::TraceNormal => "stafeto-trace-normal",
            Variant::TestIcount => "stafeto-ktest-icount",
            Variant::FaultProbe => "stafeto-probe",
            Variant::OverflowProbe => "stafeto-overflow",
        }
    }
}

const USAGE: &str = "usage: cargo xtask <command>

commands:
  build     build the kernel image and the boot image
  run       build and boot in QEMU to the shell (Ctrl-A X quits); with
            --hvf under HVF on a Mac with Apple silicon
  test [--jobs N] host tests, then boot checks, the console dialog, init
            tests and kernel tests in QEMU; N boots at a time (half the
            cores by default; 1 runs them one after the other)
  kernel-test [machine [icount]] run only the kernel test image in QEMU (512M by default), under -icount with `icount`
  init-test [machine] run only the EL0 init test image in QEMU (512M by default)
  gdb       boot in QEMU halted at the first instruction, debugger on :1234
  ci [--jobs N] formatting, clippy, then everything `test` does
  hvf       boot checks, the console dialog, init tests and kernel tests
            under HVF on a Mac with Apple silicon, on Apple's GICv3 and
            QEMU's GICv2; skips elsewhere
  vz        boot the shell through Apple Virtualization.framework
  rtbench   measure RTOS throughput and timer wakeups on TCG, HVF and VZ;
            with --minutes N, the POSIX scenarios of rtbench 2 on HVF and VZ,
            at the same time or, with --serial, one after the other;
            with --short, one round of them on TCG; with --short --icount, as
            ci runs it, under -icount, where the instructions of S5 stay under
            S5_ICOUNT_MAX; with --marks added, the segments of that path
  rtbench-check [--same-guest OLD=NEW] SESSION... compare the base and head runs of
            at least four alternating sessions (each a directory with `order`,
            `base/`, `head/`, the files rtbench-hvf.txt and rtbench-vz.txt)
            against the limits of epoch 2 (S5 p50, median S5 p99 difference,
            median S10 p50 ratio) and fail naming the rows that are over; `order`
            has to agree with the `uptime before` lines of the runs, and
            --same-guest declares that commit OLD in a file is the guest of NEW
  ext4ro    read an e2fsprogs ext4 image inside the QEMU guest
  ramfs     exercise the RAM file service and descriptors in QEMU
  posix-cancel-input verify cancelled UART reads and cleanup handlers
  posix-cancel-input-vz verify cancelled reads of the Virtio console on Apple VZ
  posix-threads verify pthread interruption and main-thread exit
  posix-threads-vz run the pthread probe on Apple Virtualization.framework
  posix-threads-hvf run the pthread probe on the host's processor (Hypervisor framework)
  image-gates verify genuine Take and accepted SetId ambiguity
  image-gates-steps measure retained image dispatches under icount
  image-gates-normal-steps measure normal SetId without reply corruption
  loader-abort verify retained file cleanup after genuine exec cancellation
  loader-info verify strict retained image metadata and incoming handle cleanup
  ramfs-gc verify binding progress during queued page reclamation
  loader-abort-steps measure retained cleanup audits at resolver limits
  ramfs-cleanup verify unfinished binding cleanup with a foreign holder
  posix-files verify authentic file identity and byte path proofs
  posix-files-steps measure full RAM dispatches across credential refresh
  posix-data-steps measure paid data cleanup and full mapping dispatches
  posix-abi run a C main against Rust POSIX and verify thread-local errno
  posix-input verify file progress during blocking console reads
  posix-input-vz verify file progress during Virtio console reads on Apple VZ
  posix-interrupt verify live IPC interruption and Rust POSIX EINTR on UART
  posix-interrupt-vz verify live IPC interruption on the Virtio console on Apple VZ
  console-restart-vz crash the Virtio console's driver on Apple VZ; init stops the
            device and restarts it
  console-early-exit-vz end the Virtio console's driver before it decodes its BARs;
            init stops the function and restarts it
  posix-shared verify cross-thread Rust POSIX file and directory state
  relibc    build relibc for stafeto from the fork at its pinned commit
            (tools/build-relibc.py) into target/relibc/sysroot
  relibc-hello run the first C program on relibc over the Rust POSIX layer
  relibc-threads run relibc's pthreads, waits, cancellation and signals
            over the Rust POSIX layer
  posix-procs run the C probe of POSIX processes: posix_spawn from the
            boot image and from files through the process service
  posix-jobs  check STOP/CONT wait reports, masks, directed signals and orphans
  loader-channels verify ordinary loader channel provenance and descriptor transfer
  process-steps run the probe of the longest step of the process service
            under -icount with a crowd of children
  relibc-threads-hvf the same on the host's processor (Hypervisor framework)
  busybox   run BusyBox cat from the boot image against ramfs in QEMU
  ash       run a BusyBox ash builtin script in QEMU
  ash-shell  run an interactive BusyBox ash in QEMU (Ctrl-A X quits)
  ash-dialog  check an interactive BusyBox ash dialog in QEMU
  ls        run BusyBox ls against the RAM file service in QEMU
  layer-names  check that the layer's libraries export no C name
  coverage  compare POSIX.1-2024 XSH names with relibc and the POSIX startup archive
  os-test [--jobs N] run os-test's io, malloc, process, signal and basic spawn,
            exec and fork tests on relibc, a boot a suite with the tests started from
            files, N boots at a time;
            the table goes to target/measure/os-test.txt; fails when a
            test of tests/os-test/pass.txt does not pass; with
            --one NAME, one test in a boot of its own, with its log
  posix-tty run the C probe of the terminal: termios, isatty, ttyname and the
            names of terminals through the terminal service, with typed input
  posix-tty-control-steps measure full terminal control with sixteen live clients
  posix-tty-steps measure controlling terminal, last-slot groups and full walks
            under -icount; startup dependency waits are printed separately
  posix-tty-vz the same over the Virtio console on Apple VZ
  tty       check the terminal service in QEMU under -icount: line editing,
            echo, INTR, raw reads with VMIN 1, output that waits for the
            driver, and each step of the service under term B
  tty-vz    the same checks over the Virtio console on Apple VZ
  entropy [--hvf] run the probe of the entropy device's driver in QEMU
            under -icount: fills, a restart of the driver, its longest
            steps; with --hvf under HVF on Apple's GICv3 and QEMU's GICv2
  entropy-vz run the probe of the entropy device's driver on Apple VZ
  posix-random run the C probe of getentropy, getrandom and fork in QEMU
  help      this text";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("build") => build(Variant::Normal).map(|_| ()),
        Some("run") => run(&args[1..]),
        Some("test") => jobs::parse_jobs("test", &args[1..]).and_then(test),
        Some("kernel-test") => {
            let variant = if args.get(2).is_some_and(|a| a == "icount") {
                Variant::TestIcount
            } else {
                Variant::Test
            };
            qemu::machine(args.get(1)).and_then(|m| kernel_tests(m, variant).map(|_| ()))
        }
        Some("init-test") => {
            let icount = args.get(2).is_some_and(|a| a == "icount");
            qemu::machine(args.get(1)).and_then(|m| init_tests(m, icount).map(|_| ()))
        }
        Some("gdb") => gdb(),
        Some("ci") => jobs::parse_jobs("ci", &args[1..]).and_then(ci),
        Some("hvf") => hvf(),
        Some("vz") => vz::run(),
        Some("rtbench") => match &args[1..] {
            [flag, minutes, placing @ ..] if flag == "--minutes" => minutes
                .parse::<u64>()
                .ok()
                .filter(|&minutes| (1..=600).contains(&minutes))
                .ok_or_else(|| "rtbench --minutes expects 1..=600".to_owned())
                .and_then(|minutes| {
                    let placing = match placing {
                        [] => rtbench2::Placing::Concurrent,
                        [flag] if flag == "--serial" => rtbench2::Placing::Serial,
                        [flag] if flag == "--concurrent" => rtbench2::Placing::Concurrent,
                        _ => {
                            return Err(
                                "usage: rtbench --minutes N [--serial|--concurrent]".to_owned()
                            );
                        }
                    };
                    rtbench2::run(minutes, placing)
                }),
            [flag, rest @ ..] if flag == "--short" => {
                let how = match rest {
                    [] => Ok(rtbench2::Short::Plain),
                    [icount] if icount == "--icount" => Ok(rtbench2::Short::Icount),
                    [icount, marks] if icount == "--icount" && marks == "--marks" => {
                        Ok(rtbench2::Short::Marks)
                    }
                    _ => Err("usage: rtbench --short [--icount [--marks]]".to_owned()),
                };
                how.and_then(|how| relibc().and_then(|()| rtbench2::short(how)))
            }
            rest => rtbench::run(rest),
        },
        Some("rtbench-check") => rtbench_check::run(&args[1..]),
        Some("ext4ro") => ext4ro_probe(),
        Some("ramfs") => ramfs_probe(),
        Some("relibc") => relibc(),
        Some("os-test") => match &args[1..] {
            [flag, name] if flag == "--one" => ostest::run_one(name),
            [flag, name, rest @ ..] if flag == "--suite" => {
                jobs::parse_jobs("os-test --suite", rest)
                    .and_then(|jobs| ostest::run_suite(name, jobs))
            }
            rest => jobs::parse_jobs("os-test", rest).and_then(ostest::run_in_budget),
        },
        Some("layer-names") => layer_c_names(),
        Some("coverage") => coverage::run(&args[1..]),
        Some("relibc-hello") => relibc_hello_probe(),
        Some("posix-files") => posix_files_probe(),
        Some("ramfs-cleanup") => ramfs_cleanup_probe(),
        Some("ramfs-gc") => ramfs_gc_probe(),
        Some("image-gates") => image_gates_probe(false, false),
        Some("image-gates-steps") => image_gates_probe(true, false),
        Some("image-gates-normal-steps") => image_gates_probe(true, true),
        Some("loader-abort") => loader_abort_probe(false),
        Some("loader-info") => loader_info_probe(),
        Some("loader-abort-steps") => loader_abort_probe(true),
        Some("posix-files-steps") => posix_files_run(true),
        Some("posix-data-steps") => posix_files_run_profile(true, true),
        Some("posix-procs") => posix_procs_probe(&qemu::VIRT),
        Some("posix-lifetimes") => posix_lifetimes_probe(&qemu::VIRT),
        Some("posix-lock-ring") => posix_lock_ring_probe(&qemu::VIRT),
        Some("loader-channels") => loader_channels_probe(),
        Some("posix-poll") => posix_poll_probe(),
        Some("posix-pty") => posix_pty_probe(),
        Some("posix-tty-control-steps") => posix_tty_control_steps(),
        Some("posix-pty-steps") => posix_pty_probe_in(true),
        Some("posix-jobs") => posix_jobs_probe(),
        Some("process-steps") => match &args[1..] {
            [] => process_steps(&qemu::VIRT, 7),
            [n] => n
                .parse()
                .ok()
                .filter(|n| (1..=7).contains(n))
                .ok_or_else(|| "process-steps expects 1..=7 branches".to_owned())
                .and_then(|n| process_steps(&qemu::VIRT, n)),
            _ => Err("process-steps [branches]".to_owned()),
        },
        Some("relibc-threads") => relibc_threads_probe(&qemu::VIRT),
        Some("relibc-threads-hvf") => match hvf_host() {
            Ok(()) => relibc_threads_probe(&qemu::HVF_V3),
            Err(why) => {
                println!("relibc-threads-hvf: skipped: {why}");
                Ok(())
            }
        },
        Some("posix-cancel-input") => posix_cancel_input_probe(false),
        Some("posix-cancel-input-vz") => posix_cancel_input_probe(true),
        Some("posix-threads") => posix_thread_probe(false),
        Some("posix-threads-vz") => posix_thread_probe(true),
        Some("posix-threads-hvf") => posix_thread_probe_hvf(),
        Some("posix-abi") => posix_abi_probe(),
        Some("posix-shared") => posix_shared_probe(),
        Some("posix-input") => posix_input_probe(false),
        Some("posix-input-vz") => posix_input_probe(true),
        Some("posix-interrupt") => posix_interrupt_probe(false),
        Some("posix-interrupt-vz") => posix_interrupt_probe(true),
        Some("console-restart-vz") => vz::console_restart(),
        Some("console-early-exit-vz") => vz::console_early_exit(),
        Some("busybox") => busybox_probe(),
        Some("ash") => ash_probe(),
        Some("ash-shell") => ash_shell(),
        Some("ash-dialog") => ash_dialog(),
        Some("ls") => ls_probe(),
        Some("posix-tty") => posix_tty_probe(false, false),
        Some("posix-tty-vz") => posix_tty_probe(true, false),
        Some("posix-tty-steps") => posix_tty_probe(false, true),
        Some("tty") => tty_probe(false),
        Some("tty-vz") => tty_probe(true),
        Some("entropy") => match args.get(1).map(String::as_str) {
            None => entropy::probe(&qemu::VIRT),
            Some("--hvf") => hvf_host().and_then(|()| {
                entropy::probe(&qemu::HVF_V3)?;
                entropy::probe(&qemu::HVF_V2)
            }),
            Some(_) => Err("entropy [--hvf]".to_owned()),
        },
        Some("entropy-vz") => entropy::probe_vz(),
        Some("posix-random") => entropy::random_probe(&qemu::VIRT),
        Some("help") | None => {
            println!("{USAGE}");
            Ok(())
        }
        Some(other) => Err(format!("unknown command {other:?}\n\n{USAGE}")),
    };
    if let Err(e) = result {
        eprintln!("xtask: {e}");
        exit(1);
    }
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives in the workspace")
        .to_path_buf()
}

/// Where cargo writes its builds: CARGO_TARGET_DIR when it is set, else
/// target/ of the workspace.
fn target_dir() -> PathBuf {
    target_dir_of(std::env::var_os("CARGO_TARGET_DIR"), &root())
}

/// target_dir with CARGO_TARGET_DIR as `var`: a relative directory is
/// taken from `root`, where xtask runs cargo.
fn target_dir_of(var: Option<OsString>, root: &Path) -> PathBuf {
    root.join(var.unwrap_or_else(|| "target".into()))
}

/// The file cargo builds for `package` on `triple` with `profile` under
/// the directory `target`.
fn cargo_output(target: &Path, triple: &str, profile: Profile, package: &str) -> PathBuf {
    target.join(triple).join(profile.dir()).join(package)
}

/// What `make` gives for `key`: made at the first call for `key` in this
/// run of xtask and kept in `made` for the calls after it.
fn once<K: PartialEq, T: Clone>(
    made: &Mutex<Vec<(K, T)>>,
    key: K,
    make: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let mut made = made.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some((_, t)) = made.iter().find(|(k, _)| *k == key) {
        return Ok(t.clone());
    }
    let t = make()?;
    made.push((key, t.clone()));
    Ok(t)
}

fn cargo() -> Command {
    let mut c = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    c.current_dir(root());
    c
}

fn run_cmd(cmd: &mut Command) -> Result<(), String> {
    // A job that keeps its output (out.rs) keeps the command's too.
    let status = if out::capturing() {
        let output = cmd.output().map_err(|e| format!("{cmd:?}: {e}"))?;
        out::write(&String::from_utf8_lossy(&output.stdout), false);
        out::write(&String::from_utf8_lossy(&output.stderr), true);
        output.status
    } else {
        cmd.status().map_err(|e| format!("{cmd:?}: {e}"))?
    };
    if status.success() {
        Ok(())
    } else {
        Err(format!("{cmd:?} failed: {status}"))
    }
}

fn run_until(
    cmd: Command,
    timeout: Duration,
    stop_marker: Option<&str>,
    elf: &Path,
) -> Result<qemu::Outcome, String> {
    let outcome = qemu::run_until(cmd, timeout, stop_marker)?;
    symbolize::backtrace(&outcome.lines, elf);
    Ok(outcome)
}

fn stdout_of(cmd: &mut Command) -> Result<String, String> {
    let out = cmd.output().map_err(|e| format!("{cmd:?}: {e}"))?;
    String::from_utf8(out.stdout).map_err(|e| e.to_string())
}

/// Path of an LLVM tool from the `llvm-tools` rustup component.
fn llvm_tool(name: &str) -> Result<PathBuf, String> {
    let sysroot = stdout_of(
        Command::new("rustc")
            .current_dir(root())
            .args(["--print", "sysroot"]),
    )?;
    let version = stdout_of(Command::new("rustc").current_dir(root()).arg("-vV"))?;
    let host = version
        .lines()
        .find_map(|l| l.strip_prefix("host: "))
        .ok_or("`rustc -vV` has no host line")?;
    let path = Path::new(sysroot.trim())
        .join("lib/rustlib")
        .join(host)
        .join("bin")
        .join(name);
    if path.exists() {
        Ok(path)
    } else {
        Err(format!(
            "{} not found: run `rustup component add llvm-tools`",
            path.display()
        ))
    }
}

#[derive(Clone)]
struct Artifacts {
    elf: PathBuf,
    image: PathBuf,
    boot_image: PathBuf,
}

/// Held while cargo builds programs or a kernel and the result is copied
/// from the path every build of a package shares: another build in
/// between would leave its own file there.
static BUILD_LOCK: Mutex<()> = Mutex::new(());

/// The kernel builds of this run of xtask, one per variant.
static BUILDS: Mutex<Vec<(Variant, Artifacts)>> = Mutex::new(Vec::new());
/// A boot image name with the programs it names: the name stands for its
/// programs, so a cache keyed on both never returns another list's image.
type BootImageKey = (&'static str, &'static [ImageProgram], Profile);
/// The boot images of this run of xtask, one per name and program list.
static BOOT_IMAGES: Mutex<Vec<(BootImageKey, PathBuf)>> = Mutex::new(Vec::new());

/// The kernel image of `variant` and the boot image of the normal build,
/// each built once in a run of xtask, whatever number of checks takes
/// them.
fn build(variant: Variant) -> Result<Artifacts, String> {
    once(&BUILDS, variant, || build_kernel(variant))
}

fn build_kernel(variant: Variant) -> Result<Artifacts, String> {
    let mut cmd = cargo();
    cmd.args([
        "build",
        "--package",
        "kernel",
        "--release",
        "--target",
        KERNEL_TARGET,
    ]);
    if let Some(feature) = variant.feature() {
        cmd.args(["--features", feature]);
    }
    let target = target_dir();
    // Every variant writes the same cargo output path; a copy next to each image
    // keeps the symbols that match it.
    let elf = target.join(format!("{}.elf", variant.stem()));
    let image = target.join(format!("{}.img", variant.stem()));
    {
        let _building = BUILD_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        run_cmd(&mut cmd)?;
        let built = cargo_output(&target, KERNEL_TARGET, Profile::Release, "kernel");
        std::fs::copy(&built, &elf)
            .map_err(|e| format!("{} -> {}: {e}", built.display(), elf.display()))?;
    }
    disasm::erratum_835769(&elf, &llvm_tool("llvm-objdump")?)?;
    disasm::erratum_843419(&elf)?;
    run_cmd(
        Command::new(llvm_tool("llvm-objcopy")?)
            .args(["-O", "binary"])
            .arg(&elf)
            .arg(&image),
    )?;
    let bytes = std::fs::read(&image).map_err(|e| format!("{}: {e}", image.display()))?;
    image::check_header(&bytes)?;
    let (limit, source) = variant.limit();
    image::check_size(bytes.len() as u64, limit)?;
    let boot_image = build_boot_image("boot.img", &BOOT_PROGRAMS, BOOT_PROFILE)?;
    println!(
        "kernel image {} ({} bytes, limit {limit} of {source})",
        image.display(),
        bytes.len()
    );
    Ok(Artifacts {
        elf,
        image,
        boot_image,
    })
}

/// Builds `programs` for EL0 with `profile` and their features and, under
/// target_dir, a boot image `name` whose files they are, in their order,
/// each with its name and the stack size its header asks for (spec 3.3,
/// 13.1); once in a run of xtask for this `(name, programs, profile)`. The
/// ELF file of each program is copied under target_dir right after the
/// build (`image_elf`): cargo writes the builds of one package with other
/// features to one path, and the checks of the ELF files take the copies.
fn build_boot_image(
    name: &'static str,
    programs: &'static [ImageProgram],
    profile: Profile,
) -> Result<PathBuf, String> {
    once(&BOOT_IMAGES, (name, programs, profile), || {
        write_boot_image(name, programs, profile)
    })
}

/// The copy of the ELF file of `package` that the boot image `image` was
/// built from, under the directory `target`.
fn image_elf(target: &Path, image: &str, package: &str) -> PathBuf {
    let dir = image.strip_suffix(".img").unwrap_or(image);
    target.join("images").join(dir).join(package)
}

fn write_boot_image(
    name: &str,
    programs: &[ImageProgram],
    profile: Profile,
) -> Result<PathBuf, String> {
    write_boot_image_with(name, programs, profile, &[])
}

/// `write_boot_image` with the variables `env` set for the build of the
/// programs (rtbench 2 takes the length of its run so).
fn write_boot_image_with(
    name: &str,
    programs: &[ImageProgram],
    profile: Profile,
    env: &[(&str, &str)],
) -> Result<PathBuf, String> {
    write_boot_image_files(name, programs, profile, env, Vec::new())
}

/// `write_boot_image_with` with `extra` files in the image's table of
/// files after those `rootfs::files_of(name)` lists (os-test's tests).
fn write_boot_image_files(
    name: &str,
    programs: &[ImageProgram],
    profile: Profile,
    env: &[(&str, &str)],
    extra: Vec<rootfs::RootFile>,
) -> Result<PathBuf, String> {
    let mut cmd = cargo();
    cmd.envs(env.iter().copied());
    cmd.arg("build").args(profile.args());
    cmd.args(["--target", PROGRAM_TARGET]);
    for (_, package, _, features) in programs {
        cmd.args(["--package", package]);
        for feature in *features {
            cmd.args(["--features", &format!("{package}/{feature}")]);
        }
    }
    let target = target_dir();
    let mut sources = Vec::new();
    {
        let _building = BUILD_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        run_cmd(&mut cmd)?;
        for &(file, package, stack, _) in programs {
            let built = cargo_output(&target, PROGRAM_TARGET, profile, package);
            let elf = image_elf(&target, name, package);
            let why = |e: String| format!("{}: {e}", elf.display());
            if let Some(dir) = elf.parent() {
                std::fs::create_dir_all(dir).map_err(|e| why(e.to_string()))?;
            }
            std::fs::copy(&built, &elf).map_err(|e| format!("{}: {e}", built.display()))?;
            sources.push((file, elf, stack));
        }
    }
    write_elf_image(name, &sources, extra)
}

fn write_elf_image(
    name: &str,
    sources: &[(&str, PathBuf, u32)],
    extra: Vec<rootfs::RootFile>,
) -> Result<PathBuf, String> {
    let target = target_dir();
    let objdump = llvm_tool("llvm-objdump")?;
    let mut files = Vec::new();
    for (file, elf, stack) in sources {
        let why = |e: String| format!("{}: {e}", elf.display());
        disasm::erratum_835769(elf, &objdump)?;
        disasm::erratum_843419(elf)?;
        if *file == "ramfs" {
            disasm::ram_main_frame(elf, &objdump)?;
        }
        // A program of stack 0 goes into the image as its ELF file alone:
        // the loader, and the programs only files of the table name.
        if *stack == 0 {
            continue;
        }
        let bytes = std::fs::read(elf).map_err(|e| why(e.to_string()))?;
        let program = bootimg::elf::program(&bytes, *stack).map_err(|e| why(e.to_string()))?;
        let written = bootimg::write::program(&program).map_err(|e| why(e.to_string()))?;
        files.push((*file, written, elf.clone()));
    }
    let mut list: Vec<_> = files.iter().map(|(f, b, _)| (*f, b.as_slice())).collect();
    // An image with a program on relibc carries relibc's licence notices.
    let mut relibc = false;
    for (_, elf, _) in sources {
        relibc |= links_relibc(&std::fs::read(elf).map_err(|e| format!("{}: {e}", elf.display()))?);
    }
    let notices = if relibc {
        Some(
            std::fs::read(notices_path())
                .map_err(|e| format!("{NOTICES}: {e}: cargo xtask relibc writes it"))?,
        )
    } else {
        None
    };
    if let Some(notices) = &notices {
        list.push((NOTICES, notices.as_slice()));
    }
    // An image with BusyBox (GPL-2.0-only) carries its licence, its
    // copyright notice and where its exact source is (GPLv2, 1 and 3).
    let busybox = sources
        .iter()
        .any(|(_, elf, _)| elf.file_name().is_some_and(|n| n == "busybox-probe"));
    let busybox_files = if busybox {
        Some(busybox_terms()?)
    } else {
        None
    };
    if let Some((licence, source)) = &busybox_files {
        list.push((BUSYBOX_LICENSE, licence.as_slice()));
        list.push((BUSYBOX_SOURCE, source.as_bytes()));
    }
    // An image with a test of os-test (ISC) carries os-test's licence.
    let os_test = sources
        .iter()
        .any(|(_, elf, _)| elf.file_name().is_some_and(|n| n == "os-test-run"));
    let os_test_licence = if os_test {
        Some(ostest::licence()?)
    } else {
        None
    };
    if let Some(licence) = &os_test_licence {
        list.push((ostest::LICENCE, licence.as_slice()));
    }
    // The files of the RAM file service: the files its table names, the
    // ELF files of programs as the linker wrote them among them, then the
    // ELF files of the other programs of stack 0 (the loader, `loader.elf`),
    // then the table (rootfs.rs).
    let mut listed = rootfs::files_of(name);
    listed.extend(extra);
    let wanted = rootfs::sources(&listed);
    let read_elf = |program: &str| -> Result<Vec<u8>, String> {
        let (_, elf, _) = sources
            .iter()
            .find(|(file, _, _)| *file == program)
            .ok_or_else(|| format!("{name}: no program {program} for its rootfs"))?;
        std::fs::read(elf).map_err(|e| format!("{}: {e}", elf.display()))
    };
    let mut elf_names = Vec::new();
    let mut elf_bytes = Vec::new();
    for source in &wanted {
        elf_bytes.push(source.bytes(read_elf)?);
        elf_names.push(source.file_name());
    }
    for (file, _, stack) in sources {
        let raw = rootfs::elf_name(file);
        if *stack == 0 && !elf_names.contains(&raw) {
            elf_bytes.push(read_elf(file)?);
            elf_names.push(raw);
        }
    }
    let first = list.len() as u32;
    for (file, bytes) in elf_names.iter().zip(&elf_bytes) {
        list.push((file.as_str(), bytes.as_slice()));
    }
    let table = if listed.is_empty() {
        None
    } else {
        Some(rootfs::table(&listed, first, list.len() as u32 + 1)?)
    };
    if let Some(table) = &table {
        list.push(("rootfs", table.as_slice()));
    }
    let image = bootimg::write::image(&list).map_err(|e| format!("{name}: {e}"))?;
    let path = target.join(name);
    std::fs::write(&path, &image).map_err(|e| format!("{}: {e}", path.display()))?;
    let from: Vec<_> = files
        .iter()
        .map(|(f, _, elf)| format!("{f} from {}", elf.display()))
        .collect();
    println!(
        "boot image {} ({} bytes): {}",
        path.display(),
        image.len(),
        from.join(", ")
    );
    Ok(path)
}

/// Init's entry point in the boot image at `path`, read as the kernel
/// reads it.
fn init_entry(path: &Path) -> Result<u64, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let init = bootimg::BootImage::parse(&bytes)
        .and_then(bootimg::BootImage::init)
        .and_then(bootimg::Program::parse)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(init.entry)
}

/// `movz x<rd>, #imm, lsl #(16 * hw)`.
const fn movz(rd: u32, imm: u16, hw: u32) -> u32 {
    0xD280_0000 | hw << 21 | (imm as u32) << 5 | rd
}

/// `movk x<rd>, #imm, lsl #(16 * hw)`.
const fn movk(rd: u32, imm: u16, hw: u32) -> u32 {
    0xF280_0000 | hw << 21 | (imm as u32) << 5 | rd
}

/// `movz x0, #imm`.
const fn movz_x0(imm: u16) -> u32 {
    movz(0, imm, 0)
}

/// `movk x0, #imm, lsl #16`.
const fn movk_x0_lsl16(imm: u16) -> u32 {
    movk(0, imm, 1)
}

/// x<rd> = `value`: a `movz` of its low 16 bits, then a `movk` of each
/// other 16 bits that are not 0.
fn mov(rd: u32, value: u64) -> Vec<u32> {
    let half = |hw: u32| (value >> (16 * hw)) as u16;
    let rest = (1..4).filter(|&hw| half(hw) != 0);
    std::iter::once(movz(rd, half(0), 0))
        .chain(rest.map(|hw| movk(rd, half(hw), hw)))
        .collect()
}

/// `svc #n`.
const fn svc(n: u16) -> u32 {
    0xD400_0001 | (n as u32) << 5
}

/// A boot image whose init xtask writes itself, with no ELF: `code` at
/// RAW_INIT_ENTRY, which is its entry; with `rodata`, a read-only page of
/// zeros on the next page; unless `data_size` is 0, a data segment of
/// that many zero bytes on the page after those.
fn raw_init(code: &[u32], rodata: bool, data_size: u64) -> Result<Vec<u8>, String> {
    let code: Vec<u8> = code.iter().flat_map(|i| i.to_le_bytes()).collect();
    let read_only = if rodata {
        bootimg::Segment {
            vaddr: RAW_INIT_ENTRY + bootimg::PAGE_SIZE,
            mem_size: bootimg::PAGE_SIZE,
            bytes: &[],
        }
    } else {
        bootimg::Segment::EMPTY
    };
    let data = match data_size {
        0 => bootimg::Segment::EMPTY,
        size => bootimg::Segment {
            vaddr: RAW_INIT_ENTRY + bootimg::PAGE_SIZE * (1 + u64::from(rodata)),
            mem_size: size,
            bytes: &[],
        },
    };
    let program = bootimg::Program {
        entry: RAW_INIT_ENTRY,
        stack_size: INIT_STACK_SIZE,
        segments: [
            bootimg::Segment {
                vaddr: RAW_INIT_ENTRY,
                mem_size: bootimg::PAGE_SIZE,
                bytes: &code,
            },
            read_only,
            data,
        ],
    };
    let init = bootimg::write::program(&program).map_err(|e| e.to_string())?;
    bootimg::write::image(&[("init", &init)]).map_err(|e| e.to_string())
}

/// `cargo xtask run` (spec 14): the normal build on the machine of
/// run_machine, with the console on the terminal.
fn run(args: &[String]) -> Result<(), String> {
    let m = run_machine(args, hvf_host)?;
    let a = build(Variant::Normal)?;
    let cmd = qemu::command(m, &a.image, Some(&a.boot_image));
    run_interactive_qemu(cmd, &a.elf)
}

fn run_interactive_qemu(mut cmd: Command, elf: &Path) -> Result<(), String> {
    cmd.arg("-nographic");
    let mut child = cmd
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{cmd:?}: {e}"))?;
    let mut source = child.stdout.take().ok_or("QEMU has no stdout")?;
    let mut output = Vec::new();
    let mut bytes = [0u8; 4096];
    loop {
        let n = std::io::Read::read(&mut source, &mut bytes).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        std::io::Write::write_all(&mut std::io::stdout(), &bytes[..n])
            .map_err(|e| e.to_string())?;
        std::io::Write::flush(&mut std::io::stdout()).map_err(|e| e.to_string())?;
        output.extend_from_slice(&bytes[..n]);
        if output.len() > 65_536 {
            output.drain(..output.len() - 65_536);
        }
    }
    let status = child.wait().map_err(|e| e.to_string())?;
    let lines: Vec<String> = String::from_utf8_lossy(&output)
        .lines()
        .map(str::to_owned)
        .collect();
    symbolize::backtrace(&lines, elf);
    if status.success() {
        Ok(())
    } else {
        Err(format!("QEMU exited with {status}"))
    }
}

/// The machine of `cargo xtask run` with `args` (spec 14): VIRT with
/// none; HVF_V3 with `--hvf` when `host` says HVF runs here (hvf_host), an
/// error with its reason otherwise, which a person asked for and should
/// see; an error for any other arguments.
fn run_machine(
    args: &[String],
    host: impl FnOnce() -> Result<(), String>,
) -> Result<&'static qemu::Machine, String> {
    match args {
        [] => Ok(&qemu::VIRT),
        [flag] if flag == "--hvf" => host().map(|()| &qemu::HVF_V3).map_err(|why| {
            format!("run --hvf needs macOS on Apple Silicon with the Hypervisor framework: {why}")
        }),
        _ => Err(format!("unknown arguments of run: {args:?}\n\n{USAGE}")),
    }
}

/// First ext4 slice: the guest reads the checked-in e2fsprogs image
/// through ext4-view. The image is embedded until a block service exists.
fn ext4ro_probe() -> Result<(), String> {
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-ext4ro.img", &EXT4RO_PROGRAMS, BOOT_PROFILE)?;
    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    let output = run_until(cmd, BOOT_TIMEOUT, None, &kernel.elf)?;
    qemu::expect_init_exit(&output, "boot complete", 0)?;
    println!("ext4 read-only guest probe passed");
    Ok(())
}

fn ramfs_probe() -> Result<(), String> {
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-ramfs.img", &RAMFS_PROGRAMS, BOOT_PROFILE)?;
    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    let output = run_until(cmd, BOOT_TIMEOUT, Some("ramfs-probe: ok"), &kernel.elf)?;
    qemu::expect_stopped_on(&output, "ramfs-probe: ok")?;
    // The service reports the size of the ELF file the image carries: the
    // guest's `wc -c` of it is the host's file length.
    let elf = image_elf(&target_dir(), "boot-ramfs.img", "ramfs-probe");
    let host = std::fs::metadata(&elf)
        .map_err(|e| format!("{}: {e}", elf.display()))?
        .len();
    match qemu::number_after(&output.lines, "ramfs-probe: image file size ") {
        Some(guest) if guest == host => {}
        guest => {
            return Err(format!(
                "the guest reads {guest:?} bytes of /bin/ramfs-probe, the ELF file has {host}"
            ));
        }
    }
    println!("RAM file service guest probe passed");
    Ok(())
}

fn posix_abi_probe() -> Result<(), String> {
    posix_abi_boots()?;
    posix_orphans()?;
    posix_thread_probe(false)?;
    posix_cancel_input_probe(false)?;
    posix_shared_probe()?;
    posix_input_probe(false)?;
    posix_interrupt_probe(false)?;
    println!("Rust POSIX C ABI, errno and shared-file guest probes passed");
    Ok(())
}

/// The first two boots of `posix-abi`: the C main on the layer, and the
/// thread-local errno.
fn posix_abi_boots() -> Result<(), String> {
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-posix-abi.img", &POSIX_ABI_PROGRAMS, BOOT_PROFILE)?;
    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    const ENDED: &str = "init: posix-abi-probe ended: exit code 0, not restarted";
    let output = run_until(cmd, BOOT_TIMEOUT, Some(ENDED), &kernel.elf)?;
    qemu::expect_stopped_on(&output, ENDED)?;
    qemu::expect_marker(&output, "posix-abi-probe: ok")?;
    let data = layer_data(&image_elf(
        &target_dir(),
        "boot-posix-abi.img",
        "posix-abi-probe",
    ))?;
    println!("posix-abi-probe: the layer's .data + .bss {data} bytes");
    let image = build_boot_image("boot-posix-tls.img", &POSIX_TLS_PROGRAMS, BOOT_PROFILE)?;
    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    let output = run_until(cmd, BOOT_TIMEOUT, Some("posix-tls-probe: ok"), &kernel.elf)?;
    qemu::expect_stopped_on(&output, "posix-tls-probe: ok")
}

/// The command of a run of the kernel that ships with the boot image
/// `image`: on Apple VZ when `vz` (vz::command), in QEMU headless
/// otherwise; and the kernel's artifacts.
fn probe_command(image: &Path, vz: bool) -> Result<(Command, Artifacts), String> {
    let kernel = build(Variant::Normal)?;
    let cmd = if vz {
        vz::command(&kernel.image, image)?
    } else {
        let machine = if PROBES_ON_HVF.load(std::sync::atomic::Ordering::Relaxed) {
            &qemu::HVF_V3
        } else {
            &qemu::VIRT
        };
        let mut cmd = qemu::command(machine, &kernel.image, Some(image));
        cmd.args(qemu::HEADLESS);
        cmd
    };
    Ok((cmd, kernel))
}

/// The process service ends before it registers (feature `exit-early`):
/// init fails the load of each POSIX process, the one that waited for its
/// session and the one loaded after the service ended, and starts neither.
fn posix_orphans() -> Result<(), String> {
    let image = build_boot_image(
        "boot-posix-orphans.img",
        &POSIX_ORPHAN_PROGRAMS,
        BOOT_PROFILE,
    )?;
    let (cmd, kernel) = probe_command(&image, false)?;
    const PEER: &str = "init: clock-peer did not load: the process service ended, not restarted";
    const PROBE: &str =
        "init: posix-abi-probe did not load: the process service ended, not restarted";
    let output = run_until(cmd, BOOT_TIMEOUT, Some(PROBE), &kernel.elf)?;
    qemu::expect_stopped_on(&output, PROBE)?;
    qemu::expect_line(&output, PEER)?;
    println!("POSIX processes whose service ended fail their loads");
    Ok(())
}

/// Set by `posix-threads-hvf`: the QEMU probes of the pthread images run on
/// the host's processor (HVF, GICv3) and not on TCG.
static PROBES_ON_HVF: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// `posix-threads-hvf`: the pthread and native survivor images (native jump,
/// router R1 to R8, signals) on the real processor.
fn posix_thread_probe_hvf() -> Result<(), String> {
    if let Err(why) = hvf_host() {
        println!("posix-threads-hvf: skipped: {why}");
        return Ok(());
    }
    PROBES_ON_HVF.store(true, std::sync::atomic::Ordering::Relaxed);
    posix_thread_probe(false)
}

fn posix_thread_probe(vz: bool) -> Result<(), String> {
    native_scopes::both_images(vz, stock_thread_probe, native_scope_probe)?;
    println!("Rust POSIX pthread lifecycle and native survivor guest probes passed");
    Ok(())
}

fn stock_thread_probe(vz: bool) -> Result<(), String> {
    let image = if vz {
        build_boot_image(
            "boot-posix-threads-vz.img",
            &POSIX_VZ_THREAD_PROGRAMS,
            BOOT_PROFILE,
        )?
    } else {
        build_boot_image(
            "boot-posix-threads.img",
            &POSIX_THREAD_PROGRAMS,
            BOOT_PROFILE,
        )?
    };
    let (cmd, kernel) = probe_command(&image, vz)?;
    const ENDED: &str = "init: posix-abi-probe ended: exit code 0, not restarted";
    let checked = run_until(cmd, BOOT_TIMEOUT, Some(ENDED), &kernel.elf).and_then(|output| {
        qemu::expect_stopped_on(&output, ENDED)
            .map_err(|e| format!("{e}; last lines: {:?}", output.lines.last()))?;
        qemu::expect_marker(&output, "posix-thread-probe: ok")?;
        qemu::expect_marker(
            &output,
            "credential-probe: a forged identity does not set the clock",
        )?;
        qemu::expect_marker(&output, "posix-sender: nobody may not set the clock")?;
        qemu::expect_marker(
            &output,
            "priority-probe: heap and files at the ceiling above main, no helper thread",
        )?;
        qemu::expect_marker(&output, "posix-process: adoption refusals ok")?;
        native_scopes::check_ended_routers(&output.lines, 1)
    });
    if vz {
        vz::stop_hint(checked)?;
    } else {
        checked?;
    }
    println!("Rust POSIX pthread lifecycle guest probe passed");
    Ok(())
}

fn native_scope_probe(vz: bool) -> Result<(), String> {
    relibc()?;
    run_cmd(Command::new("python3").arg(root().join("tools/build-busybox.py")))?;
    let (name, programs): (&str, &[ImageProgram]) = if vz {
        (
            "boot-posix-native-scopes-vz.img",
            &POSIX_VZ_NATIVE_SCOPE_PROGRAMS,
        )
    } else {
        ("boot-posix-native-scopes.img", &POSIX_NATIVE_SCOPE_PROGRAMS)
    };
    let image = build_boot_image(name, programs, BOOT_PROFILE)?;
    let (cmd, kernel) = probe_command(&image, vz)?;
    const ENDED: &str = "init: posix-procs ended: exit code 0, not restarted";
    let output = run_until(cmd, BOOT_TIMEOUT, Some(ENDED), &kernel.elf)?;
    let checked = qemu::expect_stopped_on(&output, ENDED)
        .and_then(|()| native_scopes::check_markers(&output.lines))
        .and_then(|()| native_scopes::check_ended_routers(&output.lines, 1));
    if vz { vz::stop_hint(checked) } else { checked }
}

fn posix_cancel_input_probe(vz: bool) -> Result<(), String> {
    let image = if vz {
        build_boot_image(
            "boot-posix-cancel-vz.img",
            &POSIX_VZ_CANCEL_INPUT_PROGRAMS,
            BOOT_PROFILE,
        )?
    } else {
        build_boot_image(
            "boot-posix-cancel.img",
            &POSIX_CANCEL_INPUT_PROGRAMS,
            BOOT_PROFILE,
        )?
    };
    let (cmd, _) = probe_command(&image, vz)?;
    const ENDED: &str = "init: posix-probe ended: exit code 0, not restarted";
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let result = (|| {
        run.expect(
            "posix-cancel-input-probe: cleanup read waiting",
            BOOT_TIMEOUT,
        )?;
        run.send("z")?;
        run.expect(
            "posix-cancel-input-probe: read after cancellation waiting",
            DIALOG_STEP,
        )?;
        run.send("v")?;
        run.expect("posix-cancel-input-probe: ok", DIALOG_STEP)?;
        run.expect(ENDED, DIALOG_STEP)
    })();
    run.stop();
    if vz {
        vz::stop_hint(result)?;
    } else {
        result?;
    }
    println!("Rust POSIX cancelled input and cleanup guest probe passed");
    Ok(())
}

fn posix_shared_probe() -> Result<(), String> {
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image(
        "boot-posix-shared.img",
        &POSIX_SHARED_PROGRAMS,
        BOOT_PROFILE,
    )?;
    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    const ENDED: &str = "init: posix-abi-probe ended: exit code 0, not restarted";
    let output = run_until(cmd, BOOT_TIMEOUT, Some(ENDED), &kernel.elf)?;
    qemu::expect_stopped_on(&output, ENDED)?;
    qemu::expect_marker(&output, "posix-shared-probe: ok")?;
    println!("Rust POSIX shared-file guest probe passed");
    Ok(())
}

fn posix_input_probe(vz: bool) -> Result<(), String> {
    let image = if vz {
        build_boot_image(
            "boot-posix-input-vz.img",
            &POSIX_VZ_INPUT_PROGRAMS,
            BOOT_PROFILE,
        )?
    } else {
        build_boot_image("boot-posix-input.img", &POSIX_INPUT_PROGRAMS, BOOT_PROFILE)?
    };
    let (cmd, _) = probe_command(&image, vz)?;
    const ENDED: &str = "init: posix-probe ended: exit code 0, not restarted";
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let result = (|| {
        run.expect(
            "posix-input-probe: files ready while input waits",
            BOOT_TIMEOUT,
        )?;
        run.send("xyz")?;
        run.expect("posix-input-probe: ok", DIALOG_STEP)?;
        run.expect(ENDED, DIALOG_STEP)
    })();
    run.stop();
    if vz {
        vz::stop_hint(result)?;
    } else {
        result?;
    }
    println!(
        "Rust POSIX concurrent input guest probe passed on {}",
        if vz { "the Virtio console" } else { "the UART" }
    );
    Ok(())
}

/// Measures the full terminal control interval against a PTY in memory.
fn posix_tty_control_steps() -> Result<(), String> {
    relibc()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image(
        "boot-posix-tty-control-steps.img",
        &POSIX_TTY_CONTROL_PROGRAMS,
        BOOT_PROFILE,
    )?;
    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS).args(qemu::ICOUNT);
    let outcome = qemu::run_until(cmd, Duration::from_secs(180), Some("init: posix-tty ended"))?;
    let dir = target_dir().join("measure");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    std::fs::write(
        dir.join("posix-tty-control-steps.log"),
        outcome.lines.join("\n") + "\n",
    )
    .map_err(|e| e.to_string())?;
    if !outcome
        .lines
        .iter()
        .any(|line| line == "posix-tty: quiet controls sixteen clients ok")
        || !outcome
            .lines
            .iter()
            .any(|line| line == "init: posix-tty ended: exit code 0, not restarted")
    {
        return Err(
            "quiet terminal controls failed; see target/measure/posix-tty-control-steps.log".into(),
        );
    }
    check_waits(&outcome.lines, &["5"], "terminal control steps")?;
    let maxima = longest_steps(&outcome.lines, "5");
    for kind in 16..=20 {
        let ticks = maxima
            .iter()
            .find(|row| row.0 == kind)
            .map_or(0, |row| row.1);
        if ticks == 0 || ticks > RAM_STEP_MAX {
            return Err(format!(
                "terminal control kind {kind}: {ticks} ticks, limit {RAM_STEP_MAX}"
            ));
        }
    }
    println!("Quiet terminal controls, sixteen live clients: {maxima:?}");
    Ok(())
}

fn posix_tty_probe(vz: bool, measure: bool) -> Result<(), String> {
    relibc()?;
    let image = if measure {
        build_boot_image(
            "boot-posix-tty-steps.img",
            &POSIX_TTY_STEPS_PROGRAMS,
            BOOT_PROFILE,
        )?
    } else if vz {
        build_boot_image(
            "boot-posix-tty-vz.img",
            &POSIX_TTY_VZ_PROGRAMS,
            BOOT_PROFILE,
        )?
    } else {
        build_boot_image("boot-posix-tty.img", &POSIX_TTY_PROGRAMS, BOOT_PROFILE)?
    };
    let (mut cmd, _) = probe_command(&image, vz)?;
    if measure {
        cmd.args(qemu::ICOUNT);
    }
    const ENDED: &str = "init: posix-tty ended: exit code 0, not restarted";
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let result = (|| {
        run.expect("posix-tty: settings ok", BOOT_TIMEOUT)?;
        for (i, byte) in b"xyz".iter().copied().enumerate() {
            run.expect(&format!("posix-tty: raw read {i} waits"), DIALOG_STEP)?;
            run.type_raw(&[byte])?;
            run.expect(
                &format!("posix-tty: raw read {i} gave 0x{byte:02x}"),
                DIALOG_STEP,
            )?;
        }
        run.expect("posix-tty: attributes restored", DIALOG_STEP)?;
        run.expect("posix-tty: canonical read waits", DIALOG_STEP)?;
        run.send("hi")?;
        run.expect("posix-tty: canonical read gave 3 bytes", DIALOG_STEP)?;
        for (ask, typed, done) in [
            ("type junk", &b"junk"[..], "tcflush dropped the input"),
            ("type more junk", b"more", "TCSAFLUSH dropped the input"),
            ("type k", b"k", "input after a flush is read"),
        ] {
            run.expect(&format!("posix-tty: {ask}"), DIALOG_STEP)?;
            run.type_raw(typed)?;
            run.expect(&format!("posix-tty: {done}"), DIALOG_STEP)?;
        }
        // STOP and START go out between the bytes written.
        run.expect("<\x13>(\x11)", DIALOG_STEP)?;
        run.expect("posix-tty: output flushed", DIALOG_STEP)?;
        run.expect("posix-tty: output ok", DIALOG_STEP)?;
        run.expect(
            "posix-tty: the layer refused the operations on the names of the terminal",
            DIALOG_STEP,
        )?;
        run.expect("posix-tty: written through /dev/console", DIALOG_STEP)?;
        run.expect("posix-tty: child wrote through /dev/console", DIALOG_STEP)?;
        run.expect(
            "posix-tty: spawned child wrote through the inherited descriptor",
            DIALOG_STEP,
        )?;
        run.expect(
            "posix-tty: spawned child wrote through the descriptor of a file action",
            DIALOG_STEP,
        )?;
        run.expect("posix-tty: foreground changed during read", DIALOG_STEP)?;
        run.send("r")?;
        run.expect("posix-tty: stopped reader resumed", DIALOG_STEP)?;
        run.send("j")?;
        run.expect("posix-tty: job control ok", DIALOG_STEP)?;
        run.expect("posix-tty: detached reader still uses open fd", DIALOG_STEP)?;
        run.send("d")?;
        run.expect(
            "posix-tty: personal detach and fresh attachment ok",
            DIALOG_STEP,
        )?;
        run.expect("posix-tty: sessions ok", DIALOG_STEP)?;
        run.expect("posix-tty: ok", DIALOG_STEP)?;
        run.expect(ENDED, DIALOG_STEP)
    })();
    let output = run.stop();
    if vz {
        vz::stop_hint(result)?;
    } else {
        result?;
    }
    if measure {
        let dir = target_dir().join("measure");
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        std::fs::write(
            dir.join("posix-tty-steps.log"),
            output.lines.join("\n") + "\n",
        )
        .map_err(|e| e.to_string())?;
        for tag in ["5", "1"] {
            println!(
                "POSIX terminal steps tag {tag}: {:?}",
                longest_steps(&output.lines, tag)
            );
        }
        check_waits(&output.lines, &["1", "5"], "POSIX terminal steps")?;
        let tty = longest_steps(&output.lines, "5");
        // This POSIX fixture calls Acquire, SetPgrp, GetPgrp and GetSid.
        // The separate native control probe also measures Controlling.
        for kind in 16..=19 {
            let ticks = tty.iter().find(|row| row.0 == kind).map_or(0, |row| row.1);
            if ticks == 0 {
                return Err(format!(
                    "terminal control kind {kind} made no measured request"
                ));
            }
        }
        let mut edge_codes = Vec::new();
        for line in &output.lines {
            let Some(scan) = line.strip_prefix("tty group scan: group ") else {
                continue;
            };
            let fields: Vec<_> = scan.split_whitespace().collect();
            let [group, ticks, "ticks", "code", code] = fields.as_slice() else {
                return Err(format!("malformed terminal group scan: {line}"));
            };
            let ticks: u64 = ticks.parse().map_err(|_| line.clone())?;
            if ticks == 0 || ticks > RAM_STEP_MAX {
                return Err(format!(
                    "terminal group scan exceeded {RAM_STEP_MAX}: {line}"
                ));
            }
            if *group == "2147483646" {
                edge_codes.push(code.parse::<u32>().map_err(|_| line.clone())?);
            }
        }
        if !edge_codes.contains(&0) || !edge_codes.iter().any(|code| *code != 0) {
            return Err(format!(
                "terminal group scans missed last-slot or absent group: {edge_codes:?}"
            ));
        }
        let process = longest_steps(&output.lines, "1");
        let walk = process
            .iter()
            .find(|row| row.0 == 65)
            .map_or(0, |row| row.1);
        if walk == 0 || walk > RAM_STEP_MAX {
            return Err(format!(
                "terminal group walk step took {walk} ticks, bound {RAM_STEP_MAX}"
            ));
        }
    }
    // No echo in raw mode: a byte typed would show before the line that
    // follows its read.
    for line in output
        .lines
        .iter()
        .filter(|l| l.contains("posix-tty: raw read"))
    {
        if !line.starts_with("posix-tty: raw read") {
            return Err(format!("a raw read's line came with an echo: {line:?}"));
        }
    }
    // What tcflush dropped never shows, and what tcflow held shows once.
    if output
        .lines
        .iter()
        .any(|l| l.contains("posix-tty: dropped by tcflush"))
    {
        return Err("the output tcflush had to drop reached the console".to_owned());
    }
    let held = output
        .lines
        .iter()
        .filter(|l| l.contains("posix-tty: held by tcflow"))
        .count();
    if held != 1 {
        return Err(format!("the output tcflow held came {held} times"));
    }
    if output.lines.iter().any(|l| l.contains("check failed")) {
        return Err("a check of the probe failed".to_owned());
    }
    println!(
        "POSIX terminal guest probe passed on {}",
        if vz { "the Virtio console" } else { "the UART" }
    );
    Ok(())
}

fn posix_interrupt_probe(vz: bool) -> Result<(), String> {
    let image = if vz {
        build_boot_image(
            "boot-posix-interrupt-vz.img",
            &POSIX_VZ_INTERRUPT_PROGRAMS,
            BOOT_PROFILE,
        )?
    } else {
        build_boot_image(
            "boot-posix-interrupt.img",
            &POSIX_INTERRUPT_PROGRAMS,
            BOOT_PROFILE,
        )?
    };
    let (cmd, _) = probe_command(&image, vz)?;
    const ENDED: &str = "init: posix-probe ended: exit code 0, not restarted";
    // Inject no input until cleanup and recovery have completed.
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let result = (|| {
        run.expect("posix-interrupt-probe: read waits armed", BOOT_TIMEOUT)?;
        run.send("r")?;
        run.expect("posix-interrupt-probe: retry waiting", BOOT_TIMEOUT)?;
        run.send("q")?;
        run.expect("posix-interrupt-probe: ok", DIALOG_STEP)?;
        run.expect(ENDED, DIALOG_STEP)
    })();
    run.stop();
    if vz {
        vz::stop_hint(result)?;
    } else {
        result?;
    }
    println!(
        "Rust POSIX interruption guest probe passed on {}",
        if vz { "the Virtio console" } else { "the UART" }
    );
    Ok(())
}

/// relibc for stafeto in target/relibc/sysroot; nothing when its stamp
/// matches.
/// relibc's licence notices, which tools/check-licenses.py writes from
/// its closure (item 6) and the boot images carry.
fn notices_path() -> PathBuf {
    target_dir().join("relibc/THIRD-PARTY-NOTICES")
}

/// The name of the notices in a boot image.
const NOTICES: &str = "THIRD-PARTY-NOTICES";
/// BusyBox's licence and the note of its notice and source in an image.
const BUSYBOX_LICENSE: &str = "BUSYBOX-LICENSE";
const BUSYBOX_SOURCE: &str = "BUSYBOX-SOURCE";

/// The value of `NAME = "value"` in the Python script `script`.
fn script_value(script: &str, name: &str) -> Result<String, String> {
    let text =
        std::fs::read_to_string(root().join(script)).map_err(|e| format!("{script}: {e}"))?;
    text.lines()
        .find_map(|line| line.strip_prefix(&format!("{name} = \"")))
        .and_then(|rest| rest.split('"').next())
        .map(str::to_owned)
        .ok_or_else(|| format!("{script}: no {name}"))
}

/// BusyBox's LICENSE (GPLv2 with its note) and the note of BusyBox's
/// copyright and of the exact source of the program in the image.
fn busybox_terms() -> Result<(Vec<u8>, String), String> {
    let path = target_dir().join("busybox/source/LICENSE");
    let licence = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let version = script_value("tools/build-busybox.py", "VERSION")?;
    let sha256 = script_value("tools/build-busybox.py", "SHA256")?;
    let relibc = script_value("tools/build-relibc.py", "COMMIT")?;
    let source = format!(
        "busybox-probe holds BusyBox {version}.\n\
         BusyBox is copyrighted by many authors between 1998-2015.\n\
         Licensed under GPLv2 (BUSYBOX-LICENSE). See source distribution for\n\
         detailed copyright notices.\n\n\
         Its source: https://busybox.net/downloads/busybox-{version}.tar.bz2\n\
         (SHA-256 {sha256}), changed and configured by tools/build-busybox.py\n\
         of https://github.com/stafeto/stafeto at commit {}, which also holds\n\
         the probe's main (tests/busybox); linked with relibc\n\
         https://github.com/stafeto/relibc at commit {relibc}\n\
         (THIRD-PARTY-NOTICES).\n",
        rtbench2::commit()
    );
    Ok((licence, source))
}

/// The builds of relibc and of BusyBox of this run of xtask: one is
/// enough for every check that takes them.
static RELIBC_BUILT: Mutex<Vec<((), ())>> = Mutex::new(Vec::new());
static BUSYBOX_BUILT: Mutex<Vec<((), ())>> = Mutex::new(Vec::new());

/// relibc built, once in a run of xtask.
fn relibc() -> Result<(), String> {
    once(&RELIBC_BUILT, (), build_relibc)
}

/// BusyBox built, once in a run of xtask.
fn busybox_build() -> Result<(), String> {
    once(&BUSYBOX_BUILT, (), || {
        run_cmd(Command::new("python3").arg(root().join("tools/build-busybox.py")))
    })
}

fn build_relibc() -> Result<(), String> {
    run_cmd(Command::new("python3").arg(root().join("tools/build-relibc.py")))?;
    // The notices follow each build of relibc.
    let modified = |path: PathBuf| std::fs::metadata(path).and_then(|m| m.modified()).ok();
    let library = modified(target_dir().join("relibc/sysroot/lib/libc.a"));
    if modified(notices_path()) < library {
        run_cmd(
            Command::new("python3")
                .arg(root().join("tools/check-licenses.py"))
                .arg("--notices"),
        )?;
    }
    Ok(())
}

/// Whether the ELF `bytes` links relibc: its start's symbol is there.
fn links_relibc(bytes: &[u8]) -> bool {
    bytes
        .windows(b"relibc_start_v1".len())
        .any(|window| window == b"relibc_start_v1")
}

/// Fails unless the boot image at `path` carries BusyBox's licence and
/// the note of its source.
fn image_has_busybox_terms(path: &Path) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let image =
        bootimg::BootImage::parse(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    let (licence, _) = busybox_terms()?;
    let carries = |name: &str, check: &dyn Fn(&[u8]) -> bool| {
        image
            .files()
            .any(|file| file.name == name && check(file.data))
    };
    if carries(BUSYBOX_LICENSE, &|data| data == licence.as_slice())
        && carries(BUSYBOX_SOURCE, &|data| {
            data.windows(16).any(|w| w == b"busybox-1.37.0.t")
                && data.windows(5).any(|w| w == b"GPLv2")
        })
    {
        Ok(())
    } else {
        Err(format!("{} carries no BusyBox terms", path.display()))
    }
}

/// Fails unless the boot image at `path` carries relibc's notices.
fn image_has_notices(path: &Path) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let image =
        bootimg::BootImage::parse(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    let notices = std::fs::read(notices_path()).map_err(|e| format!("{NOTICES}: {e}"))?;
    if image
        .files()
        .any(|file| file.name == NOTICES && file.data == notices.as_slice())
    {
        Ok(())
    } else {
        Err(format!("{} carries no {NOTICES}", path.display()))
    }
}

fn relibc_hello_probe() -> Result<(), String> {
    relibc()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-relibc.img", &RELIBC_PROGRAMS, BOOT_PROFILE)?;
    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    let mut run = qemu::Run::start(cmd, qemu::Input::Null)?;
    // The four runs end in any order: the program, then abort and a failed
    // assert, which die by SIGABRT, and a panic of relibc, which exits
    // with 134 itself.
    let ended = (|| {
        for line in [
            "init: relibc-hello ended: exit code 0, not restarted",
            "init: relibc-abort ended: signal 6 (SIGABRT), not restarted",
            "init: relibc-assert ended: signal 6 (SIGABRT), not restarted",
            "init: relibc-panic ended: exit code 134, not restarted",
        ] {
            run.expect_seen(line, BOOT_TIMEOUT)?;
        }
        Ok::<(), String>(())
    })();
    let outcome = run.stop();
    symbolize::backtrace(&outcome.lines, &kernel.elf);
    ended?;
    for marker in [
        "relibc-hello: printf argc=1 argv0=relibc-hello pi=3.142",
        "relibc-hello: malloc heap x",
        "relibc-hello: fread ",
        "relibc-hello: monotonic ",
        "relibc-hello: directories, stat, descriptors, mmap, math",
        "relibc-hello: constants: _POSIX_VERSION 202405, _POSIX_SUBPROFILE 1, 11 options claimed, timers -1",
        "relibc-hello: getentropy without the service: ENOSYS",
        "relibc-hello: ok",
        "Assertion `how == NULL` failed.",
        "RELIBC PANIC: ",
    ] {
        qemu::expect_marker(&outcome, marker)?;
    }
    println!("relibc C-program guest probe passed");
    Ok(())
}

/// The probe of POSIX processes (tests/posix-procs): its checks pass, its
/// child says the PID the parent's posix_spawn gave and the parent's PID,
/// and the child that did not load got no process.
fn posix_poll_probe() -> Result<(), String> {
    if std::env::var_os("STAFETO_RELIBC_SYSROOT").is_none() {
        relibc()?;
    }
    let kernel = build(Variant::Normal)?;
    const PROGRAMS: [ImageProgram; 11] = [
        ("init", "init", INIT_STACK_SIZE, &["table-posix-poll"]),
        ("uart", "uart", UART_STACK_SIZE, &[]),
        ("tty", "tty", TTY_STACK_SIZE, &["quiet-steps"]),
        POSIX_PROCS_PROGRAMS[1],
        ("pipe", "pipe", PIPE_STACK_SIZE, &["quiet-steps"]),
        POSIX_PROCS_PROGRAMS[3],
        POSIX_PROCS_PROGRAMS[4],
        ("posix-poll", "posix-poll", POSIX_STACK_SIZE, &[]),
        POSIX_PROCS_PROGRAMS[6],
        POSIX_PROCS_PROGRAMS[8],
        POSIX_PROCS_PROGRAMS[9],
    ];
    let image = build_boot_image("boot-posix-poll.img", &PROGRAMS, BOOT_PROFILE)?;
    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS).args(qemu::ICOUNT);
    let output = run_until(
        cmd,
        BOOT_TIMEOUT,
        Some("init: posix-poll ended: "),
        &kernel.elf,
    )?;
    qemu::expect_marker(&output, "posix-poll: ok")?;
    qemu::expect_stopped_on(
        &output,
        "init: posix-poll ended: exit code 0, not restarted",
    )?;
    check_watch_steps(&output.lines)
}

fn posix_pty_probe() -> Result<(), String> {
    posix_pty_probe_in(false)
}
fn posix_pty_steps() -> Result<(), String> {
    posix_pty_probe_in(true)
}

fn posix_pty_probe_in(steps: bool) -> Result<(), String> {
    if std::env::var_os("STAFETO_RELIBC_SYSROOT").is_none() {
        relibc()?;
    }
    busybox_build()?;
    let kernel = build(Variant::Normal)?;
    const PROGRAMS: [ImageProgram; 12] = [
        ("init", "init", INIT_STACK_SIZE, &["table-posix-pty"]),
        ("uart", "uart", UART_STACK_SIZE, &[]),
        ("tty", "tty", TTY_STACK_SIZE, &[]),
        POSIX_PROCS_PROGRAMS[1],
        ("pipe", "pipe", PIPE_STACK_SIZE, &[]),
        POSIX_PROCS_PROGRAMS[3],
        POSIX_PROCS_PROGRAMS[4],
        ("posix-pty", "posix-pty", POSIX_STACK_SIZE, &[]),
        (
            "busybox-probe",
            "busybox-probe",
            POSIX_STACK_SIZE,
            &["ash-interactive"],
        ),
        POSIX_PROCS_PROGRAMS[6],
        POSIX_PROCS_PROGRAMS[8],
        POSIX_PROCS_PROGRAMS[9],
    ];
    const STEPS: [ImageProgram; 12] = {
        let mut programs = PROGRAMS;
        programs[2].3 = &["quiet-steps"];
        programs[7].3 = &["clone-steps"];
        programs
    };
    let image = build_boot_image(
        if steps {
            "boot-posix-pty-steps.img"
        } else {
            "boot-posix-pty.img"
        },
        if steps { &STEPS } else { &PROGRAMS },
        BOOT_PROFILE,
    )?;
    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS).args(qemu::ICOUNT);
    let output = run_until(
        cmd,
        BOOT_TIMEOUT,
        Some("init: posix-pty ended: "),
        &kernel.elf,
    )?;
    qemu::expect_marker(&output, "posix-pty: ok")?;
    qemu::expect_stopped_on(&output, "init: posix-pty ended: exit code 0, not restarted")?;
    if steps {
        check_waits(&output.lines, &["5"], "terminal Clone steps")?;
        let measured = longest_steps(&output.lines, "5");
        for kind in [7, 65] {
            let ticks = measured
                .iter()
                .find(|row| row.0 == kind)
                .map_or(0, |row| row.1);
            if ticks == 0 || ticks > RAM_STEP_MAX {
                return Err(format!(
                    "terminal Clone 32: kind {kind} took {ticks} ticks, bound {RAM_STEP_MAX}"
                ));
            }
        }
    }
    Ok(())
}

/// The most a step of the terminal service's Watch takes with 16 elements.
const WATCH_FULL_MAX: u64 = 18_000;

fn check_watch_steps(lines: &[String]) -> Result<(), String> {
    for (tag, methods) in [("4", [14, 15, 16]), ("5", [25, 26, 27])] {
        check_waits(lines, &[tag], "watch steps")?;
        let steps = longest_steps(lines, tag);
        for &(kind, ticks, _) in &steps {
            if ticks == 0 || ticks > RAM_STEP_MAX {
                return Err(format!(
                    "watch service {tag}, kind {kind} exceeded {RAM_STEP_MAX}: {ticks}"
                ));
            }
        }
        let cases: Vec<String> = lines
            .iter()
            .filter(|line| line.starts_with("service case:"))
            .map(|line| line.replacen("service case:", "service step:", 1))
            .collect();
        let full = longest_steps(&cases, tag);
        for &(_, ticks, _) in &full {
            if ticks == 0 || ticks > RAM_STEP_MAX {
                return Err(format!("watch full case exceeded {RAM_STEP_MAX}: {ticks}"));
            }
        }
        // The pipe service's Watch holds 32 elements, the terminal's 16
        // (a poll of 32 makes two).
        let elements = if tag == "5" { 16 } else { 32 };
        for method in methods {
            if !full
                .iter()
                .any(|&(kind, ticks, detail)| kind == method && ticks != 0 && detail == elements)
            {
                return Err(format!(
                    "watch method {method} has no full {elements}-element measurement: {steps:?}"
                ));
            }
        }
        // The terminal service's Watch of 16 elements (two for a poll of 32) keeps a margin under
        // term B: its elements are met once for each description and the
        // descriptions are found by a bit test.
        if tag == "5"
            && let Some(&(kind, _, detail)) = steps
                .iter()
                .find(|&&(kind, _, detail)| methods.contains(&kind) && detail > 16)
        {
            return Err(format!(
                "terminal service: a Watch step of kind {kind} had {detail} elements, past 16"
            ));
        }
        if tag == "5"
            && let Some(&(kind, ticks, _)) = full
                .iter()
                .find(|&&(kind, ticks, _)| methods.contains(&kind) && ticks > WATCH_FULL_MAX)
        {
            return Err(format!(
                "terminal service: a Watch of 16 elements, kind {kind}, took {ticks}, past {WATCH_FULL_MAX}"
            ));
        }
        if ![64, 65].iter().all(|wanted| {
            steps
                .iter()
                .any(|&(kind, ticks, _)| kind == *wanted && ticks != 0)
        }) {
            return Err(format!(
                "watch service {tag} has no heartbeat/notification or Gone measurement"
            ));
        }
    }
    Ok(())
}
fn posix_jobs_probe() -> Result<(), String> {
    if std::env::var_os("STAFETO_RELIBC_SYSROOT").is_none() {
        relibc()?;
    }
    busybox_build()?;
    let kernel = build(Variant::Normal)?;
    const PROGRAMS: [ImageProgram; 10] = {
        let mut programs = POSIX_PROCS_PROGRAMS;
        programs[5].3 = &["jobs"];
        programs
    };
    let image = build_boot_image("boot-posix-jobs.img", &PROGRAMS, BOOT_PROFILE)?;
    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    let mut run = qemu::Run::start(cmd, qemu::Input::Null)?;
    let ended = run.expect_seen(
        "init: posix-procs ended: exit code 0, not restarted",
        BOOT_TIMEOUT,
    );
    let outcome = run.stop();
    ended?;
    qemu::expect_marker(&outcome, "posix-jobs: ok")
}

fn loader_channels_probe() -> Result<(), String> {
    if std::env::var_os("STAFETO_RELIBC_SYSROOT").is_none() {
        relibc()?;
    }
    let kernel = build(Variant::Normal)?;
    const PROGRAMS: [ImageProgram; 11] = [
        ("init", "init", INIT_STACK_SIZE, &["table-loader-channels"]),
        ("uart", "uart", UART_STACK_SIZE, &[]),
        ("tty", "tty", TTY_STACK_SIZE, &[]),
        POSIX_PROCS_PROGRAMS[1],
        POSIX_PROCS_PROGRAMS[2],
        POSIX_PROCS_PROGRAMS[3],
        POSIX_PROCS_PROGRAMS[4],
        (
            "posix-procs",
            "posix-procs",
            POSIX_STACK_SIZE,
            &["terminal"],
        ),
        POSIX_PROCS_PROGRAMS[6],
        POSIX_PROCS_PROGRAMS[8],
        POSIX_PROCS_PROGRAMS[9],
    ];
    let image = build_boot_image("boot-loader-channels.img", &PROGRAMS, BOOT_PROFILE)?;
    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    let mut run = qemu::Run::start(cmd, qemu::Input::Null)?;
    let ended = run.expect_seen(
        "init: posix-procs ended: exit code 0, not restarted",
        BOOT_TIMEOUT,
    );
    let outcome = run.stop();
    symbolize::backtrace(&outcome.lines, &kernel.elf);
    ended?;
    qemu::expect_marker(&outcome, "loader-channels: ok")
}

fn ramfs_gc_probe() -> Result<(), String> {
    relibc()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-ramfs-gc.img", &RAMFS_GC_PROGRAMS, BOOT_PROFILE)?;
    let mut command = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    command.args(qemu::HEADLESS).args(qemu::ICOUNT);
    let ended = "init: posix-files ended: exit code 0, not restarted";
    let output = run_until(command, BOOT_TIMEOUT, Some(ended), &kernel.elf)?;
    qemu::expect_stopped_on(&output, ended)?;
    qemu::expect_marker(
        &output,
        "ramfs-gc: binding and page reclamation both progress ok",
    )?;
    check_waits(&output.lines, &["2"], "RAM file service steps")?;
    let steps = longest_steps(&output.lines, "2");
    for kind in [22, 63, 65] {
        if !steps
            .iter()
            .any(|(seen, ticks, _)| *seen == kind && *ticks != 0)
        {
            return Err(format!(
                "RAM GC probe has no kind {kind} measurement: {steps:?}"
            ));
        }
    }
    if let Some((kind, ticks, _)) = steps.iter().find(|(_, ticks, _)| *ticks > RAM_STEP_MAX) {
        return Err(format!(
            "RAM GC kind {kind} took {ticks} ticks, past {RAM_STEP_MAX}: {steps:?}"
        ));
    }
    println!("RAM GC dispatches under icount (B {RAM_STEP_MAX}): {steps:?}");
    Ok(())
}

fn image_gates_probe(measured: bool, normal: bool) -> Result<(), String> {
    relibc()?;
    let kernel = build(Variant::Normal)?;
    const MEASURED: [ImageProgram; 6] = {
        let mut programs = IMAGE_GATES_PROGRAMS;
        programs[1].3 = &["image-gates", "steps"];
        programs[2].3 = &["image-probe", "steps"];
        programs
    };
    const NORMAL: [ImageProgram; 6] = {
        let mut programs = MEASURED;
        programs[1].3 = &["auth-probe", "steps"];
        programs[2].3 = &["steps"];
        programs[4].3 = &["image-gates-normal"];
        programs[5].3 = &["auth-probe"];
        programs
    };
    let (name, programs) = if normal {
        ("boot-image-gates-normal-steps.img", &NORMAL)
    } else if measured {
        ("boot-image-gates-steps.img", &MEASURED)
    } else {
        ("boot-image-gates.img", &IMAGE_GATES_PROGRAMS)
    };
    let image = build_boot_image(name, programs, BOOT_PROFILE)?;
    let mut command = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    command.args(qemu::HEADLESS);
    if measured {
        command.args(qemu::ICOUNT);
    }
    let ended = "init: posix-files ended: exit code 0, not restarted";
    let output = run_until(command, BOOT_TIMEOUT, Some(ended), &kernel.elf)?;
    qemu::expect_stopped_on(&output, ended)?;
    qemu::expect_marker(
        &output,
        if normal {
            "posix-files: normal SetId same OpenExec branch and genuine Abort ok"
        } else {
            "posix-files: actual Take Handoff and ambiguous SetId gates ok"
        },
    )?;
    if measured {
        check_waits(&output.lines, &["2"], "RAM file service steps")?;
        let steps = longest_steps(&output.lines, "2");
        let required: &[usize] = if normal {
            &[14, 20, 21, 22, 65]
        } else {
            &[14, 17, 20, 21, 22, 23, 65]
        };
        for &kind in required {
            if !steps.iter().any(|(k, ticks, _)| *k == kind && *ticks != 0) {
                return Err(format!(
                    "RAM image probe has no method {kind} measurement: {steps:?}"
                ));
            }
        }
        if let Some((kind, ticks, _)) = steps.iter().find(|(_, ticks, _)| *ticks > RAM_STEP_MAX) {
            return Err(format!(
                "RAM image kind {kind} took {ticks} ticks, past {RAM_STEP_MAX}: {steps:?}"
            ));
        }
        println!("RAM image dispatches under icount (B {RAM_STEP_MAX}): {steps:?}");
    }
    Ok(())
}

fn loader_info_probe() -> Result<(), String> {
    relibc()?;
    let kernel = build(Variant::Normal)?;
    const PROGRAMS: [ImageProgram; 6] = {
        let mut programs = LOADER_ABORT_PROGRAMS;
        programs[0].3 = &["table-posix-files", "loader-info"];
        programs[1].3 = &["image-info-probe", "steps"];
        programs[4].3 = &["image-info-probe"];
        programs[5].3 = &["image-info-probe"];
        programs
    };
    let image = build_boot_image("boot-loader-info.img", &PROGRAMS, BOOT_PROFILE)?;
    let mut command = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    command.args(qemu::HEADLESS);
    command.args(qemu::ICOUNT);
    let ended = "init: posix-files ended: exit code 0, not restarted";
    let output = run_until(command, BOOT_TIMEOUT, Some(ended), &kernel.elf)?;
    qemu::expect_stopped_on(&output, ended)?;
    qemu::expect_marker(
        &output,
        "posix-files: strict image metadata and incoming handle cleanup ok",
    )?;
    check_waits(&output.lines, &["2"], "RAM file service steps")?;
    let steps = longest_steps(&output.lines, "2");
    if let Some((kind, ticks, _)) = steps.iter().find(|(_, ticks, _)| *ticks > RAM_STEP_MAX) {
        return Err(format!(
            "RAM image metadata kind {kind} took {ticks} ticks, past {RAM_STEP_MAX}: {steps:?}"
        ));
    }
    println!("RAM image metadata dispatches under icount (B {RAM_STEP_MAX}): {steps:?}");
    Ok(())
}

fn loader_abort_probe(measured: bool) -> Result<(), String> {
    relibc()?;
    let kernel = build(Variant::Normal)?;
    const MEASURED: [ImageProgram; 6] = {
        let mut programs = LOADER_ABORT_PROGRAMS;
        programs[1].3 = &["auth-probe", "steps"];
        programs
    };
    let (name, programs) = if measured {
        ("boot-loader-abort-steps.img", &MEASURED)
    } else {
        ("boot-loader-abort.img", &LOADER_ABORT_PROGRAMS)
    };
    let image = build_boot_image(name, programs, BOOT_PROFILE)?;
    let mut command = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    command.args(qemu::HEADLESS);
    if measured {
        command.args(qemu::ICOUNT);
    }
    let ended = "init: posix-files ended: exit code 0, not restarted";
    let output = run_until(command, BOOT_TIMEOUT, Some(ended), &kernel.elf)?;
    qemu::expect_stopped_on(&output, ended)?;
    qemu::expect_marker(
        &output,
        "posix-files: genuine loader abort releases retained capture ok",
    )?;
    if measured {
        for count in [16, 96] {
            qemu::expect_marker(
                &output,
                &format!(
                    "posix-files: cleanup audit {count} jobs preserves retained byte and frontend quota ok"
                ),
            )?;
        }
        check_waits(&output.lines, &["2"], "RAM file service steps")?;
        let steps = longest_steps(&output.lines, "2");
        for kind in [19, 21, 22, 23, 63, 65] {
            if !steps.iter().any(|(k, ticks, _)| *k == kind && *ticks != 0) {
                return Err(format!(
                    "RAM cleanup audit has no kind {kind} measurement: {steps:?}"
                ));
            }
        }
        if let Some((kind, ticks, _)) = steps.iter().find(|(_, ticks, _)| *ticks > RAM_STEP_MAX) {
            return Err(format!(
                "RAM cleanup audit kind {kind} took {ticks} ticks, past {RAM_STEP_MAX}: {steps:?}"
            ));
        }
        println!("RAM cleanup audit dispatches under icount (B {RAM_STEP_MAX}): {steps:?}");
    }
    Ok(())
}

/// C operations observe the real Process identities and Files proofs.
fn ramfs_cleanup_probe() -> Result<(), String> {
    relibc()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image(
        "boot-ramfs-cleanup.img",
        &RAMFS_CLEANUP_PROGRAMS,
        BOOT_PROFILE,
    )?;
    let mut command = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    command.args(qemu::HEADLESS);
    let ended = "init: posix-files ended: exit code 0, not restarted";
    let output = run_until(command, BOOT_TIMEOUT, Some(ended), &kernel.elf)?;
    qemu::expect_stopped_on(&output, ended)?;
    qemu::expect_marker(&output, "ramfs-cleanup: ok")?;
    for owner in ["ramfs-owner-0", "ramfs-owner-1", "ramfs-owner-2"] {
        qemu::expect_marker(
            &output,
            &format!("init: {owner} ended: exit code 0, not restarted"),
        )?;
    }
    Ok(())
}

fn posix_files_probe() -> Result<(), String> {
    posix_files_run(false)
}

fn posix_files_run(measured: bool) -> Result<(), String> {
    posix_files_run_profile(measured, false)
}

fn posix_files_run_profile(measured: bool, data: bool) -> Result<(), String> {
    relibc()?;
    let kernel = build(Variant::Normal)?;
    const MEASURED: [ImageProgram; 5] = {
        let mut programs = POSIX_FILES_PROGRAMS;
        programs[1].3 = &["steps"];
        programs
    };
    const DATA: [ImageProgram; 5] = {
        let mut programs = POSIX_FILES_PROGRAMS;
        programs[0].3 = &["table-posix-files", "data-carrier-probe"];
        programs[1].3 = &["steps", "auth-probe"];
        programs[4].3 = &["data-carrier-probe"];
        programs
    };
    let programs = if data {
        &DATA
    } else if measured {
        &MEASURED
    } else {
        &POSIX_FILES_PROGRAMS
    };
    let name = if data {
        "boot-posix-data-steps.img"
    } else if measured {
        "boot-posix-files-steps.img"
    } else {
        "boot-posix-files.img"
    };
    let image = build_boot_image(name, programs, BOOT_PROFILE)?;
    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    if measured {
        cmd.args(qemu::ICOUNT);
    }
    let ended = "init: posix-files ended: exit code 0, not restarted";
    let output = run_until(cmd, BOOT_TIMEOUT, Some(ended), &kernel.elf)?;
    qemu::expect_stopped_on(&output, ended)?;
    qemu::expect_marker(&output, "posix-files: raw Change requests ok")?;
    qemu::expect_marker(&output, "posix-files: names and metadata functions ok")?;
    qemu::expect_marker(&output, "posix-files: layer names ok")?;
    qemu::expect_marker(&output, "posix-files: identity and proofs ok")?;
    if !data {
        qemu::expect_marker(
            &output,
            "posix-files: a lost reply of Start, Second, Step, Commit and Release leaves one effect",
        )?;
    }
    if measured {
        check_waits(&output.lines, &["2"], "RAM file service steps")?;
        let steps = longest_steps(&output.lines, "2");
        let required: &[usize] = if data {
            &[
                15, 19, 21, 25, 35, 36, 37, 38, 39, 40, 41, 42, 44, 45, 46, 47, 48, 65,
            ]
        } else {
            &[15, 19, 21, 25, 44, 45, 46, 47, 48, 65]
        };
        for &kind in required {
            if !steps.iter().any(|(k, ticks, _)| *k == kind && *ticks != 0) {
                return Err(format!(
                    "RAM credential probe has no method {kind} measurement: {steps:?}"
                ));
            }
        }
        if let Some((kind, ticks, _)) = steps.iter().find(|(_, ticks, _)| *ticks > RAM_STEP_MAX) {
            return Err(format!(
                "RAM method {kind} took {ticks} ticks, past {RAM_STEP_MAX}: {steps:?}"
            ));
        }
        println!("RAM credential dispatches under icount (B {RAM_STEP_MAX}): {steps:?}");
    }
    Ok(())
}

fn posix_lock_ring_probe(machine: &qemu::Machine) -> Result<(), String> {
    relibc()?;
    run_cmd(Command::new("python3").arg(root().join("tools/build-busybox.py")))?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image(
        "boot-posix-lock-ring.img",
        &POSIX_LOCK_RING_PROGRAMS,
        BOOT_PROFILE,
    )?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS).args(qemu::ICOUNT);
    let mut run = qemu::Run::start(cmd, qemu::Input::Null)?;
    let mut ended = 0u8;
    let result = (|| {
        while ended != 15 {
            let line = run.expect_line(
                "all four genuine payer families to exit",
                |line| line.starts_with("init: lock-ring-") && line.contains(" ended:"),
                Duration::from_secs(30),
            )?;
            for family in 0..4 {
                if line.starts_with(&format!("init: lock-ring-{family} ended:")) {
                    if line != format!("init: lock-ring-{family} ended: exit code 0, not restarted")
                    {
                        return Err(format!("genuine ring family failed: {line}"));
                    }
                    ended |= 1 << family;
                }
            }
        }
        Ok(())
    })();
    let outcome = run.stop();
    symbolize::backtrace(&outcome.lines, &kernel.elf);
    result?;
    for family in 0..4 {
        qemu::expect_marker(
            &outcome,
            &format!("posix-procs: genuine ring16 family {family} ok"),
        )?;
    }
    qemu::expect_marker(
        &outcome,
        "posix-procs: ring16 result deadlock=1 success=15 vertices=16 registrations=16 watches=16 ticks=",
    )?;
    Ok(())
}

fn posix_lifetimes_probe(machine: &qemu::Machine) -> Result<(), String> {
    relibc()?;
    run_cmd(Command::new("python3").arg(root().join("tools/build-busybox.py")))?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image(
        "boot-posix-lifetimes.img",
        &POSIX_LIFETIMES_PROGRAMS,
        BOOT_PROFILE,
    )?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    cmd.args(qemu::ICOUNT);
    let mut run = qemu::Run::start(cmd, qemu::Input::Null)?;
    let ended = run.expect_line(
        "the PID lifetime probe to exit",
        |line| line.starts_with("init: posix-procs ended:"),
        Duration::from_secs(30),
    );
    let outcome = run.stop();
    symbolize::backtrace(&outcome.lines, &kernel.elf);
    if ended? != "init: posix-procs ended: exit code 0, not restarted" {
        return Err("the PID lifetime probe failed".into());
    }
    qemu::expect_marker(&outcome, "posix-procs: PID lifetime page ok")?;
    for marker in [
        "posix-procs: public nonblocking locks, canonical fields, PID close and OFD fork ok",
        "posix-procs: public lock reply loss, exact keys, full GET receipt, numeric close and reuse ok ticks=",
        "posix-procs: lock depth within 16 KiB, nested SIGUSR1 close, siglongjmp and thread departure ok",
        "posix-procs: true WAIT unlock, SIGUSR1, restart, close/reuse and canonical success ok",
        "posix-procs: genuine FIFO oldest eligible Read, blocked older Write and later PID SET ok",
        "posix-procs: FIFO own dispatch ",
        "posix-procs: genuine WAIT End exact debts and live parent fork exec custody ok",
        "posix-procs: genuine PID cycle EDEADLK and OFD noncycle ok",
    ] {
        qemu::expect_marker(&outcome, marker)?;
    }
    qemu::expect_marker(
        &outcome,
        "RAM close event: exact replay, stale body, physical I/O and 32-reference birth cleanup ok",
    )?;
    for marker in [
        "POSIX close receipts: event loss, physical loss and helper reuse ok",
        "POSIX close signal: genuine SIGUSR1 siglongjmp preserves physical debt and reused fd ok",
        "POSIX close places: all 16 Closing and 16 Control slots retain independent progress ok",
    ] {
        qemu::expect_marker(&outcome, marker)?;
    }
    check_waits(&outcome.lines, &["2"], "RAM close event steps")?;
    let steps = longest_steps(&outcome.lines, "2");
    qemu::expect_marker(
        &outcome,
        "RAM native locks: genuine PID, OFD conflict, unlocked query, replay, cross-family release and late Start fence ok",
    )?;
    qemu::expect_marker(
        &outcome,
        "RAM native lock cancel: retained canonical blocker, lost reply, absent Start fence and separate Release ok",
    )?;
    qemu::expect_marker(
        &outcome,
        "RAM native lock departure: sixteen held outcomes and genuine paid label return without another RAM request ok",
    )?;
    for kind in [49, 50, 51, 52, 53, 66] {
        if !steps
            .iter()
            .any(|(measured, ticks, _)| *measured == kind && *ticks != 0)
        {
            return Err(format!(
                "RAM close event probe has no method {kind} measurement: {steps:?}"
            ));
        }
    }
    if let Some((kind, ticks, _)) = steps.iter().find(|(_, ticks, _)| *ticks > RAM_STEP_MAX) {
        return Err(format!(
            "RAM close event method {kind} took {ticks} ticks, past {RAM_STEP_MAX}: {steps:?}"
        ));
    }
    println!("RAM close event dispatches under icount (B {RAM_STEP_MAX}): {steps:?}");
    Ok(())
}

fn posix_procs_probe(machine: &qemu::Machine) -> Result<(), String> {
    relibc()?;
    // BusyBox is /bin/ls of the image's files (5c).
    run_cmd(Command::new("python3").arg(root().join("tools/build-busybox.py")))?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-posix-procs.img", &POSIX_NAMES_PROGRAMS, BOOT_PROFILE)?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    let mut run = qemu::Run::start(cmd, qemu::Input::Null)?;
    // The probe is the table's only record: its end is init's line, and
    // its children are processes of the service that init never hears of.
    // It ends in an exec (stage 10) of the role that exits with 42: init
    // reports the new image's end. The authenticated component proofs add
    // bounded IPC rounds across this large spawn/fork/exec scenario.
    let ended = run
        .expect_line(
            "the POSIX process probe to exit",
            |line| line.starts_with("init: posix-procs ended:"),
            Duration::from_secs(60),
        )
        .and_then(|line| {
            if line == "init: posix-procs ended: exit code 42, not restarted" {
                Ok(())
            } else {
                Err(format!("the POSIX process probe failed: {line}"))
            }
        });
    let outcome = run.stop();
    symbolize::backtrace(&outcome.lines, &kernel.elf);
    ended?;
    qemu::expect_marker(&outcome, "posix-procs: names ok")?;
    qemu::expect_marker(&outcome, "posix-procs: the names of posix_spawn ok")?;
    qemu::expect_marker(&outcome, "posix-procs: dup3 with O_CLOFORK across fork ok")?;
    qemu::expect_marker(&outcome, "posix-procs: ok")?;
    qemu::expect_marker(&outcome, "posix-procs: the last image ran")?;
    qemu::expect_marker(&outcome, "posix-procs: orphan saw ppid 1")?;
    // The first goal of 5c: /bin/ls from a file lists /etc, a line alone,
    // from a spawn and from an exec.
    if outcome.lines.iter().filter(|l| l.trim() == "motd").count() < 2 {
        return Err("ls of /etc printed `motd` fewer than twice".into());
    }
    // The new image of an exec whose old image ended first never runs.
    if outcome
        .lines
        .iter()
        .any(|l| l.contains("the image of a dead exec ran"))
    {
        return Err("an exec ran after its old image ended".into());
    }
    // The old image of an exec ends at ExecCommit.
    if outcome
        .lines
        .iter()
        .any(|l| l.contains("the old image lived past ExecCommit"))
    {
        return Err("an old image lived past its ExecCommit".into());
    }
    if outcome
        .lines
        .iter()
        .any(|l| l.contains("the old image set the clock"))
    {
        return Err("an old image set the clock with its record's new rights".into());
    }
    for marker in [
        // The pipe service (5e) registered with init.
        "pipe: ready",
        "posix-procs: a child inherits the mask and SIG_IGN",
        "posix-procs: a thread took SIGUSR1 after main left",
        "posix-procs: the last thread ran atexit",
        // Stage 7 (5c): ls of /etc from a file, argv and envp, set-ID.
        "posix-process: loader ready",
        "posix-procs: ls of /etc ended with 0",
        "posix-procs: args 4 [one two] [three] X=1",
        "posix-procs: setid uid 65534 euid 0 secure 1 fd 3",
        "posix-procs: nobody uid 65534 euid 65534",
        // Stage 8: the file actions' current directory.
        "posix-procs: the child's directory is /bin",
        // Stage 9: exec keeps the PID.
        "posix-procs: after exec pid",
        // The memory map of a program from a file (5d).
        "posix-procs: memory map ",
        // fork's copy (5d).
        "posix-procs: a bare fork copied the parent",
        "posix-procs: fork with the layer bound",
        "posix-procs: a forked child execs ls",
        "posix-procs: ash -c ran /bin/ls",
        "posix-procs: 40 forks of a parent with six threads",
        // Pipes (5e): within a process and across fork.
        "posix-procs: pipes within a process and across fork",
        // The signals of the shell and setpgid of a child of fork (5e).
        "posix-procs: shell signals and setpgid of a child",
        // /dev/null (5e): 1 MiB written, nothing kept.
        "posix-procs: /dev/null drops 1 MiB",
        // Across spawn, fork and exec: cat on two pipes, the ends' numbers,
        // the waiters of an old image, the loader's refusal, ash's pipeline.
        "posix-procs: ash -c ran ls | cat",
        "posix-procs: pipes across spawn and exec",
    ] {
        qemu::expect_marker(&outcome, marker)?;
    }
    let number = |prefix: &str| -> Result<Vec<i64>, String> {
        let line = outcome
            .lines
            .iter()
            .find_map(|l| l.trim_end().strip_prefix(prefix))
            .ok_or_else(|| format!("no line {prefix:?}"))?;
        line.split(|c: char| !c.is_ascii_digit())
            .filter(|w| !w.is_empty())
            .map(|w| w.parse().map_err(|e| format!("{line:?}: {e}")))
            .collect()
    };
    let parent = number("posix-procs: parent ")?;
    let child = number("posix-procs: child ")?;
    // "parent P spawned C" and "child C of P".
    if parent.len() != 2 || child != [parent[1], parent[0]] || parent[0] < 256 {
        return Err(format!(
            "the child says {child:?}, the parent {parent:?}: no child of that parent"
        ));
    }
    println!("C POSIX process probe passed: posix_spawn and exec from files");
    Ok(())
}

/// The most the own part of a Vouch or a RetainedLoader may take, in ticks
/// under -icount. Seen with 128 and 248 children: Vouch 4,849 to 5,636,
/// RetainedLoader 4,798 to 6,013; preemption by holders of the lock at level
/// 31 adds noise of up to 1,200 ticks to either. 8,000 is a third over the
/// largest, and a walk over the entries costing more than about 13 ticks an
/// entry with 248 children fails it (5b's Vouch took 539 ticks an entry).
const VOUCH_TICKS_MAX: u64 = 8_000;

/// Term B of the blocking of every level, in ticks under -icount: the
/// budget the response-time analysis gives the kernel and every step of a
/// service is compared with. The number is the longest row of the `B on`
/// line of `kernel_tests` (icount build) at 637d3a6, which lowered it from
/// 20 538; the kernel has run under KERNEL_B_MAX since the stage Handles
/// went by half chunks, so the room between them belongs to the services.
/// The budget of the services' steps. `kernel_tests` fails above
/// `KERNEL_B_MAX`; only the tests inside the kernel and tests/posix-tty
/// print their numbers.
const TERM_B: u64 = 20_410;

/// The bound on the kernel itself: the longest row of the `B on` line of
/// `kernel_tests` (icount build) may not pass it. The longest paths at
/// the time are first_map (16 738 on 512M) and release (16 060 on 2G);
/// growth up to the bound goes unremarked, beyond it needs a decision
/// (another split, or a higher bound with the reason written down), so
/// that the kernel cannot spend the room TERM_B promises the services.
const KERNEL_B_MAX: u64 = 18_000;
const _: () = assert!(KERNEL_B_MAX < TERM_B);

/// The guards of the paths epoch 2 made shorter, in ticks under -icount on
/// the normal build (`init_tests`, row `null` of `normal build`), on the
/// test build (`kernel_tests`, row `threads_ready` of `teardown portions`)
/// and on the benchmark's image (`rtbench --short --icount`, the `min` of
/// the three `s5_*` rows: the whole path of `pthread_kill` to the handler
/// of the target, in instructions). The first two sit four ticks above the
/// measure at the end of epoch 2 (262 and 12 764), the third sixteen above
/// the measure (2 754; 2 756 at e0c670e, when the distributor saved the
/// flags twice, and 4f3c7d0 had 2 562); a higher number needs a decision
/// with its reason written down.
///
/// Rules for a guard that fires (the paths are deterministic under -icount,
/// so a firing is no noise and a repeat does not clear it):
/// 1. The commit that trips a guard either gives the path back or raises
///    the constant in the same commit, with a line here: the new number,
///    the commit, the reason.
/// 2. When the source of the path did not change (the compiler moved the
///    code) and the excess is at most `NULL_SLACK` for `null`,
///    `THREADS_READY_SLACK` for `threads_ready` (one instruction a thread)
///    or `S5_ICOUNT_SLACK` for the S5 rows, the author raises it with that
///    line; a larger excess or a changed path needs the decision of the
///    reviewer of the kernel (for the S5 rows, of the realtime reviewer:
///    `rtbench --short --icount --marks` prints the segments of the path).
/// 3. A change of the Rust toolchain measures both rows again and sets the
///    constants anew in the same commit.
/// 4. The guard looks down too: when the room is larger than the slack,
///    `guard_lower_hint` prints "lower <NAME> to N", the measure plus the
///    room the guard keeps (4, and 16 for S5; it does not fail), and
///    the next commit lowers the constant, so that a shorter path does not
///    turn into room for later growth.
const NULL_MAX: u64 = 266;
const THREADS_READY_MAX: u64 = 12_768;
const S5_ICOUNT_MAX: u64 = 2_770;
/// The room above which a guard asks to be lowered (rule 4).
const NULL_SLACK: u64 = 16;
/// The room each guard keeps above its measure when it is set or lowered.
const NULL_KEEP: u64 = 4;
const THREADS_READY_KEEP: u64 = 4;
const S5_ICOUNT_KEEP: u64 = 16;
const THREADS_READY_SLACK: u64 = 128;
const S5_ICOUNT_SLACK: u64 = 16;

/// The most one step of a service may take (one READ_INTO of up to
/// proto_fs::READ_INTO_MAX bytes in the RAM file service's loop, for
/// instance): term B, in ticks under -icount.
const RAM_STEP_MAX: u64 = TERM_B;

/// The steps of the process service that are longer than term B today,
/// until step 5z splits them: (kind, name, the limit with 4 branches of
/// children (`process-steps 4`), the limit with 7 (`ci` and the plain
/// command)). A step above its number fails `process-steps`; a step at or
/// under B shows that its entry can go. Each number is the largest of
/// four runs at e1-g2-steps (identical to the tick, since -icount is
/// deterministic for one build; with 4 and 7 branches: Create 61,378 and
/// 61,378, SpawnStart 92,323 and 92,556, ExecStart 51,039 and 50,833,
/// ForkStart 53,737 and 54,153) plus NOISE_MARGIN; ForkStart again as the
/// largest of four runs at the head of E1 with 4 and with 7 branches
/// (53,772 and 55,793: the pin of relibc a5adc5f8, a table entry in
/// `sysconf`, moved the 7-branch figure up from 54,610 at 30f48fe7).
/// ExecStart with 7 branches is 52,895 (the largest of the runs at
/// a604c161; 52,562 at the head of E3-1 part 1) since the probe runs the
/// raw change jobs among the crowd. No step of the loop drains the closed
/// ends of the identity sessions the probe clones: the thread `ends::taker`
/// of services/process/src/ends.rs receives them one at a time, each a
/// bounded call. The run with STEPS_SESSIONS (identity sessions cloned and
/// closed before the exec steps, beside the one of the change stages)
/// shows it: 1, 8 and 32 closed sessions give ExecStart 50,888, 50,670
/// and 50,491, so the step does not grow with their number. The same
/// source with one more call that does nothing (0 sessions) gives 50,888
/// where the head gives 52,562: the figure moves by about 1,700 with the
/// layout of the code. The
/// margin covers what moves between builds: the layout of the code and the processes of the
/// level above that run in the middle of a step (SpawnStart was 92,262 and
/// 93,009 at 4e9abf5 and 92,369 at d7743c9 with the same source of the
/// step).
/// SpawnStart with 7 branches is 94,134 (95,634 with the margin): a run
/// of fix round 2 of E3-1 part 1 with another layout of the code of the
/// probe gave 94,134, 1,578 over the base of 92,556 that held before, more
/// than the margin; the head of that round gives 92,231. The step is O(1)
/// (one page of the loader's data is copied, `start_child` of
/// services/process/src/main.rs), so the figure moves with the layout of
/// the code and with the processes of the level above that run in the
/// middle of the step. The entry goes in E5 (rv8.P3: Create, SpawnStart,
/// ExecStart and ForkStart are cut into pieces no longer than B), and the
/// base for 4 branches stays. Raising it again needs a new look at
/// CALL_WAIT_MAX.
const PROCESS_STEPS_ABOVE_B: [(usize, &str, u64, u64); 4] = [
    (1, "Create", 61_378 + NOISE_MARGIN, 61_378 + NOISE_MARGIN),
    (
        22,
        "SpawnStart",
        92_323 + NOISE_MARGIN,
        94_134 + NOISE_MARGIN,
    ),
    (
        28,
        "ExecStart",
        51_039 + NOISE_MARGIN,
        52_895 + NOISE_MARGIN,
    ),
    (
        34,
        "ForkStart",
        53_772 + NOISE_MARGIN,
        55_793 + NOISE_MARGIN,
    ),
];

/// The room the limits of PROCESS_STEPS_ABOVE_B leave over the largest
/// measured step, in ticks: 1,200 is the noise the experts saw between
/// builds, rounded up.
const NOISE_MARGIN: u64 = 1_500;

/// The kinds of the lines of the RAM file service (tag 2), by the numbers
/// of proto_fs::Method.
const RAM_STEP_KINDS: [(usize, &str); 21] = [
    (1, "Open"),
    (13, "ReadAt"),
    (14, "OpenExec"),
    (15, "Clone"),
    (17, "ReadInto"),
    (19, "Bind"),
    (20, "BindPending"),
    (21, "ResolveStart"),
    (22, "ResolveStep"),
    (23, "ResolveCancel"),
    (24, "ResolveSecond"),
    (25, "FinishBinding"),
    (34, "CloneExact"),
    (44, "ChangeStart"),
    (45, "ChangeSecond"),
    (46, "ChangeStep"),
    (47, "ChangeQuery"),
    (48, "ChangeRelease"),
    (64, "notification"),
    (65, "maintenance"),
    (66, "session gone"),
];

/// The most a step of a service may wait in `send` for the answer of
/// another, in ticks under -icount. The wait measures other services' work
/// (their own steps carry their own limits, each against term B) and
/// the processes of higher levels that run in the middle of it: a send to
/// init (level 63) in a heartbeat and its reply, 200,000 seen once in a
/// volley of the steps probe's crowd. For the response-time analysis the
/// wait of a client is a blocking term: C_ipc, the longest step of the
/// callee and the step of the request itself.
const WAIT_MAX: u64 = 500_000;

/// The most a step may wait for the answer of a service in a call that is
/// no heartbeat, in ticks under -icount: one round trip (C_ipc about
/// 2,000), the longest step of the process service that may be running
/// (SpawnStart, 95,634 with its margin), and the step of the request
/// itself (term B), with room: 95,634 + 20,410 + 2,034 = 118,078 under
/// 120,000, 1,922 of room, so a next rise of SpawnStart needs a new look
/// at this limit. Seen at most 9,946 (ramfs FinishBinding with 248
/// children).
const CALL_WAIT_MAX: u64 = 120_000;

/// The kinds of the lines of the pipe service (tag 4), by the numbers of
/// proto_pipe::Method.
const PIPE_STEP_KINDS: [(usize, &str); 15] = [
    (1, "Create"),
    (2, "ReadStart"),
    (3, "ReadTake"),
    (4, "ReadCancel"),
    (5, "WriteStart"),
    (6, "WriteTake"),
    (7, "WriteCancel"),
    (8, "Close"),
    (9, "Clone"),
    (10, "GetFlags"),
    (11, "SetFlags"),
    (12, "Stat"),
    (13, "Abandon"),
    (64, "heartbeat: its own part, the send to init is the wait"),
    (65, "own step: a description let go of, a session gone"),
];

/// The kinds of the lines `service step: T kind K N ticks detail D` of the
/// process service (tag 1), by the numbers of proto_process::Method.
const STEP_KINDS: [(usize, &str); 17] = [
    (1, "Create"),
    (13, "Kill"),
    (21, "Vouch"),
    (53, "RetainedLoader"),
    (22, "SpawnStart"),
    (23, "Boot"),
    (24, "Take"),
    (25, "SpawnCommit"),
    (28, "ExecStart"),
    (29, "ExecCommit"),
    (31, "Replace"),
    (34, "ForkStart"),
    (35, "ForkCommit"),
    (36, "ForkAbort"),
    (10, "WaitStart"),
    (64, "notification"),
    (66, "session gone"),
];

/// The kinds of the lines `loader step: kind K N ticks detail D` of a
/// loader that copies a fork (services/loader, feature `steps`), each a
/// kernel call or the copy of one piece.
const LOADER_STEP_KINDS: [(usize, &str); 9] = [
    (1, "mem_create"),
    (2, "map of the new object"),
    (3, "mem_map of a piece"),
    (4, "copy of a piece"),
    (5, "mem_unmap of a piece"),
    (6, "remap with the access"),
    (7, "handle_duplicate"),
    (8, "Regions"),
    (9, "Go, the whole copy"),
];

/// The longest step of each kind in `lines`: (kind, ticks, detail), the
/// last line of a kind being its longest, since each prints only when it
/// grows.
fn longest_steps(lines: &[String], tag: &str) -> Vec<(usize, u64, u64)> {
    let mut out: Vec<(usize, u64, u64)> = Vec::new();
    for line in lines {
        let words: Vec<&str> = line.split_whitespace().collect();
        let [
            "service",
            "step:",
            line_tag,
            "kind",
            kind,
            ticks,
            "ticks",
            "detail",
            detail,
        ] = words.as_slice()
        else {
            continue;
        };
        if *line_tag != tag {
            continue;
        }
        let (Ok(kind), Ok(ticks), Ok(detail)) = (kind.parse(), ticks.parse(), detail.parse())
        else {
            continue;
        };
        match out.iter_mut().find(|(k, ..)| *k == kind) {
            Some(row) => *row = (kind, ticks, detail),
            None => out.push((kind, ticks, detail)),
        }
    }
    out
}

/// The longest wait of each kind in `lines`: (kind, wait, whole step), from
/// the lines `service wait: T kind K W ticks of A` that `rt` prints (feature
/// `step-stats`) when the wait of a kind grows, so the last line of a kind
/// is its longest. W is the time the step spent in `send` waiting for
/// another service, A the whole step of that case.
fn longest_waits(lines: &[String], tag: &str) -> Vec<(usize, u64, u64)> {
    let mut out: Vec<(usize, u64, u64)> = Vec::new();
    for line in lines {
        let words: Vec<&str> = line.split_whitespace().collect();
        let [
            "service",
            "wait:",
            line_tag,
            "kind",
            kind,
            wait,
            "ticks",
            "of",
            whole,
        ] = words.as_slice()
        else {
            continue;
        };
        if *line_tag != tag {
            continue;
        }
        let (Ok(kind), Ok(wait), Ok(whole)) = (kind.parse(), wait.parse(), whole.parse()) else {
            continue;
        };
        match out.iter_mut().find(|(k, ..)| *k == kind) {
            Some(row) => *row = (kind, wait, whole),
            None => out.push((kind, wait, whole)),
        }
    }
    out
}

/// The wait of kind `kind` in `waits`, 0 when none.
fn wait_of(waits: &[(usize, u64, u64)], kind: usize) -> u64 {
    waits.iter().find(|r| r.0 == kind).map_or(0, |r| r.1)
}

/// Fails when a wait in the lines of the services `tags` passes its limit
/// (WAIT_MAX for the heartbeat, kind 64; CALL_WAIT_MAX for the others), or
/// when `rt` cut an accounting that added up to more than its step.
fn check_waits(lines: &[String], tags: &[&str], who: &str) -> Result<(), String> {
    if let Some(line) = lines.iter().find(|l| l.starts_with("service wait cut:")) {
        return Err(format!("{who}: the accounting of a wait was cut: {line}"));
    }
    for tag in tags {
        for (kind, wait, whole) in longest_waits(lines, tag) {
            let limit = if kind == 64 { WAIT_MAX } else { CALL_WAIT_MAX };
            if wait > limit {
                return Err(format!(
                    "{who} (tag {tag}): kind {kind} waited {wait} ticks of a step of {whole}, past {limit}"
                ));
            }
        }
    }
    Ok(())
}

/// Whether the long rmdir of the starvation line (G1 of 5i-5b) ends within
/// ten seconds against the flood of utimensat: "no" until 5i-5b step 2 (a
/// change of the file raised the epoch every operation proved its path in),
/// "yes" since the epoch of a directory (a change of a file raises nothing).
/// A change either way is a change of the expectation, made here.
const STARVATION_ENDS_WITHIN_10_S: &str = "yes";

/// The most repeats of JOBS_FULL one thread of a volley makes (G6): the wait
/// for room doubles from one millisecond to sixteen.
const VOLLEY_REPEATS_MAX: u64 = 64;

/// The longest step of the process service under -icount with the crowd
/// of children of tests/posix-procs in its steps mode: kill(-1), spawn,
/// exec, the ends of all, and a Vouch with the identity channel full.
/// The crowd is `branches` branches of 32 children each (up to 7; with 7,
/// 24 children of the probe's own beside them).
/// Prints a row for each kind of step, checks that the longest Vouch stays
/// under VOUCH_TICKS_MAX, and the numbers go to `target/measure`.
/// The lines of the operations on names that the steps probe prints before the
/// crowd (names-volley.c): the times of the operations alone, the long rmdir
/// against the loop of utimensat (its restarts and whether it ended within ten
/// seconds), the long operations against the other floods (G2 to G5), and the
/// volley of 112 renames, which
/// all end and in which a Start is refused with JOBS_FULL and repeated. The
/// lines go to the output for the report.
fn names_lines(lines: &[String]) -> Result<Vec<String>, String> {
    let shown: Vec<&String> = lines
        .iter()
        .filter(|line| line.starts_with("posix-procs: names "))
        .collect();
    let find = |what: &str| {
        shown
            .iter()
            .find(|line| line.contains(what))
            .map(|line| line.as_str())
            .ok_or_else(|| format!("the steps probe printed no line with {what:?}"))
    };
    for row in [
        "names time a missing component:",
        "names time unlink /tmp/a:",
        "names time rmdir:",
        "names time chdir to depth 64:",
        "names time getcwd at depth 64:",
        "names time a path of 32 links:",
        "names time rename of a directory under a chain 64 deep:",
        "names time rmdir with a full table:",
        "names thread cost:",
    ] {
        find(row)?;
    }
    // G1: the long rmdir against the loop of utimensat of a file of its own:
    // It ends with the same request count and at most 2.5 times the time alone.
    let starvation = find("names starvation:")?;
    let verdict = format!("finished within 10 s: {STARVATION_ENDS_WITHIN_10_S}");
    if !starvation.contains(&verdict) {
        return Err(format!(
            "the starvation line does not say {verdict:?}: update the expectation \
             STARVATION_ENDS_WITHIN_10_S if the change is meant: {starvation}"
        ));
    }
    let starvation_line = [starvation.to_owned()];
    let number = |lines: &[String], prefix: &str| {
        qemu::number_after(lines, prefix)
            .ok_or_else(|| format!("the line has no number after {prefix:?}: {lines:?}"))
    };
    if number(&starvation_line, "against a loop of utimensat: ")? != 0 {
        return Err(format!("G1: the long rmdir restarted: {starvation}"));
    }
    let (took, alone) = (
        number(&starvation_line, "took ")?,
        number(&starvation_line, "alone ")?,
    );
    let requests = number(&starvation_line, ", requests ")?;
    let alone_requests = number(&starvation_line, "alone requests ")?;
    if requests != alone_requests || requests == 0 {
        return Err(format!(
            "G1: request count changed from {alone_requests} to {requests}: {starvation}"
        ));
    }
    if took.saturating_mul(2) > alone.saturating_mul(5) {
        return Err(format!(
            "G1: the long rmdir took {took} ticks against the flood, more than 2.5 times the \
             {alone} ticks it takes alone: {starvation}"
        ));
    }
    // G2 and G3: a long path of links against the creation and removal of a
    // name elsewhere, the rename of a directory under a chain of 64 against
    // the mode of a file: both end, with no restart. G4 and G5 (the same
    // directory, the moves of directories) are printed for the report.
    for (tag, what) in [
        ("G2", "a path of 32 links"),
        ("G3", "the rename of a directory"),
        ("G2b", "a rename against a colliding name"),
    ] {
        let line = find(&format!("names interference {tag}:"))?;
        if !line.contains("0 restarts, finished within 10 s: yes") || !line.contains(what) {
            return Err(format!(
                "{tag}: the operation must end within 10 s with no restart: {line}"
            ));
        }
    }
    for tag in ["G4", "G5"] {
        find(&format!("names interference {tag}:"))?;
    }
    // The volley of 112 renames in one directory, and the same with a
    // directory for each process: both end in all renames, both give the
    // numbers 5i-5b compares with.
    for (what, volley) in [
        ("common directory", find("names volley:")?),
        (
            "directory for each process",
            find("names volley in directories:")?,
        ),
    ] {
        if !volley.contains("112 renames, all done") {
            return Err(format!(
                "the volley ({what}) did not end in 112 renames: {volley}"
            ));
        }
        let lines = [volley.to_owned()];
        for number in [
            "the most repeats of JOBS_FULL of one thread ",
            "the most restarts of one rename ",
            "the longest rename ",
        ] {
            qemu::number_after(&lines, number)
                .ok_or_else(|| format!("the volley ({what}) line has no {number:?}: {volley}"))?;
        }
        // G6: the wait for room keeps the repeats of a thread down.
        let repeats =
            qemu::number_after(&lines, "the most repeats of JOBS_FULL of one thread ").unwrap_or(0);
        if repeats > VOLLEY_REPEATS_MAX {
            return Err(format!(
                "G6: a thread of the volley ({what}) repeated its Start {repeats} times, past \
                 {VOLLEY_REPEATS_MAX}: {volley}"
            ));
        }
    }
    let repeats = qemu::number_after(
        &[find("names volley:")?.to_owned()],
        "repeats of JOBS_FULL of one thread ",
    )
    .unwrap_or(0);
    if repeats == 0 {
        return Err(format!(
            "no thread of the volley met JOBS_FULL, the refused Start was not exercised: {}",
            find("names volley:")?
        ));
    }
    find("names volley ok")?;
    // A process that goes in the middle of a prepaid rename, by _exit and by
    // execve: the names stay, and the places of the root come back.
    find("names gone ok")?;
    // The worst states of the steps of the service built on purpose: a Start
    // into a table of 127 jobs with two paths of 511 bytes and a descriptor
    // for a base, and the restart after a stale proof at the commit of a
    // rename of a directory over an empty one.
    let publish = find("names bounds commit after 500 rival names: 0 restarts")?;
    let publish_line = [publish.to_owned()];
    let ticks = number(&publish_line, ", commit ")?;
    let baseline = number(&publish_line, "baseline ")?;
    if ticks == 0 || baseline == 0 || ticks > baseline.saturating_add(NOISE_MARGIN) {
        return Err(format!("publication grew with 500 rival names: {publish}"));
    }
    for count in [1, 32] {
        let row = find(&format!("names bounds reclaim: {count} nodes with pages"))?;
        if !row.contains(&format!("backlog {count} -> {}", count + 1))
            || !row.ends_with("0 restarts")
        {
            return Err(format!(
                "the reclamation commit has wrong queue counts: {row}"
            ));
        }
        let pages = row
            .split(", pages ")
            .nth(1)
            .ok_or_else(|| format!("no paid pages in {row}"))?;
        let pages_line = [format!("pages {pages}")];
        let before = number(&pages_line, "pages ")?;
        let after = number(&pages_line, " -> ")?;
        if before < count || after + u64::from(count >= 32) != before {
            return Err(format!(
                "the reclamation commit released the wrong number of pages: {row}"
            ));
        }
    }
    find("names bounds ok")?;
    Ok(shown.iter().map(|line| (*line).clone()).collect())
}

fn process_steps(machine: &qemu::Machine, branches: u32) -> Result<(), String> {
    relibc()?;
    let kernel = build(Variant::Normal)?;
    let image = write_boot_image_with(
        "boot-posix-steps.img",
        &POSIX_STEPS_PROGRAMS,
        BOOT_PROFILE,
        &[("STEPS_BRANCHES", &branches.to_string())],
    )?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    cmd.args(qemu::ICOUNT);
    // The probe of the departed process takes a few seconds of the host's
    // clock. A service that does not give back the job of a process that
    // went keeps the probe waiting, and in a guest the service starves (it
    // spins in its maintenance) the probe cannot say so: the run is cut here.
    let outcome = qemu::run_until_staged(
        cmd,
        STEPS_TIMEOUT,
        Some("init: posix-procs ended"),
        Some(qemu::Stage {
            after: "posix-procs: names volley ok",
            until: "posix-procs: names gone ok",
            within: GONE_PROBE_TIMEOUT,
        }),
    )?;
    symbolize::backtrace(&outcome.lines, &kernel.elf);
    let dir = target_dir().join("measure");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let log = dir.join("process-steps.log");
    std::fs::write(&log, outcome.lines.join("\n") + "\n")
        .map_err(|e| format!("{}: {e}", log.display()))?;
    if outcome
        .lines
        .iter()
        .any(|l| l.contains("posix-procs: names volley ok"))
        && !outcome
            .lines
            .iter()
            .any(|l| l.contains("posix-procs: names gone ok"))
    {
        let tail: Vec<&String> = outcome.lines.iter().rev().take(6).collect();
        return Err(format!(
            "the probe of the departed process printed no \"names gone ok\" within {GONE_PROBE_TIMEOUT:?} \
             of the volley: the service does not give back the job of a process that went, or the places \
             stay taken; the last lines, the last first: {tail:?}"
        ));
    }
    qemu::expect_marker(&outcome, "posix-procs: steps done")?;
    for line in names_lines(&outcome.lines)? {
        println!("{line}");
    }
    let rows = longest_steps(&outcome.lines, "1");
    let ram = longest_steps(&outcome.lines, "2");
    let pipe = longest_steps(&outcome.lines, "4");
    // The loader's lines, as the services' with the tag 3.
    let loader_lines: Vec<String> = outcome
        .lines
        .iter()
        .filter_map(|l| l.strip_prefix("loader step: "))
        .map(|l| format!("service step: 3 {l}"))
        .collect();
    let loader = longest_steps(&loader_lines, "3");
    if rows.is_empty() {
        return Err("the process service printed no step".into());
    }
    // The volleys armed the crowd, and the clock asked Vouch with every
    // identity session in the channel: Vouch reads the label of the copy
    // from the kernel (object_info LABEL) and stays as short as with no
    // crowd at all.
    let live = qemu::number_after(&outcome.lines, "posix-procs: steps ").unwrap_or(0);
    let vouch = rows.iter().find(|(k, ..)| *k == 21).map_or(0, |r| r.1);
    if vouch == 0 || vouch > VOUCH_TICKS_MAX {
        return Err(format!(
            "the longest Vouch took {vouch} ticks with {live} children, past {VOUCH_TICKS_MAX}"
        ));
    }
    let retained = rows.iter().find(|r| r.0 == 53).map_or(0, |r| r.1);
    if retained == 0 || retained > VOUCH_TICKS_MAX {
        return Err(format!(
            "RetainedLoader took {retained} ticks with {live} children, past {VOUCH_TICKS_MAX} or none"
        ));
    }
    // One READ_INTO is a step of the RAM file service at level 40 whose
    // copy is bounded by READ_INTO_MAX; it stays under term B.
    let read_into = ram.iter().find(|(k, ..)| *k == 17).map_or(0, |r| r.1);
    if read_into == 0 || read_into > RAM_STEP_MAX {
        return Err(format!(
            "the RAM file service: READ_INTO took {read_into} ticks, past {RAM_STEP_MAX}: {ram:?}"
        ));
    }
    // Authentication admission, each proof step, effects and notified cleanup
    // are all full service dispatches under the same unchanged term B.
    if let Some((kind, ticks, _)) = ram.iter().find(|(_, ticks, _)| *ticks > RAM_STEP_MAX) {
        return Err(format!(
            "the RAM file service: method {kind} took {ticks} ticks, past {RAM_STEP_MAX}: {ram:?}"
        ));
    }
    // ForkStart makes a process as SpawnStart does and stays within it
    // (5d); the copy of a fork has run, in steps of the loader.
    let longest = |kind: usize| rows.iter().find(|(k, ..)| *k == kind).map_or(0, |r| r.1);
    let (spawn, fork_start, fork_commit) = (longest(22), longest(34), longest(35));
    if fork_start == 0 || fork_commit == 0 || fork_start > spawn {
        return Err(format!(
            "ForkStart took {fork_start} ticks and ForkCommit {fork_commit}, SpawnStart {spawn}"
        ));
    }
    // Every step of the process service stays under term B but the four
    // that the list PROCESS_STEPS_ABOVE_B holds, each within its number.
    for &(kind, name, at_4, at_7) in &PROCESS_STEPS_ABOVE_B {
        let limit = if branches == 4 { at_4 } else { at_7 };
        let ticks = longest(kind);
        if ticks == 0 || ticks > limit {
            return Err(format!(
                "the process service: {name} took {ticks} ticks, past its exception {limit} (B {TERM_B})"
            ));
        }
        let verdict = if ticks > TERM_B {
            format!("{} over B", ticks - TERM_B)
        } else {
            "under B: remove it from PROCESS_STEPS_ABOVE_B".to_owned()
        };
        println!("process service {name}: {ticks} of exception {limit}, B {TERM_B}: {verdict}");
    }
    if let Some((kind, ticks, _)) = rows.iter().find(|(kind, ticks, _)| {
        *ticks > TERM_B && !PROCESS_STEPS_ABOVE_B.iter().any(|(k, ..)| k == kind)
    }) {
        return Err(format!(
            "the process service: kind {kind} took {ticks} ticks, past B {TERM_B} and not in the exceptions"
        ));
    }
    if !loader.iter().any(|(k, ..)| *k == 9) {
        return Err("no loader step of a copy: the forks did not run".into());
    }
    // The five methods of the change jobs (44 to 48) ran among the crowd, and
    // the longest of each stays under term B like every step of the service.
    for kind in 44..=48 {
        let ticks = ram.iter().find(|(k, ..)| *k == kind).map_or(0, |r| r.1);
        if ticks == 0 || ticks > RAM_STEP_MAX {
            return Err(format!(
                "the RAM file service: change method {kind} took {ticks} ticks, none or past {RAM_STEP_MAX}: {ram:?}"
            ));
        }
    }
    // A fork uses CloneExact to copy its retained descriptor list.
    let clone = ram.iter().find(|(k, ..)| *k == 34).map_or(0, |r| r.1);
    if clone == 0 || clone > RAM_STEP_MAX {
        return Err(format!(
            "the RAM file service: CloneExact took {clone} ticks, past {RAM_STEP_MAX}: {ram:?}"
        ));
    }
    // Every step of the pipe service (5e) stays under term B: a copy of
    // one message and up to 8 notifications, one description of a session
    // that went, a Clone of up to 32 ends, the cancels, the flags, Stat
    // and Abandon. The probe's role steppipes makes each of them, the
    // first ones at their longest.
    for kind in [2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 65] {
        let ticks = pipe.iter().find(|(k, ..)| *k == kind).map_or(0, |r| r.1);
        if ticks == 0 || ticks > RAM_STEP_MAX {
            return Err(format!(
                "the pipe service: kind {kind} took {ticks} ticks, past {RAM_STEP_MAX} or none: {pipe:?}"
            ));
        }
    }
    // Every kind counts the own part of the step, the heartbeat too: its
    // send to init and the wait for the reply are the wait of the step
    // (below), and a volley of the crowd's processes at a higher level may
    // run in the middle of it.
    if let Some(row) = pipe.iter().find(|r| r.1 > RAM_STEP_MAX) {
        return Err(format!("the pipe service: a step past term B: {row:?}"));
    }
    // The entropy device's driver (tag 10): its own steps, under term B.
    let driver = longest_steps(&outcome.lines, "10");
    if let Some(row) = driver.iter().find(|r| r.1 > RAM_STEP_MAX) {
        return Err(format!(
            "the entropy device's driver: a step past term B: {row:?}"
        ));
    }
    // The entropy service (tag 11): CLONE for each child of the crowd,
    // whose cost stays the same with the live clones (entropy::CLONE_FULL_MAX
    // bounds it with the table full), and its own steps; every one under term B.
    let entropy = longest_steps(&outcome.lines, "11");
    let clone = entropy.iter().find(|(k, ..)| *k == 8).map_or(0, |r| r.1);
    if clone == 0 {
        return Err(format!("the entropy service gave no CLONE: {entropy:?}"));
    }
    if let Some(row) = entropy.iter().find(|r| r.1 > RAM_STEP_MAX) {
        return Err(format!("the entropy service: a step past term B: {row:?}"));
    }
    // The waits of all services stay under CALL_WAIT_MAX (the heartbeat's
    // under WAIT_MAX), so that a growth of a wait shows. The wait of
    // FinishBinding (ramfs asks the process service) and of the heartbeat
    // of the pipe service must have been counted: without them the
    // accounting of waits is lost and the own parts above would hold the
    // waits again.
    check_waits(
        &outcome.lines,
        &["1", "2", "4", "10", "11"],
        "process-steps",
    )?;
    let ram_waits = longest_waits(&outcome.lines, "2");
    let pipe_waits = longest_waits(&outcome.lines, "4");
    if wait_of(&ram_waits, 25) == 0 {
        return Err(format!(
            "the RAM file service: no wait of FinishBinding counted: {ram_waits:?}"
        ));
    }
    if wait_of(&pipe_waits, 64) == 0 {
        return Err(format!(
            "the pipe service: no wait of the heartbeat counted: {pipe_waits:?}"
        ));
    }
    let rows_waits = longest_waits(&outcome.lines, "1");
    let mut text = String::from("kind method ticks(own) detail wait\n");
    for (kind, ticks, detail) in &loader {
        let name = LOADER_STEP_KINDS
            .iter()
            .find(|(k, _)| k == kind)
            .map_or("other", |(_, n)| n);
        text += &format!("loader {kind} {name} {ticks} {detail} 0\n");
    }
    for (kind, name, ticks, detail) in ram.iter().map(|(k, t, d)| {
        let name = RAM_STEP_KINDS
            .iter()
            .find(|(n, _)| n == k)
            .map_or("other", |(_, n)| n);
        (k, name, t, d)
    }) {
        let wait = wait_of(&ram_waits, *kind);
        text += &format!("ramfs {kind} {name} {ticks} {detail} {wait}\n");
    }
    for (kind, ticks, detail) in &pipe {
        let name = PIPE_STEP_KINDS
            .iter()
            .find(|(k, _)| k == kind)
            .map_or("other", |(_, n)| n);
        let wait = wait_of(&pipe_waits, *kind);
        text += &format!("pipe {kind} {name} {ticks} {detail} {wait}\n");
    }
    for (kind, ticks, detail) in &rows {
        let name = STEP_KINDS
            .iter()
            .find(|(k, _)| k == kind)
            .map_or("other", |(_, n)| n);
        let wait = wait_of(&rows_waits, *kind);
        text += &format!("{kind} {name} {ticks} {detail} {wait}\n");
    }
    let path = dir.join("process-steps.txt");
    std::fs::write(&path, &text).map_err(|e| format!("{}: {e}", path.display()))?;
    print!(
        "process steps under icount on {}, {live} children live:\n{text}",
        machine.name
    );
    println!("C process steps passed: {}", log.display());
    Ok(())
}

fn relibc_threads_probe(machine: &qemu::Machine) -> Result<(), String> {
    relibc()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image(
        "boot-relibc-threads.img",
        &RELIBC_THREADS_PROGRAMS,
        BOOT_PROFILE,
    )?;
    let mut cmd = qemu::command(machine, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    // Stops on any end, so that a failure shows at once.
    const ENDED: &str = "init: relibc-threads ended: exit code 0, not restarted";
    let output = run_until(
        cmd,
        RELIBC_THREADS_TIMEOUT,
        Some("init: relibc-threads ended"),
        &kernel.elf,
    )?;
    qemu::expect_marker(&output, ENDED)?;
    qemu::expect_marker(
        &output,
        "relibc-threads: a thread ran on the stack given to pthread_attr_setstack",
    )?;
    qemu::expect_marker(&output, "relibc-threads: ok")?;
    println!("relibc pthread guest probe passed");
    Ok(())
}

/// The threads probe runs about 10^5 turns of each object on TCG.
const RELIBC_THREADS_TIMEOUT: Duration = Duration::from_secs(240);

fn busybox_probe() -> Result<(), String> {
    relibc()?;
    if std::env::var_os("STAFETO_BUSYBOX_ROOT").is_none() {
        busybox_build()?;
    }
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-busybox.img", &BUSYBOX_PROGRAMS, BOOT_PROFILE)?;
    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    const ENDED: &str = "init: busybox-probe ended: exit code 0, not restarted";
    let output = run_until(cmd, BOOT_TIMEOUT, Some(ENDED), &kernel.elf)?;
    qemu::expect_stopped_on(&output, ENDED)?;
    qemu::expect_marker(&output, "stafeto ramfs")?;
    image_has_notices(&image)?;
    image_has_busybox_terms(&image)?;
    println!(
        "BusyBox cat guest probe passed, {NOTICES}, {BUSYBOX_LICENSE} and {BUSYBOX_SOURCE} in its image"
    );
    Ok(())
}

fn ash_probe() -> Result<(), String> {
    relibc()?;
    busybox_build()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-ash.img", &ASH_PROGRAMS, BOOT_PROFILE)?;
    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    const ENDED: &str = "init: busybox-probe ended: exit code 0, not restarted";
    let output = run_until(cmd, BOOT_TIMEOUT, Some(ENDED), &kernel.elf)?;
    qemu::expect_stopped_on(&output, ENDED)?;
    expect_ash_names(&output.lines)?;
    println!("BusyBox ash builtin guest probe passed");
    Ok(())
}

/// What the script of the ash probe (tests/busybox/src/main.rs) prints after
/// `shell-ready`: a file moved, read back and removed, a directory made, a
/// listing of `/tmp` with the directory just made and the node of the image,
/// the directory removed, a link read back, the mode `chmod` set.
const ASH_NAMES_OUTPUT: [&str; 10] = [
    "a-gone",
    "x",
    "b-gone",
    "d-made",
    "d",
    "probe",
    "d-gone",
    "b",
    "mode -rw-------",
    "init: busybox-probe ended: exit code 0, not restarted",
];

/// The lines of the guest after `shell-ready` are exactly those of the
/// script, in order.
fn expect_ash_names(lines: &[String]) -> Result<(), String> {
    let at = lines
        .iter()
        .position(|line| line == "shell-ready")
        .ok_or_else(|| {
            format!(
                "no shell-ready; last lines: {:?}",
                &lines[lines.len().saturating_sub(8)..]
            )
        })?;
    let got = &lines[at + 1..];
    if got.len() >= ASH_NAMES_OUTPUT.len()
        && got
            .iter()
            .zip(ASH_NAMES_OUTPUT)
            .all(|(line, want)| line == want)
    {
        Ok(())
    } else {
        Err(format!(
            "the ash script printed {:?}, wanted {:?}",
            got.iter()
                .take(ASH_NAMES_OUTPUT.len() + 2)
                .collect::<Vec<_>>(),
            ASH_NAMES_OUTPUT
        ))
    }
}

fn ash_dialog() -> Result<(), String> {
    relibc()?;
    busybox_build()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image(
        "boot-ash-dialog.img",
        &ASH_INTERACTIVE_PROGRAMS,
        BOOT_PROFILE,
    )?;
    // What `ls -l` shows of the files of /bin: the mode, the links and the
    // size of the ELF file of the program the file holds (rootfs.rs).
    let elf_size = |program: &str| -> Result<String, String> {
        let elf = image_elf(&target_dir(), "boot-ash-dialog.img", program);
        let meta = std::fs::metadata(&elf).map_err(|e| format!("{}: {e}", elf.display()))?;
        Ok(meta.len().to_string())
    };
    let busybox = elf_size("busybox-probe")?;
    let bin_listing = [
        ("-rwxr-xr-x", "8", "ash", busybox.clone()),
        ("-rwxr-xr-x", "8", "busybox", busybox.clone()),
        ("-rwxr-xr-x", "8", "cat", busybox.clone()),
        ("-rwxr-xr-x", "8", "head", busybox.clone()),
        ("-rwxr-xr-x", "8", "ls", busybox.clone()),
        ("-rwxr-xr-x", "8", "mktemp", busybox.clone()),
        ("-rwxr-xr-x", "8", "sleep", busybox.clone()),
        ("-rwxr-xr-x", "8", "wc", busybox),
        ("-rwsr-x---", "1", "ramfs", elf_size("ramfs")?),
    ];
    // The entries of /bin: the table of the image lists them (rootfs.rs).
    let bin_count = bin_listing.len().to_string();
    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let talked = (|| {
        run.expect(SERVICES_STARTED, BOOT_TIMEOUT)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("echo interactive-ready")?;
        run.expect("echo interactive-ready", DIALOG_STEP)?;
        run.expect_line(
            "interactive-ready",
            |line| line == "interactive-ready",
            DIALOG_STEP,
        )?;
        run.expect("# ", DIALOG_STEP)?;
        // Each builtin produces an observed result. The numeric false cases
        // also check exit status, and command bypasses the function named echo.
        let builtin_cases: &[(&str, &[&str])] = &[
            ("echo arithmetic:$((6 * 7))", &["arithmetic:42"]),
            (
                "test 7 -eq 7; echo test-true:$?; test 7 -eq 8; echo test-false:$?",
                &["test-true:0", "test-false:1"],
            ),
            (
                "[ word = word ]; echo bracket-true:$?; [ word = other ]; echo bracket-false:$?",
                &["bracket-true:0", "bracket-false:1"],
            ),
            (
                "printf 'formatted:%04d:%s\\n' 7 word",
                &["formatted:0007:word"],
            ),
            (
                "set -- -a -b value; while getopts 'ab:' opt; do echo option:$opt:$OPTARG; done; echo option-index:$OPTIND",
                &["option:a:", "option:b:value", "option-index:4"],
            ),
            ("alias hello='echo alias-ready'", &[]),
            ("hello", &["alias-ready"]),
            (
                "unalias hello; command -v hello >/dev/null; echo unalias:$?",
                &["unalias:127"],
            ),
            (
                "echo() { printf 'function:%s\\n' \"$1\"; }; echo called; command echo bypassed; unset -f echo",
                &["function:called", "bypassed"],
            ),
            ("command -v printf", &["printf"]),
        ];
        for (command, expected) in builtin_cases {
            run.send(command)?;
            for expected_line in *expected {
                run.expect_line(expected_line, |line| line == *expected_line, DIALOG_STEP)?;
            }
            run.expect("# ", DIALOG_STEP)?;
        }
        // The terminal service edits the line before ash reads it (5f):
        // DEL erases the "x" and its echo, and ash gets "echo abc".
        run.send("echo abx\x7fc")?;
        run.expect("echo abx\x08 \x08c", DIALOG_STEP)?;
        run.expect_line("abc", |line| line == "abc", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        // The name of the terminal is the layer's to resolve (5f): the
        // shell opens /dev/console for a redirection, and a file of /bin
        // that the shell forks and execs writes to the descriptor it
        // inherits (the terminal moves through exec).
        run.send("echo console >/dev/console")?;
        run.expect("echo console >/dev/console", DIALOG_STEP)?;
        run.expect_line("console", |line| line == "console", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("/bin/ls -1 /etc >/dev/console")?;
        run.expect("/bin/ls -1 /etc >/dev/console", DIALOG_STEP)?;
        run.expect_line("motd", |line| line == "motd", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        // The first goal of 5f: INTR at the console reaches the shell's
        // foreground group, the shell's session's (its getty made it): the
        // command ends by SIGINT and the shell, which catches it, goes on.
        run.send("echo sleeping; sleep 100")?;
        run.expect_line("sleeping", |line| line == "sleeping", DIALOG_STEP)?;
        std::thread::sleep(Duration::from_secs(2));
        run.type_raw(b"\x03")?;
        run.expect("^C", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("echo $?")?;
        run.expect_line("130", |line| line == "130", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("echo stopping; sleep 100")?;
        run.expect_line("stopping", |line| line == "stopping", DIALOG_STEP)?;
        std::thread::sleep(Duration::from_secs(1));
        run.type_raw(b"\x1a")?;
        run.expect("^Z", DIALOG_STEP)?;
        run.expect("Stopped", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("jobs")?;
        run.expect("Stopped", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("bg")?;
        run.expect("sleep 100", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("fg")?;
        run.expect("sleep 100", DIALOG_STEP)?;
        std::thread::sleep(Duration::from_millis(500));
        run.type_raw(b"\x03")?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("echo $?")?;
        run.expect_line("130", |line| line == "130", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("ls -1 /")?;
        run.expect("ls -1 /", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("ls -1 /etc")?;
        run.expect("ls -1 /etc", DIALOG_STEP)?;
        run.expect_line("motd", |line| line == "motd", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("ls -la")?;
        run.expect("ls -la", DIALOG_STEP)?;
        // The directories show as such: st_mode of a directory.
        run.expect("dr-xr-xr-x", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        // The files of the boot image's table: the modes and the sizes of
        // the ELF files (four names of BusyBox, a set-user-ID file), one
        // command each.
        for (mode, links, name, size) in &bin_listing {
            let command = format!("ls -l /bin/{name}");
            run.send(&command)?;
            run.expect(&command, DIALOG_STEP)?;
            run.expect_line(
                name,
                |line| {
                    let words: Vec<_> = line.split_whitespace().collect();
                    line.starts_with(mode)
                        && words.get(1) == Some(links)
                        && words.contains(&size.as_str())
                        && words.last() == Some(&format!("/bin/{name}").as_str())
                },
                DIALOG_STEP,
            )?;
            run.expect("# ", DIALOG_STEP)?;
        }
        run.send("ls --help")?;
        run.expect("ls --help", DIALOG_STEP)?;
        run.expect("Usage: ls", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("le /?")?;
        run.expect("le /?", DIALOG_STEP)?;
        run.expect("ash: le: not found", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        // A command with a path is no applet: ash forks for it (5d) and
        // the child execs the file. A file that is missing ends the child
        // with 127 and the shell goes on.
        run.send("/bin/x")?;
        run.expect("/bin/x", DIALOG_STEP)?;
        run.expect("ash: /bin/x: not found", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("echo $?")?;
        run.expect("echo $?", DIALOG_STEP)?;
        run.expect_line("127", |line| line == "127", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        // External programs: fork and exec of a file of /bin, alone, in a
        // list and with a status.
        run.send("/bin/ls -la")?;
        run.expect("/bin/ls -la", DIALOG_STEP)?;
        run.expect("dr-xr-xr-x", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("/bin/ls -1 /etc")?;
        run.expect("/bin/ls -1 /etc", DIALOG_STEP)?;
        run.expect_line("motd", |line| line == "motd", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("echo hi && ls -1 /etc")?;
        run.expect("echo hi && ls -1 /etc", DIALOG_STEP)?;
        run.expect_line("hi", |line| line == "hi", DIALOG_STEP)?;
        run.expect_line("motd", |line| line == "motd", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("echo hi && /bin/ls -1 /etc")?;
        run.expect("echo hi && /bin/ls -1 /etc", DIALOG_STEP)?;
        run.expect_line("hi", |line| line == "hi", DIALOG_STEP)?;
        run.expect_line("motd", |line| line == "motd", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("/bin/ash -c 'exit 3'")?;
        run.expect("/bin/ash -c 'exit 3'", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("echo $?")?;
        run.expect("echo $?", DIALOG_STEP)?;
        run.expect_line("3", |line| line == "3", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("/bin/ash -c '/bin/ash -c \"exit 4\"; echo inner $?'")?;
        run.expect_line("inner 4", |line| line == "inner 4", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("ls /missing")?;
        run.expect("ls /missing", DIALOG_STEP)?;
        run.expect("No such file or directory", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("echo $?")?;
        run.expect("echo $?", DIALOG_STEP)?;
        run.expect_line("1", |line| line == "1", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("echo after-ls")?;
        run.expect("echo after-ls", DIALOG_STEP)?;
        run.expect_line("after-ls", |line| line == "after-ls", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("cd etc")?;
        run.expect("cd etc", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("pwd")?;
        run.expect("pwd", DIALOG_STEP)?;
        run.expect_line("/etc", |line| line == "/etc", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("ls -la")?;
        run.expect("ls -la", DIALOG_STEP)?;
        run.expect("motd", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("cd ..")?;
        run.expect("cd ..", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("ls tmp")?;
        run.expect("ls tmp", DIALOG_STEP)?;
        run.expect("probe", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("ls /etc")?;
        run.expect("ls /etc", DIALOG_STEP)?;
        run.expect("motd", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("cd /missing")?;
        run.expect("cd /missing", DIALOG_STEP)?;
        run.expect("No such file or directory", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("echo after-cd-error")?;
        run.expect("echo after-cd-error", DIALOG_STEP)?;
        run.expect_line(
            "after-cd-error",
            |line| line == "after-cd-error",
            DIALOG_STEP,
        )?;
        run.expect("# ", DIALOG_STEP)?;
        // Pipelines (5e): each side a child of the shell, the ends of the
        // pipe service's pipes as its standard streams.
        run.send("ls /etc | cat")?;
        run.expect("ls /etc | cat", DIALOG_STEP)?;
        run.expect_line("motd", |line| line == "motd", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("echo hello | cat | cat")?;
        run.expect("echo hello | cat | cat", DIALOG_STEP)?;
        run.expect_line("hello", |line| line == "hello", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("ls /bin | wc -l")?;
        run.expect("ls /bin | wc -l", DIALOG_STEP)?;
        run.expect_line(
            "the count of /bin",
            |line| line.trim() == bin_count,
            DIALOG_STEP,
        )?;
        run.expect("# ", DIALOG_STEP)?;
        // A writer that writes nothing and outlasts its reader's start: the
        // reader sits in `read` on the empty pipe when the last end of the
        // writer closes, and that end wakes it.
        run.send("(/bin/ls /bin > /dev/null) | cat; echo piped $?")?;
        run.expect_line("piped 0", |line| line == "piped 0", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("/bin/ls /nope | /bin/cat; echo status $?")?;
        run.expect_line("status 0", |line| line == "status 0", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        // A job in the background reads /dev/null; `wait` returns when it
        // ends and gives its status.
        run.send("/bin/ls /etc & wait")?;
        run.expect("/bin/ls /etc & wait", DIALOG_STEP)?;
        run.expect_line("motd", |line| line == "motd", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("echo job-ended & wait; echo wait $?")?;
        run.expect_line("job-ended", |line| line == "job-ended", DIALOG_STEP)?;
        run.expect_line("wait 0", |line| line == "wait 0", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        // Whatever a command writes to /dev/null is gone, and its input
        // from there is at the end.
        run.send("echo lost > /dev/null && echo gone; echo more >> /dev/null && echo gone-too")?;
        run.expect_line("gone", |line| line == "gone", DIALOG_STEP)?;
        run.expect_line("gone-too", |line| line == "gone-too", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("cat < /dev/null; echo null $?")?;
        run.expect_line("null 0", |line| line == "null 0", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        // The random devices (5e'): character devices by `ls -l`, read
        // through pipelines by the children of the shell (the layer of
        // each serves the bytes from its own generator), a write taken.
        for name in ["null", "random", "urandom"] {
            let command = format!("ls -l /dev/{name}");
            run.send(&command)?;
            run.expect(&command, DIALOG_STEP)?;
            run.expect_line(
                name,
                |line| {
                    line.starts_with("crw-rw-rw-")
                        && line.split_whitespace().last() == Some(format!("/dev/{name}").as_str())
                },
                DIALOG_STEP,
            )?;
            run.expect("# ", DIALOG_STEP)?;
        }
        run.send("head -c 4096 /dev/urandom | wc -c")?;
        run.expect("head -c 4096 /dev/urandom | wc -c", DIALOG_STEP)?;
        run.expect_line("4096 bytes", |line| line.trim() == "4096", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("head -c 100 /dev/random | wc -c")?;
        run.expect("head -c 100 /dev/random | wc -c", DIALOG_STEP)?;
        run.expect_line("100 bytes", |line| line.trim() == "100", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        // The writer never ends: the reader's exit closes the pipe.
        run.send("cat /dev/urandom | head -c 100 | wc -c")?;
        run.expect("cat /dev/urandom | head -c 100 | wc -c", DIALOG_STEP)?;
        run.expect_line("100 bytes by cat", |line| line.trim() == "100", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("echo lost > /dev/urandom && echo taken")?;
        run.expect_line("taken", |line| line == "taken", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        // ash's $RANDOM is a generator of the shell (seeded with the
        // process number and the time); a seed given repeats it.
        run.send(
            "a=$RANDOM; b=$RANDOM; case $a in $b) echo same-random;; *) echo differ-random;; esac",
        )?;
        run.expect_line("differ-random", |line| line == "differ-random", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("RANDOM=7; a=$RANDOM; RANDOM=7; b=$RANDOM; case $a in $b) echo repeats;; *) echo no-repeat;; esac")?;
        run.expect_line("repeats", |line| line == "repeats", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        // mktemp creates an exclusive file with a name from the generator.
        run.send("mktemp /tmp/dialog.XXXXXX; echo mktemp $?")?;
        let temporary = run.expect_line(
            "temporary file name",
            |line| {
                line.strip_prefix("/tmp/dialog.").is_some_and(|suffix| {
                    suffix.len() == 6 && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
                })
            },
            DIALOG_STEP,
        )?;
        run.expect_line("mktemp 0", |line| line == "mktemp 0", DIALOG_STEP)?;
        run.expect("# ", DIALOG_STEP)?;
        run.send(&format!("/bin/ls {temporary}; echo temporary-file $?"))?;
        run.expect_line(
            "created temporary file",
            |line| line == temporary,
            DIALOG_STEP,
        )?;
        run.expect_line(
            "temporary-file 0",
            |line| line == "temporary-file 0",
            DIALOG_STEP,
        )?;
        run.expect("# ", DIALOG_STEP)?;
        run.send("exit")?;
        run.expect("exit", DIALOG_STEP)?;
        run.expect(
            "init: busybox-probe ended: exit code 0, not restarted",
            DIALOG_STEP,
        )
    })();
    let output = run.stop();
    symbolize::backtrace(&output.lines, &kernel.elf);
    talked?;
    if output.lines.iter().any(|line| {
        line.contains("process fault:")
            || line.contains("KERNEL PANIC")
            || line.contains("out of memory")
            || line.contains("I/O error")
    }) {
        return Err("ash dialog faulted".into());
    }
    if !["etc", "tmp"]
        .iter()
        .all(|entry| output.lines.iter().any(|line| line == entry))
    {
        return Err("ash root listing is incomplete".into());
    }
    if !["etc", "tmp"].iter().all(|entry| {
        output
            .lines
            .iter()
            .any(|line| line.starts_with('d') && line.ends_with(entry))
    }) {
        return Err("ash long listing is incomplete".into());
    }
    let elf = image_elf(&target_dir(), "boot-ash-dialog.img", "busybox-probe");
    // Information only: a program's size has no bound, the kernel's has.
    let text = text_size(&elf)?;
    println!("BusyBox ash interactive guest dialog passed; .text {text} bytes");
    Ok(())
}

/// The kinds of the lines of the terminal service (tag 5), by the
/// numbers of proto_tty::Method.
const TTY_STEP_KINDS: [(usize, &str); 18] = [
    (1, "ReadStart"),
    (2, "ReadTake"),
    (3, "ReadCancel"),
    (4, "WriteStart"),
    (5, "WriteTake"),
    (6, "WriteCancel"),
    (7, "Clone"),
    (8, "GetAttr"),
    (9, "SetAttr"),
    (10, "Abandon"),
    (11, "DrainStart"),
    (12, "DrainTake"),
    (13, "DrainCancel"),
    (14, "FlushQueues"),
    (15, "Flow"),
    (64, "heartbeat: its own part, the send to init is the wait"),
    (
        65,
        "own step: input, room, the next step, the timer of VTIME",
    ),
    (66, "session gone"),
];

/// The probe of the terminal service (tests/tty) on QEMU, or over the
/// Virtio console on Apple VZ (`vz`): xtask types INTR after "lost", then
/// "ab", DEL, "c" and Enter, and the probe's canonical read gives "ac\n"
/// while the console shows the echo of the erase; with VMIN 1 each byte
/// typed comes alone; 200 lines of output come whole and in order. On QEMU
/// the measure of the steps follows (`tty_steps`).
const ENDED_TTY: &str = "init: tty-probe ended: exit code 0, not restarted";

fn tty_probe(vz: bool) -> Result<(), String> {
    let image = if vz {
        build_boot_image("boot-tty-vz.img", &TTY_VZ_PROGRAMS, BOOT_PROFILE)?
    } else {
        build_boot_image("boot-tty.img", &TTY_PROGRAMS, BOOT_PROFILE)?
    };
    let (cmd, _) = probe_command(&image, vz)?;
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let result = (|| {
        run.expect("tty-probe: canonical read waits", BOOT_TIMEOUT)?;
        // INTR drops what was typed before it and asks for SIGINT.
        run.type_raw(b"lost\x03")?;
        run.expect("^C", DIALOG_STEP)?;
        run.expect("tty: SIGINT, no foreground process group", DIALOG_STEP)?;
        run.send("ab\x7fc")?;
        // The echo: the erase of the "b" and Enter as CR LF.
        run.expect("ab\x08 \x08c\r\n", DIALOG_STEP)?;
        run.expect("tty-probe: read ac and a newline", DIALOG_STEP)?;
        for (i, b) in ["x", "y", "z"].iter().enumerate() {
            run.expect(&format!("tty-probe: raw read {i} waits"), DIALOG_STEP)?;
            run.type_raw(b.as_bytes())?;
            run.expect(&format!("tty-probe: raw read {i} gave {b}"), DIALOG_STEP)?;
        }
        run.expect("tty-probe: raw reads gave each byte", DIALOG_STEP)?;
        // ONLCR clear: the console's driver adds no CR either.
        run.expect_bytes(b"\nbare-lf\n", DIALOG_STEP)?;
        run.expect("tty-probe: wrote", DIALOG_STEP)?;
        run.expect("tty-probe: ok", DIALOG_STEP)?;
        run.expect(ENDED_TTY, DIALOG_STEP)?;
        // The debug completion can precede bytes already accepted by UART.
        run.expect_seen(
            "tty-probe line 199 abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            DIALOG_STEP,
        )
    })();
    let output = run.stop();
    if vz {
        vz::stop_hint(result)?;
    } else {
        result?;
    }
    // The lines of the output come whole, each once, in their order. A
    // line of the kernel's log may cut one short: the driver shows the
    // part that went out again after it (uart::output), so a part of a
    // line comes before the line whole.
    let text = " abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let want: Vec<String> = (0..200)
        .map(|n| format!("tty-probe line {n:03}{text}"))
        .collect();
    let mut next = 0;
    for line in output
        .lines
        .iter()
        .filter(|l| l.starts_with("tty-probe line "))
    {
        let Some(wanted) = want.get(next) else {
            return Err(format!("a line past the probe's {}: {line:?}", want.len()));
        };
        if line == wanted {
            next += 1;
        } else if !wanted.starts_with(line.as_str()) {
            return Err(format!("line {next} of the probe came as {line:?}"));
        }
    }
    if next != want.len() {
        return Err(format!("{next} lines of the probe's {} came", want.len()));
    }
    println!(
        "terminal service guest probe passed on {}",
        if vz { "the Virtio console" } else { "the UART" }
    );
    if vz { Ok(()) } else { tty_steps() }
}

/// The measure of the terminal service's steps under -icount, against a
/// quiet driver (tests/tty, roles `S` and `s`): every step stays under
/// term B (a chunk of input through the discipline with the longest echo,
/// a message of output to the driver, WAITERS notifications), and every
/// byte of echo and output reached the driver.
fn tty_steps() -> Result<(), String> {
    let image = build_boot_image("boot-tty-steps.img", &TTY_STEPS_PROGRAMS, BOOT_PROFILE)?;
    let (mut cmd, kernel) = probe_command(&image, false)?;
    cmd.args(qemu::ICOUNT);
    let output = run_until(
        cmd,
        BOOT_TIMEOUT,
        Some("init: tty-probe ended"),
        &kernel.elf,
    )?;
    let dir = target_dir().join("measure");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let log = dir.join("tty-steps.log");
    std::fs::write(&log, output.lines.join("\n") + "\n")
        .map_err(|e| format!("{}: {e}", log.display()))?;
    qemu::expect_stopped_on(&output, ENDED_TTY)?;
    qemu::expect_marker(&output, "tty-probe: ok")?;
    // 255 clones of one root alive, each asked, then ended: the steps of
    // Clone, GetAttr and a session's end below run with the tables full.
    qemu::expect_marker(&output, "tty-probe: holdsets 255 clones live")?;
    let steps = longest_steps(&output.lines, "5");
    let waits = longest_waits(&output.lines, "5");
    let mut table = String::from("kind method ticks(own) detail wait\n");
    for (kind, ticks, detail) in &steps {
        let name = TTY_STEP_KINDS
            .iter()
            .find(|(k, _)| k == kind)
            .map_or("other", |(_, n)| n);
        let wait = wait_of(&waits, *kind);
        table += &format!("tty {kind} {name} {ticks} {detail} {wait}\n");
    }
    let path = dir.join("tty-steps.txt");
    std::fs::write(&path, &table).map_err(|e| format!("{}: {e}", path.display()))?;
    print!("terminal service steps under icount:\n{table}");
    // Each method and the service's own notifications made a step, each
    // under term B in its own part; the waits have their own bound.
    for kind in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 65, 66] {
        let ticks = steps.iter().find(|(k, ..)| *k == kind).map_or(0, |r| r.1);
        if ticks == 0 || ticks > RAM_STEP_MAX {
            return Err(format!(
                "the terminal service: kind {kind} took {ticks} ticks, past {RAM_STEP_MAX} or none: {steps:?}"
            ));
        }
    }
    if let Some(row) = steps.iter().find(|r| r.1 > RAM_STEP_MAX) {
        return Err(format!("the terminal service: a step past term B: {row:?}"));
    }
    check_waits(&output.lines, &["5"], "the terminal service")?;
    if wait_of(&waits, 64) == 0 {
        return Err(format!(
            "the terminal service: no wait of the heartbeat counted: {waits:?}"
        ));
    }
    println!("terminal service steps passed: {}", log.display());
    Ok(())
}

fn ash_shell() -> Result<(), String> {
    relibc()?;
    busybox_build()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image(
        "boot-ash-dialog.img",
        &ASH_INTERACTIVE_PROGRAMS,
        BOOT_PROFILE,
    )?;
    let cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    run_interactive_qemu(cmd, &kernel.elf)
}

fn ls_probe() -> Result<(), String> {
    relibc()?;
    busybox_build()?;
    let kernel = build(Variant::Normal)?;
    let image = build_boot_image("boot-ls.img", &LS_PROGRAMS, BOOT_PROFILE)?;
    let mut cmd = qemu::command(&qemu::VIRT, &kernel.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    const ENDED: &str = "init: busybox-probe ended: exit code 0, not restarted";
    let output = run_until(cmd, BOOT_TIMEOUT, Some(ENDED), &kernel.elf)?;
    qemu::expect_stopped_on(&output, ENDED)?;
    for entry in ["etc", "tmp", "motd"] {
        qemu::expect_line(&output, entry)?;
    }
    println!("BusyBox ls guest probe passed");
    Ok(())
}

/// `cargo xtask test`: the host tests, then the boots, up to `jobs` at a
/// time (jobs.rs). The boots stand alone, so the order of the list is the
/// order of the output and of the files of measures, and `--jobs 1` runs
/// them one after the other in it. Under -icount the numbers of the
/// kernel tests count instructions, so a loaded host changes none of
/// them.
fn test(jobs: usize) -> Result<(), String> {
    host_tests()?;
    if jobs > 1 {
        // What several boots share is built once, before they start, so
        // that the log tells where each line comes from.
        relibc()?;
        busybox_build()?;
        for variant in [Variant::Normal, Variant::Test, Variant::TestIcount] {
            build(variant)?;
        }
        build_boot_image("boot-test.img", &TEST_PROGRAMS, TEST_PROFILE)?;
        build_boot_image("boot-svc.img", &SVC_PROGRAMS, TEST_PROFILE)?;
    }
    let (os_test, plan) = ostest::plan()?;
    jobs::run_all(boot_jobs(os_test), jobs)?;
    // Checks that read the host's time on TCG run alone, after the rest.
    jobs::run_all(timing_jobs(), 1)?;
    println!("Rust POSIX C ABI, errno and shared-file guest probes passed");
    ostest::finish(plan)?;
    write_measures()?;
    println!("all checks passed");
    Ok(())
}

/// The boots of `test` whose verdicts depend on the host's time (the test
/// init's heartbeats on their absolute deadlines without -icount, the
/// monitor of QEMU for the ELF boot): they run one at a time once the
/// others have ended, so that the load of the others cannot fail them.
fn timing_jobs() -> Vec<jobs::Job> {
    use jobs::job;
    vec![
        // A hung test is killed after a second of the host's time.
        ostest::runner_check_job(),
        job(
            "elf boot without a device tree",
            elf_boot_reports_missing_device_tree,
        ),
        job("init tests 512M", || {
            init_tests(&qemu::VIRT, false).map(drop)
        }),
        job("init tests 2G", || {
            init_tests(&qemu::VIRT_2G, false).map(drop)
        }),
        job("init tests GICv3", || {
            init_tests(&qemu::VIRT_V3, false).map(drop)
        }),
        job("init tests EL2", || {
            init_tests(&qemu::VIRT_EL2, false).map(drop)
        }),
    ]
}

/// The independent boots of `test`, in the order they ran in before there
/// were jobs.
fn boot_jobs(os_test: Vec<jobs::Job>) -> Vec<jobs::Job> {
    use jobs::job;
    let mut list = vec![
        job("ext4ro", ext4ro_probe),
        job("ramfs", ramfs_probe),
        job("posix-abi", posix_abi_boots),
        job("posix-orphans", posix_orphans),
        job("posix-threads", || posix_thread_probe(false)),
        job("posix-cancel-input", || posix_cancel_input_probe(false)),
        job("posix-shared", posix_shared_probe),
        job("posix-input", || posix_input_probe(false)),
        job("posix-interrupt", || posix_interrupt_probe(false)),
        job("posix-tty", || posix_tty_probe(false, false)),
        job("posix-tty-control-steps", posix_tty_control_steps),
        job("relibc-hello", relibc_hello_probe),
        job("relibc-threads", || relibc_threads_probe(&qemu::VIRT)),
        job("posix-files", posix_files_probe),
        job("posix-files steps", || posix_files_run(true)),
        job("posix-procs", || posix_procs_probe(&qemu::VIRT)),
        job("posix-lifetimes", || posix_lifetimes_probe(&qemu::VIRT)),
        job("posix-lock-ring", || posix_lock_ring_probe(&qemu::VIRT)),
        job("posix-jobs", posix_jobs_probe),
        job("loader-channels", loader_channels_probe),
        job("posix-poll", posix_poll_probe),
        job("posix-pty", posix_pty_probe),
        job("posix-pty-steps", posix_pty_steps),
        // The longest step of the process service with 248 children, under
        // -icount: the host's time changes none of its numbers.
        job("process-steps", || process_steps(&qemu::VIRT, 7)),
        // BusyBox on relibc guards the C surface (5a').
        job("busybox", busybox_probe),
        job("ash", ash_probe),
        job("ash-dialog", ash_dialog),
        job("ls", ls_probe),
        // One round of the benchmark under -icount: its rows are whole and
        // the path of pthread_kill stays under S5_ICOUNT_MAX.
        job("rtbench-short", || rtbench2::short(rtbench2::Short::Icount)),
        job("boot 512M GICv2", || {
            boot_smoke(&qemu::VIRT, GIC_V2_LINE).map(drop)
        }),
        job("boot 512M GICv3", || {
            boot_smoke(&qemu::VIRT_V3, GIC_V3_LINE).map(drop)
        }),
        job("boot EL2 GICv2", || {
            boot_smoke(&qemu::VIRT_EL2, GIC_V2_LINE).map(drop)
        }),
        job("boot EL2 GICv3", || {
            boot_smoke(&qemu::VIRT_EL2_V3, GIC_V3_LINE).map(drop)
        }),
        job("boot 2G", two_gib_boot),
        job("console dialog 512M", || console_dialog(&qemu::VIRT)),
        job("trace dialog 512M", || trace_dialog(&qemu::VIRT)),
        job("console dialog GICv3", || console_dialog(&qemu::VIRT_V3)),
        job("bad boot images", bad_boot_images_stop_the_boot),
        job("init fault", init_fault_stops_the_machine),
        job("panic log", panic_prints_the_log_nobody_showed),
        job("fault report", fault_report),
        job("stack overflow", stack_overflow_report),
        job("test build symbols", test_build_carries_test_symbols),
        job("strict panic", strict_panic_only_in_checked_programs),
        job("no u128 division", no_u128_division_is_linked),
        job("shipping init", shipping_init_has_no_test_table),
        job("init tests 512M icount", || {
            init_tests(&qemu::VIRT, true).map(drop)
        }),
        job("init tests 2G icount", || {
            init_tests(&qemu::VIRT_2G, true).map(drop)
        }),
        job("service tests 512M", || svc_tests(&qemu::VIRT).map(drop)),
        job("service tests GICv3", || {
            svc_tests(&qemu::VIRT_V3).map(drop)
        }),
        job("bad tables", bad_tables_are_refused),
        job("kernel tests 512M", || {
            kernel_tests(&qemu::VIRT, Variant::Test).map(drop)
        }),
        job("kernel tests 2G", || {
            kernel_tests(&qemu::VIRT_2G, Variant::Test).map(drop)
        }),
        job("kernel tests GICv3", || {
            kernel_tests(&qemu::VIRT_V3, Variant::Test).map(drop)
        }),
        job("kernel tests EL2", || {
            kernel_tests(&qemu::VIRT_EL2, Variant::Test).map(drop)
        }),
        job("kernel tests 512M icount", || {
            kernel_tests(&qemu::VIRT, Variant::TestIcount).map(drop)
        }),
        job("kernel tests 2G icount", || {
            kernel_tests(&qemu::VIRT_2G, Variant::TestIcount).map(drop)
        }),
        job("tty", || tty_probe(false)),
        // The entropy device's driver under -icount, its steps measured.
        job("entropy", || entropy::probe(&qemu::VIRT)),
        job("posix-random", || entropy::random_probe(&qemu::VIRT)),
    ];
    // os-test (a boot a suite) within its time budget; its passing tests
    // (tests/os-test/pass.txt) still pass (`ostest::finish`). Its boots
    // come after `ls`.
    let at = list
        .iter()
        .position(|j| j.name() == "ls")
        .map_or(0, |i| i + 1);
    list.splice(at..at, os_test);
    list
}

fn host_tests() -> Result<(), String> {
    run_cmd(cargo().args([
        "test",
        "--package",
        "abi",
        "--package",
        "bootimg",
        "--package",
        "ext4ro",
        "--package",
        "posix-path",
        "--package",
        "posix-fd",
        "--package",
        "posix-change",
        "--package",
        "posix-types",
        "--package",
        "posix-heap",
        "--package",
        "posix-map",
        "--package",
        "posix-order",
        "--package",
        "posix-request",
        "--package",
        "posix-time",
        "--package",
        "posix-signals",
        "--package",
        "posix-signal-queue",
        "--package",
        "entries",
        "--package",
        "posix-credentials",
        "--package",
        "proto-process",
        "--package",
        "proto-loader",
        "--package",
        "posix-process-service",
        "--package",
        "init",
        "--package",
        "kcore",
        "--package",
        "proto-init",
        "--package",
        "proto-fs",
        "--package",
        "proto-uart",
        "--package",
        "proto-wire",
        "--package",
        "proto-clock",
        "--package",
        "proto-pipe",
        "--package",
        "pipe",
        "--package",
        "shell",
        "--package",
        "ramfs",
        "--package",
        "uart",
        "--package",
        "virtio-console",
        "--package",
        "xtask",
        "--package",
        "proto-tty",
        "--package",
        "tty",
        "--package",
        "virtio-pci",
        "--package",
        "proto-entropy",
        "--package",
        "virtio-rng",
        "--package",
        "posix-random",
        "--package",
        "entropy",
    ]))
}

/// A normal build boots on machine `m`, prints its report (boot_report)
/// with the line of the GIC, `gic`, and init's entry point from the boot
/// image, and starts init, which checks its table and starts the UART
/// driver and the shell, which connects to it and says so: xtask stops
/// QEMU on SHELL_CONNECTED, with no panic before it
/// (qemu::expect_stopped_on). Gives the timer's frequency. On VIRT_EL2
/// and VIRT_EL2_V3 the kernel is entered at EL2, as the PinePhone's loader
/// does: head.S must drop to EL1, and with a GICv3 open its system
/// registers to EL1 first. The image also carries none of the kernel's own
/// tests (spec 3.4): `no_test_symbols` checks it here so every normal
/// build, the one that ships included, is covered.
fn boot_smoke(m: &qemu::Machine, gic: &str) -> Result<u64, String> {
    let a = build(Variant::Normal)?;
    no_test_symbols(&a.elf)?;
    let mut cmd = qemu::command(m, &a.image, Some(&a.boot_image));
    cmd.args(qemu::HEADLESS);
    let o = run_until(cmd, BOOT_TIMEOUT, Some(SHELL_CONNECTED), &a.elf)?;
    qemu::expect_stopped_on(&o, SHELL_CONNECTED)?;
    let entry = init_entry(&a.boot_image)?;
    qemu::expect_marker(&o, &format!("init       entry {entry:#x},"))?;
    let size = std::fs::metadata(&a.boot_image)
        .map_err(|e| format!("{}: {e}", a.boot_image.display()))?
        .len();
    let hz = boot_report(&o.lines, m, size, gic)?;
    measure::record(m, &o.lines);
    Ok(hz)
}

/// Whether `l` is the kernel's first line, `stafeto <version> booting`,
/// which it says before it read the device tree and knew its port: it
/// waits in the kernel log until the port is known, and goes out then
/// (spec 3.2).
fn is_booting(l: &str) -> bool {
    l.strip_prefix("stafeto ")
        .and_then(|l| l.strip_suffix(" booting"))
        .is_some_and(|v| !v.is_empty() && !v.contains(' '))
}

/// The kernel's boot report (spec 3.3) on machine `m` with a boot image of
/// `boot_image` bytes and the line of the GIC `gic`: `is_booting` once, before
/// the line of `m`'s RAM at VIRT_RAM; the lines of the boot image, the
/// GIC, `m`'s PSCI conduit, the timer and `boot complete`, each whole.
/// Gives the timer's frequency, which depends on the host.
fn boot_report(
    lines: &[String],
    m: &qemu::Machine,
    boot_image: u64,
    gic: &str,
) -> Result<u64, String> {
    let memory = format!("memory     {VIRT_RAM:#x}..{:#x}", VIRT_RAM + m.ram());
    let booting: Vec<usize> = (0..lines.len())
        .filter(|&i| is_booting(&lines[i]))
        .collect();
    let first_memory = lines.iter().position(|l| l.starts_with("memory     "));
    if booting.len() != 1 || first_memory.is_some_and(|m| m < booting[0]) {
        return Err(
            "the boot report has not one line `stafeto <version> booting` before its memory".into(),
        );
    }
    let psci = format!("psci       {}", m.psci());
    for line in [memory.as_str(), gic, psci.as_str(), "boot complete"] {
        if !lines.iter().any(|l| l == line) {
            return Err(format!("the boot report has no line {line:?}"));
        }
    }
    let hex = |s: &str| u64::from_str_radix(s.strip_prefix("0x")?, 16).ok();
    let image = lines.iter().find_map(|l| {
        let (start, end) = l.strip_prefix("boot image ")?.split_once("..")?;
        hex(end)?.checked_sub(hex(start)?)
    });
    if image != Some(boot_image) {
        return Err(format!(
            "the boot report has no line of a boot image of {boot_image} bytes"
        ));
    }
    lines
        .iter()
        .find_map(|l| {
            l.strip_prefix("timer      ")?
                .strip_suffix(" Hz")?
                .parse()
                .ok()
        })
        .filter(|&hz| hz > 0)
        .ok_or_else(|| "the boot report has no line `timer N Hz`".into())
}

/// With 2 GiB of RAM the second GiB is not mapped at boot: the allocator
/// must receive it after the kernel page tables map all RAM. The boot
/// goes on to the shell (SHELL_CONNECTED).
fn two_gib_boot() -> Result<(), String> {
    let a = build(Variant::Normal)?;
    let mut cmd = qemu::command(&qemu::VIRT_2G, &a.image, Some(&a.boot_image));
    cmd.args(qemu::HEADLESS);
    let o = run_until(cmd, BOOT_TIMEOUT, Some(SHELL_CONNECTED), &a.elf)?;
    qemu::expect_stopped_on(&o, SHELL_CONNECTED)?;
    let free =
        qemu::number_after(&o.lines, "frames ").ok_or("the kernel printed no frames line")?;
    if free < 1900 {
        return Err(format!("only {free} MiB of frames free with 2 GiB of RAM"));
    }
    Ok(())
}

/// Spec 13.5, 13.6, 14, 15.2: the normal build on machine `m` with a pipe
/// on the console's input (qemu::Run): the UART driver's line, the
/// shell's line and its prompt; `help` gives HELP_LINES; `echo hello
/// stafeto` comes back as its echo, the line typed, then the line `hello
/// stafeto` after it; `uptime` gives seconds with milliseconds; `ps`
/// gives its header whole and the rows of init, uart and shell, running
/// at their levels, uart and shell never failed or restarted and with the
/// limits of their records (ps_row); `mem` their pages, a total where a
/// child's quota counts by what the child uses (spec 7.5), and the
/// kernel's line; `bench` its line with its five numbers (bench_numbers),
/// which fail nothing by their values (spec 15.3); a prompt after each
/// answer. A line of TYPED_AHEAD bytes typed while `bench` runs, past the
/// driver's ring of input, comes back as its first 128 bytes (spec 13.5,
/// 13.6), and init's SERVICES_STARTED, which reaches the log after the
/// driver's first read and only its timer shows, comes before the crash.
/// Then `crash uart`: the driver restarts and the shell connects
/// again (crash_uart); `ps` shows uart running at 60/60, failed and
/// restarted once, and the shell running, never failed or restarted;
/// `echo after the crash` comes back; and
/// a_broken_driver_gives_the_port_back. The run has no KERNEL PANIC line.
fn console_dialog(m: &qemu::Machine) -> Result<(), String> {
    let a = build(Variant::Normal)?;
    let mut cmd = qemu::command(m, &a.image, Some(&a.boot_image));
    cmd.args(qemu::HEADLESS);
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let talked = dialog(&mut run);
    let o = run.stop();
    symbolize::backtrace(&o.lines, &a.elf);
    let bench = talked.map_err(|e| format!("console dialog on {}: {e}", m.name))?;
    if let Some(panic) = o.lines.iter().find(|l| l.contains("KERNEL PANIC")) {
        return Err(format!("console dialog on {}: {panic}", m.name));
    }
    println!("console dialog on {}: ok; {bench}", m.name);
    Ok(())
}

fn trace_dialog(m: &qemu::Machine) -> Result<(), String> {
    let a = build(Variant::TraceNormal)?;
    let mut cmd = qemu::command(m, &a.image, Some(&a.boot_image));
    cmd.args(qemu::HEADLESS);
    let mut run = qemu::Run::start(cmd, qemu::Input::Pipe)?;
    let talked = (|| {
        run.expect_line(
            SHELL_CONNECTED,
            |line| line == SHELL_CONNECTED,
            BOOT_TIMEOUT,
        )?;
        run.expect(PROMPT, DIALOG_STEP)?;
        run.send("trace")?;
        run.expect_line(
            "trace event",
            |line| {
                line.starts_with("trace: ")
                    && (line.contains(" syscall ")
                        || line.contains(" switch ")
                        || line.contains(" interrupt "))
            },
            DIALOG_STEP,
        )?;
        run.expect(PROMPT, DIALOG_STEP).map(|_| ())
    })();
    let o = run.stop();
    symbolize::backtrace(&o.lines, &a.elf);
    talked.map_err(|e| format!("trace dialog on {}: {e}", m.name))?;
    if o.lines.iter().any(|line| line.contains("KERNEL PANIC")) {
        return Err(format!("trace dialog on {} panicked", m.name));
    }
    println!("trace dialog on {}: ok", m.name);
    Ok(())
}

/// The steps of `console_dialog`, each after the one before it; gives
/// the line of `bench`.
fn dialog(run: &mut qemu::Run) -> Result<String, String> {
    let whole = |line: &'static str| move |l: &str| l == line;
    run.expect_line(UART_LINE, whole(UART_LINE), BOOT_TIMEOUT)?;
    run.expect_line(SHELL_CONNECTED, whole(SHELL_CONNECTED), DIALOG_STEP)?;
    run.expect(PROMPT, DIALOG_STEP)?;
    run.send("help")?;
    for line in HELP_LINES {
        run.expect_line(line, whole(line), DIALOG_STEP)?;
    }
    run.expect(PROMPT, DIALOG_STEP)?;
    run.send("echo hello stafeto")?;
    run.expect("echo hello stafeto\r\n", DIALOG_STEP)?;
    run.expect_line("hello stafeto", whole("hello stafeto"), DIALOG_STEP)?;
    run.expect(PROMPT, DIALOG_STEP)?;
    run.send("uptime")?;
    run.expect_line("the uptime", is_uptime, DIALOG_STEP)?;
    run.expect(PROMPT, DIALOG_STEP)?;
    run.send("ps")?;
    run.expect_line(PS_HEADER, whole(PS_HEADER), DIALOG_STEP)?;
    // The records of the table that ships: running, never failed, with
    // the levels, handle limit and quota of their records.
    for (name, levels, limit) in [
        ("init", "63/63", ""),
        ("uart", "60/60", "32"),
        ("shell", "30/30", "32"),
    ] {
        let row = |l: &str| {
            ps_row(l, name).is_some_and(|c| {
                c[1..3] == ["running", levels]
                    && (limit.is_empty()
                        || (c[3..5] == ["0", "0"]
                            && c[5].rsplit('/').next() == Some(limit)
                            && c[6].rsplit('/').next() == Some(limit)))
            })
        };
        run.expect_line(&format!("the row of {name} in ps"), row, DIALOG_STEP)?;
    }
    run.expect(PROMPT, DIALOG_STEP)?;
    run.send("mem")?;
    let mut rows = Vec::new();
    for name in ["init", "uart", "shell"] {
        let row = run.expect_line(
            &format!("the row of {name} in mem"),
            |l| mem_row(l, name).is_some(),
            DIALOG_STEP,
        )?;
        rows.push(mem_row(&row, name).unwrap_or_default());
    }
    // A child's quota counts whole in what init uses (spec 7.5).
    let unused: u64 = rows[1..]
        .iter()
        .map(|(used, quota)| quota.saturating_sub(*used))
        .sum();
    let sum = (rows[0].0.saturating_sub(unused), rows[0].1);
    let total = |l: &str| mem_row(l, "total") == Some(sum);
    run.expect_line(&format!("a total of {sum:?} in mem"), total, DIALOG_STEP)?;
    let kernel = "kernel: # frames free, # pages in pools; init: # pages of quota free";
    run.expect_line(kernel, |l| numbers(l, kernel).is_some(), DIALOG_STEP)?;
    run.expect(PROMPT, DIALOG_STEP)?;
    run.send("bench")?;
    // Typed while bench keeps the shell busy: more than the driver's ring
    // of input holds, which masks input until the shell reads again.
    run.send(&format!("echo {}", "a".repeat(TYPED_AHEAD)))?;
    let line = run.expect_line(
        "the line of bench",
        |l| bench_numbers(l).is_some(),
        DIALOG_STEP,
    )?;
    run.expect(PROMPT, DIALOG_STEP)?;
    let kept = "a".repeat(128 - "echo ".len());
    run.expect_line("the line typed ahead", |l| l == kept, DIALOG_STEP)?;
    run.expect(PROMPT, DIALOG_STEP)?;
    // Init writes its line into the kernel log once the shell started,
    // after the driver's first read: only the driver's timer shows it.
    run.expect_seen(SERVICES_STARTED, DIALOG_STEP)?;
    crash_uart(run, CRASH_DECISIONS[0])?;
    run.send("ps")?;
    // The driver failed and restarted once; connecting again restarted
    // no shell.
    for (name, levels, counts) in [
        ("uart", "60/60", ["1", "1"]),
        ("shell", "30/30", ["0", "0"]),
    ] {
        let row = |l: &str| {
            ps_row(l, name).is_some_and(|c| c[1..3] == ["running", levels] && c[3..5] == counts)
        };
        let what = format!(
            "the row of {name} in ps with fails and restarts {} {}",
            counts[0], counts[1]
        );
        run.expect_line(&what, row, DIALOG_STEP)?;
    }
    run.expect(PROMPT, DIALOG_STEP)?;
    run.send("echo after the crash")?;
    run.expect("echo after the crash\r\n", DIALOG_STEP)?;
    run.expect_line("after the crash", whole("after the crash"), DIALOG_STEP)?;
    run.expect(PROMPT, DIALOG_STEP)?;
    a_broken_driver_gives_the_port_back(run)?;
    Ok(line)
}

/// `crash uart` with the driver restarting after init's `decision` (spec
/// 13.5, 13.6, 16.2): the shell says so and connects again, and prompts
/// (crash_lines).
fn crash_uart(run: &mut qemu::Run, decision: &str) -> Result<(), String> {
    let from = run.lines().len();
    run.send("crash uart")?;
    let whole = |l: &str| l == RECONNECTED;
    run.expect_line(RECONNECTED, whole, DIALOG_STEP)?;
    run.expect(PROMPT, DIALOG_STEP)?;
    crash_lines(&run.lines()[from..], decision).map_err(|e| format!("crash uart, {decision}: {e}"))
}

/// The lines from `crash uart` to the prompt after it, when the driver
/// restarts after `decision` (spec 13.6, 16.2): the shell's CRASHING, then
/// the kernel's line of the driver's fault at address 0, which went into
/// the kernel log while the driver's window held the port and which the
/// new instance shows, and init's line of the driver's end with that
/// fault and `decision`, each exactly once, then the new driver's
/// UART_LINE and the shell's RECONNECTED last, in this order. Other lines
/// may come between: records of the log the dead instance did not show.
fn crash_lines(lines: &[String], decision: &str) -> Result<(), String> {
    let fault = |l: &str| driver_fault(l);
    let ended = |l: &str| uart_ended(l, decision);
    let once = |what: &str, wanted: &dyn Fn(&str) -> bool| one_line(lines, what, wanted);
    let steps = [
        once("the shell's crashing", &|l| l == CRASHING)?,
        once("the driver's fault", &fault)?,
        once("uart's end", &|l| l.starts_with(UART_ENDED))?,
        once("the driver's start", &|l| l == UART_LINE)?,
    ];
    if !ended(&lines[steps[2]]) {
        return Err(format!(
            "{:?}: a fault at 0 and {decision:?} expected",
            lines[steps[2]]
        ));
    }
    if !steps.is_sorted() || lines.last().is_none_or(|l| l != RECONNECTED) {
        return Err(format!(
            "{CRASHING:?}, the fault, uart's end, {UART_LINE:?} and {RECONNECTED:?} expected in this order: {lines:?}"
        ));
    }
    Ok(())
}

/// Whether `l` is the kernel's line of the driver's fault at address 0
/// (spec 7.9): DRIVER_FAULT, the syndrome, FAR 0 and the ELR.
fn driver_fault(l: &str) -> bool {
    l.strip_prefix(DRIVER_FAULT)
        .and_then(|l| l.split_once(" FAR=0x0 ELR=0x"))
        .is_some_and(|(esr, elr)| is_hex(esr) && is_hex(elr))
}

/// Whether `l` is init's line of the driver's end by that fault with
/// `decision` (spec 16.2).
fn uart_ended(l: &str, decision: &str) -> bool {
    l.strip_prefix(UART_ENDED)
        .and_then(|l| l.strip_prefix("fault ESR=0x"))
        .and_then(|l| l.strip_suffix(decision)?.strip_suffix("; "))
        .and_then(|l| l.split_once(" FAR=0x0 ELR=0x"))
        .is_some_and(|(esr, elr)| is_hex(esr) && is_hex(elr))
}

/// Whether `s` is one hex digit or more.
fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The place of the one line of `lines` that `wanted` takes, which `what`
/// names in the error when there is none or more.
fn one_line(lines: &[String], what: &str, wanted: &dyn Fn(&str) -> bool) -> Result<usize, String> {
    let at: Vec<usize> = (0..lines.len()).filter(|&i| wanted(&lines[i])).collect();
    match at[..] {
        [i] => Ok(i),
        _ => Err(format!(
            "{} lines of {what}, one expected: {lines:?}",
            at.len()
        )),
    }
}

/// Spec 13.4, 13.6, 16.3: four more `crash uart` in a row, the driver
/// restarting after the second to the fourth pause of CRASH_DECISIONS and
/// the shell connecting again after each (crash_uart); the fifth failure
/// in 60 s marks the driver broken, its window goes, the port is the
/// kernel's again, the shell says BROKEN through debug_write, and init's
/// worker shows what is left of the kernel log: the lines of that last
/// end (broken_lines).
fn a_broken_driver_gives_the_port_back(run: &mut qemu::Run) -> Result<(), String> {
    for decision in &CRASH_DECISIONS[1..4] {
        crash_uart(run, decision)?;
    }
    let from = run.lines().len();
    run.send("crash uart")?;
    let broken = CRASH_DECISIONS[4];
    run.expect_line(BROKEN, |l| l == BROKEN, DIALOG_STEP)
        .and_then(|_| run.expect_line(UART_ENDED, |l| uart_ended(l, broken), DIALOG_STEP))
        .and_then(|_| broken_lines(&run.lines()[from..]))
        .map(drop)
        .map_err(|e| format!("a broken driver: {e}"))
}

/// The lines from the fifth `crash uart` to init's line of the driver's
/// end (spec 13.4, 13.6, 16.3): the shell's CRASHING and BROKEN, then the
/// kernel's line of the driver's fault and init's line of its end with the
/// mark of a broken service, which init's worker shows from the kernel
/// log once the port is the kernel's, each exactly once and in this order;
/// no line of a new driver or of a reconnection.
fn broken_lines(lines: &[String]) -> Result<(), String> {
    let broken = CRASH_DECISIONS[4];
    let once = |what: &str, wanted: &dyn Fn(&str) -> bool| one_line(lines, what, wanted);
    let steps = [
        once("the shell's crashing", &|l| l == CRASHING)?,
        once("the shell's broken", &|l| l == BROKEN)?,
        once("the driver's fault", &driver_fault)?,
        once("uart's end", &|l| uart_ended(l, broken))?,
    ];
    if !steps.is_sorted() || lines.iter().any(|l| l == UART_LINE || l == RECONNECTED) {
        return Err(format!(
            "{CRASHING:?}, {BROKEN:?}, the fault and uart's end expected in this order, and no new driver: {lines:?}"
        ));
    }
    Ok(())
}

/// The header of the shell's `ps`, whole.
const PS_HEADER: &str = "name             state     prio fails restarts        handles       pages";

/// The columns of `line` when it is the row of `name` in the shell's `ps`
/// (spec 13.6): the name, a state, priority/ceiling, failures, restarts,
/// handles live/retired/limit and pages used/quota.
fn ps_row<'a>(line: &'a str, name: &str) -> Option<Vec<&'a str>> {
    let cols: Vec<&str> = line.split_whitespace().collect();
    let numbers = |col: &str, n: usize| {
        let parts: Vec<&str> = col.split('/').collect();
        parts.len() == n && parts.iter().all(|p| p.parse::<u64>().is_ok())
    };
    let row = cols.len() == 7
        && cols[0] == name
        && cols[1].bytes().all(|b| b.is_ascii_lowercase())
        && numbers(cols[2], 2)
        && numbers(cols[3], 1)
        && numbers(cols[4], 1)
        && numbers(cols[5], 3)
        && numbers(cols[6], 2);
    row.then_some(cols)
}

/// The pages used and the quota of `line` when it is the row of `name`
/// in the shell's `mem`: `<name> <used> of <quota> pages`.
fn mem_row(line: &str, name: &str) -> Option<(u64, u64)> {
    match line.split_whitespace().collect::<Vec<_>>()[..] {
        [n, used, "of", quota, "pages"] if n == name => {
            Some((used.parse().ok()?, quota.parse().ok()?))
        }
        _ => None,
    }
}

/// The five numbers of the line of the shell's `bench` (spec 13.6): the
/// least, mean and most of 1000 round trips of PING and the longest
/// latencies of a timer that woke the kernel from `wfi` (x2 of
/// KERNEL_STATS) and of one that came while a thread or the kernel ran
/// (x3), each in ns.
fn bench_numbers(line: &str) -> Option<[u64; 5]> {
    let template = "bench: ping round trip over 1000 rounds: min # ns, mean # ns, max # ns; \
                    timer latency max # ns; interrupt latency max # ns";
    numbers(line, template)?.try_into().ok()
}

/// The numbers of `line` when it is `template` word by word, with a
/// number at each `#`.
fn numbers(line: &str, template: &str) -> Option<Vec<u64>> {
    let words = line.split_whitespace();
    let mut numbers = Vec::new();
    for (word, wanted) in words.clone().zip(template.split_whitespace()) {
        match wanted.strip_prefix('#') {
            Some(rest) => numbers.push(word.strip_suffix(rest)?.parse().ok()?),
            None if word == wanted => {}
            None => return None,
        }
    }
    (words.count() == template.split_whitespace().count()).then_some(numbers)
}

/// Whether `line` is the shell's `uptime`: `up <seconds>.<ms> s`, with
/// three digits of milliseconds.
fn is_uptime(line: &str) -> bool {
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    line.strip_prefix("up ")
        .and_then(|l| l.strip_suffix(" s"))
        .and_then(|l| l.split_once('.'))
        .is_some_and(|(s, ms)| digits(s) && digits(ms) && ms.len() == 3)
}

/// Booting the ELF leaves x0 = 0; the kernel must say why it stops. It
/// says so before it read the device tree, so with no port: its panic
/// stays in the kernel log, which xtask reads from the guest's RAM through
/// QEMU's monitor (ring, spec 3.2), after the line the kernel said first.
fn elf_boot_reports_missing_device_tree() -> Result<(), String> {
    let a = build(Variant::Normal)?;
    let port = ring::free_port()?;
    let dump = ring::path(&target_dir(), "elf-boot.ram");
    let mut cmd = qemu::command(&qemu::VIRT, &a.elf, None);
    cmd.args(["-display", "none", "-serial", "null"])
        .args(ring::monitor_args(port));
    const MARKER: &str = "no device tree in x0";
    let text = ring::wait_for(cmd, port, &dump, MARKER, BOOT_TIMEOUT)?;
    let lines: Vec<&str> = text.lines().collect();
    let first = lines.first().copied().unwrap_or_default();
    if !is_booting(first) || !lines.iter().any(|l| l.contains("KERNEL PANIC")) {
        return Err(format!(
            "the kernel log in RAM has no first line `stafeto <version> booting` and panic: {text:?}"
        ));
    }
    println!("ELF boot: the panic before the device tree is in the kernel log in RAM");
    Ok(())
}

/// A boot image that is missing, cut short, damaged or not whole pages
/// stops the boot with a panic that says what is wrong (spec 3.3, 13.1).
/// The cases: no boot image; the image without the last byte of init; the
/// image's signature spoiled; init's signature spoiled; the image with a
/// byte past its whole pages; an init whose data segment is
/// bigger than a memory object can be, which the kernel cannot load.
fn bad_boot_images_stop_the_boot() -> Result<(), String> {
    let a = build(Variant::Normal)?;
    let good =
        std::fs::read(&a.boot_image).map_err(|e| format!("{}: {e}", a.boot_image.display()))?;
    let init = bootimg::BootImage::parse(&good)
        .map_err(|e| e.to_string())?
        .files()
        .next()
        .ok_or("the boot image has no files")?;
    let (init_at, init_end) = (init.offset as usize, init.offset as usize + init.data.len());
    let mut odd = good.clone();
    odd.push(0);
    let mut unsigned = good.clone();
    unsigned[0] = b's';
    let mut bad_init = good.clone();
    bad_init[init_at] = b's';
    let huge = raw_init(&[LDR_X0_X0], false, HUGE_DATA)?;
    let cases = [
        (None, "no boot image"),
        (Some(&good[..init_end - 1]), "boot image: cut short"),
        (Some(&unsigned[..]), "boot image: no STAFBOOT signature"),
        (
            Some(&bad_init[..]),
            "boot image: init: no STAFPROG signature",
        ),
        (Some(&odd[..]), "boot image: not whole pages"),
        (
            Some(&huge[..]),
            "init: no memory object for its data segment",
        ),
    ];
    let path = target_dir().join("bad-boot.img");
    for (bytes, marker) in cases {
        if let Some(b) = bytes {
            std::fs::write(&path, b).map_err(|e| format!("{}: {e}", path.display()))?;
        }
        let image = bytes.map(|_| path.as_path());
        let mut cmd = qemu::command(&qemu::VIRT, &a.image, image);
        cmd.args(qemu::HEADLESS);
        let o = run_until(cmd, BOOT_TIMEOUT, None, &a.elf)?;
        qemu::expect_powered_off(&o)?;
        qemu::expect_marker(&o, "KERNEL PANIC")?;
        qemu::expect_marker(&o, marker)?;
    }
    Ok(())
}

/// An init that faults or is killed stops the machine (spec 7.9). At a
/// fault the kernel prints the fault and init's registers, panics with
/// the fault, and the machine powers off. The cases: a load through a
/// null pointer; a store to init's read-only data and a branch into it,
/// which its protection forbids (spec 3.3). An init that kills its own
/// process makes the kernel panic with «killed», and no fault is printed.
fn init_fault_stops_the_machine() -> Result<(), String> {
    let a = build(Variant::Normal)?;
    let path = target_dir().join("fault-init.img");
    let run = |image: Vec<u8>| {
        std::fs::write(&path, image).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut cmd = qemu::command(&qemu::VIRT, &a.image, Some(&path));
        cmd.args(qemu::HEADLESS);
        let o = run_until(cmd, BOOT_TIMEOUT, None, &a.elf)?;
        qemu::expect_powered_off(&o)?;
        qemu::expect_marker(&o, "KERNEL PANIC")?;
        Ok::<_, String>(o)
    };
    let cases: [(&[u32], bool, &str, &str, u64); 3] = [
        (
            &[LDR_X0_X0],
            false,
            "data abort from EL0 (EC 0x24)",
            "ESR=0x92000006 FAR=0x0 ELR=0x200000",
            0x20_0000,
        ),
        (
            &[ADR_X1_NEXT_PAGE, STR_X0_X1],
            true,
            "data abort from EL0 (EC 0x24)",
            "ESR=0x9200004f FAR=0x201000 ELR=0x200004",
            0x20_0004,
        ),
        (
            &[B_NEXT_PAGE],
            true,
            "instruction abort from EL0 (EC 0x20)",
            "ESR=0x8200000f FAR=0x201000 ELR=0x201000",
            0x20_1000,
        ),
    ];
    for (code, rodata, class, fault, elr) in cases {
        let o = run(raw_init(code, rodata, 0)?)?;
        qemu::expect_line(&o, &format!("process fault: {class} {fault}"))?;
        qemu::expect_line(&o, &init_registers(elr))?;
        qemu::expect_line(&o, &format!("init terminated by a fault: {fault}"))?;
    }
    let o = run(raw_init(&KILL_ITSELF, false, 0)?)?;
    qemu::expect_line(&o, "init terminated: Killed")?;
    if let Some(l) = o.lines.iter().find(|l| l.starts_with("process fault")) {
        return Err(format!("an init that killed itself faulted: {l}"));
    }
    Ok(())
}

/// Spec 16.1: the panic shows the records of the kernel log that nobody
/// showed or took, before its own report. An init of xtask's own
/// (raw_init) makes a device window over the console's page through its
/// system resource, which takes the port from the kernel (spec 3.2),
/// writes `pan-log` with debug_write and loads from address 0: the kernel
/// puts the line of the fault and init's registers into its log, and the
/// panic shows `pan-log`, the line and the registers, in that order,
/// before its line KERNEL PANIC and the line of its cause, every line
/// whole; the machine powers off.
fn panic_prints_the_log_nobody_showed() -> Result<(), String> {
    let a = build(Variant::Normal)?;
    let resource = abi::INIT_RESOURCE.0;
    let mut code = Vec::new();
    code.extend(mov(0, resource));
    code.extend(mov(1, CONSOLE_PA));
    code.extend(mov(2, bootimg::PAGE_SIZE));
    code.push(svc(abi::Call::DeviceWindowCreate.number()));
    code.extend(mov(0, resource));
    code.extend(mov(1, 8));
    code.extend(mov(2, u64::from_le_bytes(*b"pan-log\n")));
    code.push(svc(abi::Call::DebugWrite.number()));
    let elr = RAW_INIT_ENTRY + 4 * code.len() as u64;
    // debug_write leaves 0 in x0: the load is from page 0.
    code.push(LDR_X0_X0);
    let path = target_dir().join("panic-log-init.img");
    std::fs::write(&path, raw_init(&code, false, 0)?)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let mut cmd = qemu::command(&qemu::VIRT, &a.image, Some(&path));
    cmd.args(qemu::HEADLESS);
    let o = run_until(cmd, BOOT_TIMEOUT, None, &a.elf)?;
    qemu::expect_powered_off(&o)?;
    let at = |what: &str, found: &dyn Fn(&str) -> bool| {
        o.lines
            .iter()
            .position(|l| found(l))
            .ok_or_else(|| format!("no line of {what}; the lines: {:?}", o.lines))
    };
    let fault = format!("ESR=0x92000006 FAR=0x0 ELR={elr:#x}");
    let fault_line = format!("process fault: data abort from EL0 (EC 0x24) {fault}");
    let cause = format!("init terminated by a fault: {fault}");
    let order = [
        at("pan-log", &|l| l == "pan-log")?,
        at("the fault", &|l| l == fault_line)?,
        at("x0", &|l| l.starts_with("x0  0x"))?,
        at("init's registers", &|l| l == init_registers(elr))?,
        at("the panic", &|l| l.starts_with("KERNEL PANIC: "))?,
        at("its cause", &|l| l == cause)?,
    ];
    if !order.is_sorted() {
        return Err(format!(
            "the log did not come before the panic in its order: lines {order:?}"
        ));
    }
    Ok(())
}

/// The line of init's registers the kernel prints at its fault
/// (exceptions::user_fault) for an init of raw_init faulting at `elr`: SP
/// at abi::INIT_STACK_TOP, 0 in SPSR and TPIDR_EL0.
fn init_registers(elr: u64) -> String {
    format!(
        "sp_el0 0x0000000100000000  elr {elr:#018x}  spsr 0x0000000000000000  tpidr_el0 0x0000000000000000"
    )
}

/// A kernel that executes an undefined instruction must name the exception
/// class, print the registers, and its backtrace must name the interrupted
/// instruction: proof that exception entry recorded a frame, beyond the printing of
/// the panic handler's own frames (they would print with no record at all).
fn fault_report() -> Result<(), String> {
    let a = build(Variant::FaultProbe)?;
    let mut cmd = qemu::command(&qemu::VIRT, &a.image, Some(&a.boot_image));
    cmd.args(qemu::HEADLESS);
    let o = run_until(cmd, BOOT_TIMEOUT, None, &a.elf)?;
    qemu::expect_not_timed_out(&o)?;
    for marker in ["unknown or undefined instruction", "x0  0x", "backtrace ("] {
        qemu::expect_marker(&o, marker)?;
    }
    // The probe's record behind its window comes once, before the report.
    let logged: Vec<usize> = (0..o.lines.len())
        .filter(|&i| o.lines[i] == "probe-log")
        .collect();
    let report = o.lines.iter().position(|l| l.starts_with("x0  0x"));
    if !matches!((&logged[..], report), ([at], Some(r)) if *at < r) {
        return Err(format!(
            "the record nobody showed did not come once before the report: {:?}",
            o.lines
        ));
    }
    qemu::backtrace_names_the_fault(&o.lines)
}

/// `llvm-nm -C`, defined symbols only, on `elf`.
fn nm_defined(elf: &Path) -> Result<String, String> {
    stdout_of(
        Command::new(llvm_tool("llvm-nm")?)
            .args(["-C", "--defined-only"])
            .arg(elf),
    )
}

/// The image that ships carries none of the kernel's own tests (spec 3.4):
/// no symbol of `elf` lies in `kernel::ktest` or `kernel::testpoint`
/// (qemu::test_symbols).
fn no_test_symbols(elf: &Path) -> Result<(), String> {
    let nm = nm_defined(elf)?;
    let found = qemu::test_symbols(&nm);
    if found.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} carries test symbols it must not ship:\n{}",
            elf.display(),
            found.join("\n")
        ))
    }
}

/// `no_test_symbols` is not a check on an image that never carries test
/// symbols at all: the ktest build's own ELF does.
fn test_build_carries_test_symbols() -> Result<(), String> {
    let a = build(Variant::Test)?;
    let nm = nm_defined(&a.elf)?;
    if qemu::test_symbols(&nm).is_empty() {
        Err(format!(
            "{} has no test symbols; no_test_symbols would pass on anything",
            a.elf.display()
        ))
    } else {
        Ok(())
    }
}

/// The ELF files of the programs of the boot image that ships and of the
/// test images, each with the profile of its image: the copies their
/// images were built from (`image_elf`).
fn program_elfs() -> Result<Vec<(PathBuf, Profile)>, String> {
    let target = target_dir();
    let mut elfs = Vec::new();
    for (name, programs, profile) in [
        ("boot.img", &BOOT_PROGRAMS[..], BOOT_PROFILE),
        ("boot-test.img", &TEST_PROGRAMS[..], TEST_PROFILE),
        ("boot-svc.img", &SVC_PROGRAMS[..], TEST_PROFILE),
        ("boot-cycle.img", &CYCLE_PROGRAMS[..], TEST_PROFILE),
        ("boot-ceiling.img", &CEILING_PROGRAMS[..], TEST_PROFILE),
    ] {
        build_boot_image(name, programs, profile)?;
        for (_, package, _, _) in programs {
            elfs.push((image_elf(&target, name, package), profile));
        }
    }
    Ok(elfs)
}

/// Init's program as the boot image at `path` carries it: its header and
/// segments, with no symbols and no debug information.
fn init_program(path: &Path) -> Result<Vec<u8>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    bootimg::BootImage::parse(&bytes)
        .and_then(bootimg::BootImage::init)
        .map(<[u8]>::to_vec)
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// Spec 13.4, 15.2: the init of the boot image that ships carries no
/// record of init's test table, whose names the init of the image of that
/// table carries: each of TEST_TABLE_NAMES is looked for in the bytes of
/// both programs (`init_program`), those of INIT_WORDS only in the second.
fn shipping_init_has_no_test_table() -> Result<(), String> {
    let shipping = init_program(&build_boot_image("boot.img", &BOOT_PROGRAMS, BOOT_PROFILE)?)?;
    let testing = init_program(&build_boot_image(
        "boot-svc.img",
        &SVC_PROGRAMS,
        TEST_PROFILE,
    )?)?;
    let carries =
        |bytes: &[u8], name: &str| bytes.windows(name.len()).any(|w| w == name.as_bytes());
    for name in TEST_TABLE_NAMES {
        if carries(&shipping, name) && !INIT_WORDS.contains(&name) {
            return Err(format!(
                "the init that ships carries the test record {name}"
            ));
        }
        if !carries(&testing, name) {
            return Err(format!(
                "the init of the test table lacks its record {name}"
            ));
        }
    }
    println!(
        "no record of the test table in the init that ships, {} names",
        TEST_TABLE_NAMES.len() - INIT_WORDS.len()
    );
    Ok(())
}

/// The start of the panic of rt on BAD_HANDLE (rt::sys), which a program
/// carries only when it links that panic.
const STRICT_PANIC: &[u8] = b"BAD_HANDLE from";

/// Spec 5.4: every program of the test images, built with `checked`,
/// carries the panic on BAD_HANDLE, and no program of the boot image that
/// ships, built with `--release`, does: there the code comes back.
fn strict_panic_only_in_checked_programs() -> Result<(), String> {
    let elfs = program_elfs()?;
    for (elf, profile) in &elfs {
        let bytes = std::fs::read(elf).map_err(|e| format!("{}: {e}", elf.display()))?;
        let strict = bytes.windows(STRICT_PANIC.len()).any(|w| w == STRICT_PANIC);
        if strict != (*profile == Profile::Checked) {
            return Err(format!(
                "{} of the profile {} {} the panic on BAD_HANDLE",
                elf.display(),
                profile.dir(),
                if strict { "carries" } else { "lacks" }
            ));
        }
    }
    println!(
        "the panic on BAD_HANDLE in the checked programs alone, {} ELF files",
        elfs.len()
    );
    Ok(())
}

/// The library calls of a 128-bit division, unsigned and signed, which
/// the time scale leaves out of the kernel and the programs (spec 10,
/// abi::time::Scale).
const U128_DIVISION: [&str; 4] = ["__udivti3", "__umodti3", "__divti3", "__modti3"];

/// Which of U128_DIVISION the symbols `nm` listed define.
fn u128_division(nm: &str) -> Vec<&'static str> {
    U128_DIVISION
        .into_iter()
        .filter(|name| {
            nm.lines()
                .any(|l| l.split_whitespace().last() == Some(name))
        })
        .collect()
}

/// Spec 10: ticks and nanoseconds convert by a multiply and a shift, so
/// neither the ELF of the normal kernel nor any program of the two boot
/// images, each of its own profile (program_elfs), links a 128-bit
/// division.
fn no_u128_division_is_linked() -> Result<(), String> {
    let programs = program_elfs()?.into_iter().map(|(elf, _)| elf);
    let elfs: Vec<_> = [build(Variant::Normal)?.elf]
        .into_iter()
        .chain(programs)
        .collect();
    for elf in &elfs {
        let found = u128_division(&nm_defined(elf)?);
        if !found.is_empty() {
            return Err(format!(
                "{} links a 128-bit division: {}",
                elf.display(),
                found.join(", ")
            ));
        }
    }
    println!("no 128-bit division in {} ELF files", elfs.len());
    Ok(())
}

/// A kernel that recurses without end must report the overflow from the
/// emergency stack and power off: the report names the real ELR inside the
/// recursive function, and its backtrace goes on into the recursion on the
/// kernel stack. The function's address range comes from the ELF's symbols.
fn stack_overflow_report() -> Result<(), String> {
    let a = build(Variant::OverflowProbe)?;
    let mut cmd = qemu::command(&qemu::VIRT, &a.image, Some(&a.boot_image));
    cmd.args(qemu::HEADLESS);
    let o = run_until(cmd, BOOT_TIMEOUT, None, &a.elf)?;
    qemu::expect_powered_off(&o)?;
    for marker in ["kernel stack overflow", "backtrace ("] {
        qemu::expect_marker(&o, marker)?;
    }
    let nm = stdout_of(
        Command::new(llvm_tool("llvm-nm")?)
            .args(["-C", "--print-size", "--defined-only"])
            .arg(&a.elf),
    )?;
    let f = qemu::symbol_range(&nm, OVERFLOW_PROBE_FN)
        .ok_or_else(|| format!("{OVERFLOW_PROBE_FN} is not in {}", a.elf.display()))?;
    qemu::overflow_report_names(&o.lines, f)
}

/// Kernel built with `ktest` on machine `m`: runs its tests, prints
/// `TESTS DONE` and powers the machine off through PSCI (spec 14). On 2
/// GiB the tests also cover RAM the boot page tables did not map. Every
/// test the kernel counts passes once. The `icount` build runs under
/// qemu::ICOUNT, where virtual time counts instructions: the tests that
/// depend on how much of a quantum is left run only there. A hang, such
/// as a quantum that never ends, fails at TEST_TIMEOUT. Gives the number
/// of tests that passed. The boot report names `m`'s PSCI conduit, as
/// the kernel took it from the device tree (on VIRT_EL2 SMC).
fn kernel_tests(m: &qemu::Machine, variant: Variant) -> Result<usize, String> {
    let a = build(variant)?;
    let mut cmd = qemu::command(m, &a.image, Some(&a.boot_image));
    cmd.args(qemu::HEADLESS);
    let icount = variant == Variant::TestIcount;
    if icount {
        cmd.args(qemu::ICOUNT);
    }
    let o = run_until(cmd, TEST_TIMEOUT, None, &a.elf)?;
    let r = qemu::parse_report(&o.lines);
    qemu::counted_verdict(&o, &r, None)?;
    qemu::expect_line(&o, &format!("psci       {}", m.psci()))?;
    for name in ICOUNT_TESTS {
        if name == "ipc_round_trip_is_measured" {
            continue;
        }
        if r.passed.iter().any(|p| p == name) != icount {
            return Err(format!(
                "{name} must pass in the icount build and only there"
            ));
        }
    }
    if !r.passed.iter().any(|p| p == "ipc_round_trip_is_measured") {
        return Err("the round-trip measurement did not pass".into());
    }
    let under = if icount { " under icount" } else { "" };
    println!(
        "kernel tests{under} on {}: {} passed",
        m.name,
        r.passed.len()
    );
    if icount {
        let mut measured = Vec::new();
        for (what, rows) in [
            ("ipc round trip", &ROUND_TRIP_ROWS[..]),
            ("memory portions", &MEMORY_PORTION_ROWS[..]),
            ("timer portions", &TIMER_PORTION_ROWS[..]),
            ("interrupt path", &INTERRUPT_PATH_ROWS[..]),
            ("device window", &WINDOW_ROWS[..]),
            ("upcall", &UPCALL_ROWS[..]),
            ("teardown portions", &TEARDOWN_ROWS[..]),
            ("suspension scopes", &SUSPENSION_ROWS[..]),
        ] {
            let ticks = ticks_of(&o.lines, what, rows)?;
            println!("{what} ticks on {}: {}", m.name, rows_of(rows, &ticks));
            measured.push((what, rows, ticks));
        }
        let (margin, to_term) = b_margin(m.name, &measured)?;
        println!(
            "B margin on {}: {margin} of {KERNEL_B_MAX}, {to_term} of TERM_B {TERM_B}",
            m.name
        );
        let (_, rows, ticks) = measured
            .iter()
            .find(|(what, ..)| *what == "teardown portions")
            .ok_or("no teardown portions measured")?;
        let room = guard_margin(
            "teardown portions",
            rows,
            ticks,
            "threads_ready",
            THREADS_READY_MAX,
        )?;
        println!(
            "threads_ready margin on {}: {room} of THREADS_READY_MAX {THREADS_READY_MAX}",
            m.name
        );
        if let Some(hint) = guard_lower_hint(
            "THREADS_READY_MAX",
            room,
            THREADS_READY_SLACK,
            THREADS_READY_MAX,
            THREADS_READY_KEEP,
        ) {
            println!("{hint}");
        }
    }
    match variant {
        Variant::Baseline => measure::record_as(m, &o.lines, "baseline "),
        Variant::Trace => measure::record_as(m, &o.lines, "trace "),
        Variant::TestIcount => measure::record_as(m, &o.lines, measure::ICOUNT),
        _ => measure::record(m, &o.lines),
    }
    Ok(r.passed.len())
}

/// Measured portions and scoped components compared against B (spec 15.3).
/// Suspension control and pick rows exclude the surrounding syscall and
/// exit-loop work; their boundaries are documented with the path table.
const PORTION_LINES: [&str; 7] = [
    "memory portions",
    "timer portions",
    "interrupt path",
    "device window",
    "upcall",
    "teardown portions",
    "suspension scopes",
];

/// The longest row of the PORTION_LINES among the `measured` lines (name,
/// rows, ticks), with its line: the blocking time B of every level (spec
/// 15.3). The teardown row `threads` is a count of threads and takes no
/// part. Shown on its own so that a change of the longest row stands out
/// in the output of `ci`; `kernel_tests` fails it above KERNEL_B_MAX.
fn blocking_time<'a>(measured: &[(&'a str, &[&'a str], Vec<u64>)]) -> (&'a str, &'a str, u64) {
    measured
        .iter()
        .filter(|(what, _, _)| PORTION_LINES.contains(what))
        .flat_map(|(what, rows, ticks)| {
            rows.iter()
                .zip(ticks)
                .map(move |(row, &n)| (*what, *row, n))
        })
        .filter(|&(what, row, _)| (what, row) != ("teardown portions", "threads"))
        .max_by_key(|&(_, _, n)| n)
        .unwrap_or(("none", "none", 0))
}

/// The margins of the longest portion in `measured`, which the `B on` line
/// prints, under KERNEL_B_MAX and under TERM_B; an error when it is past
/// KERNEL_B_MAX.
fn b_margin(name: &str, measured: &[(&str, &[&str], Vec<u64>)]) -> Result<(u64, u64), String> {
    let (what, row, n) = blocking_time(measured);
    println!("B on {name}: {row}={n} ({what})");
    match KERNEL_B_MAX.checked_sub(n) {
        Some(margin) => Ok((margin, TERM_B - n)),
        None => Err(format!(
            "B on {name}: {row}={n} ({what}) is {} past KERNEL_B_MAX {KERNEL_B_MAX}",
            n - KERNEL_B_MAX
        )),
    }
}

/// The row `row` of `rows` among the `ticks`, which may not pass `max`: the
/// room left under it, or an error that names the row. The caller prints it.
fn guard_margin(
    what: &str,
    rows: &[&str],
    ticks: &[u64],
    row: &str,
    max: u64,
) -> Result<u64, String> {
    let n = rows
        .iter()
        .zip(ticks)
        .find_map(|(r, &n)| (*r == row).then_some(n))
        .ok_or_else(|| format!("the {what} line has no row {row}"))?;
    max.checked_sub(n)
        .ok_or_else(|| format!("{what} {row}={n} is {} past its guard {max}", n - max))
}

/// The line that asks to lower the guard `name` when its `room` under `max`
/// is larger than `slack`: the new number is the measure plus `keep` ticks,
/// the room the rule of that guard keeps (`NULL_KEEP` and `THREADS_READY_KEEP`
/// 4, `S5_ICOUNT_KEEP` 16).
fn guard_lower_hint(name: &str, room: u64, slack: u64, max: u64, keep: u64) -> Option<String> {
    (room > slack).then(|| format!("lower {name} to {}", max - room + keep))
}

/// `rows` with their `ticks`, as `<row>=<n> ...`.
fn rows_of(rows: &[&str], ticks: &[u64]) -> String {
    let rows: Vec<_> = rows
        .iter()
        .zip(ticks)
        .map(|(row, n)| format!("{row}={n}"))
        .collect();
    rows.join(" ")
}

/// The numbers of the line `<what> ticks: <row>=<n> ...` that a measuring
/// test prints (`ipc round trip`, `memory portions`), one for each of
/// `rows` in that order: an error when no line has them all.
fn ticks_of(lines: &[String], what: &str, rows: &[&str]) -> Result<Vec<u64>, String> {
    let prefix = format!("{what} ticks: ");
    let line = lines
        .iter()
        .find_map(|l| l.strip_prefix(prefix.as_str()))
        .ok_or_else(|| format!("the kernel printed no {what} ticks"))?;
    let fields: Vec<_> = line.split_whitespace().collect();
    if fields.len() != rows.len() {
        return Err(format!("the {what} line has other rows: {line:?}"));
    }
    rows.iter()
        .zip(fields)
        .map(|(row, field)| {
            field
                .strip_prefix(row)
                .and_then(|f| f.strip_prefix('='))
                .and_then(|n| n.parse().ok())
                .ok_or_else(|| format!("{field:?} is no {row} row of the {what} line"))
        })
        .collect()
}

/// The test init (tests/init) as init of the normal build, the kernel that
/// ships, on machine `m`, under qemu::ICOUNT when `icount`, with its child
/// program (tests/child) as the second file of the boot image: each of its
/// INIT_TESTS tests passes once, the lines it, its children and the kernel
/// print for the tests come whole, CHILD_FAULTS children fault, and it
/// exits with 0, which the kernel ends with a panic that names the code
/// (qemu::expect_init_exit after `TESTS DONE`). Its first line says how
/// long a counted loop took, which under -icount must be the loop's
/// instructions; there it also prints the costs of the build that ships
/// (NORMAL_BUILD_ROWS), which fail nothing by their numbers (spec 15.3).
/// Under HVF qemu::hvf_verdict judges the run: the test of a window on a
/// hole fails, one child fewer faults, and init exits with 1. Gives the
/// number of tests that passed.
fn init_tests(m: &qemu::Machine, icount: bool) -> Result<usize, String> {
    let a = build(Variant::Normal)?;
    let image = build_boot_image("boot-test.img", &TEST_PROGRAMS, TEST_PROFILE)?;
    let mut cmd = qemu::command(m, &a.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    if icount {
        cmd.args(qemu::ICOUNT);
    }
    let o = run_until(cmd, TEST_TIMEOUT, None, &a.elf)?;
    let r = qemu::parse_report(&o.lines);
    let hvf = m.is_hvf();
    if hvf {
        qemu::hvf_verdict(&o, &r)?;
    } else {
        qemu::counted_verdict(&o, &r, Some(0))?;
    }
    if r.total != Some(INIT_TESTS) {
        return Err(format!(
            "the test init has {:?} tests, {INIT_TESTS} expected",
            r.total
        ));
    }
    for line in TEST_INIT_LINES {
        qemu::expect_line(&o, line)?;
    }
    log_markers(&o)?;
    child_panic_comes_whole(&o.lines)?;
    let faults = o
        .lines
        .iter()
        .filter(|l| l.starts_with("process fault: "))
        .count();
    let made = CHILD_FAULTS - usize::from(hvf);
    if faults != made {
        return Err(format!(
            "{faults} process fault lines; the test init makes {made}"
        ));
    }
    let ticks = qemu::number_after(&o.lines, "counter ticks of 10000 turns: ")
        .ok_or("the test init printed no loop time")?;
    if icount && !(20_000..=20_100).contains(&ticks) {
        return Err(format!(
            "{ticks} ticks for 10000 turns: the run is not under -icount"
        ));
    }
    let under = if icount { " under icount" } else { "" };
    println!("init tests{under} on {}: {} passed", m.name, r.passed.len());
    if icount {
        let ticks = ticks_of(&o.lines, "normal build", &NORMAL_BUILD_ROWS)?;
        println!(
            "normal build ticks on {}: {}",
            m.name,
            rows_of(&NORMAL_BUILD_ROWS, &ticks)
        );
        let room = guard_margin("normal build", &NORMAL_BUILD_ROWS, &ticks, "null", NULL_MAX)?;
        println!("null margin on {}: {room} of NULL_MAX {NULL_MAX}", m.name);
        if let Some(hint) = guard_lower_hint("NULL_MAX", room, NULL_SLACK, NULL_MAX, NULL_KEEP) {
            println!("{hint}");
        }
        let ticks = ticks_of(&o.lines, "log", &LOG_ROWS)?;
        println!("log ticks on {}: {}", m.name, rows_of(&LOG_ROWS, &ticks));
    }
    measure::record_as(m, &o.lines, if icount { measure::ICOUNT } else { "" });
    Ok(r.passed.len())
}

/// Spec 3.2: the line the test init writes behind a window over the
/// console's page reaches no line of the port, and the one it writes once
/// the window went comes whole.
fn log_markers(o: &qemu::Outcome) -> Result<(), String> {
    if let Some(l) = o.lines.iter().find(|l| l.contains(LOG_BEHIND)) {
        return Err(format!("a line behind the window reached the port: {l}"));
    }
    qemu::expect_line(o, LOG_IN_FRONT)
}

/// The image of init's test table (spec 15.2): init built with
/// `table-test` and the test services (tests/svc), on the normal build of
/// the kernel, on machine `m`. The client `checker` runs its tests: each
/// of its SVC_TESTS passes once, then it ends, and xtask stops QEMU on
/// init's line of its end (qemu::counted_verdict of a run stopped on its
/// line, where no panic may come). Init's lines of the failures and of
/// the end of the client come whole
/// (`failure_lines_name_the_reason_and_the_pause`,
/// `a_client_that_ends_is_not_restarted`). Gives the number of tests that
/// passed.
fn svc_tests(m: &qemu::Machine) -> Result<usize, String> {
    let a = build(Variant::Normal)?;
    let image = build_boot_image("boot-svc.img", &SVC_PROGRAMS, TEST_PROFILE)?;
    let mut cmd = qemu::command(m, &a.image, Some(&image));
    cmd.args(qemu::HEADLESS);
    let o = run_until(cmd, TEST_TIMEOUT, Some(CHECKER_END), &a.elf)?;
    let r = qemu::parse_report(&o.lines);
    qemu::counted_verdict(&o, &r, None)?;
    failure_lines_name_the_reason_and_the_pause(&o.lines)?;
    the_watchdog_names_the_level_it_kills_from(&o.lines)?;
    a_client_that_ends_is_not_restarted(&o)?;
    if r.total != Some(SVC_TESTS) {
        return Err(format!(
            "the checker has {:?} tests, {SVC_TESTS} expected",
            r.total
        ));
    }
    println!("service tests on {}: {} passed", m.name, r.passed.len());
    Ok(r.passed.len())
}

/// Spec 13.4, 16.2: init prints one line for each failure of `crash` of
/// its test table, with its reason, a fault at address 0 with the
/// syndrome and the address of the load, and its decision, those of
/// CRASH_DECISIONS in their order. The wait of `hog` for quota is no
/// failure: one line says that it waits, none that it ended or did not
/// load.
fn failure_lines_name_the_reason_and_the_pause(lines: &[String]) -> Result<(), String> {
    let crash: Vec<&str> = lines
        .iter()
        .filter_map(|l| l.strip_prefix("init: crash ended: "))
        .collect();
    if crash.len() != CRASH_DECISIONS.len() {
        return Err(format!(
            "{} lines of failures of crash, {} expected: {crash:?}",
            crash.len(),
            CRASH_DECISIONS.len()
        ));
    }
    let hex = |s: &str| u64::from_str_radix(s, 16).is_ok();
    for (line, decision) in crash.iter().zip(CRASH_DECISIONS) {
        let (reason, got) = line.split_once("; ").unwrap_or((line, ""));
        let fault = reason
            .strip_prefix("fault ESR=0x")
            .and_then(|r| r.split_once(" FAR=0x0 ELR=0x"))
            .is_some_and(|(esr, elr)| hex(esr) && hex(elr));
        if !fault || got != decision {
            return Err(format!(
                "init: crash ended: {line}: a fault at 0 and {decision:?} expected"
            ));
        }
    }
    let waits = lines
        .iter()
        .filter(|l| l.starts_with("init: hog waits for quota: needs "))
        .count();
    let failed = lines
        .iter()
        .find(|l| l.starts_with("init: hog ended") || l.starts_with("init: hog did not load"));
    match (waits, failed) {
        (1, None) => Ok(()),
        (_, Some(line)) => Err(format!("the wait of hog for quota failed it: {line}")),
        (n, None) => Err(format!("{n} lines of hog's wait for quota, one expected")),
    }
}

/// Spec 13.4, 16.2: init names the level its worker kills a silent
/// service from, one above the service's ceiling, and its decision: every
/// line of a silent service whole, in its order, and no other
/// (SILENT_KILLED).
fn the_watchdog_names_the_level_it_kills_from(lines: &[String]) -> Result<(), String> {
    let got: Vec<&str> = lines
        .iter()
        .map(String::as_str)
        .filter(|l| l.contains(" went silent, "))
        .collect();
    if got != SILENT_KILLED {
        return Err(format!(
            "the lines of silent services are {got:?}, {SILENT_KILLED:?} expected"
        ));
    }
    Ok(())
}

/// Spec 13.4: the client `checker`, whose policy is never, ends with code
/// 0 once its tests are done, and init does not start it again: the run
/// stopped on CHECKER_ENDED, its last line, with no panic before it.
fn a_client_that_ends_is_not_restarted(o: &qemu::Outcome) -> Result<(), String> {
    qemu::expect_stopped_on(o, CHECKER_ENDED)
}

/// Spec 13.4, 15.2: init refuses each table of REFUSED before it starts
/// anything. Its image, on the normal build of the kernel on VIRT, prints
/// the reason line whole and ends with init's exit with code 2, which the
/// kernel ends with a panic after it (qemu::expect_init_exit).
fn bad_tables_are_refused() -> Result<(), String> {
    let a = build(Variant::Normal)?;
    for (name, programs, reason) in REFUSED {
        let image = build_boot_image(name, programs, TEST_PROFILE)?;
        let mut cmd = qemu::command(&qemu::VIRT, &a.image, Some(&image));
        cmd.args(qemu::HEADLESS);
        let o = run_until(cmd, BOOT_TIMEOUT, None, &a.elf)?;
        qemu::expect_line(&o, reason)?;
        qemu::expect_init_exit(&o, "init: table refused: ", 2)?;
    }
    println!("bad tables refused: {} images", REFUSED.len());
    Ok(())
}

/// The panic of a child comes whole (spec 13.2): a line with where it
/// panicked, CHILD_PANIC_AT and the line and column, then CHILD_PANIC on
/// the next line.
fn child_panic_comes_whole(lines: &[String]) -> Result<(), String> {
    let whole = lines.windows(2).any(|pair| {
        let place = pair[0].strip_prefix(CHILD_PANIC_AT).and_then(|p| {
            let (line, column) = p.strip_suffix(':')?.split_once(':')?;
            line.parse::<u32>().ok().zip(column.parse::<u32>().ok())
        });
        place.is_some() && pair[1] == CHILD_PANIC
    });
    if whole {
        Ok(())
    } else {
        Err("the child's panic did not come whole".into())
    }
}

fn gdb() -> Result<(), String> {
    let a = build(Variant::Normal)?;
    println!(
        "QEMU is halted before the kernel starts (kernel entry: PA 0x40200000). In another terminal:\n  lldb {} -o 'gdb-remote 1234'\nCode before the MMU runs at physical addresses; see docs/debugging.md.",
        a.elf.display()
    );
    run_cmd(
        qemu::command(&qemu::VIRT, &a.image, Some(&a.boot_image)).args(["-nographic", "-s", "-S"]),
    )
}

/// `cargo xtask hvf` (spec 14, 15.2): on a Mac with Apple silicon, for
/// HVF_V3 and then HVF_V2, the boot of the normal build with the counter
/// at HVF_HZ, the console dialog, the test init under qemu::hvf_verdict,
/// the image of init's test table and the kernel tests, with a line of
/// results for each machine. Elsewhere it prints why it skips and
/// succeeds: `ci` does not run it.
fn hvf() -> Result<(), String> {
    if let Err(why) = hvf_host() {
        println!(
            "hvf: skipped: needs macOS on Apple Silicon with the Hypervisor framework ({why})"
        );
        return Ok(());
    }
    for (m, gic) in [(&qemu::HVF_V3, GIC_V3_LINE), (&qemu::HVF_V2, GIC_V2_LINE)] {
        let hz = boot_smoke(m, gic)?;
        if hz != HVF_HZ {
            return Err(format!("the counter runs at {hz} Hz on {}", m.name));
        }
        console_dialog(m)?;
        trace_dialog(m)?;
        // relibc's pthreads and the POSIX processes, the loader of files
        // among them, on the real processor.
        if m.name == qemu::HVF_V3.name {
            relibc_threads_probe(m)?;
            posix_procs_probe(m)?;
        }
        // The entropy device's DMA through the real processor's caches,
        // and the layer's generator across fork.
        entropy::probe(m)?;
        entropy::random_probe(m)?;
        let init = init_tests(m, false)?;
        let svc = svc_tests(m)?;
        let mut kernel = 0;
        for pair in 0..20 {
            let variants = if pair % 2 == 0 {
                [Variant::Test, Variant::Baseline]
            } else {
                [Variant::Baseline, Variant::Test]
            };
            for variant in variants {
                let passed = kernel_tests(m, variant)?;
                if variant == Variant::Test {
                    kernel = passed;
                }
            }
        }
        for _ in 0..20 {
            kernel_tests(m, Variant::Trace)?;
        }
        write_measures()?;
        println!(
            "hvf on {}: boot ok, console dialog ok, entropy ok, relibc threads and POSIX processes ok on GICv3, init tests {init} passed (hole reads zero), service tests {svc} passed, kernel tests {kernel} passed",
            m.name
        );
    }
    Ok(())
}

fn write_measures() -> Result<(), String> {
    let a = build(Variant::Normal)?;
    let size = |path: &Path| {
        std::fs::metadata(path)
            .map(|m| m.len())
            .map_err(|e| format!("{}: {e}", path.display()))
    };
    measure::write_all(&target_dir(), size(&a.image)?, size(&a.boot_image)?)
}

/// qemu::hvf_host on this host: its OS and processor, `sysctl -n
/// kern.hv_support` and `qemu-system-aarch64 -accel help`; a command that
/// does not run gives no output.
fn hvf_host() -> Result<(), String> {
    let output = |cmd: &mut Command| {
        cmd.output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default()
    };
    qemu::hvf_host(
        std::env::consts::OS,
        std::env::consts::ARCH,
        &output(Command::new("sysctl").args(["-n", "kern.hv_support"])),
        &output(Command::new("qemu-system-aarch64").args(["-accel", "help"])),
    )
}

/// The names the layer's crates (`lib/posix-*`) may give the linker: the
/// platform's `stafeto_*` (and its `STAFETO_PLATFORM_ABI`) and posix-crt's
/// `__rt_main`. A C name there would stand in for relibc's, or clash with
/// it (step 5a′).
fn layer_symbol_allowed(name: &str) -> bool {
    name.to_ascii_lowercase().starts_with("stafeto_") || name == "__rt_main"
}

/// The C names in `listing`, the output of `llvm-nm --defined-only -g`:
/// the global symbols that are no Rust symbol (`_R`, `_ZN`), which the
/// linker would match with relibc's.
fn c_symbols(listing: &str) -> Vec<String> {
    listing
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let (_, kind, name) = (words.next()?, words.next()?, words.next()?);
            (kind != "U" && !name.starts_with("_R") && !name.starts_with("_ZN"))
                .then(|| name.to_owned())
        })
        .collect()
}

/// The `.rlib` files cargo's JSON messages `messages` name for packages
/// whose crate starts with `posix_`.
fn layer_libraries(messages: &str) -> Vec<PathBuf> {
    messages
        .lines()
        .filter(|line| {
            line.contains("\"reason\":\"compiler-artifact\"") && line.contains("\"name\":\"posix_")
        })
        .flat_map(|line| {
            line.split('"')
                .filter(|word| word.ends_with(".rlib"))
                .map(PathBuf::from)
                .collect::<Vec<_>>()
        })
        .collect()
}

/// No C names in the layer: the symbols of every crate of `lib/posix-*`,
/// as built for the programs, are Rust's or `layer_symbol_allowed`
/// (`no_mangle`, `export_name`, `global_asm!` and macros alike).
fn layer_c_names() -> Result<(), String> {
    let mut packages = Vec::new();
    for entry in std::fs::read_dir(root().join("lib")).map_err(|e| format!("lib: {e}"))? {
        let path = entry.map_err(|e| format!("lib: {e}"))?.path();
        if !path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("posix-"))
        {
            continue;
        }
        let manifest = std::fs::read_to_string(path.join("Cargo.toml"))
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let name = manifest
            .lines()
            .find_map(|line| line.strip_prefix("name = \""))
            .and_then(|rest| rest.strip_suffix('"'))
            .ok_or_else(|| format!("{}: no package name", path.display()))?;
        packages.push(name.to_owned());
    }
    let mut cmd = cargo();
    cmd.args([
        "build",
        "--release",
        "--target",
        PROGRAM_TARGET,
        "--message-format=json",
    ]);
    for package in &packages {
        cmd.args(["--package", package]);
    }
    let messages = stdout_of(&mut cmd)?;
    let libraries = layer_libraries(&messages);
    if libraries.len() < packages.len() {
        return Err(format!(
            "the layer's names: {} libraries for {} packages",
            libraries.len(),
            packages.len()
        ));
    }
    let nm = llvm_tool("llvm-nm")?;
    let mut found = Vec::new();
    for library in &libraries {
        let listing = stdout_of(
            Command::new(&nm)
                .args(["--defined-only", "-g", "--no-sort"])
                .arg(library),
        )?;
        for name in c_symbols(&listing) {
            if !layer_symbol_allowed(&name) {
                found.push(format!("{}: {name}", library.display()));
            }
        }
    }
    if found.is_empty() {
        println!(
            "layer C names: none in {} libraries, only stafeto_* and __rt_main",
            libraries.len()
        );
        Ok(())
    } else {
        Err(format!("C names in the layer (relibc has them): {found:?}"))
    }
}

/// The layer's `.data` and `.bss` in the ELF `elf`: the sizes of the
/// symbols of the layer's crates (`posix_*`, `rt`), by `llvm-nm`.
fn layer_data(elf: &Path) -> Result<u64, String> {
    let output = stdout_of(
        Command::new(llvm_tool("llvm-nm")?)
            .args(["--size-sort", "-S", "-C"])
            .arg(elf),
    )?;
    Ok(layer_data_of(&output))
}

/// `layer_data` of the output of `llvm-nm --size-sort -S -C`.
fn layer_data_of(listing: &str) -> u64 {
    listing
        .lines()
        .filter_map(|line| {
            let mut words = line.splitn(4, ' ');
            let (_, size, kind, name) =
                (words.next()?, words.next()?, words.next()?, words.next()?);
            let layer = name.starts_with("posix_") || name.starts_with("rt::");
            (layer && matches!(kind, "b" | "B" | "d" | "D"))
                .then(|| u64::from_str_radix(size, 16).ok())?
        })
        .sum()
}

/// The size of `.text` in the ELF `elf` (`llvm-size -A`).
fn text_size(elf: &Path) -> Result<u64, String> {
    let output = stdout_of(Command::new(llvm_tool("llvm-size")?).arg("-A").arg(elf))?;
    output
        .lines()
        .find_map(|line| {
            let mut words = line.split_whitespace();
            (words.next() == Some(".text")).then(|| words.next()?.parse().ok())?
        })
        .ok_or_else(|| format!("{}: no .text", elf.display()))
}

/// The test hooks of the reply journals went with the journals (spec 6.1):
/// no Cargo.toml of the workspace names the feature `transport-probe`.
fn no_transport_probe() -> Result<(), String> {
    let mut found = Vec::new();
    let mut paths = vec![root()];
    while let Some(path) = paths.pop() {
        if path.is_dir() {
            if path
                .file_name()
                .is_some_and(|n| n == "target" || n == ".git")
            {
                continue;
            }
            let entries = std::fs::read_dir(&path).map_err(|e| format!("{path:?}: {e}"))?;
            for entry in entries {
                paths.push(entry.map_err(|e| format!("{path:?}: {e}"))?.path());
            }
        } else if path.file_name().is_some_and(|n| n == "Cargo.toml") {
            let text = std::fs::read_to_string(&path).map_err(|e| format!("{path:?}: {e}"))?;
            if text.contains("transport-probe") {
                found.push(path);
            }
        }
    }
    if !found.is_empty() {
        return Err(format!("the feature transport-probe is back in {found:?}"));
    }
    println!("no Cargo.toml names transport-probe");
    Ok(())
}

fn ci(jobs: usize) -> Result<(), String> {
    // First: the licence check and the C programs take relibc's build.
    relibc()?;
    run_cmd(Command::new("python3").arg(root().join("tools/check-licenses.py")))?;
    no_transport_probe()?;
    layer_c_names()?;
    run_cmd(cargo().args(["fmt", "--all", "--check"]))?;
    run_cmd(cargo().args([
        "clippy",
        "--package",
        "abi",
        "--package",
        "bootimg",
        "--package",
        "ext4ro",
        "--package",
        "posix-path",
        "--package",
        "posix-fd",
        "--package",
        "posix-change",
        "--package",
        "posix-types",
        "--package",
        "posix-heap",
        "--package",
        "posix-map",
        "--package",
        "posix-order",
        "--package",
        "posix-request",
        "--package",
        "posix-time",
        "--package",
        "posix-signals",
        "--package",
        "posix-signal-queue",
        "--package",
        "entries",
        "--package",
        "posix-credentials",
        "--package",
        "proto-process",
        "--package",
        "kcore",
        "--package",
        "proto-init",
        "--package",
        "proto-fs",
        "--package",
        "proto-uart",
        "--package",
        "proto-wire",
        "--package",
        "proto-clock",
        "--package",
        "proto-pipe",
        "--package",
        "proto-loader",
        "--package",
        "xtask",
        "--package",
        "proto-tty",
        "--package",
        "virtio-pci",
        "--package",
        "proto-entropy",
        "--package",
        "posix-random",
        "--all-targets",
        "--",
        "-D",
        "warnings",
    ]))?;
    // The libraries of init, of the UART driver and of the shell and their
    // tests on the host; their programs build for stafeto alone, below.
    run_cmd(cargo().args([
        "clippy",
        "--package",
        "init",
        "--package",
        "ramfs",
        "--package",
        "pipe",
        "--package",
        "shell",
        "--package",
        "uart",
        "--package",
        "virtio-console",
        "--package",
        "posix-process-service",
        "--package",
        "tty",
        "--package",
        "virtio-rng",
        "--package",
        "entropy",
        "--lib",
        "--tests",
        "--",
        "-D",
        "warnings",
    ]))?;
    run_cmd(cargo().args([
        "clippy",
        "--package",
        "abi",
        "--package",
        "bootimg",
        "--target",
        KERNEL_TARGET,
        "--",
        "-D",
        "warnings",
    ]))?;
    // The kernel's code: every unsafe block says why it is sound.
    run_cmd(cargo().args([
        "clippy",
        "--package",
        "kcore",
        "--target",
        KERNEL_TARGET,
        "--",
        "-D",
        "warnings",
        "-D",
        "clippy::undocumented_unsafe_blocks",
    ]))?;
    run_cmd(cargo().args([
        "clippy",
        "--package",
        "proto-init",
        "--package",
        "proto-fs",
        "--package",
        "proto-uart",
        "--package",
        "proto-wire",
        "--package",
        "proto-clock",
        "--package",
        "proto-pipe",
        "--package",
        "rt",
        "--package",
        "posix-fs",
        "--package",
        "posix-signal-queue",
        "--package",
        "entries",
        "--package",
        "posix-abi",
        "--package",
        "posix-crt",
        "--package",
        "posix-abi-probe",
        "--package",
        "posix-clock",
        "--package",
        "posix-clock-service",
        "--package",
        "posix-process-service",
        "--package",
        "process-client",
        "--package",
        "posix-clock-peer",
        "--package",
        "posix-tls-probe",
        "--package",
        "posix-thread",
        "--package",
        "posix-sync",
        "--package",
        "posix-thread-probe",
        "--package",
        "posix-shared-probe",
        "--package",
        "ext4ro",
        "--package",
        "init",
        "--package",
        "ramfs",
        "--package",
        "pipe",
        "--package",
        "shell",
        "--package",
        "uart",
        "--package",
        "virtio-console",
        "--features",
        "uart/crash,virtio-console/crash,init/dma-watch,posix-shared-probe/input-probe,posix-process-service/adoption-refusals,posix-abi/rtbench",
        "--package",
        "loader",
        "--package",
        "test-init",
        "--package",
        "test-child",
        "--package",
        "ext4ro-probe",
        "--package",
        "ramfs-probe",
        "--package",
        "test-svc",
        "--package",
        "rtbench",
        "--package",
        "rtbench-posix",
        "--package",
        "rtbench-load",
        "--package",
        "tty",
        "--package",
        "tty-probe",
        "--package",
        "virtio-rng",
        "--package",
        "entropy-probe",
        "--package",
        "entropy",
        "--features",
        "virtio-rng/crash,virtio-rng/steps,entropy/steps,entropy/report",
        "--target",
        PROGRAM_TARGET,
        "--",
        "-D",
        "warnings",
    ]))?;
    // Init as it ships, without the feature of the probe of a stop.
    run_cmd(cargo().args([
        "clippy",
        "--package",
        "init",
        "--target",
        PROGRAM_TARGET,
        "--",
        "-D",
        "warnings",
    ]))?;
    run_cmd(cargo().args([
        "clippy",
        "--package",
        "posix-shared-probe",
        "--features",
        "interrupt-probe",
        "--target",
        PROGRAM_TARGET,
        "--",
        "-D",
        "warnings",
    ]))?;
    // The layer under relibc (posix-abi without its C names), apart: the
    // feature would take the C names from the programs above.
    run_cmd(cargo().args([
        "clippy",
        "--package",
        "posix-platform",
        "--package",
        "relibc-hello",
        "--package",
        "relibc-threads",
        "--package",
        "posix-procs",
        "--package",
        "os-test-run",
        "--package",
        "posix-random-probe",
        "--package",
        "posix-pty",
        "--target",
        PROGRAM_TARGET,
        "--",
        "-D",
        "warnings",
    ]))?;
    run_cmd(cargo().args([
        "clippy",
        "--package",
        "posix-thread-probe",
        "--features",
        "cancel-input",
        "--target",
        PROGRAM_TARGET,
        "--",
        "-D",
        "warnings",
    ]))?;
    for variant in Variant::ALL {
        let mut cmd = cargo();
        cmd.args([
            "clippy",
            "--package",
            "kernel",
            "--release",
            "--target",
            KERNEL_TARGET,
        ]);
        if let Some(feature) = variant.feature() {
            cmd.args(["--features", feature]);
        }
        run_cmd(cmd.args([
            "--",
            "-D",
            "warnings",
            "-D",
            "clippy::undocumented_unsafe_blocks",
        ]))?;
    }
    test(jobs)?;
    let a = build(Variant::Normal)?;
    disasm::shipping(&a.elf, &llvm_tool("llvm-objdump")?)
}

#[cfg(test)]
mod tests {
    fn names_log(repeats: &str) -> Vec<String> {
        [
            "posix-procs: names time a missing component: 73 requests, 617628 ticks",
            "posix-procs: names time unlink /tmp/a: 27 requests, 250823 ticks",
            "posix-procs: names time rmdir: 96 requests, 853412 ticks",
            "posix-procs: names time chdir to depth 64: 130 requests, 900000 ticks",
            "posix-procs: names time getcwd at depth 64: 0 requests, 1971 ticks",
            "posix-procs: names time a path of 32 links: 672 requests, 5704952 ticks",
            "posix-procs: names time rename of a directory under a chain 64 deep: 1559 requests, 15679606 ticks",
            "posix-procs: names time rmdir with a full table: 96 requests, 855238 ticks",
            "posix-procs: names thread cost: 28672 bytes (7 pages) for the first thread, 28672 bytes the last, 86016 bytes for 3, stack 20480 bytes",
            "posix-procs: names starvation: rmdir in a table of 382 names against a loop of utimensat: 0 restarts, finished within 10 s: yes, took 218444 ticks, alone 110180 ticks, requests 10, alone requests 10",
            "posix-procs: names interference G2: a path of 32 links against a name made and removed in another directory: 0 restarts, finished within 10 s: yes, result 0, took 1356992 ticks, alone 629874 ticks",
            "posix-procs: names interference G2b: a rename against a colliding name in another directory: 0 restarts, finished within 10 s: yes, result 0, took 2900000 ticks, alone 1300000 ticks",
            "posix-procs: names interference G3: the rename of a directory under a chain 64 deep against chmod of a file: 0 restarts, finished within 10 s: yes, result 0, took 2895999 ticks, alone 1308386 ticks",
            "posix-procs: names interference G4: a rename over a name that is made and removed in the same directory: 3042 restarts, finished within 10 s: no, result 0, took 624667089 ticks, alone 145549 ticks",
            "posix-procs: names interference G5: the canonical path of a directory 64 deep against directories that move: 1602 restarts, finished within 10 s: no, result 0, took 625555306 ticks, alone 1172516 ticks",
            repeats,
            "posix-procs: names volley in directories: 16 processes of 7 threads, 112 renames, all done, the most repeats of JOBS_FULL of one thread 12, the most restarts of one rename 2, the longest rename 25107135 ticks, 177424279 ticks",
            "posix-procs: names volley ok",
            "posix-procs: names gone ok",
            "posix-procs: names bounds commit after 500 rival names: 0 restarts, commit 14000 ticks, baseline 13900 ticks",
            "posix-procs: names bounds reclaim: 1 nodes with pages, backlog 1 -> 2, pages 2 -> 2, commit 12369 ticks, 0 restarts",
            "posix-procs: names bounds reclaim: 32 nodes with pages, backlog 32 -> 33, pages 33 -> 32, commit 12488 ticks, 0 restarts",
            "posix-procs: names bounds ok",
        ]
        .iter()
        .map(|line| (*line).to_owned())
        .collect()
    }

    /// The lines of the names volley are all there, the volley ended in 112
    /// renames and some thread met JOBS_FULL.
    #[test]
    fn the_names_volley_lines_are_read_strictly() {
        let good = "posix-procs: names volley: 16 processes of 7 threads, 112 renames, all done, the most repeats of JOBS_FULL of one thread 13, the most restarts of one rename 4, the longest rename 99000000 ticks, 6879297680 ticks";
        assert!(super::names_lines(&names_log(good)).is_ok());
        let none = good.replace("thread 13", "thread 0");
        assert!(super::names_lines(&names_log(&none)).is_err());
        let slow_publish: Vec<String> = names_log(good)
            .iter()
            .map(|line| line.replace("commit 14000 ticks", "commit 15401 ticks"))
            .collect();
        assert!(super::names_lines(&slow_publish).is_err());
        let missing_publish_ticks: Vec<String> = names_log(good)
            .iter()
            .map(|line| line.replace(", commit 14000 ticks", ""))
            .collect();
        assert!(super::names_lines(&missing_publish_ticks).is_err());
        // G6: no thread repeats its Start more than 64 times.
        let many = good.replace("thread 13", "thread 65");
        assert!(super::names_lines(&names_log(&many)).is_err());
        let limit = good.replace("thread 13", "thread 64");
        assert!(super::names_lines(&names_log(&limit)).is_ok());
        // A change of the verdict of the starvation line is a change of the
        // expectation: the line that says "no" is refused until the
        // constant says so.
        let mut turned = names_log(good);
        for line in &mut turned {
            if line.contains("names starvation") {
                *line = line.replace("finished within 10 s: yes", "finished within 10 s: no");
            }
        }
        assert!(super::names_lines(&turned).is_err());
        // G1 rejects restarts, extra requests and more than 2.5 times the quiet time.
        let mut restarted = names_log(good);
        for line in &mut restarted {
            if line.contains("names starvation") {
                *line = line.replace("utimensat: 0 restarts", "utimensat: 1 restarts");
            }
        }
        assert!(super::names_lines(&restarted).is_err());
        let mut slow = names_log(good);
        for line in &mut slow {
            if line.contains("names starvation") {
                *line = line.replace("took 218444 ticks", "took 275451 ticks");
            }
        }
        assert!(super::names_lines(&slow).is_err());
        for replacement in [
            ", requests 11, alone requests 10",
            ", requests 0, alone requests 0",
        ] {
            let changed: Vec<String> = names_log(good)
                .iter()
                .map(|line| line.replace(", requests 10, alone requests 10", replacement))
                .collect();
            assert!(super::names_lines(&changed).is_err());
        }
        for ticks in [220361, 275450] {
            let boundary: Vec<String> = names_log(good)
                .iter()
                .map(|line| line.replace("took 218444 ticks", &format!("took {ticks} ticks")))
                .collect();
            assert!(super::names_lines(&boundary).is_ok());
        }
        // G2 and G3 end with no restart; G4 and G5 only have to be printed.
        for tag in ["G2", "G2b", "G3"] {
            let mut bad = names_log(good);
            for line in &mut bad {
                if line.contains(&format!("interference {tag}")) {
                    *line = line.replace(": 0 restarts", ": 1 restarts");
                }
            }
            assert!(super::names_lines(&bad).is_err(), "{tag}");
        }
        for tag in ["G4", "G5"] {
            let mut without = names_log(good);
            without.retain(|line| !line.contains(&format!("interference {tag}")));
            assert!(super::names_lines(&without).is_err(), "{tag}");
        }
        for prefix in [
            "bounds reclaim: 1 nodes",
            "bounds reclaim: 32 nodes",
            "bounds commit after 500",
        ] {
            let mut missing = names_log(good);
            missing.retain(|line| !line.contains(prefix));
            assert!(super::names_lines(&missing).is_err());
        }
        let extra_page: Vec<String> = names_log(good)
            .iter()
            .map(|line| line.replace("pages 2 -> 2", "pages 2 -> 1"))
            .collect();
        assert!(super::names_lines(&extra_page).is_err());
        let lost_page: Vec<String> = names_log(good)
            .iter()
            .map(|line| line.replace("pages 33 -> 32", "pages 33 -> 33"))
            .collect();
        assert!(super::names_lines(&lost_page).is_err());
        let mut without_bounds = names_log(good);
        without_bounds.retain(|line| !line.contains("names bounds ok"));
        assert!(super::names_lines(&without_bounds).is_err());
        let no_restarts = good.replace("the most restarts of one rename 4, ", "");
        assert!(super::names_lines(&names_log(&no_restarts)).is_err());
        let no_longest = good.replace("the longest rename 99000000 ticks, ", "");
        assert!(super::names_lines(&names_log(&no_longest)).is_err());
        let fewer = good.replace("112 renames, all done", "97 renames");
        assert!(super::names_lines(&names_log(&fewer)).is_err());
        let mut without_row = names_log(good);
        without_row.remove(2);
        assert!(super::names_lines(&without_row).is_err());
        let mut without_volley = names_log(good);
        without_volley.retain(|line| !line.contains("names volley:"));
        assert!(super::names_lines(&without_volley).is_err());
        let mut without_directories = names_log(good);
        without_directories.retain(|line| !line.contains("in directories"));
        assert!(super::names_lines(&without_directories).is_err());
        let mut without_gone = names_log(good);
        without_gone.retain(|line| !line.contains("names gone ok"));
        assert!(super::names_lines(&without_gone).is_err());
        let mut short_directories = names_log(good);
        for line in &mut short_directories {
            if line.contains("in directories") {
                *line = line.replace("112 renames, all done", "97 renames");
            }
        }
        assert!(super::names_lines(&short_directories).is_err());
    }

    /// The lines of the ash script are checked exactly, in order, after
    /// `shell-ready`.
    #[test]
    fn the_output_of_the_ash_names_script_is_exact() {
        let log = |lines: &[&str]| -> Vec<String> {
            ["boot", "shell-ready"]
                .iter()
                .chain(lines)
                .map(|line| (*line).to_owned())
                .collect()
        };
        assert!(super::expect_ash_names(&log(&super::ASH_NAMES_OUTPUT)).is_ok());
        // A line missing (a `mv` that did not run), another text, another order.
        let mut without = super::ASH_NAMES_OUTPUT.to_vec();
        without.remove(1);
        assert!(super::expect_ash_names(&log(&without)).is_err());
        let mut other = super::ASH_NAMES_OUTPUT.to_vec();
        other[7] = "mode -rw-r--r--";
        assert!(super::expect_ash_names(&log(&other)).is_err());
        let mut swapped = super::ASH_NAMES_OUTPUT.to_vec();
        swapped.swap(0, 1);
        assert!(super::expect_ash_names(&log(&swapped)).is_err());
        assert!(super::expect_ash_names(&["boot".to_owned()]).is_err());
    }

    #[test]
    fn only_names_image_enables_service_signal_pause() {
        use super::*;
        assert_eq!(POSIX_NAMES_PROGRAMS[1].3, &["signal-probe"]);
        for programs in [
            &POSIX_PROCS_PROGRAMS[..],
            &POSIX_LIFETIMES_PROGRAMS[..],
            &POSIX_LOCK_RING_PROGRAMS[..],
            &POSIX_NATIVE_SCOPE_PROGRAMS[..],
            &POSIX_VZ_NATIVE_SCOPE_PROGRAMS[..],
            &POSIX_STEPS_PROGRAMS[..],
        ] {
            assert!(
                programs
                    .iter()
                    .all(|program| !program.3.contains(&"signal-probe"))
            );
        }
    }

    #[test]
    fn lifetime_probe_has_its_own_process_and_program_features() {
        let manifest = include_str!("../../tests/posix-procs/Cargo.toml");
        let close_features: Vec<_> = manifest
            .lines()
            .filter(|line| line.contains("posix-abi/close-probe"))
            .collect();
        assert_eq!(close_features.len(), 1);
        assert!(close_features[0].starts_with("lifetime-probe = "));
        assert_eq!(POSIX_LIFETIMES_PROGRAMS[1].3, &["lifetime-probe", "steps"]);
        assert_eq!(POSIX_LIFETIMES_PROGRAMS[3].3, &["lifetime-probe"]);
        assert_eq!(POSIX_LIFETIMES_PROGRAMS[5].3, &["lifetime-probe"]);
        assert_eq!(
            &POSIX_LOCK_RING_PROGRAMS[1..],
            &POSIX_LIFETIMES_PROGRAMS[1..]
        );
        assert_eq!(POSIX_LOCK_RING_PROGRAMS[0].3, &["table-posix-lock-ring"]);
        for programs in [
            &POSIX_PROCS_PROGRAMS[..],
            &POSIX_NAMES_PROGRAMS[..],
            &POSIX_NATIVE_SCOPE_PROGRAMS[..],
            &POSIX_VZ_NATIVE_SCOPE_PROGRAMS[..],
            &POSIX_STEPS_PROGRAMS[..],
            &POSIX_FILES_PROGRAMS[..],
        ] {
            assert!(
                programs
                    .iter()
                    .all(|program| !program.3.contains(&"lifetime-probe"))
            );
        }
    }

    #[test]
    fn native_images_keep_the_loader_pool_and_both_platforms() {
        use super::*;
        assert_eq!(POSIX_NATIVE_SCOPE_PROGRAMS.len(), 11);
        assert_eq!(POSIX_VZ_NATIVE_SCOPE_PROGRAMS.len(), 12);
        for (index, expected) in POSIX_PROCS_PROGRAMS.iter().enumerate() {
            if index != 5 {
                assert_eq!(POSIX_NATIVE_SCOPE_PROGRAMS[index], *expected);
            }
        }
        assert_eq!(
            POSIX_NATIVE_SCOPE_PROGRAMS[5].3,
            &["pending-open", "native-scopes-launcher"]
        );
        assert_eq!(
            POSIX_VZ_NATIVE_SCOPE_PROGRAMS[0].3,
            &["table-posix-native-vz"]
        );
        assert_eq!(
            &POSIX_VZ_NATIVE_SCOPE_PROGRAMS[1..11],
            &POSIX_NATIVE_SCOPE_PROGRAMS[1..]
        );
        assert_eq!(
            POSIX_VZ_NATIVE_SCOPE_PROGRAMS[11],
            ("virtio-console", "virtio-console", UART_STACK_SIZE, &[][..])
        );
        for name in [
            "boot-posix-native-scopes.img",
            "boot-posix-native-scopes-vz.img",
        ] {
            let files = rootfs::files_of(name);
            let native = files
                .iter()
                .find(|file| file.path == "/bin/native-scopes")
                .unwrap();
            assert_eq!(native.mode, 0o755);
            assert_eq!(
                native.source.as_ref().and_then(rootfs::Source::program),
                Some("posix-thread-probe")
            );
        }
    }

    #[test]
    fn longest_waits_reads_its_lines_only() {
        let lines: Vec<String> = [
            "service step: 2 kind 25 8000 ticks detail 0",
            "service wait: 2 kind 25 9000 ticks of 17000",
            "service wait: 4 kind 64 5000 ticks of 6000",
            "service wait: 2 kind 25 12246 ticks of 18306",
            "service wait: 2 kind 65 100 ticks of 200",
            "service wait: 2 kind x 100 ticks of 200",
            "service wait: 2 kind 7 100 ticks 200",
        ]
        .map(String::from)
        .into();
        // The last line of a kind is its longest; W is the wait and A the step.
        assert_eq!(
            longest_waits(&lines, "2"),
            vec![(25, 12_246, 18_306), (65, 100, 200)]
        );
        assert_eq!(longest_waits(&lines, "4"), vec![(64, 5_000, 6_000)]);
        assert!(longest_waits(&lines, "5").is_empty());
        assert_eq!(wait_of(&longest_waits(&lines, "2"), 25), 12_246);
        assert_eq!(wait_of(&longest_waits(&lines, "2"), 1), 0);
    }

    #[test]
    fn the_spawn_start_limit_holds_the_largest_run_and_the_call_wait_sum() {
        // 94,134 is the run of fix round 2 with another layout of the probe;
        // the limit of the call wait must hold the longest step of the
        // process service, a step of the callee (term B) and a round trip.
        let spawn = PROCESS_STEPS_ABOVE_B
            .iter()
            .find(|(k, ..)| *k == 22)
            .expect("SpawnStart is in the list");
        assert!(spawn.3 >= 94_134 + NOISE_MARGIN);
        assert!(spawn.3 + TERM_B + 2_034 <= CALL_WAIT_MAX);
    }

    #[test]
    fn a_wait_past_the_limit_fails() {
        // A call has CALL_WAIT_MAX, the heartbeat WAIT_MAX, and a cut line fails.
        let call = |w: u64| vec![format!("service wait: 2 kind 25 {w} ticks of {w}")];
        assert!(check_waits(&call(CALL_WAIT_MAX), &["2"], "t").is_ok());
        assert!(check_waits(&call(CALL_WAIT_MAX + 1), &["2"], "t").is_err());
        let cut = vec!["service wait cut: 2 kind 25 9000 ticks of 8000".to_owned()];
        assert!(check_waits(&cut, &["5"], "t").is_err());
        let ok = vec![format!(
            "service wait: 4 kind 64 {WAIT_MAX} ticks of 600000"
        )];
        assert!(check_waits(&ok, &["4"], "t").is_ok());
        let bad = vec![format!(
            "service wait: 4 kind 64 {} ticks of 600000",
            WAIT_MAX + 1
        )];
        assert!(check_waits(&bad, &["4"], "t").is_err());
        assert!(check_waits(&bad, &["5"], "t").is_ok());
    }

    #[test]
    fn full_watch_case_survives_a_longer_single_item_maximum() {
        let mut lines = Vec::new();
        // The pipe service's full Watch has 32 elements, the terminal's 16.
        for (tag, methods, full) in [(4, [14, 15, 16], 32), (5, [25, 26, 27], 16)] {
            for method in methods {
                lines.push(format!(
                    "service step: {tag} kind {method} 15000 ticks detail 1"
                ));
                lines.push(format!(
                    "service case: {tag} kind {method} 14000 ticks detail {full}"
                ));
            }
            for kind in [64, 65] {
                lines.push(format!(
                    "service step: {tag} kind {kind} 1000 ticks detail 0"
                ));
            }
        }
        assert!(super::check_watch_steps(&lines).is_ok());
        let mut missing = lines.clone();
        missing.retain(|line| !line.starts_with("service case: 5 kind 26 "));
        assert!(super::check_watch_steps(&missing).is_err());
        // A Watch of the terminal past B, past 18 000 under B, or with
        // more than 16 elements fails.
        for bad in [
            "service case: 5 kind 26 20539 ticks detail 16",
            "service case: 5 kind 25 18500 ticks detail 16",
            "service step: 5 kind 25 15000 ticks detail 32",
        ] {
            let mut worse = lines.clone();
            worse.push(bad.into());
            assert!(super::check_watch_steps(&worse).is_err(), "{bad}");
        }
    }
    use super::*;

    /// The check of the layer's names takes every global defined symbol
    /// that is no Rust symbol, and lets through only the platform's names.
    #[test]
    fn layer_names_are_found() {
        let listing = "\n/x/libposix_abi.rlib(posix_abi-1.o):\n\
                       0000000000000000 T strlen\n\
                       0000000000000010 T _RNvCs123_9posix_abi4open\n\
                       0000000000000020 T _ZN9posix_abi4read17h0E\n\
                       0000000000000030 T stafeto_read\n\
                       0000000000000040 T __rt_main\n\
                       0000000000000050 D STAFETO_PLATFORM_ABI\n\
                       0000000000000060 T memset\n\
                                        U strcmp\n";
        let names = c_symbols(listing);
        assert_eq!(
            names,
            [
                "strlen",
                "stafeto_read",
                "__rt_main",
                "STAFETO_PLATFORM_ABI",
                "memset"
            ]
        );
        let refused: Vec<_> = names.iter().filter(|n| !layer_symbol_allowed(n)).collect();
        assert_eq!(refused, ["strlen", "memset"]);
    }

    /// The libraries of the layer come from cargo's messages.
    #[test]
    fn layer_libraries_come_from_cargo() {
        let messages = "{\"reason\":\"compiler-artifact\",\"target\":{\"name\":\"posix_abi\"},\"filenames\":[\"/t/libposix_abi-1.rlib\",\"/t/libposix_abi-1.rmeta\"]}\n\
                        {\"reason\":\"compiler-artifact\",\"target\":{\"name\":\"rt\"},\"filenames\":[\"/t/librt-2.rlib\"]}\n";
        assert_eq!(
            layer_libraries(messages),
            [PathBuf::from("/t/libposix_abi-1.rlib")]
        );
    }

    /// The layer's data counts the data and bss symbols of its crates.
    #[test]
    fn layer_data_counts_its_crates() {
        let listing = "0000000000001000 0000000000000800 b posix_sync::TABLE\n\
                       0000000000002000 0000000000000100 d rt::time::SCALE\n\
                       0000000000003000 0000000000000388 b relibc::ALLOCATOR\n\
                       0000000000004000 0000000000000040 t posix_abi::read\n\
                       0000000000005000 0000000000000010 D posix_abi::relibc::TABLE\n";
        assert_eq!(layer_data_of(listing), 0x800 + 0x100 + 0x10);
    }

    #[test]
    fn kill_itself_is_what_an_assembler_makes() {
        // movz x0, #0x1; movk x0, #0x1, lsl #16; svc #13; ldr x0, [x0]
        assert_eq!(
            KILL_ITSELF,
            [0xD280_0020, 0xF2A0_0020, 0xD400_01A1, 0xF940_0000]
        );
    }

    #[test]
    fn variants_have_their_own_artifacts_and_features() {
        let all = Variant::ALL;
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a.stem(), b.stem());
                assert_ne!(a.feature(), b.feature());
            }
        }
        assert_eq!(Variant::Normal.feature(), None);
    }

    /// The build that ships and its probes keep the limit of spec 3.4; the
    /// builds with the kernel tests have one of their own.
    #[test]
    fn test_builds_have_a_limit_of_their_own() {
        for variant in [Variant::Normal, Variant::FaultProbe, Variant::OverflowProbe] {
            assert_eq!(variant.limit(), (204_800, "spec 3.4"));
        }
        for variant in [Variant::Test, Variant::TestIcount] {
            assert_eq!(variant.limit(), (524_288, "test builds"));
        }
    }

    /// The text of every file under `dirs` of the workspace that reads as
    /// UTF-8, with its path from the workspace's root.
    fn texts(dirs: &[&str]) -> Vec<(String, String)> {
        let mut found = Vec::new();
        let mut paths: Vec<_> = dirs.iter().map(|dir| root().join(dir)).collect();
        while let Some(path) = paths.pop() {
            if path.is_dir() {
                let entries = std::fs::read_dir(&path).expect("a readable directory");
                paths.extend(entries.map(|e| e.expect("a directory entry").path()));
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let name = path.strip_prefix(root()).expect("a path in the workspace");
            found.push((name.to_string_lossy().into_owned(), text));
        }
        found
    }

    /// The kernel keeps the FP and SIMD registers for programs and saves
    /// them only when threads switch (spec 8), so FP or SIMD anywhere else
    /// in the kernel would change a program's registers without a word.
    /// Only the thread switch and the EL0 test programs may assemble them.
    /// Every crate linked into the kernel is searched: the kernel itself,
    /// kcore, abi and bootimg.
    #[test]
    fn only_the_thread_switch_uses_fp() {
        let mut found: Vec<_> = texts(&["kernel", "kcore", "lib/abi", "lib/bootimg"])
            .into_iter()
            .filter(|(_, text)| {
                text.lines().any(|l| {
                    (l.contains(".arch_extension") && (l.contains("fp") || l.contains("simd")))
                        || ((l.contains("target_feature") || l.contains("target-feature"))
                            && (l.contains("neon") || l.contains("fp-armv8")))
                })
            })
            .map(|(name, _)| name)
            .collect();
        found.sort();
        assert_eq!(
            found,
            ["kernel/src/arch/aarch64/fpsimd.S", "kernel/src/ktest/el0.S"]
        );
    }

    /// Cargo writes under CARGO_TARGET_DIR when it is set, which cargo
    /// takes from the directory it runs in, the workspace's root for
    /// xtask's builds, and under target/ of the workspace otherwise; the
    /// kernel's ELF and the programs are taken from there.
    #[test]
    fn artifacts_come_from_cargo_target_dir() {
        let root = Path::new("/w");
        assert_eq!(target_dir_of(None, root), Path::new("/w/target"));
        assert_eq!(target_dir_of(Some("/t".into()), root), Path::new("/t"));
        assert_eq!(target_dir_of(Some("out".into()), root), Path::new("/w/out"));
        assert_eq!(
            cargo_output(
                &target_dir_of(Some("/t".into()), root),
                KERNEL_TARGET,
                Profile::Release,
                "kernel"
            ),
            Path::new("/t/aarch64-unknown-none-softfloat/release/kernel")
        );
    }

    /// The lines of the section `[profile.NAME]` of the workspace's
    /// Cargo.toml, up to the next section.
    fn profile_section(name: &str) -> Vec<String> {
        let toml = std::fs::read_to_string(root().join("Cargo.toml")).expect("Cargo.toml");
        let head = format!("[profile.{name}]");
        toml.lines()
            .skip_while(|l| *l != head)
            .skip(1)
            .take_while(|l| !l.starts_with('['))
            .map(str::to_string)
            .collect()
    }

    /// Spec 5.4, 15.2: the programs of the test images build with the
    /// profile `checked`, release with debug assertions, where rt is
    /// strict; cargo writes them under checked/.
    #[test]
    fn test_images_build_with_the_checked_profile() {
        assert_eq!(TEST_PROFILE.args(), ["--profile", "checked"]);
        assert_eq!(
            cargo_output(Path::new("/t"), PROGRAM_TARGET, TEST_PROFILE, "test-init"),
            Path::new("/t/aarch64-unknown-none/checked/test-init")
        );
        let checked = profile_section("checked");
        for line in ["inherits = \"release\"", "debug-assertions = true"] {
            assert!(
                checked.iter().any(|l| l == line),
                "[profile.checked] has no line {line}"
            );
        }
    }

    /// Spec 5.4: the boot image that ships builds with `--release`, whose
    /// profile keeps debug assertions off; that its programs carry no
    /// panic on BAD_HANDLE, the step strict_panic_only_in_checked_programs
    /// checks on the ELF files.
    #[test]
    fn normal_image_builds_without_checks() {
        assert_eq!(BOOT_PROFILE.args(), ["--release"]);
        assert!(
            !profile_section("release")
                .iter()
                .any(|l| l.starts_with("debug-assertions")),
            "[profile.release] sets debug-assertions"
        );
    }

    /// `u128_division` finds the symbols of a 128-bit division in the
    /// lines `llvm-nm -C --defined-only` prints, and nothing in others.
    #[test]
    fn u128_division_is_found_by_its_symbols() {
        let nm = "ffffffffc001d3b8 t __udivti3\n0000000000201000 T _start\n";
        assert_eq!(u128_division(nm), ["__udivti3"]);
        assert!(u128_division("0000000000201000 T __umodti3_like\n").is_empty());
        let both = "1 T __umodti3\n2 t __udivti3\n";
        assert_eq!(u128_division(both), ["__udivti3", "__umodti3"]);
        let signed = "1 T __modti3\n2 t __divti3\n";
        assert_eq!(u128_division(signed), ["__divti3", "__modti3"]);
    }

    /// `once` calls `make` at most once for a key: a second call with the
    /// same key returns the cached value with no further call, a call with
    /// another key builds its own, and a `make` that fails is not cached.
    #[test]
    fn once_builds_a_key_only_once() {
        let made: Mutex<Vec<(&str, u32)>> = Mutex::new(Vec::new());
        let calls = Mutex::new(0u32);
        let make = |calls: &Mutex<u32>| {
            *calls.lock().unwrap_or_else(PoisonError::into_inner) += 1;
            Ok(*calls.lock().unwrap_or_else(PoisonError::into_inner))
        };
        assert_eq!(once(&made, "a", || make(&calls)), Ok(1));
        assert_eq!(once(&made, "a", || make(&calls)), Ok(1));
        assert_eq!(*calls.lock().unwrap_or_else(PoisonError::into_inner), 1);
        assert_eq!(once(&made, "b", || make(&calls)), Ok(2));
        assert_eq!(*calls.lock().unwrap_or_else(PoisonError::into_inner), 2);

        let failing: Mutex<Vec<(&str, u32)>> = Mutex::new(Vec::new());
        assert_eq!(
            once(&failing, "x", || Err::<u32, _>("no".into())),
            Err("no".into())
        );
        assert_eq!(once(&failing, "x", || Ok(1)), Ok(1));
    }

    /// The boot report passes with each of its lines whole, and fails
    /// without any one of them or with one that tells of another machine;
    /// the RAM and the PSCI conduit come from the machine.
    #[test]
    fn boot_smoke_needs_every_report_line() {
        assert_eq!(
            (qemu::VIRT.ram(), qemu::VIRT_2G.ram()),
            (512 << 20, 2 << 30)
        );
        assert_eq!(
            (qemu::VIRT.psci(), qemu::VIRT_EL2_V3.psci()),
            ("Hvc", "Smc")
        );
        let report = [
            "stafeto 0.1.0 booting",
            "memory     0x40000000..0x60000000",
            "boot image 0x48000000..0x48005000",
            GIC_V2_LINE,
            "psci       Hvc",
            "timer      62500000 Hz",
            "boot complete",
        ]
        .map(String::from);
        let check = |lines: &[String], m, gic| boot_report(lines, m, 0x5000, gic);
        assert_eq!(check(&report, &qemu::VIRT, GIC_V2_LINE), Ok(62_500_000));
        for i in 0..report.len() {
            let mut cut = report.to_vec();
            cut.remove(i);
            let cut = check(&cut, &qemu::VIRT, GIC_V2_LINE);
            assert!(cut.is_err(), "without {:?}", report[i]);
        }
        assert!(check(&report, &qemu::VIRT, GIC_V3_LINE).is_err());
        assert!(check(&report, &qemu::VIRT_2G, GIC_V2_LINE).is_err());
        assert!(check(&report, &qemu::VIRT_EL2, GIC_V2_LINE).is_err());
        for (i, other) in [
            (2, "boot image 0x48000000..0x48006000"),
            (5, "timer      0 Hz"),
        ] {
            let mut changed = report.clone();
            changed[i] = other.to_string();
            let changed = check(&changed, &qemu::VIRT, GIC_V2_LINE);
            assert!(changed.is_err(), "with {other:?}");
        }
        let mut el2 = report.clone();
        el2[4] = "psci       Smc".to_string();
        el2[5] = "timer      24000000 Hz".to_string();
        assert_eq!(check(&el2, &qemu::VIRT_EL2, GIC_V2_LINE), Ok(24_000_000));
        // The early line after the report's memory, or twice, is out of its
        // order.
        let mut late = report.to_vec();
        late.swap(0, 1);
        assert!(check(&late, &qemu::VIRT, GIC_V2_LINE).is_err());
        let mut twice = report.to_vec();
        twice.push("stafeto 0.2.0 booting".into());
        assert!(check(&twice, &qemu::VIRT, GIC_V2_LINE).is_err());
    }

    /// `cargo xtask run` boots VIRT; with `--hvf` it boots HVF_V3 only
    /// where HVF runs and names the reason otherwise; other arguments are
    /// refused.
    #[test]
    fn run_takes_hvf_only_where_it_runs() {
        let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let here = || Ok(());
        let elsewhere = || Err("this is linux on x86_64".to_string());
        let name = |m: Result<&qemu::Machine, String>| m.map(|m| m.name);
        assert_eq!(name(run_machine(&args(&[]), here)), Ok(qemu::VIRT.name));
        assert_eq!(
            name(run_machine(&args(&[]), elsewhere)),
            Ok(qemu::VIRT.name)
        );
        assert_eq!(
            name(run_machine(&args(&["--hvf"]), here)),
            Ok(qemu::HVF_V3.name)
        );
        let why = run_machine(&args(&["--hvf"]), elsewhere).map(drop);
        assert!(why.is_err_and(|e| e.contains("this is linux on x86_64")));
        for other in [&["--hfv"][..], &["--hvf", "--hvf"], &["-nographic"]] {
            assert!(run_machine(&args(other), here).is_err(), "{other:?}");
        }
    }

    /// The lines of a `crash uart` as a run of the normal build shows them:
    /// a record the dead instance did not show before the fault line.
    fn crash_run(decision: &str) -> Vec<String> {
        [
            "stafeto> crash uart",
            CRASHING,
            "init: services started",
            "process fault: data abort from EL0 (EC 0x24) ESR=0x92000006 FAR=0x0 ELR=0x202a34",
            &format!("init: uart ended: fault ESR=0x92000006 FAR=0x0 ELR=0x202a34; {decision}"),
            UART_LINE,
            RECONNECTED,
        ]
        .map(String::from)
        .to_vec()
    }

    /// Spec 13.6, 16.2: a `crash uart` passes with the kernel's line of the
    /// fault and init's line with its decision, each once, and the lines
    /// in their order; it fails with either line missing or twice, with
    /// another decision or reason, or out of order.
    #[test]
    fn a_crash_shows_the_fault_and_the_restart_once() {
        let run = crash_run("restarts in 200 ms");
        assert_eq!(crash_lines(&run, "restarts in 200 ms"), Ok(()));
        assert!(crash_lines(&run, "restarts in 100 ms").is_err());
        for i in 1..run.len() {
            let mut cut = run.clone();
            cut.remove(i);
            if i != 2 {
                assert!(
                    crash_lines(&cut, "restarts in 200 ms").is_err(),
                    "without {i}"
                );
            }
            let mut twice = run.clone();
            twice.insert(i, run[i].clone());
            if i != 2 && i != run.len() - 1 {
                assert!(
                    crash_lines(&twice, "restarts in 200 ms").is_err(),
                    "{i} twice"
                );
            }
        }
        let mut swapped = run.clone();
        swapped.swap(3, 4);
        assert!(crash_lines(&swapped, "restarts in 200 ms").is_err());
        let mut late = run.clone();
        late.swap(5, 6);
        assert!(crash_lines(&late, "restarts in 200 ms").is_err());
        let mut exited = run.clone();
        exited[4] = "init: uart ended: exit code 5; restarts in 200 ms".into();
        assert!(crash_lines(&exited, "restarts in 200 ms").is_err());
        let mut elsewhere = run.clone();
        elsewhere[3] = elsewhere[3].replace("FAR=0x0", "FAR=0x8");
        assert!(crash_lines(&elsewhere, "restarts in 200 ms").is_err());
    }

    /// Spec 13.4, 16.3: the fifth crash passes with the shell's lines, then
    /// the fault and init's line with the mark of a broken service, each
    /// once and in this order; it fails with either of the last missing or
    /// before BROKEN, or with a new driver after it.
    #[test]
    fn a_broken_driver_shows_its_end_after_the_shell() {
        let end = format!(
            "init: uart ended: fault ESR=0x92000006 FAR=0x0 ELR=0x202a34; {}",
            CRASH_DECISIONS[4]
        );
        let run: Vec<String> = [
            "stafeto> crash uart",
            CRASHING,
            BROKEN,
            "process fault: data abort from EL0 (EC 0x24) ESR=0x92000006 FAR=0x0 ELR=0x202a34",
            &end,
        ]
        .map(String::from)
        .to_vec();
        assert_eq!(broken_lines(&run), Ok(()));
        for i in 1..run.len() {
            let mut cut = run.clone();
            cut.remove(i);
            assert!(broken_lines(&cut).is_err(), "without {i}");
        }
        let mut early = run.clone();
        early.swap(2, 3);
        assert!(broken_lines(&early).is_err());
        let mut restarted = run.clone();
        restarted.push(UART_LINE.into());
        assert!(broken_lines(&restarted).is_err());
    }

    /// The drivers reach registers through arch::mmio and rt::mmio only
    /// (spec 9): one `ldr` or `str` with the address in a register, which a
    /// hypervisor emulates from the syndrome [G34]. `read_volatile` and
    /// `write_volatile` may compile to a pair or a writeback, which stops
    /// QEMU under HVF. Every file of the services and the programs is
    /// checked, a new driver with them; the kernel's drivers and those of
    /// the tests are listed.
    #[test]
    fn device_registers_go_through_mmio() {
        let listed = [
            "kernel/src/arch/aarch64/gic.rs",
            "kernel/src/console.rs",
            "tests/init/src/devices.rs",
            "tests/svc/src/device.rs",
        ];
        let mut files: Vec<PathBuf> = listed.iter().map(|f| root().join(f)).collect();
        for dir in ["services", "apps"] {
            rust_files(&root().join(dir), &mut files);
        }
        assert!(
            files
                .iter()
                .any(|f| f.ends_with("services/uart/src/irq.rs")),
            "the walk missed the UART driver"
        );
        for file in files {
            let text = std::fs::read_to_string(&file).expect("a device file");
            assert!(
                !text.contains("read_volatile") && !text.contains("write_volatile"),
                "{} reaches a register without mmio",
                file.display()
            );
        }
    }

    /// The `.rs` files under `dir`, at any depth, into `files`; none for a
    /// directory that is not there.
    fn rust_files(dir: &Path, files: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                rust_files(&path, files);
            } else if path.extension().is_some_and(|e| e == "rs") {
                files.push(path);
            }
        }
    }

    /// Each access of arch::mmio and rt::mmio is one plain `ldr` or `str`
    /// (or a byte of it) with the address in a register, with no writeback
    /// and no pair, or the `dmb oshst` of `wmb` [G34]: a hypervisor
    /// emulates only such an access from the syndrome.
    #[test]
    fn mmio_is_one_plain_load_or_store() {
        let allowed = [
            "ldr {v:w}, [{a}]",
            "str {v:w}, [{a}]",
            "ldrb {v:w}, [{a}]",
            "strb {v:w}, [{a}]",
            "ldr {v}, [{a}]",
            "str {v}, [{a}]",
            "dmb oshst",
        ];
        for file in ["kernel/src/arch/aarch64/mmio.rs", "lib/rt/src/mmio.rs"] {
            let text = std::fs::read_to_string(root().join(file)).expect("an mmio file");
            let mut accesses = 0;
            for line in text.lines().filter(|line| line.contains("asm!(")) {
                // The template, and no second template after it.
                let template = line
                    .split_once("asm!(\"")
                    .and_then(|(_, rest)| rest.split_once('"'))
                    .filter(|(_, rest)| !rest.starts_with(", \""))
                    .map(|(template, _)| template);
                assert!(
                    template.is_some_and(|t| allowed.contains(&t)),
                    "{file}: {line}"
                );
                accesses += 1;
            }
            assert!(accesses > 0, "{file} has no access");
        }
    }

    /// The round trip's line gives its six rows in order, and nothing else
    /// passes for it.
    #[test]
    fn round_trip_line_gives_six_rows() {
        let what = "ipc round trip";
        let line = "ipc round trip ticks: null=1 switch=2 fast=3 slow=4 buffer=5 handles=6";
        let lines = ["TEST fast_path_is_taken ok", line].map(String::from);
        let ticks = ticks_of(&lines, what, &ROUND_TRIP_ROWS);
        assert_eq!(ticks, Ok(vec![1, 2, 3, 4, 5, 6]));
        for bad in [
            "ipc round trip ticks: null=1 switch=2 fast=3 slow=4 buffer=5",
            "ipc round trip ticks: null=1 switch=2 fast=3 slow=4 handles=5 buffer=6",
            "ipc round trip ticks: null=x switch=2 fast=3 slow=4 buffer=5 handles=6",
            "ipc round trip ticks: null=1 switch=2 fast=3 slow=4 buffer=5 handles=6 more=7",
        ] {
            let lines = [bad.to_string()];
            assert!(ticks_of(&lines, what, &ROUND_TRIP_ROWS).is_err(), "{bad}");
        }
        assert!(ticks_of(&[], what, &ROUND_TRIP_ROWS).is_err());
    }

    /// The line of the portions of memory objects gives its eleven rows in
    /// order, and the round trip's does not pass for it.
    #[test]
    fn memory_portions_line_gives_eleven_rows() {
        let what = "memory portions";
        let line = "memory portions ticks: create=1 create_high=2 map=3 map_exec=4 unmap=5 protect=6 \
                    protect_exec=7 release=8 first_map=9 dma_create=10 dma_release=11";
        let lines = [line.to_string()];
        let ticks = ticks_of(&lines, what, &MEMORY_PORTION_ROWS);
        assert_eq!(ticks, Ok((1..=11).collect()));
        for bad in [
            "memory portions ticks: create=1 map=2 map_exec=3 unmap=4 protect=5 protect_exec=6 release=7",
            "memory portions ticks: map=2 create=1 map_exec=3 unmap=4 protect=5 protect_exec=6 release=7 first_map=8",
            "ipc round trip ticks: null=1 switch=2 fast=3 slow=4 buffer=5 handles=6",
        ] {
            let lines = [bad.to_string()];
            assert!(
                ticks_of(&lines, what, &MEMORY_PORTION_ROWS).is_err(),
                "{bad}"
            );
        }
    }

    /// The guards of the paths of epoch 2 name the row and the excess.
    #[test]
    fn a_path_past_its_guard_fails_with_the_row_named() {
        let null = |n| {
            guard_margin(
                "normal build",
                &NORMAL_BUILD_ROWS,
                &[n, 1, 1, 1, 1],
                "null",
                NULL_MAX,
            )
        };
        assert_eq!(null(NULL_MAX), Ok(0));
        assert_eq!(null(262), Ok(4));
        let error = null(NULL_MAX + 1).unwrap_err();
        assert!(
            error.contains("null=267") && error.contains("1 past"),
            "{error}"
        );
        let mut teardown = [0; 10];
        teardown[TEARDOWN_ROWS
            .iter()
            .position(|r| *r == "threads_ready")
            .unwrap()] = THREADS_READY_MAX + 8;
        let error = guard_margin(
            "teardown portions",
            &TEARDOWN_ROWS,
            &teardown,
            "threads_ready",
            THREADS_READY_MAX,
        )
        .unwrap_err();
        assert!(error.contains("threads_ready=12776"), "{error}");
        assert!(guard_margin("x", &NORMAL_BUILD_ROWS, &[0; 5], "none", 1).is_err());
    }

    /// A guard with more room than its slack asks to be lowered; at the slack
    /// it stays quiet.
    #[test]
    fn a_guard_with_much_room_asks_to_be_lowered() {
        assert_eq!(
            guard_lower_hint("NULL_MAX", 4, NULL_SLACK, NULL_MAX, NULL_KEEP),
            None
        );
        assert_eq!(
            guard_lower_hint("NULL_MAX", NULL_SLACK, NULL_SLACK, NULL_MAX, NULL_KEEP),
            None
        );
        assert_eq!(
            guard_lower_hint("NULL_MAX", 17, NULL_SLACK, NULL_MAX, NULL_KEEP),
            Some("lower NULL_MAX to 253".to_owned())
        );
        assert_eq!(
            guard_lower_hint(
                "THREADS_READY_MAX",
                129,
                THREADS_READY_SLACK,
                THREADS_READY_MAX,
                THREADS_READY_KEEP
            ),
            Some("lower THREADS_READY_MAX to 12643".to_owned())
        );
        // S5 keeps 16 above its measure: a measure 17 under the number
        // (room 17) asks for the measure plus 16, which leaves room 16.
        assert_eq!(
            guard_lower_hint(
                "S5_ICOUNT_MAX",
                17,
                S5_ICOUNT_SLACK,
                S5_ICOUNT_MAX,
                S5_ICOUNT_KEEP
            ),
            Some("lower S5_ICOUNT_MAX to 2769".to_owned())
        );
    }

    /// B is the longest row of any line of portions or short calls, never
    /// the count of threads and never a row of the round trip, which spans
    /// two calls.
    #[test]
    fn a_suspension_number_past_the_kernel_bound_fails_the_parse_of_the_log() {
        let log = |n: u64| {
            vec![format!(
                "suspension scopes ticks: control_stop_no_queue=33 control_stop_cancel=99 \
                 pick_park_selected=80 control_continue=94 resume_64=3731 longest_portion={n}"
            )]
        };
        let margin = |n| {
            let ticks = ticks_of(&log(n), "suspension scopes", &SUSPENSION_ROWS)?;
            b_margin("t", &[("suspension scopes", &SUSPENSION_ROWS[..], ticks)])
        };
        assert_eq!(margin(KERNEL_B_MAX), Ok((0, TERM_B - KERNEL_B_MAX)));
        assert!(
            margin(KERNEL_B_MAX + 1)
                .unwrap_err()
                .contains("past KERNEL_B_MAX")
        );
    }

    #[test]
    fn blocking_time_is_the_longest_row_but_threads() {
        let line =
            |what, rows: &'static [&'static str], ticks: &[u64]| (what, rows, ticks.to_vec());
        let memory = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let timers = [1, 2, 3, 4];
        let teardown = [5, 15, 1, 24, 42, 30, 20, 21, 7, 128];
        let mut measured = vec![
            line("ipc round trip", &ROUND_TRIP_ROWS, &[1, 2, 3, 4, 5, 99_999]),
            line("memory portions", &MEMORY_PORTION_ROWS, &memory),
            line("timer portions", &TIMER_PORTION_ROWS, &timers),
            line("interrupt path", &INTERRUPT_PATH_ROWS, &[1, 2, 3, 4]),
            line("device window", &WINDOW_ROWS, &[1, 2, 3]),
            line("upcall", &UPCALL_ROWS, &[1, 2, 3, 4, 5]),
            line("teardown portions", &TEARDOWN_ROWS, &teardown),
        ];
        assert_eq!(
            blocking_time(&measured),
            ("teardown portions", "teardown_threads", 42)
        );
        measured[6].2 = vec![5, 15, 1, 24, 18, 30, 20, 21, 7, 50_000];
        assert_eq!(
            blocking_time(&measured),
            ("teardown portions", "child_threads", 30)
        );
        // The longest portion of any teardown is B as well.
        measured[6].2[8] = 31;
        assert_eq!(
            blocking_time(&measured),
            ("teardown portions", "teardown_any", 31)
        );
        measured[6].2[8] = 7;
        // A memory portion above every teardown row is B.
        measured[1].2[8] = 31;
        assert_eq!(
            blocking_time(&measured),
            ("memory portions", "first_map", 31)
        );
        // So is the timer queue's, and a device window's.
        measured[2].2[1] = 32;
        assert_eq!(blocking_time(&measured), ("timer portions", "fire", 32));
        measured[4].2[1] = 33;
        assert_eq!(blocking_time(&measured), ("device window", "map", 33));
        // An upcall call is a stretch of its own as well.
        measured[5].2[4] = 34;
        assert_eq!(blocking_time(&measured), ("upcall", "return", 34));
    }

    /// A child's panic is its place and its message on two whole lines, and
    /// nothing else passes for it.
    #[test]
    fn child_panic_is_two_whole_lines() {
        let place = format!("{CHILD_PANIC_AT}42:5:");
        let good = [place.clone(), CHILD_PANIC.to_string()];
        assert_eq!(child_panic_comes_whole(&good), Ok(()));
        for bad in [
            [place.clone(), format!("{CHILD_PANIC} more")],
            [format!("{CHILD_PANIC_AT}42:"), CHILD_PANIC.to_string()],
            [format!("{CHILD_PANIC_AT}42:5"), CHILD_PANIC.to_string()],
            [CHILD_PANIC.to_string(), place.clone()],
        ] {
            assert!(child_panic_comes_whole(&bad).is_err(), "{bad:?}");
        }
    }

    /// Runs end with PSCI SYSTEM_OFF on every machine (spec 14): the exit
    /// through `hlt #0xf000`, an undefined instruction under HVF, is gone
    /// from the kernel, the programs, xtask and the documents. The word is
    /// built here so that this test finds neither its text nor its name.
    #[test]
    fn no_semihosting_left() {
        let word = ["semi", "hosting"].concat();
        let own_name = format!("fn no_{word}_left() {{");
        let mut found: Vec<_> = texts(&[
            "kernel",
            "kcore",
            "lib",
            "services",
            "tests",
            "xtask",
            "docs",
            "README.md",
        ])
        .into_iter()
        .filter(|(_, text)| {
            text.lines()
                .any(|l| l.to_lowercase().contains(&word) && l.trim() != own_name)
        })
        .map(|(name, _)| name)
        .collect();
        found.sort();
        assert!(found.is_empty(), "{word} in {found:?}");
    }

    /// The kernel tests wake their threads through timers of programs
    /// (spec 10): the test builds keep no deadline of their own for the
    /// kernel's timer to serve besides the programs' timers.
    #[test]
    fn kernel_tests_keep_no_deadline_of_their_own() {
        let found: Vec<_> = texts(&["kernel/src"])
            .into_iter()
            .filter(|(name, text)| {
                text.contains("el0::deadline")
                    || (name.starts_with("kernel/src/ktest") && text.contains("fn deadline("))
            })
            .map(|(name, _)| name)
            .collect();
        assert!(found.is_empty(), "a test deadline in {found:?}");
    }
}
