// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Build, run and test stafeto. Usage: `cargo xtask <command>`.

#[macro_use]
mod out;

mod disasm;
mod entropy;
mod image;
mod jobs;
mod measure;
mod ostest;
mod qemu;
mod ring;
mod rootfs;
mod rtbench;
mod rtbench2;
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
    ("posix-procs", "posix-procs", POSIX_STACK_SIZE, &[]),
    // Pieces of 64 KiB: the probe's forks copy regions past one piece.
    ("loader", "loader", 0, &["small-pieces"]),
    ("busybox-probe", "busybox-probe", 0, &["applets"]),
    ("virtio-rng", "virtio-rng", entropy::RNG_STACK_SIZE, &[]),
    ("entropy", "entropy", entropy::ENTROPY_STACK_SIZE, &[]),
];
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
    ("posix-procs", "posix-procs", POSIX_STACK_SIZE, &[]),
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
    ("tty-probe", "tty-probe", SVC_STACK_SIZE, &[]),
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
const TEARDOWN_ROWS: [&str; 9] = [
    "buffers",
    "shell",
    "end_call",
    "threads_ready",
    "teardown_threads",
    "child_threads",
    "session_buffers",
    "session_handles",
    "threads",
];
/// Scoped direct-control, pick + park and continuation measurements.
const SUSPENSION_ROWS: [&str; 5] = [
    "control_stop_no_queue",
    "control_stop_cancel",
    "pick_park_selected",
    "control_continue",
    "resume_64",
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
            with --short, one round of them on TCG, as ci runs it
  ext4ro    read an e2fsprogs ext4 image inside the QEMU guest
  ramfs     exercise the RAM file service and descriptors in QEMU
  posix-cancel-input verify cancelled UART reads and cleanup handlers
  posix-cancel-input-vz verify cancelled reads of the Virtio console on Apple VZ
  posix-threads verify pthread interruption and main-thread exit
  posix-threads-vz run the pthread probe on Apple Virtualization.framework
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
            [flag] if flag == "--short" => relibc().and_then(|()| rtbench2::short()),
            rest => rtbench::run(rest),
        },
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
        Some("relibc-hello") => relibc_hello_probe(),
        Some("posix-procs") => posix_procs_probe(&qemu::VIRT),
        Some("loader-channels") => loader_channels_probe(),
        Some("posix-poll") => posix_poll_probe(),
        Some("posix-pty") => posix_pty_probe(),
        Some("posix-tty-control-steps") => posix_tty_control_steps(),
        Some("posix-pty-steps") => posix_pty_probe_in(true),
