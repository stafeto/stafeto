// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! Direct native children exercise physical reclamation after an armed process ends.
use rt::abi::{Access, Call, ProcessState, Rights, ThreadState};
use rt::{Handle, sys};

core::arch::global_asm!(
    ".pushsection .text.native_arm_child,\"ax\",@progbits",
    ".balign 4",
    ".global native_arm_child_begin",
    ".global native_arm_child_end",
    "native_arm_child_begin:",
    "mov x19, x0",
    "mov x0, #1",
    "svc #{create}",
    "cbnz x0, 3f",
    "mov x21, x1",
    "mov x0, #{start}",
    "mov x1, #0",
    "mov x2, #1",
    "mov x3, #1",
    "mov x4, #0",
    "mov x5, #0",
    "svc #0xffe0",
    "cbnz x0, 3f",
    "mov x0, #{start}",
    "mov x1, #1",
    "svc #{notify}",
    "cbnz x0, 3f",
    "cbz x19, 2f",
    "mov x0, x21",
    "mov x1, #0",
    "svc #{receive}",
    "b 3f",
    "2:",
    "mov x0, #7",
    "svc #{exit}",
    "b 3f",
    "3:",
    "mov x0, #{start}",
    "mov x1, #2",
    "svc #{notify}",
    "mov x0, #9",
    "svc #{exit}",
    "b 3b",
    "native_arm_child_end:",
    ".popsection",
    create = const Call::CreateChannel.number(),
    notify = const Call::Notify.number(),
    receive = const Call::Receive.number(),
    exit = const Call::ProcessExit.number(),
    start = const rt::abi::START_CHANNEL.0,
);
unsafe extern "C" {
    static native_arm_child_begin: u8;
    static native_arm_child_end: u8;
}
// A failed preparation still ends its child before owned handles are released.
struct StopChild<'a>(&'a Handle<rt::handle::Process>);
impl Drop for StopChild<'_> {
    fn drop(&mut self) {
        let _ = sys::process_kill(self.0);
    }
}
struct Alias<'a> {
    process: &'a Handle<rt::handle::Process>,
    active: bool,
}
impl Drop for Alias<'_> {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: this guard owns the fresh scratch mapping, containing no live Rust objects.
            let _ = unsafe { sys::mem_unmap(self.process, ALIAS, PAGE) };
        }
    }
}
const PAGE: u64 = 4096;
const CODE: usize = 0x10000;
const STACK: usize = 0x20000;
const ALIAS: usize = 0xd00000;
fn live() -> [u64; 5] {
    // SAFETY: the test-only call returns value-only physical slot counts and arm presence.
    let regs = unsafe { sys::raw::<0xffe3>([0; 10]) };
    regs[1..6].try_into().expect("five counters")
}
fn settled(expected: [u64; 5]) -> bool {
    for _ in 0..1000 {
        if live() == expected {
            return true;
        }
        let _ = sys::yield_now();
    }
    rt::println!(
        "posix-files: physical Live {:?}, expected {:?}",
        live(),
        expected
    );
    false
}
pub fn run() -> Result<(), i32> {
    let parent = posix_abi::allocation::process();
    let before = live();
    for case in 0..4 {
        let control = sys::channel_create(1).map_err(|_| 170)?;
        let exit = sys::channel_create(1).map_err(|_| 171)?;
        let label = 9000 + case;
        let exit_copy = sys::handle_label(&exit, Rights::NOTIFY, label, 30).map_err(|_| 172)?;
        let start = if case < 2 {
            sys::handle_duplicate(&control, Rights::SEND | Rights::NOTIFY | Rights::TRANSFER)
        } else {
            sys::handle_label(
                &control,
                Rights::SEND | Rights::NOTIFY | Rights::TRANSFER,
                8000 + case,
                30,
            )
        }
        .map_err(|_| 173)?;
        let child =
            sys::process_create_with(64 * PAGE, 32, 31, Some((&exit_copy, 30)), Some(start))
                .map_err(|_| 174)?;
        let stop = StopChild(&child);
        drop(exit_copy);
        let code = sys::mem_create(PAGE).map_err(|_| 175)?;
        let stack = sys::mem_create(PAGE).map_err(|_| 176)?;
        sys::mem_map(parent, &code, 0, PAGE, ALIAS, Access::ReadWrite).map_err(|_| 177)?;
        let mut alias = Alias {
            process: parent,
            active: true,
        };
        let begin = core::ptr::addr_of!(native_arm_child_begin);
        let end = core::ptr::addr_of!(native_arm_child_end);
        // SAFETY: these ordered assembly labels delimit a single static executable section.
        let len = unsafe { end.offset_from(begin) } as usize;
        if len == 0 || len > PAGE as usize {
            return Err(178);
        }
        // SAFETY: ALIAS is our fresh writable page, and the static code spans len readable bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(begin, ALIAS as *mut u8, len);
        }
        // SAFETY: the scratch alias contains only the copied entry and no active Rust objects.
        unsafe { sys::mem_unmap(parent, ALIAS, PAGE) }.map_err(|_| 179)?;
        alias.active = false;
        drop(alias);
        sys::mem_map(&child, &code, 0, PAGE, CODE, Access::Read).map_err(|_| 180)?;
        // SAFETY: the child has not started; existing MemProtect synchronizes this code's I-cache.
        unsafe { sys::mem_protect(&child, CODE, PAGE, Access::ReadExec) }.map_err(|_| 181)?;
        sys::mem_map(&child, &stack, 0, PAGE, STACK, Access::ReadWrite).map_err(|_| 182)?;
        // SAFETY: CODE holds the isolated AArch64 entry, fully mapped RX before its first instruction.
        let entry: extern "C" fn(u64) -> ! = unsafe { core::mem::transmute(CODE) };
        // SAFETY: the child owns distinct mapped code, stack and message-buffer address space.
        let thread = unsafe {
            sys::thread_create(
                &child,
                entry,
                STACK + PAGE as usize,
                case & 1,
                31,
                rt::abi::Policy::Fifo,
                0x30000,
            )
        }
        .map_err(|_| 183)?;
        sys::thread_start(&thread).map_err(|_| 184)?;
        let ready = sys::try_receive(&control).map_err(|_| 185)?;
        if !matches!(ready, sys::Received::Notification { bits, .. } if bits & 1 != 0 && bits & 2 == 0)
        {
            return Err(186);
        }
        if case & 1 != 0 {
            if !sys::thread_info(&thread).is_ok_and(|info| info.state == ThreadState::Receiving) {
                return Err(187);
            }
            sys::process_kill(&child).map_err(|_| 188)?;
        }
        let mut notified = false;
        for _ in 0..1000 {
            match sys::try_receive(&exit) {
                Ok(sys::Received::Notification {
                    label: got, bits, ..
                }) if got == label && bits & 1 != 0 => {
                    notified = true;
                    break;
                }
                Ok(_) => {}
                Err(_) => {
                    let _ = sys::yield_now();
                }
            }
        }
        if !notified
            || sys::process_state(&child)
                != Ok(if case & 1 == 0 {
                    ProcessState::Exited { code: 7 }
                } else {
                    ProcessState::Killed
                })
        {
            return Err(189);
        }
        drop(thread);
        drop(stop);
        drop(child);
        drop(code);
        drop(stack);
        drop(control);
        drop(exit);
        if !settled(before) {
            return Err(190);
        }
    }
    rt::println!("posix-files: armed process death returns physical objects ok");
    Ok(())
}
