// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The dedicated guest observes the actual service page and its transferred rights.

static BUDGET_PRINTED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

#[unsafe(no_mangle)]
pub extern "C" fn ram_lifetime(pid: i32) -> i32 {
    let result = (|| {
        let raw =
            posix_abi::shared::with_files(|files| Ok(files.sessions().0.raw())).map_err(|_| -1)?;
        let channel = rt::Handle::<rt::handle::Channel>::borrowed(raw);
        let mut request = proto_wire::Writer::new();
        proto_wire::Header::new(0xfff3, proto_fs::VERSION)
            .write(&mut request)
            .map_err(|_| -2)?;
        request.u32(pid as u32).map_err(|_| -3)?;
        for _ in 0..128 {
            let reply = rt::fs::Files::send_on(&channel, request.as_bytes()).map_err(|_| -4)?;
            if !reply.handles.is_empty() {
                return Err(-5);
            }
            let mut buffer = [0; rt::abi::MESSAGE_MAX];
            let mut body = proto_wire::Reader::new(reply.bytes(&mut buffer));
            let status = body.u32().map_err(|_| -6)?;
            if status == proto_fs::RESOLVING {
                if body.u32().map_err(|_| -9)? != 0 {
                    return Err(-9);
                }
                body.finish().map_err(|_| -9)?;
                rt::sys::yield_now().map_err(|_| -11)?;
                continue;
            }
            if status != 0 {
                return Err(-7);
            }
            let live = body.u32().map_err(|_| -8)?;
            let quota = body.u64().map_err(|_| -13)?;
            let used = body.u64().map_err(|_| -14)?;
            body.finish().map_err(|_| -9)?;
            if quota.saturating_sub(used) < 128 * 4096 {
                return Err(-15);
            }
            if !BUDGET_PRINTED.swap(true, core::sync::atomic::Ordering::Relaxed) {
                rt::println!(
                    "RAM lifetime budget: quota={} used={} free={} pages ticks={}",
                    quota / 4096,
                    used / 4096,
                    quota.saturating_sub(used) / 4096,
                    rt::time::now()
                );
            }
            if live > 1 {
                return Err(-10);
            }
            return Ok(live as i32);
        }
        Err(-12)
    })();
    result.unwrap_or_else(|error| error)
}

#[unsafe(no_mangle)]
pub extern "C" fn process_lifetime(pid: i32) -> i32 {
    let result = (|| {
        let mut request = proto_wire::Writer::new();
        proto_wire::Header::new(0xfff0, proto_process::VERSION)
            .write(&mut request)
            .map_err(|_| -1)?;
        request.u32(pid as u32).map_err(|_| -2)?;
        let mut reply = rt::sys::send(posix_abi::process::client().session(), request.as_bytes())
            .map_err(|_| -3)?;
        let mut buffer = [0; rt::abi::MESSAGE_MAX];
        let mut body = proto_wire::Reader::new(reply.bytes(&mut buffer));
        if body.u32().map_err(|_| -4)? != 0 {
            return Err(-5);
        }
        let live = body.u32().map_err(|_| -6)?;
        body.finish().map_err(|_| -7)?;
        if reply.handles.info(0)
            != Some((
                rt::abi::ObjectKind::Memory,
                rt::abi::Rights::MAP_READ | rt::abi::Rights::TRANSFER,
            ))
            || reply.handles.len() != 1
            || live > 1
        {
            return Err(-8);
        }
        const WINDOW: usize = 0x60_0000_0000;
        let memory = reply
            .handles
            .take::<rt::handle::Memory>(0)
            .map_err(|_| -9)?;
        let process = posix_abi::allocation::process();
        rt::sys::mem_map(process, &memory, 0, 4096, WINDOW, rt::abi::Access::Read)
            .map_err(|_| -10)?;
        // SAFETY: the service initialized Page in this aligned read-only mapping.
        let mapped_live =
            unsafe { &*(WINDOW as *const proto_process::lifetimes::Page) }.live(pid as u32);
        // SAFETY: this single-threaded fixture no longer accesses its temporary mapping.
        unsafe { rt::sys::mem_unmap(process, WINDOW, 4096) }.map_err(|_| -11)?;
        if u32::from(mapped_live) != live {
            return Err(-12);
        }
        Ok(live as i32)
    })();
    result.unwrap_or_else(|error| error)
}
