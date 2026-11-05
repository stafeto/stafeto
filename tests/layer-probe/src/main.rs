// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The leader of the layer probe (xtask layer-probe, stafeto-design pk1-design R17). It holds
//! the layer session and the boot profile of the RAM file service, reads the layers of its
//! tests from the files `/test/layers/<name>.layer` and builds one of 32 MiB itself, attaches
//! and detaches them, and drives `layer-user`, the POSIX program that looks at the tree,
//! through files in `/tmp`.

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicBool, Ordering};
use posix_fs::{PosixFs, StartupFiles};
use proto_fs::{
    ALREADY_EXISTS, BAD_LAYER, BAD_MODE, CONFLICT, CREATE, LayerOp, LayerReply, LayerStart,
    LayerStep, PERMISSION, READ_ONLY, WRITE_ONLY,
};
use proto_wire::{Header, Reader, Writer};
use rt::abi::{Access, MESSAGE_MAX, Rights, Source};
use rt::handle::{Channel, Handle, Memory, Process};
use rt::sys::{self, Received};

rt::entry!(main);

/// Where the leader maps the object it fills.
const WORK: usize = 0x70_0000_0000;
const PAGE: usize = 4096;
/// The file of the big layer, in bytes.
const BIG: usize = 32 << 20;
/// The labels of the notifications of the layers, by the number of the layer.
const LABEL: u64 = 0x6c70_0000;

struct FileCell(core::cell::UnsafeCell<core::mem::MaybeUninit<PosixFs>>);
// SAFETY: one native owner; BUSY admits it once.
unsafe impl Sync for FileCell {}
static FILES: FileCell = FileCell(core::cell::UnsafeCell::new(core::mem::MaybeUninit::uninit()));
static BUSY: AtomicBool = AtomicBool::new(false);
#[repr(C, align(4096))]
struct Pages([[u8; posix_fs::DESCRIPTOR_PAGE_BYTES]; posix_fs::DESCRIPTOR_PAGES]);
static mut PAGES: Pages = Pages([[0; posix_fs::DESCRIPTOR_PAGE_BYTES]; posix_fs::DESCRIPTOR_PAGES]);

fn files(parent: &Handle<Channel>) -> Option<&'static mut PosixFs> {
    if BUSY.swap(true, Ordering::Acquire) {
        return None;
    }
    let startup = StartupFiles::connect(parent, false).ok()?;
    // SAFETY: the guard above gives the only owner of the static.
    unsafe {
        PosixFs::initialize_at(
            (*FILES.0.get()).as_mut_ptr(),
            startup,
            b"/",
            None,
            false,
            &mut posix_fs::Late::new(),
        )
        .ok()?;
        for k in 0..posix_fs::DESCRIPTOR_PAGES {
            let page = (&raw mut PAGES.0[k]).cast::<u8>();
            (*FILES.0.get())
                .assume_init_mut()
                .add_page(k, core::ptr::NonNull::new_unchecked(page));
        }
        Some((*FILES.0.get()).assume_init_mut())
    }
}

struct Probe {
    files: &'static mut PosixFs,
    process: Handle<Process>,
    layers: Handle<Channel>,
    profile: Handle<Channel>,
    level: u8,
    /// The channel the notification of each layer comes on, by its number.
    notices: [Option<Handle<Channel>>; 8],
}

macro_rules! must {
    ($cond:expr, $what:expr) => {
        if !$cond {
            rt::println!("layer-probe: failed {}", $what);
            return Err($what);
        }
    };
}

fn main(_: u64) -> u64 {
    let Ok(mut start) = rt::startup() else {
        return 1;
    };
    if let Ok(console) = start.take::<rt::handle::Resource>("console") {
        rt::console::set(console);
    }
    let level = sys::thread_info(&start.thread).map_or(1, |info| info.base);
    let (Some(files), Ok(layers), Ok(profile)) = (
        files(&start.parent),
        rt::service::connect(&start.parent, "ramfs/layers"),
        rt::service::connect(&start.parent, "ramfs"),
    ) else {
        rt::println!("layer-probe: failed to connect");
        return 3;
    };
    let process = rt::Handle::borrowed(start.process.raw());
    let mut probe = Probe {
        files,
        process: core::mem::ManuallyDrop::into_inner(process),
        layers,
        profile,
        level,
        notices: [const { None }; 8],
    };
    let result = probe.run();
    core::mem::forget(probe.process);
    match result {
        Ok(()) => {
            rt::println!("layer-probe: ok");
            0
        }
        Err(what) => {
            rt::println!("layer-probe: failed {what}");
            2
        }
    }
}

impl Probe {
    fn run(&mut self) -> Result<(), &'static str> {
        let before = self.mappings()?;
        rt::println!("layer-probe: ramfs holds {before} mappings before the layers");
        must!(
            before <= 16,
            "the service holds more than 16 mappings at the start"
        );
        // The layers of 1 024 entries with the longest paths and names, the second with all
        // the names in one bucket (xtask layer-probe steps): the portions of the work.
        if self.exists("/test/layers/wide.layer") {
            for (name, number) in [("wide", 6), ("wideb", 7), ("many", 4)] {
                let layer = self.load(name)?;
                let reply = self.attach(number, &layer, true)?;
                if reply != (LayerReply::Done { names: 1024 }) {
                    rt::println!("layer-probe: {name} answered {reply:?}");
                }
                must!(
                    reply == LayerReply::Done { names: 1024 },
                    "attach a wide layer"
                );
                must!(
                    self.detach(number)? == LayerReply::Done { names: 1024 },
                    "detach it"
                );
                must!(
                    self.notified(number, 5000),
                    "no notification of a wide layer"
                );
                rt::println!("layer-probe: {name} attached and detached ok");
            }
        }
        let good = self.load("good")?;
        // The layer session and nothing else: a call of the boot profile is refused.
        let refused = self.start_on(&self.profile, LayerOp::Detach, 1, 0, None);
        if refused != (LayerReply::Refused { status: PERMISSION }) {
            rt::println!("layer-probe: the profile answered {refused:?}");
        }
        must!(
            refused == LayerReply::Refused { status: PERMISSION },
            "LayerStart on the profile"
        );
        // 1. good goes in.
        let reply = self.attach(1, &good, true)?;
        must!(
            matches!(reply, LayerReply::Done { names } if names >= 10),
            "attach good"
        );
        must!(
            self.mappings()? == before + 1,
            "one more mapping for a layer"
        );
        self.touch("good")?;
        self.wait_for("checked")?;
        rt::println!("layer-probe: 1 good attached and looked at ok");
        // 2. The refusals leave the tree as it was.
        for (name, status, entry) in [
            ("conflict", CONFLICT, 1),
            ("setid", BAD_MODE, 1),
            ("bad", BAD_LAYER, 1),
        ] {
            let layer = self.load(name)?;
            let reply = self.attach(2, &layer, true)?;
            must!(reply == LayerReply::Entry { status, entry }, name);
            self.wait_release(2)?;
        }
        must!(self.exists("/layer/bin/hello"), "good is still there");
        must!(
            self.files.stat(b"/etc/passwd").is_ok(),
            "the file of the system is still there"
        );
        let again = self.attach(1, &good, false)?;
        must!(
            again
                == LayerReply::Refused {
                    status: ALREADY_EXISTS
                },
            "number taken"
        );
        must!(self.mappings()? == before + 1, "refusals map nothing");
        rt::println!("layer-probe: 2 conflict, set-ID and table refusals ok");
        // 3. An open file reads to the end after the detach.
        self.touch("phase2")?;
        self.wait_for("opened")?;
        let detached = self.detach(1)?;
        must!(matches!(detached, LayerReply::Done { .. }), "detach good");
        must!(!self.exists("/layer/bin/hello"), "the names are gone");
        must!(
            !self.notified(1, 200),
            "the layer was released while a file of it was open"
        );
        self.touch("detached")?;
        self.wait_for("closed")?;
        must!(self.notified(1, 2000), "no notification of the release");
        must!(self.mappings()? == before, "the mapping came back");
        rt::println!("layer-probe: 3 detach, open file, release and unmap ok");
        // 4. big goes in and out three times while layer-user reads another layer.
        let again = self.load("good")?;
        must!(
            matches!(self.attach(3, &again, true)?, LayerReply::Done { .. }),
            "attach good again"
        );
        self.touch("phase4")?;
        let big = self.synthesize()?;
        for round in 0..3 {
            let reply = self.attach(5, &big, true)?;
            must!(matches!(reply, LayerReply::Done { names: 2 }), "attach big");
            must!(self.mappings()? == before + 2, "big maps once");
            must!(
                matches!(self.detach(5)?, LayerReply::Done { names: 2 }),
                "detach big"
            );
            must!(self.notified(5, 2000), "no notification of big");
            rt::println!("layer-probe: big round {round} ok");
        }
        self.touch("stop")?;
        self.wait_for("user-ok")?;
        must!(
            matches!(self.detach(3)?, LayerReply::Done { .. }),
            "detach good again"
        );
        must!(self.notified(3, 2000), "no notification of good again");
        must!(self.mappings()? == before, "all mappings are back");
        rt::println!("layer-probe: 4 big three times beside a reader ok");
        Ok(())
    }

    /// The mappings the service held before the experiment (R9).
    fn mappings(&self) -> Result<u32, &'static str> {
        let page = sys::mem_create(PAGE as u64).map_err(|_| "page")?;
        let page = sys::handle_duplicate(&page, Rights::MAP_READ | Rights::TRANSFER)
            .map_err(|_| "page rights")?;
        let mut w = Writer::new();
        Header::new(0xfff0, proto_fs::VERSION)
            .write(&mut w)
            .map_err(|_| "header")?;
        let reply = sys::send_handles(&self.profile, w.as_bytes(), [page.erase()])
            .map_err(|_| "the mappings call")?;
        let mut buffer = [0; MESSAGE_MAX];
        let mut r = Reader::new(reply.bytes(&mut buffer));
        match (r.u32(), r.u32()) {
            (Ok(0), Ok(n)) => Ok(n),
            _ => Err("the mappings call answered an error"),
        }
    }

    /// The layer `name` from the files of the image; `attach` gives the service a read-only copy.
    fn load(&mut self, name: &str) -> Result<Handle<Memory>, &'static str> {
        let mut path = [0u8; 48];
        let text = b"/test/layers/";
        path[..text.len()].copy_from_slice(text);
        path[text.len()..text.len() + name.len()].copy_from_slice(name.as_bytes());
        let end = text.len() + name.len();
        path[end..end + 6].copy_from_slice(b".layer");
        let path = &path[..end + 6];
        let size = self.files.stat(path).map_err(|_| "stat the layer")?.size as usize;
        let memory = sys::mem_create(size.next_multiple_of(PAGE) as u64).map_err(|_| "memory")?;
        sys::mem_map(
            &self.process,
            &memory,
            0,
            size.next_multiple_of(PAGE) as u64,
            WORK,
            Access::ReadWrite,
        )
        .map_err(|_| "map")?;
        let fd = self
            .files
            .open(path, READ_ONLY)
            .map_err(|_| "open the layer")?;
        let mut done = 0;
        while done < size {
            // SAFETY: the window is the mapping made above.
            let out = unsafe {
                core::slice::from_raw_parts_mut((WORK + done) as *mut u8, (size - done).min(8192))
            };
            let n = self.files.read(fd, out).map_err(|_| "read the layer")?;
            must!(n != 0, "short layer");
            done += n;
        }
        let _ = self.files.close(fd);
        // SAFETY: nothing uses the window now.
        let _ = unsafe { sys::mem_unmap(&self.process, WORK, size.next_multiple_of(PAGE) as u64) };
        Ok(memory)
    }

    /// A package file of one file of 32 MiB under `/big`, built here.
    fn synthesize(&mut self) -> Result<Handle<Memory>, &'static str> {
        let total = (4 * PAGE + BIG).next_multiple_of(PAGE);
        let memory = sys::mem_create(total as u64).map_err(|_| "memory")?;
        sys::mem_map(
            &self.process,
            &memory,
            0,
            total as u64,
            WORK,
            Access::ReadWrite,
        )
        .map_err(|_| "map")?;
        // SAFETY: the window is the mapping made above, which only this function uses.
        let out = unsafe { core::slice::from_raw_parts_mut(WORK as *mut u8, total) };
        let table = rootfs_big();
        let files: [(&[u8], &[u8], usize, usize); 4] = [
            (b"meta", b"meta", PAGE, 4),
            (b"rootfs", &table, 2 * PAGE, table.len()),
            (b"manifest", b"manifest", 3 * PAGE, 8),
            (b"3", &[], 4 * PAGE, BIG),
        ];
        out[..8].copy_from_slice(b"STAFPKG1");
        out[8..12].copy_from_slice(&1u32.to_le_bytes());
        out[12..16].copy_from_slice(&4u32.to_le_bytes());
        for (i, (name, bytes, offset, length)) in files.iter().enumerate() {
            let at = 16 + 48 * i;
            out[at..at + name.len()].copy_from_slice(name);
            out[at + 32..at + 40].copy_from_slice(&(*offset as u64).to_le_bytes());
            out[at + 40..at + 48].copy_from_slice(&(*length as u64).to_le_bytes());
            out[*offset..*offset + bytes.len()].copy_from_slice(bytes);
        }
        let (words, _) = out[4 * PAGE..4 * PAGE + BIG].as_chunks_mut::<8>();
        for (i, word) in words.iter_mut().enumerate() {
            *word = (i as u64).to_le_bytes();
        }
        // SAFETY: nothing uses the window now.
        let _ = unsafe { sys::mem_unmap(&self.process, WORK, total as u64) };
        Ok(memory)
    }

    fn start_on(
        &self,
        session: &Handle<Channel>,
        op: LayerOp,
        layer: u32,
        level: u32,
        handles: Option<[rt::handle::Handle<rt::handle::Any>; 2]>,
    ) -> LayerReply {
        let mut w = Writer::new();
        if (LayerStart { op, layer, level }).write(&mut w).is_err() {
            return LayerReply::Refused { status: 304 };
        }
        let reply = match handles {
            Some(handles) => sys::send_handles(session, w.as_bytes(), handles).map_err(|_| ()),
            None => sys::send(session, w.as_bytes()).map_err(|_| ()),
        };
        let Ok(reply) = reply else {
            return LayerReply::Refused { status: 0xffff };
        };
        let mut buffer = [0; MESSAGE_MAX];
        LayerReply::read(Reader::new(reply.bytes(&mut buffer)))
            .unwrap_or(LayerReply::Refused { status: 0xfffe })
    }

    /// Attach `memory` as layer `number`, with the notification on slot `slot`: the answer
    /// after the last step.
    fn attach(
        &mut self,
        number: u32,
        memory: &Handle<Memory>,
        keep: bool,
    ) -> Result<LayerReply, &'static str> {
        let channel = sys::channel_create(self.level).map_err(|_| "channel")?;
        let tell = sys::handle_label(
            &channel,
            Rights::NOTIFY | Rights::TRANSFER,
            LABEL + u64::from(number),
            self.level,
        )
        .map_err(|_| "label")?;
        let copy = sys::handle_duplicate(memory, Rights::MAP_READ | Rights::TRANSFER)
            .map_err(|_| "copy")?;
        if keep {
            self.notices[(number as usize) % 8] = Some(channel);
        }
        let mut reply = self.start_on(
            &self.layers,
            LayerOp::Attach,
            number,
            u32::from(self.level),
            Some([copy.erase(), tell.erase()]),
        );
        while reply == LayerReply::Resolving {
            reply = self.step(number);
        }
        Ok(reply)
    }

    fn detach(&mut self, number: u32) -> Result<LayerReply, &'static str> {
        let mut reply = self.start_on(&self.layers, LayerOp::Detach, number, 0, None);
        while reply == LayerReply::Resolving {
            reply = self.step(number);
        }
        Ok(reply)
    }

    fn step(&self, number: u32) -> LayerReply {
        let mut w = Writer::new();
        if (LayerStep { layer: number }).write(&mut w).is_err() {
            return LayerReply::Refused { status: 304 };
        }
        let Ok(reply) = sys::send(&self.layers, w.as_bytes()) else {
            return LayerReply::Refused { status: 0xffff };
        };
        let mut buffer = [0; MESSAGE_MAX];
        LayerReply::read(Reader::new(reply.bytes(&mut buffer)))
            .unwrap_or(LayerReply::Refused { status: 0xfffe })
    }

    /// Whether the notification of layer `number` comes within `ms`.
    fn notified(&self, number: u32, ms: u64) -> bool {
        let Some(channel) = self.notices[(number as usize) % 8].as_ref() else {
            return false;
        };
        let Ok(timer) = sys::timer_create(channel, self.level) else {
            return false;
        };
        let deadline = rt::time::ticks_to_ns(rt::time::now()) + ms * 1_000_000;
        if sys::timer_set(&timer, deadline).is_err() {
            return false;
        }
        loop {
            match sys::receive(channel) {
                Ok(Received::Notification { source, label, .. }) => {
                    if source == Source::Timer {
                        return false;
                    }
                    if label == LABEL + u64::from(number) {
                        let _ = sys::timer_cancel(&timer);
                        return true;
                    }
                }
                _ => return false,
            }
        }
    }

    /// A layer that failed is released: its notification comes.
    fn wait_release(&self, number: u32) -> Result<(), &'static str> {
        must!(
            self.notified(number, 2000),
            "no notification of a refused layer"
        );
        Ok(())
    }

    fn exists(&mut self, path: &str) -> bool {
        self.files.stat(path.as_bytes()).is_ok()
    }

    /// Creates `/tmp/<name>`.
    fn touch(&mut self, name: &str) -> Result<(), &'static str> {
        let mut path = [0u8; 48];
        path[..5].copy_from_slice(b"/tmp/");
        path[5..5 + name.len()].copy_from_slice(name.as_bytes());
        let fd = self
            .files
            .open(&path[..5 + name.len()], CREATE | WRITE_ONLY)
            .map_err(|_| "create a marker")?;
        let _ = self.files.write(fd, b"x");
        let _ = self.files.close(fd);
        Ok(())
    }

    /// Waits for `/tmp/<name>` at most 20 seconds.
    fn wait_for(&mut self, name: &str) -> Result<(), &'static str> {
        let mut path = [0u8; 48];
        path[..5].copy_from_slice(b"/tmp/");
        path[5..5 + name.len()].copy_from_slice(name.as_bytes());
        let path = &path[..5 + name.len()];
        for _ in 0..60000 {
            if self.files.stat(path).is_ok() {
                return Ok(());
            }
            sleep_ms(self.level, 10);
        }
        rt::println!("layer-probe: failed waiting for /tmp/{name}");
        Err("a marker of layer-user did not come")
    }
}

fn sleep_ms(level: u8, ms: u64) {
    let Ok(channel) = sys::channel_create(level) else {
        return;
    };
    let Ok(timer) = sys::timer_create(&channel, level) else {
        return;
    };
    let deadline = rt::time::ticks_to_ns(rt::time::now()) + ms * 1_000_000;
    if sys::timer_set(&timer, deadline).is_ok() {
        let _ = sys::receive(&channel);
    }
}

/// The table of the big layer: the directory `/big` and its file, the container's file 3.
fn rootfs_big() -> [u8; 24 + 2 * 24 + 5 + 9] {
    let mut out = [0u8; 24 + 2 * 24 + 5 + 9];
    out[..8].copy_from_slice(b"STAFROOT");
    out[8..12].copy_from_slice(&2u32.to_le_bytes());
    out[12..16].copy_from_slice(&2u32.to_le_bytes());
    let paths: [(&[u8], u32, u32); 2] = [(b"/big", 0o040_755, 0), (b"/big/file", 0o100_644, 3)];
    let mut offset = 24 + 2 * 24;
    for (i, (path, mode, file)) in paths.iter().enumerate() {
        let at = 24 + 24 * i;
        out[at..at + 4].copy_from_slice(&(offset as u32).to_le_bytes());
        out[at + 4..at + 6].copy_from_slice(&(path.len() as u16).to_le_bytes());
        out[at + 8..at + 12].copy_from_slice(&mode.to_le_bytes());
        out[at + 20..at + 24].copy_from_slice(&file.to_le_bytes());
        out[offset..offset + path.len()].copy_from_slice(path);
        offset += path.len();
    }
    out
}
