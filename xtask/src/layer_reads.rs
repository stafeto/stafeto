// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

//! The reads of the build of the layer index (`cargo xtask layer-reads`): the build of the index
//! of the volume of the scale probe (`data_image::layer_steps_entries`, 8,192 names) by the real
//! `Scan` of the layer service against the real data service (`datafs::server::Server`) on a
//! disk in memory, with the count of the reads the device was asked for. On the t4g.small a read
//! of the disk costs about 0.63 ms and a build of 297 s was 310,000 to 460,000 reads, so the count
//! is the cost of the build (reports/2026-11-28-layered-fs-c4-aws.md).

use crate::data_image;
use datafs::mem::MemDevice;
use datafs::server::Server;
use datafs::volume;
use layerd::index::Index;
use layerd::scan::{Failure, Progress, Scan};
use layerd::volume::{BATCH_BYTES, R, Visit, Volume};
use proto_data as p;
use proto_data::Method;
use proto_wire::{Status, Writer};
use std::boxed::Box;

/// The calls of the scan over the server and a volume in memory; the calls the scan never makes
/// answer with an error.
struct Direct<'a, 'b> {
    server: &'a mut Server,
    fs: &'a mut datafs::Fs<'b, datafs::Window<MemDevice>>,
    /// The requests the scan made, by method.
    calls: [u32; 64],
}

impl Direct<'_, '_> {
    fn call(&mut self, build: impl FnOnce(&mut Writer) -> Result<(), Status>) -> R<Vec<u8>> {
        let mut w = Writer::new();
        build(&mut w)?;
        // The method number is the first u16 of the header of the request.
        if let Some(n) = w.as_bytes().get(..2) {
            let method = u16::from_le_bytes(n.try_into().unwrap());
            if let Some(slot) = self.calls.get_mut(method as usize) {
                *slot += 1;
            }
        }
        let reply = self.server.handle(self.fs, p::SERVICE, 0, w.as_bytes());
        p::reply(reply.as_bytes()).map(|mut r| r.bytes(r.left()).unwrap().to_vec())
    }
}

fn unused<T>() -> R<T> {
    Err(Status::Unknown(0))
}

impl Volume for Direct<'_, '_> {
    type Pass = ();

    fn open(&mut self, path: &[u8], flags: u32, mode: u32) -> R<u32> {
        let bytes = self.call(|w| p::open(path, flags, mode, w))?;
        Ok(u32::from_le_bytes(bytes[..4].try_into().unwrap()))
    }
    fn open_numbered(&mut self, _: &[u8], _: u32, _: u32, _: u64) -> R<u32> {
        unused()
    }
    fn truncate(&mut self, _: u32, _: u64) -> R<()> {
        unused()
    }
    fn chmod(&mut self, _: &[u8], _: u32) -> R<()> {
        unused()
    }
    fn chown(&mut self, _: &[u8], _: u32, _: u32) -> R<()> {
        unused()
    }
    fn utimens(&mut self, _: &[u8], _: i64, _: i64) -> R<()> {
        unused()
    }
    fn close(&mut self, handle: u32) -> R<()> {
        self.call(|w| p::handle_call(Method::Close, handle, w))
            .map(drop)
    }
    fn read(&mut self, _: u32, _: &mut [u8]) -> R<usize> {
        unused()
    }
    fn write(&mut self, _: u32, _: &[u8]) -> R<usize> {
        unused()
    }
    fn fsync(&mut self, _: u32) -> R<()> {
        unused()
    }
    fn stat(&mut self, path: &[u8]) -> R<p::Stat> {
        let bytes = self.call(|w| p::path_call(Method::Stat, path, w))?;
        p::Stat::from_bytes(&bytes[..p::STAT_LEN])
    }
    fn mkdir(&mut self, _: &[u8], _: u32) -> R<()> {
        unused()
    }
    fn mkdir_numbered(&mut self, _: &[u8], _: u32, _: u64) -> R<()> {
        unused()
    }
    fn rename(&mut self, _: &[u8], _: &[u8]) -> R<()> {
        unused()
    }
    fn unlink(&mut self, _: &[u8]) -> R<()> {
        unused()
    }
    fn rmdir(&mut self, _: &[u8]) -> R<()> {
        unused()
    }
    fn read_dir(&mut self, _: u32, _: Visit<'_>) -> R<bool> {
        unused()
    }
    fn export(&mut self, _: u32) -> R<()> {
        unused()
    }
    fn read_dir_raw(&mut self, _: u32, _: &mut [u8; BATCH_BYTES]) -> R<(usize, bool)> {
        unused()
    }
    fn read_dir_attr_raw(&mut self, handle: u32, out: &mut [u8; BATCH_BYTES]) -> R<(usize, bool)> {
        let bytes = self.call(|w| p::handle_call(Method::ReaddirAttr, handle, w))?;
        let more = match u32::from_le_bytes(bytes[..4].try_into().unwrap()) {
            0 => false,
            1 => true,
            _ => return Err(Status::BadSize),
        };
        let rest = &bytes[4..];
        out[..rest.len()].copy_from_slice(rest);
        Ok((rest.len(), more))
    }
}

/// What a build of the scale volume cost.
#[derive(Clone, Copy, Debug)]
pub struct Reads {
    /// The calls of the device's read, and the reads of the mount alone.
    pub total: u64,
    pub mount: u64,
    /// The steps of the scan.
    pub steps: u32,
    /// The requests the scan made, by method number.
    pub requests: [u32; 64],
}

impl Reads {
    /// The reads of the build alone.
    pub fn build(&self) -> u64 {
        self.total - self.mount
    }
}

/// Builds the volume of the scale probe in a file, loads it into memory, mounts it and runs the
/// scan to its end.
pub fn measure() -> Result<Reads, String> {
    let dir = std::env::temp_dir().join(format!("stafeto-layer-reads-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let file = dir.join("volume.img");
    let made = data_image::make_layer_steps_volume(&file, 128 << 20);
    let medium = made.and_then(|()| std::fs::read(&file).map_err(|e| e.to_string()));
    let _ = std::fs::remove_dir_all(&dir);
    let medium = medium?;
    let mut state = datafs::Storage::boxed();
    let (mut fs, _, _) = volume::open(MemDevice::from_medium(medium), &mut state, 1)
        .map_err(|r| format!("the volume does not open: {}", r.text()))?;
    let mut server = Server::with_epoch(1);
    let mount = fs.device().device.reads;
    let mut index = Box::new(Index::new());
    index.set_seed(0x5eed);
    let mut scan = Box::new(Scan::new());
    let mut direct = Direct {
        server: &mut server,
        fs: &mut fs,
        calls: [0; 64],
    };
    loop {
        match scan.step(&mut index, &mut direct, b"/.layers/00", 0) {
            Ok(Progress::More) => {}
            Ok(Progress::Done) => break,
            Err(Failure::Volume(s)) => return Err(format!("the volume answered {s:?}")),
            Err(f) => return Err(format!("the build failed: {f:?}")),
        }
    }
    let requests = direct.calls;
    let steps = scan.steps;
    let total = fs.device().device.reads;
    Ok(Reads {
        total,
        mount,
        steps,
        requests,
    })
}

/// The reads of the build and the calls it made, on the console.
pub fn command(_args: &[String]) -> Result<(), String> {
    let reads = std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(measure)
        .map_err(|e| e.to_string())?
        .join()
        .map_err(|_| "the measurement panicked".to_string())??;
    println!(
        "layer-reads: the build took {} reads of the device ({} more at the mount), {} steps",
        reads.build(),
        reads.mount,
        reads.steps
    );
    for (method, n) in reads.requests.iter().enumerate() {
        if *n != 0 {
            println!("layer-reads: method {method}: {n} calls");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_build_of_the_scale_volume_reads_the_disk_few_times() {
        let reads = std::thread::Builder::new()
            .stack_size(256 << 20)
            .spawn(super::measure)
            .unwrap()
            .join()
            .unwrap()
            .unwrap();
        // The bound of the fast build (stafeto#657): the plan said 2,000 to 3,000 reads, the
        // gate is 5,000. Before the change the build took over 300,000.
        assert!(reads.build() < 5_000, "{} reads", reads.build());
    }
}
